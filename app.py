#!/usr/bin/env python3
"""
Hoblera Monitor - Enhanced v2.1
With Django Applications Monitoring
"""

from flask import Flask, render_template, jsonify
import sqlite3
import psutil
import subprocess
from datetime import datetime, timedelta
from config import Config
from pathlib import Path
import sys
import requests
import time as time_module
import configparser

app = Flask(__name__)
app.config.from_object(Config)

def get_db():
    conn = sqlite3.connect(Config.DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def run_command(cmd):
    """Bezpieczne uruchomienie komendy"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        
        # Debug log
        print(f"[DEBUG] CMD: {cmd}", file=sys.stderr)
        print(f"[DEBUG] Return: {result.returncode}, Stdout: '{stdout}', Stderr: '{stderr}'", file=sys.stderr)
        
        return stdout, result.returncode
    except Exception as e:
        print(f"[ERROR] Command failed: {cmd}, Error: {e}", file=sys.stderr)
        return "", -1

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    """Statystyki ogólne"""
    conn = get_db()
    cursor = conn.cursor()
    
    # SSH stats (last 24h)
    cursor.execute('''
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as successful,
            SUM(CASE WHEN status IN ('failed', 'invalid') THEN 1 ELSE 0 END) as failed
        FROM ssh_logs
        WHERE timestamp > datetime('now', '-1 day')
    ''')
    ssh_stats = dict(cursor.fetchone())
    
    cursor.execute('''
        SELECT COUNT(DISTINCT ip_address) as unique_ips
        FROM ssh_logs
        WHERE timestamp > datetime('now', '-1 day')
    ''')
    ssh_stats['unique_ips'] = cursor.fetchone()[0]
    
    cursor.execute('''
        SELECT COUNT(*) as active_alerts
        FROM alerts
        WHERE created_at > datetime('now', '-1 day')
    ''')
    alerts_count = cursor.fetchone()[0]
    
    memory = psutil.virtual_memory()
    net = psutil.net_io_counters()
    
    # Media disk (/dev/sdb1)
    media_disk = None
    for partition in psutil.disk_partitions():
        if '/media' in partition.mountpoint or 'sdb' in partition.device:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                media_disk = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'percent': usage.percent,
                    'total_gb': round(usage.total / (1024**3), 2),
                    'used_gb': round(usage.used / (1024**3), 2),
                    'free_gb': round(usage.free / (1024**3), 2)
                }
                break
            except:
                continue
    
    # Root disk
    root_disk = psutil.disk_usage('/')
    
    system = {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'cpu_count': psutil.cpu_count(),
        'memory_percent': memory.percent,
        'memory_total_gb': round(memory.total / (1024**3), 2),
        'memory_used_gb': round(memory.used / (1024**3), 2),
        'root_disk_percent': root_disk.percent,
        'root_disk_total_gb': round(root_disk.total / (1024**3), 2),
        'root_disk_used_gb': round(root_disk.used / (1024**3), 2),
        'root_disk_free_gb': round(root_disk.free / (1024**3), 2),
        'media_disk': media_disk,
        'network_sent_mb': round(net.bytes_sent / (1024**2), 2),
        'network_recv_mb': round(net.bytes_recv / (1024**2), 2),
        'uptime_seconds': int((datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds()),
        'uptime_human': str(timedelta(seconds=int((datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds())))
    }
    
    conn.close()
    
    return jsonify({
        'ssh': ssh_stats,
        'system': system,
        'alerts': alerts_count
    })

@app.route('/api/disk_partitions')
def api_disk_partitions():
    """Kompaktowa lista partycji"""
    partitions = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            partitions.append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'total_gb': round(usage.total / (1024**3), 2),
                'used_gb': round(usage.used / (1024**3), 2),
                'percent': usage.percent
            })
        except:
            continue
    
    return jsonify(partitions)

@app.route('/api/top_processes')
def api_top_processes():
    """Top procesy"""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = proc.info
            processes.append({
                'pid': pinfo['pid'],
                'name': pinfo['name'],
                'username': pinfo['username'],
                'cpu_percent': pinfo['cpu_percent'],
                'memory_percent': round(pinfo['memory_percent'], 2)
            })
        except:
            continue
    
    processes_cpu = sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:10]
    processes_mem = sorted(processes, key=lambda x: x['memory_percent'] or 0, reverse=True)[:10]
    
    return jsonify({
        'by_cpu': processes_cpu,
        'by_memory': processes_mem
    })

@app.route('/api/systemd_services')
def api_systemd_services():
    """Status serwisów"""
    services = [
        'instagram-gallery',
        'hoblera-monitor',
        'sshd',
        'docker',
        'cron'
    ]
    
    statuses = []
    for service in services:
        output, returncode = run_command(f"/usr/bin/systemctl is-active {service}")
        
        # Explicit check
        active = (returncode == 0 and output.strip() == 'active')
        
        print(f"[SERVICE] {service}: output='{output}', returncode={returncode}, active={active}", file=sys.stderr)
        
        statuses.append({
            'name': service,
            'active': active,
            'status': output if output else 'unknown'
        })
    
    return jsonify(statuses)

@app.route('/api/apps')
def api_apps():
    """Status applications (Django & Flask)"""
    apps = [
        {
            'name': 'HobleraVOD',
            'type': 'Django',
            'service': 'hoblera-vod',
            'url': 'http://10.10.10.111:8000',
            'path': '/www/HobleraVOD',
            'process_match': 'HobleraVOD'
        },
        {
            'name': 'Instagram Gallery',
            'type': 'Flask',
            'service': 'instagram-gallery',
            'url': 'http://10.10.10.111:8001',
            'path': '/www/InstagramGallery',
            'process_match': 'InstagramGallery/app.py'
        },
        {
            'name': 'Hoblera Monitor',
            'type': 'Flask',
            'service': 'hoblera-monitor',
            'url': 'http://10.10.10.111:8002',
            'path': '/www/HobleraMonitor',
            'process_match': 'HobleraMonitor/app.py'
        },
        {
            'name': 'MiniDLNA',
            'type': 'Media Server',
            'service': 'minidlna',
            'url': 'http://10.10.10.111:8200/',
            'path': '/var/cache/minidlna',
            'process_match': 'minidlnad'
        }
    ]
    
    results = []
    for app in apps:
        # Check systemd service
        output, returncode = run_command(f"/usr/bin/systemctl is-active {app['service']}")
        service_active = (returncode == 0 and output.strip() == 'active')
        
        # Check HTTP response
        http_ok = False
        response_time = None
        try:
            start = time_module.time()
            resp = requests.get(app['url'], timeout=5)
            response_time = round((time_module.time() - start) * 1000, 2)  # ms
            # Treat any non-server-error as online (e.g. 403 Forbidden means it's running)
            http_ok = (resp.status_code < 500)
        except Exception as e:
            print(f"[ERROR] HTTP check failed for {app['name']}: {e}", file=sys.stderr)
        
        # Check if directory exists
        path_exists = Path(app['path']).exists()
        
        # Get process info
        process_info = None
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_percent', 'cpu_percent']):
                cmdline = ' '.join(proc.info['cmdline'] or [])
                # Generalize matching logic
                if app['process_match'] in cmdline:
                    process_info = {
                        'pid': proc.info['pid'],
                        'memory_percent': round(proc.info['memory_percent'], 2),
                        'cpu_percent': round(proc.info['cpu_percent'] or 0, 2)
                    }
                    break
        except Exception as e:
            print(f"[ERROR] Process check failed for {app['name']}: {e}", file=sys.stderr)
        
        results.append({
            'name': app['name'],
            'type': app['type'],
            'service': app['service'],
            'service_active': service_active,
            'http_ok': http_ok,
            'response_time_ms': response_time,
            'path': app['path'],
            'path_exists': path_exists,
            'url': app['url'],
            'process': process_info
        })
    
    return jsonify(results)

@app.route('/api/banned_ips')
def api_banned_ips():
    """Lista zbanowanych IP z fail2ban"""
    # Process runs as root, sudo not needed (and not in path)
    output, returncode = run_command("/usr/bin/fail2ban-client status sshd")
    
    banned_ips = []
    if returncode == 0:
        for line in output.split('\n'):
            if "Banned IP list:" in line:
                # Format: `- Banned IP list:	IP1, IP2, ...`
                ips_part = line.split(":", 1)[1].strip()
                if ips_part:
                    # Split by comma or whitespace just in case
                    banned_ips = [ip.strip() for ip in ips_part.replace(',', ' ').split() if ip.strip()]
                break
    
    # Return list of objects for easier future extensibility (e.g. adding ban time)
    return jsonify([{'ip': ip} for ip in banned_ips])

@app.route('/api/ssh_timeline')
def api_ssh_timeline():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT 
            strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
            status,
            COUNT(*) as count
        FROM ssh_logs
        WHERE timestamp > datetime('now', '-1 day')
        GROUP BY hour, status
        ORDER BY hour
    ''')
    
    data = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in data])

@app.route('/api/top_ips')
def api_top_ips():
    conn = get_db()
    cursor = conn.cursor()
    
    trusted_ips = "('10.10.10.102', '10.10.10.103', '127.0.0.1', '10.10.10.111')"
    
    cursor.execute(f'''
        SELECT 
            ip_address,
            MAX(dns_name) as dns_name,
            GROUP_CONCAT(DISTINCT username) as usernames,
            COUNT(*) as total_attempts,
            SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as successful,
            SUM(CASE WHEN status IN ('failed', 'invalid') THEN 1 ELSE 0 END) as failed,
            MAX(timestamp) as last_seen
        FROM ssh_logs
        WHERE timestamp > datetime('now', '-7 days')
        AND (dns_name IS NULL OR dns_name NOT LIKE 'ec2-%.eu-central-1.compute.amazonaws.com')
        AND ip_address NOT IN {trusted_ips}
        GROUP BY ip_address
        ORDER BY total_attempts DESC
        LIMIT 20
    ''')
    
    data = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in data])

@app.route('/api/trusted_hosts')
def api_trusted_hosts():
    conn = get_db()
    cursor = conn.cursor()
    
    trusted_ips = "('10.10.10.102', '10.10.10.103', '127.0.0.1', '10.10.10.111')"
    
    cursor.execute(f'''
        SELECT 
            ip_address,
            MAX(dns_name) as dns_name,
            GROUP_CONCAT(DISTINCT username) as usernames,
            COUNT(*) as total_attempts,
            SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as successful,
            SUM(CASE WHEN status IN ('failed', 'invalid') THEN 1 ELSE 0 END) as failed,
            MAX(timestamp) as last_seen
        FROM ssh_logs
        WHERE timestamp > datetime('now', '-1 day')
        AND (
            dns_name LIKE 'ec2-%.eu-central-1.compute.amazonaws.com'
            OR ip_address IN {trusted_ips}
        )
        GROUP BY ip_address
        ORDER BY last_seen DESC
        LIMIT 20
    ''')
    
    data = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in data])

@app.route('/api/recent_logs')
def api_recent_logs():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT *
        FROM ssh_logs
        ORDER BY timestamp DESC
        LIMIT 100
    ''')
    
    data = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in data])

@app.route('/api/alerts')
def api_alerts():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT *
        FROM alerts
        WHERE created_at > datetime('now', '-7 days')
        AND email_sent = 0
        ORDER BY created_at DESC
        LIMIT 50
    ''')
    
    data = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in data])

@app.route('/api/system_history')
def api_system_history():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT *
        FROM system_metrics
        WHERE timestamp > datetime('now', '-1 day')
        ORDER BY timestamp
    ''')
    
    data = cursor.fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in data])

@app.route('/api/fail2ban/config', methods=['GET'])
def get_fail2ban_config():
    """Pobierz konfigurację fail2ban"""
    config = configparser.ConfigParser()
    # Use path relative to app.py
    config_path = Path(app.root_path) / 'jail.local.strict'
    
    try:
        config.read(config_path)
        return jsonify({
            'bantime': config.get('DEFAULT', 'bantime', fallback='86400'),
            'findtime': config.get('DEFAULT', 'findtime', fallback='600'),
            'maxretry': config.get('DEFAULT', 'maxretry', fallback='5')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/fail2ban/config', methods=['POST'])
def update_fail2ban_config():
    """Aktualizuj konfigurację fail2ban"""
    config = configparser.ConfigParser()
    config_path = Path(app.root_path) / 'jail.local.strict'
    
    try:
        from flask import request
        data = request.json
        
        config.read(config_path)
        
        if 'DEFAULT' not in config:
            config['DEFAULT'] = {}
            
        if 'bantime' in data:
            config['DEFAULT']['bantime'] = str(data['bantime'])
        if 'findtime' in data:
            config['DEFAULT']['findtime'] = str(data['findtime'])
        if 'maxretry' in data:
            config['DEFAULT']['maxretry'] = str(data['maxretry'])
            
        # Write config
        # If file is owned by root and we are not root, this might fail unless we sudo write.
        # Try normal write first.
        try:
             with open(config_path, 'w') as configfile:
                config.write(configfile)
        except PermissionError:
            # Fallback: Write to temp and sudo move
            import tempfile
            import os
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                config.write(tmp)
                tmp_path = tmp.name
                
            cmd = f"sudo mv {tmp_path} {config_path}"
            out, ret = run_command(cmd)
            if ret != 0:
                return jsonify({'error': f'Failed to save config (Permission denied): {out}'}), 500
            
        return jsonify({'status': 'success', 'message': 'Configuration saved internally'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/fail2ban/reload', methods=['POST'])
def reload_fail2ban():
    """Zastosuj zmiany i przeładuj"""
    try:
        import shutil
        import os
        
        # Determine paths
        config_path = Path(app.root_path) / 'jail.local.strict'
        dest_path = '/etc/fail2ban/jail.local'
        
        # 1. Copy file using Python's shutil (no external binary needed)
        try:
            shutil.copy2(config_path, dest_path)
        except PermissionError:
            # If we lack permission (e.g. running as flat532 not root), we MUST use sudo.
            # But we must use absolute path for cp and sudo.
            # System confirms: /usr/bin/cp, /usr/bin/sudo
            
            cmd_cp = f"/usr/bin/sudo /usr/bin/cp {config_path} {dest_path}"
            proc = subprocess.run(cmd_cp, shell=True, capture_output=True, text=True)
            if proc.returncode != 0:
                 return jsonify({'status': 'error', 'message': f'Failed to copy config. Out: {proc.stdout}, Err: {proc.stderr}'}), 403

        # 2. Reload fail2ban
        # Use absolute path for systemctl to avoid PATH issues
        # System confirmed: /usr/bin/systemctl
        systemctl_cmd = "/usr/bin/systemctl"
        if not os.path.exists(systemctl_cmd):
             # Fallback just in case
            systemctl_cmd = "/bin/systemctl"
            
        cmd_reload = f"{systemctl_cmd} reload fail2ban"
        
        # If not root, prepend sudo (pkexec/sudo needs full path too usually, but sudo main binary is strictly /usr/bin/sudo)
        if os.geteuid() != 0:
            cmd_reload = f"/usr/bin/sudo {cmd_reload}"
            
        proc = subprocess.run(cmd_reload, shell=True, capture_output=True, text=True)
        
        if proc.returncode != 0:
            return jsonify({'status': 'error', 'message': f'Failed to reload service. Out: {proc.stdout}, Err: {proc.stderr}'}), 403
            
        return jsonify({'status': 'success', 'message': 'Configuration applied and Service reloaded'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print(f"Starting Hoblera Monitor on {app.config['HOST']}:{app.config['PORT']}")
    app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'])
