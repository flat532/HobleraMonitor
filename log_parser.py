import subprocess
import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from config import Config

def init_db():
    """Inicjalizuj bazę danych"""
    conn = sqlite3.connect(Config.DB_FILE)
    cursor = conn.cursor()
    
    # Tabela SSH logów
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssh_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            username TEXT,
            ip_address TEXT,
            port INTEGER,
            status TEXT,
            message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabela alertów
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            message TEXT,
            details TEXT,
            email_sent BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabela system metrics
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cpu_percent REAL,
            memory_percent REAL,
            disk_percent REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Migration: Add dns_name column if not exists
    try:
        cursor.execute("ALTER TABLE ssh_logs ADD COLUMN dns_name TEXT")
        print("Migrated database: added dns_name column to ssh_logs")
    except sqlite3.OperationalError:
        pass

    # Migration: Add network metrics columns if not exists
    try:
        cursor.execute("ALTER TABLE system_metrics ADD COLUMN net_sent_bytes INTEGER")
        cursor.execute("ALTER TABLE system_metrics ADD COLUMN net_recv_bytes INTEGER")
        print("Migrated database: added network columns to system_metrics")
    except sqlite3.OperationalError:
        pass
    
    conn.commit()
    conn.close()

def resolve_ip_dns(ip_address):
    """Resolve IP to DNS name with cache and timeout"""
    import socket
    try:
        # Set timeout for DNS resolution to avoid hanging
        socket.setdefaulttimeout(1)
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except Exception:
        return None

def parse_journalctl_log():
    """Parsuj logi bezpośrednio z journalctl (systemd)"""
    print("Using journalctl for log parsing...")
    
    conn = sqlite3.connect(Config.DB_FILE)
    cursor = conn.cursor()
    
    # Pobierz ostatni timestamp z bazy
    cursor.execute("SELECT MAX(timestamp) FROM ssh_logs")
    last_ts_str = cursor.fetchone()[0]
    
    cmd = ["journalctl", "-u", "sshd", "-o", "json", "--no-pager"]
    
    # Add time filter if we have history
    if last_ts_str:
        # Add 1 second to avoid duplicates (journalctl --since is inclusive)
        try:
            last_ts = datetime.strptime(last_ts_str, "%Y-%m-%d %H:%M:%S")
            since_ts = last_ts + timedelta(seconds=1)
            cmd.extend(["--since", since_ts.strftime("%Y-%m-%d %H:%M:%S")])
        except Exception as e:
            print(f"Error parsing last timestamp: {e}")
            
    print(f"Executing: {' '.join(cmd)}")
    
    try:
        # Run command
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running journalctl: {result.stderr}")
            conn.close()
            return 0
            
        logs = []
        for line in result.stdout.splitlines():
            try:
                if not line.strip(): continue
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
                
    except Exception as e:
        print(f"Failed to execute journalctl: {e}")
        conn.close()
        return 0

    # Patterns for MESSAGE content only (no timestamp/host prefix)
    patterns = {
        'accepted_password': re.compile(
            r'Accepted password for (\w+) from ([\da-fA-F:.%]+) port (\d+)'
        ),
        'accepted_publickey': re.compile(
            r'Accepted publickey for (\w+) from ([\da-fA-F:.%]+) port (\d+)'
        ),
        'failed': re.compile(
            r'Failed password for (?:invalid user )?(\w+) from ([\da-fA-F:.%]+) port (\d+)'
        ),
        'invalid': re.compile(
            r'Invalid user (\w+) from ([\da-fA-F:.%]+) port (\d+)'
        )
    }

    new_entries = 0
    dns_cache = {}
    
    for entry in logs:
        message = entry.get('MESSAGE', '')
        # Journalctl timestamp is in microseconds (integer string)
        # e.g. "1641493908873105"
        ts_us = int(entry.get('__REALTIME_TIMESTAMP', 0))
        timestamp = datetime.fromtimestamp(ts_us / 1_000_000)
        
        for status_key, pattern in patterns.items():
            match = pattern.search(message)
            if match:
                username = match.group(1)
                ip = match.group(2)
                port = match.group(3)
                
                # Determine status
                final_status = 'accepted' if 'accepted' in status_key else status_key
                
                # Resolve DNS
                if ip not in dns_cache:
                    dns_cache[ip] = resolve_ip_dns(ip)
                dns_name = dns_cache[ip]
                
                try:
                    cursor.execute('''
                        INSERT INTO ssh_logs (timestamp, username, ip_address, dns_name, port, status, message)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (timestamp, username, ip, dns_name, port, final_status, message))
                    
                    new_entries += 1
                except sqlite3.Error as e:
                    print(f"DB Error: {e}")
                
                break # Matched one pattern, move to next log
    
    conn.commit()
    conn.close()
    
    print(f"Parsed {new_entries} new SSH log entries from journalctl")
    return new_entries

def parse_ssh_log():
    """Parsuj auth.log LUB journalctl i wyciągnij SSH logowania"""
    
    # Fallback to journalctl if file not found
    if not Path(Config.AUTH_LOG).exists():
        print(f"Log file not found: {Config.AUTH_LOG}. Switching to journalctl.")
        return parse_journalctl_log()
    
    conn = sqlite3.connect(Config.DB_FILE)
    cursor = conn.cursor()
    
    # Pobierz ostatni timestamp z bazy
    cursor.execute("SELECT MAX(timestamp) FROM ssh_logs")
    res = cursor.fetchone()
    last_ts = res[0] if res else None
    
    # Patterns dla ISO 8601 format: 2026-01-06T18:31:48.873105+01:00
    patterns = {
        'accepted_password': re.compile(
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Accepted password for (\w+) from ([\da-fA-F:.%]+) port (\d+)'
        ),
        'accepted_publickey': re.compile(
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Accepted publickey for (\w+) from ([\da-fA-F:.%]+) port (\d+)'
        ),
        'failed': re.compile(
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Failed password for (?:invalid user )?(\w+) from ([\da-fA-F:.%]+) port (\d+)'
        ),
        'invalid': re.compile(
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Invalid user (\w+) from ([\da-fA-F:.%]+) port (\d+)'
        )
    }
    
    new_entries = 0
    dns_cache = {}
    
    try:
        with open(Config.AUTH_LOG, 'r') as f:
            for line in f:
                for status, pattern in patterns.items():
                    match = pattern.search(line)
                    if match:
                        timestamp_str = match.group(1)
                        username = match.group(2)
                        ip = match.group(3)
                        port = match.group(4)
                        
                        # Parse ISO timestamp (tylko do sekund)
                        try:
                            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                            
                            # Skip if already in DB
                            if last_ts and timestamp.strftime("%Y-%m-%d %H:%M:%S") <= last_ts:
                                continue
                            
                            # Determine status (accepted vs failed/invalid)
                            final_status = 'accepted' if 'accepted' in status else status
                            
                            # Resolve DNS (with local cache for this run)
                            if ip not in dns_cache:
                                dns_cache[ip] = resolve_ip_dns(ip)
                            dns_name = dns_cache[ip]
                            
                            cursor.execute('''
                                INSERT INTO ssh_logs (timestamp, username, ip_address, dns_name, port, status, message)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''', (timestamp, username, ip, dns_name, port, final_status, line.strip()))
                            
                            new_entries += 1
                            
                        except Exception as e:
                            print(f"Error parsing line: {e}")
                            print(f"Line: {line.strip()}")
                            continue
    except Exception as e:
        print(f"Error reading auth.log: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"Parsed {new_entries} new SSH log entries from auth.log")
    return new_entries

def check_anomalies():
    """Sprawdź anomalie i generuj alerty"""
    conn = sqlite3.connect(Config.DB_FILE)
    cursor = conn.cursor()
    
    # Sprawdź failed logins w ostatniej godzinie
    cursor.execute('''
        SELECT COUNT(*), ip_address 
        FROM ssh_logs 
        WHERE status IN ('failed', 'invalid') 
        AND timestamp > datetime('now', 'localtime', '-1 hour')
        GROUP BY ip_address
        HAVING COUNT(*) > ?
    ''', (Config.MAX_FAILED_LOGINS_PER_HOUR,))
    
    for count, ip in cursor.fetchall():
        message = f"Suspicious activity: {count} failed login attempts from {ip} in last hour"
        
        # Check if alert already exists (last 1 hour)
        cursor.execute('''
            SELECT id FROM alerts 
            WHERE alert_type = 'failed_login' 
            AND details = ?
            AND created_at > datetime('now', 'localtime', '-1 hour')
        ''', (ip,))
        
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO alerts (alert_type, severity, message, details)
                VALUES (?, ?, ?, ?)
            ''', ('failed_login', 'warning', message, ip))
            print(f"Alert created: {message}")
    
    conn.commit()
    conn.close()

def main():
    init_db()
    parse_ssh_log()
    check_anomalies()

if __name__ == "__main__":
    main()
