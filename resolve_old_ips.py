#!/usr/bin/env python3
"""
Backfill DNS names for existing SSH logs
"""
import sqlite3
import socket
from config import Config

def resolve_ip(ip):
    try:
        socket.setdefaulttimeout(1)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except:
        return None

def main():
    print("Starting DNS backfill...")
    conn = sqlite3.connect(Config.DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get distinct IPs with null dns_name
    cursor.execute("SELECT DISTINCT ip_address FROM ssh_logs WHERE dns_name IS NULL")
    ips = [row['ip_address'] for row in cursor.fetchall()]
    
    print(f"Found {len(ips)} unique IPs to resolve.")
    
    resolved_count = 0
    for ip in ips:
        hostname = resolve_ip(ip)
        if hostname:
            print(f"Resolved {ip} -> {hostname}")
            cursor.execute("UPDATE ssh_logs SET dns_name = ? WHERE ip_address = ?", (hostname, ip))
            resolved_count += 1
        else:
            print(f"Could not resolve {ip}")
            
    conn.commit()
    conn.close()
    print(f"Done. Resolved {resolved_count} IPs.")

if __name__ == "__main__":
    main()
