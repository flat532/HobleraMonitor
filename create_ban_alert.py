#!/usr/bin/env python3
"""
Trigger Fail2Ban Alert
Usage: python3 create_ban_alert.py <IP_ADDRESS>
"""
import sys
import sqlite3
from config import Config

def trigger_ban_alert(ip_address):
    conn = sqlite3.connect(Config.DB_FILE)
    cursor = conn.cursor()
    
    message = f"⛔ Fail2Ban: IP {ip_address} has been banned for repeated failed logins."
    
    cursor.execute('''
        INSERT INTO alerts (alert_type, severity, message, details)
        VALUES (?, ?, ?, ?)
    ''', ('security_ban', 'critical', message, ip_address))
    
    conn.commit()
    conn.close()
    print(f"Alert created for banned IP: {ip_address}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 create_ban_alert.py <IP>")
        sys.exit(1)
        
    trigger_ban_alert(sys.argv[1])
