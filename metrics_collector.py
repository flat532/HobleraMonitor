#!/usr/bin/env python3
"""
System Metrics Collector - zapisuje metryki co 5 minut
"""

import sqlite3
import psutil
from config import Config

def collect_metrics():
    conn = sqlite3.connect(Config.DB_FILE)
    cursor = conn.cursor()
    
    # Pobierz metryki
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    
    net = psutil.net_io_counters()
    net_sent = net.bytes_sent
    net_recv = net.bytes_recv
    
    cursor.execute('''
        INSERT INTO system_metrics (cpu_percent, memory_percent, disk_percent, net_sent_bytes, net_recv_bytes)
        VALUES (?, ?, ?, ?, ?)
    ''', (cpu, memory, disk, net_sent, net_recv))
    
    conn.commit()
    conn.close()
    
    print(f"Metrics: CPU={cpu}%, MEM={memory}%, DISK={disk}%, NET_TX={net_sent}, NET_RX={net_recv}")

if __name__ == "__main__":
    collect_metrics()
