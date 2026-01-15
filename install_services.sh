#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

echo "Installing Hoblera Monitor Services..."

# Copy files
cp systemd/hoblera-metrics.service /etc/systemd/system/
cp systemd/hoblera-metrics.timer /etc/systemd/system/
cp systemd/hoblera-logs.service /etc/systemd/system/
cp systemd/hoblera-logs.timer /etc/systemd/system/

# Reload daemon
systemctl daemon-reload

# Enable and start timers
echo "Enabling timers..."
systemctl enable --now hoblera-metrics.timer
systemctl enable --now hoblera-logs.timer

echo "Done! Metrics will collect every 5min, Logs every 1min."
echo "Check status with: systemctl list-timers --all"
