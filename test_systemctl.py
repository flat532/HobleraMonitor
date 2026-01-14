#!/usr/bin/env python3
import subprocess

def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        print(f"Command: {cmd}")
        print(f"Return code: {result.returncode}")
        print(f"Stdout: '{result.stdout.strip()}'")
        print(f"Stderr: '{result.stderr.strip()}'")
        return result.stdout.strip(), result.returncode
    except Exception as e:
        print(f"Exception: {e}")
        return None, -1

# Test
services = ['instagram-gallery', 'sshd', 'docker', 'cron']

for service in services:
    print("=" * 50)
    output, returncode = run_command(f"systemctl is-active {service}")
    active = (returncode == 0 and output == 'active')
    print(f"Active: {active}")
    print()
