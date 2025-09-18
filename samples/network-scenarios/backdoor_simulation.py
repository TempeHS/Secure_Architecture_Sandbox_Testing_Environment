#!/usr/bin/env python3
"""
Backdoor Communication Simulator
Educational tool for demonstrating backdoor/malware communication patterns.

This script simulates the network behavior of backdoors and malware to help
students understand and identify these threats in network traffic.

Author: Secure Architecture Sandbox Testing Environment
Purpose: Educational cybersecurity training
"""

import time
import threading
import socket
import sys
import random
from datetime import datetime
import json
import base64


class BackdoorSimulator:
    """Simulates backdoor and malware network communication patterns."""

    def __init__(self):
        self.activity_log = []
        self.running = False
        self.session_id = f"session_{random.randint(1000, 9999)}"

    def log_activity(self, activity_type, details, risk_level="HIGH"):
        """Log backdoor activity with timestamp and risk assessment."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'type': activity_type,
            'details': details,
            'risk_level': risk_level,
            'session_id': self.session_id,
            'educational_note': self._get_educational_note(activity_type)
        }
        self.activity_log.append(entry)
        print(f"[{entry['timestamp']}] BACKDOOR - {activity_type}: {details}")

    def _get_educational_note(self, activity_type):
        """Get educational explanation for each backdoor activity type."""
        notes = {
            'REVERSE_SHELL': 'Reverse shells connect back to attacker-controlled servers',
            'CC_BEACON': 'C&C beacons are periodic check-ins with command servers',
            'DATA_EXFILTRATION': 'Data exfiltration moves sensitive data to external systems',
            'PERSISTENCE_CHECK': 'Backdoors check connectivity to maintain persistent access',
            'COMMAND_DOWNLOAD': 'Backdoors download new commands or malware updates',
            'KEYLOGGER_UPLOAD': 'Keyloggers upload captured keystrokes to remote servers',
            'BACKDOOR_INSTALLATION': 'Installation phase creates network connections for setup'
        }
        return notes.get(activity_type, 'Analyze this backdoor behavior pattern')

    def simulate_reverse_shell(self, duration=60):
        """Simulate reverse shell connection attempts."""
        print(f"\n🔙 Simulating reverse shell for {duration} seconds...")

        # Common reverse shell ports used by attackers
        reverse_ports = [4444, 4445, 4446, 1337, 31337, 8080, 443]
        # Simulated C&C server IPs (using localhost for safety)
        cc_servers = ['127.0.0.1']

        start_time = time.time()
        attempt_count = 0

        while time.time() - start_time < duration and self.running:
            port = random.choice(reverse_ports)
            server = random.choice(cc_servers)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((server, port))

                if result == 0:
                    # Simulate shell session data
                    fake_commands = ['whoami', 'pwd',
                                     'ls -la', 'cat /etc/passwd']
                    command = random.choice(fake_commands)

                    self.log_activity(
                        'REVERSE_SHELL',
                        f"Reverse shell to {server}:{port} - Command: {command}",
                        'CRITICAL'
                    )

                    # Simulate interactive session
                    time.sleep(random.uniform(2, 5))
                else:
                    self.log_activity(
                        'REVERSE_SHELL',
                        f"Reverse shell attempt to {server}:{port} failed",
                        'HIGH'
                    )

                sock.close()
                attempt_count += 1

                # Realistic delay between attempts
                time.sleep(random.uniform(10, 30))

            except Exception as e:
                self.log_activity(
                    'REVERSE_SHELL',
                    f"Reverse shell error: {str(e)}",
                    'MEDIUM'
                )

        print(f"🔙 Completed {attempt_count} reverse shell attempts")

    def simulate_cc_beacons(self, duration=60):
        """Simulate Command & Control beacon traffic."""
        print(f"\n📡 Simulating C&C beacons for {duration} seconds...")

        start_time = time.time()
        beacon_count = 0

        while time.time() - start_time < duration and self.running:
            # Simulate beacon data
            beacon_data = {
                'victim_id': f"victim_{random.randint(100, 999)}",
                'status': 'alive',
                'ip': '192.168.1.100',
                'os': 'Linux',
                'timestamp': datetime.now().isoformat()
            }

            # Encode beacon data (common in malware)
            encoded_data = base64.b64encode(
                json.dumps(beacon_data).encode()).decode()

            try:
                # Attempt connection to C&C server
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('127.0.0.1', 8080))

                self.log_activity(
                    'CC_BEACON',
                    f"C&C beacon sent - Data: {encoded_data[:50]}...",
                    'CRITICAL'
                )

                sock.close()
                beacon_count += 1

                # Regular intervals typical of beacons
                time.sleep(random.uniform(15, 45))

            except Exception as e:
                self.log_activity(
                    'CC_BEACON',
                    f"C&C beacon failed: {str(e)}",
                    'HIGH'
                )

        print(f"📡 Sent {beacon_count} C&C beacons")

    def simulate_data_exfiltration(self, duration=60):
        """Simulate data exfiltration patterns."""
        print(f"\n📤 Simulating data exfiltration for {duration} seconds...")

        start_time = time.time()
        exfil_count = 0

        # Simulated sensitive file types
        file_types = ['passwords.txt', 'financial_data.csv',
                      'customer_list.db', 'secrets.key']

        while time.time() - start_time < duration and self.running:
            filename = random.choice(file_types)
            file_size = random.randint(1024, 1048576)  # 1KB to 1MB

            # Simulate file content encoding
            fake_content = f"SENSITIVE_DATA_{random.randint(1000, 9999)}"
            encoded_content = base64.b64encode(fake_content.encode()).decode()

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                # HTTPS port for stealth
                result = sock.connect_ex(('127.0.0.1', 443))

                self.log_activity(
                    'DATA_EXFILTRATION',
                    f"Exfiltrating {filename} ({file_size} bytes) - {encoded_content[:30]}...",
                    'CRITICAL'
                )

                sock.close()
                exfil_count += 1

                # Delay to avoid detection
                time.sleep(random.uniform(20, 60))

            except Exception as e:
                self.log_activity(
                    'DATA_EXFILTRATION',
                    f"Data exfiltration failed: {str(e)}",
                    'HIGH'
                )

        print(f"📤 Attempted {exfil_count} data exfiltrations")

    def simulate_keylogger_upload(self, duration=60):
        """Simulate keylogger data upload."""
        print(f"\n⌨️  Simulating keylogger uploads for {duration} seconds...")

        start_time = time.time()
        upload_count = 0

        while time.time() - start_time < duration and self.running:
            # Simulate captured keystrokes
            fake_keystrokes = [
                "username: admin",
                "password: secret123",
                "email: user@company.com",
                "credit_card: 4111111111111111"
            ]

            keystroke_data = random.choice(fake_keystrokes)
            encoded_keys = base64.b64encode(keystroke_data.encode()).decode()

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(('127.0.0.1', 8443))

                self.log_activity(
                    'KEYLOGGER_UPLOAD',
                    f"Keylogger data upload - Keys: {encoded_keys}",
                    'CRITICAL'
                )

                sock.close()
                upload_count += 1

                # Periodic uploads
                time.sleep(random.uniform(30, 90))

            except Exception as e:
                self.log_activity(
                    'KEYLOGGER_UPLOAD',
                    f"Keylogger upload failed: {str(e)}",
                    'HIGH'
                )

        print(f"⌨️  Uploaded {upload_count} keylogger data sets")

    def simulate_persistence_checks(self, duration=60):
        """Simulate backdoor persistence verification."""
        print(f"\n🔄 Simulating persistence checks for {duration} seconds...")

        start_time = time.time()
        check_count = 0

        while time.time() - start_time < duration and self.running:
            # Simulate checking if backdoor is still active
            check_types = [
                'registry_key_exists',
                'service_running',
                'scheduled_task_active',
                'file_permissions_ok'
            ]

            check_type = random.choice(check_types)

            self.log_activity(
                'PERSISTENCE_CHECK',
                f"Checking persistence mechanism: {check_type}",
                'HIGH'
            )

            # Also check network connectivity
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', 9090))

                if result == 0:
                    self.log_activity(
                        'PERSISTENCE_CHECK',
                        "Backdoor connectivity verified - persistence active",
                        'CRITICAL'
                    )
                else:
                    self.log_activity(
                        'PERSISTENCE_CHECK',
                        "Backdoor connectivity check failed",
                        'MEDIUM'
                    )

                sock.close()
                check_count += 1

                # Regular persistence checks
                time.sleep(random.uniform(45, 120))

            except Exception as e:
                self.log_activity(
                    'PERSISTENCE_CHECK',
                    f"Persistence check error: {str(e)}",
                    'LOW'
                )

        print(f"🔄 Performed {check_count} persistence checks")

    def run_scenario(self, duration=300):
        """Run the complete backdoor simulation scenario."""
        print("🚨 Starting Backdoor Communication Simulation")
        print("=" * 50)
        print(f"Session ID: {self.session_id}")
        print(f"Duration: {duration} seconds")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        print("⚠️  WARNING: Simulating malware network behavior for education")
        print("   Use only in controlled environments for learning purposes")
        print()

        self.running = True
        self.activity_log = []

        # Run different backdoor activities in parallel
        activities = [
            threading.Thread(target=self.simulate_reverse_shell,
                             args=(duration//5,)),
            threading.Thread(target=self.simulate_cc_beacons,
                             args=(duration//5,)),
            threading.Thread(
                target=self.simulate_data_exfiltration, args=(duration//5,)),
            threading.Thread(
                target=self.simulate_keylogger_upload, args=(duration//5,)),
            threading.Thread(
                target=self.simulate_persistence_checks, args=(duration//5,))
        ]

        # Stagger activity start times
        for i, activity in enumerate(activities):
            activity.start()
            time.sleep(3)

        # Wait for all activities to complete
        for activity in activities:
            activity.join()

        self.running = False

        print("\n" + "=" * 50)
        print("🚨 Backdoor Simulation Complete")
        print(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total backdoor activities: {len(self.activity_log)}")

        return self.activity_log

    def save_report(self, filename=None):
        """Save backdoor activity report to file."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"backdoor_simulation_{timestamp}.json"

        # Categorize activities by type
        activity_summary = {}
        for activity in self.activity_log:
            activity_type = activity['type']
            if activity_type not in activity_summary:
                activity_summary[activity_type] = 0
            activity_summary[activity_type] += 1

        report = {
            'scenario': 'Backdoor Communication Simulation',
            'session_id': self.session_id,
            'start_time': self.activity_log[0]['timestamp'] if self.activity_log else datetime.now().isoformat(),
            'end_time': self.activity_log[-1]['timestamp'] if self.activity_log else datetime.now().isoformat(),
            'total_activities': len(self.activity_log),
            'activity_summary': activity_summary,
            'activities': self.activity_log,
            'threat_indicators': [
                'Connections to known backdoor ports (4444, 1337, 31337)',
                'Regular beacon traffic to external servers',
                'Data exfiltration to suspicious destinations',
                'Encoded/encrypted communication patterns',
                'Persistence mechanism checks'
            ],
            'detection_methods': [
                'Monitor connections to unusual ports',
                'Look for regular, periodic network traffic',
                'Analyze traffic for encoded/encrypted data',
                'Check for reverse shell patterns',
                'Monitor data volume to external destinations'
            ]
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📄 Backdoor simulation report saved to: {filename}")
        return filename


def main():
    """Main function to run the backdoor simulation scenario."""
    print("🚨 Backdoor Communication Simulator")
    print("Educational Cybersecurity Tool")
    print()

    # Parse command line arguments
    duration = 300  # Default 5 minutes
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("❌ Invalid duration. Using default 300 seconds.")

    print(f"⏱️  Scenario duration: {duration} seconds")
    print("\n🚨 This scenario will simulate:")
    print("  • Reverse shell connections")
    print("  • Command & Control beacons")
    print("  • Data exfiltration attempts")
    print("  • Keylogger data uploads")
    print("  • Persistence verification checks")
    print()
    print("⚠️  Educational Use Only - Simulated Malware Behavior")
    print()

    input("Press Enter to start backdoor simulation...")
    print()

    # Create and run scenario
    simulator = BackdoorSimulator()

    try:
        activity_log = simulator.run_scenario(duration)

        # Save report
        report_file = simulator.save_report()

        # Display summary
        activity_counts = {}
        for activity in activity_log:
            activity_type = activity['type']
            if activity_type not in activity_counts:
                activity_counts[activity_type] = 0
            activity_counts[activity_type] += 1

        print("\n📊 Backdoor Activity Summary:")
        print(f"  • Total activities: {len(activity_log)}")
        for activity_type, count in activity_counts.items():
            print(f"  • {activity_type}: {count}")

        print("\n🔍 Analysis Instructions:")
        print("  1. Look for connections to backdoor ports (4444, 1337, 31337)")
        print("  2. Identify periodic beacon patterns")
        print("  3. Monitor data exfiltration attempts")
        print(f"  4. Review detailed analysis in: {report_file}")

        print("\n💡 Key Detection Indicators:")
        print("  • Regular connections to unusual ports")
        print("  • Encoded/encrypted data in network traffic")
        print("  • Outbound connections to suspicious destinations")
        print("  • Reverse shell connection patterns")
        print("  • Periodic beacon traffic with fixed intervals")

    except KeyboardInterrupt:
        simulator.running = False
        print("\n⚠️  Scenario interrupted by user")
        print("Partial results may have been logged")

    except Exception as e:
        print(f"\n❌ Error during scenario execution: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
