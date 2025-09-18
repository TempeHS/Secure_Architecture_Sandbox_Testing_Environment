#!/usr/bin/env python3
"""
Suspicious Traffic Generator
Educational tool for demonstrating suspicious network behavior patterns.

This script generates network patterns that indicate potential security threats,
helping students learn to identify malicious network activity.

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
import subprocess


class SuspiciousTrafficGenerator:
    """Generates suspicious network activity patterns for educational purposes."""

    def __init__(self):
        self.activity_log = []
        self.running = False

    def log_activity(self, activity_type, details, risk_level="MEDIUM"):
        """Log suspicious network activity with timestamp and risk assessment."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'type': activity_type,
            'details': details,
            'risk_level': risk_level,
            'educational_note': self._get_educational_note(activity_type)
        }
        self.activity_log.append(entry)
        print(f"[{entry['timestamp']}] {risk_level} - {activity_type}: {details}")

    def _get_educational_note(self, activity_type):
        """Get educational explanation for each activity type."""
        notes = {
            'PORT_SCAN': 'Port scanning is often the first step in network reconnaissance attacks',
            'BACKDOOR_CONNECTION': 'Connections to common backdoor ports indicate potential malware infection',
            'UNUSUAL_DNS': 'Unusual DNS patterns may indicate data exfiltration or C&C communication',
            'RAPID_CONNECTIONS': 'Rapid connection attempts may indicate automated attacks or malware',
            'EXTERNAL_DATA': 'Large data transfers to external IPs may indicate data exfiltration',
            'SUSPICIOUS_PORT': 'Connections on non-standard ports may indicate malicious activity',
            'REPEATED_FAILURES': 'Repeated connection failures may indicate brute force attacks'
        }
        return notes.get(activity_type, 'Analyze this pattern for potential security implications')

    def simulate_port_scanning(self, target='127.0.0.1', duration=60):
        """Simulate port scanning behavior - a common reconnaissance technique."""
        print(
            f"\n🔍 Simulating port scan against {target} for {duration} seconds...")

        # Common ports that attackers typically scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135,
                        139, 143, 443, 993, 995, 1433, 3306, 3389, 5900]

        start_time = time.time()
        scan_count = 0

        while time.time() - start_time < duration and self.running:
            port = random.choice(common_ports)

            try:
                # Attempt connection with very short timeout (typical of port scans)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Very short timeout - characteristic of scanning
                sock.settimeout(0.1)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:
                    self.log_activity(
                        'PORT_SCAN',
                        f"Port {port} on {target} is open",
                        'HIGH'
                    )
                else:
                    self.log_activity(
                        'PORT_SCAN',
                        f"Port {port} on {target} is closed/filtered",
                        'MEDIUM'
                    )

                scan_count += 1

                # Rapid scanning - suspicious behavior
                time.sleep(random.uniform(0.1, 0.5))

            except Exception as e:
                self.log_activity(
                    'PORT_SCAN',
                    f"Scan error on port {port}: {str(e)}",
                    'LOW'
                )

        print(f"⚠️  Completed {scan_count} port scan attempts")

    def simulate_backdoor_connections(self, duration=60):
        """Simulate connections to common backdoor/malware ports."""
        print(f"\n🚪 Simulating backdoor connections for {duration} seconds...")

        # Known backdoor/malware ports
        backdoor_ports = [4444, 6666, 1337, 31337, 12345, 54321, 1234, 9999]

        start_time = time.time()
        connection_count = 0

        while time.time() - start_time < duration and self.running:
            port = random.choice(backdoor_ports)
            target = '127.0.0.1'  # Simulate local backdoor

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                sock.close()

                self.log_activity(
                    'BACKDOOR_CONNECTION',
                    f"Attempted connection to backdoor port {port}",
                    'CRITICAL'
                )

                connection_count += 1

                # Simulate periodic beacon behavior
                time.sleep(random.uniform(5, 15))

            except Exception as e:
                self.log_activity(
                    'BACKDOOR_CONNECTION',
                    f"Backdoor connection attempt failed: {str(e)}",
                    'HIGH'
                )

        print(f"🚨 Completed {connection_count} backdoor connection attempts")

    def simulate_dns_tunneling(self, duration=60):
        """Simulate DNS tunneling patterns for data exfiltration."""
        print(f"\n🕳️  Simulating DNS tunneling for {duration} seconds...")

        start_time = time.time()
        query_count = 0

        while time.time() - start_time < duration and self.running:
            # Generate suspicious DNS query patterns
            # Long subdomains typical of DNS tunneling
            random_data = ''.join(random.choices('abcdef0123456789', k=32))
            suspicious_domain = f"{random_data}.suspicious-domain.com"

            try:
                # Attempt DNS resolution (will fail, but generates suspicious traffic)
                socket.gethostbyname(suspicious_domain)
            except socket.gaierror:
                # Expected to fail - the pattern is what's important
                pass

            self.log_activity(
                'UNUSUAL_DNS',
                f"DNS query for suspicious domain: {suspicious_domain}",
                'HIGH'
            )

            query_count += 1

            # High frequency DNS queries - suspicious pattern
            time.sleep(random.uniform(0.5, 2))

        print(f"🔍 Generated {query_count} suspicious DNS queries")

    def simulate_rapid_connections(self, duration=60):
        """Simulate rapid connection attempts typical of automated attacks."""
        print(
            f"\n⚡ Simulating rapid connection attempts for {duration} seconds...")

        start_time = time.time()
        attempt_count = 0

        while time.time() - start_time < duration and self.running:
            # Rapid connection attempts to various ports
            port = random.choice([22, 80, 443, 21, 23, 3389])
            target = '127.0.0.1'

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)  # Very short timeout
                result = sock.connect_ex((target, port))
                sock.close()

                self.log_activity(
                    'RAPID_CONNECTIONS',
                    f"Rapid connection attempt to {target}:{port}",
                    'MEDIUM'
                )

                attempt_count += 1

                # Very rapid attempts - characteristic of automated tools
                time.sleep(random.uniform(0.1, 0.3))

            except Exception as e:
                self.log_activity(
                    'RAPID_CONNECTIONS',
                    f"Rapid connection failed: {str(e)}",
                    'LOW'
                )

        print(f"⚡ Completed {attempt_count} rapid connection attempts")

    def simulate_unusual_ports(self, duration=60):
        """Simulate connections on unusual/non-standard ports."""
        print(
            f"\n🔌 Simulating unusual port activity for {duration} seconds...")

        # Unusual/suspicious ports
        unusual_ports = [8080, 8443, 9090, 7777, 8888, 2222, 4444, 5555]

        start_time = time.time()
        connection_count = 0

        while time.time() - start_time < duration and self.running:
            port = random.choice(unusual_ports)
            target = '127.0.0.1'

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()

                self.log_activity(
                    'SUSPICIOUS_PORT',
                    f"Connection attempt to unusual port {port}",
                    'MEDIUM'
                )

                connection_count += 1

                time.sleep(random.uniform(2, 8))

            except Exception as e:
                self.log_activity(
                    'SUSPICIOUS_PORT',
                    f"Unusual port connection failed: {str(e)}",
                    'LOW'
                )

        print(f"🔌 Completed {connection_count} unusual port connections")

    def run_scenario(self, duration=300):
        """Run the complete suspicious traffic scenario."""
        print("🚨 Starting Suspicious Traffic Generation Scenario")
        print("=" * 50)
        print(f"Duration: {duration} seconds")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        print("⚠️  WARNING: This generates suspicious network patterns for education")
        print("   Use only in controlled environments for learning purposes")
        print()

        self.running = True
        self.activity_log = []

        # Run different suspicious activities in parallel
        activities = [
            threading.Thread(target=self.simulate_port_scanning,
                             args=('127.0.0.1', duration//5)),
            threading.Thread(
                target=self.simulate_backdoor_connections, args=(duration//5,)),
            threading.Thread(target=self.simulate_dns_tunneling,
                             args=(duration//5,)),
            threading.Thread(
                target=self.simulate_rapid_connections, args=(duration//5,)),
            threading.Thread(
                target=self.simulate_unusual_ports, args=(duration//5,))
        ]

        # Start activities with staggered timing
        for i, activity in enumerate(activities):
            activity.start()
            time.sleep(2)  # Slight delay between starting each activity

        # Wait for all activities to complete
        for activity in activities:
            activity.join()

        self.running = False

        print("\n" + "=" * 50)
        print("🚨 Suspicious Traffic Generation Complete")
        print(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total suspicious activities: {len(self.activity_log)}")

        return self.activity_log

    def save_report(self, filename=None):
        """Save suspicious activity report to file."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"suspicious_traffic_{timestamp}.json"

        # Categorize activities by risk level
        risk_summary = {
            'CRITICAL': len([a for a in self.activity_log if a['risk_level'] == 'CRITICAL']),
            'HIGH': len([a for a in self.activity_log if a['risk_level'] == 'HIGH']),
            'MEDIUM': len([a for a in self.activity_log if a['risk_level'] == 'MEDIUM']),
            'LOW': len([a for a in self.activity_log if a['risk_level'] == 'LOW'])
        }

        report = {
            'scenario': 'Suspicious Traffic Generation',
            'start_time': self.activity_log[0]['timestamp'] if self.activity_log else datetime.now().isoformat(),
            'end_time': self.activity_log[-1]['timestamp'] if self.activity_log else datetime.now().isoformat(),
            'total_activities': len(self.activity_log),
            'risk_summary': risk_summary,
            'activities': self.activity_log,
            'educational_objectives': [
                'Identify port scanning patterns',
                'Recognize backdoor communication attempts',
                'Detect DNS tunneling indicators',
                'Spot rapid/automated connection patterns',
                'Understand risk levels of different activities'
            ],
            'detection_indicators': [
                'Rapid sequential port connections',
                'Connections to known backdoor ports',
                'High-frequency DNS queries with long subdomains',
                'Automated connection patterns',
                'Unusual port usage'
            ]
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📄 Suspicious traffic report saved to: {filename}")
        return filename


def main():
    """Main function to run the suspicious traffic scenario."""
    print("🚨 Suspicious Traffic Generator")
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
    print("\n🚨 This scenario will generate:")
    print("  • Port scanning patterns")
    print("  • Backdoor connection attempts")
    print("  • DNS tunneling simulation")
    print("  • Rapid connection patterns")
    print("  • Unusual port activity")
    print()
    print("⚠️  Educational Use Only - Controlled Environment Required")
    print()

    input("Press Enter to start generating suspicious traffic...")
    print()

    # Create and run scenario
    generator = SuspiciousTrafficGenerator()

    try:
        activity_log = generator.run_scenario(duration)

        # Save report
        report_file = generator.save_report()

        # Display summary
        risk_counts = {
            'CRITICAL': len([a for a in activity_log if a['risk_level'] == 'CRITICAL']),
            'HIGH': len([a for a in activity_log if a['risk_level'] == 'HIGH']),
            'MEDIUM': len([a for a in activity_log if a['risk_level'] == 'MEDIUM']),
            'LOW': len([a for a in activity_log if a['risk_level'] == 'LOW'])
        }

        print("\n📊 Suspicious Activity Summary:")
        print(f"  • Total activities: {len(activity_log)}")
        print(f"  • CRITICAL risk: {risk_counts['CRITICAL']}")
        print(f"  • HIGH risk: {risk_counts['HIGH']}")
        print(f"  • MEDIUM risk: {risk_counts['MEDIUM']}")
        print(f"  • LOW risk: {risk_counts['LOW']}")

        print("\n🔍 Analysis Instructions:")
        print("  1. Compare this traffic with baseline normal activity")
        print("  2. Identify patterns that distinguish malicious behavior")
        print("  3. Note the risk levels and educational explanations")
        print(f"  4. Review detailed analysis in: {report_file}")

        print("\n💡 Key Learning Points:")
        print("  • Port scanning creates distinctive connection patterns")
        print("  • Backdoor ports are immediate red flags")
        print("  • DNS tunneling uses unusual domain structures")
        print("  • Automated attacks show rapid, repetitive patterns")
        print("  • Context and frequency matter in threat detection")

    except KeyboardInterrupt:
        generator.running = False
        print("\n⚠️  Scenario interrupted by user")
        print("Partial results may have been logged")

    except Exception as e:
        print(f"\n❌ Error during scenario execution: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
