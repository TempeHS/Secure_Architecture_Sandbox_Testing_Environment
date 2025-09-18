#!/usr/bin/env python3
"""
Basic Network Activity Generator
Educational tool for demonstrating normal network behaviour patterns.

This script generates legitimate network activity to establish baseline
patterns for comparison with suspicious traffic.

Author: Secure Architecture Sandbox Testing Environment
Purpose: Educational cybersecurity training
"""

import time
import threading
import requests
import socket
import subprocess
import sys
from datetime import datetime
import json
import random


class BasicNetworkActivity:
    """Generates normal network activity for baseline comparison."""

    def __init__(self):
        self.activity_log = []
        self.running = False

    def log_activity(self, activity_type, details):
        """Log network activity with timestamp."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'type': activity_type,
            'details': details
        }
        self.activity_log.append(entry)
        print(f"[{entry['timestamp']}] {activity_type}: {details}")

    def generate_web_requests(self, duration=60):
        """Generate normal web browsing patterns."""
        print(f"\n🌐 Generating web requests for {duration} seconds...")

        # Common legitimate websites for testing
        test_sites = [
            'http://httpbin.org/get',
            'http://httpbin.org/json',
            'http://httpbin.org/user-agent',
            'http://httpbin.org/headers'
        ]

        start_time = time.time()
        request_count = 0

        while time.time() - start_time < duration and self.running:
            try:
                site = random.choice(test_sites)
                response = requests.get(site, timeout=5)
                request_count += 1

                self.log_activity(
                    'HTTP_REQUEST',
                    f"GET {site} - Status: {response.status_code}"
                )

                # Realistic browsing delay
                time.sleep(random.uniform(2, 8))

            except requests.RequestException as e:
                self.log_activity('HTTP_ERROR', f"Request failed: {str(e)}")
                time.sleep(5)

        print(f"✅ Completed {request_count} web requests")

    def generate_dns_queries(self, duration=60):
        """Generate normal DNS resolution patterns."""
        print(f"\n🔍 Generating DNS queries for {duration} seconds...")

        # Common legitimate domains
        domains = [
            'google.com',
            'github.com',
            'stackoverflow.com',
            'python.org',
            'docker.com',
            'microsoft.com'
        ]

        start_time = time.time()
        query_count = 0

        while time.time() - start_time < duration and self.running:
            try:
                domain = random.choice(domains)

                # Perform DNS lookup
                ip_address = socket.gethostbyname(domain)
                query_count += 1

                self.log_activity(
                    'DNS_QUERY',
                    f"Resolved {domain} to {ip_address}"
                )

                time.sleep(random.uniform(1, 5))

            except socket.gaierror as e:
                self.log_activity(
                    'DNS_ERROR', f"DNS resolution failed: {str(e)}")
                time.sleep(3)

        print(f"✅ Completed {query_count} DNS queries")

    def check_service_connectivity(self):
        """Check connectivity to common legitimate services."""
        print(f"\n🔌 Checking service connectivity...")

        services = [
            ('google.com', 80),
            ('github.com', 443),
            ('stackoverflow.com', 443)
        ]

        for host, port in services:
            try:
                with socket.create_connection((host, port), timeout=5) as sock:
                    self.log_activity(
                        'SERVICE_CHECK',
                        f"Connection to {host}:{port} successful"
                    )
            except socket.error as e:
                self.log_activity(
                    'SERVICE_ERROR',
                    f"Connection to {host}:{port} failed: {str(e)}"
                )

        print("✅ Service connectivity cheques completed")

    def generate_local_activity(self, duration=60):
        """Generate normal local network activity."""
        print(
            f"\n🏠 Generating local network activity for {duration} seconds...")

        start_time = time.time()
        activity_count = 0

        while time.time() - start_time < duration and self.running:
            try:
                # Test local connectivity
                with socket.create_connection(('127.0.0.1', 22), timeout=1) as sock:
                    self.log_activity(
                        'LOCAL_CONNECTION',
                        'Connected to local SSH service'
                    )
                    activity_count += 1
            except socket.error:
                # SSH might not be running, that's okay
                pass

            try:
                # Test DNS resolution
                socket.gethostbyname('localhost')
                self.log_activity(
                    'LOCAL_DNS',
                    'Resolved localhost successfully'
                )
                activity_count += 1
            except socket.error as e:
                self.log_activity(
                    'LOCAL_ERROR',
                    f"Local DNS failed: {str(e)}"
                )

            time.sleep(random.uniform(3, 10))

        print(f"✅ Completed {activity_count} local network activities")

    def run_scenario(self, duration=180):
        """Run the complete basic network activity scenario."""
        print("🚀 Starting Basic Network Activity Scenario")
        print("=" * 50)
        print(f"Duration: {duration} seconds")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        self.running = True
        self.activity_log = []

        # Run different activities in parallel threads
        activities = [
            threading.Thread(target=self.generate_web_requests,
                             args=(duration//3,)),
            threading.Thread(target=self.generate_dns_queries,
                             args=(duration//3,)),
            threading.Thread(
                target=self.generate_local_activity, args=(duration//3,))
        ]

        # Start all activities
        for activity in activities:
            activity.start()

        # Run service connectivity check
        time.sleep(5)
        self.check_service_connectivity()

        # Wait for all activities to complete
        for activity in activities:
            activity.join()

        self.running = False

        print("\n" + "=" * 50)
        print("✅ Basic Network Activity Scenario Complete")
        print(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total activities logged: {len(self.activity_log)}")

        return self.activity_log

    def save_report(self, filename=None):
        """Save activity report to file."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"basic_network_activity_{timestamp}.json"

        report = {
            'scenario': 'Basic Network Activity',
            'start_time': self.activity_log[0]['timestamp'] if self.activity_log else datetime.now().isoformat(),
            'end_time': self.activity_log[-1]['timestamp'] if self.activity_log else datetime.now().isoformat(),
            'total_activities': len(self.activity_log),
            'activities': self.activity_log,
            'summary': {
                'http_requests': len([a for a in self.activity_log if a['type'] == 'HTTP_REQUEST']),
                'dns_queries': len([a for a in self.activity_log if a['type'] == 'DNS_QUERY']),
                'local_connections': len([a for a in self.activity_log if a['type'] == 'LOCAL_CONNECTION']),
                'service_checks': len([a for a in self.activity_log if a['type'] == 'SERVICE_CHECK']),
                'errors': len([a for a in self.activity_log if 'ERROR' in a['type']])
            }
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📄 Report saved to: {filename}")
        return filename


def main():
    """Main function to run the basic network activity scenario."""
    print("🎓 Basic Network Activity Generator")
    print("Educational Cybersecurity Tool")
    print()

    # Parse command line arguments
    duration = 180  # Default 3 minutes
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("❌ Invalid duration. Using default 180 seconds.")

    print(f"⏱️  Scenario duration: {duration} seconds")
    print("\n📋 This scenario will generate:")
    print("  • Normal web browsing requests")
    print("  • Legitimate DNS queries")
    print("  • Local network connectivity tests")
    print("  • Service availability cheques")
    print()

    input("Press Enter to start the scenario...")
    print()

    # Create and run scenario
    generator = BasicNetworkActivity()

    try:
        activity_log = generator.run_scenario(duration)

        # Save report
        report_file = generator.save_report()

        print("\n📊 Activity Summary:")
        print(f"  • Total activities: {len(activity_log)}")
        print(
            f"  • HTTP requests: {len([a for a in activity_log if a['type'] == 'HTTP_REQUEST'])}")
        print(
            f"  • DNS queries: {len([a for a in activity_log if a['type'] == 'DNS_QUERY'])}")
        print(
            f"  • Local connections: {len([a for a in activity_log if a['type'] == 'LOCAL_CONNECTION'])}")
        print(
            f"  • Service cheques: {len([a for a in activity_log if a['type'] == 'SERVICE_CHECK'])}")
        print(
            f"  • Errors: {len([a for a in activity_log if 'ERROR' in a['type']])}")

        print("\n🔍 Analysis Instructions:")
        print("  1. Use network monitoring tools to observe this traffic")
        print("  2. Compare patterns with suspicious traffic scenarios")
        print("  3. Document normal baseline behaviour for future reference")
        print(f"  4. Review detailed report: {report_file}")

        print("\n💡 Educational Notes:")
        print("  • This represents normal, legitimate network activity")
        print("  • Regular intervals and common destinations are typical")
        print("  • Error rates should be low in normal scenarios")
        print("  • Use this as baseline for comparison with threat scenarios")

    except KeyboardInterrupt:
        generator.running = False
        print("\n⚠️  Scenario interrupted by user")
        print("Partial results may have been logged")

    except Exception as e:
        print(f"\n❌ Error during scenario execution: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
