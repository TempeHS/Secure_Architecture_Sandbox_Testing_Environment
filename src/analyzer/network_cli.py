#!/usr/bin/env python3
"""
Network Traffic Analysis CLI Tool
Command-line interface for network security analysis and monitoring.

This tool provides comprehensive network traffic analysis capabilities
including connection monitoring, service scanning, and threat detection.
Operates independently from SAST and DAST tools for educational clarity.

Usage:
    python src/analyzer/network_cli.py --monitor-connections
    python src/analyzer/network_cli.py --scan-services localhost
    python src/analyzer/network_cli.py --capture-traffic --duration 60
    python src/analyzer/network_cli.py --dns-analysis --duration 30

Author: Cybersecurity Education Platform
License: Educational Use Only
"""

from analyzer.vulnerability_database import VulnerabilityDatabase
from analyzer.network_analyzer import NetworkAnalyzer
import argparse
import sys
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import the report generator for markdown output
try:
    from reporter.report_generator import MarkdownReportGenerator
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False
    print("Warning: Markdown report generation not available")


class NetworkCLI:
    """
    Command-line interface for network traffic analysis

    Provides educational network security analysis tools with
    comprehensive reporting and threat detection capabilities.
    """

    def __init__(self):
        """Initialize the network analysis CLI"""
        self.vuln_db = VulnerabilityDatabase()

    def run(self) -> int:
        """Main CLI execution method"""
        parser = self._create_argument_parser()
        args = parser.parse_args()

        try:
            # Handle different analysis modes
            if args.monitor_connections:
                return self._handle_connection_monitoring(args)
            elif args.scan_services:
                return self._handle_service_scanning(args)
            elif args.capture_traffic:
                return self._handle_traffic_capture(args)
            elif args.dns_analysis:
                return self._handle_dns_analysis(args)
            elif args.demo_network:
                return self._handle_demo_mode(args)
            else:
                parser.print_help()
                return 1

        except KeyboardInterrupt:
            print("\n\n⚠️  Analysis interrupted by user")
            return 1
        except Exception as e:
            print(f"\n❌ Error during analysis: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    def _create_argument_parser(self) -> argparse.ArgumentParser:
        """Create and configure argument parser"""
        parser = argparse.ArgumentParser(
            description="Network Traffic Analysis Tool - Educational Cybersecurity Platform",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Monitor active network connections
  python src/analyzer/network_cli.py --monitor-connections

  # Scan services on localhost
  python src/analyzer/network_cli.py --scan-services localhost

  # Capture and analyze network traffic
  python src/analyzer/network_cli.py --capture-traffic --duration 60

  # Analyze DNS traffic patterns
  python src/analyzer/network_cli.py --dns-analysis --duration 30

  # Run demo with educational explanations
  python src/analyzer/network_cli.py --demo-network --educational

Analysis Types:
  --monitor-connections    Monitor active network connections
  --scan-services TARGET   Scan network services on target
  --capture-traffic        Capture and analyze network traffic
  --dns-analysis          Analyze DNS traffic patterns
  --demo-network          Run network analysis demonstration

Output Options:
  --output PATH           Save report to specified file
  --format FORMAT         Report format: json, text (default: text)
  --educational           Enable detailed educational explanations
  --quiet                 Suppress progress output
  --verbose               Enable verbose output
            """
        )

        # Analysis type arguments (mutually exclusive)
        analysis_group = parser.add_mutually_exclusive_group(required=True)
        analysis_group.add_argument(
            '--monitor-connections',
            action='store_true',
            help='Monitor active network connections for suspicious activity'
        )
        analysis_group.add_argument(
            '--scan-services',
            metavar='TARGET',
            help='Scan network services on target (IP address or hostname)'
        )
        analysis_group.add_argument(
            '--capture-traffic',
            action='store_true',
            help='Capture and analyze network traffic patterns'
        )
        analysis_group.add_argument(
            '--dns-analysis',
            action='store_true',
            help='Analyze DNS traffic for suspicious patterns'
        )
        analysis_group.add_argument(
            '--demo-network',
            action='store_true',
            help='Run network analysis demonstration with sample data'
        )

        # Analysis configuration
        parser.add_argument(
            '--interface',
            default='any',
            help='Network interface to monitor (default: any)'
        )
        parser.add_argument(
            '--duration',
            type=int,
            default=60,
            help='Analysis duration in seconds (default: 60)'
        )
        parser.add_argument(
            '--filter',
            help='Packet capture filter expression'
        )

        # Output configuration
        parser.add_argument(
            '--output',
            help='Output file path (auto-generates if not specified)'
        )
        parser.add_argument(
            '--format',
            choices=['json', 'text'],
            default='text',
            help='Output format (default: text)'
        )

        # Mode configuration
        parser.add_argument(
            '--educational',
            action='store_true',
            help='Enable detailed educational explanations and insights'
        )
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress progress output (useful for automation)'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output for debugging'
        )

        return parser

    def _handle_connection_monitoring(self, args) -> int:
        """Handle active connection monitoring"""
        if not args.quiet:
            print("🌐 NETWORK CONNECTION MONITORING")
            print("=" * 60)

        analyzer = NetworkAnalyzer(
            interface=args.interface,
            educational_mode=args.educational
        )

        # Monitor active connections
        results = analyzer.monitor_active_connections()

        # Generate and save report
        report_path = self._generate_report(
            results, args, "connection_monitoring")

        # Display results
        self._display_connection_results(results, args)

        if not args.quiet and report_path:
            print(f"\n📄 Report saved to: {report_path}")

        return 0

    def _handle_service_scanning(self, args) -> int:
        """Handle network service scanning"""
        target = args.scan_services

        if not args.quiet:
            print("🔍 NETWORK SERVICE SCANNING")
            print("=" * 60)
            print(f"Target: {target}")

        analyzer = NetworkAnalyzer(
            interface=args.interface,
            educational_mode=args.educational
        )

        # Scan network services
        results = analyzer.scan_network_services(target)

        # Generate and save report
        report_path = self._generate_report(results, args, "service_scan")

        # Display results
        self._display_service_results(results, args)

        if not args.quiet and report_path:
            print(f"\n📄 Report saved to: {report_path}")

        return 0

    def _handle_traffic_capture(self, args) -> int:
        """Handle network traffic capture and analysis"""
        if not args.quiet:
            print("📡 NETWORK TRAFFIC CAPTURE & ANALYSIS")
            print("=" * 60)
            print(f"Duration: {args.duration} seconds")
            if args.filter:
                print(f"Filter: {args.filter}")

        analyzer = NetworkAnalyzer(
            interface=args.interface,
            educational_mode=args.educational
        )

        # Capture and analyze traffic
        results = analyzer.start_packet_capture(args.duration, args.filter)

        # Generate and save report
        report_path = self._generate_report(results, args, "traffic_capture")

        # Display results
        self._display_traffic_results(results, args)

        if not args.quiet and report_path:
            print(f"\n📄 Report saved to: {report_path}")

        return 0

    def _handle_dns_analysis(self, args) -> int:
        """Handle DNS traffic analysis"""
        if not args.quiet:
            print("🔍 DNS TRAFFIC ANALYSIS")
            print("=" * 60)
            print(f"Duration: {args.duration} seconds")

        analyzer = NetworkAnalyzer(
            interface=args.interface,
            educational_mode=args.educational
        )

        # Analyze DNS traffic
        results = analyzer.analyze_dns_traffic(args.duration)

        # Generate and save report
        report_path = self._generate_report(results, args, "dns_analysis")

        # Display results
        self._display_dns_results(results, args)

        if not args.quiet and report_path:
            print(f"\n📄 Report saved to: {report_path}")

        return 0

    def _handle_demo_mode(self, args) -> int:
        """Handle demonstration mode with sample data"""
        if not args.quiet:
            print("🎓 NETWORK ANALYSIS DEMONSTRATION")
            print("=" * 60)

        # Run all analysis types with demo data
        results = self._run_demo_analysis(args)

        # Generate and save report
        report_path = self._generate_report(results, args, "network_demo")

        # Display results
        self._display_demo_results(results, args)

        if not args.quiet and report_path:
            print(f"\n📄 Report saved to: {report_path}")

        return 0

    def _run_demo_analysis(self, args) -> Dict[str, Any]:
        """Run demonstration analysis with sample data"""
        analyzer = NetworkAnalyzer(educational_mode=True)

        # Simulate network analysis results
        demo_results = {
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'network_demonstration',
            'connection_monitoring': analyzer.monitor_active_connections(),
            'service_scanning': analyzer.scan_network_services('localhost'),
            'educational_insights': analyzer.generate_educational_insights(),
            'demo_mode': True
        }

        return demo_results

    def _display_connection_results(self, results: Dict[str, Any], args) -> None:
        """Display connection monitoring results"""
        if args.quiet:
            return

        connections = results.get('active_connections', [])
        suspicious = results.get('suspicious_connections', [])
        findings = results.get('findings', [])

        print(f"\n📊 CONNECTION ANALYSIS SUMMARY")
        print("-" * 40)
        print(f"Total Active Connections: {len(connections)}")
        print(f"Suspicious Connections: {len(suspicious)}")
        print(f"Security Findings: {len(findings)}")

        if suspicious:
            print(f"\n🚨 SUSPICIOUS CONNECTIONS ({len(suspicious)})")
            print("-" * 40)
            for i, conn in enumerate(suspicious[:5], 1):
                print(f"{i}. {conn.get('protocol', 'Unknown')} "
                      f"{conn.get('local_address', 'Unknown')} -> "
                      f"{conn.get('remote_address', 'Unknown')}")
                print(f"   Reason: {conn.get('reason', 'Unknown')}")
                print(f"   Risk: {conn.get('risk_level', 'Unknown')}")
                print()

        if findings:
            self._display_findings(findings, args)

    def _display_service_results(self, results: Dict[str, Any], args) -> None:
        """Display service scanning results"""
        if args.quiet:
            return

        services = results.get('discovered_services', [])
        analysis = results.get('security_analysis', {})
        findings = results.get('findings', [])

        print(f"\n📊 SERVICE SCAN SUMMARY")
        print("-" * 40)
        print(f"Target: {results.get('target', 'Unknown')}")
        print(f"Services Discovered: {len(services)}")
        print(f"Security Score: {analysis.get('security_score', 0)}/100")

        if services:
            print(f"\n🔍 DISCOVERED SERVICES ({len(services)})")
            print("-" * 40)
            for service in services:
                print(f"Port {service['port']}: {service['service']}")
                print(f"  Description: {service['description']}")
                print(f"  Security Note: {service['security_concern']}")
                print()

        if findings:
            self._display_findings(findings, args)

    def _display_traffic_results(self, results: Dict[str, Any], args) -> None:
        """Display traffic capture results"""
        if args.quiet:
            return

        if not results.get('success', True):
            print(
                f"\n❌ Traffic capture failed: {results.get('error', 'Unknown error')}")
            return

        summary = results.get('summary', {})
        findings = results.get('findings', [])

        print(f"\n📊 TRAFFIC ANALYSIS SUMMARY")
        print("-" * 40)
        print(
            f"Analysis Duration: {results.get('analysis_duration', 0):.1f} seconds")
        print(f"Packets Analyzed: {results.get('packet_count', 0)}")
        print(f"Unique IP Addresses: {results.get('unique_ips', 0)}")
        print(f"Security Findings: {summary.get('total_findings', 0)}")

        # Protocol breakdown
        protocols = results.get('protocol_breakdown', {})
        if protocols:
            print(f"\n📈 PROTOCOL BREAKDOWN")
            print("-" * 40)
            for protocol, count in protocols.items():
                print(f"{protocol}: {count}")

        if findings:
            self._display_findings(findings, args)

    def _display_dns_results(self, results: Dict[str, Any], args) -> None:
        """Display DNS analysis results"""
        if args.quiet:
            return

        dns_analysis = results.get('dns_analysis', {})
        suspicious_queries = dns_analysis.get('suspicious_queries', [])
        findings = results.get('findings', [])

        print(f"\n📊 DNS ANALYSIS SUMMARY")
        print("-" * 40)
        print(f"Total DNS Queries: {dns_analysis.get('total_queries', 0)}")
        print(f"Suspicious Queries: {len(suspicious_queries)}")

        if suspicious_queries:
            print(f"\n🚨 SUSPICIOUS DNS QUERIES ({len(suspicious_queries)})")
            print("-" * 40)
            for query in suspicious_queries[:5]:
                print(f"Domain: {query['domain']}")
                print(f"Reason: {query['reason']}")
                print(f"Risk Level: {query['risk_level']}")
                print()

        if findings:
            self._display_findings(findings, args)

    def _display_demo_results(self, results: Dict[str, Any], args) -> None:
        """Display demonstration results"""
        if args.quiet:
            return

        print("\n🎓 EDUCATIONAL NETWORK ANALYSIS DEMONSTRATION")
        print("=" * 60)

        # Display connection monitoring demo
        conn_results = results.get('connection_monitoring', {})
        if conn_results:
            print("\n1. CONNECTION MONITORING ANALYSIS")
            self._display_connection_results(conn_results, args)

        # Display service scanning demo
        service_results = results.get('service_scanning', {})
        if service_results:
            print("\n2. NETWORK SERVICE SCANNING")
            self._display_service_results(service_results, args)

        # Display educational insights
        insights = results.get('educational_insights', {})
        if insights and args.educational:
            self._display_educational_insights(insights)

    def _display_findings(self, findings: list, args) -> None:
        """Display security findings"""
        if not findings or args.quiet:
            return

        # Group findings by severity
        high = [f for f in findings if f.get('severity') == 'high']
        medium = [f for f in findings if f.get('severity') == 'medium']
        low = [f for f in findings if f.get('severity') == 'low']

        print(f"\n🔍 SECURITY FINDINGS ({len(findings)} total)")
        print("-" * 40)

        # Display high severity findings
        if high:
            print(f"\n🚨 HIGH SEVERITY ({len(high)} findings)")
            for i, finding in enumerate(high, 1):
                print(f"\n{i}. {finding.get('title', 'Unknown Issue')}")
                print(
                    f"   Description: {finding.get('description', 'No description')}")
                if args.educational and finding.get('educational_note'):
                    print(
                        f"   📚 Educational Note: {finding['educational_note']}")

        # Display medium severity findings
        if medium:
            print(f"\n🟡 MEDIUM SEVERITY ({len(medium)} findings)")
            for i, finding in enumerate(medium, 1):
                print(f"\n{i}. {finding.get('title', 'Unknown Issue')}")
                print(
                    f"   Description: {finding.get('description', 'No description')}")
                if args.educational and finding.get('educational_note'):
                    print(
                        f"   📚 Educational Note: {finding['educational_note']}")

        # Display low severity findings
        if low and args.verbose:
            print(f"\n🔵 LOW SEVERITY ({len(low)} findings)")
            for i, finding in enumerate(low, 1):
                print(f"\n{i}. {finding.get('title', 'Unknown Issue')}")
                print(
                    f"   Description: {finding.get('description', 'No description')}")

    def _display_educational_insights(self, insights: Dict[str, Any]) -> None:
        """Display educational insights about network security"""
        print(f"\n🎓 EDUCATIONAL INSIGHTS")
        print("=" * 60)

        concepts = insights.get('network_security_concepts', [])
        if concepts:
            print(f"\n📚 Network Security Concepts:")
            for i, concept in enumerate(concepts, 1):
                print(f"  {i}. {concept}")

        practices = insights.get('monitoring_best_practices', [])
        if practices:
            print(f"\n🛡️  Monitoring Best Practices:")
            for i, practice in enumerate(practices, 1):
                print(f"  {i}. {practice}")

        indicators = insights.get('threat_indicators', [])
        if indicators:
            print(f"\n🚨 Threat Indicators to Watch For:")
            for i, indicator in enumerate(indicators, 1):
                print(f"  {i}. {indicator}")

    def _generate_report(self, results: Dict[str, Any], args, analysis_type: str) -> Optional[str]:
        """Generate and save analysis report"""
        if args.format == 'json':
            return self._save_json_report(results, args, analysis_type)
        else:
            return self._save_text_report(results, args, analysis_type)

    def _save_json_report(self, results: Dict[str, Any], args, analysis_type: str) -> Optional[str]:
        """Save results as JSON report"""
        output_path = self._resolve_output_path(
            args.output, analysis_type, 'json')

        try:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)

            # Generate markdown report alongside JSON if available
            if MARKDOWN_AVAILABLE:
                try:
                    markdown_generator = MarkdownReportGenerator()

                    # Generate base filename without extension
                    base_path = os.path.splitext(output_path)[0]
                    markdown_filename = os.path.basename(f"{base_path}.md")

                    # Generate markdown content based on analysis type
                    if analysis_type in ['network', 'traffic', 'connections',
                                         'dns', 'connection_monitoring',
                                         'service_scan', 'traffic_capture',
                                         'dns_analysis', 'network_demo']:
                        generated_path = (
                            markdown_generator.generate_markdown_report(
                                results, 'network', markdown_filename))
                    else:
                        generated_path = (
                            markdown_generator.generate_markdown_report(
                                results, 'general', markdown_filename))

                    if not args.quiet:
                        print(f"✓ Markdown report saved: {generated_path}")

                except Exception as e:
                    if not args.quiet:
                        print(f"Warning: Failed to generate markdown "
                              f"report: {e}")

            return output_path
        except Exception as e:
            if not args.quiet:
                print(f"Warning: Could not save JSON report: {e}")
            return None

    def _save_text_report(self, results: Dict[str, Any], args, analysis_type: str) -> Optional[str]:
        """Save results as text report"""
        output_path = self._resolve_output_path(
            args.output, analysis_type, 'txt')

        try:
            with open(output_path, 'w') as f:
                f.write(self._format_text_report(results, args, analysis_type))
            return output_path
        except Exception as e:
            if not args.quiet:
                print(f"Warning: Could not save text report: {e}")
            return None

    def _format_text_report(self, results: Dict[str, Any], args, analysis_type: str) -> str:
        """Format results as text report"""
        report_lines = [
            "🌐 NETWORK TRAFFIC ANALYSIS REPORT",
            "=" * 60,
            f"Analysis Type: {analysis_type.replace('_', ' ').title()}",
            f"Timestamp: {results.get('timestamp', 'Unknown')}",
            f"Educational Mode: {'Enabled' if args.educational else 'Disabled'}",
            ""
        ]

        # Add analysis-specific content
        if analysis_type == 'connection_monitoring':
            self._add_connection_report_content(report_lines, results)
        elif analysis_type == 'service_scan':
            self._add_service_report_content(report_lines, results)
        elif analysis_type == 'traffic_capture':
            self._add_traffic_report_content(report_lines, results)
        elif analysis_type == 'dns_analysis':
            self._add_dns_report_content(report_lines, results)
        elif analysis_type == 'network_demo':
            self._add_demo_report_content(report_lines, results)

        # Add findings
        findings = results.get('findings', [])
        if findings:
            report_lines.extend([
                "",
                f"🔍 SECURITY FINDINGS ({len(findings)} total)",
                "-" * 40
            ])

            for i, finding in enumerate(findings, 1):
                report_lines.extend([
                    f"\n{i}. {finding.get('title', 'Unknown Issue')}",
                    f"   Severity: {finding.get('severity', 'Unknown').upper()}",
                    f"   Description: {finding.get('description', 'No description')}"
                ])

                if args.educational and finding.get('educational_note'):
                    report_lines.append(
                        f"   Educational Note: {finding['educational_note']}")

        return '\n'.join(report_lines)

    def _add_connection_report_content(self, lines: list, results: Dict[str, Any]) -> None:
        """Add connection monitoring content to report"""
        connections = results.get('active_connections', [])
        suspicious = results.get('suspicious_connections', [])

        lines.extend([
            "📊 CONNECTION ANALYSIS SUMMARY",
            f"Total Active Connections: {len(connections)}",
            f"Suspicious Connections: {len(suspicious)}",
            ""
        ])

    def _add_service_report_content(self, lines: list, results: Dict[str, Any]) -> None:
        """Add service scanning content to report"""
        services = results.get('discovered_services', [])
        analysis = results.get('security_analysis', {})

        lines.extend([
            "📊 SERVICE SCAN SUMMARY",
            f"Target: {results.get('target', 'Unknown')}",
            f"Services Discovered: {len(services)}",
            f"Security Score: {analysis.get('security_score', 0)}/100",
            ""
        ])

    def _add_traffic_report_content(self, lines: list, results: Dict[str, Any]) -> None:
        """Add traffic capture content to report"""
        summary = results.get('summary', {})

        lines.extend([
            "📊 TRAFFIC ANALYSIS SUMMARY",
            f"Analysis Duration: {results.get('analysis_duration', 0):.1f} seconds",
            f"Packets Analyzed: {results.get('packet_count', 0)}",
            f"Unique IP Addresses: {results.get('unique_ips', 0)}",
            f"Security Findings: {summary.get('total_findings', 0)}",
            ""
        ])

    def _add_dns_report_content(self, lines: list, results: Dict[str, Any]) -> None:
        """Add DNS analysis content to report"""
        dns_analysis = results.get('dns_analysis', {})

        lines.extend([
            "📊 DNS ANALYSIS SUMMARY",
            f"Total DNS Queries: {dns_analysis.get('total_queries', 0)}",
            f"Suspicious Queries: {len(dns_analysis.get('suspicious_queries', []))}",
            ""
        ])

    def _add_demo_report_content(self, lines: list, results: Dict[str, Any]) -> None:
        """Add demonstration content to report"""
        lines.extend([
            "🎓 NETWORK ANALYSIS DEMONSTRATION",
            "This report contains demonstration data for educational purposes.",
            ""
        ])

    def _resolve_output_path(self, output_arg: Optional[str], analysis_type: str, extension: str) -> str:
        """Resolve output file path"""
        if output_arg:
            return output_arg

        # Auto-generate path in reports directory
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_{analysis_type}_{timestamp}.{extension}"

        return str(reports_dir / filename)


def main():
    """Main entry point"""
    cli = NetworkCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
