#!/usr/bin/env python3
"""
Dynamic Application Security Testing (DAST) Command-Line Interface

This script provides an easy-to-use CLI for running dynamic security analysis
on web applications. Unlike static analysis which examines code, DAST tests
running applications to find vulnerabilities that only appear during execution.

Usage Examples:
    # Basic scan of a web application
    python dast_cli.py http://localhost:5000

    # Deep scan with all available tools
    python dast_cli.py http://localhost:5000 --deep-scan

    # Scan with specific tools only
    python dast_cli.py http://localhost:5000 --tools nikto gobuster

    # Generate detailed educational report
    python dast_cli.py http://localhost:5000 --educational --output report.json

    # Scan all demo applications (must be running)
    python dast_cli.py --demo-apps

    # Quick vulnerability check
    python dast_cli.py http://localhost:5000 --quick
"""

from analyzer.vulnerability_database import vulnerability_db
from analyzer.dynamic_analyzer import (
    DynamicAnalyzer, DynamicAnalysisReport, analyze_demo_applications_dynamic, logger
)
import sys
import argparse
import json
import logging
import os
from pathlib import Path
from typing import List, Dict, Any

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the report generator for markdown output
try:
    from reporter.report_generator import MarkdownReportGenerator
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False
    logger.warning("Markdown report generation not available")


class DASTCLI:
    """Command-line interface for dynamic application security testing"""

    def __init__(self):
        self.analyzer = DynamicAnalyzer()

    def run_analysis(self, args) -> None:
        """Execute dynamic analysis based on command-line arguments"""

        if args.demo_apps:
            self._analyze_demo_applications(args)
            return

        if not args.target_url:
            print("Error: Target URL is required unless using --demo-apps")
            print("Example: python dast_cli.py http://localhost:5000")
            sys.exit(1)

        # Validate URL format
        if not args.target_url.startswith(('http://', 'https://')):
            print("Error: Target must be a valid URL starting with http:// or https://")
            sys.exit(1)

        try:
            # Configure scan options
            deep_scan = args.deep_scan and not args.quick
            tools = args.tools if args.tools else None

            print(
                f"🌐 Starting dynamic security analysis of: {args.target_url}")
            if deep_scan:
                print("🔍 Deep scan mode enabled - this may take several minutes")
            elif args.quick:
                print("⚡ Quick scan mode - basic vulnerability checks only")

            if tools:
                print(f"🛠️  Using tools: {', '.join(tools)}")

            # Run dynamic analysis
            report = self.analyzer.analyze_application(
                args.target_url,
                tools=tools,
                deep_scan=deep_scan
            )

            # Save report if requested
            if args.output:
                output_path = self._resolve_output_path(args.output, 'dast')
                self._save_report(report, output_path, args.format)
                print(f"📄 Report saved to: {output_path}")
            else:
                # Auto-save with timestamp if no output specified
                auto_output_path = self._generate_auto_output_path(
                    'dast', args.format)
                self._save_report(report, auto_output_path, args.format)
                print(f"📄 Report auto-saved to: {auto_output_path}")

            # Display results
            self._display_report(report, args.educational, args.verbose)

        except Exception as e:
            print(f"❌ Dynamic analysis failed: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    def _analyze_demo_applications(self, args) -> None:
        """Analyze all demo applications (must be running)"""
        print("🎯 Scanning all demo applications...")
        print("📝 Note: Applications must be running for dynamic analysis")
        print("   Start with: cd docker && docker-compose up -d")

        try:
            results = analyze_demo_applications_dynamic(args.educational)

            if not results:
                print("❌ No demo applications were accessible for scanning")
                print("💡 Make sure the applications are running:")
                print("   - Flask App: http://localhost:5000")
                print("   - PWA App: http://localhost:9090")
                return

            # Display summary for each app
            total_findings = 0
            for app_name, report in results.items():
                print(f"\n🔍 Application: {app_name}")
                print(f"   Target: {report.target_url}")
                print(f"   Duration: {report.scan_duration:.1f}s")
                print(f"   Findings: {len(report.findings)}")
                print(f"   Requests: {report.total_requests}")

                severity_summary = report.summary.get(
                    'severity_distribution', {})
                if any(severity_summary.values()):
                    print(f"   Severity breakdown:")
                    for severity, count in severity_summary.items():
                        if count > 0:
                            print(f"     {severity.capitalize()}: {count}")

                total_findings += len(report.findings)

            print(
                f"\n📊 Total findings across all applications: {total_findings}")

            # Save combined report if requested
            if args.output:
                output_path = self._resolve_output_path(
                    args.output, 'dast_demo')
                self._save_demo_report(results, output_path, args.format)
                print(f"📄 Combined report saved to: {output_path}")
            else:
                # Auto-save with timestamp if no output specified
                auto_output_path = self._generate_auto_output_path(
                    'dast_demo', args.format)
                self._save_demo_report(results, auto_output_path, args.format)
                print(f"📄 Combined report auto-saved to: {auto_output_path}")

        except Exception as e:
            print(f"❌ Demo analysis failed: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    def _display_report(self, report: DynamicAnalysisReport, educational: bool, verbose: bool) -> None:
        """Display analysis results in a user-friendly format"""

        print(f"\n🛡️ DYNAMIC SECURITY ANALYSIS REPORT")
        print("=" * 60)
        print(f"Target URL: {report.target_url}")
        print(f"Scan Duration: {report.scan_duration:.1f} seconds")
        print(f"Timestamp: {report.timestamp}")
        print(f"Tools Used: {', '.join(report.tools_used)}")
        print(f"Total Requests: {report.total_requests}")
        print(f"Successful Responses: {report.successful_responses}")
        print(f"Error Responses: {report.error_responses}")

        # Summary statistics
        summary = report.summary
        print(f"\n📊 SCAN SUMMARY")
        print("-" * 30)
        print(f"Total Findings: {summary['total_findings']}")

        severity_dist = summary['severity_distribution']
        if any(severity_dist.values()):
            print(f"Severity Distribution:")
            for severity, count in severity_dist.items():
                if count > 0:
                    emoji = self._get_severity_emoji(severity)
                    print(f"  {emoji} {severity.capitalize()}: {count}")

        if summary.get('risk_score'):
            print(f"Overall Risk Score: {summary['risk_score']:.1f}/100")

        # OWASP categories
        owasp_cats = summary.get('owasp_categories', {})
        if owasp_cats:
            print(f"\nOWASP Top 10 Categories Found:")
            for category, count in owasp_cats.items():
                print(f"  • {category}: {count} finding(s)")

        # Detailed findings
        if report.findings:
            print(f"\n🔍 DETAILED FINDINGS")
            print("-" * 40)

            # Group findings by severity
            findings_by_severity = {}
            for finding in report.findings:
                severity = finding.severity
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding)

            # Display findings in severity order
            severity_order = ['critical', 'high', 'medium', 'low', 'info']
            for severity in severity_order:
                if severity in findings_by_severity:
                    findings = findings_by_severity[severity]
                    emoji = self._get_severity_emoji(severity)
                    print(
                        f"\n{emoji} {severity.upper()} SEVERITY ({len(findings)} findings)")

                    for i, finding in enumerate(findings, 1):
                        print(f"\n{i}. {finding.title}")
                        print(f"   Tool: {finding.tool}")
                        print(f"   URL: {finding.url}")
                        if finding.method != "GET":
                            print(f"   Method: {finding.method}")
                        if finding.status_code:
                            print(f"   Status: {finding.status_code}")

                        # Educational explanations
                        if educational:
                            print(f"   Description: {finding.description}")

                            if finding.cwe_id:
                                print(f"   CWE ID: {finding.cwe_id}")

                            if finding.owasp_category:
                                print(
                                    f"   OWASP Category: {finding.owasp_category}")

                            if finding.payload:
                                print(f"   Test Payload: {finding.payload}")

                            if finding.evidence:
                                print(f"   Evidence: {finding.evidence}")

                            # Add educational context from vulnerability database
                            if finding.cwe_id:
                                vuln_info = self._get_vulnerability_info(
                                    finding.cwe_id)
                                if vuln_info:
                                    print(f"   💡 Education: {vuln_info}")

                        # Verbose technical details
                        if verbose:
                            print(f"   Confidence: {finding.confidence}")
                            if finding.response_time:
                                print(
                                    f"   Response Time: {finding.response_time:.3f}s")
        else:
            print(f"\n✅ No security issues found during dynamic analysis!")
            print("This is good news, but remember:")
            print("• Dynamic analysis only finds issues in tested paths")
            print("• Combine with static analysis for comprehensive coverage")
            print("• Consider manual testing for complex business logic")

    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            'critical': '🚨',
            'high': '🔴',
            'medium': '🟡',
            'low': '🔵',
            'info': 'ℹ️'
        }
        return emojis.get(severity, '❓')

    def _get_vulnerability_info(self, cwe_id: str) -> str:
        """Get educational information about a vulnerability"""
        # Map CWE IDs to vulnerability types in our database
        cwe_mapping = {
            'CWE-79': 'xss',
            'CWE-89': 'sql_injection',
            'CWE-352': 'csrf',
            'CWE-601': 'unvalidated_redirects',
            'CWE-287': 'broken_authentication',
            'CWE-384': 'broken_session_management'
        }

        vuln_type = cwe_mapping.get(cwe_id)
        if vuln_type and vuln_type in vulnerability_db:
            vuln_info = vulnerability_db[vuln_type]
            return vuln_info.get('student_explanation', 'No additional information available')

        return ""

    def _resolve_output_path(self, output_path: str, scan_type: str) -> str:
        """Resolve output path, ensuring it goes to reports directory if relative"""
        import os

        # If absolute path, use as-is
        if os.path.isabs(output_path):
            return output_path

        # If relative path, check if it's just a filename
        if os.path.dirname(output_path) == '':
            # Just a filename, put it in reports directory
            reports_dir = os.path.join(os.getcwd(), 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            return os.path.join(reports_dir, output_path)

        # Relative path with directory, use as-is (user specified structure)
        return output_path

    def _generate_auto_output_path(self, scan_type: str, format_type: str) -> str:
        """Generate automatic output path with timestamp"""
        import os
        from datetime import datetime

        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(os.getcwd(), 'reports')
        os.makedirs(reports_dir, exist_ok=True)

        # Generate timestamped filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        extension = 'json' if format_type == 'json' else 'txt'
        filename = f"{scan_type}_report_{timestamp}.{extension}"

        return os.path.join(reports_dir, filename)

    def _save_report(self, report: DynamicAnalysisReport, output_path: str, format_type: str) -> None:
        """Save analysis report to file"""
        try:
            if format_type == 'json':
                with open(output_path, 'w') as f:
                    json.dump(report.to_dict(), f, indent=2)

                # Auto-generate markdown report alongside JSON
                if MARKDOWN_AVAILABLE:
                    try:
                        generator = MarkdownReportGenerator()
                        markdown_path = output_path.replace('.json', '.md')
                        generator.generate_markdown_report(
                            json_data=report.to_dict(),
                            analyzer_type='dast',
                            output_file=os.path.basename(markdown_path)
                        )
                        logger.info(
                            f"Generated markdown report: {markdown_path}")
                    except Exception as e:
                        logger.warning(
                            f"Failed to generate markdown report: {e}")

            else:  # txt format
                with open(output_path, 'w') as f:
                    # Capture display output
                    import io
                    from contextlib import redirect_stdout

                    output_buffer = io.StringIO()
                    with redirect_stdout(output_buffer):
                        self._display_report(
                            report, educational=True, verbose=True)

                    f.write(output_buffer.getvalue())

        except Exception as e:
            print(f"Error saving report: {e}")

    def _save_demo_report(self, results: Dict[str, DynamicAnalysisReport],
                          output_path: str, format_type: str) -> None:
        """Save combined demo analysis report"""
        try:
            if format_type == 'json':
                combined_data = {}
                for app_name, report in results.items():
                    combined_data[app_name] = report.to_dict()

                with open(output_path, 'w') as f:
                    json.dump(combined_data, f, indent=2)
            else:  # txt format
                with open(output_path, 'w') as f:
                    f.write("COMBINED DYNAMIC ANALYSIS REPORT\n")
                    f.write("=" * 50 + "\n\n")

                    for app_name, report in results.items():
                        f.write(f"APPLICATION: {app_name}\n")
                        f.write("-" * 30 + "\n")

                        # Use string capture for individual reports
                        import io
                        from contextlib import redirect_stdout

                        output_buffer = io.StringIO()
                        with redirect_stdout(output_buffer):
                            self._display_report(
                                report, educational=True, verbose=False)

                        f.write(output_buffer.getvalue())
                        f.write("\n" + "=" * 50 + "\n\n")

        except Exception as e:
            print(f"Error saving combined report: {e}")


def main():
    """Main entry point for DAST CLI"""
    parser = argparse.ArgumentParser(
        description='Educational Dynamic Application Security Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan of a web application
  python dast_cli.py http://localhost:5000
  
  # Deep scan with educational explanations
  python dast_cli.py http://localhost:5000 --deep-scan --educational
  
  # Quick vulnerability check
  python dast_cli.py http://localhost:5000 --quick
  
  # Scan with specific tools
  python dast_cli.py http://localhost:5000 --tools nikto gobuster
  
  # Scan all demo applications
  python dast_cli.py --demo-apps --educational
  
  # Generate detailed JSON report
  python dast_cli.py http://localhost:5000 --output report.json --format json --verbose
        """
    )

    parser.add_argument('target_url', nargs='?',
                        help='Target URL to analyze (e.g., http://localhost:5000)')

    parser.add_argument('--demo-apps', action='store_true',
                        help='Analyze all demo applications (must be running)')

    parser.add_argument('--tools', nargs='+',
                        choices=['nikto', 'gobuster', 'basic_tests', 'all'],
                        help='Specific tools to run (default: auto-detect)')

    parser.add_argument('--deep-scan', action='store_true',
                        help='Enable deep scanning with crawling and comprehensive testing')

    parser.add_argument('--quick', action='store_true',
                        help='Quick scan mode - basic vulnerability checks only')

    parser.add_argument('--output', '-o', help='Output file path for report')

    parser.add_argument('--format', choices=['json', 'txt'], default='json',
                        help='Output format (default: json)')

    parser.add_argument('--educational', action='store_true',
                        help='Enable educational mode with detailed explanations')

    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output with technical details')

    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Quiet mode - minimal output')

    args = parser.parse_args()

    # Validate conflicting options
    if args.deep_scan and args.quick:
        print("Error: Cannot use --deep-scan and --quick together")
        sys.exit(1)

    # Configure logging based on verbosity
    if args.quiet:
        logger.setLevel(logging.ERROR)
    elif args.verbose:
        logger.setLevel(logging.DEBUG)

    # Initialize and run CLI
    cli = DASTCLI()
    cli.run_analysis(args)


if __name__ == "__main__":
    main()
