#!/usr/bin/env python3
"""
Command-line interface for the Static Application Security Testing (SAST) Module

This script provides an easy-to-use CLI for running static security analysis
on code files and applications. SAST analyses source code without executing it.

For Dynamic Application Security Testing (DAST), use dast_cli.py instead.
SAST and DAST are kept separate for educational clarity:
- SAST: Analyses source code (this tool)
- DAST: Tests running applications (dast_cli.py)

Usage Examples:
    # Analyse a single file
    python analyse_cli.py /path/to/file.py

    # Analyse a directory with specific tools
    python analyse_cli.py /path/to/app --tools bandit safety

    # Analyse all demo applications
    python analyse_cli.py --demo-apps

    # Generate detailed report
    python analyse_cli.py /path/to/app --output report.json --format json

    # Educational mode with explanations
    python analyse_cli.py /path/to/app --educational
"""

import os
import sys
from analyser.static_analyser import (
    StaticAnalyser, AnalysisReport, analyse_demo_applications, logger
)
import argparse
import json
import sys
import os
import logging
from pathlib import Path
from typing import List

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the report generator for markdown output
try:
    from reporter.report_generator import MarkdownReportGenerator
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False
    logger.warning("Markdown report generation not available")

# Import the MD to PDF converter
try:
    from tools.md_to_pdf_converter import MarkdownToPdfConverter
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logger.warning("PDF conversion not available")

# Import health check integration
try:
    from analyser.health_check_integration import (
        ensure_apps_running, get_health_check_args)
    HEALTH_CHECK_AVAILABLE = True
except ImportError:
    HEALTH_CHECK_AVAILABLE = False
    logger.warning("Health check integration not available")


class AnalysisCLI:
    """Command-line interface for static security analysis"""

    def __init__(self):
        self.analyser = StaticAnalyser()

    def run_analysis(self, args) -> None:
        """Execute analysis based on command-line arguments"""

        # Run health check if available and not skipped
        if (HEALTH_CHECK_AVAILABLE and
                not getattr(args, 'skip_health_check', False)):
            # For static analysis, we typically check demo apps
            demo_apps = args.demo_apps if hasattr(args, 'demo_apps') else False
            verbose = getattr(args, 'health_check_verbose', False)
            ensure_apps_running(
                target=getattr(args, 'target', None),
                demo_apps=demo_apps,
                verbose=verbose
            )

        if args.demo_apps:
            self._analyse_demo_applications(args)
            return

        if not args.target:
            print("Error: Target path is required unless using --demo-apps")
            sys.exit(1)

        # Validate target path
        if not os.path.exists(args.target):
            print(f"Error: Target path does not exist: {args.target}")
            sys.exit(1)

        # Determine analysis types
        analysis_types = self._get_analysis_types(args)

        try:
            # Run analysis
            print(f"🔍 Starting security analysis of: {args.target}")
            print(f"📊 Analysis types: {', '.join(analysis_types)}")

            report = self.analyser.analyse_target(args.target, analysis_types)

            # Output results
            if args.output:
                output_path = self._resolve_output_path(args.output, 'sast')
                self._save_report(report, output_path, args.format)
                print(f"📄 Report saved to: {output_path}")
            else:
                # Auto-save with timestamp if no output specified
                auto_output_path = self._generate_auto_output_path(
                    'sast', args.format)
                self._save_report(report, auto_output_path, args.format)
                print(f"📄 Report auto-saved to: {auto_output_path}")

            # Display results
            self._display_report(report, args.educational, args.verbose)

        except Exception as e:
            print(f"❌ Analysis failed: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    def _analyse_demo_applications(self, args) -> None:
        """Analyse all demo applications"""
        print("🎯 Analysing all demo applications...")

        try:
            results = analyse_demo_applications()

            if not results:
                print("❌ No demo applications found or analysis failed")
                return

            # Display summary for each app
            for app_name, report in results.items():
                print(f"\n📱 Application: {app_name}")
                print("=" * 50)
                self._display_report_summary(report)

                if args.educational:
                    self._display_educational_insights(report)

            # Save combined report if requested
            if args.output:
                output_path = self._resolve_output_path(
                    args.output, 'sast_demo')
                combined_report = self._combine_reports(results)
                self._save_report(combined_report, output_path, args.format)
                print(f"\n📄 Combined report saved to: {output_path}")
            else:
                # Auto-save with timestamp if no output specified
                auto_output_path = self._generate_auto_output_path(
                    'sast_demo', args.format)
                combined_report = self._combine_reports(results)
                self._save_report(
                    combined_report, auto_output_path, args.format)
                print(f"\n📄 Combined report auto-saved to: {auto_output_path}")

        except Exception as e:
            print(f"❌ Demo analysis failed: {str(e)}")
            sys.exit(1)

    def _get_analysis_types(self, args) -> List[str]:
        """Determine which analysis types to run"""
        if args.tools:
            # Map CLI tool names to analysis types
            tool_mapping = {
                'bandit': 'python',
                'safety': 'python',
                'semgrep': 'python',
                'npm': 'nodejs',
                'all': 'all'
            }

            analysis_types = set()
            for tool in args.tools:
                if tool in tool_mapping:
                    analysis_types.add(tool_mapping[tool])
                else:
                    print(f"⚠️  Unknown tool: {tool}")

            return list(analysis_types) or ['all']

        # Auto-detect if no specific tools requested
        return ['all']

    def _display_report(self, report: AnalysisReport, educational: bool = False, verbose: bool = False) -> None:
        """Display analysis report to console"""

        print("\n" + "="*60)
        print("🛡️  SECURITY ANALYSIS REPORT")
        print("="*60)

        # Summary
        self._display_report_summary(report)

        # Findings breakdown
        if report.findings:
            print(f"\n📋 DETAILED FINDINGS ({len(report.findings)} total)")
            print("-" * 40)

            # Group findings by severity
            severity_groups = {}
            for finding in report.findings:
                severity = finding.severity
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(finding)

            # Display by severity (highest first)
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in severity_groups:
                    print(
                        f"\n🚨 {severity.upper()} SEVERITY ({len(severity_groups[severity])} findings)")

                    # Limit display
                    for i, finding in enumerate(severity_groups[severity][:10]):
                        self._display_finding(finding, educational, verbose)

                        if i >= 9 and len(severity_groups[severity]) > 10:
                            remaining = len(severity_groups[severity]) - 10
                            print(
                                f"    ... and {remaining} more {severity} severity findings")
                            break

        if educational:
            self._display_educational_insights(report)

    def _display_report_summary(self, report: AnalysisReport) -> None:
        """Display summary statistics"""
        summary = report.summary

        print(f"📂 Target: {report.target_path}")
        print(f"⏰ Analysis Time: {report.analysis_timestamp}")
        print(f"📁 Files Analysed: {report.total_files_analysed}")
        print(
            f"🔧 Tools Used: {', '.join(report.tools_used) if report.tools_used else 'None'}")

        print(f"\n📊 FINDINGS SUMMARY:")
        print(f"   Total: {summary['total']}")
        print(f"   Critical: {summary.get('critical', 0)}")
        print(f"   High: {summary['high']}")
        print(f"   Medium: {summary['medium']}")
        print(f"   Low: {summary['low']}")
        print(f"   Info: {summary.get('info', 0)}")

    def _display_finding(self, finding, educational: bool = False, verbose: bool = False) -> None:
        """Display individual finding"""
        print(f"\n  [{finding.tool.upper()}] {finding.title}")
        print(f"    📁 File: {finding.file_path}")

        if finding.line_number:
            print(f"    📍 Line: {finding.line_number}")

        if verbose:
            print(f"    📝 Description: {finding.description}")

            if finding.rule_id:
                print(f"    🔍 Rule ID: {finding.rule_id}")

            if finding.cwe_id:
                print(f"    🌐 CWE: {finding.cwe_id}")

        if educational and finding.educational_note:
            print(f"    🎓 Educational Note: {finding.educational_note}")

        if educational and finding.remediation:
            print(f"    🔧 Remediation: {finding.remediation}")

    def _display_educational_insights(self, report: AnalysisReport) -> None:
        """Display educational insights and learning points"""
        print(f"\n🎓 EDUCATIONAL INSIGHTS")
        print("-" * 40)

        # Categorise findings for educational purposes
        categories = {}
        for finding in report.findings:
            category = finding.category or 'other'
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)

        print(f"📚 Vulnerability Categories Found:")
        for category, findings in categories.items():
            count = len(findings)
            category_name = category.replace('_', ' ').title()
            print(
                f"   • {category_name}: {count} finding{'s' if count != 1 else ''}")

        # Educational recommendations
        print(f"\n💡 LEARNING RECOMMENDATIONS:")

        if any(f.tool == 'bandit' for f in report.findings):
            print("   • Study Python security best practices")
            print("   • Learn about input validation and sanitization")

        if any(f.category == 'dependency_vulnerability' for f in report.findings):
            print("   • Practice dependency management")
            print("   • Learn about supply chain security")

        if any('injection' in f.description.lower() for f in report.findings):
            print("   • Study injection attack vectors")
            print("   • Practice secure coding patterns")

        high_severity_count = report.summary.get('high', 0)
        if high_severity_count > 0:
            print(
                f"   • Focus on {high_severity_count} high-severity issues first")
            print("   • Understand risk assessment and prioritization")

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

    def _save_report(self, report, output_path: str, format_type: str) -> None:
        """Save report to file with support for multiple formats"""

        # Convert dataclass to dict for JSON serialization (needed for all formats)
        report_dict = {
            'target_path': report.target_path,
            'analysis_timestamp': report.analysis_timestamp,
            'total_files_analysed': report.total_files_analysed,
            'tools_used': report.tools_used,
            'findings': [
                {
                    'tool': f.tool,
                    'severity': f.severity,
                    'title': f.title,
                    'description': f.description,
                    'file_path': f.file_path,
                    'line_number': f.line_number,
                    'column': f.column,
                    'cwe_id': f.cwe_id,
                    'confidence': f.confidence,
                    'rule_id': f.rule_id,
                    'category': f.category,
                    'educational_note': f.educational_note,
                    'remediation': f.remediation
                } for f in report.findings
            ],
            'summary': report.summary,
            'metadata': report.metadata
        }

        if format_type == 'json':
            # JSON only
            with open(output_path, 'w') as f:
                json.dump(report_dict, f, indent=2)

        elif format_type == 'md':
            # JSON + Markdown
            # Save JSON file
            json_path = output_path.replace('.md', '.json')
            with open(json_path, 'w') as f:
                json.dump(report_dict, f, indent=2)
            print(f"📄 JSON report saved to: {json_path}")

            # Generate markdown report
            if MARKDOWN_AVAILABLE:
                try:
                    generator = MarkdownReportGenerator()
                    generator.generate_markdown_report(
                        json_data=report_dict,
                        analyser_type='sast',
                        output_file=os.path.basename(output_path)
                    )
                    print(f"📄 Markdown report saved to: {output_path}")
                except Exception as e:
                    logger.error(f"Failed to generate markdown report: {e}")
                    print(f"❌ Markdown generation failed: {e}")
            else:
                print("❌ Markdown generation not available")

        elif format_type == 'pdf':
            # JSON + Markdown + PDF
            # Save JSON file
            json_path = output_path.replace('.pdf', '.json')
            with open(json_path, 'w') as f:
                json.dump(report_dict, f, indent=2)
            print(f"📄 JSON report saved to: {json_path}")

            # Generate markdown report
            if MARKDOWN_AVAILABLE:
                try:
                    markdown_path = output_path.replace('.pdf', '.md')
                    generator = MarkdownReportGenerator()
                    generator.generate_markdown_report(
                        json_data=report_dict,
                        analyser_type='sast',
                        output_file=os.path.basename(markdown_path)
                    )
                    print(f"📄 Markdown report saved to: {markdown_path}")

                    # Convert to PDF
                    if PDF_AVAILABLE:
                        try:
                            converter = MarkdownToPdfConverter(
                                page_break_mode="continuous"
                            )
                            converter.convert_file_to_pdf(
                                input_file=Path(markdown_path),
                                output_file=Path(output_path)
                            )
                            print(f"📄 PDF report saved to: {output_path}")
                        except Exception as e:
                            logger.error(f"Failed to convert to PDF: {e}")
                            print(f"❌ PDF conversion failed: {e}")
                    else:
                        print("❌ PDF conversion not available")

                except Exception as e:
                    logger.error(f"Failed to generate markdown report: {e}")
                    print(f"❌ Markdown generation failed: {e}")
            else:
                print("❌ Markdown generation not available")

        elif format_type == 'txt':
            # Text format (legacy)
            with open(output_path, 'w') as f:
                f.write("SECURITY ANALYSIS REPORT\n")
                f.write("=" * 60 + "\n\n")

                f.write(f"Target: {report.target_path}\n")
                f.write(f"Analysis Time: {report.analysis_timestamp}\n")
                f.write(f"Files Analysed: {report.total_files_analysed}\n")
                f.write(f"Tools Used: {', '.join(report.tools_used)}\n\n")

                f.write("SUMMARY:\n")
                for severity, count in report.summary.items():
                    f.write(f"  {severity.title()}: {count}\n")

                f.write(f"\nFINDINGS ({len(report.findings)} total):\n")
                f.write("-" * 40 + "\n")

                for i, finding in enumerate(report.findings, 1):
                    f.write(
                        f"\n{i}. [{finding.severity.upper()}] {finding.title}\n")
                    f.write(f"   Tool: {finding.tool}\n")
                    f.write(f"   File: {finding.file_path}")
                    if finding.line_number:
                        f.write(f":{finding.line_number}")
                    f.write(f"\n   Description: {finding.description}\n")

                    if finding.educational_note:
                        f.write(
                            f"   Educational Note: {finding.educational_note}\n")

                    if finding.remediation:
                        f.write(f"   Remediation: {finding.remediation}\n")

    def _combine_reports(self, reports_dict) -> AnalysisReport:
        """Combine multiple reports into one"""
        # This is a simplified combination - in practice you might want more sophisticated merging
        combined_findings = []
        combined_tools = set()
        total_files = 0

        for app_name, report in reports_dict.items():
            # Prefix findings with app name for clarity
            for finding in report.findings:
                finding.file_path = f"{app_name}/{finding.file_path}"

            combined_findings.extend(report.findings)
            combined_tools.update(report.tools_used)
            total_files += report.total_files_analysed

        # Generate combined summary
        summary = {'total': len(combined_findings), 'critical': 0,
                   'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in combined_findings:
            severity = finding.severity.lower()
            if severity in summary:
                summary[severity] += 1

        return AnalysisReport(
            target_path="Combined Demo Applications",
            analysis_timestamp=reports_dict[list(reports_dict.keys())[
                0]].analysis_timestamp,
            total_files_analysed=total_files,
            tools_used=list(combined_tools),
            findings=combined_findings,
            summary=summary,
            metadata={'combined_from': list(reports_dict.keys())}
        )


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Educational Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyse a Python file
  python analyse_cli.py /path/to/app.py
  
  # Analyse directory with specific tools
  python analyse_cli.py /path/to/app --tools bandit safety
  
  # Analyse all demo applications
  python analyse_cli.py --demo-apps --educational
  
  # Generate detailed JSON report
  python analyse_cli.py /path/to/app --output report.json --format json --verbose
        """
    )

    parser.add_argument('target', nargs='?',
                        help='Target file or directory to analyse')

    parser.add_argument('--demo-apps', action='store_true',
                        help='Analyse all demo applications in samples directory')

    parser.add_argument('--tools', nargs='+',
                        choices=['bandit', 'safety', 'semgrep', 'npm', 'all'],
                        help='Specific tools to run (default: auto-detect)')

    parser.add_argument('--output', '-o', help='Output file path for report')

    parser.add_argument('--format',
                        choices=['json', 'txt', 'md', 'pdf'],
                        default='json',
                        help='Output format: json (JSON only), '
                             'md (JSON + Markdown), '
                             'pdf (JSON + Markdown + PDF), txt (text format)')

    parser.add_argument('--educational', action='store_true',
                        help='Enable educational mode with explanations')

    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output with detailed information')

    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Quiet mode - minimal output')

    # Add health check arguments if available
    if HEALTH_CHECK_AVAILABLE:
        get_health_check_args(parser)

    args = parser.parse_args()

    # Configure logging based on verbosity
    if args.quiet:
        logger.setLevel(logging.ERROR)
    elif args.verbose:
        logger.setLevel(logging.DEBUG)

    # Initialize and run CLI
    cli = AnalysisCLI()
    cli.run_analysis(args)


if __name__ == "__main__":
    main()
