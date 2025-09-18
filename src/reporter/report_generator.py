"""
Comprehensive Markdown Report Generator for Security Analysis Tools

A clean, well-structured report generator that creates professional markdown
reports for all security analyzer types with educational content.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class MarkdownReportGenerator:
    """
    Generates educational markdown reports for security analysis results.

    Supports SAST, DAST, Network, and Sandbox analysis with unified formatting,
    educational content, and visual enhancements.
    """

    def __init__(self, reports_directory: str = "reports"):
        """Initialize the report generator."""
        self.reports_dir = Path(reports_directory)
        self.reports_dir.mkdir(exist_ok=True)

        # Analyzer configurations
        self.analyzer_config = {
            'sast': {
                'icon': '🔍',
                'name': 'Static Application Security Testing (SAST)',
                'description': 'Analyzes source code for security vulnerabilities without executing the program'
            },
            'dast': {
                'icon': '🌐',
                'name': 'Dynamic Application Security Testing (DAST)',
                'description': 'Tests running applications for security vulnerabilities through external interactions'
            },
            'network': {
                'icon': '🔌',
                'name': 'Network Traffic Analysis',
                'description': 'Monitors and analyzes network connections and traffic patterns for threats'
            },
            'sandbox': {
                'icon': '📦',
                'name': 'Sandbox Security Analysis',
                'description': 'Analyzes application behavior in an isolated environment to detect malicious activities'
            }
        }

        # Learning objectives by analyzer type
        self.learning_objectives = {
            'sast': [
                'Understand how static code analysis identifies security vulnerabilities',
                'Learn to interpret SAST tool outputs and prioritize findings',
                'Recognize common code patterns that lead to security issues',
                'Apply secure coding practices to prevent vulnerabilities'
            ],
            'dast': [
                'Understand how dynamic testing identifies runtime vulnerabilities',
                'Learn to analyze web application security through external testing',
                'Recognize common web vulnerabilities like XSS and SQL injection',
                'Apply defense-in-depth strategies for web application security'
            ],
            'network': [
                'Understand network traffic analysis and monitoring techniques',
                'Learn to identify suspicious network patterns and behaviors',
                'Recognize common network-based attack indicators',
                'Apply network security monitoring best practices'
            ],
            'sandbox': [
                'Understand behavioral analysis in isolated environments',
                'Learn to identify malicious application behaviors',
                'Recognize system-level security threats and indicators',
                'Apply sandboxing techniques for security analysis'
            ]
        }

    def _create_severity_badge(self, severity: str) -> str:
        """Create markdown badge for severity level."""
        colors = {
            'critical': 'red',
            'high': 'orange',
            'medium': 'yellow',
            'low': 'green',
            'info': 'blue'
        }
        color = colors.get(severity.lower(), 'lightgrey')
        return f"![{severity.upper()}](https://img.shields.io/badge/{severity.upper()}-{color}?style=flat)"

    def _create_tool_badge(self, tool: str) -> str:
        """Create markdown badge for analysis tool."""
        return f"![{tool}](https://img.shields.io/badge/Tool-{tool}-blue?style=flat)"

    def _create_report_header(self, analyzer_type: str, data: Dict[str, Any]) -> str:
        """Generate the report header with metadata."""
        config = self.analyzer_config.get(analyzer_type, {
            'icon': '🔍', 'name': f'{analyzer_type.upper()} Analysis',
            'description': 'Security analysis report'
        })

        lines = [
            f"# {config['icon']} {config['name']} Report",
            "",
            f"> {config['description']}",
            "",
            "## 📋 Report Information",
            "",
            "| Field | Value |",
            "|-------|-------|"
        ]

        # Add timestamp
        timestamp = data.get('timestamp') or data.get('analysis_timestamp')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                readable_time = dt.strftime('%B %d, %Y at %I:%M %p UTC')
                lines.append(f"| **Generated** | {readable_time} |")
            except:
                lines.append(f"| **Generated** | {timestamp} |")

        # Add analyzer-specific metadata
        if analyzer_type == 'sast':
            target = data.get('target_path', 'Unknown')
            files = data.get('total_files_analyzed', 0)
            tools = ', '.join(data.get('tools_used', []))
            lines.extend([
                f"| **Target Path** | `{target}` |",
                f"| **Files Analyzed** | {files} |",
                f"| **Tools Used** | {tools} |"
            ])
        elif analyzer_type == 'dast':
            target = data.get('target_url', 'Unknown')
            duration = data.get('scan_duration', 0)
            lines.extend([
                f"| **Target URL** | {target} |",
                f"| **Scan Duration** | {duration:.2f} seconds |"
            ])
        elif analyzer_type == 'network':
            total = data.get('total_connections', 0)
            active = len(data.get('active_connections', []))
            lines.extend([
                f"| **Total Connections** | {total} |",
                f"| **Active Connections** | {active} |"
            ])

        lines.append("")
        return "\n".join(lines)

    def _create_executive_summary(self, findings: List[Dict], summary: Dict) -> str:
        """Generate executive summary section."""
        lines = ["## 📊 Executive Summary", ""]

        total = summary.get('total', len(findings))
        if total == 0:
            lines.extend([
                "✅ **Great news!** No security vulnerabilities were detected in this analysis.",
                "",
                "This indicates that the analyzed target follows good security practices. However, remember that security is an ongoing process, and different tools may detect different types of issues.",
                ""
            ])
        else:
            critical = summary.get('critical', 0)
            high = summary.get('high', 0)

            if critical > 0 or high > 0:
                msg = f"🚨 **{total} security issues** were found"
                if critical > 0:
                    msg += f", including **{critical} critical**"
                if high > 0:
                    msg += f" and **{high} high severity**"
                msg += " issues that require immediate attention."
                lines.append(msg)
            else:
                lines.append(
                    f"⚠️ **{total} security issues** were found. While none are critical, these should be reviewed and addressed.")

            lines.append("")

            # Add vulnerability breakdown table
            lines.extend([
                "### Vulnerability Breakdown",
                "",
                "| Severity | Count | Percentage |",
                "|----------|-------|------------|"
            ])

            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = summary.get(severity, 0)
                percentage = (count / total * 100) if total > 0 else 0
                badge = self._create_severity_badge(severity)
                lines.append(f"| {badge} | {count} | {percentage:.1f}% |")

            lines.append("")

        return "\n".join(lines)

    def _create_learning_objectives(self, analyzer_type: str) -> str:
        """Generate learning objectives section."""
        objectives = self.learning_objectives.get(analyzer_type, [])

        lines = [
            "## 🎯 Learning Objectives",
            "",
            f"After reviewing this {analyzer_type.upper()} analysis report, you should be able to:",
            ""
        ]

        for i, objective in enumerate(objectives, 1):
            lines.append(f"{i}. {objective}")

        lines.append("")
        return "\n".join(lines)

    def _create_vulnerability_section(self, finding: Dict[str, Any], index: int) -> str:
        """Create detailed vulnerability section."""
        severity = finding.get('severity', 'unknown')
        title = finding.get('title', 'Unknown Vulnerability')
        tool = finding.get('tool', 'unknown')

        lines = [
            f"### Finding {index}",
            "",
            f"#### {self._create_severity_badge(severity)} {title}",
            "",
            self._create_tool_badge(tool),
            ""
        ]

        # Description
        description = finding.get('description', 'No description available')
        lines.extend([f"**Description:** {description}", ""])

        # Location (SAST)
        if 'file_path' in finding:
            file_path = finding['file_path']
            line_number = finding.get('line_number', '')
            if line_number:
                lines.append(f"**Location:** `{file_path}:{line_number}`")
            else:
                lines.append(f"**Location:** `{file_path}`")
            lines.append("")

        # URL (DAST)
        if 'url' in finding:
            url = finding['url']
            method = finding.get('method', 'GET')
            status = finding.get('status_code', '')
            url_info = f"**URL:** `{method} {url}`"
            if status:
                url_info += f" (Status: {status})"
            lines.extend([url_info, ""])

        # Network info
        if 'local_address' in finding:
            local = finding['local_address']
            remote = finding.get('remote_address', 'N/A')
            protocol = finding.get('protocol', 'unknown')
            lines.extend(
                [f"**Connection:** `{protocol}` {local} → {remote}", ""])

        # CWE reference
        cwe_id = finding.get('cwe_id')
        if cwe_id:
            cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
            lines.extend([f"**CWE ID:** [CWE-{cwe_id}]({cwe_url})", ""])

        # OWASP category
        owasp = finding.get('owasp_category')
        if owasp:
            lines.extend([f"**OWASP Category:** {owasp}", ""])

        # Educational explanation
        educational = finding.get('educational_note')
        if educational:
            lines.extend([
                "##### 📚 Educational Explanation",
                "",
                educational,
                ""
            ])

        # Remediation
        remediation = finding.get('remediation')
        if remediation:
            lines.extend([
                "##### 🔧 How to Fix This",
                "",
                remediation,
                ""
            ])

        # Additional DAST details
        payload = finding.get('payload')
        if payload:
            lines.extend([f"**Test Payload:** `{payload}`", ""])

        evidence = finding.get('evidence')
        if evidence:
            lines.extend([f"**Evidence:** {evidence}", ""])

        # Confidence
        confidence = finding.get('confidence')
        if confidence:
            lines.extend([f"**Confidence:** {confidence}", ""])

        return "\n".join(lines)

    def _create_recommendations(self, findings: List[Dict], analyzer_type: str) -> str:
        """Generate recommendations section."""
        lines = ["## 💡 Recommendations", ""]

        if not findings:
            lines.extend([
                "No security issues were found! This is excellent. Continue following secure development practices.",
                ""
            ])
            return "\n".join(lines)

        # General recommendations by type
        general_recs = {
            'sast': [
                "Integrate SAST tools into your development pipeline for continuous security scanning",
                "Address high and critical severity findings first",
                "Review and understand each vulnerability before marking as false positive",
                "Use secure coding guidelines to prevent similar issues in the future"
            ],
            'dast': [
                "Implement proper input validation and output encoding",
                "Use security headers to protect against common web attacks",
                "Regularly test your application with DAST tools",
                "Follow OWASP guidelines for web application security"
            ],
            'network': [
                "Monitor network traffic continuously for suspicious patterns",
                "Implement network segmentation and access controls",
                "Use intrusion detection systems (IDS) for real-time monitoring",
                "Regularly audit network connections and services"
            ],
            'sandbox': [
                "Use sandboxing for analyzing suspicious applications",
                "Monitor system behavior for indicators of compromise",
                "Implement application behavior monitoring in production",
                "Regular security assessment of deployed applications"
            ]
        }

        lines.append("### General Security Recommendations:")
        lines.append("")
        for i, rec in enumerate(general_recs.get(analyzer_type, []), 1):
            lines.append(f"{i}. {rec}")

        # Priority actions for high/critical issues
        high_count = len([f for f in findings if f.get('severity') == 'high'])
        critical_count = len(
            [f for f in findings if f.get('severity') == 'critical'])

        if critical_count > 0 or high_count > 0:
            lines.extend([
                "",
                "### 🚨 Priority Actions:",
                "",
                "The following issues require immediate attention:",
                ""
            ])
            if critical_count > 0:
                lines.append(
                    f"- **{critical_count} Critical issues** - Address immediately")
            if high_count > 0:
                lines.append(
                    f"- **{high_count} High severity issues** - Address within 24-48 hours")

        lines.append("")
        return "\n".join(lines)

    def _create_learning_resources(self, analyzer_type: str) -> str:
        """Generate learning resources section."""
        lines = [
            "## 📚 Additional Learning Resources",
            "",
            "To learn more about security testing and vulnerability management:",
            "",
            "- [OWASP Top 10](https://owasp.org/Top10/) - Most critical web application security risks",
            "- [CWE/SANS Top 25](https://www.sans.org/top25-software-errors/) - Most dangerous software weaknesses",
            "- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Cybersecurity best practices"
        ]

        # Add analyzer-specific resources
        specific_resources = {
            'sast': "- [OWASP Static Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)",
            'dast': "- [OWASP ZAP User Guide](https://www.zaproxy.org/docs/)",
            'network': "- [SANS Network Security Monitoring](https://www.sans.org/white-papers/)",
            'sandbox': "- [NIST SP 800-83 Malware Incident Prevention](https://csrc.nist.gov/publications/detail/sp/800-83/rev-1/final)"
        }

        if analyzer_type in specific_resources:
            lines.append(specific_resources[analyzer_type])

        lines.append("")
        return "\n".join(lines)

    def _create_footer(self, analyzer_type: str) -> str:
        """Generate report footer."""
        current_time = datetime.now().strftime('%B %d, %Y at %I:%M %p')
        return "\n".join([
            "---",
            "",
            "*This report was generated by the Secure Architecture Sandbox Testing Environment Security Analysis Platform*",
            f"*Report Type: {analyzer_type.upper()} Analysis*",
            f"*Generated: {current_time}*",
            ""
        ])

    def generate_markdown_report(self, json_data: Dict[str, Any], analyzer_type: str, output_file: Optional[str] = None) -> str:
        """
        Generate comprehensive markdown report from JSON data.

        Args:
            json_data: Analysis results in JSON format
            analyzer_type: Type of analyzer (sast, dast, network, sandbox)
            output_file: Optional output filename

        Returns:
            Path to generated markdown file
        """
        # Generate filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"{analyzer_type}_report_{timestamp}.md"

        output_path = self.reports_dir / output_file

        # Extract findings and summary
        findings = json_data.get('findings', [])
        summary = json_data.get('summary', {})

        # Generate summary if not provided
        if not summary and findings:
            summary = {'total': len(findings)}
            for finding in findings:
                severity = finding.get('severity', 'unknown')
                summary[severity] = summary.get(severity, 0) + 1

        # Build markdown content
        content_sections = [
            self._create_report_header(analyzer_type, json_data),
            self._create_executive_summary(findings, summary),
            self._create_learning_objectives(analyzer_type)
        ]

        # Add findings or no issues message
        if findings:
            content_sections.append(
                f"## 🔍 Detailed Findings\n\nThe following {len(findings)} security issues were identified:\n")

            # Sort by severity
            severity_order = {'critical': 0, 'high': 1,
                              'medium': 2, 'low': 3, 'info': 4}
            sorted_findings = sorted(
                findings, key=lambda x: severity_order.get(x.get('severity', 'info'), 4))

            for i, finding in enumerate(sorted_findings, 1):
                content_sections.append(
                    self._create_vulnerability_section(finding, i))
        else:
            no_issues = [
                "## ✅ No Issues Found",
                "",
                "This analysis did not identify any security vulnerabilities. This is a positive result, but remember that:",
                "",
                "- Different tools may find different types of issues",
                "- Security testing should be performed regularly",
                "- Manual code review is still recommended",
                "- Keep security tools and signatures up to date",
                ""
            ]
            content_sections.append("\n".join(no_issues))

        # Add recommendations and resources
        content_sections.extend([
            self._create_recommendations(findings, analyzer_type),
            self._create_learning_resources(analyzer_type),
            self._create_footer(analyzer_type)
        ])

        # Write the file
        markdown_content = "\n".join(content_sections)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown_content)

        return str(output_path)

    def convert_json_to_markdown(self, json_file_path: str, analyzer_type: str = None) -> str:
        """Convert existing JSON report to markdown."""
        with open(json_file_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)

        # Auto-detect analyzer type if not provided
        if not analyzer_type:
            filename = os.path.basename(json_file_path).lower()
            if 'sast' in filename:
                analyzer_type = 'sast'
            elif 'dast' in filename:
                analyzer_type = 'dast'
            elif 'network' in filename:
                analyzer_type = 'network'
            elif 'sandbox' in filename:
                analyzer_type = 'sandbox'
            else:
                # Detect from structure
                if 'target_path' in json_data and 'tools_used' in json_data:
                    analyzer_type = 'sast'
                elif 'target_url' in json_data and 'scan_duration' in json_data:
                    analyzer_type = 'dast'
                elif 'active_connections' in json_data or 'total_connections' in json_data:
                    analyzer_type = 'network'
                else:
                    analyzer_type = 'general'

        # Generate output filename
        base_name = os.path.splitext(os.path.basename(json_file_path))[0]
        output_file = f"{base_name}.md"

        return self.generate_markdown_report(json_data, analyzer_type, output_file)


def main():
    """Command-line interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Generate markdown reports from JSON analysis files')
    parser.add_argument('json_file', help='Path to JSON report file')
    parser.add_argument(
        '--type', choices=['sast', 'dast', 'network', 'sandbox'], help='Analyzer type')
    parser.add_argument('--output', help='Output markdown filename')
    parser.add_argument('--reports-dir', default='reports',
                        help='Reports directory')

    args = parser.parse_args()

    generator = MarkdownReportGenerator(args.reports_dir)

    try:
        output_path = generator.convert_json_to_markdown(
            args.json_file, args.type)
        print(f"✅ Markdown report generated: {output_path}")
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
