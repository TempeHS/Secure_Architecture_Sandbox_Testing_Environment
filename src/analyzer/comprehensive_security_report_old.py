#!/usr/bin/env python3
"""
Comprehensive Security Report Tool

This tool orchestrates all security testing modules (SAST, DAST, Network Analysis,
and Penetration Testing) to provide a complete security assessment of applications.
It runs all tests, collects their JSON outputs, and generates a comprehensive
markdown report for educational purposes.

Usage Examples:
    # Comprehensive security assessment of a web application
    python comprehensive_security_report.py http://localhost:5000

    # Test a local directory for static analysis plus web app testing
    python comprehensive_security_report.py /path/to/app --target-url \
        http://localhost:5000

    # Test demo applications with all security modules
    python comprehensive_security_report.py --demo-apps --educational

    # Full assessment with penetration testing (requires permission)
    python comprehensive_security_report.py http://localhost:5000 \
        --include-pentest

    # Generate report with custom output path
    python comprehensive_security_report.py http://localhost:5000 \
        --output comprehensive_report

Security Testing Modules:
    - SAST (Static Application Security Testing): Source code analysis
    - DAST (Dynamic Application Security Testing): Runtime testing
    - Network Analysis: Traffic monitoring and service scanning
    - Penetration Testing: Active exploitation testing (optional)

Author: Cybersecurity Education Platform
License: Educational Use Only
"""

import argparse
import json
import sys
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer.vulnerability_database import vulnerability_db


class ComprehensiveSecurityReporter:
    """
    Orchestrates multiple security testing tools and generates comprehensive reports
    """

    def __init__(self, educational_mode: bool = False):
        """Initialize the comprehensive security reporter"""
        self.educational_mode = educational_mode
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        self.session_id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.now()
        
        # Paths to individual analyzer CLIs
        self.analyzer_dir = Path(__file__).parent
        self.sast_cli = self.analyzer_dir / "analyze_cli.py"
        self.dast_cli = self.analyzer_dir / "dast_cli.py"
        self.network_cli = self.analyzer_dir / "network_cli.py"
        self.pentest_cli = self.analyzer_dir / "pentest_cli.py"
        
        # Results storage
        self.individual_reports: Dict[str, Dict[str, Any]] = {}
        self.execution_log: List[str] = []

    def run_comprehensive_assessment(
        self,
        target_url: Optional[str] = None,
        target_path: Optional[str] = None,
        demo_mode: bool = False,
        include_pentest: bool = False,
        include_network: bool = True,
        quick_scan: bool = False,
        output_prefix: str = "comprehensive_security_report"
    ) -> str:
        """
        Run comprehensive security assessment using all available tools
        
        Args:
            target_url: URL of web application to test
            target_path: Local path for static analysis
            demo_mode: Test demo applications instead of specific target
            include_pentest: Include penetration testing (requires caution)
            include_network: Include network traffic analysis
            quick_scan: Run quick scans instead of deep analysis
            output_prefix: Prefix for output files
            
        Returns:
            Path to the generated comprehensive report
        """
        
        print("🛡️  COMPREHENSIVE SECURITY ASSESSMENT")
        print("=" * 70)
        print(f"Session ID: {self.session_id}")
        print(f"Timestamp: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if demo_mode:
            print("🎯 Mode: Demo Applications Testing")
        else:
            print(f"🎯 Target URL: {target_url}")
            print(f"📁 Target Path: {target_path}")
        
        print(f"🔍 Penetration Testing: "
              f"{'Enabled' if include_pentest else 'Disabled'}")
        print(f"🌐 Network Analysis: "
              f"{'Enabled' if include_network else 'Disabled'}")
        print(f"⚡ Quick Scan: {'Yes' if quick_scan else 'No'}")
        print()

        # Step 1: Static Application Security Testing (SAST)
        self._run_sast_analysis(target_path, demo_mode, quick_scan)
        
        # Step 2: Dynamic Application Security Testing (DAST)
        if target_url or demo_mode:
            self._run_dast_analysis(target_url, demo_mode, quick_scan)
        
        # Step 3: Network Traffic Analysis
        if include_network:
            self._run_network_analysis(target_url, demo_mode, quick_scan)
        
        # Step 4: Penetration Testing (optional)
        if include_pentest:
            self._run_penetration_testing(target_url, demo_mode, quick_scan)
        
        # Step 5: Generate comprehensive report
        report_path = self._generate_comprehensive_report(output_prefix)
        
        print(f"\n✅ Comprehensive security assessment completed!")
        print(f"📄 Report saved to: {report_path}")
        
        return report_path

    def _run_sast_analysis(self, target_path: Optional[str], demo_mode: bool, quick_scan: bool) -> None:
        """Run Static Application Security Testing"""
        print("🔍 1. STATIC APPLICATION SECURITY TESTING (SAST)")
        print("-" * 50)
        
        try:
            cmd = [sys.executable, str(self.sast_cli)]
            
            if demo_mode:
                cmd.append("--demo-apps")
            elif target_path:
                cmd.append(target_path)
            else:
                # Default to current directory if no path specified
                cmd.append(".")
            
            cmd.extend(["--format", "json"])
            
            if self.educational_mode:
                cmd.append("--educational")
            
            # Auto-generate output filename
            sast_output = self.reports_dir / f"sast_{self.session_id}.json"
            cmd.extend(["--output", str(sast_output)])
            
            self.execution_log.append(f"Running SAST: {' '.join(cmd)}")
            print(f"   Command: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print("   ✅ SAST analysis completed successfully")
                self._load_report("sast", sast_output)
            else:
                print(f"   ❌ SAST analysis failed: {result.stderr}")
                self.execution_log.append(f"SAST failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("   ⏰ SAST analysis timed out")
            self.execution_log.append("SAST timed out")
        except Exception as e:
            print(f"   ❌ SAST analysis error: {str(e)}")
            self.execution_log.append(f"SAST error: {str(e)}")

    def _run_dast_analysis(self, target_url: Optional[str], demo_mode: bool, quick_scan: bool) -> None:
        """Run Dynamic Application Security Testing"""
        print("\n🌐 2. DYNAMIC APPLICATION SECURITY TESTING (DAST)")
        print("-" * 50)
        
        try:
            cmd = [sys.executable, str(self.dast_cli)]
            
            if demo_mode:
                cmd.append("--demo-apps")
            elif target_url:
                cmd.append(target_url)
            else:
                print("   ⚠️  No target URL provided, skipping DAST")
                return
            
            cmd.extend(["--format", "json"])
            
            if quick_scan:
                cmd.append("--quick")
            else:
                cmd.append("--deep-scan")
            
            if self.educational_mode:
                cmd.append("--educational")
            
            # Auto-generate output filename
            dast_output = self.reports_dir / f"dast_{self.session_id}.json"
            cmd.extend(["--output", str(dast_output)])
            
            self.execution_log.append(f"Running DAST: {' '.join(cmd)}")
            print(f"   Command: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                print("   ✅ DAST analysis completed successfully")
                self._load_report("dast", dast_output)
            else:
                print(f"   ❌ DAST analysis failed: {result.stderr}")
                self.execution_log.append(f"DAST failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("   ⏰ DAST analysis timed out")
            self.execution_log.append("DAST timed out")
        except Exception as e:
            print(f"   ❌ DAST analysis error: {str(e)}")
            self.execution_log.append(f"DAST error: {str(e)}")

    def _run_network_analysis(self, target_url: Optional[str], demo_mode: bool, quick_scan: bool) -> None:
        """Run Network Traffic Analysis"""
        print("\n🌐 3. NETWORK TRAFFIC ANALYSIS")
        print("-" * 50)
        
        try:
            cmd = [sys.executable, str(self.network_cli)]
            
            if demo_mode:
                cmd.append("--demo-network")
            else:
                # For network analysis, we'll do connection monitoring
                cmd.append("--monitor-connections")
            
            cmd.extend(["--format", "json"])
            
            if self.educational_mode:
                cmd.append("--educational")
            
            # Auto-generate output filename
            network_output = self.reports_dir / f"network_{self.session_id}.json"
            cmd.extend(["--output", str(network_output)])
            
            # Shorter duration for network analysis
            duration = 30 if quick_scan else 60
            cmd.extend(["--duration", str(duration)])
            
            self.execution_log.append(f"Running Network Analysis: {' '.join(cmd)}")
            print(f"   Command: {' '.join(cmd)}")
            print(f"   Duration: {duration} seconds")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 30)
            
            if result.returncode == 0:
                print("   ✅ Network analysis completed successfully")
                self._load_report("network", network_output)
            else:
                print(f"   ❌ Network analysis failed: {result.stderr}")
                self.execution_log.append(f"Network analysis failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("   ⏰ Network analysis timed out")
            self.execution_log.append("Network analysis timed out")
        except Exception as e:
            print(f"   ❌ Network analysis error: {str(e)}")
            self.execution_log.append(f"Network analysis error: {str(e)}")

    def _run_penetration_testing(self, target_url: Optional[str], demo_mode: bool, quick_scan: bool) -> None:
        """Run Penetration Testing"""
        print("\n💥 4. PENETRATION TESTING")
        print("-" * 50)
        print("⚠️  WARNING: Penetration testing performs active exploitation attempts")
        print("   Only test applications you own or have explicit permission to test")
        
        try:
            cmd = [sys.executable, str(self.pentest_cli)]
            
            if demo_mode:
                cmd.append("--demo-apps")
            elif target_url:
                cmd.append(target_url)
            else:
                print("   ⚠️  No target URL provided, skipping penetration testing")
                return
            
            cmd.extend(["--format", "json"])
            
            if not quick_scan:
                cmd.append("--deep")
            
            if self.educational_mode:
                cmd.append("--educational")
            
            # Force mode to skip interactive prompts in automation
            cmd.append("--force")
            
            # Auto-generate output filename
            pentest_output = self.reports_dir / f"pentest_{self.session_id}.json"
            cmd.extend(["--output", str(pentest_output)])
            
            self.execution_log.append(f"Running Penetration Testing: {' '.join(cmd)}")
            print(f"   Command: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            
            if result.returncode == 0:
                print("   ✅ Penetration testing completed successfully")
                self._load_report("pentest", pentest_output)
            else:
                print(f"   ❌ Penetration testing failed: {result.stderr}")
                self.execution_log.append(f"Penetration testing failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("   ⏰ Penetration testing timed out")
            self.execution_log.append("Penetration testing timed out")
        except Exception as e:
            print(f"   ❌ Penetration testing error: {str(e)}")
            self.execution_log.append(f"Penetration testing error: {str(e)}")

    def _load_report(self, analyzer_type: str, report_path: Path) -> None:
        """Load individual analyzer report"""
        try:
            if report_path.exists():
                with open(report_path, 'r') as f:
                    report_data = json.load(f)
                self.individual_reports[analyzer_type] = report_data
                print(f"   📊 Loaded {analyzer_type.upper()} report with {self._count_findings(report_data)} findings")
            else:
                print(f"   ⚠️  Report file not found: {report_path}")
                
        except Exception as e:
            print(f"   ❌ Failed to load {analyzer_type} report: {str(e)}")
            self.execution_log.append(f"Failed to load {analyzer_type} report: {str(e)}")

    def _count_findings(self, report_data: Dict[str, Any]) -> int:
        """Count findings in a report"""
        if isinstance(report_data, dict):
            # Handle different report formats
            if 'findings' in report_data:
                return len(report_data['findings'])
            elif 'summary' in report_data and 'total_findings' in report_data['summary']:
                return report_data['summary']['total_findings']
            elif 'summary' in report_data and 'total' in report_data['summary']:
                return report_data['summary']['total']
        return 0

    def _generate_comprehensive_report(self, output_prefix: str) -> str:
        """Generate comprehensive markdown report from all individual reports"""
        print(f"\n📄 5. GENERATING COMPREHENSIVE REPORT")
        print("-" * 50)
        
        # Generate comprehensive JSON report
        json_report_path = self.reports_dir / f"{output_prefix}_{self.session_id}.json"
        comprehensive_data = self._create_comprehensive_json()
        
        with open(json_report_path, 'w') as f:
            json.dump(comprehensive_data, f, indent=2)
        
        print(f"   ✅ JSON report saved: {json_report_path}")
        
        # Generate comprehensive markdown report
        markdown_report_path = self.reports_dir / f"{output_prefix}_{self.session_id}.md"
        markdown_content = self._create_comprehensive_markdown(comprehensive_data)
        
        with open(markdown_report_path, 'w') as f:
            f.write(markdown_content)
        
        print(f"   ✅ Markdown report saved: {markdown_report_path}")
        
        return str(markdown_report_path)

    def _create_comprehensive_json(self) -> Dict[str, Any]:
        """Create comprehensive JSON report combining all analyzer results"""
        total_findings = 0
        all_findings = []
        all_tools = set()
        severity_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # Aggregate data from all reports
        for analyzer_type, report_data in self.individual_reports.items():
            findings = self._extract_findings(report_data, analyzer_type)
            all_findings.extend(findings)
            total_findings += len(findings)
            
            # Extract tools used
            tools = self._extract_tools(report_data)
            all_tools.update(tools)
            
            # Aggregate severity distribution
            severity_dist = self._extract_severity_distribution(report_data)
            for severity, count in severity_dist.items():
                if severity in severity_distribution:
                    severity_distribution[severity] += count

        # Calculate risk assessment
        risk_score = self._calculate_overall_risk_score(severity_distribution)
        risk_level = self._get_risk_level(risk_score)
        
        comprehensive_data = {
            'metadata': {
                'session_id': self.session_id,
                'timestamp': self.timestamp.isoformat(),
                'assessment_type': 'comprehensive_security_assessment',
                'educational_mode': self.educational_mode,
                'analyzers_used': list(self.individual_reports.keys()),
                'total_analyzers': len(self.individual_reports),
                'execution_log': self.execution_log
            },
            'executive_summary': {
                'total_findings': total_findings,
                'overall_risk_score': risk_score,
                'overall_risk_level': risk_level,
                'severity_distribution': severity_distribution,
                'analyzers_completed': len(self.individual_reports),
                'key_recommendations': self._generate_key_recommendations()
            },
            'detailed_results': {
                'all_findings': all_findings,
                'findings_by_analyzer': {
                    analyzer: self._extract_findings(report, analyzer)
                    for analyzer, report in self.individual_reports.items()
                },
                'tools_used': list(all_tools)
            },
            'individual_reports': self.individual_reports,
            'risk_assessment': {
                'methodology': self._get_risk_methodology(),
                'scoring_criteria': self._get_scoring_criteria(),
                'recommendations': self._generate_detailed_recommendations()
            },
            'educational_insights': self._generate_educational_insights() if self.educational_mode else {}
        }
        
        return comprehensive_data

    def _extract_findings(self, report_data: Dict[str, Any], analyzer_type: str) -> List[Dict[str, Any]]:
        """Extract findings from a report and normalize format"""
        findings = []
        
        if isinstance(report_data, dict):
            raw_findings = []
            
            # Handle different report structures
            if 'findings' in report_data:
                raw_findings = report_data['findings']
            elif isinstance(report_data, dict) and any(key.endswith('_report') for key in report_data.keys()):
                # Handle combined demo reports
                for key, sub_report in report_data.items():
                    if isinstance(sub_report, dict) and 'findings' in sub_report:
                        raw_findings.extend(sub_report['findings'])
            
            # Normalize findings format
            for finding in raw_findings:
                if isinstance(finding, dict):
                    normalized_finding = {
                        'analyzer': analyzer_type,
                        'severity': finding.get('severity', 'unknown'),
                        'title': finding.get('title', 'Unknown Issue'),
                        'description': finding.get('description', ''),
                        'tool': finding.get('tool', analyzer_type),
                        'target': finding.get('target', finding.get('file_path', 'Unknown')),
                        'cwe_id': finding.get('cwe_id'),
                        'confidence': finding.get('confidence'),
                        'remediation': finding.get('remediation'),
                        'educational_note': finding.get('educational_note'),
                        'category': finding.get('category', finding.get('owasp_category')),
                        'raw_finding': finding  # Keep original for reference
                    }
                    findings.append(normalized_finding)
        
        return findings

    def _extract_tools(self, report_data: Dict[str, Any]) -> List[str]:
        """Extract tools used from a report"""
        tools = []
        
        if isinstance(report_data, dict):
            if 'tools_used' in report_data:
                tools.extend(report_data['tools_used'])
            elif isinstance(report_data, dict) and any(key.endswith('_report') for key in report_data.keys()):
                # Handle combined demo reports
                for sub_report in report_data.values():
                    if isinstance(sub_report, dict) and 'tools_used' in sub_report:
                        tools.extend(sub_report['tools_used'])
        
        return tools

    def _extract_severity_distribution(self, report_data: Dict[str, Any]) -> Dict[str, int]:
        """Extract severity distribution from a report"""
        severity_dist = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        if isinstance(report_data, dict):
            # Try to get from summary first
            if 'summary' in report_data:
                summary = report_data['summary']
                if 'severity_distribution' in summary:
                    for severity, count in summary['severity_distribution'].items():
                        if severity in severity_dist:
                            severity_dist[severity] += count
                elif isinstance(summary, dict):
                    # Try individual severity fields
                    for severity in severity_dist.keys():
                        if severity in summary:
                            severity_dist[severity] += summary[severity]
            
            # If no summary, count from findings
            if sum(severity_dist.values()) == 0 and 'findings' in report_data:
                for finding in report_data['findings']:
                    if isinstance(finding, dict):
                        severity = finding.get('severity', '').lower()
                        if severity in severity_dist:
                            severity_dist[severity] += 1
        
        return severity_dist

    def _calculate_overall_risk_score(self, severity_distribution: Dict[str, int]) -> float:
        """Calculate overall risk score based on severity distribution"""
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        
        total_score = sum(severity_distribution[severity] * weight
                         for severity, weight in weights.items())
        total_findings = sum(severity_distribution.values())
        
        if total_findings == 0:
            return 0.0
        
        # Normalize to 0-100 scale
        max_possible_per_finding = weights['critical']
        average_score_per_finding = total_score / total_findings
        normalized_score = (average_score_per_finding / max_possible_per_finding) * 100
        
        return round(normalized_score, 1)

    def _get_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    def _generate_key_recommendations(self) -> List[str]:
        """Generate key recommendations based on findings"""
        recommendations = []
        
        # Analyze findings to generate specific recommendations
        total_findings = sum(sum(self._extract_severity_distribution(report).values())
                           for report in self.individual_reports.values())
        
        if total_findings == 0:
            recommendations.append("Continue maintaining good security practices")
            recommendations.append("Implement regular security assessments")
        else:
            recommendations.append("Address high and critical severity findings immediately")
            recommendations.append("Implement security monitoring and alerting")
            recommendations.append("Conduct regular security training for development team")
            recommendations.append("Establish secure coding standards and code review processes")
            
        if 'pentest' in self.individual_reports:
            recommendations.append("Implement penetration testing as part of regular security assessments")
            
        return recommendations[:5]  # Limit to top 5

    def _get_risk_methodology(self) -> str:
        """Get risk assessment methodology description"""
        return ("Risk assessment based on OWASP risk rating methodology. "
                "Severity levels weighted: Critical (10), High (7), Medium (4), Low (2), Info (1). "
                "Overall score calculated as weighted average normalized to 0-100 scale.")

    def _get_scoring_criteria(self) -> Dict[str, str]:
        """Get scoring criteria explanation"""
        return {
            "CRITICAL (80-100)": "Immediate action required - vulnerabilities can lead to full system compromise",
            "HIGH (60-79)": "High priority - significant security weaknesses that should be addressed quickly",
            "MEDIUM (40-59)": "Medium priority - security issues that should be addressed in next release cycle",
            "LOW (20-39)": "Low priority - minor security improvements recommended",
            "MINIMAL (0-19)": "Good security posture - continue monitoring and maintenance"
        }

    def _generate_detailed_recommendations(self) -> List[str]:
        """Generate detailed recommendations based on all findings"""
        recommendations = []
        
        # Add general security recommendations
        recommendations.extend([
            "Implement a comprehensive security testing strategy including SAST, DAST, and penetration testing",
            "Establish security requirements and acceptance criteria for all development projects",
            "Create incident response procedures for security vulnerabilities",
            "Implement security monitoring and logging for all applications",
            "Conduct regular security awareness training for all team members",
            "Establish secure development lifecycle (SDLC) practices",
            "Implement automated security testing in CI/CD pipelines",
            "Conduct regular threat modeling exercises",
            "Maintain an inventory of all applications and their security status",
            "Establish relationships with security researchers for responsible disclosure"
        ])
        
        return recommendations

    def _generate_educational_insights(self) -> Dict[str, Any]:
        """Generate educational insights for learning purposes"""
        insights = {
            'security_testing_types': {
                'SAST': {
                    'description': 'Static Application Security Testing - analyzes source code without executing it',
                    'benefits': ['Early detection of vulnerabilities', 'Full code coverage', 'Cost-effective'],
                    'limitations': ['Cannot detect runtime issues', 'May have false positives', 'Limited context']
                },
                'DAST': {
                    'description': 'Dynamic Application Security Testing - tests running applications',
                    'benefits': ['Tests real runtime behavior', 'Low false positives', 'Tests actual attack scenarios'],
                    'limitations': ['Limited code coverage', 'Requires running application', 'Later in development']
                },
                'Network Analysis': {
                    'description': 'Monitors network traffic and connections for suspicious activity',
                    'benefits': ['Detects network-based attacks', 'Monitors live traffic', 'Infrastructure visibility'],
                    'limitations': ['Requires network access', 'May miss encrypted traffic', 'Complex setup']
                },
                'Penetration Testing': {
                    'description': 'Active exploitation testing to prove vulnerability impact',
                    'benefits': ['Proves real exploitability', 'Tests defense mechanisms', 'Comprehensive assessment'],
                    'limitations': ['Requires expertise', 'Potential system impact', 'Time intensive']
                }
            },
            'security_concepts': self._extract_educational_concepts(),
            'learning_recommendations': [
                'Study OWASP Top 10 and understand each vulnerability type',
                'Practice secure coding techniques for your programming language',
                'Learn about common attack vectors and mitigation strategies',
                'Understand the security testing pyramid: Unit tests, Integration tests, System tests',
                'Study threat modeling methodologies like STRIDE or PASTA',
                'Practice using security tools and understanding their outputs',
                'Learn about security compliance requirements relevant to your industry'
            ]
        }
        
        return insights

    def _extract_educational_concepts(self) -> List[str]:
        """Extract educational concepts from vulnerability database"""
        concepts = []
        
        # Extract unique concepts from vulnerability database
        for vuln_type, vuln_info in vulnerability_db.items():
            if 'student_explanation' in vuln_info:
                concepts.append(f"{vuln_type.replace('_', ' ').title()}: {vuln_info['student_explanation']}")
        
        return concepts[:10]  # Limit to top 10

    def _create_comprehensive_markdown(self, comprehensive_data: Dict[str, Any]) -> str:
        """Create comprehensive markdown report"""
        lines = []
        
        # Header
        lines.extend([
            "# 🛡️ Comprehensive Security Assessment Report",
            "",
            f"**Session ID:** {comprehensive_data['metadata']['session_id']}",
            f"**Timestamp:** {comprehensive_data['metadata']['timestamp']}",
            f"**Assessment Type:** Comprehensive Security Assessment",
            f"**Educational Mode:** {'Enabled' if comprehensive_data['metadata']['educational_mode'] else 'Disabled'}",
            "",
            "---",
            ""
        ])
        
        # Executive Summary
        executive = comprehensive_data['executive_summary']
        lines.extend([
            "## 📊 Executive Summary",
            "",
            f"- **Total Findings:** {executive['total_findings']}",
            f"- **Overall Risk Level:** {executive['overall_risk_level']}",
            f"- **Overall Risk Score:** {executive['overall_risk_score']}/100",
            f"- **Analyzers Completed:** {executive['analyzers_completed']}/4",
            "",
            "### Severity Distribution",
            ""
        ])
        
        severity_dist = executive['severity_distribution']
        for severity, count in severity_dist.items():
            if count > 0:
                emoji = self._get_severity_emoji(severity)
                lines.append(f"- {emoji} **{severity.capitalize()}:** {count}")
        
        lines.extend(["", "### Key Recommendations", ""])
        for i, rec in enumerate(executive['key_recommendations'], 1):
            lines.append(f"{i}. {rec}")
        
        lines.extend(["", "---", ""])
        
        # Detailed Results by Analyzer
        lines.extend([
            "## 🔍 Detailed Results by Security Testing Type",
            ""
        ])
        
        for analyzer_type, report_data in self.individual_reports.items():
            lines.extend(self._create_analyzer_section(analyzer_type, report_data))
        
        # Risk Assessment
        lines.extend([
            "## 🎯 Risk Assessment",
            "",
            f"**Methodology:** {comprehensive_data['risk_assessment']['methodology']}",
            "",
            "### Scoring Criteria",
            ""
        ])
        
        for level, description in comprehensive_data['risk_assessment']['scoring_criteria'].items():
            lines.append(f"- **{level}:** {description}")
        
        lines.extend(["", "### Detailed Recommendations", ""])
        for i, rec in enumerate(comprehensive_data['risk_assessment']['recommendations'][:10], 1):
            lines.append(f"{i}. {rec}")
        
        # Educational Insights (if enabled)
        if comprehensive_data['educational_insights']:
            lines.extend(["", "---", "", "## 🎓 Educational Insights", ""])
            lines.extend(self._create_educational_section(comprehensive_data['educational_insights']))
        
        # Execution Log
        lines.extend([
            "", "---", "",
            "## 📋 Execution Log",
            "",
            "The following commands were executed during this assessment:",
            ""
        ])
        
        for i, log_entry in enumerate(comprehensive_data['metadata']['execution_log'], 1):
            lines.append(f"{i}. `{log_entry}`")
        
        # Footer
        lines.extend([
            "", "---", "",
            "## ⚠️ Important Notes",
            "",
            "- This report is generated for educational purposes and authorized security testing only",
            "- Results should be verified manually and assessed within proper business context",
            "- Remediation should be prioritized based on business impact and exploitability",
            "- Regular security assessments should be conducted to maintain security posture",
            "",
            f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ])
        
        return "\n".join(lines)

    def _create_analyzer_section(self, analyzer_type: str, report_data: Dict[str, Any]) -> List[str]:
        """Create markdown section for individual analyzer results"""
        lines = []
        
        # Section header
        analyzer_names = {
            'sast': 'Static Application Security Testing (SAST)',
            'dast': 'Dynamic Application Security Testing (DAST)',
            'network': 'Network Traffic Analysis',
            'pentest': 'Penetration Testing'
        }
        
        analyzer_name = analyzer_names.get(analyzer_type, analyzer_type.upper())
        lines.extend([
            f"### {analyzer_name}",
            ""
        ])
        
        # Extract findings and summary
        findings = self._extract_findings(report_data, analyzer_type)
        severity_dist = self._extract_severity_distribution(report_data)
        tools = self._extract_tools(report_data)
        
        lines.extend([
            f"**Findings:** {len(findings)}",
            f"**Tools Used:** {', '.join(tools) if tools else 'None'}",
            ""
        ])
        
        # Severity breakdown
        if any(severity_dist.values()):
            lines.append("**Severity Breakdown:**")
            for severity, count in severity_dist.items():
                if count > 0:
                    emoji = self._get_severity_emoji(severity)
                    lines.append(f"- {emoji} {severity.capitalize()}: {count}")
            lines.append("")
        
        # Top findings
        if findings:
            high_severity_findings = [f for f in findings if f['severity'] in ['critical', 'high']]
            if high_severity_findings:
                lines.extend(["**Key Findings:**", ""])
                for i, finding in enumerate(high_severity_findings[:5], 1):
                    lines.append(f"{i}. **{finding['title']}** ({finding['severity'].upper()})")
                    lines.append(f"   - Target: `{finding['target']}`")
                    lines.append(f"   - Tool: {finding['tool']}")
                    if finding['description']:
                        lines.append(f"   - Description: {finding['description'][:100]}...")
                    lines.append("")
        else:
            lines.extend(["✅ No security issues found by this analyzer.", ""])
        
        return lines

    def _create_educational_section(self, educational_insights: Dict[str, Any]) -> List[str]:
        """Create educational insights section"""
        lines = []
        
        # Security testing types
        if 'security_testing_types' in educational_insights:
            lines.extend(["### Security Testing Types", ""])
            
            for test_type, info in educational_insights['security_testing_types'].items():
                lines.extend([
                    f"#### {test_type}",
                    f"{info['description']}",
                    "",
                    "**Benefits:**"
                ])
                for benefit in info['benefits']:
                    lines.append(f"- {benefit}")
                
                lines.append("")
                lines.append("**Limitations:**")
                for limitation in info['limitations']:
                    lines.append(f"- {limitation}")
                lines.append("")
        
        # Learning recommendations
        if 'learning_recommendations' in educational_insights:
            lines.extend(["### Learning Recommendations", ""])
            for i, rec in enumerate(educational_insights['learning_recommendations'], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")
        
        # Security concepts
        if 'security_concepts' in educational_insights:
            lines.extend(["### Security Concepts Covered", ""])
            for concept in educational_insights['security_concepts']:
                lines.append(f"- {concept}")
            lines.append("")
        
        return lines

    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emojis = {
            'critical': '🚨',
            'high': '🔴',
            'medium': '🟡',
            'low': '🔵',
            'info': 'ℹ️'
        }
        return emojis.get(severity.lower(), '❓')


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Comprehensive Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Comprehensive assessment of a web application
  python comprehensive_security_report.py http://localhost:5000
  
  # Test local code and web application
  python comprehensive_security_report.py http://localhost:5000 --target-path /path/to/code
  
  # Test demo applications with all security modules
  python comprehensive_security_report.py --demo-apps --educational
  
  # Full assessment including penetration testing
  python comprehensive_security_report.py http://localhost:5000 --include-pentest
  
  # Quick assessment (faster scans)
  python comprehensive_security_report.py http://localhost:5000 --quick-scan
  
  # Custom output filename
  python comprehensive_security_report.py http://localhost:5000 --output my_security_report

Security Testing Modules:
  - SAST: Static code analysis for source code vulnerabilities
  - DAST: Dynamic testing of running web applications  
  - Network: Network traffic analysis and monitoring
  - Penetration Testing: Active exploitation testing (optional)

Note: Only test applications you own or have explicit permission to test.
        """
    )

    parser.add_argument('target_url', nargs='?',
                        help='Target URL for web application testing (e.g., http://localhost:5000)')

    parser.add_argument('--target-path',
                        help='Local path for static code analysis')

    parser.add_argument('--demo-apps', action='store_true',
                        help='Test demo applications instead of specific target')

    parser.add_argument('--include-pentest', action='store_true',
                        help='Include penetration testing (requires caution and permission)')

    parser.add_argument('--skip-network', action='store_true',
                        help='Skip network traffic analysis')

    parser.add_argument('--quick-scan', action='store_true',
                        help='Run quick scans instead of deep analysis (faster)')

    parser.add_argument('--output', default='comprehensive_security_report',
                        help='Output filename prefix (default: comprehensive_security_report)')

    parser.add_argument('--educational', action='store_true',
                        help='Enable educational mode with detailed explanations')

    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output during execution')

    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Quiet mode - minimal output')

    args = parser.parse_args()

    # Validation
    if not args.demo_apps and not args.target_url:
        print("Error: Either target URL or --demo-apps must be specified")
        print("Example: python comprehensive_security_report.py http://localhost:5000")
        sys.exit(1)

    # Security warning for penetration testing
    if args.include_pentest:
        print("⚠️  WARNING: Penetration testing mode enabled")
        print("Only test applications you own or have explicit permission to test")
        print("Unauthorized penetration testing is illegal")
        print()

    # Initialize reporter
    reporter = ComprehensiveSecurityReporter(educational_mode=args.educational)

    # Run comprehensive assessment
    try:
        report_path = reporter.run_comprehensive_assessment(
            target_url=args.target_url,
            target_path=args.target_path,
            demo_mode=args.demo_apps,
            include_pentest=args.include_pentest,
            include_network=not args.skip_network,
            quick_scan=args.quick_scan,
            output_prefix=args.output
        )
        
        print(f"\n🎉 Comprehensive security assessment completed successfully!")
        print(f"📄 Full report available at: {report_path}")
        
    except KeyboardInterrupt:
        print("\n⚠️  Assessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Assessment failed: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()