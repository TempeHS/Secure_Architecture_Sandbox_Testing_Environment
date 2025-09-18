"""
Static Code Analysis Module for Cybersecurity Education

This module provides comprehensive static analysis capabilities for educational
cybersecurity demonstrations. It integrates multiple security tools to analyze
code and generate educational reports about security vulnerabilities.

Supported Analysis Types:
- Python Security Analysis (Bandit, Safety, Semgrep)
- JavaScript/Node.js Analysis (ESLint, npm audit)
- Dependency Vulnerability Scanning
- Pattern-based Security Analysis
- Educational Vulnerability Explanations

Author: Secure Architecture Sandbox Testing Environment
License: MIT (Educational Use)
"""

import os
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging
from .vulnerability_database import vulnerability_db
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a security finding from static analysis"""
    tool: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    column: Optional[int] = None
    cwe_id: Optional[str] = None
    confidence: Optional[str] = None
    rule_id: Optional[str] = None
    category: Optional[str] = None
    educational_note: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class AnalysisReport:
    """Comprehensive analysis report containing all findings"""
    target_path: str
    analysis_timestamp: str
    total_files_analyzed: int
    tools_used: List[str]
    findings: List[Finding]
    summary: Dict[str, int]
    metadata: Dict[str, Any]


class SecurityToolRunner:
    """Handles execution of security analysis tools"""

    def __init__(self, working_directory: str = None):
        self.working_dir = working_directory or os.getcwd()
        self.tools_available = self._check_tool_availability()

    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which security tools are available on the system"""
        tools = {
            'bandit': self._is_command_available('bandit'),
            'safety': self._is_command_available('safety'),
            'semgrep': self._is_command_available('semgrep'),
            'eslint': self._is_command_available('eslint'),
            'npm': self._is_command_available('npm'),
            'flake8': self._is_command_available('flake8'),
            'mypy': self._is_command_available('mypy'),
        }

        logger.info(
            f"Available security tools: {[k for k, v in tools.items() if v]}")
        return tools

    @staticmethod
    def _is_command_available(command: str) -> bool:
        """Check if a command is available in PATH"""
        try:
            subprocess.run([command, '--version'],
                           capture_output=True, check=False, timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def run_bandit(self, target_path: str) -> List[Finding]:
        """Run Bandit security analysis on Python code"""
        if not self.tools_available.get('bandit', False):
            logger.warning(
                "Bandit not available, skipping Python security analysis")
            return []

        findings = []
        try:
            cmd = [
                'bandit', '-r', target_path,
                '-f', 'json',
                '--skip', 'B101',  # Skip assert_used test for education
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )

            if result.stdout:
                bandit_data = json.loads(result.stdout)

                for issue in bandit_data.get('results', []):
                    finding = Finding(
                        tool='bandit',
                        severity=self._map_bandit_severity(
                            issue.get('issue_severity')),
                        title=issue.get('test_name', 'Unknown Issue'),
                        description=issue.get('issue_text', ''),
                        file_path=issue.get('filename', ''),
                        line_number=issue.get('line_number'),
                        cwe_id=issue.get('issue_cwe', {}).get('id'),
                        confidence=issue.get('issue_confidence'),
                        rule_id=issue.get('test_id'),
                        category='python_security',
                        educational_note=self._get_educational_note(
                            'bandit', issue.get('test_id'),
                            issue.get('test_name', '')),
                        remediation=self._get_remediation(
                            'bandit', issue.get('test_id'),
                            issue.get('test_name', ''))
                    )
                    findings.append(finding)

            logger.info(f"Bandit analysis completed: {len(findings)} findings")

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            logger.error(f"Bandit analysis failed: {str(e)}")

        return findings

    def run_safety(self, target_path: str) -> List[Finding]:
        """Run Safety analysis for Python dependency vulnerabilities"""
        if not self.tools_available.get('safety', False):
            logger.warning(
                "Safety not available, skipping dependency analysis")
            return []

        findings = []
        try:
            # Look for requirements.txt files
            req_files = list(Path(target_path).rglob('requirements.txt'))

            for req_file in req_files:
                cmd = ['safety', 'check', '--json', '--file', str(req_file)]

                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30
                )

                if result.stdout and result.stdout.strip():
                    try:
                        safety_data = json.loads(result.stdout)

                        for vuln in safety_data:
                            finding = Finding(
                                tool='safety',
                                severity='high',  # Most dependency vulns are high
                                title=f"Vulnerable dependency: {vuln.get('package')}",
                                description=vuln.get('advisory', ''),
                                file_path=str(req_file),
                                line_number=None,
                                cwe_id=None,
                                confidence='high',
                                rule_id=vuln.get('id'),
                                category='dependency_vulnerability',
                                educational_note=self._get_educational_note(
                                    'safety', 'dependency_vuln'),
                                remediation=f"Update {vuln.get('package')} to version {vuln.get('vulnerable_versions', 'latest')}"
                            )
                            findings.append(finding)
                    except json.JSONDecodeError:
                        # Safety might return no JSON if no vulnerabilities
                        pass

            logger.info(f"Safety analysis completed: {len(findings)} findings")

        except (subprocess.TimeoutExpired, Exception) as e:
            logger.error(f"Safety analysis failed: {str(e)}")

        return findings

    def run_semgrep(self, target_path: str) -> List[Finding]:
        """Run Semgrep pattern-based security analysis"""
        if not self.tools_available.get('semgrep', False):
            logger.warning("Semgrep not available, skipping pattern analysis")
            return []

        findings = []
        try:
            cmd = [
                'semgrep', '--config=auto',
                '--json', target_path
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )

            if result.stdout:
                semgrep_data = json.loads(result.stdout)

                for result_item in semgrep_data.get('results', []):
                    severity = self._map_semgrep_severity(
                        result_item.get('extra', {}).get('severity'))

                    finding = Finding(
                        tool='semgrep',
                        severity=severity,
                        title=result_item.get('extra', {}).get(
                            'message', 'Security Pattern Detected'),
                        description=result_item.get(
                            'extra', {}).get('message', ''),
                        file_path=result_item.get('path', ''),
                        line_number=result_item.get('start', {}).get('line'),
                        column=result_item.get('start', {}).get('col'),
                        rule_id=result_item.get('check_id'),
                        category='pattern_analysis',
                        educational_note=self._get_educational_note(
                            'semgrep', result_item.get('check_id'),
                            result_item.get('message', '')),
                        remediation=self._get_remediation(
                            'semgrep', result_item.get('check_id'),
                            result_item.get('message', ''))
                    )
                    findings.append(finding)

            logger.info(
                f"Semgrep analysis completed: {len(findings)} findings")

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            logger.error(f"Semgrep analysis failed: {str(e)}")

        return findings

    def run_npm_audit(self, target_path: str) -> List[Finding]:
        """Run npm audit for Node.js dependency vulnerabilities"""
        if not self.tools_available.get('npm', False):
            logger.warning("npm not available, skipping Node.js analysis")
            return []

        findings = []
        try:
            # Look for package.json files
            package_files = list(Path(target_path).rglob('package.json'))

            for package_file in package_files:
                package_dir = package_file.parent

                # First try to install dependencies if needed
                if not (package_dir / 'node_modules').exists():
                    install_cmd = ['npm', 'install', '--silent']
                    subprocess.run(
                        install_cmd,
                        cwd=package_dir,
                        capture_output=True,
                        timeout=60
                    )

                # Run npm audit
                cmd = ['npm', 'audit', '--json']

                result = subprocess.run(
                    cmd,
                    cwd=package_dir,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)

                        for vuln_id, vuln in audit_data.get('vulnerabilities', {}).items():
                            severity = vuln.get('severity', 'medium')

                            finding = Finding(
                                tool='npm_audit',
                                severity=severity,
                                title=f"Node.js vulnerability in {vuln_id}",
                                description=vuln.get('title', ''),
                                file_path=str(package_file),
                                line_number=None,
                                rule_id=str(vuln.get('id', vuln_id)),
                                category='nodejs_dependency',
                                educational_note=self._get_educational_note(
                                    'npm', 'dependency_vuln'),
                                remediation=f"Update package {vuln_id} to a secure version"
                            )
                            findings.append(finding)
                    except json.JSONDecodeError:
                        pass

            logger.info(f"npm audit completed: {len(findings)} findings")

        except (subprocess.TimeoutExpired, Exception) as e:
            logger.error(f"npm audit failed: {str(e)}")

        return findings

    @staticmethod
    def _map_bandit_severity(bandit_severity: str) -> str:
        """Map Bandit severity levels to standardized levels"""
        mapping = {
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return mapping.get(bandit_severity, 'medium')

    @staticmethod
    def _map_semgrep_severity(semgrep_severity: str) -> str:
        """Map Semgrep severity levels to standardized levels"""
        mapping = {
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low'
        }
        return mapping.get(semgrep_severity, 'medium')

    def _get_educational_note(self, tool: str, rule_id: str,
                              finding_message: str = "") -> str:
        """Get educational explanation for a specific finding using the 
        vulnerability database"""

        # First try to get explanation from vulnerability database
        if finding_message:
            explanation = vulnerability_db.get_educational_explanation(
                finding_message)
            if explanation != ("Security pattern detected - review for "
                               "potential vulnerabilities."):
                return explanation

        # Fallback to tool-specific educational notes
        educational_notes = {
            'bandit': {
                'B102': ("This finding indicates the use of 'exec()' function, "
                         "which can execute arbitrary code and is dangerous if "
                         "user input is not properly validated."),
                'B301': ("Pickle is unsafe because it can execute arbitrary "
                         "code during deserialization. Consider using JSON for "
                         "data serialization."),
                'B608': ("SQL injection vulnerability detected. Use "
                         "parameterized queries instead of string formatting."),
                'B201': ("Flask debug mode should not be enabled in production "
                         "as it can expose sensitive information."),
                'hardcoded_sql_expressions': ("SQL injection vulnerability "
                                              "detected. Use parameterized queries instead of string "
                                              "formatting."),
                'flask_debug_true': ("Flask debug mode should not be enabled "
                                     "in production as it can expose sensitive information."),
                'subprocess_popen_with_shell_equals_true': ("Using shell=True "
                                                            "with subprocess can lead to command injection "
                                                            "vulnerabilities."),
            },
            'safety': {
                'dependency_vuln': ("This dependency has known security "
                                    "vulnerabilities. Keeping dependencies updated is "
                                    "crucial for security."),
            },
            'npm': {
                'dependency_vuln': ("Node.js dependency vulnerability detected. "
                                    "Regular dependency updates are essential for security."),
            },
            'semgrep': {
                'default': ("Pattern-based analysis detected a potential "
                            "security issue. Review the code for proper input "
                            "validation and security controls."),
            }
        }

        tool_notes = educational_notes.get(tool, {})
        return tool_notes.get(rule_id, tool_notes.get('default',
                                                      "Security pattern detected - review for potential vulnerabilities."))

    def _get_remediation(self, tool: str, rule_id: str,
                         finding_message: str = "") -> str:
        """Get remediation advice for a specific finding using the 
        vulnerability database"""

        # First try to get remediation from vulnerability database
        if finding_message:
            remediation = vulnerability_db.get_remediation_advice(
                finding_message)
            if remediation != ("Review the code and implement appropriate "
                               "security controls."):
                return remediation

        # Fallback to tool-specific remediations
        remediations = {
            'bandit': {
                'B102': ("Replace exec() with safer alternatives. If dynamic "
                         "execution is necessary, validate and sanitize all "
                         "inputs rigorously."),
                'B301': ("Replace pickle with JSON or implement custom "
                         "serialization. If pickle is necessary, ensure data "
                         "source is trusted."),
                'B608': ("Use parameterized queries with placeholders (?). "
                         "Example: cursor.execute('SELECT * FROM users WHERE "
                         "id = ?', (user_id,))"),
                'B201': ("Set debug=False in production. Use environment "
                         "variables to control debug mode."),
                'hardcoded_sql_expressions': ("Use parameterized queries "
                                              "with placeholders (?). Example: cursor.execute"
                                              "('SELECT * FROM users WHERE id = ?', (user_id,))"),
                'flask_debug_true': ("Set debug=False in production. Use "
                                     "environment variables to control debug mode."),
                'subprocess_popen_with_shell_equals_true': ("Avoid using "
                                                            "shell=True. Use subprocess with a list of arguments "
                                                            "instead."),
            }
        }

        tool_remediations = remediations.get(tool, {})
        return tool_remediations.get(rule_id,
                                     "Review the code and implement appropriate security controls.")


class StaticAnalyzer:
    """Main static analysis orchestrator for educational cybersecurity"""

    def __init__(self, working_directory: str = None):
        self.working_dir = working_directory or os.getcwd()
        self.tool_runner = SecurityToolRunner(working_directory)

    def analyze_target(self, target_path: str, analysis_types: List[str] = None) -> AnalysisReport:
        """
        Perform comprehensive static analysis on target path

        Args:
            target_path: Path to analyze (file or directory)
            analysis_types: List of analysis types to run ['python', 'nodejs', 'all']
                          If None, auto-detect based on files present

        Returns:
            AnalysisReport containing all findings and metadata
        """
        target_path = os.path.abspath(target_path)

        if not os.path.exists(target_path):
            raise ValueError(f"Target path does not exist: {target_path}")

        logger.info(f"Starting static analysis of: {target_path}")

        # Auto-detect analysis types if not specified
        if analysis_types is None:
            analysis_types = self._detect_analysis_types(target_path)

        all_findings = []
        tools_used = []

        # Run Python analysis
        if 'python' in analysis_types or 'all' in analysis_types:
            if self._has_python_files(target_path):
                logger.info("Running Python security analysis...")

                # Bandit analysis
                bandit_findings = self.tool_runner.run_bandit(target_path)
                all_findings.extend(bandit_findings)
                if bandit_findings:
                    tools_used.append('bandit')

                # Safety analysis
                safety_findings = self.tool_runner.run_safety(target_path)
                all_findings.extend(safety_findings)
                if safety_findings:
                    tools_used.append('safety')

                # Semgrep analysis
                semgrep_findings = self.tool_runner.run_semgrep(target_path)
                all_findings.extend(semgrep_findings)
                if semgrep_findings:
                    tools_used.append('semgrep')

        # Run Node.js analysis
        if 'nodejs' in analysis_types or 'all' in analysis_types:
            if self._has_nodejs_files(target_path):
                logger.info("Running Node.js security analysis...")

                # npm audit
                npm_findings = self.tool_runner.run_npm_audit(target_path)
                all_findings.extend(npm_findings)
                if npm_findings:
                    tools_used.append('npm_audit')

        # Generate summary statistics
        summary = self._generate_summary(all_findings)

        # Count analyzed files
        total_files = self._count_source_files(target_path)

        # Create analysis report
        report = AnalysisReport(
            target_path=target_path,
            analysis_timestamp=datetime.now().isoformat(),
            total_files_analyzed=total_files,
            tools_used=tools_used,
            findings=all_findings,
            summary=summary,
            metadata={
                'analyzer_version': '1.0.0',
                'analysis_types': analysis_types,
                'total_runtime_seconds': 0,  # TODO: Add timing
                'tools_available': self.tool_runner.tools_available,
            }
        )

        logger.info(f"Analysis completed: {len(all_findings)} total findings")
        return report

    def _detect_analysis_types(self, target_path: str) -> List[str]:
        """Auto-detect what types of analysis to run based on files present"""
        analysis_types = []

        if self._has_python_files(target_path):
            analysis_types.append('python')

        if self._has_nodejs_files(target_path):
            analysis_types.append('nodejs')

        return analysis_types or ['all']  # Fallback to all if nothing detected

    @staticmethod
    def _has_python_files(target_path: str) -> bool:
        """Check if target contains Python files"""
        python_extensions = {'.py', '.pyw'}

        if os.path.isfile(target_path):
            return Path(target_path).suffix in python_extensions

        for root, dirs, files in os.walk(target_path):
            for file in files:
                if Path(file).suffix in python_extensions:
                    return True

        return False

    @staticmethod
    def _has_nodejs_files(target_path: str) -> bool:
        """Check if target contains Node.js files"""
        if os.path.isfile(target_path):
            return target_path.endswith(('.js', '.json', 'package.json'))

        # Look for package.json or .js files
        for root, dirs, files in os.walk(target_path):
            if 'package.json' in files:
                return True
            for file in files:
                if file.endswith('.js'):
                    return True

        return False

    @staticmethod
    def _count_source_files(target_path: str) -> int:
        """Count source code files in target path"""
        if os.path.isfile(target_path):
            return 1

        source_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.json'}
        count = 0

        for root, dirs, files in os.walk(target_path):
            for file in files:
                if Path(file).suffix in source_extensions:
                    count += 1

        return count

    @staticmethod
    def _generate_summary(findings: List[Finding]) -> Dict[str, int]:
        """Generate summary statistics from findings"""
        summary = {
            'total': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for finding in findings:
            severity = finding.severity.lower()
            if severity in summary:
                summary[severity] += 1

        return summary


# Convenience functions for direct usage
def analyze_python_file(file_path: str) -> AnalysisReport:
    """Quick analysis of a single Python file"""
    analyzer = StaticAnalyzer()
    return analyzer.analyze_target(file_path, ['python'])


def analyze_directory(directory_path: str) -> AnalysisReport:
    """Comprehensive analysis of a directory"""
    analyzer = StaticAnalyzer()
    return analyzer.analyze_target(directory_path, ['all'])


def analyze_demo_applications() -> Dict[str, AnalysisReport]:
    """Analyze all demo applications in the samples directory"""
    samples_dir = Path(__file__).parent.parent.parent / 'samples'

    results = {}
    analyzer = StaticAnalyzer()

    demo_apps = [
        'vulnerable-flask-app',
        'vulnerable-nodejs-app',
        'unsecure-pwa'
    ]

    for app in demo_apps:
        app_path = samples_dir / app
        if app_path.exists():
            logger.info(f"Analyzing demo application: {app}")
            results[app] = analyzer.analyze_target(str(app_path))

    return results


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) > 1:
        target = sys.argv[1]
        analyzer = StaticAnalyzer()
        report = analyzer.analyze_target(target)

        print(f"Analysis Report for: {target}")
        print(f"Total findings: {report.summary['total']}")
        print(f"High severity: {report.summary['high']}")
        print(f"Medium severity: {report.summary['medium']}")
        print(f"Low severity: {report.summary['low']}")

        for finding in report.findings[:5]:  # Show first 5 findings
            print(f"\n[{finding.severity.upper()}] {finding.title}")
            print(f"  Tool: {finding.tool}")
            print(
                f"  File: {finding.file_path}:{finding.line_number or 'N/A'}")
            print(f"  Description: {finding.description[:100]}...")
    else:
        print("Usage: python static_analyzer.py <target_path>")
        print("Example: python static_analyzer.py /path/to/vulnerable/app")
