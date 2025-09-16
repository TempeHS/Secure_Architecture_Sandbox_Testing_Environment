"""
Dynamic Application Security Testing (DAST) Module for Cybersecurity Education

This module provides comprehensive dynamic analysis capabilities for educational
cybersecurity demonstrations. It performs runtime security testing against
running web applications to identify vulnerabilities that can only be detected
during execution.

Supported Analysis Types:
- Web Application Scanning (nikto, gobuster)
- HTTP Request/Response Analysis
- Authentication Testing
- Input Validation Testing (XSS, SQL Injection)
- Session Management Testing
- Configuration Testing
- Educational Vulnerability Demonstrations

Author: Cybersecurity Sandbox Demo
License: MIT (Educational Use)
"""

import os
import json
import subprocess
import requests
import time
import re
import socket
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import logging
from urllib.parse import urljoin, urlparse, parse_qs
from .vulnerability_database import vulnerability_db
import threading
import queue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class DynamicFinding:
    """Represents a security finding from dynamic analysis"""
    tool: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    request_data: Optional[str] = None
    response_data: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: str = "medium"  # high, medium, low
    payload: Optional[str] = None
    evidence: Optional[str] = None


@dataclass
class DynamicAnalysisReport:
    """Container for dynamic analysis results"""
    target_url: str
    scan_duration: float
    timestamp: str
    findings: List[DynamicFinding]
    tools_used: List[str]
    total_requests: int
    successful_responses: int
    error_responses: int
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary format"""
        return {
            'target_url': self.target_url,
            'scan_duration': self.scan_duration,
            'timestamp': self.timestamp,
            'findings': [asdict(finding) for finding in self.findings],
            'tools_used': self.tools_used,
            'total_requests': self.total_requests,
            'successful_responses': self.successful_responses,
            'error_responses': self.error_responses,
            'summary': self.summary
        }


class WebCrawler:
    """Simple web crawler for discovering application endpoints"""

    def __init__(self, base_url: str, max_depth: int = 2):
        self.base_url = base_url
        self.max_depth = max_depth
        self.visited_urls = set()
        self.discovered_urls = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DAST-Educational-Scanner/1.0'
        })

    def crawl(self) -> List[str]:
        """Crawl the web application to discover endpoints"""
        try:
            self._crawl_recursive(self.base_url, 0)
            return list(self.discovered_urls)
        except Exception as e:
            logger.error(f"Error during crawling: {e}")
            return [self.base_url]  # Return at least the base URL

    def _crawl_recursive(self, url: str, depth: int):
        """Recursively crawl URLs up to max_depth"""
        if depth > self.max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)

        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                self.discovered_urls.add(url)

                # Extract links from HTML
                links = self._extract_links(response.text, url)
                for link in links:
                    if self._is_same_domain(link, self.base_url):
                        self._crawl_recursive(link, depth + 1)

        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML content"""
        links = []
        # Simple regex for href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        matches = re.findall(href_pattern, html, re.IGNORECASE)

        for match in matches:
            if match.startswith('http'):
                links.append(match)
            elif match.startswith('/'):
                links.append(urljoin(base_url, match))

        return links

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if URL belongs to the same domain"""
        try:
            return urlparse(url).netloc == urlparse(base_url).netloc
        except:
            return False


class VulnerabilityTester:
    """Tests for common web application vulnerabilities"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DAST-Educational-Scanner/1.0'
        })

        # XSS payloads for testing
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>"
        ]

        # SQL injection payloads
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "1' UNION SELECT NULL--",
            "admin'--"
        ]

    def test_xss(self, url: str, params: Dict[str, str]) -> List[DynamicFinding]:
        """Test for Cross-Site Scripting vulnerabilities"""
        findings = []

        for param in params:
            for payload in self.xss_payloads:
                test_params = params.copy()
                test_params[param] = payload

                try:
                    response = self.session.get(
                        url, params=test_params, timeout=10)

                    if payload in response.text:
                        finding = DynamicFinding(
                            tool="custom_xss_tester",
                            severity="high",
                            title=f"Reflected XSS in parameter '{param}'",
                            description=f"The parameter '{param}' appears to be vulnerable to reflected XSS. "
                            f"User input is reflected in the response without proper sanitization.",
                            url=response.url,
                            method="GET",
                            status_code=response.status_code,
                            cwe_id="CWE-79",
                            owasp_category="A03:2021 - Injection",
                            confidence="high",
                            payload=payload,
                            evidence=f"Payload '{payload}' reflected in response"
                        )
                        findings.append(finding)
                        break  # Found XSS, no need to test more payloads for this param

                except Exception as e:
                    logger.debug(f"Error testing XSS on {url}: {e}")

        return findings

    def test_sql_injection(self, url: str, params: Dict[str, str]) -> List[DynamicFinding]:
        """Test for SQL Injection vulnerabilities"""
        findings = []

        for param in params:
            for payload in self.sqli_payloads:
                test_params = params.copy()
                test_params[param] = payload

                try:
                    response = self.session.get(
                        url, params=test_params, timeout=10)

                    # Look for SQL error messages
                    sql_errors = [
                        "sqlite3.OperationalError",
                        "MySQL Error",
                        "PostgreSQL Error",
                        "ORA-",
                        "Microsoft SQL Server",
                        "syntax error",
                        "sqlite error"
                    ]

                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            finding = DynamicFinding(
                                tool="custom_sqli_tester",
                                severity="critical",
                                title=f"SQL Injection in parameter '{param}'",
                                description=f"The parameter '{param}' appears to be vulnerable to SQL injection. "
                                f"Database error messages are exposed when malicious SQL is injected.",
                                url=response.url,
                                method="GET",
                                status_code=response.status_code,
                                cwe_id="CWE-89",
                                owasp_category="A03:2021 - Injection",
                                confidence="high",
                                payload=payload,
                                evidence=f"SQL error detected: {error}"
                            )
                            findings.append(finding)
                            break

                except Exception as e:
                    logger.debug(f"Error testing SQL injection on {url}: {e}")

        return findings


class DynamicAnalyzer:
    """Main class for dynamic application security testing"""

    def __init__(self):
        self.tools_available = self._check_tool_availability()
        self.crawler = None
        self.vulnerability_tester = VulnerabilityTester()
        self.request_count = 0
        self.successful_responses = 0
        self.error_responses = 0

    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which external tools are available"""
        tools = {
            'nikto': self._command_exists('nikto'),
            'gobuster': self._command_exists('gobuster'),
            'nmap': self._command_exists('nmap'),
            'curl': self._command_exists('curl')
        }
        logger.info(
            f"Available tools: {[tool for tool, available in tools.items() if available]}")
        return tools

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system PATH"""
        try:
            subprocess.run([command, '--help'],
                           capture_output=True,
                           timeout=5,
                           check=False)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def analyze_application(self, target_url: str,
                            tools: Optional[List[str]] = None,
                            deep_scan: bool = False) -> DynamicAnalysisReport:
        """Perform comprehensive dynamic analysis of a web application"""

        start_time = time.time()
        findings = []
        tools_used = []

        logger.info(f"Starting dynamic analysis of {target_url}")

        # Reset counters
        self.request_count = 0
        self.successful_responses = 0
        self.error_responses = 0

        # 1. Basic connectivity and information gathering
        basic_findings = self._basic_reconnaissance(target_url)
        findings.extend(basic_findings)
        if basic_findings:
            tools_used.append('basic_recon')

        # 2. Web crawling to discover endpoints
        if deep_scan:
            self.crawler = WebCrawler(target_url, max_depth=2)
            discovered_urls = self.crawler.crawl()
            logger.info(f"Discovered {len(discovered_urls)} URLs")
        else:
            discovered_urls = [target_url]

        # 3. Run external tools if available and requested
        if not tools:
            tools = ['nikto', 'gobuster'] if deep_scan else ['basic_tests']

        for tool in tools:
            if tool == 'nikto' and self.tools_available.get('nikto'):
                nikto_findings = self._run_nikto(target_url)
                findings.extend(nikto_findings)
                tools_used.append('nikto')

            elif tool == 'gobuster' and self.tools_available.get('gobuster'):
                gobuster_findings = self._run_gobuster(target_url)
                findings.extend(gobuster_findings)
                tools_used.append('gobuster')

        # 4. Vulnerability testing on discovered URLs
        for url in discovered_urls[:10]:  # Limit to prevent excessive testing
            vuln_findings = self._test_vulnerabilities(url)
            findings.extend(vuln_findings)

        if any(findings for findings in [self._test_vulnerabilities(url) for url in discovered_urls[:10]]):
            tools_used.append('vulnerability_tester')

        # 5. Generate summary
        scan_duration = time.time() - start_time
        summary = self._generate_summary(findings)

        report = DynamicAnalysisReport(
            target_url=target_url,
            scan_duration=scan_duration,
            timestamp=datetime.now().isoformat(),
            findings=findings,
            tools_used=tools_used,
            total_requests=self.request_count,
            successful_responses=self.successful_responses,
            error_responses=self.error_responses,
            summary=summary
        )

        logger.info(
            f"Dynamic analysis completed in {scan_duration:.2f} seconds")
        logger.info(f"Found {len(findings)} potential issues")

        return report

    def _basic_reconnaissance(self, url: str) -> List[DynamicFinding]:
        """Perform basic reconnaissance and information gathering"""
        findings = []

        try:
            self.request_count += 1
            response = requests.get(url, timeout=10, allow_redirects=True)

            if response.status_code == 200:
                self.successful_responses += 1
            else:
                self.error_responses += 1

            # Check for common security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'X-XSS-Protection': 'XSS filtering',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content security policy'
            }

            for header, description in security_headers.items():
                if header not in response.headers:
                    finding = DynamicFinding(
                        tool="header_analyzer",
                        severity="medium",
                        title=f"Missing Security Header: {header}",
                        description=f"The response is missing the '{header}' security header. "
                        f"This header provides {description}.",
                        url=url,
                        method="GET",
                        status_code=response.status_code,
                        cwe_id="CWE-16",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        confidence="high"
                    )
                    findings.append(finding)

            # Check for server information disclosure
            server_header = response.headers.get('Server', '')
            if server_header and not any(x in server_header.lower() for x in ['nginx', 'apache']):
                finding = DynamicFinding(
                    tool="header_analyzer",
                    severity="low",
                    title="Server Information Disclosure",
                    description=f"The server header reveals detailed version information: '{server_header}'. "
                    f"This information can help attackers identify specific vulnerabilities.",
                    url=url,
                    method="GET",
                    status_code=response.status_code,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    confidence="medium",
                    evidence=f"Server: {server_header}"
                )
                findings.append(finding)

            # Check for debug information in response
            debug_patterns = [
                r'debug\s*=\s*true',
                r'traceback',
                r'stack trace',
                r'flask.*debug',
                r'django.*debug'
            ]

            for pattern in debug_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    finding = DynamicFinding(
                        tool="content_analyzer",
                        severity="medium",
                        title="Debug Information Exposure",
                        description="The application appears to be running in debug mode or exposing "
                        "debug information. This can reveal sensitive information about "
                        "the application structure and internal workings.",
                        url=url,
                        method="GET",
                        status_code=response.status_code,
                        cwe_id="CWE-200",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        confidence="medium",
                        evidence=f"Debug pattern found: {pattern}"
                    )
                    findings.append(finding)
                    break

        except Exception as e:
            logger.error(f"Error in basic reconnaissance: {e}")
            self.error_responses += 1

        return findings

    def _test_vulnerabilities(self, url: str) -> List[DynamicFinding]:
        """Test for common web vulnerabilities"""
        findings = []

        try:
            # Parse URL to extract query parameters
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)

            # Convert multi-value params to single values for testing
            test_params = {k: v[0] if v else '' for k, v in params.items()}

            if test_params:
                # Test for XSS
                xss_findings = self.vulnerability_tester.test_xss(
                    url, test_params)
                findings.extend(xss_findings)

                # Test for SQL injection
                sqli_findings = self.vulnerability_tester.test_sql_injection(
                    url, test_params)
                findings.extend(sqli_findings)

        except Exception as e:
            logger.debug(f"Error testing vulnerabilities on {url}: {e}")

        return findings

    def _run_nikto(self, url: str) -> List[DynamicFinding]:
        """Run Nikto web vulnerability scanner"""
        findings = []

        try:
            # Run nikto with basic options
            cmd = ['nikto', '-h', url, '-Format', 'json']
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0 and result.stdout:
                # Parse nikto output (simplified)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'OSVDB' in line or 'OWASP' in line:
                        finding = DynamicFinding(
                            tool="nikto",
                            severity="medium",
                            title="Nikto Finding",
                            description=line.strip(),
                            url=url,
                            method="GET",
                            confidence="medium"
                        )
                        findings.append(finding)

        except subprocess.TimeoutExpired:
            logger.warning("Nikto scan timed out")
        except Exception as e:
            logger.error(f"Error running Nikto: {e}")

        return findings

    def _run_gobuster(self, url: str) -> List[DynamicFinding]:
        """Run Gobuster directory/file enumeration"""
        findings = []

        try:
            # Create a simple wordlist for educational purposes
            wordlist_content = "admin\ntest\nbackup\nconfig\n.git\n.env\ndebug\nlogin\napi"

            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write(wordlist_content)
                wordlist_path = f.name

            try:
                cmd = ['gobuster', 'dir', '-u', url, '-w', wordlist_path, '-q']
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Status: 200' in line:
                            path = line.split()[0] if line.split() else ""
                            if path:
                                finding = DynamicFinding(
                                    tool="gobuster",
                                    severity="info",
                                    title=f"Directory/File Found: {path}",
                                    description=f"Gobuster discovered an accessible path: {path}",
                                    url=urljoin(url, path),
                                    method="GET",
                                    status_code=200,
                                    confidence="high"
                                )
                                findings.append(finding)

            finally:
                os.unlink(wordlist_path)

        except subprocess.TimeoutExpired:
            logger.warning("Gobuster scan timed out")
        except Exception as e:
            logger.error(f"Error running Gobuster: {e}")

        return findings

    def _generate_summary(self, findings: List[DynamicFinding]) -> Dict[str, Any]:
        """Generate analysis summary"""
        severity_counts = {'critical': 0, 'high': 0,
                           'medium': 0, 'low': 0, 'info': 0}
        owasp_categories = {}

        for finding in findings:
            severity_counts[finding.severity] += 1
            if finding.owasp_category:
                owasp_categories[finding.owasp_category] = owasp_categories.get(
                    finding.owasp_category, 0) + 1

        return {
            'total_findings': len(findings),
            'severity_distribution': severity_counts,
            'owasp_categories': owasp_categories,
            'risk_score': self._calculate_risk_score(severity_counts)
        }

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate overall risk score based on findings"""
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        total_score = sum(severity_counts[severity] * weight
                          for severity, weight in weights.items())
        max_possible = sum(severity_counts.values()) * weights['critical']

        return (total_score / max_possible * 100) if max_possible > 0 else 0


def analyze_demo_applications_dynamic(educational: bool = True) -> Dict[str, DynamicAnalysisReport]:
    """Analyze all demo applications with dynamic testing"""

    # Application endpoints (assuming they're running)
    demo_apps = {
        'vulnerable-flask-app': 'http://localhost:5000',
        'unsecure-pwa': 'http://localhost:9090'
    }

    analyzer = DynamicAnalyzer()
    results = {}

    for app_name, url in demo_apps.items():
        try:
            logger.info(f"Analyzing {app_name} at {url}")

            # Check if application is accessible
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                report = analyzer.analyze_application(url, deep_scan=True)
                results[app_name] = report
            else:
                logger.warning(f"{app_name} not accessible at {url}")

        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not connect to {app_name} at {url}: {e}")
            logger.info(
                f"Make sure {app_name} is running before performing dynamic analysis")

    return results
