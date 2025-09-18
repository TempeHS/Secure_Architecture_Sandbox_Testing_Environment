# 🌐 Dynamic Application Security Testing (DAST) Report

> Tests running applications for security vulnerabilities through external interactions

## 📋 Report Information

| Field | Value |
|-------|-------|
| **Generated** | September 18, 2025 at 04:28 AM UTC |
| **Target URL** | http://localhost:5000 |
| **Scan Duration** | 0.12 seconds |

## 📊 Executive Summary

⚠️ **6 security issues** were found. While none are critical, these should be reviewed and addressed.

### Vulnerability Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| ![CRITICAL](https://img.shields.io/badge/CRITICAL-red?style=flat) | 0 | 0.0% |
| ![HIGH](https://img.shields.io/badge/HIGH-orange?style=flat) | 0 | 0.0% |
| ![MEDIUM](https://img.shields.io/badge/MEDIUM-yellow?style=flat) | 0 | 0.0% |
| ![LOW](https://img.shields.io/badge/LOW-green?style=flat) | 0 | 0.0% |
| ![INFO](https://img.shields.io/badge/INFO-blue?style=flat) | 0 | 0.0% |

## 🎯 Learning Objectives

After reviewing this DAST analysis report, you should be able to:

1. Understand how dynamic testing identifies runtime vulnerabilities
2. Learn to analyse web application security through external testing
3. Recognise common web vulnerabilities like XSS and SQL injection
4. Apply defence-in-depth strategies for web application security

## 🔍 Detailed Findings

The following 6 security issues were identified:

### Finding 1

#### ![MEDIUM](https://img.shields.io/badge/MEDIUM-yellow?style=flat) Missing Security Header: X-Frame-Options

![header_analyser](https://img.shields.io/badge/Tool-header_analyser-blue?style=flat)

**Description:** The response is missing the 'X-Frame-Options' security header. This header provides Clickjacking protection.

**URL:** `GET http://localhost:5000` (Status: 200)

**CWE ID:** [CWE-CWE-16](https://cwe.mitre.org/data/definitions/CWE-16.html)

**OWASP Category:** A05:2021 - Security Misconfiguration

**Confidence:** high

### Finding 2

#### ![MEDIUM](https://img.shields.io/badge/MEDIUM-yellow?style=flat) Missing Security Header: X-Content-Type-Options

![header_analyser](https://img.shields.io/badge/Tool-header_analyser-blue?style=flat)

**Description:** The response is missing the 'X-Content-Type-Options' security header. This header provides MIME type sniffing protection.

**URL:** `GET http://localhost:5000` (Status: 200)

**CWE ID:** [CWE-CWE-16](https://cwe.mitre.org/data/definitions/CWE-16.html)

**OWASP Category:** A05:2021 - Security Misconfiguration

**Confidence:** high

### Finding 3

#### ![MEDIUM](https://img.shields.io/badge/MEDIUM-yellow?style=flat) Missing Security Header: X-XSS-Protection

![header_analyser](https://img.shields.io/badge/Tool-header_analyser-blue?style=flat)

**Description:** The response is missing the 'X-XSS-Protection' security header. This header provides XSS filtering.

**URL:** `GET http://localhost:5000` (Status: 200)

**CWE ID:** [CWE-CWE-16](https://cwe.mitre.org/data/definitions/CWE-16.html)

**OWASP Category:** A05:2021 - Security Misconfiguration

**Confidence:** high

### Finding 4

#### ![MEDIUM](https://img.shields.io/badge/MEDIUM-yellow?style=flat) Missing Security Header: Strict-Transport-Security

![header_analyser](https://img.shields.io/badge/Tool-header_analyser-blue?style=flat)

**Description:** The response is missing the 'Strict-Transport-Security' security header. This header provides HTTPS enforcement.

**URL:** `GET http://localhost:5000` (Status: 200)

**CWE ID:** [CWE-CWE-16](https://cwe.mitre.org/data/definitions/CWE-16.html)

**OWASP Category:** A05:2021 - Security Misconfiguration

**Confidence:** high

### Finding 5

#### ![MEDIUM](https://img.shields.io/badge/MEDIUM-yellow?style=flat) Missing Security Header: Content-Security-Policy

![header_analyser](https://img.shields.io/badge/Tool-header_analyser-blue?style=flat)

**Description:** The response is missing the 'Content-Security-Policy' security header. This header provides Content security policy.

**URL:** `GET http://localhost:5000` (Status: 200)

**CWE ID:** [CWE-CWE-16](https://cwe.mitre.org/data/definitions/CWE-16.html)

**OWASP Category:** A05:2021 - Security Misconfiguration

**Confidence:** high

### Finding 6

#### ![LOW](https://img.shields.io/badge/LOW-green?style=flat) Server Information Disclosure

![header_analyser](https://img.shields.io/badge/Tool-header_analyser-blue?style=flat)

**Description:** The server header reveals detailed version information: 'Werkzeug/3.1.3 Python/3.9.23'. This information can help attackers identify specific vulnerabilities.

**URL:** `GET http://localhost:5000` (Status: 200)

**CWE ID:** [CWE-CWE-200](https://cwe.mitre.org/data/definitions/CWE-200.html)

**OWASP Category:** A05:2021 - Security Misconfiguration

**Evidence:** Server: Werkzeug/3.1.3 Python/3.9.23

**Confidence:** medium

## 💡 Recommendations

### General Security Recommendations:

1. Implement proper input validation and output encoding
2. Use security headers to protect against common web attacks
3. Regularly test your application with DAST tools
4. Follow OWASP guidelines for web application security

## 📚 Additional Learning Resources

To learn more about security testing and vulnerability management:

- [OWASP Top 10](https://owasp.org/Top10/) - Most critical web application security risks
- [CWE/SANS Top 25](https://www.sans.org/top25-software-errors/) - Most dangerous software weaknesses
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) - Cybersecurity best practices
- [OWASP ZAP User Guide](https://www.zaproxy.org/docs/)

---

*This report was generated by the Secure Architecture Sandbox Testing Environment Security Analysis Platform*
*Report Type: DAST Analysis*
*Generated: September 18, 2025 at 04:28 AM*
