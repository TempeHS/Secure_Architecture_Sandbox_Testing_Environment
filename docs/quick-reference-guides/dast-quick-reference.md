# DAST Quick Reference Guide

## 🚀 Command Quick Reference

### Basic Commands
```bash
# Help and options
python src/analyzer/dast_cli.py --help

# Basic scan
python src/analyzer/dast_cli.py http://localhost:5000

# Quick vulnerability check
python src/analyzer/dast_cli.py http://localhost:5000 --quick

# Educational mode with explanations
python src/analyzer/dast_cli.py http://localhost:5000 --educational

# Deep scan with all tools
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan

# Scan all demo applications
python src/analyzer/dast_cli.py --demo-apps --educational
```

### Output and Reporting
```bash
# Save to JSON file
python src/analyzer/dast_cli.py http://localhost:5000 --output report.json

# Save to text file
python src/analyzer/dast_cli.py http://localhost:5000 --output report.txt --format txt

# Verbose output with technical details
python src/analyzer/dast_cli.py http://localhost:5000 --verbose

# Quiet mode (minimal output)
python src/analyzer/dast_cli.py http://localhost:5000 --quiet
```

### Tool-Specific Scans
```bash
# Use specific tools only
python src/analyzer/dast_cli.py http://localhost:5000 --tools nikto
python src/analyzer/dast_cli.py http://localhost:5000 --tools gobuster
python src/analyzer/dast_cli.py http://localhost:5000 --tools nikto gobuster

# All available tools
python src/analyzer/dast_cli.py http://localhost:5000 --tools all
```

## 🎯 Application URLs

| Application | URL | Purpose |
|-------------|-----|---------|
| **Vulnerable Flask App** | http://localhost:5000 | Web application vulnerabilities |
| **Unsecure PWA** | http://localhost:9090 | Progressive web app security |

## 🔍 Understanding DAST vs SAST

| Aspect | SAST (Static) | DAST (Dynamic) |
|--------|---------------|----------------|
| **Analysis Method** | Source code examination | Running application testing |
| **Application State** | Not running | Must be running |
| **Access Required** | Source code | Application URL |
| **Detection Approach** | Pattern matching in code | Black-box testing with payloads |
| **Speed** | Fast | Slower (network requests) |
| **Coverage** | All code paths | Only accessible paths |

## 🛠️ Available DAST Tools

### Built-in Tools:
- **basic_tests**: HTTP header analysis, information disclosure detection
- **vulnerability_tester**: Custom XSS and SQL injection testing
- **header_analyzer**: Security header validation
- **content_analyzer**: Debug information and sensitive data exposure

### External Tools:
- **nikto**: Web vulnerability scanner
- **gobuster**: Directory/file enumeration
- **nmap**: Network port scanning (if available)

## 📊 Common Vulnerability Types Found by DAST

### High Severity:
- **Cross-Site Scripting (XSS)**: User input reflected without sanitization
- **SQL Injection**: Database queries vulnerable to malicious input
- **Authentication Bypass**: Login mechanisms can be circumvented

### Medium Severity:
- **Missing Security Headers**: Lack of protective HTTP headers
- **Information Disclosure**: Server details or debug info exposed
- **Session Management Issues**: Weak session handling

### Low/Info Severity:
- **Directory Listings**: Accessible file/directory structures
- **Version Disclosure**: Software version information exposed
- **Missing Best Practices**: Recommended security configurations absent

## 🔧 HTTP Security Headers

### Critical Headers:
| Header | Purpose | Missing Risk |
|--------|---------|-------------|
| **X-Frame-Options** | Prevents clickjacking | Medium |
| **X-Content-Type-Options** | Prevents MIME sniffing | Medium |
| **X-XSS-Protection** | Browser XSS filtering | Medium |
| **Strict-Transport-Security** | Enforces HTTPS | High |
| **Content-Security-Policy** | Controls resource loading | High |

### Header Values:
```http
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## 📋 DAST Scan Output Interpretation

### Severity Levels:
- **🚨 Critical**: Immediate action required (SQL injection, RCE)
- **🔴 High**: High risk vulnerabilities (XSS, auth bypass)
- **🟡 Medium**: Security misconfigurations (missing headers)
- **🔵 Low**: Information disclosure issues
- **ℹ️ Info**: Best practice recommendations

### Report Sections:
1. **Scan Summary**: Duration, requests made, tools used
2. **Severity Distribution**: Count of findings by severity
3. **OWASP Categories**: Mapping to OWASP Top 10
4. **Detailed Findings**: Individual vulnerability details
5. **Risk Score**: Overall security posture rating

## 🚨 Emergency Troubleshooting

### Applications Not Accessible:
```bash
# Check if containers are running
docker-compose ps

# Start applications
cd docker && docker-compose up -d

# Verify connectivity
curl -I http://localhost:5000
curl -I http://localhost:9090
```

### DAST Scanner Issues:
```bash
# Check Python environment
python --version
pip list | grep requests

# Test with minimal command
python src/analyzer/dast_cli.py http://localhost:5000 --quick

# Enable verbose logging
python src/analyzer/dast_cli.py http://localhost:5000 --verbose
```

### Common Error Messages:
- **"Connection refused"**: Application not running
- **"Target URL is required"**: Missing URL parameter
- **"Invalid URL"**: URL must start with http:// or https://
- **"No findings"**: May be normal, try --deep-scan for more thorough testing

## 🎓 Educational Tips

### Understanding Results:
1. **Start with Summary**: Review total findings and severity distribution
2. **Focus on High Severity**: Address critical and high findings first
3. **Understand Detection**: Learn why each finding was classified as vulnerable
4. **Verify Manually**: Use browser tools to confirm findings

### Best Practices:
- Always run DAST against staging/test environments, never production
- Combine DAST with SAST for comprehensive coverage
- Regular scanning catches new vulnerabilities as code changes
- Document findings and track remediation progress

### Learning Path:
1. **Basic Concepts**: Understand HTTP, web applications, security basics
2. **Tool Usage**: Master command-line options and output interpretation
3. **Manual Verification**: Learn to validate findings using browser tools
4. **Remediation**: Understand how to fix identified vulnerabilities
5. **Integration**: Plan DAST into development workflows

## 📚 OWASP Top 10 Mapping

| OWASP Category | DAST Detection | Tools Used |
|----------------|----------------|------------|
| A01 - Broken Access Control | Authentication testing | Custom tests |
| A02 - Cryptographic Failures | HTTPS analysis | Header analyzer |
| A03 - Injection | SQL injection, XSS testing | Vulnerability tester |
| A04 - Insecure Design | Manual analysis needed | N/A |
| A05 - Security Misconfiguration | Missing headers, debug info | Header analyzer |
| A06 - Vulnerable Components | Limited detection | Basic reconnaissance |
| A07 - Authentication Failures | Login bypass testing | Custom tests |
| A08 - Software Integrity Failures | Limited detection | N/A |
| A09 - Security Logging Failures | Limited detection | N/A |
| A10 - Server-Side Request Forgery | SSRF testing | Custom tests |

## 🔗 Useful Resources

### Official Documentation:
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/

### Tools:
- OWASP ZAP: https://www.zaproxy.org/
- Burp Suite: https://portswigger.net/burp
- Nikto: https://cirt.net/Nikto2

### Learning:
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- OWASP WebGoat: https://owasp.org/www-project-webgoat/

---

**💡 Remember**: DAST is most effective when applications are running in a realistic test environment. Always combine with other testing methods for comprehensive security coverage!