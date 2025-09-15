# Dynamic Application Security Testing (DAST) Exercise

## 📖 Overview

Dynamic Application Security Testing (DAST) is a "black-box" security testing method that finds vulnerabilities in running web applications. Unlike Static Application Security Testing (SAST) which examines source code, DAST tests applications from the outside by sending requests and analyzing responses.

**Key Learning Objectives:**
- ✅ Understand the difference between SAST and DAST
- ✅ Learn how to test running web applications for security issues
- ✅ Practice using web vulnerability scanners (nikto, gobuster)
- ✅ Identify runtime vulnerabilities like XSS and SQL injection
- ✅ Analyze HTTP responses for security misconfigurations
- ✅ Generate professional dynamic analysis reports

## 🎯 SAST vs DAST Comparison

| Aspect | SAST (Static) | DAST (Dynamic) |
|--------|---------------|----------------|
| **Analysis Type** | Source code analysis | Running application testing |
| **When to Run** | During development | During runtime/testing |
| **Access Needed** | Source code access | Application URL/endpoint |
| **Finds** | Code-level vulnerabilities | Runtime vulnerabilities |
| **Examples** | Hardcoded secrets, unsafe functions | XSS, SQL injection, auth bypass |
| **Speed** | Fast (no app needed) | Slower (requires running app) |
| **Coverage** | All code paths | Only tested paths |

## 🧪 Lab Environment Setup

### Prerequisites
1. Docker Sandbox Demo environment running
2. Sample applications started: `cd docker && docker-compose up -d`
3. Python 3.8+ with DAST tools available
4. Access to the 2 running web applications:
   - Flask App: http://localhost:5000
   - PWA App: http://localhost:9090

### Tool Verification
```bash
# Test the DAST analyzer
python src/analyzer/dast_cli.py --help

# Verify demo applications are running
curl -s http://localhost:5000 | head -5
curl -s http://localhost:9090 | head -5
```

## 🎯 Sample Applications

### 1. Vulnerable Flask Application (Port 5000)
- **Technology**: Python Flask web framework
- **Test URL**: http://localhost:5000
- **Purpose**: Demonstrates web application vulnerabilities
- **Expected Findings**: HTTP security headers, debug information, input validation issues

### 2. Unsecure PWA (Port 9090)  
- **Technology**: Progressive Web App with Python backend
- **Test URL**: http://localhost:9090
- **Purpose**: Demonstrates configuration and session management issues
- **Expected Findings**: Authentication bypass, session issues, redirect vulnerabilities

---

## 📋 Exercise 1: Understanding DAST Fundamentals

### 1.1 Basic DAST Concepts
**Task**: Read and understand the key differences between SAST and DAST

**Questions to Answer:**
1. Why can't DAST find hardcoded passwords in source code?
2. Why can't SAST find SQL injection vulnerabilities that only occur with specific user input?
3. When would you use DAST in a development workflow?

### 1.2 Tool Exploration
Run the DAST help command and explore the available options:

```bash
python src/analyzer/dast_cli.py --help
```

**Key Features to Note:**
- Different scan modes (quick, deep-scan)
- Multiple output formats (JSON, text)
- Educational mode for learning
- Integration with external tools

---

## 📋 Exercise 2: Basic Web Application Scanning

### 2.1 Quick Vulnerability Scan
Start with a quick scan of the Flask application:

```bash
python src/analyzer/dast_cli.py http://localhost:5000 --quick --educational
```

**Analysis Questions:**
1. What security headers are missing?
2. Are there any information disclosure issues?
3. What is the overall risk score?

### 2.2 Deep Scan with Tools
Run a comprehensive scan with all available tools:

```bash
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational --verbose
```

**Observation Tasks:**
1. How many HTTP requests were made during the scan?
2. What additional endpoints were discovered?
3. Which tools provided the most valuable findings?

### 2.3 PWA Application Analysis
Scan the Progressive Web App:

```bash
python src/analyzer/dast_cli.py http://localhost:9090 --educational --output pwa_dast_report.json
```

**Comparison Analysis:**
1. How do the findings differ between the Flask app and PWA?
2. Which application has more severe vulnerabilities?
3. What types of vulnerabilities are unique to each application?

---

## 📋 Exercise 3: Vulnerability Deep Dive

### 3.1 Cross-Site Scripting (XSS) Testing
The DAST scanner tests for XSS automatically. Review the findings:

**Understanding XSS Detection:**
- Scanner sends payloads like `<script>alert('XSS')</script>`
- Checks if the payload appears in the HTTP response
- Different payloads test various XSS scenarios

**Practical Exercise:**
1. Look for XSS findings in your scan results
2. Note which parameters were vulnerable
3. Understand why the scanner classified it as XSS

### 3.2 SQL Injection Detection
Review SQL injection findings from your scans:

**How DAST Finds SQL Injection:**
- Sends malicious SQL payloads like `' OR 1=1--`
- Looks for database error messages in responses
- Tests different injection points (GET/POST parameters)

**Analysis Tasks:**
1. Identify any SQL injection vulnerabilities found
2. Examine the payloads that triggered the detection
3. Understand the evidence that confirmed the vulnerability

### 3.3 Security Configuration Issues
DAST excels at finding configuration problems:

**Common Misconfigurations Found:**
- Missing security headers (X-Frame-Options, CSP)
- Server information disclosure
- Debug mode enabled
- Insecure cookie settings

---

## 📋 Exercise 4: Comparative Analysis

### 4.1 All Applications Scan
Run DAST against both applications simultaneously:

```bash
python src/analyzer/dast_cli.py --demo-apps --educational --output combined_dast_report.json
```

### 4.2 SAST vs DAST Results Comparison
Compare your DAST results with previous SAST results:

**Create Comparison Table:**
| Vulnerability Type | Found by SAST? | Found by DAST? | Why the Difference? |
|-------------------|----------------|----------------|-------------------|
| SQL Injection | | | |
| XSS | | | |
| Missing Security Headers | | | |
| Debug Information | | | |
| Hardcoded Secrets | | | |

**Analysis Questions:**
1. Which testing method found more vulnerabilities overall?
2. What types of issues are unique to each approach?
3. How would you combine SAST and DAST in a security program?

---

## 📋 Exercise 5: Professional Reporting

### 5.1 Generate Executive Summary
Based on your DAST findings, create a security summary:

**Template:**
```
DYNAMIC SECURITY ASSESSMENT SUMMARY

Applications Tested: [List applications]
Testing Duration: [Total scan time]
Total Findings: [Number of issues found]

HIGH-RISK ISSUES:
1. [Most critical finding]
2. [Second most critical finding]
3. [Third most critical finding]

RECOMMENDATIONS:
1. [Top priority fix]
2. [Second priority fix]
3. [Third priority fix]

METHODOLOGY:
- Dynamic black-box testing
- Automated vulnerability scanning
- Manual verification of findings
```

### 5.2 Technical Remediation Guide
For each finding, provide specific remediation steps:

**Example Format:**
```
VULNERABILITY: Missing X-Frame-Options Header

RISK: Medium
DESCRIPTION: Application responses lack clickjacking protection
IMPACT: Users could be tricked into clicking malicious content

REMEDIATION:
1. Add X-Frame-Options header to all responses
2. Set value to 'DENY' or 'SAMEORIGIN'
3. Flask example: response.headers['X-Frame-Options'] = 'DENY'

VERIFICATION:
- Rescan application after implementing fix
- Use browser developer tools to verify header presence
```

---

## 🚀 Advanced Challenges (Optional)

### Challenge 1: Custom Payload Testing
Modify the DAST scanner to test custom payloads:
1. Add new XSS payloads to test
2. Create custom SQL injection test cases
3. Test for specific application logic flaws

### Challenge 2: Authenticated Scanning
Explore how DAST would work with authenticated sessions:
1. Research session-based testing
2. Consider how to test login functionality
3. Plan testing of user-specific features

### Challenge 3: CI/CD Integration
Design how DAST would fit into a development pipeline:
1. When should DAST scans run?
2. How would you handle scan failures?
3. What metrics would you track over time?

---

## 📚 Key Takeaways

### What You Learned:
1. **DAST Fundamentals**: How dynamic testing differs from static analysis
2. **Practical Skills**: Using web vulnerability scanners effectively
3. **Vulnerability Types**: Runtime issues that only DAST can find
4. **Reporting**: Professional security assessment documentation
5. **Integration**: How DAST fits into a comprehensive security program

### Best Practices:
- ✅ Combine SAST and DAST for comprehensive coverage
- ✅ Run DAST against staging environments regularly
- ✅ Focus on high-severity findings first
- ✅ Verify findings manually before reporting
- ✅ Document remediation steps clearly

### Real-World Applications:
- Web application penetration testing
- DevSecOps pipeline integration
- Compliance validation (PCI DSS, SOX)
- Continuous security monitoring
- Security assessment consulting

---

## 🔍 Reflection Questions

1. **Effectiveness**: Which vulnerabilities are better detected by DAST vs SAST?

2. **Limitations**: What are the main limitations of dynamic testing?

3. **Workflow Integration**: How would you integrate DAST into a development team's workflow?

4. **Prioritization**: How do you prioritize DAST findings for remediation?

5. **Coverage**: How do you ensure comprehensive test coverage with DAST?

---

## 📖 Additional Resources

### Industry Standards:
- OWASP Application Security Verification Standard (ASVS)
- NIST Cybersecurity Framework
- ISO 27001 Security Controls

### Tools and Technologies:
- OWASP ZAP (Zed Attack Proxy)
- Burp Suite Professional
- Nessus Web Application Scanning
- Qualys Web Application Scanning

### Learning Path:
1. Master basic web application security concepts
2. Learn manual penetration testing techniques
3. Study advanced DAST tool configuration
4. Explore integration with development workflows
5. Develop custom security testing scripts

**🎓 Congratulations! You've completed the Dynamic Application Security Testing exercise and gained hands-on experience with runtime vulnerability detection!**