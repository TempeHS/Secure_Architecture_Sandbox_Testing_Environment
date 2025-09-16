# DAST Student Worksheet - Answer Sheet

**Instructor Guide and Answer Key**

---

## 🔧 Pre-Exercise Setup Verification - Expected Responses

### Expected Verification Results:
- **Container Status**: Both `cybersec_sandbox` and `vulnerable_web_app` should show "Up" status
- **Application Access**: Both Flask (5000) and PWA (9090) should respond with HTML content
- **DAST Tool**: Help information should display available options and commands

**Teaching Note**: If verification fails, guide students through troubleshooting steps before proceeding.

---

## 🎯 Learning Objectives - Assessment Criteria

Students should demonstrate understanding of:
- [ ] Dynamic vs Static testing differences (runtime vs code analysis)
- [ ] Web vulnerability scanner execution and interpretation
- [ ] Runtime vulnerability identification (XSS, SQL injection, headers)
- [ ] Professional security assessment methodology and reporting
- [ ] SAST/DAST integration in comprehensive security programs

---

## 📋 Exercise 1: DAST Fundamentals - Answer Key

### 1.1 Concept Understanding

| Testing Aspect | SAST (Static) | DAST (Dynamic) |
|---------------|---------------|----------------|
| **Application must be running** | **No** | **Yes** |
| **Requires source code access** | **Yes** | **No** |
| **Tests actual user input** | **No** | **Yes** |
| **Finds runtime vulnerabilities** | **No** | **Yes** |
| **Speed of analysis** | **Fast** | **Slow** |

**Teaching Points**:
- DAST is "black-box" testing from external perspective
- SAST analyzes all code paths; DAST only tests accessible functionality
- DAST finds configuration and runtime issues SAST cannot detect

### 1.2 Tool Exploration

**3 Scan Modes Available**:
1. **--quick** - Fast scan with basic vulnerability checks
2. **--deep-scan** - Comprehensive scan with directory enumeration and detailed testing
3. **--demo-apps** - Scan all demo applications simultaneously

**Report File Formats**:
- **JSON** - Structured data format for automation and integration
- **Text** - Human-readable format for manual review

---

## 📋 Exercise 2: Basic Web Application Scanning - Answer Key

### 2.1 Flask Application Quick Scan

**Expected Command**: `python src/analyzer/dast_cli.py http://localhost:5000 --quick --educational`

**Typical Scan Results Summary**:
- **Total Findings**: 8-12 security issues
- **Scan Duration**: 15-30 seconds
- **HTTP Requests Made**: 25-40 requests
- **Successful Responses**: 20-35 responses

**Expected Severity Breakdown**:
- **Critical**: 0-1 (severe XSS or SQL injection)
- **High**: 2-4 (XSS, information disclosure)
- **Medium**: 4-6 (missing headers, weak configurations)
- **Low**: 2-4 (information leakage, minor issues)
- **Info**: 1-3 (informational findings)

### 2.2 Security Headers Analysis

**3 Common Missing Security Headers**:
1. **X-Frame-Options** - Prevents clickjacking attacks
2. **X-Content-Type-Options** - Prevents MIME type sniffing
3. **Content-Security-Policy** - Prevents XSS and code injection

**Why Missing Headers Are Concerning**:
- **Clickjacking**: Malicious sites can embed the application in frames
- **MIME Sniffing**: Browsers may execute malicious content
- **XSS**: Lack of CSP allows unrestricted script execution
- **CSRF**: Missing protection allows cross-site request forgery

### 2.3 Deep Scan Analysis

**Expected Command**: `python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational`

**Additional Deep Scan Findings**:
- **Additional endpoints**: /admin, /debug, /config, hidden directories
- **New vulnerabilities**: Directory listing, backup files, admin interfaces
- **Scan time difference**: 60-120 seconds longer than quick scan

**Tools Used in Deep Scan**:
- **Nikto** - Web vulnerability scanner
- **Gobuster** - Directory and file enumeration
- **Custom testers** - XSS and SQL injection probes
- **Header analyzer** - Security header validation

---

## 📋 Exercise 3: PWA Application Analysis - Answer Key

### 3.1 Progressive Web App Scan

**Expected Command**: `python src/analyzer/dast_cli.py http://localhost:9090 --educational --output pwa_report.json`

**Typical PWA Scan Results**:
- **Total Findings**: 6-10 security issues
- **Most Severe Finding**: Missing security headers or session management issues
- **Unique Vulnerabilities**: Service worker security, manifest configuration issues

### 3.2 Application Comparison

| Vulnerability Type | Flask App | PWA App | Which is More Severe? |
|--------------------|-----------|---------|----------------------|
| Missing Security Headers | **Found** | **Found** | **Same** |
| XSS Vulnerabilities | **Found** | **Not Found** | **Flask** |
| SQL Injection | **Found** | **Not Found** | **Flask** |
| Information Disclosure | **Found** | **Found** | **Flask** |

**Higher Overall Risk**: **Flask Application** (typically has more database interactions and user input points)

---

## 📋 Exercise 4: Vulnerability Deep Dive - Answer Key

### 4.1 Cross-Site Scripting (XSS) Analysis

**If XSS Found - Expected Details**:
- **Vulnerable Parameter**: search, comment, username fields
- **Test Payload Used**: `<script>alert('XSS')</script>` or `<img src=x onerror=alert('XSS')>`
- **Evidence**: Script payload reflected in HTML response without encoding

**How DAST Detects XSS**:
- Sends various XSS payloads to input fields
- Analyzes HTTP responses for reflected payloads
- Checks if payloads are properly encoded/escaped
- Tests different contexts (HTML, JavaScript, CSS)

### 4.2 SQL Injection Analysis

**If SQL Injection Found - Expected Details**:
- **Vulnerable Parameter**: login, search, id parameters
- **Test Payload Used**: `' OR 1=1--`, `' UNION SELECT 1,2,3--`
- **Database Error Message**: MySQL/SQLite error messages revealing database structure

**Why Error Messages Indicate SQL Injection**:
- Database errors should not be exposed to users
- Error messages reveal database structure and query construction
- Confirms that user input is being processed as SQL code
- Indicates lack of input validation and parameterized queries

### 4.3 Information Disclosure

**Typical Sensitive Information Disclosed**:
- Server software versions (Apache, Nginx, Flask)
- Directory structures and file listings
- Database error messages and schema information
- Debug information and stack traces
- Application framework details

**How Attackers Use This Information**:
- Target specific versions with known vulnerabilities
- Map application structure for further attacks
- Craft targeted exploits based on technology stack
- Understand application logic and data flow

---

## 📋 Exercise 5: SAST vs DAST Comparison - Answer Key

### 5.1 Combined Analysis Results

**Expected Command**: `python src/analyzer/dast_cli.py --demo-apps --educational`

**SAST vs DAST Comparison Table**:

| Vulnerability Category | SAST Found | DAST Found | Why the Difference? |
|----------------------|------------|------------|-------------------|
| **SQL Injection** | **Yes** | **Yes** | **Both can detect, but SAST finds in code, DAST confirms in runtime** |
| **Cross-Site Scripting** | **Yes** | **Yes** | **SAST finds in templates, DAST confirms in HTTP responses** |
| **Missing Security Headers** | **No** | **Yes** | **Headers are runtime configuration, not visible in source code** |
| **Debug Information** | **Yes** | **Yes** | **SAST finds debug code, DAST finds debug responses** |
| **Hardcoded Secrets** | **Yes** | **No** | **DAST cannot see source code to find hardcoded values** |
| **Dependency Vulnerabilities** | **Yes** | **No** | **DAST cannot analyze imported libraries and versions** |

### 5.2 Methodology Strengths

**2 Advantages of DAST over SAST**:
1. **Tests actual runtime behavior** - Finds configuration and deployment issues
2. **No source code required** - Can test any web application regardless of technology

**2 Advantages of SAST over DAST**:
1. **Faster analysis** - No need to run application or send HTTP requests
2. **Complete code coverage** - Analyzes all code paths, not just accessible ones

**Using Both Methods Together**:
- **Comprehensive coverage** - SAST finds code issues, DAST finds runtime issues
- **Validation** - DAST confirms SAST findings are exploitable
- **CI/CD integration** - SAST in development, DAST in testing phases
- **Risk prioritization** - Combined results provide complete security picture

---

## 📋 Exercise 6: Professional Reporting - Answer Key

### 6.1 Executive Summary Template

**DYNAMIC SECURITY ASSESSMENT SUMMARY**

**Applications Tested**: Flask Web Application (localhost:5000), Progressive Web Application (localhost:9090)

**Total Security Issues Found**: 14-22 vulnerabilities across both applications

**Most Critical Finding**: Missing security headers allowing clickjacking and XSS attacks, or SQL injection vulnerabilities in user input fields

**Immediate Action Required**: 
- Implement Content Security Policy (CSP) headers
- Add X-Frame-Options and X-Content-Type-Options headers
- Validate and sanitize all user inputs
- Disable debug mode in production

**Overall Risk Level**: **High** (due to combination of XSS, missing headers, and information disclosure)

### 6.2 Top 3 Remediation Priorities

**Priority #1**:
- **Vulnerability**: Missing X-Frame-Options header
- **Risk Level**: Medium-High
- **Remediation**: Add `X-Frame-Options: DENY` to all HTTP responses
- **Estimated Effort**: 2-4 hours (configuration change)

**Priority #2**:
- **Vulnerability**: Cross-Site Scripting (XSS) in user input fields
- **Risk Level**: High
- **Remediation**: Implement output encoding and Content Security Policy
- **Estimated Effort**: 8-16 hours (code changes and testing)

**Priority #3**:
- **Vulnerability**: Information disclosure through error messages
- **Risk Level**: Medium
- **Remediation**: Implement custom error pages and disable debug mode
- **Estimated Effort**: 4-8 hours (error handling implementation)

### 6.3 Security Recommendations

**3 General Security Improvements**:
1. **Implement comprehensive security headers** (CSP, HSTS, X-Frame-Options)
2. **Add input validation and output encoding** for all user data
3. **Configure secure session management** with proper timeout and encryption

---

## 🎯 Reflection Questions - Answer Key

### Technical Understanding

**1. Types of vulnerabilities ONLY found through dynamic testing**:
- **Missing security headers** (runtime configuration)
- **Authentication bypass** (session management issues)
- **Server misconfigurations** (directory listing, debug modes)
- **Network-level vulnerabilities** (SSL/TLS issues)
- **Environment-specific issues** (production vs development differences)

**2. Why test applications in running state**:
- **Configuration matters** - Production settings differ from code
- **Integration issues** - Multiple components may create vulnerabilities
- **User perspective** - Tests actual attack surface available to attackers
- **Validation** - Confirms theoretical vulnerabilities are exploitable

**3. Limitations of DAST compared to SAST**:
- **Coverage** - Only tests accessible functionality
- **Speed** - Slower due to HTTP requests and response analysis
- **Depth** - Cannot analyze complex business logic in source code
- **Credentials** - May require authentication to test protected areas

### Practical Application

**4. When to run DAST scans in development workflow**:
- **Integration testing phase** - After application deployment
- **Pre-production testing** - Before release to production
- **Regular security testing** - Monthly or quarterly assessments
- **Post-deployment verification** - Confirm production security

**5. How to verify DAST findings before reporting**:
- **Manual validation** - Manually reproduce the vulnerability
- **Multiple tools** - Cross-validate with other scanners
- **Source code review** - Confirm with SAST findings
- **Expert analysis** - Security professional verification

### Career Relevance

**6. Cybersecurity roles using DAST tools**:
- **Application Security Engineers** - Regular application testing
- **Penetration Testers** - External security assessments
- **Security Consultants** - Client application evaluations
- **DevSecOps Engineers** - Automated security pipeline integration

**7. DAST compliance requirements**:
- **PCI DSS** - Requirement 6.5.1 (application vulnerability testing)
- **SOX** - IT controls validation for financial applications
- **HIPAA** - Security controls testing for healthcare applications
- **ISO 27001** - Regular security assessment requirements

---

## ⚖️ Legal and Ethical Considerations - Answer Key

### Professional Responsibility in Dynamic Testing

**1. Employment Impact**:
**Expected Answer**: Runtime vulnerabilities can lead to immediate security incidents affecting IT and development teams, require emergency response and overtime work, impact performance reviews and team reputation, necessitate additional training and process improvements.

**2. Privacy Rights**:
**Expected Answer**: Runtime testing may expose personal data through XSS or SQL injection, requires careful handling of any discovered data, must comply with privacy regulations during testing, testing should avoid accessing actual user data.

**3. Intellectual Property**:
**Expected Answer**: Security misconfigurations could expose proprietary application logic, business rules, and competitive information through error messages and debug information, API endpoints may reveal trade secrets.

### Regulatory Compliance

**4. Web Application Compliance**:
**Expected Answer**: Missing security headers violate OWASP guidelines, PCI DSS requirements for web application security, and industry security standards for data protection.

**5. Data Protection Violations**:
**Expected Answer**: 
- **GDPR**: XSS and SQL injection violate data protection requirements
- **CCPA**: Security vulnerabilities may lead to unauthorized data access
- **PCI DSS**: Web application vulnerabilities violate payment security requirements

### Ethical Testing Practices

**6. Authorized Testing Importance**:
**Expected Answer**: Unauthorized DAST testing may violate computer crime laws, could cause service disruption or data exposure, requires explicit permission and defined scope, professional liability and legal consequences possible.

**7. Responsible Disclosure**:
**Expected Answer**: Contact application owner privately, provide detailed technical information, allow reasonable time for remediation (90-120 days), coordinate public disclosure timing, avoid exploitation beyond proof-of-concept.

---

## 🔐 Cryptography and Runtime Security - Answer Key

**1. Transport Security Issues**:
**Expected Answer**: Missing HTTPS implementation, weak SSL/TLS configuration, certificate validation bypassing, insecure redirect handling from HTTP to HTTPS.

**2. Session Management**:
**Expected Answer**: Weak session token generation, insecure session storage, missing session timeout, inadequate session invalidation on logout.

**3. Authentication Security**:
**Expected Answer**: Weak password requirements, missing account lockout mechanisms, insecure password reset functionality, lack of multi-factor authentication.

**4. Runtime Cryptography Recommendations**:
**Expected Answer**: Implement HTTPS with strong TLS configuration, use secure session management with proper encryption, implement proper authentication controls, add security headers for additional protection.

---

## 💼 Business Impact Assessment - Answer Key

### Enterprise Runtime Security Impact

**1. Operational Impact**:
**Expected Answer**: Runtime exploitation can cause immediate service disruption, data corruption requiring restoration, customer service interruption, compliance audit failures.

**2. Customer Trust**:
**Expected Answer**: Security incidents damage brand reputation, lead to customer churn and lost revenue, require costly public relations efforts, affect new customer acquisition.

**3. Compliance Costs**:
- **PCI DSS Violations**: $5,000-100,000 per month until remediated
- **Data Protection Fines**: €20M or 4% annual revenue (GDPR), up to $7,500 per violation (CCPA)
- **Industry-Specific Penalties**: Varies by sector (healthcare, financial, government)

**4. Incident Response Costs**:
**Expected Answer**: Emergency security team engagement ($200-500/hour), forensic investigation costs ($50,000-200,000), legal and compliance review fees, communication and customer notification expenses.

---

## 📚 Additional Learning - Answer Key

### Challenge Questions

**1. Authenticated vs Unauthenticated DAST Scanning**:
**Expected Answer**: 
- **Unauthenticated**: Tests public-facing functionality, limited scope, misses authenticated features
- **Authenticated**: Requires credentials, tests full application functionality, finds privilege escalation issues, more comprehensive coverage

**2. DAST CI/CD Integration Design**:
**Expected Answer**: 
- **Staging environment scanning** after deployment
- **Automated reporting** to development teams
- **Quality gates** preventing deployment with critical findings
- **Integration with issue tracking** systems
- **Baseline establishment** for regression testing

**3. DAST Program Effectiveness Metrics**:
**Expected Answer**:
- **Vulnerability detection rate** (new vs missed)
- **Time to remediation** for critical findings
- **False positive rate** and accuracy improvements
- **Coverage metrics** (pages/endpoints tested)
- **Integration success** (CI/CD pipeline stability)

---

## 🎓 Completion Checklist - Assessment Guide

Students should demonstrate:
- [ ] **Technical Execution**: Successfully ran all scan commands
- [ ] **Analysis Skills**: Accurately interpreted scan results and compared applications
- [ ] **Integration Understanding**: Effectively compared SAST vs DAST methodologies
- [ ] **Professional Communication**: Created clear, actionable remediation recommendations
- [ ] **Practical Application**: Connected findings to real-world cybersecurity scenarios

**Common Student Strengths**:
- Understanding runtime vs static analysis concepts
- Interpreting web vulnerability scanner output
- Recognizing common web application security issues

**Common Student Challenges**:
- Distinguishing between different severity levels
- Understanding business impact of technical findings
- Integrating DAST with other security testing methods

**Extension Activities**:
- Configure authenticated DAST scanning
- Integrate DAST tools into development workflow
- Compare multiple DAST tool outputs for same application

---

**Teaching Notes**: Emphasize that DAST complements rather than replaces SAST, and both are essential components of a comprehensive application security program. Stress the importance of testing in production-like environments and the need for proper authorization before conducting dynamic testing.