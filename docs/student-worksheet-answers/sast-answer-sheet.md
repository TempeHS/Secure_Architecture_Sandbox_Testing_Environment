# SAST Exercise Student Worksheet - Answer Sheet

**Instructor Guide and Answer Key**

---

## 🎯 Learning Objectives - Assessment Criteria

Students should demonstrate understanding of:
- [ ] Static Application Security Testing (SAST) concepts and timing in SDLC
- [ ] Industry-standard tool usage (Bandit, Semgrep, Safety)
- [ ] Security finding interpretation and severity prioritization
- [ ] Vulnerability remediation techniques and best practices
- [ ] OWASP Top 10 vulnerabilities through practical analysis
- [ ] Business impact and ethical implications of security findings

---

## 📋 Exercise 1: SAST Fundamentals - Answer Key

### 1.1 Tool Availability Check

**Expected Output**:
```
Available tools: ['bandit', 'semgrep', 'safety']
```

**Teaching Note**: If tools are missing, guide students through installation or container restart.

### 1.2 Basic Command Understanding

| Command Flag | Purpose |
|--------------|---------|
| `--educational` | **Provides detailed explanations and learning context for findings** |
| `--verbose` | **Shows detailed output including tool execution details and debug information** |
| `--output json` | **Formats output as JSON for structured data processing and automation** |

### 1.3 Reflection Questions

**1. What is the main difference between SAST and DAST?**
**Expected Answer**: 
- SAST analyzes source code without executing the program (white-box testing)
- DAST tests running applications by sending inputs and analyzing responses (black-box testing)
- SAST finds code-level vulnerabilities; DAST finds runtime vulnerabilities
- SAST is faster and can analyze all code paths; DAST requires running application

**2. When in the development process should SAST be performed?**
**Expected Answer**: 
- Early in development cycle (during coding phase)
- As part of continuous integration/continuous deployment (CI/CD) pipeline
- Before code commits or merges
- During code reviews
- Before application deployment

**3. What are two limitations of SAST tools?**
**Expected Answers**:
a) **False positives** - May flag secure code as vulnerable
b) **Context limitations** - Cannot understand runtime behavior or data flow
c) **Configuration issues** - May miss vulnerabilities in configuration files
d) **Language coverage** - Limited to supported programming languages

---

## 📋 Exercise 2: Flask Application Analysis - Answer Key

### 2.1 Initial Analysis Results

**Expected Command**: `python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational`

**Typical Findings Summary** (17-20 findings expected):
- **Total Findings**: 17-20 security issues
- **High Severity**: 7-9 issues (SQL injection, hardcoded secrets, XSS)
- **Medium Severity**: 8-12 issues (security headers, input validation)
- **Low Severity**: 2-4 issues (code quality, minor security practices)

**Key Vulnerabilities Students Should Identify**:
1. **SQL Injection** (High) - Direct SQL query construction
2. **Cross-Site Scripting** (High) - Unescaped user input in templates
3. **Hardcoded Secrets** (High) - Database credentials in source code
4. **Debug Mode** (Medium) - Flask debug mode enabled
5. **Missing Security Headers** (Medium) - No CSRF protection, security headers

### 2.2 Vulnerability Deep Dive

**SQL Injection Analysis**:
- **Location**: Login functionality, search features
- **Evidence**: String concatenation in SQL queries like `"SELECT * FROM users WHERE username='" + username + "'"`
- **Risk**: Database compromise, data theft, authentication bypass

**Cross-Site Scripting (XSS)**:
- **Location**: Comment sections, search results, user profile pages
- **Evidence**: Direct template rendering without escaping: `{{ user_input }}`
- **Risk**: Account hijacking, malicious script execution, data theft

**Hardcoded Secrets**:
- **Location**: Configuration files, database connection strings
- **Evidence**: `DATABASE_URL = "mysql://admin:password123@localhost"`
- **Risk**: Credential exposure, unauthorized access, system compromise

### 2.3 Remediation Planning

**Prioritization Strategy** (High to Low):
1. **SQL Injection** - Immediate fix required (parameterized queries)
2. **Hardcoded Secrets** - Critical for production (environment variables)
3. **XSS** - Important for user safety (template escaping)
4. **Debug Mode** - Security best practice (disable in production)
5. **Security Headers** - Defense in depth (implement CSP, CSRF protection)

---

## 📋 Exercise 3: PWA Analysis - Answer Key

### 3.1 PWA Scan Results

**Expected Command**: `python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational`

**Typical Findings Summary** (12-16 findings expected):
- **Total Findings**: 12-16 security issues
- **High Severity**: 4-6 issues
- **Medium Severity**: 6-8 issues
- **Low Severity**: 2-4 issues

**Key PWA-Specific Vulnerabilities**:
1. **Insecure Service Worker** - Unvalidated cache poisoning
2. **Missing Content Security Policy** - XSS protection gaps
3. **Insecure Manifest Configuration** - Privilege escalation risks
4. **Weak Session Management** - Token handling issues

### 3.2 Comparative Analysis

**Application Comparison Table**:

| Vulnerability Type | Flask App | PWA App | Reasoning |
|-------------------|-----------|---------|-----------|
| **SQL Injection** | **High (3-4 instances)** | **Medium (1-2 instances)** | **Flask has more database interactions** |
| **XSS** | **High (5-6 instances)** | **Medium (2-3 instances)** | **Flask has more user input points** |
| **Configuration Issues** | **Medium** | **High** | **PWA has complex manifest and service worker config** |
| **Hardcoded Secrets** | **High** | **Low** | **Flask has more backend configuration** |

**Higher Risk Application**: **Flask App** (typically 17-20 vs 12-16 findings)

---

## 📋 Exercise 4: Dependency Analysis - Answer Key

### 4.1 Safety Tool Results

**Expected Command**: `python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational --verbose`

**Typical Dependency Vulnerabilities**:
- **Flask version issues** - Outdated version with known CVEs
- **SQLAlchemy vulnerabilities** - SQL injection bypass techniques
- **Jinja2 template issues** - Server-side template injection
- **Werkzeug debug issues** - Information disclosure in debug mode

**Critical Dependencies to Update**:
1. **Flask** → Latest stable version
2. **SQLAlchemy** → Version with SQL injection patches
3. **Jinja2** → Version with template injection fixes
4. **Requests** → Version with SSL verification fixes

### 4.2 Risk Assessment

**Dependency Risk Matrix**:

| Package | Current Version | Vulnerable | Severity | Remediation Effort |
|---------|----------------|------------|----------|-------------------|
| **Flask** | **1.0.2** | **Yes** | **High** | **Medium** |
| **SQLAlchemy** | **1.3.0** | **Yes** | **Critical** | **High** |
| **Jinja2** | **2.10** | **Yes** | **Medium** | **Low** |
| **Werkzeug** | **0.15.0** | **Yes** | **Medium** | **Low** |

---

## 📋 Exercise 5: Professional Reporting - Answer Key

### 5.1 Executive Summary Template

**STATIC SECURITY ASSESSMENT EXECUTIVE SUMMARY**

**Applications Analyzed**: Vulnerable Flask Web Application, Insecure Progressive Web Application

**Analysis Methodology**: Static Application Security Testing (SAST) using industry-standard tools including Bandit, Semgrep, and Safety dependency scanner

**Total Security Issues Identified**: 29-36 vulnerabilities across both applications

**Risk Distribution**:
- **Critical/High Risk**: 11-15 issues requiring immediate attention
- **Medium Risk**: 14-18 issues requiring planned remediation  
- **Low Risk**: 4-6 issues for long-term improvement

**Most Critical Findings**:
1. **SQL Injection vulnerabilities** - Critical risk of database compromise
2. **Hardcoded database credentials** - Critical risk of unauthorized access
3. **Cross-Site Scripting (XSS)** - High risk of user account compromise

**Immediate Actions Required**:
1. Implement parameterized queries for all database operations
2. Move all credentials to environment variables
3. Enable template auto-escaping and input validation
4. Disable debug mode in production environments

**Overall Risk Assessment**: **HIGH** - Multiple critical vulnerabilities present significant security risk

**Compliance Impact**: Findings may violate ISM, Privacy Act,1988 (Privacy Act), and industry security standards

### 5.2 Technical Remediation Guide

**Priority 1 - SQL Injection**:
```python
# VULNERABLE CODE:
query = "SELECT * FROM users WHERE username='" + username + "'"

# SECURE CODE:
query = "SELECT * FROM users WHERE username=?"
cursor.execute(query, (username,))
```

**Priority 2 - Hardcoded Secrets**:
```python
# VULNERABLE CODE:
DATABASE_URL = "mysql://admin:password123@localhost"

# SECURE CODE:
DATABASE_URL = os.environ.get('DATABASE_URL')
```

**Priority 3 - XSS Prevention**:
```html
<!-- VULNERABLE TEMPLATE: -->
<p>{{ user_comment }}</p>

<!-- SECURE TEMPLATE: -->
<p>{{ user_comment | escape }}</p>
```

---

## ⚖️ Legal and Ethical Considerations - Answer Key

### Professional Responsibility in Code Analysis

**1. Employment Impact**:
**Expected Answer**: Vulnerabilities found can affect developer job security if exploited, create liability for development teams, require additional training and skills development, impact performance reviews and career advancement, necessitate code review process improvements.

**2. Privacy Rights**:
**Expected Answer**: SQL injection can expose personal data (PII, financial, health), XSS can compromise user sessions and private information, hardcoded secrets can lead to unauthorized data access, compliance violations (Privacy Act,1988 (Privacy Act)) for data protection.

**3. Intellectual Property**:
**Expected Answer**: Source code vulnerabilities can expose proprietary algorithms, trade secrets in application logic, competitive advantage information, customer lists and business processes, licensing and patent violations.

### Regulatory Compliance

**4. Data Protection Laws**:
**Expected Answer**: SQL injection violates data minimization principles, XSS compromises data integrity requirements, inadequate access controls violate authorization requirements, missing audit trails violate accountability standards.

**5. Industry Standards**:
**Expected Answer**: 
- **ISM**: Security controls and vulnerability management requirements
- **ISO9126**: Software quality standards including security characteristics
- **ISO14598**: Software product evaluation requirements for security assessment

### Ethical Security Testing

**6. Responsible Disclosure**:
**Expected Answer**: Contact vendor/developer privately, provide detailed vulnerability information, allow reasonable time for fixes (90-120 days), coordinate public disclosure, avoid exploitation or proof-of-concept that causes harm.

**7. Professional Standards**:
**Expected Answer**: Maintain confidentiality of findings, avoid unauthorized access beyond testing scope, report findings accurately without exaggeration, provide actionable remediation guidance, maintain professional competence and certification.

---

## 🔐 Cryptography and Security Assessment - Answer Key

**1. Encryption Assessment**:
**Expected Answer**: Found plaintext credential storage instead of hashing, weak password hashing algorithms (MD5, SHA1), missing encryption for sensitive data in database, unencrypted data transmission (HTTP vs HTTPS).

**2. Key Management**:
**Expected Answer**: Hardcoded encryption keys in source code, weak key generation using predictable values, no key rotation mechanisms, inadequate key storage practices, shared keys across environments.

**3. Cryptographic Best Practices**:
**Expected Answer**: Implement bcrypt/scrypt for password hashing, use environment variables for key storage, implement proper random number generation, add HTTPS/TLS for data in transit, use authenticated encryption (AES-GCM).

**4. Security by Design**:
**Expected Answer**: Cryptography should be implemented from the beginning of development, use proven algorithms and libraries, implement defense in depth, regular security assessments, threat modeling includes cryptographic requirements.

---

## 💼 Business Impact Assessment - Answer Key

### Enterprise Impact Analysis

**1. Productivity Impact**:
**Expected Answer**: Security incidents require developer time for emergency fixes, security reviews slow development velocity, incident response disrupts normal operations, training requirements reduce coding time, compliance audits require documentation and remediation.

**2. Financial Impact Estimates**:
- **Direct Costs**: Emergency security fixes ($50,000-100,000), compliance fines ($10,000-millions), legal and forensic costs ($25,000-200,000)
- **Indirect Costs**: Lost productivity ($100,000-500,000), customer churn (5-25% revenue loss), insurance premium increases
- **Regulatory Fines**: Privacy Act,1988 (Privacy Act) penalties may apply, ISM compliance requirements, ISO9126 and ISO14598 standard violations

**3. Reputation Damage**:
**Expected Answer**: Loss of customer trust and confidence, negative media coverage and social media impact, competitive disadvantage in security-conscious markets, difficulty recruiting top talent, long-term brand damage requiring years to recover.

**4. Business Continuity**:
**Expected Answer**: SQL injection poses greatest risk to data availability and integrity, XSS affects user experience and trust, hardcoded secrets create systemic access risks, debug mode exposure threatens entire application stack.

---

## 🎯 Self-Assessment - Instructor Guidance

### Expected Confidence Levels:
- **Understanding SAST concepts**: 4-5/5 (concepts are straightforward)
- **Tool execution**: 3-4/5 (command-line experience varies)
- **Vulnerability identification**: 3-4/5 (requires practice with different vulnerability types)
- **Remediation strategies**: 2-3/5 (requires coding knowledge and experience)
- **Professional reporting**: 3-4/5 (business writing skills vary)

### Common Student Challenges:
1. **Understanding tool output** - Large volume of findings can be overwhelming
2. **Prioritizing vulnerabilities** - Difficulty distinguishing critical vs minor issues
3. **Technical remediation** - Limited coding experience affects solution understanding
4. **Business context** - Connecting technical findings to business impact

### Extension Activities for Advanced Students:
1. **Custom Rule Creation** - Develop Semgrep rules for organization-specific vulnerabilities
2. **CI/CD Integration** - Design SAST integration for automated development pipeline
3. **False Positive Analysis** - Investigate and classify potential false positive findings
4. **Tool Comparison** - Compare SAST tools and evaluate effectiveness for different vulnerability types

---

**Teaching Notes**: 
- Emphasize that SAST is one component of comprehensive security testing
- Stress the importance of combining SAST with DAST and manual testing
- Highlight the role of SAST in shift-left security practices
- Connect findings to real-world security incidents and case studies
- Encourage students to think about the developer experience and how to make security findings actionable