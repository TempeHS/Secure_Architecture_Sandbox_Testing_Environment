# Static Application Security Testing (SAST) Exercise

## 🎯 Learning Objectives

By the end of this exercise, students will be able to:
- Understand what Static Application Security Testing (SAST) is and why it's important
- Use automated tools to identify security vulnerabilities in code
- Interpret SAST tool outputs and prioritize findings
- Apply remediation techniques to fix common security issues
- Understand the OWASP Top 10 vulnerabilities through hands-on analysis

## 📚 What is Static Application Security Testing (SAST)?

### Definition
Static Application Security Testing (SAST) is a security testing methodology that analyzes source code, bytecode, or binary code **without executing the program**. Think of it like a security-focused code review that happens automatically.

### Key Characteristics:
- **White-box testing**: Full access to source code
- **Early detection**: Finds vulnerabilities during development
- **Comprehensive coverage**: Can analyze entire codebase
- **No runtime required**: Doesn't need the application to be running

### SAST vs Other Testing Types:

| Testing Type | When | Access | Execution |
|--------------|------|--------|-----------|
| **SAST** | Development | Source Code | No |
| **DAST** | Runtime | External Interface | Yes |
| **IAST** | Runtime | Internal Instrumentation | Yes |

### Why SAST Matters:
- **Early Detection**: Find bugs before they reach production
- **Cost Effective**: Cheaper to fix during development
- **Comprehensive**: Analyzes all code paths, not just those executed
- **Educational**: Helps developers learn secure coding practices

## 🛠️ Tools We'll Use

### 1. Bandit (Python Security Linter)
- **Purpose**: Identifies common security issues in Python code
- **Strengths**: Fast, well-documented, integrates with CI/CD
- **Coverage**: SQL injection, XSS, weak crypto, hardcoded secrets

### 2. Semgrep (Pattern-Based Analysis)
- **Purpose**: Uses patterns to find security anti-patterns
- **Strengths**: Multi-language, customizable rules, low false positives
- **Coverage**: OWASP Top 10, custom security patterns

### 3. Safety (Dependency Scanner)
- **Purpose**: Checks for known vulnerabilities in dependencies
- **Strengths**: Real-time database updates, integrates with pip
- **Coverage**: Known CVEs in Python packages



## 🧪 Lab Environment Setup

### Prerequisites
1. Docker Sandbox Demo environment running
2. Python 3.8+ with security tools installed
3. Access to the 2 sample applications

## 🎯 Sample Applications

### 1. **Vulnerable Flask Application** (`samples/vulnerable-flask-app/`)
- **Technology**: Python Flask web application
- **Vulnerabilities**: SQL injection, XSS, weak authentication, debug mode
- **Educational Focus**: Python security, web application vulnerabilities

### 2. **Unsecure PWA** (`samples/unsecure-pwa/`)
- **Technology**: Python Progressive Web App
- **Vulnerabilities**: SQL injection, open redirects, insecure configurations
- **Educational Focus**: Mobile/PWA security, configuration issues

## 📋 Exercise 1: Understanding SAST Fundamentals

### Step 1: Explore the Analysis Tool
```bash
# Navigate to the project directory
cd /workspaces/Docker_Sandbox_Demo

# Get help on the analysis tool
python src/analyzer/analyze_cli.py --help

# Check available tools
python -c "from src.analyzer.static_analyzer import SecurityToolRunner; print(SecurityToolRunner().check_available_tools())"
```

### Step 2: Basic Analysis Commands
```bash
# Run basic analysis on Flask app
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app

# Run analysis with educational explanations
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational

# Run verbose analysis for debugging
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --verbose

# Generate JSON output for automation
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --output json
```

### 🤔 Discussion Questions:
1. What's the difference between the basic and educational output modes?
2. Why might you want JSON output instead of human-readable reports?
3. How does static analysis differ from manual code review?

## 📋 Exercise 2: Analyzing the Vulnerable Flask Application

### Step 1: Initial Analysis
```bash
# Run comprehensive analysis
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational --verbose
```

### Step 2: Understanding the Output

#### Sample Finding Analysis:
```
🚨 HIGH SEVERITY
[BANDIT] flask_debug_true
📁 File: samples/vulnerable-flask-app/app.py
📍 Line: 522
🎓 Educational Note: Flask debug mode should not be enabled in production...
🔧 Remediation: Set debug=False in production. Use environment variables...
```

### Step 3: Categorize Findings
Create a table of findings by vulnerability type:

| Vulnerability Type | Count | Severity | OWASP Category |
|-------------------|--------|----------|----------------|
| SQL Injection | ? | High | A03:2021 - Injection |
| XSS | ? | High | A03:2021 - Injection |
| Debug Mode | ? | Medium | A09:2021 - Security Logging |

### 🔍 Investigation Tasks:

#### Task 2.1: SQL Injection Analysis
1. **Find SQL injection vulnerabilities** in the Flask app
2. **Examine the vulnerable code** at the reported line numbers
3. **Understand the risk**: How could an attacker exploit this?
4. **Propose fixes**: What specific changes would prevent this vulnerability?

```bash
# Look for SQL-related findings
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep -A 5 -B 5 "SQL\|sql"
```

#### Task 2.2: Authentication Issues
1. **Identify authentication weaknesses** in the findings
2. **Examine password handling** in the code
3. **Check session management** implementation
4. **Evaluate the security impact** of these issues

#### Task 2.3: Configuration Problems
1. **Find configuration-related vulnerabilities**
2. **Understand why debug mode is dangerous** in production
3. **Identify other insecure configurations**

### 📝 Student Worksheet:

**Flask App Vulnerability Assessment**

1. **Total Findings**: _____ (High: ___, Medium: ___, Low: ___)

2. **Most Critical Vulnerability**: ________________
   - **Why is this critical?**: ________________________________
   - **How to fix it?**: ____________________________________

3. **Authentication Issues Found**:
   - [ ] Weak password hashing
   - [ ] Missing rate limiting  
   - [ ] Insecure session management
   - [ ] Other: _______________

4. **Top 3 Remediation Priorities**:
   1. _________________________________________________
   2. _________________________________________________  
   3. _________________________________________________

## 📋 Exercise 3: Analyzing the Unsecure PWA

### Step 1: Progressive Web App Analysis
```bash
# Analyze the PWA application
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational --verbose
```

### Step 2: Multi-File Analysis
```bash
# Check how many files are being analyzed
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational | grep "Files Analyzed"

# Look at the file structure
find samples/unsecure-pwa -name "*.py" -o -name "*.js" -o -name "*.html"
```

### 🔍 Investigation Tasks:

#### Task 4.1: PWA-Specific Security Issues
1. **Identify PWA-specific vulnerabilities** (service workers, manifest, etc.)
2. **Analyze mobile security considerations**
3. **Check for data storage security**
4. **Evaluate offline functionality security**

#### Task 3.2: Cross-Application Comparison
1. **Compare vulnerability types** across both applications
2. **Identify common patterns** in security issues
3. **Determine which app has the highest risk**
4. **Analyze the security posture differences**

### 📊 PWA Security Assessment:

**Progressive Web App Vulnerability Analysis**

1. **Unique PWA Vulnerabilities**:
   - _________________________________________________
   - _________________________________________________

2. **Common Web App Vulnerabilities**:
   - _________________________________________________
   - _________________________________________________

3. **Risk Assessment Comparison**:
   | Application | High Risk | Medium Risk | Low Risk | Overall Risk |
   |-------------|-----------|-------------|----------|--------------|
   | Flask App   |           |             |          |              |
   | PWA App     |           |             |          |              |

## 📋 Exercise 4: Advanced SAST Techniques

### Step 1: Custom Analysis Patterns
```bash
# Create custom analysis for specific patterns
python -c "
from src.analyzer.vulnerability_database import vulnerability_db
print('Available vulnerability types:')
for vuln_type in ['sql_injection', 'xss', 'csrf', 'broken_authentication']:
    info = vulnerability_db.get_vulnerability_info(vuln_type)
    print(f'- {info.name}: {info.severity}')
"
```

### Step 2: Comparative Analysis
```bash
# Run analysis on both applications and compare
echo '=== FLASK APP ===' > security_comparison.txt
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep "FINDINGS SUMMARY" -A 10 >> security_comparison.txt

echo '=== PWA APP ===' >> security_comparison.txt
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational | grep "FINDINGS SUMMARY" -A 10 >> security_comparison.txt

cat security_comparison.txt
```

### Step 3: JSON Analysis and Automation
```bash
# Generate JSON reports for automation
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --output json > flask_report.json
python src/analyzer/analyze_cli.py samples/unsecure-pwa --output json > pwa_report.json

# Analyze JSON structure
echo "Flask findings count:" && cat flask_report.json | grep -o '"severity"' | wc -l
echo "PWA findings count:" && cat pwa_report.json | grep -o '"severity"' | wc -l
```

## 🎯 Exercise 5: Remediation Planning

### Step 1: Priority Matrix Creation

Create a remediation priority matrix based on your findings:

| Vulnerability | Severity | Exploitability | Impact | Priority |
|---------------|----------|----------------|--------|----------|
| SQL Injection | High | Easy | High | 1 |
| Debug Mode | Medium | Medium | Medium | 2 |
| ... | ... | ... | ... | ... |

### Step 2: Remediation Implementation

#### Task 6.1: Fix a SQL Injection Issue
1. **Locate a SQL injection vulnerability** in the Flask app
2. **Understand the current code** and why it's vulnerable
3. **Implement a fix** using parameterized queries
4. **Re-run the analysis** to verify the fix

#### Task 6.2: Secure Configuration
1. **Identify configuration issues** across all apps
2. **Create secure configuration templates**
3. **Document the security improvements**

### Step 3: Verification Testing
```bash
# After making fixes, re-run analysis to verify improvements
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational

# Compare before and after results
echo "Original findings: [record your count]"
echo "After fixes: [record new count]"
echo "Improvement: [calculate reduction]"
```

## 🎓 Assessment and Reflection

### Knowledge Check Questions:

1. **What are the main advantages of SAST over DAST?**
   - [ ] Finds runtime-only vulnerabilities
   - [ ] Can analyze without running the application
   - [ ] Provides 100% code coverage analysis
   - [ ] Faster than manual code review

2. **Which vulnerability type is typically the highest priority to fix?**
   - [ ] Information disclosure
   - [ ] SQL injection
   - [ ] Missing security headers
   - [ ] Deprecated dependencies

3. **What makes a good SAST tool?**
   - [ ] High accuracy, low false positives
   - [ ] Support for multiple languages
   - [ ] Integration with development workflows
   - [ ] All of the above

### Practical Assessment:

#### Scenario: You're a security consultant hired to assess a new web application.

**Task**: Using the SAST tools and techniques learned, create a security assessment report that includes:

1. **Executive Summary** (for management)
   - Overall risk level
   - Key findings summary
   - Recommended actions

2. **Technical Findings** (for developers)
   - Detailed vulnerability descriptions
   - Code locations and line numbers
   - Specific remediation steps

3. **Remediation Roadmap** (for project planning)
   - Priority-ordered action items
   - Estimated effort for each fix
   - Timeline recommendations

### 🏆 Advanced Challenge:

**Create Your Own SAST Rule**

1. **Identify a security pattern** not caught by existing tools
2. **Write a detection rule** (conceptually, or using Semgrep syntax)
3. **Test it against the sample applications**
4. **Document your rule** with examples and remediation advice

Example Semgrep rule structure:
```yaml
rules:
  - id: your-custom-rule
    pattern: dangerous_function($VAR)
    message: Security issue detected
    severity: HIGH
    languages: [python]
```

## 📚 Additional Resources

### Documentation:
- [OWASP SAST Guide](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Semgrep Rule Writing](https://semgrep.dev/docs/writing-rules/overview/)

---

**Next Steps**: After mastering SAST, students can progress to Dynamic Application Security Testing (DAST) and Interactive Application Security Testing (IAST) to complete their application security testing knowledge.