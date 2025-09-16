# Static Application Security Testing (SAST) Exercise

## 🎯 Learning Objectives

By the end of this exercise, students will be able to:

- ✅ Understand what Static Application Security Testing (SAST) is and why it's
  important
- ✅ Use automated tools to identify security vulnerabilities in code
- ✅ Interpret SAST tool outputs and prioritize findings
- ✅ Apply remediation techniques to fix common security issues
- ✅ Understand the OWASP Top 10 vulnerabilities through hands-on analysis

## 📍 Getting Started - Important Navigation

**🏠 Always start from the main project folder:**

```bash
# If you get lost, return to the main folder with this command:
cd /workspaces/Docker_Sandbox_Demo

# Check you're in the right place (should see folders like 'src', 'samples', 'docker'):
ls
```

**Expected Output:**

```
copilot-instructions.md  docker/  docs/  reports/  samples/  src/  ...
```

## 📚 What is Static Application Security Testing (SAST)?

### Definition

Static Application Security Testing (SAST) is a security testing methodology
that analyzes source code **without executing the program**. Think of it like a
**spell-check for security** - it reads your code and finds potential security
problems before they become real threats.

### 🔍 Real-World Analogy

Imagine you're a teacher checking student essays for grammar mistakes. You can
spot problems just by reading the essays without having the students read them
aloud. SAST works the same way - it "reads" computer code to find security
mistakes.

### Key Characteristics:

- **White-box testing**: Full access to source code (like having the essay to
  read)
- **Early detection**: Finds vulnerabilities during development (like catching
  typos before printing)
- **Comprehensive coverage**: Can analyze entire codebase (like checking every
  sentence)
- **No runtime required**: Doesn't need the application to be running (like not
  needing to hear the essay read aloud)

### SAST vs Other Testing Types:

| Testing Type | When        | Access                   | Execution | Real-World Example            |
| ------------ | ----------- | ------------------------ | --------- | ----------------------------- |
| **SAST**     | Development | Source Code              | No        | Proofreading an essay         |
| **DAST**     | Runtime     | External Interface       | Yes       | Listening to a speech         |
| **IAST**     | Runtime     | Internal Instrumentation | Yes       | Following along while reading |

### Why SAST Matters:

- **Early Detection**: Find bugs before they reach production (like catching
  typos before publishing)
- **Cost Effective**: Cheaper to fix during development (like editing before
  printing)
- **Comprehensive**: Analyzes all code paths (like checking every paragraph)
- **Educational**: Helps developers learn secure coding practices (like learning
  grammar rules)

## 🛠️ Tools We'll Use (Don't Worry - They're Pre-Installed!)

### 1. Bandit (Python Security Detective)

- **What it does**: Finds common security problems in Python code
- **Think of it as**: A security expert reading through code looking for
  dangerous patterns
- **Finds**: SQL injection, weak passwords, debug mode issues

### 2. Semgrep (Pattern Detective)

- **What it does**: Uses smart patterns to find security anti-patterns
- **Think of it as**: A detective with a checklist of "red flags" to watch for
- **Finds**: OWASP Top 10 vulnerabilities, custom security issues

### 3. Safety (Dependency Checker)

- **What it does**: Checks if any code libraries have known security problems
- **Think of it as**: Checking if any ingredients in a recipe are expired or
  contaminated
- **Finds**: Known vulnerabilities in Python packages

## 🧪 Lab Environment Setup

### ✅ Prerequisites Check

**Step 1: Navigate to the main folder**

```bash
cd /workspaces/Docker_Sandbox_Demo
```

**Step 2: Verify you're in the right place**

```bash
pwd
```

**Expected Output:**

```
/workspaces/Docker_Sandbox_Demo
```

**Step 3: Check sample applications exist**

```bash
ls samples/
```

**Expected Output:**

```
README.md  backdoor-apps/  network-scenarios/  resource-abuse/  suspicious-scripts/  unsecure-pwa/  vulnerable-flask-app/
```

**Step 4: Test the analysis tool**

```bash
python src/analyzer/analyze_cli.py --help
```

**Expected Output (first few lines):**

```
usage: analyze_cli.py [-h] [--educational] [--verbose] [--output {text,json}] file_or_directory
Static Application Security Testing (SAST) tool for educational purposes
```

**❌ If Something Goes Wrong:**

- **Can't find folders?** Run: `cd /workspaces/Docker_Sandbox_Demo`
- **Python error?** Make sure you're in the main project folder
- **Tool not found?** Check that you're in `/workspaces/Docker_Sandbox_Demo`

## 🎯 Sample Applications (Your Security Testing Targets)

### 1. **Vulnerable Flask Application** (`samples/vulnerable-flask-app/`)

- **Technology**: Python Flask web application
- **Purpose**: Demonstrates common web security vulnerabilities
- **What you'll find**: SQL injection, XSS, weak authentication, debug mode
  issues
- **Educational Focus**: Learning about Python web application security

### 2. **Unsecure PWA** (`samples/unsecure-pwa/`)

- **Technology**: Python Progressive Web App (mobile-friendly website)
- **Purpose**: Shows mobile/web app specific security issues
- **What you'll find**: SQL injection, redirect vulnerabilities, configuration
  problems
- **Educational Focus**: Mobile and progressive web app security

## 📋 Exercise 1: Understanding SAST Fundamentals

### 🎯 Goal: Learn how to use security analysis tools

### Step 1: Explore the Analysis Tool

**Make sure you're in the right place:**

```bash
# Return to main folder if needed
cd /workspaces/Docker_Sandbox_Demo

# Verify you're in the correct location
pwd
```

**Expected Output:**

```
/workspaces/Docker_Sandbox_Demo
```

**Get help on the analysis tool:**

```bash
python src/analyzer/analyze_cli.py --help
```

**Expected Output (first few lines):**

```
usage: analyze_cli.py [-h] [--educational] [--verbose] [--output {text,json}] file_or_directory

Static Application Security Testing (SAST) tool for educational purposes

positional arguments:
  file_or_directory     File or directory to analyze for security vulnerabilities
```

**Check what security tools are available:**

```bash
python -c "from src.analyzer.static_analyzer import SecurityToolRunner; print(SecurityToolRunner().check_available_tools())"
```

**Expected Output:**

```
Available security tools:
✅ bandit: Python security linter
✅ safety: Dependency vulnerability scanner
✅ semgrep: Pattern-based security analysis
```

### Step 2: Basic Analysis Commands

**📍 Navigation Check:** Make sure you're still in
`/workspaces/Docker_Sandbox_Demo`

```bash
pwd
```

**Run basic analysis on Flask app:**

```bash
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app
```

**Expected Output (sample):**

```
🔍 STATIC APPLICATION SECURITY TESTING (SAST) REPORT
📂 Target: samples/vulnerable-flask-app
📅 Scan Date: [current date]

FINDINGS SUMMARY:
🚨 High: 8 findings
⚠️ Medium: 12 findings
🔵 Low: 5 findings
Total: 25 findings
```

**Run analysis with educational explanations:**

```bash
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational
```

**Expected Additional Output:**

```
🎓 Educational explanations included for each finding
🔧 Remediation guidance provided
```

**Run verbose analysis for debugging:**

```bash
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --verbose
```

**Expected Additional Output:**

```
🔍 Detailed analysis progress shown
📝 Extra debugging information included
```

**Generate JSON output for automation:**

```bash
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --output json
```

**Expected Output Format:**

```json
{
  "scan_summary": {
    "target": "samples/vulnerable-flask-app",
    "findings_count": 25,
    "high_severity": 8
  }
}
```

### 🤔 Self-Check Questions:

Answer these to test your understanding:

1. **What's the difference between the basic and educational output modes?**

   - Basic mode: Shows findings only
   - Educational mode: Shows findings + explanations + how to fix them

2. **Why might you want JSON output instead of human-readable reports?**

   - JSON can be processed by other tools automatically
   - Good for integration with development pipelines
   - Can be imported into databases or reporting systems

3. **How does static analysis differ from manual code review?**
   - Static analysis: Automated, fast, consistent, finds known patterns
   - Manual review: Human judgment, context-aware, finds logic flaws, slower

### ❌ Troubleshooting:

**Problem**: Command not found or Python errors **Solution**:

```bash
cd /workspaces/Docker_Sandbox_Demo
python --version  # Should show Python 3.8+
ls src/analyzer/   # Should show analyze_cli.py
```

**Problem**: No findings or empty output **Solution**: Make sure target
directory exists:

```bash
ls samples/vulnerable-flask-app/  # Should show Python files
```

## 📋 Exercise 2: Analyzing the Vulnerable Flask Application

### 🎯 Goal: Find and understand real security vulnerabilities

### Step 1: Initial Analysis

**Navigation check:**

```bash
cd /workspaces/Docker_Sandbox_Demo
pwd  # Should show /workspaces/Docker_Sandbox_Demo
```

**Run comprehensive analysis:**

```bash
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational --verbose
```

**Expected Output (sample):**

```
🔍 STATIC APPLICATION SECURITY TESTING (SAST) REPORT
📂 Target: samples/vulnerable-flask-app
📅 Scan Date: 2025-XX-XX

🔧 Tools Used:
✅ bandit: Python security linter
✅ safety: Dependency vulnerability scanner
✅ semgrep: Pattern-based security analysis

FINDINGS SUMMARY:
🚨 High: 8 findings
⚠️ Medium: 12 findings
🔵 Low: 5 findings
Total: 25 findings

🚨 HIGH SEVERITY FINDINGS:
```

### Step 2: Understanding the Output

**Look for output like this:**

#### Sample Finding Analysis:

```
🚨 HIGH SEVERITY
[BANDIT] flask_debug_true
📁 File: samples/vulnerable-flask-app/app.py
📍 Line: 522
🎓 Educational Note: Flask debug mode should not be enabled in production as it can expose sensitive information and allow code execution.
🔧 Remediation: Set debug=False in production. Use environment variables to control debug mode: app.run(debug=os.getenv('FLASK_ENV') == 'development')
```

**What this means:**

- **🚨 HIGH SEVERITY**: This is a serious security problem
- **[BANDIT]**: The tool that found this issue
- **flask_debug_true**: The type of vulnerability
- **📁 File & 📍 Line**: Exactly where the problem is
- **🎓 Educational Note**: Why this is dangerous
- **🔧 Remediation**: How to fix it

### Step 3: Categorize Your Findings

**Create a findings summary (fill this out as you work):**

| Vulnerability Type  | Count  | Severity | OWASP Category              | Why Dangerous?                     |
| ------------------- | ------ | -------- | --------------------------- | ---------------------------------- |
| SQL Injection       | \_\_\_ | High     | A03:2021 - Injection        | Attackers can read/modify database |
| XSS                 | \_\_\_ | High     | A03:2021 - Injection        | Attackers can steal user data      |
| Debug Mode          | \_\_\_ | Medium   | A09:2021 - Security Logging | Exposes sensitive information      |
| Weak Authentication | \_\_\_ | High     | A07:2021 - ID/Auth Failures | Easy to break into accounts        |

### 🔍 Investigation Tasks:

#### Task 2.1: SQL Injection Analysis

**Find SQL injection vulnerabilities:**

```bash
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep -A 5 -B 5 "SQL\|sql"
```

**Expected to see something like:**

```
🚨 HIGH SEVERITY
[BANDIT] hardcoded_sql_expressions
📁 File: samples/vulnerable-flask-app/app.py
📍 Line: 89
🎓 Educational Note: SQL injection vulnerability - user input is directly concatenated into SQL queries
```

**Your investigation steps:**

1. **Find SQL injection vulnerabilities** - Note the line numbers where they
   occur
2. **Look at the actual code** - Run:
   `cat samples/vulnerable-flask-app/app.py | sed -n '89p'` (replace 89 with
   actual line number)
3. **Understand the risk** - Attackers could steal all database data or delete
   records
4. **Propose fixes** - Use parameterized queries instead of string concatenation

**Fill out your findings:**

- Line numbers with SQL injection: ******\_\_\_******
- How many SQL injection issues found: ****\_\_\_****
- Most dangerous SQL injection (line **\_): **\_****

#### Task 2.2: Authentication Issues

**Find authentication weaknesses:**

```bash
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep -A 3 -B 3 "auth\|password\|login"
```

**Investigation steps:**

1. **Identify authentication weaknesses** in the findings
2. **Examine password handling** - Look for weak hashing or plaintext passwords
3. **Check session management** - Look for insecure session handling
4. **Evaluate the security impact** - Could attackers easily break into user
   accounts?

**Expected findings might include:**

- Weak password hashing (using MD5 instead of bcrypt)
- Missing rate limiting on login attempts
- Insecure session management

**Fill out your findings:**

- Password vulnerabilities found: ******\_\_\_\_******
- Session management issues: ********\_\_\_********
- Authentication bypass possibilities: ****\_\_\_\_****

#### Task 2.3: Configuration Problems

**Find configuration-related vulnerabilities:**

```bash
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep -A 3 -B 3 "debug\|config\|secret"
```

**Investigation steps:**

1. **Find configuration-related vulnerabilities**
2. **Understand why debug mode is dangerous** - It can expose source code and
   allow remote code execution
3. **Identify other insecure configurations** - Look for hardcoded secrets, weak
   security settings

**Common configuration problems:**

- Debug mode enabled (app.run(debug=True))
- Hardcoded secret keys
- Insecure cookie settings
- Missing security headers

**Fill out your findings:**

- Debug mode issues: ************\_\_\_************
- Hardcoded secrets found: ********\_\_\_\_********
- Other config problems: **********\_\_**********

### 📝 Student Worksheet - Complete This:

**Flask App Vulnerability Assessment**

1. **Total Findings**: **\_**

   - High Severity: \_\_\_\_
   - Medium Severity: \_\_\_\_
   - Low Severity: \_\_\_\_

2. **Most Critical Vulnerability**: ******\_\_\_\_******

   - **File and line number**: **************\_\_\_\_**************
   - **Why is this critical?**: **************\_\_\_\_**************
   - **How to fix it?**: ****************\_\_\_\_****************

3. **Authentication Issues Found** (check all that apply):

   - [ ] Weak password hashing (using MD5/SHA1 instead of bcrypt)
   - [ ] Missing rate limiting on login attempts
   - [ ] Insecure session management
   - [ ] Hardcoded passwords or secrets
   - [ ] Other: ******\_\_\_******

4. **Top 3 Remediation Priorities** (most dangerous first):

   1. ***
   2. ***
   3. ***

5. **OWASP Top 10 Mapping** - Which OWASP categories did you find?
   - [ ] A01: Broken Access Control
   - [ ] A02: Cryptographic Failures
   - [ ] A03: Injection
   - [ ] A04: Insecure Design
   - [ ] A05: Security Misconfiguration
   - [ ] A06: Vulnerable Components
   - [ ] A07: Identification/Authentication Failures
   - [ ] A08: Software/Data Integrity Failures
   - [ ] A09: Security Logging/Monitoring Failures
   - [ ] A10: Server-Side Request Forgery

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

   - ***
   - ***

2. **Common Web App Vulnerabilities**:

   - ***
   - ***

3. **Risk Assessment Comparison**: | Application | High Risk | Medium Risk | Low
   | Risk | Overall Risk |
   | ---- | ------------ |  |  |  || Flask
   App | | | | | | PWA App | | | | |

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
| ------------- | -------- | -------------- | ------ | -------- |
| SQL Injection | High     | Easy           | High   | 1        |
| Debug Mode    | Medium   | Medium         | Medium | 2        |
| ...           | ...      | ...            | ...    | ...      |

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

**Task**: Using the SAST tools and techniques learned, create a security
assessment report that includes:

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

**Next Steps**: After mastering SAST, students can progress to Dynamic
Application Security Testing (DAST) and Interactive Application Security Testing
(IAST) to complete their application security testing knowledge.
