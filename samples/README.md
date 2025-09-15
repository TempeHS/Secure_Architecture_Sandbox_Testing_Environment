# Demo Applications for Cybersecurity Analysis

This folder contains three vulnerable applications designed for educational cybersecurity testing and static analysis demonstrations.

## 🚨 **IMPORTANT SECURITY WARNING**
**These applications contain intentional security vulnerabilities and should NEVER be deployed in production environments. They are designed solely for educational purposes within a controlled sandbox environment.**

---

## 📁 Application Overview

### 1. **Vulnerable Node.js Application** (`vulnerable-nodejs-app/`)
**Technology Stack:** Node.js, Express.js, SQLite, EJS
**Primary Language:** JavaScript
**Port:** 3000

**Key Vulnerabilities Demonstrated:**
- ✅ SQL Injection (Login & Search)
- ✅ Cross-Site Scripting (XSS) - Reflected & Stored
- ✅ Command Injection (Ping functionality)
- ✅ Path Traversal (File access)
- ✅ Insecure Direct Object References (User profiles)
- ✅ Missing Authentication/Authorization
- ✅ Weak Session Management
- ✅ Information Disclosure (Debug endpoint)
- ✅ Unrestricted File Upload
- ✅ Cross-Site Request Forgery (CSRF)

**Quick Start:**
```bash
cd vulnerable-nodejs-app
npm install
npm start
# Access: http://localhost:3000
```

**Default Credentials:** `admin` / `admin123`

### 2. **Vulnerable Flask Application** (`vulnerable-flask-app/`)
**Technology Stack:** Python, Flask, SQLite, Jinja2
**Primary Language:** Python
**Port:** 5000

**Key Vulnerabilities Demonstrated:**
- ✅ SQL Injection (Login & Search)
- ✅ Cross-Site Scripting (XSS)
- ✅ Server-Side Template Injection (SSTI)
- ✅ Command Injection (Ping functionality)
- ✅ Path Traversal (File reading)
- ✅ Insecure Deserialization (Pickle)
- ✅ Weak Cryptographic Practices (MD5 hashes)
- ✅ Missing Authorization Controls
- ✅ Information Disclosure (API & Debug)
- ✅ Insecure Direct Object References

**Quick Start:**
```bash
cd vulnerable-flask-app
pip install -r requirements.txt
python app.py
# Access: http://localhost:5000
```

**Default Credentials:** `admin` / `admin123` or `user` / `user123`

### 3. **The Unsecure PWA** (`unsecure-pwa/`)
**Technology Stack:** Python, Flask, SQLite
**Primary Language:** Python
**Port:** 5001 (configurable)

**Key Vulnerabilities Demonstrated:**
- ✅ Advanced Python-specific vulnerabilities
- ✅ Progressive Web App security issues
- ✅ Database injection attacks
- ✅ Authentication bypass techniques
- ✅ Session management flaws

**Quick Start:**
```bash
cd unsecure-pwa
pip install -r requirements.txt
python main.py
# Access: http://localhost:5001
```

---

## 🎯 **Educational Use Cases**

### **For Static Analysis Training:**
1. **Beginner Level:** Start with the Flask app - clearer Python code structure
2. **Intermediate Level:** Progress to Node.js app - different language patterns
3. **Advanced Level:** Analyze the Unsecure PWA - real-world complexity

### **For Security Testing:**
1. **Manual Testing:** Use web interfaces to discover vulnerabilities
2. **Automated Scanning:** Run security tools against running applications
3. **Code Analysis:** Perform static analysis on source code

### **For Vulnerability Assessment:**
1. **Network Scanning:** Use nmap to discover open ports and services
2. **Web Application Testing:** Use tools like Nikto, Gobuster for web vulnerabilities
3. **Code Review:** Use Bandit, Safety, Semgrep for Python code analysis

---

## 🔧 **Analysis Configuration**

### **Recommended Security Tools for Each Application:**

#### Node.js Application Analysis:
```bash
# Static analysis
npm audit                           # Dependency vulnerabilities
eslint app.js                      # Code quality issues
# Network scanning
nmap -sV -sC localhost -p 3000     # Service detection
# Web application testing
nikto -h localhost:3000            # Web vulnerability scan
gobuster dir -u http://localhost:3000 -w /path/to/wordlist
```

#### Flask Application Analysis:
```bash
# Static analysis
bandit -r .                        # Python security issues
safety check                      # Dependency vulnerabilities
semgrep --config=auto .           # Pattern-based vulnerability detection
# Network scanning
nmap -sV -sC localhost -p 5000     # Service detection
# Web application testing
nikto -h localhost:5000            # Web vulnerability scan
```

#### Unsecure PWA Analysis:
```bash
# Advanced Python analysis
bandit -r . -f json               # Detailed security analysis
safety check --json              # JSON output for parsing
semgrep --config=security .       # Security-focused rules
# Network and web testing
nmap -A localhost -p 5001         # Aggressive scan
nikto -h localhost:5001 -C all    # Comprehensive web testing
```

---

## 📊 **Expected Analysis Results**

### **Static Analysis Findings:**
- **High Severity:** SQL injection, command injection, path traversal
- **Medium Severity:** XSS, CSRF, insecure deserialization
- **Low Severity:** Information disclosure, weak cryptography
- **Informational:** Missing security headers, debug mode enabled

### **Dynamic Analysis Findings:**
- **Authentication Bypass:** Multiple methods per application
- **Injection Attacks:** SQL, Command, Template injection points
- **File System Access:** Path traversal and unrestricted uploads
- **Session Issues:** Weak session management and CSRF vulnerabilities

---

## 🎓 **Learning Objectives**

After analyzing these applications, students should understand:

1. **Common Vulnerability Patterns:** How security flaws manifest in code
2. **Attack Vectors:** How vulnerabilities can be exploited
3. **Detection Methods:** How security tools identify issues
4. **Risk Assessment:** How to categorize and prioritize findings
5. **Remediation Strategies:** How to fix identified vulnerabilities

---

## 🔒 **Safety Guidelines**

1. **Isolated Environment:** Only run these applications in the provided sandbox
2. **No Production Use:** Never deploy these applications in real environments
3. **Educational Purpose:** Use only for learning and authorized testing
4. **Responsible Disclosure:** Apply learned concepts ethically in real scenarios

---

## 📝 **Quick Reference Commands**

### Start All Applications:
```bash
# Terminal 1: Node.js App
cd vulnerable-nodejs-app && npm start

# Terminal 2: Flask App
cd vulnerable-flask-app && python app.py

# Terminal 3: Unsecure PWA
cd unsecure-pwa && python main.py
```

### Run Security Analysis:
```bash
# Python applications
bandit -r vulnerable-flask-app/ vulnerable-pwa/
safety check --file vulnerable-flask-app/requirements.txt
semgrep --config=auto vulnerable-flask-app/ unsecure-pwa/

# Network scanning
nmap -sV localhost -p 3000,5000,5001

# Web vulnerability testing
nikto -h localhost:3000
nikto -h localhost:5000
nikto -h localhost:5001
```

---

**Remember:** These applications are powerful learning tools when used responsibly within the cybersecurity sandbox environment! 🛡️