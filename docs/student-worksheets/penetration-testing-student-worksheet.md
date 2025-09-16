# Penetration Testing - Student Worksheet

**Name:** ________________________________ **Date:** ________________

**Lab Partner:** _________________________ **Section:** ______________

## ⚠️ Ethical Agreement
**I understand that all penetration testing techniques learned in this exercise are for educational purposes only. I agree to only use these techniques in authorized environments and will never attempt unauthorized access to systems I do not own or lack explicit permission to test.**

**Student Signature**: _________________ **Date**: _________

## 🔧 Pre-Exercise Setup Verification

**Before starting penetration testing, verify your environment is ready:**

### Step 1: Check Target Environment
```bash
# Verify Docker containers are running:
cd docker && docker-compose ps
```

**Container Status Check:**
- [ ] `cybersec_sandbox` - State: Up
- [ ] `vulnerable_web_app` - State: Up

### Step 2: Verify Target Applications
```bash
# Test Flask Application:
curl -s http://localhost:5000 | head -3

# Test PWA Application:
curl -s http://localhost:9090 | head -3
```

**Target Accessibility Check:**
- [ ] Flask App responds at http://localhost:5000 ✅
- [ ] PWA App responds at http://localhost:9090 ✅

### Step 3: Verify All Analysis Tools
```bash
# Test SAST tool:
python src/analyzer/analyze_cli.py --help

# Test DAST tool:
python src/analyzer/dast_cli.py --help

# Test Network Analysis tool:
python src/analyzer/network_cli.py --help

# Test basic network tools:
nmap --version
```

**Tool Verification Checklist:**
- [ ] SAST CLI available ✅
- [ ] DAST CLI available ✅  
- [ ] Network Analysis CLI available ✅
- [ ] Network scanning tools available ✅

### Step 4: Verify Sample Applications
```bash
# Test access to suspicious applications:
ls samples/backdoor-apps/
ls samples/suspicious-scripts/
ls samples/resource-abuse/
```

**Sample Apps Check:**
- [ ] Backdoor applications accessible ✅
- [ ] Suspicious scripts accessible ✅
- [ ] Resource abuse samples accessible ✅

### Troubleshooting:
**If any verification fails:**
1. Restart environment: `cd docker && docker-compose down && docker-compose up -d`
2. Wait 60 seconds for full startup
3. Re-run verification steps
4. **Contact instructor if issues persist - do not proceed without working environment**

**⚠️ IMPORTANT: Complete ALL verification steps before beginning penetration testing activities.**

---

## 🎯 Learning Objectives Checklist
By the end of this exercise, I will be able to:
- [ ] Explain penetration testing methodology and ethical considerations
- [ ] Conduct systematic reconnaissance using multiple techniques
- [ ] Integrate SAST, DAST, Network Analysis, and Sandbox findings
- [ ] Perform controlled exploitation in a safe environment
- [ ] Document findings and create professional security reports
- [ ] Understand legal and ethical responsibilities of security professionals

## 📋 Phase 1: Reconnaissance (45 minutes)

### 1.1 Network Discovery
**Objective**: Identify active services and potential entry points

#### Commands to Execute:
```bash
# Start network monitoring
python src/analyzer/network_cli.py --monitor-connections --educational --duration 300 &

# Discover active services
python src/analyzer/network_cli.py --scan-services localhost --educational
```

#### Documentation Section:
**Services Discovered**:
| Port | Service | Version | Risk Level |
|------|---------|---------|------------|
|      |         |         |            |
|      |         |         |            |
|      |         |         |            |

**Potential Entry Points Identified**:
1. _________________________________
2. _________________________________
3. _________________________________

### 1.2 Web Application Enumeration
**Objective**: Map web application structure and functionality

#### Commands to Execute:
```bash
# Enumerate web directories and files
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational
python src/analyzer/dast_cli.py http://localhost:8080 --deep-scan --educational
```

#### Documentation Section:
**Web Application Structure**:
- **Application 1** (Port 5000):
  - Key endpoints: _________________________________
  - Technologies identified: _________________________________
  - Interesting files/directories: _________________________________

- **Application 2** (Port 8080):
  - Key endpoints: _________________________________
  - Technologies identified: _________________________________
  - Interesting files/directories: _________________________________

### 1.3 Technology Stack Analysis
**Objective**: Understand the underlying technologies and potential vulnerabilities

#### Commands to Execute:
```bash
# Analyze application code for technology insights
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational --verbose
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational --verbose
```

#### Documentation Section:
**Technology Stack Summary**:
- **Programming Languages**: _________________________________
- **Frameworks**: _________________________________
- **Dependencies**: _________________________________
- **Potential Technology-Specific Vulnerabilities**: _________________________________

### Knowledge Check 1:
**Q1**: What is the difference between active and passive reconnaissance?
**A1**: _________________________________________________

**Q2**: Why is it important to understand the technology stack before attempting exploitation?
**A2**: _________________________________________________

**Q3**: What ethical considerations apply during the reconnaissance phase?
**A3**: _________________________________________________

## 🔍 Phase 2: Vulnerability Assessment (60 minutes)

### 2.1 Static Analysis Integration
**Objective**: Identify code-level vulnerabilities that could be exploited

#### Commands to Execute:
```bash
# Comprehensive SAST analysis
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational --output reports/pentest_sast_flask.json
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational --output reports/pentest_sast_pwa.json
```

#### Vulnerability Classification Table:
| Vulnerability Type | Severity | Exploitable? | Location | Notes |
|-------------------|----------|--------------|----------|-------|
|                   |          |              |          |       |
|                   |          |              |          |       |
|                   |          |              |          |       |
|                   |          |              |          |       |

### 2.2 Dynamic Testing Results
**Objective**: Identify runtime vulnerabilities and misconfigurations

#### Commands to Execute:
```bash
# Comprehensive DAST scans
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational --output reports/pentest_dast_flask.json
python src/analyzer/dast_cli.py http://localhost:8080 --deep-scan --educational --output reports/pentest_dast_pwa.json
```

#### Runtime Vulnerability Assessment:
**High Priority Targets for Exploitation**:
1. **Vulnerability**: _________________________________
   - **Location**: _________________________________
   - **Exploitation Potential**: _________________________________
   - **Expected Impact**: _________________________________

2. **Vulnerability**: _________________________________
   - **Location**: _________________________________
   - **Exploitation Potential**: _________________________________
   - **Expected Impact**: _________________________________

3. **Vulnerability**: _________________________________
   - **Location**: _________________________________
   - **Exploitation Potential**: _________________________________
   - **Expected Impact**: _________________________________

### 2.3 Network Traffic Patterns
**Objective**: Understand normal vs. suspicious network behavior

#### Commands to Execute:
```bash
# Monitor network behavior during testing
python src/analyzer/network_cli.py --capture-traffic --duration 300 --educational --output reports/pentest_network.json
```

#### Network Analysis Results:
**Normal Traffic Patterns Observed**:
- _________________________________
- _________________________________
- _________________________________

**Suspicious Patterns to Watch For**:
- _________________________________
- _________________________________
- _________________________________

### Knowledge Check 2:
**Q1**: How do SAST and DAST findings complement each other in penetration testing?
**A1**: _________________________________________________

**Q2**: What factors determine the exploitability of a vulnerability?
**A2**: _________________________________________________

**Q3**: How should vulnerabilities be prioritized for exploitation attempts?
**A3**: _________________________________________________

## ⚔️ Phase 3: Controlled Exploitation (90 minutes)

### 3.1 SQL Injection Exploitation
**Objective**: Safely demonstrate SQL injection impact

#### Pre-Exploitation Checklist:
- [ ] Target confirmed to be in sandbox environment
- [ ] Exploitation method reviewed with instructor
- [ ] Documentation template ready
- [ ] Safety procedures understood

#### Exploitation Attempts:
```bash
# Test basic SQL injection
curl -X POST "http://localhost:5000/login" \
  -d "username=admin' OR '1'='1&password=anything" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Results Documentation**:
- **Success/Failure**: _________________________________
- **Data Accessed**: _________________________________
- **Error Messages**: _________________________________
- **Impact Assessment**: _________________________________

### 3.2 Cross-Site Scripting (XSS) Testing
**Objective**: Demonstrate XSS vulnerabilities and impact

#### Exploitation Attempts:
```bash
# Test for reflected XSS
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"

# Test for stored XSS
curl -X POST "http://localhost:5000/comment" \
  -d "comment=<img src=x onerror=alert('Stored XSS')>" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Results Documentation**:
- **XSS Type Found**: _________________________________
- **Payload Used**: _________________________________
- **Response Received**: _________________________________
- **Potential Impact**: _________________________________

### 3.3 Configuration Exploitation
**Objective**: Exploit misconfigurations and weak settings

#### Exploitation Attempts:
```bash
# Test debug mode exposure
curl "http://localhost:5000/debug" -v

# Test weak authentication
curl -X POST "http://localhost:8080/login" \
  -d "username=admin&password=admin" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

**Results Documentation**:
- **Configuration Issues Found**: _________________________________
- **Information Disclosed**: _________________________________
- **Authentication Bypassed**: _________________________________
- **Access Gained**: _________________________________

### Exploitation Summary Table:
| Vulnerability | Exploitation Success | Impact Level | Evidence Gathered |
|---------------|---------------------|--------------|-------------------|
|               |                     |              |                   |
|               |                     |              |                   |
|               |                     |              |                   |

### Knowledge Check 3:
**Q1**: What is the difference between a proof-of-concept and a weaponized exploit?
**A1**: _________________________________________________

**Q2**: How do you ensure exploitation activities remain within ethical boundaries?
**A2**: _________________________________________________

**Q3**: What should you do if you accidentally access unintended data during testing?
**A3**: _________________________________________________

## 🔍 Phase 4: Post-Exploitation Analysis (45 minutes)

### 4.1 Persistence and Access Maintenance
**Objective**: Understand how attackers maintain long-term access

#### Simulation Commands:
```bash
# Monitor persistent connections
python samples/backdoor-apps/backdoor_app.py &
python src/analyzer/network_cli.py --monitor-connections --duration 120 --educational
```

**Persistence Mechanisms Observed**:
1. **Method**: _________________________________
   - **Detection Difficulty**: _________________________________
   - **Persistence Duration**: _________________________________

2. **Method**: _________________________________
   - **Detection Difficulty**: _________________________________
   - **Persistence Duration**: _________________________________

### 4.2 Data Exfiltration Patterns
**Objective**: Recognize data theft techniques and patterns

#### Simulation Commands:
```bash
# Monitor exfiltration patterns
python samples/network-scenarios/backdoor_simulation.py 90 &
python src/analyzer/network_cli.py --capture-traffic --duration 100 --educational
```

**Exfiltration Analysis**:
- **Data Types Targeted**: _________________________________
- **Exfiltration Methods**: _________________________________
- **Traffic Patterns**: _________________________________
- **Detection Indicators**: _________________________________

### 4.3 Impact Assessment
**Objective**: Evaluate the full business impact of successful exploitation

#### Impact Analysis Framework:
**Confidentiality Impact**:
- **Data Accessed**: _________________________________
- **Sensitivity Level**: _________________________________
- **Affected Parties**: _________________________________

**Integrity Impact**:
- **Data Modified**: _________________________________
- **System Changes**: _________________________________
- **Trust Implications**: _________________________________

**Availability Impact**:
- **Services Affected**: _________________________________
- **Downtime Potential**: _________________________________
- **Recovery Complexity**: _________________________________

### Knowledge Check 4:
**Q1**: What is the difference between impact and exploitability in risk assessment?
**A1**: _________________________________________________

**Q2**: How do you assess the business impact of a technical vulnerability?
**A2**: _________________________________________________

**Q3**: What factors determine how long an attacker can maintain access?
**A3**: _________________________________________________

## 📊 Phase 5: Professional Reporting (60 minutes)

### 5.1 Executive Summary Draft
**Objective**: Communicate risk to business stakeholders

#### Executive Summary Template:
**Assessment Overview**:
- **Target Environment**: _________________________________
- **Testing Duration**: _________________________________
- **Methodology Used**: _________________________________

**Key Findings**:
- **Critical Vulnerabilities**: _____ (Number)
- **High-Risk Issues**: _____ (Number)  
- **Successfully Exploited**: _____ (Number)

**Business Risk Level**: ❑ Critical ❑ High ❑ Medium ❑ Low

**Top 3 Recommendations**:
1. _________________________________
2. _________________________________
3. _________________________________

### 5.2 Technical Findings Report
**Objective**: Provide detailed technical information for remediation

#### Vulnerability Details Template:
**Vulnerability 1**:
- **Title**: _________________________________
- **Severity**: ❑ Critical ❑ High ❑ Medium ❑ Low
- **CVSS Score**: _____
- **Location**: _________________________________
- **Description**: _________________________________
- **Exploitation Steps**: _________________________________
- **Impact**: _________________________________
- **Remediation**: _________________________________
- **Evidence**: _________________________________

**Vulnerability 2**:
- **Title**: _________________________________
- **Severity**: ❑ Critical ❑ High ❑ Medium ❑ Low
- **CVSS Score**: _____
- **Location**: _________________________________
- **Description**: _________________________________
- **Exploitation Steps**: _________________________________
- **Impact**: _________________________________
- **Remediation**: _________________________________
- **Evidence**: _________________________________

### 5.3 Risk Prioritization Matrix

| Vulnerability | Exploitability | Impact | Risk Score | Priority |
|---------------|----------------|---------|------------|----------|
|               |                |         |            |          |
|               |                |         |            |          |
|               |                |         |            |          |
|               |                |         |            |          |

### 5.4 Remediation Roadmap
**Objective**: Provide actionable steps for security improvement

#### Immediate Actions (0-30 days):
1. _________________________________
2. _________________________________
3. _________________________________

#### Short-term Improvements (1-3 months):
1. _________________________________
2. _________________________________
3. _________________________________

#### Long-term Strategy (6-12 months):
1. _________________________________
2. _________________________________
3. _________________________________

### Knowledge Check 5:
**Q1**: How should technical findings be communicated differently to executives vs. developers?
**A1**: _________________________________________________

**Q2**: What factors should influence vulnerability remediation prioritization?
**A2**: _________________________________________________

**Q3**: How do you balance technical accuracy with business communication needs?
**A3**: _________________________________________________

## 🎓 Self-Assessment and Reflection

### Technical Skills Self-Evaluation
Rate your performance in each area (1=Needs Improvement, 5=Excellent):

- **Reconnaissance**: 1 - 2 - 3 - 4 - 5
- **Vulnerability Assessment**: 1 - 2 - 3 - 4 - 5  
- **Exploitation**: 1 - 2 - 3 - 4 - 5
- **Post-Exploitation Analysis**: 1 - 2 - 3 - 4 - 5
- **Report Writing**: 1 - 2 - 3 - 4 - 5

### Ethical Understanding Self-Check
**Q1**: Do I fully understand the legal and ethical boundaries of penetration testing?
❑ Yes, completely ❑ Mostly ❑ Somewhat ❑ Need more training

**Q2**: Am I confident I can apply these skills ethically in real-world scenarios?
❑ Yes, completely ❑ Mostly ❑ Somewhat ❑ Need more training

**Q3**: Do I understand the professional responsibilities of security practitioners?
❑ Yes, completely ❑ Mostly ❑ Somewhat ❑ Need more training

### Reflection Questions
**1. What was the most challenging aspect of this penetration testing exercise?**
_________________________________________________

**2. How has this exercise changed your understanding of cybersecurity?**
_________________________________________________

**3. What ethical dilemmas did you encounter during the exercise?**
_________________________________________________

**4. How would you explain the value of penetration testing to a business owner?**
_________________________________________________

**5. What additional skills or knowledge do you need to develop for a cybersecurity career?**
_________________________________________________

## 🔄 Integration Review

### Connection to Previous Exercises
**How did SAST findings inform your penetration testing approach?**
_________________________________________________

**How did DAST results guide your exploitation attempts?**
_________________________________________________

**How did Network Analysis help you understand attack patterns?**
_________________________________________________

**How did Sandbox Analysis inform your post-exploitation assessment?**
_________________________________________________

### Career and Next Steps
**Interest in Cybersecurity Career**:
❑ Very interested ❑ Somewhat interested ❑ Neutral ❑ Not interested

**Areas of Cybersecurity Most Interesting**:
❑ Penetration Testing ❑ Security Analysis ❑ Incident Response ❑ Security Architecture
❑ Compliance ❑ Forensics ❑ Risk Management ❑ Security Awareness

**Next Learning Goals**:
1. _________________________________
2. _________________________________
3. _________________________________

---

**Instructor Use Only**

**Student Performance Summary**:
- **Technical Competency**: ___/40 points
- **Professional Skills**: ___/30 points  
- **Ethical Understanding**: ___/30 points
- **Total Score**: ___/100 points

**Additional Comments**:
_________________________________________________