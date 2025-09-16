# DAST Student Worksheet - Dynamic Application Security Testing

**Name:** ________________________________ **Date:** ________________

**Lab Partner:** _________________________ **Section:** ______________

---

## � Pre-Exercise Setup Verification

**Before starting the DAST analysis, verify your environment is ready:**

### Step 1: Check Docker Containers
```bash
# Command to run:
cd docker && docker-compose ps
```

**Expected Output**: You should see containers running including `cybersec_sandbox` and `vulnerable_web_app`

**Container Status Check:**
- [ ] `cybersec_sandbox` - State: Up
- [ ] `vulnerable_web_app` - State: Up

### Step 2: Verify Applications Are Accessible
```bash
# Test Flask Application (Port 5000):
curl -s http://localhost:5000 | head -3

# Test PWA Application (Port 9090):  
curl -s http://localhost:9090 | head -3
```

**Application Accessibility Check:**
- [ ] Flask App responds at http://localhost:5000 ✅
- [ ] PWA App responds at http://localhost:9090 ✅

### Step 3: Test DAST Tool
```bash
# Verify DAST analyzer is working:
python src/analyzer/dast_cli.py --help
```

**Tool Verification:**
- [ ] DAST CLI displays help information ✅

### Troubleshooting:
**If applications don't respond:**
1. Restart containers: `cd docker && docker-compose down && docker-compose up -d`
2. Wait 30 seconds for applications to fully start
3. Re-test with curl commands above

**If you encounter any issues, notify your instructor before proceeding.**

---

## �📋 Exercise 1: DAST Fundamentals

### 1.1 Concept Understanding
**Complete the comparison table:**

| Testing Aspect | SAST (Static) | DAST (Dynamic) |
|---------------|---------------|----------------|
| **Application must be running** | Yes / No | Yes / No |
| **Requires source code access** | Yes / No | Yes / No |
| **Tests actual user input** | Yes / No | Yes / No |
| **Finds runtime vulnerabilities** | Yes / No | Yes / No |
| **Speed of analysis** | Fast / Slow | Fast / Slow |

### 1.2 Tool Exploration
```bash
# Command run:
python src/analyzer/dast_cli.py --help
```

**List 3 scan modes available:**
1. _________________________________________________________________
2. _________________________________________________________________  
3. _________________________________________________________________

**What file formats can reports be saved in?**
_________________________________________________________________

---

## 📋 Exercise 2: Basic Web Application Scanning

### 2.1 Flask Application Quick Scan
```bash
# Command run:
python src/analyzer/dast_cli.py http://localhost:5000 --quick --educational
```

**Scan Results Summary:**
- **Total Findings:** _____________
- **Scan Duration:** _____________ seconds
- **HTTP Requests Made:** _____________
- **Successful Responses:** _____________

**Severity Breakdown:**
- **Critical:** _____ **High:** _____ **Medium:** _____ **Low:** _____ **Info:** _____

### 2.2 Security Headers Analysis
**List 3 missing security headers found:**
1. _________________________________________________________________
2. _________________________________________________________________
3. _________________________________________________________________

**Why are missing security headers a security concern?**
_________________________________________________________________
_________________________________________________________________

### 2.3 Deep Scan Analysis
```bash
# Command run:
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational
```

**Additional findings from deep scan:**
- **Additional endpoints discovered:** _________________________________
- **New vulnerabilities found:** ___________________________________
- **Total scan time difference:** ______ seconds (quick vs deep)

**Which tools were used in the deep scan?**
_________________________________________________________________

---

## 📋 Exercise 3: PWA Application Analysis

### 3.1 Progressive Web App Scan
```bash
# Command run:
python src/analyzer/dast_cli.py http://localhost:9090 --educational --output pwa_report.json
```

**PWA Scan Results:**
- **Total Findings:** _____________
- **Most Severe Finding:** ________________________________________
- **Unique Vulnerabilities (not in Flask app):** _____________________

### 3.2 Application Comparison
**Complete the vulnerability comparison:**

| Vulnerability Type | Flask App | PWA App | Which is More Severe? |
|--------------------|-----------|---------|----------------------|
| Missing Security Headers | Found / Not Found | Found / Not Found | Flask / PWA / Same |
| XSS Vulnerabilities | Found / Not Found | Found / Not Found | Flask / PWA / Same |
| SQL Injection | Found / Not Found | Found / Not Found | Flask / PWA / Same |
| Information Disclosure | Found / Not Found | Found / Not Found | Flask / PWA / Same |

**Which application has the higher overall risk score?**
_________________________________________________________________

---

## 📋 Exercise 4: Vulnerability Deep Dive

### 4.1 Cross-Site Scripting (XSS) Analysis
**If XSS was found, complete this section:**

**XSS Finding Details:**
- **Vulnerable Parameter:** ________________________________________
- **Test Payload Used:** __________________________________________
- **Evidence of Vulnerability:** ___________________________________

**How does the DAST scanner detect XSS?**
_________________________________________________________________
_________________________________________________________________

### 4.2 SQL Injection Analysis  
**If SQL injection was found, complete this section:**

**SQL Injection Details:**
- **Vulnerable Parameter:** ________________________________________
- **Test Payload Used:** __________________________________________
- **Database Error Message:** _____________________________________

**Why do error messages indicate SQL injection vulnerability?**
_________________________________________________________________
_________________________________________________________________

### 4.3 Information Disclosure
**What sensitive information was disclosed by the applications?**
_________________________________________________________________
_________________________________________________________________

**How could an attacker use this information?**
_________________________________________________________________
_________________________________________________________________

---

## 📋 Exercise 5: SAST vs DAST Comparison

### 5.1 Combined Analysis Results
```bash
# Command run:
python src/analyzer/dast_cli.py --demo-apps --educational
```

**Compare with previous SAST results:**

| Vulnerability Category | SAST Found | DAST Found | Why the Difference? |
|----------------------|------------|------------|-------------------|
| **SQL Injection** | Yes / No | Yes / No | _________________ |
| **Cross-Site Scripting** | Yes / No | Yes / No | _________________ |
| **Missing Security Headers** | Yes / No | Yes / No | _________________ |
| **Debug Information** | Yes / No | Yes / No | _________________ |
| **Hardcoded Secrets** | Yes / No | Yes / No | _________________ |
| **Dependency Vulnerabilities** | Yes / No | Yes / No | _________________ |

### 5.2 Methodology Strengths
**List 2 advantages of DAST over SAST:**
1. _________________________________________________________________
2. _________________________________________________________________

**List 2 advantages of SAST over DAST:**
1. _________________________________________________________________
2. _________________________________________________________________

**How would you use both methods together in a security program?**
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________

---

## 📋 Exercise 6: Professional Reporting

### 6.1 Executive Summary
**Write a brief executive summary of your findings:**

**DYNAMIC SECURITY ASSESSMENT SUMMARY**

**Applications Tested:** ___________________________________________

**Total Security Issues Found:** ___________________________________

**Most Critical Finding:** _______________________________________
_________________________________________________________________

**Immediate Action Required:** ____________________________________
_________________________________________________________________

**Overall Risk Level:** Low / Medium / High / Critical

### 6.2 Top 3 Remediation Priorities

**1. Priority #1:**
- **Vulnerability:** _____________________________________________
- **Risk Level:** ______________________________________________
- **Remediation:** _____________________________________________
- **Estimated Effort:** ________________________________________

**2. Priority #2:**
- **Vulnerability:** _____________________________________________
- **Risk Level:** ______________________________________________  
- **Remediation:** _____________________________________________
- **Estimated Effort:** ________________________________________

**3. Priority #3:**
- **Vulnerability:** _____________________________________________
- **Risk Level:** ______________________________________________
- **Remediation:** _____________________________________________
- **Estimated Effort:** ________________________________________

### 6.3 Security Recommendations
**List 3 general security improvements for the applications:**

1. _________________________________________________________________
2. _________________________________________________________________
3. _________________________________________________________________

---

## 🎯 Reflection Questions

### Technical Understanding:
**1. What types of vulnerabilities can ONLY be found through dynamic testing?**
_________________________________________________________________
_________________________________________________________________

**2. Why is it important to test applications in a running state?**
_________________________________________________________________
_________________________________________________________________

**3. What are the limitations of DAST compared to SAST?**
_________________________________________________________________
_________________________________________________________________

### Practical Application:
**4. When would you run DAST scans in a development workflow?**
_________________________________________________________________
_________________________________________________________________

**5. How would you verify DAST findings before reporting them?**
_________________________________________________________________
_________________________________________________________________

### Career Relevance:
**6. What roles in cybersecurity would regularly use DAST tools?**
_________________________________________________________________
_________________________________________________________________

**7. How does DAST fit into compliance requirements (like PCI DSS)?**
_________________________________________________________________
_________________________________________________________________

---

## 📚 Additional Learning

### Challenge Questions:
**1. Research: What is the difference between authenticated and unauthenticated DAST scanning?**
_________________________________________________________________
_________________________________________________________________

**2. Design: How would you integrate DAST into a CI/CD pipeline?**
_________________________________________________________________
_________________________________________________________________

**3. Analysis: What metrics would you track to measure DAST program effectiveness?**
_________________________________________________________________
_________________________________________________________________

---

## ⚖️ Legal and Ethical Considerations

### Professional Responsibility in Dynamic Testing
**1. Employment Impact:** How do runtime vulnerabilities you found affect developers and IT staff responsibilities?
_________________________________________________________________
_________________________________________________________________

**2. Privacy Rights:** What personal data could be exposed through the runtime vulnerabilities identified?
_________________________________________________________________
_________________________________________________________________

**3. Intellectual Property:** Could the security misconfigurations expose proprietary application logic?
_________________________________________________________________
_________________________________________________________________

### Regulatory Compliance
**4. Web Application Compliance:** How do missing security headers violate web security standards?
_________________________________________________________________
_________________________________________________________________

**5. Data Protection:** Which findings could lead to regulatory violations (GDPR, CCPA, PCI DSS)?
_________________________________________________________________
_________________________________________________________________

### Ethical Testing Practices
**6. Authorized Testing:** Why is it critical to only perform DAST on applications you own or have permission to test?
_________________________________________________________________
_________________________________________________________________

**7. Responsible Disclosure:** How should runtime vulnerabilities be reported to application owners?
_________________________________________________________________
_________________________________________________________________

---

## 🔐 Cryptography and Runtime Security

### Cryptographic Implementation Assessment
**1. Transport Security:** Did you find issues with HTTPS implementation or weak encryption in transit?
_________________________________________________________________
_________________________________________________________________

**2. Session Management:** What cryptographic weaknesses were found in session handling?
_________________________________________________________________
_________________________________________________________________

**3. Authentication Security:** How do the authentication vulnerabilities relate to cryptographic best practices?
_________________________________________________________________
_________________________________________________________________

**4. Runtime Cryptography:** What recommendations would you make for improving cryptographic controls?
_________________________________________________________________
_________________________________________________________________

---

## 💼 Business Impact Assessment

### Enterprise Runtime Security Impact
**1. Operational Impact:** How would runtime exploitation of these vulnerabilities affect business operations?
_________________________________________________________________
_________________________________________________________________

**2. Customer Trust:** How could runtime security issues affect customer confidence and retention?
_________________________________________________________________
_________________________________________________________________

**3. Compliance Costs:** What would be the cost of regulatory fines from runtime security failures?
- **PCI DSS Violations:** __________________________________________
- **Data Protection Fines:** ______________________________________
- **Industry-Specific Penalties:** _________________________________

**4. Incident Response:** What would be the cost of responding to a security incident from these vulnerabilities?
_________________________________________________________________
_________________________________________________________________

---

**🎓 Completion Checklist:**
- [ ] Completed all scan commands successfully
- [ ] Analyzed findings from both applications  
- [ ] Compared SAST vs DAST results
- [ ] Created professional remediation recommendations
- [ ] Reflected on practical applications of DAST

**Instructor Signature:** _________________________ **Grade:** _______