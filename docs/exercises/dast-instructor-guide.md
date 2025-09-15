# DAST Instructor Guide - Dynamic Application Security Testing

## 📚 Course Overview

**Duration**: 3-4 hours  
**Prerequisites**: Basic understanding of web applications and HTTP  
**Difficulty Level**: Intermediate  
**Group Size**: 15-25 students (ideal for lab environment)

## 🎯 Learning Objectives

By the end of this exercise, students will be able to:
- [ ] Distinguish between static (SAST) and dynamic (DAST) security testing
- [ ] Execute dynamic vulnerability scans against web applications
- [ ] Interpret DAST tool outputs and prioritize findings
- [ ] Identify runtime-specific vulnerabilities (XSS, SQL injection, headers)
- [ ] Create professional dynamic security assessment reports
- [ ] Understand when and how to integrate DAST into development workflows

## ⏰ Lesson Timeline

### Phase 1: Introduction and Setup (30 minutes)
- **0-10 min**: SAST vs DAST concept introduction
- **10-20 min**: Environment setup and tool verification
- **20-30 min**: Sample application walkthrough

### Phase 2: Basic Scanning (45 minutes)
- **30-50 min**: Exercise 1 - DAST fundamentals
- **50-75 min**: Exercise 2 - Basic web application scanning

### Phase 3: Vulnerability Analysis (60 minutes)
- **75-105 min**: Exercise 3 - Vulnerability deep dive
- **105-135 min**: Exercise 4 - Comparative analysis

### Phase 4: Professional Reporting (45 minutes)
- **135-165 min**: Exercise 5 - Professional reporting
- **165-180 min**: Wrap-up and reflection

## 🧑‍🏫 Instructor Preparation

### Pre-Class Setup:
1. **Environment Verification**: Ensure all containers are running
   ```bash
   cd docker && docker-compose up -d
   curl http://localhost:5000  # Should return Flask app
   curl http://localhost:9090  # Should return PWA app
   ```

2. **Tool Testing**: Verify DAST CLI works correctly
   ```bash
   python src/analyzer/dast_cli.py --help
   python src/analyzer/dast_cli.py http://localhost:5000 --quick
   ```

3. **Student Materials**: Print or share digitally:
   - Exercise worksheet
   - Quick reference guide
   - Assessment rubric

### Demonstration Scripts:
Keep these commands ready for live demonstrations:

```bash
# Basic scan demo
python src/analyzer/dast_cli.py http://localhost:5000 --quick --educational

# Deep scan demo  
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --verbose

# Demo apps scan
python src/analyzer/dast_cli.py --demo-apps --educational
```

## 📋 Exercise Solutions and Teaching Notes

### Exercise 1: DAST Fundamentals

**Teaching Points:**
- Emphasize the "black-box" nature of DAST vs "white-box" SAST
- Use analogy: DAST is like testing a car by driving it vs SAST is like inspecting the engine
- Highlight complementary nature - both are needed for comprehensive security

**Expected Student Responses:**
1. **Why DAST can't find hardcoded passwords**: No access to source code, only tests runtime behavior
2. **Why SAST can't find all SQL injection**: Static analysis can't predict all possible user inputs
3. **When to use DAST**: Testing phase, pre-production, regular security audits

### Exercise 2: Basic Web Application Scanning

**Common Student Findings:**
- **Flask App** (~8-12 findings expected):
  - Missing X-Frame-Options header
  - Missing X-Content-Type-Options header  
  - Missing X-XSS-Protection header
  - Server information disclosure
  - Debug information exposure
  
- **PWA App** (~5-8 findings expected):
  - Missing security headers
  - Session management issues
  - Redirect vulnerabilities

**Teaching Guidance:**
- Walk through each finding type and explain why it's a security issue
- Demonstrate how to read HTTP headers using browser developer tools
- Show how attackers could exploit missing security headers

### Exercise 3: Vulnerability Deep Dive

**Key Concepts to Reinforce:**

**XSS Testing:**
- Show payload examples: `<script>alert('XSS')</script>`
- Explain how DAST detects reflection in responses
- Discuss different XSS types (reflected, stored, DOM-based)

**SQL Injection Testing:**
- Demonstrate payload: `' OR 1=1--`
- Show database error message detection
- Explain why error messages reveal vulnerabilities

**Security Headers:**
- Use browser developer tools to show missing headers
- Explain each header's purpose and protection mechanism
- Demonstrate clickjacking attack scenarios

### Exercise 4: Comparative Analysis

**Expected SAST vs DAST Results:**

| Vulnerability | SAST | DAST | Explanation |
|---------------|------|------|-------------|
| SQL Injection | ✅ | ✅ | Both can find, different methods |
| XSS | ✅ | ✅ | Both effective, SAST finds more variants |
| Missing Headers | ❌ | ✅ | Runtime configuration issue |
| Debug Info | ✅ | ✅ | SAST finds in code, DAST in responses |
| Hardcoded Secrets | ✅ | ❌ | DAST can't see source code |

**Discussion Points:**
- Why some vulnerabilities appear in both
- Unique strengths of each approach
- How to combine both methodologies effectively

## 🎯 Assessment Rubric

### Knowledge Assessment (40%)

**Excellent (90-100%)**:
- Clearly explains SAST vs DAST differences
- Accurately interprets all scan results
- Demonstrates deep understanding of vulnerability types
- Can explain detection mechanisms for each finding

**Proficient (80-89%)**:
- Understands basic SAST vs DAST concepts
- Correctly interprets most scan results
- Shows understanding of major vulnerability types
- Can explain most detection mechanisms

**Developing (70-79%)**:
- Shows basic understanding of testing concepts
- Can interpret simple scan results with guidance
- Recognizes some vulnerability types
- Needs support explaining detection methods

**Beginning (Below 70%)**:
- Limited understanding of testing concepts
- Difficulty interpreting scan results
- Cannot identify vulnerability types
- Cannot explain detection mechanisms

### Practical Skills Assessment (40%)

**Excellent (90-100%)**:
- Successfully executes all scan commands
- Generates comprehensive reports
- Identifies and prioritizes all findings
- Proposes detailed remediation steps

**Proficient (80-89%)**:
- Executes most scan commands correctly
- Generates adequate reports
- Identifies most findings correctly
- Proposes basic remediation steps

**Developing (70-79%)**:
- Executes basic scan commands with help
- Generates simple reports
- Identifies some findings with guidance
- Needs help with remediation planning

**Beginning (Below 70%)**:
- Cannot execute scan commands independently
- Cannot generate reports
- Cannot identify findings
- Cannot propose remediation steps

### Professional Communication (20%)

**Excellent (90-100%)**:
- Clear, professional technical writing
- Well-organized reports with executive summary
- Appropriate use of security terminology
- Actionable recommendations

**Proficient (80-89%)**:
- Generally clear technical communication
- Organized reports with basic structure
- Mostly correct use of terminology
- Basic recommendations provided

**Developing (70-79%)**:
- Some technical communication with guidance
- Basic report structure attempted
- Limited use of correct terminology
- Vague recommendations

**Beginning (Below 70%)**:
- Poor technical communication
- No clear report structure
- Incorrect or no security terminology
- No actionable recommendations

## 🔧 Troubleshooting Guide

### Common Issues:

**Applications Not Responding:**
```bash
# Restart containers
cd docker && docker-compose down && docker-compose up -d

# Check status
docker-compose ps
curl http://localhost:5000
curl http://localhost:9090
```

**DAST Scanner Errors:**
```bash
# Verify Python environment
python --version
pip list | grep requests

# Test basic connectivity
curl -I http://localhost:5000
```

**No Findings Detected:**
- Check if applications are actually running
- Verify URLs are correct (http:// not https://)
- Try with --verbose flag to see detailed output

**Students Getting Different Results:**
- Normal variation based on application state
- Some findings may be intermittent
- Focus on teaching concepts, not exact match of results

## 💡 Extension Activities

### For Advanced Students:
1. **Custom Payload Creation**: Modify scanner to test additional XSS payloads
2. **Authenticated Testing**: Research how to test authenticated application areas
3. **CI/CD Integration**: Design DAST integration for automated pipelines
