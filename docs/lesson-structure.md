# Cybersecurity Education - Comprehensive Lesson Structure

## 📚 Course Overview

This comprehensive cybersecurity education programme provides hands-on experience
with security analysis techniques through a structured learning progression.
Students will master foundational concepts before advancing to integrated
methodologies and strategic security assessment.

**Total Course Duration**: 17-22 hours (7 exercises × 1-4 hours each)  
**Prerequisites**: Basic understanding of computer systems and web
applications  
**Target Audience**: High school students (ages 14-18)  
**Learning Approach**: Hands-on laboratory exercises with real vulnerable
applications progressing from manual analysis to automated testing to strategic
assessment

---

## 🎯 Learning Progression & Rationale

### Why This Order?

1. **Manual Code Review First**: Develops security thinking and systematic
   analysis skills
2. **Sandbox Analysis Second**: Builds fundamental security awareness and threat
   detection skills
3. **SAST Third**: Introduces automated code-level security analysis with
   immediate feedback
4. **DAST Fourth**: Adds runtime testing to complement static analysis
   understanding
5. **Network Traffic Analysis Fifth**: Adds comprehensive network security
   monitoring and threat detection
6. **Penetration Testing Sixth**: Integrates all previous skills into
   professional methodology
7. **Organisational Vulnerability Assessment Last**: Develops strategic security
   thinking and business alignment

This progression ensures students build foundational security thinking before
advancing to automated tools, then integrate technical skills with strategic
business understanding.

---

## 📖 Lesson 1: Manual Code Review

**Foundation Building - Human Security Analysis**

### 📍 Overview

Students learn to manually review source code for security vulnerabilities using
human intelligence and systematic methodology, developing foundational security
thinking skills that complement automated testing.

### ⏱️ Duration: 1-2 hours

### 📋 Materials

- **Main Exercise**:
  [`exercises/1.manual-code-review-exercise.md`](exercises/1.manual-code-review-exercise.md)
- **Instructor Guide**:
  [`instructor-guides/1.manual-code-review-instructor-guide.md`](instructor-guides/1.manual-code-review-instructor-guide.md)
- **Student Worksheet**:
  [`student-worksheets/1.manual-code-review-student-worksheet.md`](student-worksheets/1.manual-code-review-student-worksheet.md)
- **Quick Reference**:
  [`quick-reference-guides/1.manual-code-review-quick-reference.md`](quick-reference-guides/1.manual-code-review-quick-reference.md)

### 🎯 Key Learning Outcomes

- ✅ Understand what manual code review is and how it differs from automated
  testing
- ✅ Apply systematic code review methodology to identify security
  vulnerabilities
- ✅ Recognise common security anti-patterns through manual source code
  inspection
- ✅ Evaluate authentication, authorisation, and input validation
  implementations
- ✅ Document security findings with clear explanations and remediation
  recommendations
- ✅ Understand the role of human judgement in security assessment

### 🧪 Sample Applications Analysed

- **Unsecure PWA**: [`samples/unsecure-pwa/`](../samples/unsecure-pwa/) - Focus
  on manual analysis of Python backend and HTML templates

### 🔧 Primary Tools

- Human intelligence and systematic analysis methodology
- Code reading and vulnerability pattern recognition
- Business logic flaw identification
- Professional security documentation

### 📊 Assessment Focus

- Security thinking development
- Systematic analysis methodology
- Vulnerability pattern recognition
- Professional documentation skills

---

## 📖 Lesson 2: Sandbox Security Analysis

**Foundation Building - Understanding Malicious Behaviour**

### 📍 Overview

Students learn to safely analyse suspicious applications in controlled
environments, developing fundamental threat detection and behavioural analysis
skills.

### ⏱️ Duration: 3-4 hours

### 📋 Materials

- **Main Exercise**:
  [`exercises/2.sandbox-security-analysis-exercise.md`](exercises/2.sandbox-security-analysis-exercise.md)
- **Instructor Guide**:
  [`instructor-guides/2.sandbox-instructor-guide.md`](instructor-guides/2.sandbox-instructor-guide.md)
- **Student Worksheet**:
  [`student-worksheets/2.sandbox-student-worksheet.md`](student-worksheets/2.sandbox-student-worksheet.md)
- **Quick Reference**:
  [`quick-reference-guides/2.sandbox-quick-reference.md`](quick-reference-guides/2.sandbox-quick-reference.md)

### 🎯 Key Learning Outcomes

- ✅ Understand what sandbox analysis is and why it's critical for cybersecurity
- ✅ **Master containerization concepts and why isolation is essential for
  security testing**
- ✅ **Learn how Docker containers create safe, controlled environments for
  malware analysis**
- ✅ **Experience professional security testing architecture with
  multi-container environments**
- ✅ Safely execute and monitor suspicious applications using system call
  tracing
- ✅ Identify behavioural indicators of malicious software (malware, backdoors,
  miners)
- ✅ Use network monitoring and resource analysis to detect threats
- ✅ **Understand how container isolation mirrors real-world security testing
  environments**
- ✅ Document security findings and behavioural patterns professionally

### 🧪 Sample Applications Used

- **Suspicious Script**:
  [`samples/suspicious-scripts/suspicious_script.py`](../samples/suspicious-scripts/suspicious_script.py)
- **Backdoor Web App**:
  [`samples/backdoor-apps/backdoor_app.py`](../samples/backdoor-apps/backdoor_app.py)
- **Crypto Miner**:
  [`samples/resource-abuse/crypto_miner.py`](../samples/resource-abuse/crypto_miner.py)

### 🔧 Primary Tools

- System call monitoring and process analysis
- Network connection monitoring
- Resource usage analysis
- Behavioural pattern recognition

### 📊 Assessment Focus

- Threat detection accuracy
- Behavioural analysis skills
- Professional documentation
- Safety protocol adherence

---

## 📖 Lesson 3: Static Application Security Testing (SAST)

**Code-Level Security Analysis**

### 📍 Overview

Students learn to analyse source code for security vulnerabilities using
automated tools, developing skills to identify common coding flaws before
applications run.

### ⏱️ Duration: 3-4 hours

### 📋 Materials

- **Main Exercise**:
  [`exercises/3.static-application-security-testing-exercise.md`](exercises/3.static-application-security-testing-exercise.md)
- **Instructor Guide**:
  [`instructor-guides/3.sast-instructor-guide.md`](instructor-guides/3.sast-instructor-guide.md)
- **Student Worksheet**:
  [`student-worksheets/3.sast-student-worksheet.md`](student-worksheets/3.sast-student-worksheet.md)
- **Quick Reference**:
  [`quick-reference-guides/3.sast-quick-reference.md`](quick-reference-guides/3.sast-quick-reference.md)

### 🎯 Key Learning Outcomes

- ✅ Understand what Static Application Security Testing is and when to use it
- ✅ Execute automated security analysis using industry-standard tools (Bandit,
  Semgrep, Safety)
- ✅ Interpret SAST tool outputs and prioritise security findings by severity
- ✅ Apply remediation techniques to fix common security vulnerabilities
- ✅ Understand OWASP Top 10 vulnerabilities through hands-on code analysis

### 🧪 Sample Applications Analysed

- **Vulnerable Flask App**:
  [`samples/vulnerable-flask-app/`](../samples/vulnerable-flask-app/)
- **Unsecure PWA**: [`samples/unsecure-pwa/`](../samples/unsecure-pwa/)

### 🔧 Primary Tools

- **Bandit**: Python security linter for common vulnerabilities
- **Semgrep**: Pattern-based static analysis for security anti-patterns
- **Safety**: Python dependency vulnerability scanner
- **CLI Interface**:
  [`src/analyser/analyse_cli.py`](../src/analyser/analyse_cli.py)

### 📊 Assessment Focus

- Tool execution proficiency
- Vulnerability identification accuracy
- Code remediation understanding
- Risk prioritization skills

---

## 📖 Lesson 4: Dynamic Application Security Testing (DAST)

**Runtime Security Testing**

### 📍 Overview

Students learn to test running web applications for security vulnerabilities,
complementing their static analysis skills with runtime testing techniques.

### ⏱️ Duration: 3-4 hours

### 📋 Materials

- **Main Exercise**:
  [`exercises/4.dynamic-application-security-testing-exercise.md`](exercises/4.dynamic-application-security-testing-exercise.md)
- **Instructor Guide**:
  [`instructor-guides/4.dast-instructor-guide.md`](instructor-guides/4.dast-instructor-guide.md)
- **Student Worksheet**:
  [`student-worksheets/4.dast-student-worksheet.md`](student-worksheets/4.dast-student-worksheet.md)
- **Quick Reference**:
  [`quick-reference-guides/4.dast-quick-reference.md`](quick-reference-guides/4.dast-quick-reference.md)

### 🎯 Key Learning Outcomes

- ✅ Understand how Dynamic Application Security Testing differs from SAST
- ✅ Execute web application vulnerability scans against running applications
- ✅ Interpret DAST tool outputs and identify runtime vulnerabilities
- ✅ Test for XSS, SQL injection, and security header misconfigurations
- ✅ Compare and contrast SAST vs DAST findings for comprehensive security
  assessment

### 🧪 Applications Tested

- **Running Flask App**: http://localhost:9090
- **Running PWA App**: http://localhost:5000

### 🔧 Primary Tools

- **Nikto**: Web vulnerability scanner
- **Gobuster**: Directory/file enumeration
- **Custom XSS/SQLi Testers**: Educational vulnerability detection
- **CLI Interface**: [`src/analyser/dast_cli.py`](../src/analyser/dast_cli.py)

### 📊 Assessment Focus

- Runtime testing execution
- Vulnerability verification skills
- SAST/DAST methodology comparison
- Professional security reporting

---

## 📖 Lesson 5: Network Traffic Analysis

**Network Security Monitoring and Threat Detection**

### 📍 Overview

Students learn to monitor network traffic, identify suspicious communication
patterns, and detect network-based threats to complement application-level
security analysis.

### ⏱️ Duration: 3-4 hours

### 📋 Materials

- **Main Exercise**:
  [`exercises/5.network-traffic-analysis-exercise.md`](exercises/5.network-traffic-analysis-exercise.md)
- **Instructor Guide**:
  [`instructor-guides/5.network-instructor-guide.md`](instructor-guides/5.network-instructor-guide.md)
- **Student Worksheet**:
  [`student-worksheets/5.network-student-worksheet.md`](student-worksheets/5.network-student-worksheet.md)
- **Quick Reference**:
  [`quick-reference-guides/5.network-quick-reference.md`](quick-reference-guides/5.network-quick-reference.md)

### 🎯 Key Learning Outcomes

- ✅ Understand what network traffic analysis is and how it complements
  SAST/DAST
- ✅ Monitor network connections and identify suspicious communication patterns
- ✅ Perform service discovery and DNS traffic analysis using network scanning
  tools
- ✅ Distinguish between normal and malicious network behaviour patterns
- ✅ Use real-time network monitoring tools for threat detection and incident
  response
- ✅ Break down an HTTPS request into DNS/TCP/TLS/transfer phases and
  visualise the full HTTP stream using `dig`, `curl -w`, and `curl -v`

### 🧪 Network Scenarios

- **Basic Network Activity**:
  [`samples/network-scenarios/basic_network_activity.py`](../samples/network-scenarios/basic_network_activity.py)
- **Suspicious Traffic**:
  [`samples/network-scenarios/suspicious_traffic_generator.py`](../samples/network-scenarios/suspicious_traffic_generator.py)
- **Backdoor Communication**:
  [`samples/network-scenarios/backdoor_simulation.py`](../samples/network-scenarios/backdoor_simulation.py)
- **DNS Threats**:
  [`samples/network-scenarios/dns_threat_scenarios.py`](../samples/network-scenarios/dns_threat_scenarios.py)

### 🔧 Primary Tools

- **Network Connection Monitoring**: Real-time connection tracking
- **Nmap**: Network scanning and service discovery
- **DNS Analysis**: DNS query monitoring and threat detection
- **CLI Interface**:
  [`src/analyser/network_cli.py`](../src/analyser/network_cli.py)

### 📊 Assessment Focus

- Network monitoring proficiency
- Pattern recognition skills
- Threat detection accuracy
- Network security understanding

---

## 📖 Lesson 6: Penetration Testing Methodology

**Advanced Integration Exercise**

### 📍 Overview

**ADVANCED EXERCISE** - Students integrate all previous skills into professional
penetration testing methodology, learning systematic security assessment and
ethical considerations.

### ⏱️ Duration: 4-5 hours

### ⚠️ Prerequisites

**REQUIRED**: Successful completion of Sandbox, SAST, and DAST exercises

### 📋 Materials

- **Main Exercise**:
  [`exercises/6.penetration-testing-exercise.md`](exercises/6.penetration-testing-exercise.md)
- **Instructor Guide**:
  [`instructor-guides/6.penetration-testing-instructor-guide.md`](instructor-guides/6.penetration-testing-instructor-guide.md)
- **Student Worksheet**:
  [`student-worksheets/6.penetration-testing-student-worksheet.md`](student-worksheets/6.penetration-testing-student-worksheet.md)
- **Quick Reference**:
  [`quick-reference-guides/6.penetration-testing-quick-reference.md`](quick-reference-guides/6.penetration-testing-quick-reference.md)

### 🎯 Key Learning Outcomes

- ✅ Understand professional penetration testing methodology and ethical
  considerations
- ✅ Conduct systematic reconnaissance using multiple security analysis
  techniques
- ✅ Integrate findings from SAST, DAST, Network Analysis, and Sandbox testing
- ✅ Perform controlled exploitation in authorised, safe environments
- ✅ Create comprehensive professional security reports with risk assessments
- ✅ Appreciate legal and ethical responsibilities of cybersecurity
  professionals

### 🔧 Integrated Tool Usage

- **All Previous Tools**: SAST, DAST, Sandbox analysis integration
- **Manual Methodology**: Professional penetration testing approach
- **Comprehensive Reporting**: Executive summary and technical detail
  integration

### ⚖️ Ethical Focus

- **Strong Ethical Guidelines**: Legal and responsible testing principles
- **Authorised Testing Only**: Clear boundaries and permission requirements
- **Professional Standards**: Industry-standard ethical practices

### 📊 Assessment Focus

- **Integration Skills**: Combining multiple analysis methodologies
- **Ethical Understanding**: Responsible security testing principles
- **Professional Communication**: Executive-level security reporting
- **Systematic Methodology**: Structured penetration testing approach

---

## 📖 Lesson 7: Organisational Vulnerability Assessment

**Strategic Security Analysis and Business Alignment**

### 📍 Overview

**CAPSTONE EXERCISE** - Students evaluate organisational security posture beyond
technical vulnerabilities, focusing on people, processes, technology practices,
and strategic factors that contribute to sustainable security.

### ⏱️ Duration: 1-2 hours

### ⚠️ Prerequisites

**REQUIRED**: Completion of previous exercises to provide technical findings for
organisational analysis

### 📋 Materials

- **Main Exercise**:
  [`exercises/7.organisational-vulnerability-assessment-exercise.md`](exercises/7.organisational-vulnerability-assessment-exercise.md)
- **Instructor Guide**:
  [`instructor-guides/7.organisational-vulnerability-assessment-instructor-guide.md`](instructor-guides/7.organisational-vulnerability-assessment-instructor-guide.md)
- **Student Worksheet**:
  [`student-worksheets/7.organisational-vulnerability-assessment-student-worksheet.md`](student-worksheets/7.organisational-vulnerability-assessment-student-worksheet.md)
- **Quick Reference**:
  [`quick-reference-guides/7.organisational-vulnerability-assessment-quick-reference.md`](quick-reference-guides/7.organisational-vulnerability-assessment-quick-reference.md)

### 🎯 Key Learning Outcomes

- ✅ Understand what organisational vulnerability assessment encompasses beyond
  technical testing
- ✅ Evaluate technology stack security posture and architectural decisions
- ✅ Assess security policies, procedures, and organisational practices
- ✅ Analyse development lifecycle security integration and security culture
- ✅ Document comprehensive security recommendations for organisational
  improvement
- ✅ Understand the business impact and strategic importance of security
  assessment

### 🧪 Assessment Focus

- **Case Study**: Comprehensive analysis of the Unsecure PWA organisation using
  all previous technical findings
- **Root Cause Analysis**: Connecting technical vulnerabilities to
  organisational factors
- **Strategic Planning**: Developing business-aligned security improvement
  roadmaps

### 🔧 Assessment Methodology

- **Evidence-Based Analysis**: Inferring organisational gaps from technical
  findings
- **Maturity Assessment**: Evaluating organisational security maturity levels
- **Gap Analysis**: Identifying specific improvement opportunities
- **Business Communication**: Developing stakeholder-appropriate recommendations

### ⚖️ Strategic Focus

- **Business Alignment**: Connecting security improvements to business
  objectives
- **Sustainable Security**: Addressing root causes rather than symptoms
- **Executive Communication**: Developing business justification for security
  investments
- **Organisational Culture**: Understanding how culture affects security
  outcomes

### 📊 Assessment Focus

- **Strategic Thinking**: Integration of technical findings with business impact
- **Root Cause Analysis**: Understanding organisational factors contributing to
  vulnerabilities
- **Business Communication**: Professional stakeholder communication skills
- **Sustainable Planning**: Realistic improvement roadmap development

---

## 🎓 Course Completion Requirements

### Individual Lesson Requirements

Each lesson requires:

- [ ] **Pre-Exercise Setup Verification**: Environment confirmation
- [ ] **Hands-on Exercise Completion**: All analysis activities
- [ ] **Student Worksheet Submission**: Documented findings and analysis
- [ ] **Reflection Questions**: Critical thinking demonstration
- [ ] **Professional Report**: Security findings documentation

### Overall Course Requirements

- [ ] **All 7 Lessons Completed**: Manual Code Review → Sandbox → SAST → DAST →
      Network Analysis → Penetration Testing → Organisational Assessment
- [ ] **Integrated Final Report**: Comprehensive security assessment combining
      all methodologies
- [ ] **Ethical Compliance Demonstration**: Understanding of responsible
      security testing
- [ ] **Tool Proficiency**: Demonstrated competency with all security analysis
      tools
- [ ] **Strategic Understanding**: Business-aligned security thinking and
      communication

---

## 📊 Assessment and Evaluation

### Individual Lesson Assessment (100 points each)

- **Technical Skills (40%)**: Tool usage and analysis execution
- **Knowledge Understanding (40%)**: Conceptual comprehension and application
- **Professional Communication (20%)**: Documentation and reporting quality

### Final Course Assessment (200 points)

- **Integration Project (50%)**: Comprehensive security assessment using all
  methodologies
- **Ethical Understanding (25%)**: Demonstrated responsible security testing
  knowledge
- **Professional Presentation (25%)**: Executive-level security findings
  presentation

### Grading Scale

- **A (90-100%)**: Mastery of all concepts with professional-level execution
- **B (80-89%)**: Proficient understanding with good practical application
- **C (70-79%)**: Basic competency with some areas needing development
- **D (60-69%)**: Limited understanding requiring additional instruction
- **F (Below 60%)**: Insufficient mastery requiring course repetition

---

## 🛠️ Technical Infrastructure

### Required Environment

- **GitHub Codespaces**: Recommended for consistent, cloud-based learning
  environment
- **Docker Containers**: All security tools and vulnerable applications
  pre-configured
- **Web Browser**: Modern browser for accessing applications and reports

### Tool Suite

- **Security Analysis**: Bandit, Semgrep, Safety, Nikto, Gobuster, Nmap
- **Development Environment**: Python 3.11, Flask, VS Code with security
  extensions
- **Monitoring Tools**: Network analysis, system call tracing, resource
  monitoring

### Sample Applications

- **5 Vulnerable Applications**: Flask web app, PWA, backdoor applications,
  suspicious scripts, crypto miners
- **4 Network Scenarios**: Normal activity, suspicious patterns, backdoor
  communication, DNS threats

---

## 👥 Instructor Resources

### Preparation Materials

- **Setup Guides**: Environment configuration and verification procedures
- **Answer Keys**: Complete solutions for all exercises and worksheets
- **Assessment Rubrics**: Detailed grading criteria for consistent evaluation
- **Troubleshooting Guides**: Common issues and resolution procedures

### Teaching Support

- **Demonstration Scripts**: Ready-to-use commands for live demonstrations
- **Extension Activities**: Advanced challenges for accelerated learners
- **Safety Protocols**: Ethical guidelines and legal compliance requirements
- **Professional Development**: Industry connections and career pathway guidance

---

## 📚 Additional Resources

### Educational Materials

- **Maintenance Guide**: [`maintenance-guide.md`](maintenance-guide.md) -
  Comprehensive project maintenance and contribution guidelines
- **Project Documentation**: [`../README.md`](../README.md) - Complete project
  overview and quick start guide

### Industry Standards and Frameworks

- **OWASP Top 10**: Web application security risks and mitigation strategies
- **NIST Cybersecurity Framework**: Industry-standard security practices and
  controls
- **ISO 27001**: Information security management system standards

### Career Pathways

- **Cybersecurity Analyst**: Entry-level security monitoring and analysis roles
- **Penetration Tester**: Specialised ethical hacking and vulnerability
  assessment
- **Security Engineer**: Security tool development and infrastructure protection
- **Security Consultant**: Independent security assessment and advisory services

---

## 🎯 Success Metrics

### Student Success Indicators

- **Tool Proficiency**: Independent execution of all security analysis tools
- **Vulnerability Recognition**: Accurate identification and classification of
  security issues
- **Professional Communication**: Clear, actionable security reports and
  recommendations
- **Ethical Understanding**: Demonstrated knowledge of responsible security
  testing principles

### Programme Success Metrics

- **Completion Rate**: Percentage of students successfully completing all 7
  lessons
- **Knowledge Retention**: Post-course assessment scores and practical
  application
- **Industry Readiness**: Student preparation for entry-level cybersecurity
  roles
- **Ethical Compliance**: Zero incidents of inappropriate tool usage or testing

---

**🎓 This comprehensive lesson structure prepares students for successful
careers in cybersecurity through hands-on experience with industry-standard
tools and professional methodologies!**
