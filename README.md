# Docker Sandbox Demo - Cybersecurity Education Platform

## 🎯 Overview

This repository contains a comprehensive Docker-based sandbox environment for teaching cybersecurity concepts to high school students. The platform provides hands-on experience with security analysis, vulnerability detection, and remediation techniques using real applications in a safe, controlled environment.

## 🚀 Quick Start

### GitHub Codespaces (Recommended)
1. Click the "Code" button and select "Create codespace on main"
2. Wait for the environment to load (2-3 minutes)
3. Follow the setup steps in our [Complete Setup Guide](docs/setup-guide.md)

### 🎯 Upload Your Own Flask App for Sandbox Testing
**Ready to upload your own Flask app for security testing?**

```bash
# Quick start - deploy your app
cd uploads/
docker exec cybersec_sandbox bash -c "cd /workspace/uploads && pip3 install -r requirements.txt"
docker exec -d cybersec_sandbox bash -c "cd /workspace/uploads && python3 app.py"

# Test your app
curl http://localhost:8000

# Run security tests
python3 src/analyzer/analyze_cli.py uploads/ --educational
python3 src/analyzer/dast_cli.py http://localhost:8000 --educational
```

**📚 Complete Instructions**: [uploads/README.md](uploads/README.md) | **🛠️ Setup Guide**: [docs/setup-guide.md](docs/setup-guide.md)

📖 **For detailed setup instructions and troubleshooting, see [docs/setup-guide.md](docs/setup-guide.md)**

## 📊 Report Organization

All security analysis reports are automatically organized in the `reports/` directory:

### SAST Reports
```bash
# Manual output path
python src/analyzer/analyze_cli.py <target> --output reports/my_sast_report.json

# Automatic timestamped reports (when no --output specified)
python src/analyzer/analyze_cli.py <target> --educational
# Saves to: reports/sast_report_YYYYMMDD_HHMMSS.json
```

### DAST Reports  
```bash
# Manual output path
python src/analyzer/dast_cli.py <url> --output reports/my_dast_report.json

# Automatic timestamped reports (when no --output specified)  
python src/analyzer/dast_cli.py <url> --educational
# Saves to: reports/dast_report_YYYYMMDD_HHMMSS.json
```

### Network Analysis Reports
```bash
# Manual output path
python src/analyzer/network_cli.py --monitor-connections --output reports/my_network_report.json

# Automatic timestamped reports (when no --output specified)
python src/analyzer/network_cli.py --capture-traffic --educational
# Saves to: reports/network_traffic_capture_YYYYMMDD_HHMMSS.json
```

**Report Formats Available**: JSON (structured data) and Text (human-readable)

## 📚 Educational Content

### 🛡️ Static Application Security Testing (SAST) Exercise
**Location**: `docs/exercises/static-application-security-testing-exercise.md`

A comprehensive 3-4 hour exercise teaching students:
- What SAST is and how it works
- How to use security analysis tools (Bandit, Semgrep, Safety)
- How to interpret security findings and prioritize remediation
- Hands-on analysis of 2 vulnerable applications
- Real-world application of OWASP Top 10 concepts

**Supporting Materials**:
- 📖 **Instructor Guide**: Complete teaching notes, answer keys, and assessment rubrics
- 📋 **Student Worksheet**: Structured activities and reflection questions  
- 🚀 **Quick Reference**: Command cheat sheet and troubleshooting guide

### 🌐 Dynamic Application Security Testing (DAST) Exercise
**Location**: `docs/exercises/dynamic-application-security-testing-exercise.md`

A comprehensive 3-4 hour exercise teaching students:
- What DAST is and how it differs from SAST
- How to test running web applications for security vulnerabilities
- How to use web vulnerability scanners (nikto, gobuster)
- Hands-on testing of 2 running web applications
- Runtime vulnerability detection (XSS, SQL injection, missing headers)

**Supporting Materials**:
- 📖 **Instructor Guide**: Complete teaching notes, answer keys, and assessment rubrics
- 📋 **Student Worksheet**: Structured activities and reflection questions  
- 🚀 **Quick Reference**: Command cheat sheet and troubleshooting guide

### 🕸️ Network Traffic Analysis Exercise
**Location**: `docs/exercises/network-traffic-analysis-exercise.md`

A comprehensive 3-4 hour exercise teaching students:
- What network traffic analysis is and how it complements SAST/DAST
- How to monitor network connections and identify suspicious patterns
- How to perform service discovery and DNS analysis
- Hands-on monitoring of network scenarios (normal vs. malicious traffic)
- Real-time threat detection and pattern recognition

**Supporting Materials**:
- 📖 **Instructor Guide**: Complete teaching notes, answer keys, and assessment rubrics
- 📋 **Student Worksheet**: Structured activities and reflection questions  
- 🚀 **Quick Reference**: Command cheat sheet and troubleshooting guide

**Sample Network Scenarios Included**:
- **Basic Network Activity**: Normal web browsing and DNS queries for baseline comparison
- **Suspicious Traffic**: Port scanning, backdoor connections, and rapid automated patterns
- **Backdoor Communication**: C&C beacons, data exfiltration, and persistence checks
- **DNS Threats**: DNS tunneling, DGA patterns, and malicious domain queries

### 🧪 Sandbox Security Analysis Exercise
**Location**: `docs/exercises/sandbox-security-analysis-exercise.md`

A comprehensive 3-4 hour exercise teaching students:
- What sandbox analysis is and how it differs from SAST and DAST
- How to safely execute and monitor suspicious applications
- Using system call tracing, network monitoring, and resource analysis
- Hands-on analysis of 3 suspicious applications (backdoors, miners, malware)
- Behavioral pattern recognition and malware detection techniques

**Supporting Materials**:
- 📖 **Instructor Guide**: Complete teaching notes, sample files, and assessment rubrics
- 📋 **Student Worksheet**: Structured activities and reflection questions  
- 🚀 **Quick Reference**: Command cheat sheet and troubleshooting guide

**Sample Applications Included**:
- **Suspicious Script**: Fake system optimizer with hidden malicious behavior
- **Backdoor Web App**: Business application with hidden command execution
- **Crypto Miner**: Resource-abusive application disguised as maintenance tool

### ⚔️ Penetration Testing Exercise
**Location**: `docs/exercises/penetration-testing-exercise.md`

A comprehensive 4-5 hour **advanced** exercise teaching students:
- Professional penetration testing methodology and ethical considerations
- Integration of SAST, DAST, Network Analysis, and Sandbox findings
- Systematic reconnaissance, vulnerability assessment, and controlled exploitation
- Post-exploitation analysis and professional security reporting
- Legal and ethical responsibilities of cybersecurity professionals

**Supporting Materials**:
- 📖 **Instructor Guide**: Complete teaching notes, ethical guidelines, and assessment rubrics
- 📋 **Student Worksheet**: Structured activities and reflection questions  
- 🚀 **Quick Reference**: Command cheat sheet and troubleshooting guide

**Key Features**:
- **Manual Methodology**: Hands-on integration of all security analysis tools
- **Ethical Focus**: Strong emphasis on legal and ethical considerations
- **Professional Skills**: Report writing and risk communication training
- **Prerequisites**: Completion of SAST, DAST, Network Analysis, and Sandbox exercises

**⚠️ Advanced Exercise**: This exercise requires instructor supervision and focuses on ethical penetration testing methodology using manual processes rather than automation.

## 🎯 Sample Applications

### 1. **Student Flask Application** (`uploads/`)
- **Purpose**: Your own Flask app for security testing
- **Technology**: Python Flask web framework (customizable)
- **Location**: `uploads/` folder with ready-to-use template
- **Access**: Port 8000 (`http://localhost:8000`)
- **Features**: File browser access, automatic Docker integration
- **Instructions**: [uploads/README.md](uploads/README.md)

### 2. Vulnerable Flask Application
- **Technology**: Python Flask web framework
- **Vulnerabilities**: SQL injection, XSS, weak authentication, debug mode
- **Educational Focus**: Python security, web application vulnerabilities
- **Analysis Results**: ~47 findings (17 high, 26 medium, 4 low severity)

### 3. Unsecure Progressive Web App (PWA)
- **Technology**: Python Flask with PWA features
- **Vulnerabilities**: Open redirects, SQL injection, insecure configurations
- **Educational Focus**: Mobile/PWA security, configuration issues
- **Analysis Results**: ~17 findings (7 high, 9 medium, 1 low severity)

## 🔧 Security Analysis Tools

### Integrated SAST Tools:
- **Bandit**: Python security linter for common vulnerabilities
- **Semgrep**: Pattern-based static analysis for multiple languages
- **Safety**: Python dependency vulnerability scanner

### Integrated DAST Tools:
- **Nikto**: Web vulnerability scanner
- **Gobuster**: Directory/file enumeration
- **Custom Testers**: XSS and SQL injection detection
- **Header Analyzer**: Security header validation

### Integrated Network Analysis Tools:
- **Connection Monitoring**: Real-time network connection tracking
- **Service Discovery**: Port scanning and service identification  
- **Traffic Capture**: Network packet analysis and pattern detection
- **DNS Analysis**: DNS query monitoring and threat detection
- **Protocol Analysis**: TCP/UDP traffic classification

### Command-Line Interfaces:

**Static Analysis (SAST):**
```bash
# Basic analysis
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app

# Educational mode with detailed explanations
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational

# Verbose output for debugging
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --verbose

# JSON output for automation
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --output json
```

**Dynamic Analysis (DAST):**
```bash
# Basic web application scan
 python src/analyzer/dast_cli.py http://localhost:9090

# Quick vulnerability check
 python src/analyzer/dast_cli.py http://localhost:9090 --quick

# Deep scan with educational explanations
 python src/analyzer/dast_cli.py http://localhost:9090 --deep-scan --educational

# Scan all demo applications
python src/analyzer/dast_cli.py --demo-apps --educational
```

**Network Traffic Analysis:**
```bash
# Monitor active connections
python src/analyzer/network_cli.py --monitor-connections --educational

# Discover running services
python src/analyzer/network_cli.py --scan-services localhost --educational

# Capture and analyze traffic
python src/analyzer/network_cli.py --capture-traffic --duration 60 --educational

# DNS traffic analysis
python src/analyzer/network_cli.py --dns-analysis --duration 30 --educational

# Run demo network scenarios
python samples/network-scenarios/basic_network_activity.py
python samples/network-scenarios/suspicious_traffic_generator.py
```

## 🎓 Vulnerability Database

### Comprehensive Educational Content for:
1. **SQL Injection** - Critical severity with library analogy explanations
2. **Cross-Site Scripting (XSS)** - High severity with graffiti analogy
3. **Cross-Site Request Forgery (CSRF)** - Medium severity with signature forgery analogy
4. **Unvalidated Redirects** - Medium severity with tour guide analogy
5. **Broken Authentication** - Critical severity with broken lock analogy
6. **Broken Session Management** - High severity with ticket analogy

### Features:
- Student-friendly explanations with real-world analogies
- OWASP Top 10 2021 mapping and categorization
- Specific remediation guidance with code examples
- Vulnerable vs. secure code comparisons
- Additional learning resources and references

## 📁 Project Structure

```
Docker_Sandbox_Demo/
├── docs/                       # All educational and documentation materials
│   ├── exercises/              # Main exercise files
│   │   ├── static-application-security-testing-exercise.md
│   │   ├── dynamic-application-security-testing-exercise.md
│   │   ├── network-traffic-analysis-exercise.md
│   │   ├── sandbox-security-analysis-exercise.md
│   │   └── penetration-testing-exercise.md
│   ├── instructor-guides/      # Instructor support materials
│   │   ├── sast-instructor-guide.md
│   │   ├── dast-instructor-guide.md
│   │   ├── network-instructor-guide.md
│   │   ├── sandbox-instructor-guide.md
│   │   └── penetration-testing-instructor-guide.md
│   ├── student-worksheets/     # Student worksheet templates
│   │   ├── sast-student-worksheet.md
│   │   ├── dast-student-worksheet.md
│   │   ├── network-student-worksheet.md
│   │   ├── sandbox-student-worksheet.md
│   │   └── penetration-testing-student-worksheet.md
│   ├── student-worksheet-answers/ # Answer keys for worksheets
│   │   ├── sast-answer-sheet.md
│   │   ├── dast-answer-sheet.md
│   │   ├── network-answer-sheet.md
│   │   ├── sandbox-answer-sheet.md
│   │   └── penetration-testing-answer-sheet.md
│   ├── quick-reference-guides/ # Tool quick references
│   │   ├── sast-quick-reference.md
│   │   ├── dast-quick-reference.md
│   │   ├── network-quick-reference.md
│   │   ├── sandbox-quick-reference.md
│   │   └── penetration-testing-quick-reference.md
│   ├── lesson-structure.md     # Course organization and progression
│   └── maintenance-guide.md    # Project maintenance documentation
├── src/analyzer/               # Security analysis implementation
│   ├── static_analyzer.py     # Core SAST analysis engine
│   ├── dynamic_analyzer.py    # Core DAST analysis engine
│   ├── network_analyzer.py    # Core network analysis engine
│   ├── analyze_cli.py         # SAST command-line interface
│   ├── dast_cli.py           # DAST command-line interface
│   ├── network_cli.py        # Network analysis command-line interface
│   └── vulnerability_database.py # Educational vulnerability content
├── samples/                    # Sample applications for analysis and testing
│   ├── vulnerable-flask-app/  # Python Flask with security issues
│   ├── unsecure-pwa/         # Progressive Web App with flaws
│   └── network-scenarios/    # Network traffic generators and scenarios
├── uploads/                   # Upload your Flask app for testing
│   ├── app.py                # Flask application template
│   ├── requirements.txt      # Python dependencies
│   └── README.md            # Upload and testing guide
├── docker/                    # Container configuration
│   ├── Dockerfile            # Sandbox container definition
│   ├── docker-compose.yml    # Service orchestration
│   └── nginx.conf            # Web server configuration
└── README.md                 # This file
```

## 🎯 Learning Outcomes

After completing the exercises, students will be able to:

### Static Analysis (SAST):
- ✅ Explain what Static Application Security Testing is and when to use it
- ✅ Execute automated security analysis using industry-standard tools
- ✅ Interpret SAST tool outputs and prioritize security findings
- ✅ Apply remediation techniques to fix common security vulnerabilities

### Dynamic Analysis (DAST):
- ✅ Explain what Dynamic Application Security Testing is and how it differs from SAST
- ✅ Execute web application vulnerability scans against running applications
- ✅ Interpret DAST tool outputs and identify runtime vulnerabilities
- ✅ Understand HTTP security headers and web application misconfigurations

### Network Traffic Analysis:
- ✅ Explain what network traffic analysis is and how it complements SAST/DAST
- ✅ Monitor network connections and identify suspicious communication patterns
- ✅ Perform service discovery and DNS traffic analysis
- ✅ Distinguish between normal and malicious network behavior
- ✅ Use network monitoring tools for real-time threat detection

### Penetration Testing (Advanced):
- ✅ Understand professional penetration testing methodology and ethical considerations
- ✅ Integrate findings from multiple security analysis tools into comprehensive assessments
- ✅ Conduct systematic reconnaissance, vulnerability assessment, and controlled exploitation
- ✅ Perform post-exploitation analysis and impact assessment
- ✅ Create professional security reports and communicate risk effectively
- ✅ Appreciate legal and ethical responsibilities of cybersecurity professionals

### General Security Skills:
- ✅ Evaluate the security posture of applications using multiple methodologies
- ✅ Create professional security assessment reports
- ✅ Understand the OWASP Top 10 through hands-on experience
- ✅ Plan comprehensive security testing strategies combining multiple methodologies
- ✅ Apply ethical principles to cybersecurity work

## 🚀 Getting Started with the Exercise

1. **Ensure Environment is Ready**:
   ```bash
   # Test the analysis tools
   python src/analyzer/analyze_cli.py --help
   python src/analyzer/dast_cli.py --help  
   python src/analyzer/network_cli.py --help
   ```

2. **Start with the Quick References**:
   - Read `docs/quick-reference-guides/sast-quick-reference.md`
   - Read `docs/quick-reference-guides/dast-quick-reference.md`
   - Read `docs/quick-reference-guides/network-quick-reference.md`
   - Bookmark for easy access during exercises

3. **Choose Your Learning Path**:
   - **Foundation Sequence** (Recommended for beginners):
     1. Start with SAST: `docs/exercises/static-application-security-testing-exercise.md`
     2. Continue with DAST: `docs/exercises/dynamic-application-security-testing-exercise.md`
     3. Add Network Analysis: `docs/exercises/network-traffic-analysis-exercise.md`
     4. Practice Sandbox Analysis: `docs/exercises/sandbox-security-analysis-exercise.md`
   - **Advanced Integration**: Complete Penetration Testing: `docs/exercises/penetration-testing-exercise.md`
   - **Individual Focus**: Choose specific exercises based on interest and skill level

4. **For Instructors**:
   - Review the corresponding instructor guide for your chosen exercise
   - Ensure proper ethical guidelines are established (especially for penetration testing)
   - Prepare demonstration environment and assessment materials

## 🛠️ Technical Requirements

### Codespaces (Recommended):
- GitHub account with Codespaces access
- Modern web browser (Chrome, Firefox, Safari, Edge)
- No additional software installation required

### Local Development:
- Docker and Docker Compose
- Python 3.8+
- Node.js 14+
- Git

### Security Tools (Auto-installed):
- bandit
- safety  
- semgrep
- nikto
- gobuster
- nmap (network analysis)
- netstat, ss (network monitoring)

## 🤝 Contributing

Contributions are welcome! Please see `docs/maintenance-guide.md` for detailed contribution guidelines, coding standards, and project structure information.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OWASP for security frameworks and vulnerability classifications
- Security tool maintainers (Bandit, Semgrep, Safety teams)
- Educational cybersecurity community
- High school educators providing feedback and guidance

## 📞 Support

For questions or issues:
- Create an issue in this repository
- Reference the troubleshooting section in the quick reference guide
- Check the instructor guide for common challenges and solutions

---

**🎓 Empowering the next generation of cybersecurity professionals through hands-on learning!**