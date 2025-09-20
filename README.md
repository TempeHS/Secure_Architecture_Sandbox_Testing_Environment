# Secure Architecture Sandbox Testing Environment

## 🎯 Overview

This repository contains a comprehensive Docker-based sandbox environment for
teaching secure architecture concepts to high school students. The platform provides
hands-on experience with security analysis, vulnerability detection, and
remediation techniques using real applications in a safe, controlled
environment.

## Sandbox Architecture

This sandbox uses a **multi-layer isolation and containerized architecture** using Codespaces and Docker that mirrors real-world cybersecurity practices.

![Docker/CodesSpaces Topology](/docs/images/secure_architecture_sandbox_network_topology.png)

## 🚀 Quick Start

**GitHub Codespaces (Recommended):**
1. Click "Code" → "Create codespace on main"
2. Wait 2-3 minutes for setup completion
3. See [docs/setup-guide.md](docs/setup-guide.md) for details

**Test Your Own Flask App:**
```bash
cd uploads/
# Deploy and test your app (see uploads/README.md)
python3 src/analyser/analyse_cli.py uploads/ --tools all --educational --output detailed_sast_upload.pdf --format pdf --verbose
python3 src/analyser/dast_cli.py http://localhost:8000 --deep-scan --educational --output detailed_dast_upload.pdf --format pdf --verbose
```

## 🤖 AI Learning Assistant

Use `@workspace` in GitHub Copilot Chat for help:
- **Students**: "I'm stuck on the SAST exercise" or "How do I run a DAST scan?"
- **Teachers**: "Where's the answer key for network analysis?" or "What's the learning sequence?"

Built-in knowledge of the NESA Software Engineering Syllabus and safety features ensure ethical learning with instructor oversight.

## 📊 Security Analysis & Reports

**Automated Report Generation:**
```bash
# All tools support --educational mode with timestamped reports
python src/analyser/analyse_cli.py <target> --tools all --educational --output detailed_sast_report.pdf --format pdf --verbose          # SAST
python src/analyser/dast_cli.py <url> --deep-scan --educational --output detailed_dast_report.pdf --format pdf --verbose               # DAST  
python src/analyser/network_cli.py --monitor-connections --educational --duration 300 --output detailed_network_report.pdf --format pdf --verbose  # Network
python src/analyser/penetration_analyser.py localhost:5000 --deep --exploit --output comprehensive_security_report.pdf       # Penetration Testing
```

Reports auto-save to `reports/` with timestamps. Manual output: `--output reports/my_report.json`

## 📚 Educational Exercises

**Recommended Learning Sequence:**

1. **Manual Code Review** - Security-focused code analysis fundamentals
2. **SAST (Static Analysis)** - Automated vulnerability scanning in code
3. **DAST (Dynamic Analysis)** - Runtime web application testing  
4. **Network Traffic Analysis** - Monitor communications and detect threats
5. **Sandbox Analysis** - Safe execution of suspicious applications
6. **Penetration Testing** - Comprehensive security assessment (Advanced)

**All exercises include:** Instructor guides, student worksheets, answer keys, and quick reference commands.

**Exercise Locations:** `docs/exercises/` | **Supporting Materials:** `docs/instructor-guides/`, `docs/student-worksheets/`, `docs/quick-reference-guides/`

## 🎯 Sample Applications

1. **Student Upload Area** (`uploads/`) - Deploy your own Flask app for testing (Port 8000)
2. **Vulnerable Flask App** - Python web app with SQL injection, XSS, weak auth (47 vulnerabilities)
3. **Unsecure PWA** - Progressive web app with open redirects, misconfigurations (17 vulnerabilities)

See [uploads/README.md](uploads/README.md) for deployment instructions.

## 🔧 Security Analysis Tools

**Integrated Tools:**
- **SAST**: Bandit, Semgrep, Safety (Python security analysis)
- **DAST**: Nikto, Gobuster (Web vulnerability scanning)  
- **Network**: nmap, netstat (Traffic monitoring & service discovery)
- **Penetration Testing**: Automated vulnerability discovery with dictionary attacks

**Quick Commands:**
```bash
# Static Analysis
python src/analyser/analyse_cli.py <target> --tools all --educational --output detailed_sast_report.pdf --format pdf --verbose

# Dynamic Analysis  
python src/analyser/dast_cli.py <url> --deep-scan --educational --output detailed_dast_report.pdf --format pdf --verbose

# Network Analysis
python src/analyser/network_cli.py --monitor-connections --educational --duration 300 --output detailed_network_report.pdf --format pdf --verbose

# Penetration Testing
python src/analyser/penetration_analyser.py <host:port> --deep --exploit --output detailed_pentest_report.pdf
```

## 🎓 Learning Features

**Educational Content:** Student-friendly vulnerability explanations with real-world analogies, OWASP Top 10 mapping, and code examples.

**Key Vulnerabilities Covered:** SQL Injection, XSS, CSRF, Authentication flaws, Session management, Unvalidated redirects.

## 📁 Project Structure

```
├── docs/                    # Educational materials (exercises, guides, worksheets)
├── src/analyser/           # Security analysis tools (SAST, DAST, Network, Penetration)  
├── samples/                # Vulnerable applications for testing
├── uploads/                # Deploy your own Flask app
├── docker/                 # Container configuration
└── reports/                # Generated security reports
```

## 🎯 Learning Outcomes

Students will master:
- **SAST/DAST**: Automated vulnerability detection and remediation
- **Network Analysis**: Traffic monitoring and threat detection  
- **Penetration Testing**: Professional security assessment methodology
- **Ethical Security**: Legal responsibilities and professional standards
- **Report Writing**: Professional security communication and risk assessment

## 🚀 Getting Started

1. **Verify Tools**: `python src/analyser/analyse_cli.py --help`
2. **Read Quick References**: `docs/quick-reference-guides/`  
3. **Choose Learning Path**:
   - **Foundation**: SAST → DAST → Network → Sandbox → Penetration Testing
   - **Individual Focus**: Pick specific exercises based on interest
4. **For Instructors**: Review corresponding instructor guides and establish ethical guidelines

## 🛠️ Requirements

**Codespaces (Recommended):** GitHub account + web browser  
**Local:** Docker, Python 3.8+, Node.js 14+

All security tools auto-install in the environment.

## 📞 Support & Contributing

- **Issues**: [Create repository issues](https://github.com/TempeHS/Secure_Architecture_Sandbox_Testing_Environment/issues)
- **Contributing**: Raise a pull request or issue.  
- **Licence**: Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International
---

<p xmlns:cc="http://creativecommons.org/ns#" xmlns:dct="http://purl.org/dc/terms/"><a property="dct:title" rel="cc:attributionURL" href="https://github.com/TempeHS/Secure_Architecture_Sandbox_Testing_Environment">Secure Architecture Testing Environment</a> by <a rel="cc:attributionURL dct:creator" property="cc:attributionName" href="https://github.com/benpaddlejones">Ben Jones</a> is licenced under <a href="https://creativecommons.org/licences/by-nc-sa/4.0/?ref=chooser-v1" target="_blank" rel="licence noopener noreferrer" style="display:inline-block;">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International<img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/cc.svg?ref=chooser-v1" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/by.svg?ref=chooser-v1" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/nc.svg?ref=chooser-v1" alt=""><img style="height:22px!important;margin-left:3px;vertical-align:text-bottom;" src="https://mirrors.creativecommons.org/presskit/icons/sa.svg?ref=chooser-v1" alt=""></a></p>

