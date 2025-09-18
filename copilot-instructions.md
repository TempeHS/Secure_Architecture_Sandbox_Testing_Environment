# Copilot Instructions for Docker Sandbox Demo Project

## Project Overview

This repository contains a Docker-based sandbox environment for demonstrating basic cybersecurity testing concepts to high school students. The system will allow students to analyze applications in an isolated environment and generate simple security reports.

## Development Instructions

### 1. Project Structure Setup

```
Docker_Sandbox_Demo/
├── .devcontainer/             # Codespaces configuration
│   └── devcontainer.json      
├── docker/                    # Docker configuration
│   ├── Dockerfile             # Main sandbox container
│   └── docker-compose.yml     # Service orchestration
├── src/                       # Source code
│   ├── sandbox/               # Sandbox implementation
│   ├── analyzer/              # Security analysis tools
│   └── reporter/              # Report generation
├── samples/                   # Sample vulnerable applications
│   ├── web-app/               # Basic vulnerable web app
│   └── scripts/               # Sample vulnerable scripts
├── docs/                      # Documentation
│   ├── setup.md               # Setup instructions
│   ├── usage.md               # How to use the sandbox
│   ├── lesson-plans/          # Example lesson plans
│   └── exercises/             # Student exercises
└── README.md                  # Project overview
```

### 2. Docker Container Setup

- Create a Dockerfile that:
  - Uses a base Ubuntu image
  - Installs necessary security tools (OWASP ZAP, Nikto, etc.)
  - Configures a controlled environment
  - Installs required dependencies (Python, Node.js)
  - Sets appropriate permissions and security boundaries

- Create a docker-compose.yml to manage:
  - The sandbox container
  - Any supporting services (database, web server)
  - Network isolation
  - Volume mounting for persistent data

### 3. Sandbox Implementation

- Develop Python scripts to:
  - Launch applications within the sandbox
  - Monitor system calls and network activity
  - Detect potential malicious behavior
  - Enforce resource limitations
  - Log all activities for review

### 4. Security Analysis Components

- Implement basic security testing tools:
  - Static code analysis (for detecting obvious vulnerabilities)
  - Network traffic monitoring
  - Input validation testing
  - Basic fuzzing capabilities
  - Configuration analysis

- Focus on educational aspects with clear output rather than comprehensive detection

### 5. Report Generation

- Create a reporting module that:
  - Summarizes detected issues
  - Categorizes findings by severity
  - Provides explanations suitable for high school students
  - Includes remediation suggestions
  - Generates HTML or PDF reports

### 6. Sample Applications

- Develop or adapt deliberately vulnerable applications:
  - A simple web application with common OWASP Top 10 issues
  - Basic scripts with security flaws
  - Ensure vulnerabilities are obvious and educational

### 7. Documentation

- Create comprehensive documentation in the /docs folder:
  - Setup instructions for instructors
  - User guides for students
  - Explanation of security concepts
  - Sample lesson plans
  - Exercise worksheets

### 8. Testing

- Test all components thoroughly:
  - Ensure sandbox containment works properly
  - Verify analysis tools detect expected vulnerabilities
  - Confirm reports generate correctly
  - Test on Codespaces environment

## Educational Considerations

- Keep content appropriate for high school students
- Focus on foundational security concepts
- Provide clear explanations of vulnerabilities and risks
- Include guided exercises with increasing difficulty levels
- Ensure ethical considerations are addressed

## Limitations and Scope

- This is an educational tool, not a production-grade sandbox
- Security containment has practical limitations in a Codespaces environment
- Analysis capabilities are intentionally basic to focus on learning
- Sample applications demonstrate concepts but aren't comprehensive
- Reports are simplified for educational purposes

## Implementation Notes

- Use Python for most implementation (accessible to students)
- Leverage existing open-source tools where possible
- Keep UI simple and focused on learning outcomes
- Ensure all code is well-commented for educational purposes
- Consider performance constraints of Codespaces

## Deliverables Checklist

- [x] Functional Docker container with security tools
- [x] Sandbox implementation with basic isolation
- [x] At least 3 analysis modules (static, dynamic, network)
- [ ] Report generation with educational explanations
- [x] 2-3 sample vulnerable applications
- [x] Complete documentation for setup and usage
- [ ] Lesson plans and exercises for classroom use

## Current Status

✅ **PHASE 1 COMPLETE**: Docker Container Setup
- Lightweight Docker container optimized for Codespaces
- Security tools installed: nmap, nikto, gobuster, dirb
- Python security packages: bandit, safety, semgrep, flask
- Complete .devcontainer configuration
- Multi-service docker-compose setup
- Sample vulnerable web application
- Automated testing and verification

✅ **PHASE 2 COMPLETE**: Analysis Modules
- **Static Analysis (SAST)**: Comprehensive Python security analysis with Bandit, Safety, Semgrep
- **Dynamic Analysis (DAST)**: Web application runtime testing with custom XSS/SQLi detection
- **Network Traffic Analysis**: Real-time network monitoring, service discovery, DNS analysis, and threat detection
- **Sandbox Analysis**: Behavioral monitoring for malicious applications using system calls and resource tracking
- Educational vulnerability database with 6 vulnerability types and explanations
- Separate CLI tools for SAST (`analyze_cli.py`), DAST (`dast_cli.py`), and Network (`network_cli.py`) for student clarity
- Automatic report organization in `reports/` directory with timestamped JSON/text outputs
- Integration with external tools (nikto, gobuster, nmap) for comprehensive coverage

✅ **PHASE 3 COMPLETE**: Educational Materials
- **SAST Exercise Package**: Main exercise, instructor guide, student worksheet, quick reference
- **DAST Exercise Package**: Main exercise, instructor guide, student worksheet, quick reference  
- **Network Analysis Exercise Package**: Main exercise, instructor guide, student worksheet, quick reference
- **Sandbox Analysis Exercise Package**: Main exercise, instructor guide, student worksheet, quick reference
- **Penetration Testing Exercise Package**: Advanced manual methodology exercise integrating all tools
- **Sample Applications**: 5 vulnerable applications including Flask app, PWA, suspicious scripts, backdoors, and crypto miners
- **Sample Network Scenarios**: 4 network traffic generators including basic activity, suspicious patterns, backdoor communication, and DNS threats
- All exercises structured for 3-4 hour classroom sessions with hands-on learning (penetration testing: 4-5 hours)
- Complete instructor guides with setup instructions, answer keys, and assessment rubrics
- Student worksheets with guided activities and reflection questions
- Strong ethical guidelines and legal considerations for penetration testing exercise

## Quick Start Guide

1. **Open in Codespaces**: Repository is ready for GitHub Codespaces
2. **Start containers**: `cd docker && docker-compose up -d`
3. **Access tools**: `docker exec -it cybersec_sandbox bash`
4. **Test web app**: Visit http://localhost:9090
5. **Run demo**: `./demo_tools.sh`
6. **For Penetration Testing**: Requires instructor supervision and completion of foundation exercises first

## Available Tools

### Security Analysis Tools
- **nmap**: Network scanning and service detection
- **nikto**: Web vulnerability scanner  
- **gobuster**: Directory/file enumeration
- **dirb**: Web content scanner
- **bandit**: Python code security analysis
- **safety**: Python dependency vulnerability scanner
- **semgrep**: Static analysis tool

### Development Environment
- **Python 3.11**: Main development language
- **Flask**: Web framework for applications
- **Docker**: Containerization platform
- **VS Code**: Fully configured with extensions

### Sample Applications
- **Vulnerable Web App**: Educational demonstration app with XSS, SQL injection simulations
- **Port 9090**: Accessible vulnerable application for testing

### Sample Network Scenarios
- **Basic Network Activity**: Normal web browsing and DNS queries for baseline comparison
- **Suspicious Traffic Generator**: Port scanning, backdoor connections, and automated patterns  
- **Backdoor Communication**: C&C beacons, data exfiltration, and persistence checks
- **DNS Threat Scenarios**: DNS tunneling, DGA patterns, and malicious domain queries

## Next Development Phases

### Phase 2: Analysis Modules 
- [x] **Static code analysis module** ✅ **COMPLETE**
- [x] **Dynamic application testing module** ✅ **COMPLETE**  
- [x] **Network traffic analysis module** ✅ **COMPLETE**

### Phase 3: Report Generation (TODO)
- [ ] Automated report generation
- [ ] Educational explanations
- [ ] PDF/HTML output formats

### Phase 4: Educational Content
- [x] **Lesson plans for instructors** ✅ **COMPLETE**
- [x] **Student exercises and worksheets** ✅ **COMPLETE**
- [x] **Assessment rubrics** ✅ **COMPLETE**
- [x] **Penetration testing manual methodology** ✅ **COMPLETE**

## Dependencies and Requirements

- Docker and Docker Compose
- Python 3.8+
- Basic security tools (OWASP ZAP, Nikto, etc.)
- GitHub Codespaces compatibility
- PDF generation library (for reports)

---

## 📚 Educational Syllabus Reference

This project aligns with comprehensive cybersecurity curriculum outcomes. All content, language, and concepts should reference and support these learning objectives:

### **Secure Software Architecture**

#### Designing Software
- **Describe the benefits of developing secure software** including:
  - Data protection principles and implementation
  - Minimizing cyber attacks and vulnerabilities through design
  - Cost-effective security from inception vs. retrofitting

#### Software Development Lifecycle Security
- **Interpret and apply fundamental software development steps to develop secure code** including:
  - Requirements definition with security considerations
  - Determining specifications with threat modeling
  - Design with security architecture principles
  - Development using secure coding practices
  - Integration with security testing and validation
  - Testing and debugging with security focus
  - Installation with secure deployment practices
  - Maintenance with ongoing security monitoring

#### User-Centered Security Design
- **Describe how capabilities and experience of end users influence secure design features** including:
  - Usability vs. security balance
  - User education and awareness requirements
  - Accessibility considerations in security design

### **Developing Secure Code**

#### Fundamental Security Concepts
- **Explore fundamental software design security concepts** including:
  - **Confidentiality**: Data protection and access control
  - **Integrity**: Data accuracy and tamper detection
  - **Availability**: System reliability and resilience
  - **Authentication**: Identity verification and validation
  - **Authorization**: Access control and privilege management
  - **Accountability**: Audit trails and non-repudiation

#### Security Features Implementation
- **Apply security features incorporated into software** including:
  - Data protection mechanisms and encryption
  - Security controls and access management
  - Privacy protection and data minimization
  - Regulatory compliance (GDPR, CCPA, industry standards)

#### Security by Design Approaches
- **Use and explain cryptography contribution to 'security by design'** including:
  - Symmetric and asymmetric encryption implementation
  - Digital signatures and certificate management
  - Key management and secure storage
  - Cryptographic protocol selection and implementation

- **Use and explain sandboxing contribution to 'security by design'** including:
  - Application isolation and containment
  - Resource limitation and monitoring
  - Behavioral analysis and threat detection
  - Safe execution environments for untrusted code

#### Privacy by Design Implementation
- **Use and explain 'privacy by design' approach** including:
  - **Proactive not reactive approach**: Anticipating privacy risks
  - **Embed privacy into design**: Built-in privacy protection
  - **Respect for user privacy**: User-centric privacy controls
  - Data minimization and purpose limitation
  - Transparency and user control mechanisms

### **Security Testing and Evaluation**

#### Comprehensive Security Assessment
- **Test and evaluate security and resilience of software** including:
  - **Determining vulnerabilities**: Systematic vulnerability assessment
  - **Hardening systems**: Security configuration and controls
  - **Handling breaches**: Incident response and containment
  - **Maintaining business continuity**: Operational resilience
  - **Conducting disaster recovery**: Recovery planning and testing

#### Security Management Strategies
- **Apply and evaluate strategies used by software developers** including:
  - **Code review**: Manual security code inspection
  - **Static Application Security Testing (SAST)**: Source code analysis
  - **Dynamic Application Security Testing (DAST)**: Runtime testing
  - **Vulnerability assessment**: Systematic security evaluation
  - **Penetration testing**: Ethical hacking and exploitation testing

### **Secure Implementation Practices**

#### Defensive Programming
- **Design, develop and implement code using defensive data input handling** including:
  - **Input validation**: Data format and range verification
  - **Sanitization**: Data cleaning and encoding
  - **Error handling**: Secure error processing and logging

#### API Security
- **Design, develop and implement safe Application Programming Interface (API)** including:
  - Authentication and authorization mechanisms
  - Input validation and output encoding
  - Rate limiting and throttling
  - Secure communication protocols

#### Performance and Security Integration
- **Design, develop and implement code considering efficient execution** including:
  - **Memory management**: Buffer overflow prevention and secure allocation
  - **Session management**: Secure session handling and timeout
  - **Exception management**: Secure error handling and information disclosure prevention

#### User Action Security Controls
- **Design, develop and implement secure code to minimize user action vulnerabilities** including:
  - **Broken authentication and session management**: Secure login and session handling
  - **Cross-site scripting (XSS)**: Input/output validation and encoding
  - **Cross-site request forgery (CSRF)**: Token-based protection
  - **Invalid forwarding and redirecting**: URL validation and whitelisting
  - **Race conditions**: Synchronization and atomic operations

#### File and Hardware Security
- **Design, develop and implement secure code to protect against file and hardware attacks** including:
  - **File attacks**: Path traversal, file inclusion, and upload security
  - **Side channel attacks**: Timing attacks, cache attacks, and information leakage prevention

### **Impact of Safe and Secure Software Development**

#### Collaborative Security Development
- **Apply and describe benefits of collaboration** including:
  - **Considering various points of view**: Diverse security perspectives
  - **Delegating tasks based on expertise**: Security specialization
  - **Quality of the solution**: Collective security knowledge

#### Enterprise Benefits
- **Investigate and explain benefits of safe and secure development practices** including:
  - **Improved products or services**: Enhanced security features and reliability
  - **Influence on future software development**: Security culture and practices
  - **Improved work practices**: Security-aware development processes
  - **Productivity**: Reduced security incidents and rework
  - **Business interactivity**: Secure digital transformation and integration

#### Social, Ethical, and Legal Considerations
- **Evaluate social, ethical and legal issues and ramifications** including:
  - **Employment**: Cybersecurity workforce development and responsibilities
  - **Data security**: Protection of personal and sensitive information
  - **Privacy**: Individual rights and organizational obligations
  - **Copyright**: Intellectual property protection in software development
  - **Intellectual property**: Software licensing and attribution
  - **Digital disruption**: Technology impact on society and industry

### **Content Alignment Guidelines**

When developing educational materials, exercises, and assessments:

1. **Language and Terminology**: Use industry-standard cybersecurity terminology that aligns with these syllabus points
2. **Concept Coverage**: Ensure each exercise addresses relevant syllabus outcomes
3. **Assessment Alignment**: Design assessments that evaluate student achievement of these specific learning objectives
4. **Progressive Learning**: Structure content to build from fundamental concepts to advanced integration
5. **Real-world Application**: Connect theoretical concepts to practical industry scenarios and tools

This syllabus serves as the foundation for all educational content development and ensures graduates are prepared for cybersecurity careers with comprehensive knowledge of secure software development principles and practices.