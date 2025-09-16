# Docker Sandbox Demo - Maintenance Guide

## 📋 Overview

This maintenance guide provides comprehensive instructions for maintaining, updating, and extending the Docker Sandbox Demo project. It covers folder organization, content style guides, Docker requirements, and repository management standards.

## 📁 Project Structure & Folder Organization

### Root Directory Structure

```
Docker_Sandbox_Demo/
├── .devcontainer/             # GitHub Codespaces configuration
├── .vscode/                   # VS Code workspace settings
├── docker/                    # Docker configuration files
├── docs/                      # Documentation and educational materials
├── reports/                   # Generated security analysis reports
├── samples/                   # Sample vulnerable applications and scenarios
├── src/                       # Source code for analysis tools
├── README.md                  # Main project documentation
├── copilot-instructions.md    # AI assistant configuration
├── demo_tools.sh             # Quick demo script
└── requirements.txt          # Python dependencies
```

### Detailed Folder Purposes

#### `.devcontainer/`
- **Purpose**: GitHub Codespaces and VS Code dev container configuration
- **Contents**: `devcontainer.json` with container settings, extensions, and post-create commands
- **Maintenance**: Update when adding new VS Code extensions or changing container requirements

#### `docker/`
- **Purpose**: Docker container configuration and orchestration
- **Contents**:
  - `Dockerfile` - Main sandbox container definition
  - `docker-compose.yml` - Service orchestration
  - `nginx.conf` - Web server configuration for vulnerable apps
- **Maintenance**: Update when adding new tools, changing security settings, or modifying service architecture

#### `docs/`
- **Purpose**: All educational and documentation materials
- **Structure**:
  ```
  docs/
  ├── exercises/                 # Main exercise files
  │   ├── [topic]-exercise.md    # Primary exercise content
  ├── instructor-guides/         # Instructor support materials
  │   └── [topic]-instructor-guide.md # Teaching guides and answer keys
  ├── student-worksheets/        # Student worksheet templates
  │   └── [topic]-student-worksheet.md # Hands-on activity sheets
  ├── student-worksheet-answers/ # Answer keys for worksheets
  │   └── [topic]-answer-sheet.md # Complete answer keys
  ├── quick-reference-guides/    # Tool quick references
  │   └── [tool]-quick-reference.md # Tool command references
  ├── lesson-plans/              # Structured lesson plans (future)
  ├── lesson-structure.md        # Course organization and progression
  └── maintenance-guide.md       # This document
  ```

#### `reports/`
- **Purpose**: Auto-generated security analysis reports
- **Organization**: Timestamped files (YYYYMMDD_HHMMSS format)
- **Types**: SAST, DAST, Network Analysis reports in JSON/text format
- **Maintenance**: Implement rotation policy for large repositories

#### `samples/`
- **Purpose**: Educational vulnerable applications and test scenarios
- **Structure**:
  ```
  samples/
  ├── README.md                  # Overview of all samples
  ├── vulnerable-flask-app/      # Main educational web application
  ├── unsecure-pwa/             # Progressive Web App with vulnerabilities
  ├── backdoor-apps/            # Malicious application examples
  ├── suspicious-scripts/        # Scripts with security issues
  ├── resource-abuse/           # Resource abuse examples (crypto miners)
  └── network-scenarios/        # Network traffic generators
  ```

#### `src/`
- **Purpose**: Source code for security analysis tools
- **Structure**:
  ```
  src/
  ├── analyzer/                  # Security analysis modules
  │   ├── analyze_cli.py         # SAST command-line interface
  │   ├── dast_cli.py           # DAST command-line interface
  │   ├── network_cli.py        # Network analysis CLI
  │   ├── static_analyzer.py    # SAST implementation
  │   ├── dynamic_analyzer.py   # DAST implementation
  │   ├── network_analyzer.py   # Network analysis implementation
  │   └── vulnerability_database.py # Vulnerability explanations
  └── reporter/                  # Report generation (future)
      ├── report_cli.py         # Report generation CLI
      └── report_generator.py   # Report formatting and output
  ```

## 📝 Content Style Guides

### Documentation Standards

#### Markdown Files
- **File naming**: Use kebab-case (lowercase with hyphens)
- **Headers**: Use sentence case with emojis for main sections
- **Code blocks**: Always specify language for syntax highlighting
- **Links**: Use descriptive text, avoid "click here"
- **Tables**: Include headers and maintain alignment

#### Exercise Content Structure
All exercise files should follow this structure:

```markdown
# [Exercise Title]

## 🎯 Learning Objectives
- Clear, measurable learning outcomes
- 3-5 bullet points maximum

## 📚 What is [Topic]?
### Definition
### Key Characteristics
### Why [Topic] Matters

## 🛠️ Tools We'll Use
- Tool descriptions with purpose and capabilities

## 📋 Prerequisites
- Required knowledge and setup

## 🚀 Exercise Steps
### Step 1: [Action]
### Step 2: [Action]
(etc.)

## 🔍 Understanding the Results
- Result interpretation guidance

## 🛡️ Remediation Techniques
- How to fix identified issues

## 🧠 Knowledge Check
- Comprehension questions

## 📚 Additional Resources
- Further reading and learning materials

## ⚖️ Ethical Considerations
- Responsible use guidelines
```

#### Instructor Guide Structure
```markdown
# [Topic] - Instructor Guide

## 📋 Overview
## ⏱️ Time Requirements
## 🎯 Learning Objectives
## 📚 Prerequisites
## 🔧 Setup Instructions
## 📖 Lesson Plan
## 💡 Teaching Tips
## ✅ Answer Key
## 🎯 Assessment Rubric
## 🔄 Troubleshooting
## 📚 Extension Activities
```

#### Student Worksheet Structure
```markdown
# [Topic] - Student Worksheet

## 👤 Student Information
## 🎯 Exercise Overview
## 📝 Pre-Exercise Questions
## 🚀 Hands-on Activities
## 📊 Results Recording
## 🧠 Analysis Questions
## 🔍 Reflection Questions
## 📚 Extension Challenges
```

#### Quick Reference Guide Structure
```markdown
# [Tool] - Quick Reference Guide

## 🔧 Tool Overview
## 📋 Common Commands
## 📊 Output Interpretation
## 🛠️ Advanced Options
## 🔄 Troubleshooting
## 📚 Further Reading
```

### Code Style Guidelines

#### Python Code Standards
- **PEP 8 compliance**: Use standard Python formatting
- **Docstrings**: All functions and classes must have descriptive docstrings
- **Type hints**: Use where beneficial for clarity
- **Error handling**: Comprehensive exception handling with educational messages
- **Comments**: Explain security concepts and educational points
- **Educational focus**: Prioritize clarity over performance optimization

Example:
```python
def analyze_sql_injection(code_content: str) -> List[Finding]:
    """
    Analyze code for SQL injection vulnerabilities.
    
    This function demonstrates how SAST tools detect SQL injection
    by looking for common anti-patterns in database queries.
    
    Args:
        code_content: The source code to analyze
        
    Returns:
        List of security findings with educational explanations
    """
    findings = []
    # Educational comment: SQL injection occurs when user input
    # is directly concatenated into SQL queries
    ...
```

#### Shell Script Standards
- **Shebang**: Always include `#!/bin/bash` or `#!/bin/zsh`
- **Error handling**: Use `set -e` for fail-fast behavior
- **Comments**: Explain each major section
- **Variables**: Use descriptive names and quote appropriately

### Sample Application Guidelines

#### Vulnerability Implementation
- **Educational clarity**: Vulnerabilities should be obvious and well-commented
- **Real-world relevance**: Based on actual security issues
- **Appropriate scope**: Suitable for high school education level
- **Safety**: No actual malicious behavior in Codespaces environment

#### Application Structure
- **README files**: Each sample app needs a README explaining vulnerabilities
- **Requirements files**: Clearly list all dependencies
- **Documentation**: Comment vulnerable code sections with educational notes

## 🐳 Docker Requirements & Standards

### Container Requirements

#### Base Image Standards
- **Official images**: Use Microsoft dev container images when possible
- **Security updates**: Regularly update base images
- **Minimal footprint**: Only install necessary tools and dependencies
- **Multi-stage builds**: Use when beneficial for image size

#### Security Configuration
```yaml
# Required security settings for educational containers
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
cap_add:
  - NET_RAW      # Required for nmap
  - NET_ADMIN    # Required for network analysis
# Resource limits for Codespaces compatibility
mem_limit: 1g
cpus: 0.8
```

#### Tool Installation Standards
- **Package managers**: Prefer official package managers (apt, pip, npm)
- **Version pinning**: Pin versions for reproducibility
- **Cleanup**: Remove package caches and temporary files
- **Documentation**: Comment tool purposes in Dockerfile

### Docker Compose Requirements

#### Service Naming
- **Descriptive names**: Use clear, educational service names
- **Consistent prefixes**: Use project-specific prefixes
- **Network isolation**: Implement appropriate network segmentation

#### Volume Management
- **Persistent data**: Use named volumes for reports and logs
- **Development mounts**: Cache workspace mounts for performance
- **Security**: Read-only mounts where appropriate

#### Environment Variables
```yaml
environment:
  - PYTHONPATH=/workspace/src
  - SANDBOX_MODE=educational
  - FLASK_ENV=development
  - FLASK_DEBUG=1
```

### Codespaces Optimization

#### Performance Considerations
- **Memory limits**: Keep containers under 1GB RAM usage
- **CPU limits**: Limit CPU usage to 0.8 cores
- **Image size**: Minimize container image sizes
- **Startup time**: Optimize for fast container startup

#### Development Experience
- **Port forwarding**: Expose necessary ports (8080, 9090, etc.)
- **Volume caching**: Use `:cached` for workspace mounts
- **Tool accessibility**: Make all tools available in PATH

## 📦 Repository Management

### Branch Strategy
- **Main branch**: Stable, production-ready code
- **Feature branches**: Use descriptive names (feature/new-exercise)
- **Release branches**: For major version releases
- **Hotfix branches**: For critical security fixes

### Commit Standards
- **Conventional commits**: Use conventional commit format
- **Educational focus**: Mention educational impact in commits
- **Security relevance**: Highlight security-related changes

Examples:
```
feat(exercises): add network analysis exercise for DNS threats
fix(docker): update container security settings for Codespaces
docs(guides): improve SAST exercise instructor guide
security(samples): fix overly permissive vulnerable app configuration
```

### Version Management
- **Semantic versioning**: Use SemVer (X.Y.Z)
- **Release notes**: Document changes and educational improvements
- **Compatibility**: Maintain backward compatibility for exercises

### Security Requirements
- **No real secrets**: Never commit actual credentials or keys
- **Safe examples**: All example vulnerabilities must be safe for educational use
- **Container isolation**: Maintain proper container security boundaries
- **Regular updates**: Keep security tools and dependencies current

## 🔄 Maintenance Tasks

### Regular Updates (Monthly)
- [ ] Update base Docker images
- [ ] Update Python dependencies in requirements.txt
- [ ] Update security tool versions
- [ ] Review and rotate generated reports
- [ ] Test all exercise paths in Codespaces
- [ ] Update vulnerability database entries

### Content Reviews (Per Semester)
- [ ] Review exercise content for curriculum alignment
- [ ] Update sample applications for current threat landscape
- [ ] Review and update quick reference guides
- [ ] Validate all instructor guides and answer keys
- [ ] Test with actual student groups for feedback

### Security Audits (Quarterly)
- [ ] Review container security configurations
- [ ] Audit sample application vulnerabilities
- [ ] Test isolation boundaries in Codespaces
- [ ] Review network security settings
- [ ] Update threat scenarios for current landscape

## 🚨 Emergency Procedures

### Security Issues
1. **Immediate isolation**: Stop affected containers
2. **Assessment**: Determine scope and impact
3. **Communication**: Notify maintainers and users
4. **Remediation**: Apply fixes and test thoroughly
5. **Documentation**: Document incident and lessons learned

### Container Failures
1. **Diagnosis**: Check logs and resource usage
2. **Recovery**: Restart services or rebuild containers
3. **Prevention**: Identify and fix root causes
4. **Monitoring**: Implement better health checks

## 📞 Support and Contact

### Maintainer Responsibilities
- **Code reviews**: Review all pull requests for educational value
- **Issue triage**: Prioritize issues based on educational impact
- **Documentation**: Keep all guides current and accurate
- **Community**: Respond to user questions and feedback

### Contributing Guidelines
- **Educational focus**: All contributions must enhance learning outcomes
- **Code quality**: Follow established style guides and standards
- **Testing**: Test all changes in Codespaces environment
- **Documentation**: Update relevant documentation with changes

---

## 📚 Additional Resources

- [Docker Best Practices](https://docs.docker.com/develop/best-practices/)
- [GitHub Codespaces Documentation](https://docs.github.com/en/codespaces)
- [Python Security Best Practices](https://python.org/dev/security/)
- [OWASP Educational Resources](https://owasp.org/www-project-webgoat/)

---

*Last Updated: September 15, 2025*  
*Version: 1.0*  
*Maintainer: TempeHS Docker Sandbox Demo Team*