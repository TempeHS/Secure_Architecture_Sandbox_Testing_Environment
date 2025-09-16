# Docker Sandbox Demo - Maintenance Guide

## 📋 Overview

This maintenance guide provides comprehensive instructions for maintaining, updating, and extending the Docker Sandbox Demo project. It covers folder organization, content style guides, Docker requirements, and repository management standards.

## 📁 Repository Management

### Git LFS (Large File Storage)
- **Purpose**: Manages large binary files (DOCX, PDF, images) outside main Git repository
- **Configuration**: `.gitattributes` file defines which file types use LFS
- **Tracked file types**:
  - Microsoft Office documents (*.docx, *.xlsx, *.pptx)
  - PDF files (*.pdf)
  - Images (*.png, *.jpg, *.jpeg, *.gif)
  - Archive files (*.zip, *.tar.gz)
  - Database files (*.db, *.sqlite, *.sqlite3)
  - Binary executables and large logs
- **Automatic setup**: Devcontainer post-create script installs and initializes Git LFS
- **Usage**: Files matching LFS patterns are automatically tracked
- **Commands**:
  - `git lfs track` - List tracked file patterns
  - `git lfs ls-files` - List files currently in LFS
  - `git lfs pull` - Download LFS files after clone

### Branch Strategy
- **Main branch**: Stable, production-ready code
- **Feature branches**: Use descriptive names (feature/new-exercise)
- **Release branches**: For major version releases
- **Hotfix branches**: For critical security fixest Structure & Folder Organization

### Root Directory Structure

```
Docker_Sandbox_Demo/
├── .devcontainer/             # GitHub Codespaces configuration
├── .vscode/                   # VS Code workspace settings
├── .gitattributes            # Git LFS file tracking configuration
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
- **Features**: Automatic Git LFS installation and initialization for handling large files
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

## � Internal Development Tools

### Worksheet Conversion Utilities

The project includes conversion utilities in `src/tools/` for internal maintenance tasks:

#### CloudConvert Converter (`cloudconvert_converter.py`)
- **Purpose**: Convert Markdown worksheets to high-quality DOCX format for distribution
- **Usage**: Internal tool for maintainers only - not for student/instructor use
- **Requirements**: CloudConvert API key (configured via environment variable)
- **Quality**: Produces professional-grade DOCX files with proper formatting
- **Commands**:
  ```bash
  # Convert all worksheets (internal use only)
  python src/tools/cloudconvert_converter.py --all
  
  # Convert single worksheet
  python src/tools/cloudconvert_converter.py --file sast-student-worksheet.md
  
  # Check account status
  python src/tools/cloudconvert_converter.py --account-info
  ```

#### Local Converter (`worksheet_converter.py`)
- **Purpose**: Offline conversion for development and testing
- **Usage**: Quick conversions during development
- **Requirements**: No external dependencies beyond python-docx
- **Quality**: Basic formatting suitable for development
- **Commands**:
  ```bash
  # Convert all worksheets locally
  python src/tools/worksheet_converter.py --all
  ```

**Note**: These tools are for maintainer use only. Students and instructors should use the pre-converted DOCX files provided in the repository.

## �🔄 Maintenance Tasks

### Regular Updates (Monthly)
- [ ] Update base Docker images
- [ ] Update Python dependencies in requirements.txt
- [ ] Update security tool versions
- [ ] Review and rotate generated reports
- [ ] Test all exercise paths in Codespaces
- [ ] Update vulnerability database entries
- [ ] Verify Git LFS tracking and clean up old files
- [ ] **Run complete test suite (76 tests across 5 modules) to ensure functionality**
- [ ] **Check for missing Python imports in analyzer modules (tempfile, etc.)**
- [ ] **Validate educational mode implementations across all CLI tools**

### Content Reviews (Per Semester)
- [ ] Review exercise content for curriculum alignment
- [ ] Update sample applications for current threat landscape
- [ ] Review and update quick reference guides
- [ ] Validate all instructor guides and answer keys
- [ ] Test with actual student groups for feedback
- [ ] **Verify all test modules pass with current codebase changes**
- [ ] **Update test expectations when module functionality changes**
- [ ] **Ensure JSON output formats match test expectations**

### Security Audits (Quarterly)
- [ ] Review container security configurations
- [ ] Audit sample application vulnerabilities
- [ ] Test isolation boundaries in Codespaces
- [ ] Review network security settings
- [ ] Update threat scenarios for current landscape
- [ ] **Validate Docker API compatibility with current Docker version**
- [ ] **Test shell command execution patterns in containers**
- [ ] **Verify educational mode security explanations are current**

## � Common Maintenance Issues & Solutions

### Import Dependencies

**Issue**: Missing Python imports causing runtime failures
**Example**: `tempfile` import missing in `dynamic_analyzer.py` causing Gobuster to fail
**Detection**: Run complete test suite regularly to catch import errors
**Solution**: 
```python
# Always verify imports at the top of modules
import tempfile  # Required for Gobuster functionality
import os
import json
# ... other imports
```

### Educational Mode Implementation

**Issue**: Inconsistent educational mode across different CLI tools
**Detection**: Test with `--educational` flag on all tools
**Solution**: Ensure all CLI tools properly implement and display educational insights
```python
# Standard educational insight pattern
if args.educational:
    print("🎓 EDUCATIONAL INSIGHTS")
    print("Detailed explanation of the security concept...")
```

### JSON Output Consistency

**Issue**: Test expectations not matching actual JSON output structure
**Example**: Tests expecting "connections" key when actual output uses "active_connections"
**Detection**: Compare test expectations with actual CLI output
**Solution**: Update tests to match implementation or vice versa

### Docker API Compatibility

**Issue**: Docker API changes affecting container command execution
**Current Solution**: Use `["sh", "-c", command]` pattern for shell commands
```python
# Correct pattern for Docker API 7.1.0+
container.exec_run(["sh", "-c", "complex shell command with | pipes"])

# Instead of:
container.exec_run("complex shell command with | pipes")  # May fail
```

### Testing Framework Maintenance

**Current Status**: 76 tests across 5 modules (SAST: 12, DAST: 15, Network: 20, Sandbox: 15, Penetration: 14)
**Best Practice**: Run full test suite before any major changes
**Command**: `python -m pytest tests/test_*.py -v`

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
- **Testing**: Test all changes in Codespaces environment and run full test suite
- **Documentation**: Update relevant documentation with changes
- **Import validation**: Ensure all Python imports are properly included
- **Educational mode**: Implement consistent educational explanations across tools
- **JSON compatibility**: Maintain consistent output formats and update tests accordingly

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