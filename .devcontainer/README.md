# DevContainer Testing Scripts

This folder contains the testing and verification scripts for the Cybersecurity Sandbox environment.

## Scripts Overview

### 1. `test_environment.py`
**Comprehensive Environment Testing**
- Tests all security tools installation
- Verifies Python packages availability
- Checks directory structure
- Validates file permissions
- Provides detailed colored output
- Most thorough testing option

**Usage:**
```bash
python3 .devcontainer/test_environment.py
```

### 2. `verify_environment.py` 
**Quick Environment Verification**
- Focused on core functionality
- Tests Python packages and CLI tools
- Specific Flask application testing
- Streamlined output for quick checks
- Used automatically by post-create script

**Usage:**
```bash
python3 .devcontainer/verify_environment.py
```

### 3. `test_tools.py`
**Basic Security Tools Test**
- Simple tool availability check
- Created dynamically by post-create script
- Basic verification for security tools
- Lightweight testing option

**Usage:**
```bash
python3 .devcontainer/test_tools.py
```

## When to Use Each Script

- **During development**: Use `test_environment.py` for comprehensive testing
- **Quick verification**: Use `verify_environment.py` for fast checks
- **Basic tool check**: Use `test_tools.py` for simple tool verification
- **Automated setup**: `verify_environment.py` runs automatically during container creation

## Post-Create Process

The `post-create.sh` script:
1. Installs all system packages and security tools
2. Creates the dynamically generated `test_tools.py`
3. Runs `verify_environment.py` for final verification
4. Reports success/failure status

All scripts are designed to work together to ensure the Cybersecurity Sandbox environment is properly configured for educational use.