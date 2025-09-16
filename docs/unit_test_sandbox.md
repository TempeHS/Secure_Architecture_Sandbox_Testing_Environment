# Unit Test Sandbox Documentation

## Overview

This document describes the comprehensive unit testing framework for the Docker Sandbox Demo project. The test suite validates all cybersecurity analysis tools, commands, and workflows documented in the quick reference guides.

## Architecture

### Test Structure

The testing framework consists of 6 specialized test modules plus 1 comprehensive system runner:

```
tests/
├── run_all_tests.py                      # Master test runner
├── test_docker_environment_clean.py      # Docker/Infrastructure tests
├── test_sast_commands.py                 # Static Analysis tests
├── test_dast_commands.py                 # Dynamic Analysis tests
├── test_network_commands.py              # Network Analysis tests
├── test_sandbox_commands.py              # Sandbox Security tests
└── test_penetration_testing_commands.py  # Integrated Pentest tests
```

### Test Execution Order

Tests are executed in logical dependency order:

1. **Docker Environment** - Validates infrastructure is ready
2. **SAST Commands** - Tests static analysis capabilities
3. **DAST Commands** - Tests dynamic analysis capabilities  
4. **Network Commands** - Tests network monitoring capabilities
5. **Sandbox Commands** - Tests container-based security analysis
6. **Penetration Testing** - Tests integrated workflows

## Quick Start

### Prerequisites

Before running tests, ensure your environment is properly set up:

```bash
# 1. Install all Python dependencies (including docker package)
pip3 install -r requirements.txt

# 2. Start Docker services
docker-compose -f docker/docker-compose.yml up -d

# 3. Install Flask application dependencies
docker exec cybersec_sandbox bash -c "cd /workspace/samples/vulnerable-flask-app && pip3 install -r requirements.txt"

# 4. Start sample applications
docker exec -d cybersec_sandbox bash -c "cd /workspace/samples/vulnerable-flask-app && python3 app.py"
```

📖 **For complete setup instructions, see [setup-guide.md](setup-guide.md)**

### Running All Tests

```bash
# Run the complete test suite
cd /workspaces/Docker_Sandbox_Demo
python tests/run_all_tests.py

# Expected output:
# ================================================================================
# DOCKER SANDBOX DEMO - COMPREHENSIVE SYSTEM TEST SUITE
# ================================================================================
# [1/6] Running Docker Environment Validation...
# [2/6] Running SAST Command Validation...
# [3/6] Running DAST Command Validation...
# [4/6] Running Network Analysis Validation...
# [5/6] Running Sandbox Command Validation...
# [6/6] Running Penetration Testing Validation...
# 🎉 SYSTEM STATUS: ALL TESTS PASSED!
```

### Running Individual Test Modules

```bash
# Test Docker environment only
python -m pytest tests/test_docker_environment_clean.py -v

# Test SAST commands only
python -m pytest tests/test_sast_commands.py -v

# Test DAST commands only
python -m pytest tests/test_dast_commands.py -v

# Test Network analysis only
python -m pytest tests/test_network_commands.py -v

# Test Sandbox commands only
python -m pytest tests/test_sandbox_commands.py -v

# Test Penetration testing workflows only
python -m pytest tests/test_penetration_testing_commands.py -v
```

### Running Individual Tests

```bash
# Run specific test method
python -m pytest tests/test_sast_commands.py::SASTCommandValidationTest::test_01_sast_help_command -v

# Run all tests in a class
python -m pytest tests/test_dast_commands.py::DASTCommandValidationTest -v
```

## Test Module Details

### 1. Docker Environment Tests (`test_docker_environment_clean.py`)

**Purpose**: Validates Docker infrastructure and application availability

**Key Tests**:
- Container status and accessibility
- Port connectivity (5000, 9090, etc.)
- Application endpoint availability
- Service health checks
- Reports directory structure

**Example**:
```bash
# What it tests:
docker ps | grep cybersec_sandbox
curl http://localhost:5000/
curl http://localhost:9090/
```

**Dependencies**: Docker, docker-compose, requests library

### 2. SAST Command Tests (`test_sast_commands.py`)

**Purpose**: Validates Static Application Security Testing CLI functionality

**Key Tests**:
- Help command and argument validation
- Educational mode explanations
- Output format validation (JSON, text)
- Tool selection and configuration
- Sample application analysis
- Report generation and validation

**Example**:
```bash
# What it tests:
python src/analyzer/analyze_cli.py --help
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational
python src/analyzer/analyze_cli.py samples/ --output report.json --format json
```

**Dependencies**: analyze_cli.py, sample applications, JSON validation

### 3. DAST Command Tests (`test_dast_commands.py`)

**Purpose**: Validates Dynamic Application Security Testing CLI functionality

**Key Tests**:
- URL target scanning
- Quick vs deep scan modes
- Educational explanations
- Tool selection (nikto, gobuster)
- Demo application scanning
- Output format validation

**Example**:
```bash
# What it tests:
python src/analyzer/dast_cli.py http://localhost:5000 --quick --educational
python src/analyzer/dast_cli.py --demo-apps --tools nikto gobuster
python src/analyzer/dast_cli.py http://localhost:5000 --output scan.json --format json
```

**Dependencies**: dast_cli.py, running web applications, HTTP client

### 4. Network Analysis Tests (`test_network_commands.py`)

**Purpose**: Validates Network Traffic Analysis CLI functionality

**Key Tests**:
- Connection monitoring
- Service discovery
- Traffic capture and analysis
- DNS analysis capabilities
- Demo network scenarios
- Report generation

**Example**:
```bash
# What it tests:
python src/analyzer/network_cli.py --monitor-connections --educational
python src/analyzer/network_cli.py --scan-services localhost
python src/analyzer/network_cli.py --capture-traffic --duration 30
```

**Dependencies**: network_cli.py, network utilities, system permissions

### 5. Sandbox Command Tests (`test_sandbox_commands.py`)

**Purpose**: Validates Sandbox Security Analysis within Docker container

**Key Tests**:
- Container accessibility and permissions
- Security tool availability (strace, netstat, lsof)
- System call tracing functionality
- File system monitoring
- Process monitoring
- Log analysis patterns

**Example**:
```bash
# What it tests (inside container):
docker exec -it cybersec_sandbox strace -o trace.log python script.py
docker exec -it cybersec_sandbox netstat -tupln
docker exec -it cybersec_sandbox grep "openat" trace.log
```

**Dependencies**: Docker container, security analysis tools, sample scripts

### 6. Penetration Testing Tests (`test_penetration_testing_commands.py`)

**Purpose**: Validates integrated penetration testing workflows

**Key Tests**:
- 4-phase pentest methodology (Recon, Assessment, Exploitation, Post-Exploitation)
- Integrated tool workflows
- Multi-module report generation
- Manual testing techniques (SQL injection, XSS)
- Professional workflow validation

**Example**:
```bash
# What it tests:
# Phase 1: Reconnaissance
python src/analyzer/network_cli.py --scan-services localhost --educational
python src/analyzer/dast_cli.py http://localhost:5000 --quick --educational

# Phase 2: Vulnerability Assessment
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational
python src/analyzer/dast_cli.py http://localhost:5000 --deep-scan --educational

# Phase 3: Controlled Exploitation
curl -X POST "http://localhost:5000/login" -d "username=admin' OR '1'='1&password=test"

# Phase 4: Post-Exploitation Analysis
python src/analyzer/network_cli.py --monitor-connections --duration 60 --educational
```

**Dependencies**: All analyzer modules, web applications, HTTP client

## System Test Runner (`run_all_tests.py`)

### Features

- **Sequential Execution**: Runs tests in logical dependency order
- **Comprehensive Reporting**: Detailed pass/fail status for each module
- **Error Analysis**: Shows first failure/error for quick diagnosis
- **Results Archival**: Saves timestamped results to `reports/` directory
- **Exit Codes**: Proper exit codes for CI/CD integration

### Output Format

```
================================================================================
DOCKER SANDBOX DEMO - COMPREHENSIVE SYSTEM TEST SUITE
================================================================================
Project Root: /workspaces/Docker_Sandbox_Demo
Test Time: 2024-12-19 14:30:15
================================================================================

[1/6] Running Docker Environment Validation...
Description: Validates Docker containers and services
------------------------------------------------------------
✅ Docker Environment Validation: PASSED (8 tests)

[2/6] Running SAST Command Validation...
Description: Tests Static Application Security Testing CLI
------------------------------------------------------------
✅ SAST Command Validation: PASSED (12 tests)

...

================================================================================
COMPREHENSIVE TEST RESULTS SUMMARY
================================================================================
Test Modules: 6/6 passed
Individual Tests: 89/89 passed
Failures: 0
Errors: 0

Module Results:
----------------------------------------
✅ PASS Docker Environment Validation: 8 tests
✅ PASS SAST Command Validation: 12 tests
✅ PASS DAST Command Validation: 15 tests
✅ PASS Network Analysis Validation: 20 tests
✅ PASS Sandbox Command Validation: 15 tests
✅ PASS Penetration Testing Validation: 14 tests

================================================================================
🎉 SYSTEM STATUS: ALL TESTS PASSED!
✅ Docker Sandbox Demo is fully operational and validated.
✅ All command workflows are working correctly.
✅ All security analysis tools are functional.
================================================================================
```

## Requirements and Dependencies

### System Requirements

- **Operating System**: Linux (tested on Debian 11)
- **Docker**: Version 20.10+ with docker-compose
- **Python**: Version 3.8+ with pip
- **Memory**: Minimum 4GB RAM recommended
- **Disk**: 2GB free space for containers and reports

### Python Dependencies

```txt
# Core testing framework
unittest (built-in)
docker
requests
json (built-in)
subprocess (built-in)
pathlib (built-in)

# Optional but recommended
pytest
pytest-cov
```

### Docker Dependencies

```bash
# Required containers
cybersec_sandbox          # Main analysis container
vulnerable-flask-app      # Test application (port 5000)
unsecure-pwa              # Test application (port 9090)
```

## Configuration

### Environment Variables

```bash
# Optional: Customize test timeouts
export TEST_TIMEOUT=120          # Default timeout in seconds
export TEST_VERBOSE=1            # Enable verbose output
export TEST_REPORTS_DIR=reports  # Custom reports directory
```

### Docker Configuration

```bash
# Ensure containers are running
docker-compose up -d

# Verify container status
docker ps | grep -E "(cybersec_sandbox|flask|pwa)"

# Check port accessibility
netstat -tuln | grep -E ":5000|:9090"
```

## Troubleshooting

### Common Issues

#### 1. Container Not Running

**Symptoms**: 
```
❌ Docker Environment Validation: FAILED
Container cybersec_sandbox not found
```

**Solution**:
```bash
docker-compose down
docker-compose up -d
docker ps  # Verify containers are running
```

#### 2. Port Conflicts

**Symptoms**:
```
⚠️ http://localhost:5000 may not be available
Connection refused
```

**Solution**:
```bash
# Check what's using the port
netstat -tuln | grep 5000
lsof -i :5000

# Restart docker-compose
docker-compose restart
```

#### 3. Permission Denied

**Symptoms**:
```
Permission denied for network operations
```

**Solution**:
```bash
# Run with sudo (if needed)
sudo python tests/run_all_tests.py

# Or use educational mode (some tests)
python src/analyzer/network_cli.py --demo-network --educational
```

#### 4. Module Import Errors

**Symptoms**:
```
❌ SAST Command Validation: IMPORT ERROR
Could not import test_sast_commands
```

**Solution**:
```bash
# Ensure you're in the project root
cd /workspaces/Docker_Sandbox_Demo

# Check Python path
export PYTHONPATH=$PYTHONPATH:$(pwd)

# Install dependencies
pip install -r requirements.txt
```

#### 5. Test Timeouts

**Symptoms**:
```
DAST deep scan timed out
```

**Solution**:
```bash
# Increase timeout in test configuration
# Edit test files and increase timeout values
# Or run individual tests with more time

# Run specific failing test
python -m pytest tests/test_dast_commands.py::DASTCommandValidationTest::test_05_dast_deep_scan_flask -v -s
```

### Debug Mode

```bash
# Run with maximum verbosity
python tests/run_all_tests.py 2>&1 | tee test_debug.log

# Run individual test with debugging
python -m pytest tests/test_sast_commands.py -v -s --tb=long

# Check specific tool functionality
python src/analyzer/analyze_cli.py --help
python src/analyzer/dast_cli.py --help
python src/analyzer/network_cli.py --help
```

## Continuous Integration

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
name: Docker Sandbox Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Docker
      run: |
        docker-compose up -d
        sleep 30  # Wait for services to start
    - name: Run Tests
      run: |
        python tests/run_all_tests.py
    - name: Archive test results
      uses: actions/upload-artifact@v2
      with:
        name: test-results
        path: reports/
```

### Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << EOF
repos:
- repo: local
  hooks:
  - id: run-tests
    name: Run Docker Sandbox Tests
    entry: python tests/run_all_tests.py
    language: system
    pass_filenames: false
EOF

# Install hooks
pre-commit install
```

## Performance Metrics

### Expected Test Execution Times

| Test Module | Duration | Test Count | Key Operations |
|-------------|----------|------------|----------------|
| Docker Environment | 30-60s | 8 tests | Container checks, HTTP requests |
| SAST Commands | 60-120s | 12 tests | File analysis, report generation |
| DAST Commands | 120-300s | 15 tests | Web scanning, deep analysis |
| Network Analysis | 90-180s | 20 tests | Network monitoring, traffic capture |
| Sandbox Commands | 60-120s | 15 tests | Container operations, tool execution |
| Penetration Testing | 180-360s | 14 tests | Integrated workflows, manual testing |
| **Total** | **8-20 minutes** | **84 tests** | **Full system validation** |

### Resource Usage

- **CPU**: 50-80% during active scanning
- **Memory**: 1-2GB peak usage
- **Disk**: 100-500MB for reports and logs
- **Network**: Local traffic only (except DNS tests)

## Maintenance

### Regular Maintenance Tasks

```bash
# Weekly: Update test data
docker-compose pull
docker system prune

# Monthly: Update dependencies
pip install --upgrade -r requirements.txt

# Quarterly: Review test coverage
python -m pytest tests/ --cov=src --cov-report=html

# As needed: Add new tests for new features
# Follow the existing test patterns in each module
```

### Adding New Tests

1. **Identify the appropriate test module** based on the functionality
2. **Follow the existing naming convention**: `test_##_descriptive_name`
3. **Include proper error handling** and timeout management
4. **Add logging** for troubleshooting
5. **Update this documentation** with new test descriptions

Example new test:
```python
def test_99_new_feature_validation(self):
    """Test new feature functionality."""
    logger.info("Testing new feature...")
    
    try:
        result = subprocess.run(
            ["python", "src/analyzer/new_tool.py", "--new-option"],
            cwd=self.project_root,
            capture_output=True,
            text=True,
            timeout=self.timeout
        )
        
        self.assertEqual(result.returncode, 0,
                         f"New feature failed: {result.stderr}")
        
        logger.info("✅ New feature validation passed")
        
    except subprocess.TimeoutExpired:
        self.fail("New feature test timed out")
```

## Security Considerations

### Test Environment Isolation

- All tests run in isolated Docker containers
- No external network access during testing (except DNS)
- Sample applications are intentionally vulnerable (educational use only)
- Test data is sanitized and does not contain real sensitive information

### Safe Testing Practices

- **Never test against production systems**
- **Always use the provided sandbox environment**
- **Validate that containers are properly isolated**
- **Clean up test artifacts after execution**

### Data Privacy

- Test results may contain system information
- Reports are stored locally only
- No test data is transmitted outside the sandbox
- Clean up reports directory regularly

---

## Conclusion

This comprehensive testing framework ensures that all components of the Docker Sandbox Demo are functional and meet educational objectives. The tests validate that students can successfully learn cybersecurity analysis techniques using the provided tools and workflows.

For questions or issues with the testing framework, refer to the troubleshooting section or check the individual test module documentation within each test file.

**Total Test Coverage**: 84 individual tests across 6 modules
**Estimated Runtime**: 8-20 minutes for complete suite
**Validation Coverage**: 100% of documented quick reference commands