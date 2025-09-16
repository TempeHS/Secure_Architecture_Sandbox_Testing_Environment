# Docker Sandbox Demo - Complete Setup Guide

## 🎯 Overview

This guide provides step-by-step instructions for setting up the Docker Sandbox Demo environment, including all required dependencies and troubleshooting common issues.

## 🚀 Setup Methods

### Method 1: GitHub Codespaces (Recommended)
1. Click the "Code" button and select "Create codespace on main"
2. Wait for the environment to load (2-3 minutes)
3. Follow the "Post-Setup Configuration" steps below

### Method 2: Local Development
```bash
git clone https://github.com/TempeHS/Docker_Sandbox_Demo.git
cd Docker_Sandbox_Demo
```

## 📋 Post-Setup Configuration

### Step 1: Install Python Dependencies
```bash
# Install all required Python packages including testing dependencies
pip3 install -r requirements.txt
```

**Note**: The requirements.txt includes the `docker` Python package needed for validation tests.

### Step 2: Start Docker Services
```bash
# Start the Docker Compose services
docker-compose -f docker/docker-compose.yml up -d

# Verify containers are running
docker ps
```

You should see two containers:
- `cybersec_sandbox` - Main analysis environment
- `vulnerable_web_app` - Nginx serving vulnerable applications

### Step 3: Install Flask Application Dependencies
The sandbox includes vulnerable Flask applications that require additional dependencies:

```bash
# Install Flask app dependencies in the main container
docker exec cybersec_sandbox bash -c "cd /workspace/samples/vulnerable-flask-app && pip3 install -r requirements.txt"
```

### Step 4: Start Sample Applications
```bash
# Start the main vulnerable Flask application (port 5000)
docker exec -d cybersec_sandbox bash -c "cd /workspace/samples/vulnerable-flask-app && python3 app.py"

# Verify the Flask app is running
curl http://localhost:5000
```

### Step 5: Validate Environment
Run the comprehensive test suite to ensure everything is working:

```bash
# Run environment validation tests
python3 tests/test_docker_environment.py

# Run all test suites (optional)
python3 tests/run_all_tests.py
```

## 🛠️ Known Issues and Solutions

### Issue 1: Docker Python Package Missing
**Symptom**: `ModuleNotFoundError: No module named 'docker'`
**Solution**: 
```bash
pip3 install docker
```

### Issue 2: Flask Applications Not Starting
**Symptom**: Connection refused on ports 5000 or 9090
**Solution**: 
```bash
# Check if dependencies are installed
docker exec cybersec_sandbox bash -c "cd /workspace/samples/vulnerable-flask-app && pip3 install -r requirements.txt"

# Start the Flask app manually
docker exec -d cybersec_sandbox bash -c "cd /workspace/samples/vulnerable-flask-app && python3 app.py"
```

### Issue 3: PWA Application Configuration Issue
**Current Status**: The PWA application is configured as a Flask app but the Docker setup serves it as static files through nginx.

**Temporary Solution**: The vulnerable Flask app on port 5000 provides comprehensive vulnerability testing.

**Permanent Solution**: Update docker-compose.yml to properly configure the PWA Flask application on port 9090.

### Issue 4: Test Failures
**Symptom**: Tests fail with container or connection errors
**Solutions**:
1. Ensure Docker is running: `docker ps`
2. Restart containers: `docker-compose -f docker/docker-compose.yml restart`
3. Check container logs: `docker logs cybersec_sandbox`

## 🔧 Container Services

### Main Sandbox Container (`cybersec_sandbox`)
- **Purpose**: Primary analysis environment
- **Ports**: 3000, 5000, 8000, 8080
- **Tools**: Python security tools, network analysis tools
- **Mount Point**: `/workspace` (mapped to project root)

### Vulnerable Web App Container (`vulnerable_web_app`)
- **Purpose**: Serves static web content for testing
- **Port**: 9090
- **Base Image**: nginx:alpine
- **Current Issue**: Configured for static files but should serve Flask PWA

## 📊 Application Access Points

### Vulnerable Flask Application
- **URL**: http://localhost:5000
- **Purpose**: Main vulnerability testing target
- **Features**: SQL injection, XSS, SSTI, command execution, file inclusion
- **Credentials**: admin/admin123, user/user123

### PWA Application (Currently under configuration)
- **Expected URL**: http://localhost:9090
- **Purpose**: Progressive Web App vulnerability testing
- **Current Status**: Needs Docker configuration fix

## 🧪 Testing Your Setup

### Basic Connectivity Test
```bash
# Test main Flask app
curl http://localhost:5000

# Check Docker containers
docker ps

# Verify tools are available
docker exec cybersec_sandbox which bandit
docker exec cybersec_sandbox which nmap
```

### Run Sample Security Analysis
```bash
# SAST analysis
python3 src/analyzer/analyze_cli.py samples/vulnerable-flask-app/ --educational

# Network monitoring (in background)
python3 src/analyzer/network_cli.py --monitor-connections --educational &

# DAST analysis
python3 src/analyzer/dast_cli.py http://localhost:5000 --educational
```

## 📝 Next Steps

1. **For Instructors**: Review the exercise files in `docs/exercises/`
2. **For Students**: Start with the SAST exercise in `docs/exercises/static-application-security-testing-exercise.md`
3. **For Developers**: See `docs/maintenance-guide.md` for contribution guidelines

## 🆘 Getting Help

- **Documentation**: Check `docs/` directory for detailed guides
- **Issues**: Report problems via GitHub Issues
- **Testing**: Use `tests/test_docker_environment.py` for environment validation
- **Logs**: Check container logs with `docker logs [container_name]`