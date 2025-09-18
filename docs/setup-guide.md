# Secure Architecture Sandbox Testing Environment - Student Flask App Requirements

## 🎯 Overview

Quick reference for students creating Flask applications for cybersecurity
testing. This guide demonstrates how **application isolation and containment**
principles support **safe execution environments for untrusted code** - key
concepts in cybersecurity architecture.

## 🐳 Understanding Our Educational Architecture

### Why Two Containers? Professional Security Testing Design

This sandbox uses a **multi-layer isolation and containerized architecture** using Codespaces and Docker that mirrors real-world cybersecurity practices.

![Docker/CodesSpaces Topology!](images/secure_architecture_sandbox_network_topology.png "Docker/CodesSpaces Topology")
**Educational Benefits:**

- **Separation of Concerns**: Clear distinction between testing tools and
  targets
- **Professional Realism**: Mirrors penetration testing and incident response
  workflows
- **Safe Experimentation**: **Resource limitation and monitoring** prevents
  system damage
- **Security by Design**: Multiple isolation layers protect both containers and
  host

### Container Security Features

**Industry-Standard Isolation Techniques:**

- **Process Isolation**: Each container runs in its own process space
- **Network Segmentation**: Controlled communication between containers
- **File System Isolation**: Containers cannot access host or other container
  files
- **Resource Limits**: CPU and memory restrictions prevent resource abuse
- **Capability Restrictions**: Limited system permissions following least
  privilege principles

## � Application Requirements

### Required Files and Structure

```
your-app-name/
├── app.py             # Main Flask application
├── requirements.txt   # Python dependencies
└── README.md         # Optional documentation
```

### File Specifications

#### `app.py` Requirements

- Must import Flask: `from flask import Flask`
- Must create app instance: `app = Flask(__name__)`
- Must include at least one route: `@app.route("/")`
- Must run on port 8000: `app.run(debug=True, host='0.0.0.0', port=8000)`

#### `requirements.txt` Requirements

- Must include: `Flask==2.3.3`
- Add other packages as needed with specific versions

### Port Assignment

- **Use port 8000** for your Flask application
- Alternative ports: 3000, 8080
- **Do NOT use port 5000** (reserved)

## 🔄 Docker Management

### Understanding Container Lifecycle for Security Testing

The container lifecycle demonstrates key **security testing and evaluation**
principles:

**1. Preparation Phase** (Container Creation)

- **Systematic vulnerability assessment** setup
- **Security configuration and controls** implementation
- **Safe execution environment** preparation

**2. Testing Phase** (Container Execution)

- **Behavioural analysis and threat detection** in isolation
- **Resource limitation and monitoring** during analysis
- **Controlled application testing** without host system risk

**3. Analysis Phase** (Data Collection)

- **Evidence collection** from isolated environment
- **Security findings documentation** with contained logs
- **Risk assessment** based on observed behaviours

**4. Cleanup Phase** (Container Disposal)

- **Secure evidence handling** and report generation
- **Environment reset** for next testing cycle
- **Incident response** preparation if threats detected

### Deploy Your App

```bash
# Copy template (optional)
cp -r uploads/ uploads/your-app-name

# Install dependencies in isolated environment
docker exec cybersec_sandbox bash -c "cd /workspace/uploads && pip3 install -r requirements.txt"

# Run your app in controlled container
docker exec -d cybersec_sandbox bash -c "cd /workspace/uploads && python3 app.py"
```

### Refresh/Restart Commands

```bash
# Restart all Docker services (demonstrates container resilience)
docker-compose -f docker/docker-compose.yml restart

# Stop and restart fresh (clean slate for testing)
docker-compose -f docker/docker-compose.yml down
docker-compose -f docker/docker-compose.yml up -d

# Kill your app and restart (incident response simulation)
docker exec cybersec_sandbox pkill -f "python.*app.py"
docker exec -d cybersec_sandbox bash -c "cd /workspace/uploads && python3 app.py"
```

## 🌐 Access Your Application

### URLs

- **Codespaces**: `https://your-codespace-name-8000.app.github.dev`
- **Local test**: `curl http://localhost:8000`
- **Web file browser**: `http://localhost:8080/uploads/` (nginx serves uploads
  folder)

### Quick Test

```bash
curl http://localhost:8000
```

### Quick Test

```bash
# Verify app is running
curl http://localhost:8000
```

## 🔒 Security Testing Commands

These commands demonstrate **systematic vulnerability assessment** and
**security management strategies** in containerized environments:

### Static Analysis (SAST) - **Source Code Analysis**

```bash
# Demonstrates defensive programming analysis
python3 src/analyser/analyse_cli.py uploads/ --educational
```

**Syllabus Connection**: **Input validation**, **sanitization**, and **error
handling** detection

### Dynamic Analysis (DAST) - **Runtime Testing**

```bash
# Tests running applications for security vulnerabilities
python3 src/analyser/dast_cli.py http://localhost:8000 --educational
```

**Syllabus Connection**: **Cross-site scripting (XSS)**, **authentication**, and
**session management** testing

### Network Analysis - **Systematic Security Evaluation**

```bash
# Monitors network behaviour and connections in isolation
python3 src/analyser/network_cli.py --monitor-connections --educational
```

**Syllabus Connection**: **Secure communication protocols** and **threat
detection** analysis

### Penetration Testing - **Ethical Hacking and Exploitation Testing**

```bash
# Comprehensive security assessment using controlled environment
python3 src/analyser/pentest_cli.py http://localhost:8000 --educational
```

**Syllabus Connection**: **Security testing and evaluation** with **incident
response** preparation

## 🐛 Quick Troubleshooting

```bash
# Check if app is running
curl http://localhost:8000

# Kill and restart your app
docker exec cybersec_sandbox pkill -f "python.*app.py"
docker exec -d cybersec_sandbox bash -c "cd /workspace/uploads && python3 app.py"

# Check port usage
docker exec cybersec_sandbox netstat -tulpn | grep :8000
```
