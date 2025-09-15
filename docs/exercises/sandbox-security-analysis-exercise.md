# Sandbox Security Analysis Exercise

## 📖 Overview

Sandbox security analysis involves testing applications in isolated, controlled environments to detect malicious behavior, system vulnerabilities, and security weaknesses. Unlike SAST (which analyzes code) and DAST (which tests running applications), sandbox analysis observes how applications behave when executed in a secure environment.

**Key Learning Objectives:**
- ✅ Understand what sandbox security analysis is and why it's critical
- ✅ Learn how to execute applications safely in controlled environments
- ✅ Practice monitoring system calls, network activity, and resource usage
- ✅ Identify potentially malicious behavior patterns
- ✅ Analyze sandbox logs to detect security threats
- ✅ Generate comprehensive sandbox analysis reports

## 🎯 Security Testing Method Comparison

| Aspect | SAST (Static) | DAST (Dynamic) | Sandbox Analysis |
|--------|---------------|----------------|------------------|
| **Analysis Type** | Source code review | Running app testing | Behavioral monitoring |
| **When to Run** | During development | During runtime | During execution |
| **Environment** | No execution needed | Production-like | Isolated/controlled |
| **Finds** | Code vulnerabilities | Runtime vulnerabilities | Malicious behavior |
| **Examples** | Hardcoded secrets | XSS, SQL injection | Malware, data exfiltration |
| **Speed** | Fast | Medium | Slow (full execution) |
| **Safety** | Very safe | Safe (controlled) | Safest (isolated) |

## 🛡️ What is Sandbox Security Analysis?

### Definition
Sandbox security analysis is a cybersecurity technique that executes potentially malicious or untrusted applications in an isolated environment while monitoring their behavior for security threats.

### Key Characteristics:
- **Behavioral Analysis**: Monitors what the application actually does
- **Isolated Execution**: Prevents damage to the host system  
- **Comprehensive Monitoring**: Tracks file, network, and system interactions
- **Real-time Detection**: Identifies threats as they occur

### Why Sandbox Analysis Matters:
- **Malware Detection**: Identifies viruses, trojans, and other malicious software
- **Zero-Day Protection**: Catches unknown threats through behavioral patterns
- **Safe Testing**: Allows analysis of suspicious files without risk
- **Incident Response**: Helps understand attack methods and impacts

## 🧪 Lab Environment Setup

### Prerequisites
1. Docker Sandbox Demo environment running
2. Containerized analysis environment: `cd docker && docker-compose up -d`
3. Python 3.8+ with security monitoring tools
4. Sample suspicious applications and scripts available

### Tool Verification
```bash
# Enter the security sandbox container
docker exec -it cybersec_sandbox bash

# Verify analysis tools are available
which strace          # System call tracer
which netstat         # Network monitoring
which ps              # Process monitoring
which lsof            # File monitoring

# Test the sandbox analyzer (coming soon)
python /sandbox/analyzer.py --help
```

## 🎯 Sample Applications for Analysis

### 1. Suspicious Python Script (`suspicious_script.py`)
- **Technology**: Python with potential malicious behavior
- **Location**: `samples/suspicious-scripts/suspicious_script.py`
- **Behaviors to Monitor**: File access, network connections, system calls
- **Expected Findings**: Unauthorized file access, suspicious network activity

### 2. Web Application with Backdoor (`backdoor_app.py`)
- **Technology**: Flask web application with hidden functionality
- **Location**: `samples/backdoor-apps/backdoor_app.py`
- **Behaviors to Monitor**: Hidden endpoints, file uploads, command execution
- **Expected Findings**: Command injection, file system manipulation

### 3. Cryptocurrency Mining Script (`crypto_miner.py`)
- **Technology**: Python script that uses excessive CPU resources
- **Location**: `samples/resource-abuse/crypto_miner.py`
- **Behaviors to Monitor**: CPU usage, network connections to mining pools
- **Expected Findings**: High resource consumption, suspicious network traffic

## 🔍 Analysis Techniques

### 1. System Call Monitoring
Monitor how applications interact with the operating system:
```bash
# Trace system calls for a Python script
strace -o trace.log python suspicious_script.py

# Analyze the trace for suspicious patterns
grep -E "(open|write|connect|execve)" trace.log
```

### 2. Network Traffic Analysis
Monitor network connections and data transmission:
```bash
# Monitor network connections
netstat -tupln

# Capture network traffic during execution
tcpdump -i any -w network_capture.pcap &
python suspicious_script.py
pkill tcpdump
```

### 3. File System Monitoring
Track file creation, modification, and access:
```bash
# Monitor file system changes
inotifywait -m -r --format '%w%f %e' /tmp &
python suspicious_script.py
```

### 4. Resource Usage Analysis
Monitor CPU, memory, and other resource consumption:
```bash
# Monitor resource usage
top -b -n 1 -p $(pgrep python)

# Track process tree
pstree -p $(pgrep python)
```

## 📋 Hands-On Exercise 1: Basic Sandbox Analysis

### Objective
Analyze a suspicious Python script in a controlled environment to identify potential security threats.

### Steps

#### Step 1: Prepare the Sandbox Environment
```bash
# Enter the sandbox container
docker exec -it cybersec_sandbox bash

# Navigate to the analysis workspace
cd /sandbox/analysis
```

#### Step 2: Examine the Suspicious Script
```bash
# Look at the script (safely, without executing)
cat ../samples/suspicious_script.py

# Note any obvious suspicious patterns:
# - Network connections
# - File operations
# - System commands
# - Obfuscated code
```

#### Step 3: Set Up Monitoring
```bash
# Start system call monitoring
strace -o syscalls.log -f python ../samples/suspicious_script.py &
SCRIPT_PID=$!

# Start network monitoring
netstat -tupln > network_before.log
```

#### Step 4: Execute and Monitor
```bash
# Let the script run for 30 seconds
sleep 30

# Capture final network state
netstat -tupln > network_after.log

# Stop the script
kill $SCRIPT_PID
```

#### Step 5: Analyze Results
```bash
# Analyze system calls
echo "=== FILE OPERATIONS ==="
grep -E "(openat|write|read)" syscalls.log | head -10

echo "=== NETWORK OPERATIONS ==="
grep -E "(socket|connect|bind)" syscalls.log | head -10

echo "=== PROCESS OPERATIONS ==="
grep -E "(execve|fork|clone)" syscalls.log | head -10

# Compare network states
echo "=== NEW NETWORK CONNECTIONS ==="
diff network_before.log network_after.log
```

### Expected Results
Students should identify:
- ✅ Unauthorized file access attempts
- ✅ Suspicious network connection attempts
- ✅ System call patterns indicating malicious behavior
- ✅ Resource consumption patterns

## 📋 Hands-On Exercise 2: Web Application Backdoor Detection

### Objective
Analyze a web application that contains hidden backdoor functionality.

### Steps

#### Step 1: Start the Backdoor Application
```bash
# Start the suspicious web application
cd /sandbox/samples/backdoor-apps
python backdoor_app.py &
APP_PID=$!

# Wait for application to start
sleep 5
```

#### Step 2: Monitor Application Behavior
```bash
# Monitor file system access
inotifywait -m -r --format '%w%f %e' /tmp > file_monitor.log &
MONITOR_PID=$!

# Monitor network connections
netstat -tupln > network_initial.log
```

#### Step 3: Test Normal Functionality
```bash
# Test normal web endpoints
curl http://localhost:5000/
curl http://localhost:5000/about
curl http://localhost:5000/contact
```

#### Step 4: Search for Hidden Endpoints
```bash
# Use directory enumeration to find hidden paths
dirb http://localhost:5000/ /usr/share/dirb/wordlists/common.txt

# Test common backdoor paths
curl http://localhost:5000/admin
curl http://localhost:5000/shell
curl http://localhost:5000/cmd
curl http://localhost:5000/backdoor
```

#### Step 5: Analyze Backdoor Activity
```bash
# Test command execution (if backdoor found)
curl "http://localhost:5000/backdoor?cmd=whoami"
curl "http://localhost:5000/backdoor?cmd=ls%20-la"

# Check for file system changes
cat file_monitor.log

# Check for new network activity
netstat -tupln > network_final.log
diff network_initial.log network_final.log
```

#### Step 6: Clean Up
```bash
# Stop monitoring and application
kill $MONITOR_PID $APP_PID
```

### Expected Results
Students should discover:
- ✅ Hidden backdoor endpoints
- ✅ Command execution capabilities
- ✅ Unauthorized file system access
- ✅ Suspicious network behavior

## 📋 Hands-On Exercise 3: Resource Abuse Detection

### Objective
Identify applications that abuse system resources, such as cryptocurrency miners.

### Steps

#### Step 1: Baseline Resource Usage
```bash
# Record initial system state
top -b -n 1 > baseline_resources.log
free -h > baseline_memory.log
```

#### Step 2: Execute Resource-Intensive Application
```bash
# Start the crypto mining simulation
cd /sandbox/samples/resource-abuse
python crypto_miner.py &
MINER_PID=$!
```

#### Step 3: Monitor Resource Consumption
```bash
# Monitor for 60 seconds
for i in {1..12}; do
    echo "=== Measurement $i ===" >> resource_monitor.log
    top -b -n 1 -p $MINER_PID >> resource_monitor.log
    sleep 5
done
```

#### Step 4: Monitor Network Activity
```bash
# Check for mining pool connections
netstat -tupln | grep $MINER_PID
lsof -p $MINER_PID | grep ESTABLISHED
```

#### Step 5: Analyze Resource Impact
```bash
# Compare resource usage
echo "=== BASELINE CPU USAGE ==="
head -15 baseline_resources.log

echo "=== CURRENT CPU USAGE ==="
top -b -n 1

# Stop the miner
kill $MINER_PID
```

### Expected Results
Students should identify:
- ✅ Abnormally high CPU usage (>80%)
- ✅ Suspicious network connections to external servers
- ✅ Long-running processes with unclear purpose
- ✅ Resource consumption patterns typical of miners

## 🎓 Learning Assessment

### Knowledge Check Questions

1. **What is the primary difference between sandbox analysis and SAST/DAST?**
   - A) Sandbox analysis is faster
   - B) Sandbox analysis monitors actual behavior during execution
   - C) Sandbox analysis only works with web applications
   - D) Sandbox analysis doesn't require isolation

2. **Which system call would most likely indicate file tampering?**
   - A) read()
   - B) openat()
   - C) write()
   - D) close()

3. **What is the main advantage of sandbox analysis for malware detection?**
   - A) It's faster than antivirus
   - B) It can detect unknown threats through behavior
   - C) It doesn't require any tools
   - D) It works without executing code

4. **Which monitoring technique would best detect cryptocurrency mining?**
   - A) File system monitoring
   - B) Network traffic analysis
   - C) CPU resource monitoring
   - D) Memory usage analysis

### Practical Assessment

**Scenario**: You've been given a suspicious Python script that claims to be a "system optimizer" but users report slow performance after running it.

**Your Task**: 
1. Set up appropriate monitoring
2. Execute the script safely
3. Analyze the results
4. Determine if the script is malicious
5. Document your findings

**Success Criteria**:
- ✅ Proper sandbox setup and execution
- ✅ Comprehensive monitoring of system calls, network, and resources
- ✅ Accurate identification of malicious behavior
- ✅ Clear documentation of findings and evidence

## 🎯 Real-World Applications

### Industry Use Cases
- **Incident Response**: Analyzing malware samples safely
- **Threat Intelligence**: Understanding new attack methods
- **Software Validation**: Testing third-party applications
- **Security Research**: Studying malware families and techniques

### Career Connections
- **Malware Analyst**: Specializes in analyzing malicious software
- **Incident Response Specialist**: Investigates and contains security breaches
- **Security Researcher**: Discovers new threats and vulnerabilities
- **Forensics Investigator**: Analyzes digital evidence from security incidents

## 📚 Additional Resources

### Tools for Further Learning
- **Cuckoo Sandbox**: Automated malware analysis system
- **ANY.RUN**: Interactive online malware analysis
- **Joe Sandbox**: Commercial malware analysis platform
- **VirtualBox/VMware**: Virtualization for safe testing

### Reference Materials
- NIST Cybersecurity Framework
- MITRE ATT&CK Framework
- OWASP Application Security Verification Standard
- "Practical Malware Analysis" by Sikorski & Honig

### Next Steps
1. Practice with more complex malware samples
2. Learn about advanced evasion techniques
3. Study machine learning approaches to behavior analysis
4. Explore cloud-based sandbox solutions

---

**Duration**: 3-4 hours  
**Difficulty**: Intermediate  
**Prerequisites**: Basic understanding of operating systems and command line  
**Tools Required**: Docker, Linux command line tools, Python