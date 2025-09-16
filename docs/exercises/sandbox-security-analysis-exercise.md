# Sandbox Security Analysis Exercise

## 📖 Overview

Sandbox security analysis involves testing applications in isolated, controlled
environments to detect malicious behavior, system vulnerabilities, and security
weaknesses. Unlike SAST (which analyzes code) and DAST (which tests running
applications), sandbox analysis observes how applications behave when executed
in a secure environment.

**Think of it this way:** If SAST is like reading a recipe to check for
dangerous ingredients, and DAST is like taste-testing a finished meal, then
sandbox analysis is like watching someone cook in a separate kitchen while you
observe everything they do through a window.

**Key Learning Objectives:**

- ✅ Understand what sandbox security analysis is and why it's critical
- ✅ Learn how to execute applications safely in controlled environments
- ✅ Practice monitoring system calls, network activity, and resource usage
- ✅ Identify potentially malicious behavior patterns
- ✅ Analyze sandbox logs to detect security threats
- ✅ Generate comprehensive sandbox analysis reports

## 📍 Getting Started - Important Navigation

**🏠 Always start from the main project folder:**

```bash
# If you get lost, return to the main folder:
cd /workspaces/Docker_Sandbox_Demo

# Check you're in the right place:
ls
```

**Expected Output:**

```
copilot-instructions.md  docker/  docs/  reports/  samples/  src/  ...
```

## 🎯 Security Testing Method Comparison

| Aspect                 | SAST (Static)        | DAST (Dynamic)          | Sandbox Analysis           |
| ---------------------- | -------------------- | ----------------------- | -------------------------- |
| **Analysis Type**      | Source code review   | Running app testing     | Behavioral monitoring      |
| **When to Run**        | During development   | During runtime          | During execution           |
| **Environment**        | No execution needed  | Production-like         | Isolated/controlled        |
| **Finds**              | Code vulnerabilities | Runtime vulnerabilities | Malicious behavior         |
| **Examples**           | Hardcoded secrets    | XSS, SQL injection      | Malware, data exfiltration |
| **Real-World Analogy** | Reading a recipe     | Taste-testing food      | Watching someone cook      |
| **Speed**              | Fast                 | Medium                  | Slow (full execution)      |
| **Safety**             | Very safe            | Safe (controlled)       | Safest (isolated)          |

## 🛡️ What is Sandbox Security Analysis?

### Definition

Sandbox security analysis is a cybersecurity technique that executes potentially
malicious or untrusted applications in an isolated environment while monitoring
their behavior for security threats.

### 🔍 Real-World Analogy

Think of sandbox analysis like having a separate, monitored workshop where you
can test suspicious tools:

- **Isolated Environment**: Like a workshop separated from your main house
- **Complete Monitoring**: Like having cameras watching everything that happens
- **Controlled Resources**: Like limiting what tools and materials are available
- **Safe Observation**: Like watching from behind protective glass
- **No Real Damage**: If something goes wrong, it only affects the workshop

### Key Characteristics:

- **Behavioral Analysis**: Monitors what the application actually does
- **Isolated Execution**: Prevents damage to the host system
- **Comprehensive Monitoring**: Tracks file, network, and system interactions
- **Real-time Detection**: Identifies threats as they occur

### Why Sandbox Analysis Matters:

- **Malware Detection**: Identifies viruses, trojans, and other malicious
  software
- **Zero-Day Protection**: Catches unknown threats through behavioral patterns
- **Safe Testing**: Allows analysis of suspicious files without risk
- **Incident Response**: Helps understand attack methods and impacts

## 🐳 Understanding Containerization for Security Testing

### What Are Containers and Why Do We Use Them?

**Containers** are like lightweight, portable "computer environments" that run
applications in isolation from the host system. Think of them as **secure,
disposable computer labs** that you can create, use, and destroy without
affecting your main computer.

#### 🏠 Real-World Analogy: The Apartment Building

Imagine containers like apartments in a building:

- **Each apartment (container)** has its own space, utilities, and resources
- **Apartments share the building infrastructure** (like containers share the
  host OS)
- **If one apartment has problems**, it doesn't affect the others
- **You can quickly set up or tear down an apartment** without affecting the
  building
- **Each apartment can be configured differently** for different purposes

### 🔒 Why Containers Are Perfect for Cybersecurity Education

#### 1. **Complete Isolation = Maximum Safety**

```
┌─────────────────────────────────────────────────────────┐
│                    HOST COMPUTER                        │
│  ┌─────────────────┐         ┌─────────────────────┐   │
│  │   CONTAINER 1   │         │    CONTAINER 2      │   │
│  │   (Attacker     │         │   (Target Web App)  │   │
│  │    Tools)       │         │                     │   │
│  │                 │         │                     │   │
│  │ • nmap          │  ═══►   │ • Vulnerable Flask  │   │
│  │ • nikto         │         │   Application       │   │
│  │ • gobuster      │         │ • Backdoor endpoints│   │
│  │ • Analysis tools│         │ • SQL injection     │   │
│  └─────────────────┘         └─────────────────────┘   │
│           ▲                            ▲               │
│           │                            │               │
│     ISOLATED FROM HOST          ISOLATED FROM HOST     │
│     Can't damage your           Can't escape and       │
│     real computer              damage real systems     │
└─────────────────────────────────────────────────────────┘
```

**What this means for students:**

- ✅ **Safe to run malware**: Even real viruses can't escape the container
- ✅ **No risk to your computer**: Container isolation protects your files and
  data
- ✅ **No network access to real systems**: Containers can only talk to each
  other
- ✅ **Easily reset**: If something goes wrong, just restart the container

#### 2. **Educational Value: Mirrors Real-World Security**

**Professional Security Teams Use Containers For:**

- **Malware Analysis Labs**: Safely analyzing suspicious files
- **Penetration Testing**: Testing attacks without damaging production systems
- **Incident Response**: Recreating attack scenarios for investigation
- **Security Research**: Studying new threats in controlled environments

**This gives students real professional experience with:**

- Industry-standard isolation techniques
- Professional security testing environments
- Real-world incident response procedures
- Enterprise security architecture patterns

#### 3. **Our Two-Container Architecture Explained**

**Why do we use TWO containers instead of one?**

```
EDUCATIONAL DESIGN PATTERN: "Attacker vs Target"

Container 1: "Security Analyst Workstation"
┌─────────────────────────────────────┐
│  🛠️  SECURITY TOOLS CONTAINER       │
│                                     │
│  Purpose: Professional security     │
│  testing environment               │
│                                     │
│  Contents:                          │
│  • nmap (network scanning)         │
│  • nikto (web vulnerability scan)  │
│  • gobuster (directory brute force)│
│  • strace (system call monitoring) │
│  • tcpdump (network packet capture)│
│  • Python security libraries       │
│                                     │
│  Real-world parallel:               │
│  Penetration tester's laptop       │
└─────────────────────────────────────┘
              │
              │ Controlled Network
              │ Connection
              ▼
┌─────────────────────────────────────┐
│  🎯  TARGET APPLICATION CONTAINER   │
│                                     │
│  Purpose: Vulnerable application    │
│  to practice testing against       │
│                                     │
│  Contents:                          │
│  • Vulnerable Flask web app        │
│  • Intentional security flaws      │
│  • Hidden backdoor endpoints       │
│  • SQL injection vulnerabilities   │
│  • Insecure configurations         │
│                                     │
│  Real-world parallel:               │
│  Customer's web application        │
│  being tested for security         │
└─────────────────────────────────────┘
```

**Educational Benefits of This Design:**

1. **🎭 Role-Playing**: Students experience both sides of security testing

   - **Attacker perspective**: "How would I test this application?"
   - **Defender perspective**: "What vulnerabilities exist in our app?"

2. **🏢 Professional Realism**: Mirrors real penetration testing scenarios

   - Security consultant tests external client applications
   - Internal security team tests company applications
   - Red team vs blue team exercises

3. **🔍 Clear Separation of Concerns**:

   - **Tools container**: Clean, professional testing environment
   - **Target container**: Focused, vulnerable application
   - **No confusion**: Students know which environment they're working in

4. **🛡️ Enhanced Security**: Double isolation
   - Even if the target application is compromised, tools remain safe
   - Each container has minimal necessary components
   - Network traffic is controlled and monitored

### 🌐 Network Isolation and Security

#### Container Network Architecture

```
Internet ❌ BLOCKED
    │
    ▼
┌─────────────────────────────────────┐
│           HOST SYSTEM               │
│                                     │
│  ┌─────────────────────────────────┐│
│  │     DOCKER BRIDGE NETWORK       ││
│  │        172.20.0.0/16            ││
│  │                                 ││
│  │  ┌─────────────┐ ┌─────────────┐││
│  │  │ Tools       │ │ Target App  │││
│  │  │ Container   │ │ Container   │││
│  │  │ 172.20.0.2  │ │ 172.20.0.3  │││
│  │  └─────────────┘ └─────────────┘││
│  │         │               │       ││
│  │         └───────────────┘       ││
│  │         Internal Network        ││
│  │         Communication Only      ││
│  └─────────────────────────────────┘│
│                                     │
│  Port Forwarding for Access:       │
│  localhost:8080 → Tools Container  │
│  localhost:5000 → Target App       │
└─────────────────────────────────────┘
```

**Security Features:**

- ✅ **No external internet access**: Malware can't phone home
- ✅ **Controlled communication**: Containers can only talk to each other
- ✅ **Host protection**: Containers can't access host files or processes
- ✅ **Port isolation**: Only specific ports are exposed for educational access

### 🔄 Container Lifecycle for Security Testing

#### Professional Workflow

```
1. PREPARATION
   │
   ├── Create clean container environment
   ├── Install security testing tools
   ├── Configure monitoring and logging
   └── Verify isolation boundaries
   │
   ▼
2. TESTING PHASE
   │
   ├── Deploy target application
   ├── Execute security tests
   ├── Monitor for malicious behavior
   └── Collect evidence and logs
   │
   ▼
3. ANALYSIS PHASE
   │
   ├── Analyze collected data
   ├── Identify security vulnerabilities
   ├── Document findings
   └── Generate security report
   │
   ▼
4. CLEANUP
   │
   ├── Stop and remove containers
   ├── Save important logs/reports
   ├── Reset environment for next test
   └── Secure disposal of test data
```

**Educational Value:**

- Students learn the complete professional security testing lifecycle
- Experience with industry-standard container orchestration
- Understanding of proper evidence handling and cleanup procedures
- Practice with professional documentation and reporting

### 🛠️ Container Commands Students Will Use

#### Essential Container Operations

```bash
# View our educational container architecture
docker-compose ps

# Enter the security tools environment (attacker workstation)
docker exec -it cybersec_sandbox bash

# View container resource usage
docker stats cybersec_sandbox pwa_flask_app

# View container network information
docker network inspect docker_sandbox_network

# Restart containers if needed (clean slate)
docker-compose restart

# View container logs for troubleshooting
docker logs cybersec_sandbox
```

#### Understanding What Each Command Does

- **`docker-compose ps`**: Shows our two-container setup (like checking if both
  apartments are occupied)
- **`docker exec -it cybersec_sandbox bash`**: Enters the tools container (like
  walking into the security analyst's office)
- **`docker stats`**: Shows resource usage (like monitoring apartment utility
  usage)
- **`docker network inspect`**: Shows network configuration (like viewing
  apartment building network setup)

### 🎓 Learning Objectives: Containerization Concepts

By completing this exercise, students will understand:

#### Technical Skills

- ✅ **Container isolation principles**: How containers protect the host system
- ✅ **Network segmentation**: How container networks provide security
  boundaries
- ✅ **Resource management**: How containers limit resource usage
- ✅ **Professional tools deployment**: How to use containers for security
  testing

#### Cybersecurity Concepts

- ✅ **Defense in depth**: Multiple layers of isolation and protection
- ✅ **Controlled testing environments**: Safe spaces for dangerous activities
- ✅ **Professional methodologies**: Industry-standard security testing
  approaches
- ✅ **Risk management**: How isolation reduces testing risks

#### Real-World Applications

- ✅ **Malware analysis**: Safe environments for studying malicious software
- ✅ **Penetration testing**: Controlled environments for security assessments
- ✅ **Incident response**: Recreating attack scenarios for investigation
- ✅ **Security research**: Studying new threats without risk

## 🧪 Lab Environment Setup

### ✅ Prerequisites Check

**Step 1: Navigate to main folder**

```bash
cd /workspaces/Docker_Sandbox_Demo
pwd
```

**Expected Output:**

```
/workspaces/Docker_Sandbox_Demo
```

**Step 2: Enter the security sandbox container**

```bash
docker exec -it cybersec_sandbox bash
```

**Expected Output:**

```
root@container:/#
```

**What this means:** You're now inside a safe, isolated environment for testing

**Step 3: Navigate to the analysis workspace**

```bash
cd /sandbox/analysis
pwd
```

**Expected Output:**

```
/sandbox/analysis
```

**Step 4: Verify analysis tools are available**

```bash
which strace && echo "✅ strace available" || echo "❌ strace missing"
which netstat && echo "✅ netstat available" || echo "❌ netstat missing"
which ps && echo "✅ ps available" || echo "❌ ps missing"
```

**Expected Output:**

```
✅ strace available
✅ netstat available
✅ ps available
```

**❌ If Something Goes Wrong:**

- **Container not found?** Run:
  `cd /workspaces/Docker_Sandbox_Demo/docker && docker-compose up -d`
- **Can't enter container?** Wait a moment and try again:
  `docker exec -it cybersec_sandbox bash`
- **Tools missing?** This is normal - focus on the Python analysis tools

### 🔧 Analysis Tools (What Each One Does)

**System Call Monitoring:**

- **strace**: Records every system call an application makes (like keeping a
  diary of everything it does)

**Network Monitoring:**

- **netstat**: Shows current network connections (like seeing who's talking to
  whom)
- **tcpdump**: Captures network traffic (like recording phone conversations)

**Process Monitoring:**

- **ps**: Shows running processes (like seeing who's currently working)
- **top**: Shows resource usage (like monitoring how much work everyone is
  doing)

**File System Monitoring:**

- **inotifywait**: Watches for file changes (like security cameras for files)
- **lsof**: Shows what files are open (like seeing what documents people are
  reading)

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

### 🎯 Goal: Analyze a suspicious Python script in a controlled environment to identify potential security threats

### Step 1: Prepare the Sandbox Environment

**Make sure you're in the sandbox container:**

```bash
# If you're not already in the container, enter it:
docker exec -it cybersec_sandbox bash

# Navigate to the analysis workspace
cd /sandbox/analysis
pwd
```

**Expected Output:**

```
/sandbox/analysis
```

**Create a workspace for this analysis:**

```bash
# Create folders for our analysis
mkdir -p suspicious_script_analysis
cd suspicious_script_analysis
```

### Step 2: Examine the Suspicious Script (Safely!)

**Look at the script WITHOUT executing it:**

```bash
cat ../samples/suspicious_script.py
```

**Expected Output (sample - will vary):**

```python
#!/usr/bin/env python3
import os
import socket
import subprocess

# This script might contain:
# - Network connections
# - File operations
# - System commands
# - Potentially suspicious behavior
```

**What to look for (note these patterns):**

- **Network connections**: `socket.connect()`, `urllib.request`
- **File operations**: `open()`, `write()`, `os.remove()`
- **System commands**: `subprocess.call()`, `os.system()`
- **Obfuscated code**: Base64 encoding, strange variable names

**Document your observations:**

```bash
echo "=== STATIC ANALYSIS NOTES ===" > analysis_report.txt
echo "Suspicious patterns observed:" >> analysis_report.txt
echo "- Network connections: [YES/NO]" >> analysis_report.txt
echo "- File operations: [YES/NO]" >> analysis_report.txt
echo "- System commands: [YES/NO]" >> analysis_report.txt
echo "- Obfuscated code: [YES/NO]" >> analysis_report.txt
echo "" >> analysis_report.txt
```

### Step 3: Set Up Monitoring

**Start system call monitoring (this records everything the script does):**

```bash
# Start monitoring system calls
strace -o syscalls.log -f python ../samples/suspicious_script.py &
SCRIPT_PID=$!
echo "Script running with PID: $SCRIPT_PID"
```

**Start network monitoring:**

```bash
# Capture network state before the script runs
netstat -tupln > network_before.log
echo "Network state captured before execution"
```

**What this monitoring does:**

- **strace**: Records every system call (like keeping a detailed diary)
- **netstat**: Shows network connections (like taking a snapshot of phone calls)

### Step 4: Execute and Monitor (Safely in Sandbox)

**Let the script run for 30 seconds:**

```bash
echo "Letting script run for 30 seconds..."
sleep 30
```

**Capture final network state:**

```bash
netstat -tupln > network_after.log
echo "Network state captured after execution"
```

**Stop the script safely:**

```bash
kill $SCRIPT_PID 2>/dev/null || echo "Script already finished"
```

### Step 5: Analyze Results

**Analyze system calls (what the script actually did):**

```bash
echo "=== FILE OPERATIONS ===" >> analysis_report.txt
grep -E "(openat|write|read)" syscalls.log | head -10 >> analysis_report.txt

echo "=== NETWORK OPERATIONS ===" >> analysis_report.txt
grep -E "(socket|connect|bind)" syscalls.log | head -10 >> analysis_report.txt

echo "=== PROCESS OPERATIONS ===" >> analysis_report.txt
grep -E "(execve|fork|clone)" syscalls.log | head -10 >> analysis_report.txt
```

**Compare network states:**

```bash
echo "=== NEW NETWORK CONNECTIONS ===" >> analysis_report.txt
diff network_before.log network_after.log >> analysis_report.txt || echo "No network changes detected" >> analysis_report.txt
```

**View your complete analysis:**

```bash
cat analysis_report.txt
```

**Expected Output (sample):**

```
=== STATIC ANALYSIS NOTES ===
Suspicious patterns observed:
- Network connections: YES
- File operations: YES
- System commands: NO
- Obfuscated code: NO

=== FILE OPERATIONS ===
openat(AT_FDCWD, "/tmp/suspicious_file.txt", O_WRONLY|O_CREAT, 0666) = 3
write(3, "Suspicious data", 15) = 15

=== NETWORK OPERATIONS ===
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
connect(4, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("192.168.1.100")}, 16) = 0

=== PROCESS OPERATIONS ===
execve("/usr/bin/python3", ["python3", "../samples/suspicious_script.py"], ...) = 0

=== NEW NETWORK CONNECTIONS ===
No network changes detected
```

### Step 6: Document Your Findings

**Create a security assessment:**

```bash
cat >> analysis_report.txt << 'EOF'

=== SECURITY ASSESSMENT ===
Risk Level: [HIGH/MEDIUM/LOW]
Malicious Behavior Detected: [YES/NO]

Evidence Summary:
1. File System Activity:
   - Files created/modified:
   - Suspicious file locations:

2. Network Activity:
   - Outbound connections attempted:
   - Suspicious ports used:

3. System Activity:
   - Processes spawned:
   - System commands executed:

Conclusion:
This script appears to be [MALICIOUS/SUSPICIOUS/BENIGN] because:
[Your reasoning here]

Recommended Actions:
1. [Action 1]
2. [Action 2]
3. [Action 3]
EOF
```

### Expected Results Summary

Students should identify:

- ✅ Unauthorized file access attempts
- ✅ Suspicious network connection attempts
- ✅ System call patterns indicating malicious behavior
- ✅ Resource consumption patterns
- ✅ Evidence of data exfiltration or backdoor communication

**Fill out your assessment:**

**Suspicious Script Analysis Worksheet:**

1. **Static Analysis Findings:**

   - Network code found: ⚪ Yes ⚪ No
   - File operations found: ⚪ Yes ⚪ No
   - System commands found: ⚪ Yes ⚪ No
   - Obfuscated code found: ⚪ Yes ⚪ No

2. **Dynamic Analysis Findings:**

   - Files created/modified: ******\_\_\_******
   - Network connections attempted: **\_\_\_\_**
   - Suspicious system calls: ******\_\_******

3. **Risk Assessment:**

   - Overall Risk: ⚪ High ⚪ Medium ⚪ Low
   - Malicious behavior detected: ⚪ Yes ⚪ No
   - Confidence level: \_\_\_\_/10

4. **Evidence Summary:**
   - Most suspicious finding: ******\_\_\_******
   - Why this is concerning: ******\_\_\_******
   - Recommended response: ******\_\_\_\_******

**❌ Troubleshooting:**

- **Script won't run?** Check you're in the sandbox:
  `docker exec -it cybersec_sandbox bash`
- **Permission denied?** Make sure you're in `/sandbox/analysis` directory
- **No output in logs?** This might be normal - the script may be benign or
  well-behaved
- **strace not working?** Try just running the script normally and observing its
  behavior

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

Identify applications that abuse system resources, such as cryptocurrency
miners.

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

**Scenario**: You've been given a suspicious Python script that claims to be a
"system optimizer" but users report slow performance after running it.

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
