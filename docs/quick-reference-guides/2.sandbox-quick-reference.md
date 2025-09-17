# Sandbox Security Analysis - Quick Reference

## 🚀 Essential Commands

### Container Environment Setup (Security by Design)

```bash
# Enter secure analysis container (application isolation)
docker exec -it cybersec_sandbox bash

# Navigate to analysis workspace (controlled environment)
cd /sandbox/analysis

# Check available tools (resource limitation)
which strace netstat top lsof
```

**Educational Context**: This demonstrates **safe execution environments for
untrusted code** - a key principle in **security by design**. The container
provides **application isolation and containment** while allowing comprehensive
**behavioral analysis and threat detection**.

### Understanding Our Educational Architecture

**Professional Security Testing Pattern:**

```
SECURITY ANALYST CONTAINER              TARGET APPLICATION CONTAINER
+----------------------------+            +---------------------------+
|                            |            |                           |
| Security Tools:            |            | Test Targets:             |
|                            |            |                           |
| - System call monitoring   |            | - Vulnerable web apps     |
| - Network traffic analysis |            | - Suspicious scripts      |
| - Process behavior tracking|            | - Malware samples         |
| - Resource usage monitoring|            | - Resource abuse tools    |
| - File system surveillance |            | - Backdoor applications   |
|                            |            |                           |
| IP: 172.20.0.2             |            | IP: 172.20.0.3            |
+----------------------------+            +---------------------------+
            |                                          |
            +-------------- Network Bridge ------------+
                      (172.20.0.0/16 subnet)
```

**Key Benefits for Security Testing:**

- **Isolation**: Malware cannot escape to damage host system
- **Monitoring**: Complete visibility into application behavior
- **Control**: Resource limits prevent system abuse
- **Repeatability**: Clean environment for each test
- **Safety**: Professional-grade security boundaries

### System Call Monitoring (Behavioral Analysis and Threat Detection)

```bash
# Basic system call tracing - monitors all application behaviors
strace -o trace.log python suspicious_script.py

# Trace specific system calls - focused threat detection
strace -e trace=openat,connect,write python script.py

# Trace with timestamps - incident response chronology
strace -t -o trace.log python script.py

# Follow child processes - comprehensive coverage
strace -f -o trace.log python script.py
```

**Educational Context**: System call tracing demonstrates **resource limitation
and monitoring** principles. By recording every system interaction, we can
detect **file attacks**, **unauthorized access attempts**, and **malicious
behavior patterns** safely within our container environment.

### Network Monitoring (Secure Communication Analysis)

```bash
# Current network connections - baseline establishment
netstat -tupln

# Monitor active connections for a process - target-specific analysis
netstat -tupln | grep PID

# List files opened by process (including sockets) - comprehensive monitoring
lsof -p PID

# Show only network connections - communication pattern analysis
lsof -p PID | grep ESTABLISHED
```

**Educational Context**: Network monitoring in our containerized environment
demonstrates **secure communication protocols** analysis. The container's
network isolation ensures that even malicious network activity cannot reach
external systems, enabling safe study of **attack patterns** and **threat
indicators**.

### Resource Monitoring

```bash
# Real-time process monitoring
top -p PID

# Single snapshot
top -b -n 1 -p PID

# Memory usage
free -h

# Process tree
pstree -p PID

# Thread information
ps -T -p PID
```

### File System Monitoring

```bash
# Monitor file access in real-time
inotifywait -m -r --format '%w%f %e' /tmp

# Monitor specific events
inotifywait -m -e create,modify,delete /tmp

# Find recently created files
find /tmp -type f -newermt "5 minutes ago"
```

## 🔍 Analysis Patterns

### System Call Analysis

```bash
# File operations
grep -E "(openat|read|write)" trace.log

# Network operations
grep -E "(socket|connect|bind)" trace.log

# Process operations
grep -E "(execve|fork|clone)" trace.log

# Specific file access
grep "/etc/passwd" trace.log
grep "/home" trace.log
```

### Network Analysis

```bash
# Before/after network comparison
netstat -tupln > before.log
# ... run suspicious application ...
netstat -tupln > after.log
diff before.log after.log

# Find listening services
netstat -tupln | grep LISTEN

# Find external connections
netstat -tupln | grep -v "127.0.0.1\|::1"
```

### Web Application Testing

```bash
# Basic endpoint testing
curl http://localhost:5000/
curl http://localhost:5000/admin
curl http://localhost:5000/debug

# Directory enumeration
dirb http://localhost:5000/ /usr/share/dirb/wordlists/common.txt

# Common backdoor paths
curl http://localhost:5000/shell
curl http://localhost:5000/cmd
curl http://localhost:5000/backdoor

# Command execution testing
curl "http://localhost:5000/backdoor?cmd=whoami"
curl "http://localhost:5000/admin?cmd=ls%20-la"
```

## 🚨 Malicious Behavior Indicators

### File System Indicators

- Access to sensitive files (`/etc/passwd`, `/etc/shadow`)
- Creation of hidden files (starting with `.`)
- Writing to system directories (`/tmp`, `/var/tmp`)
- Modifying configuration files

### Network Indicators

- Connections to unusual ports (4444, 6666, 8080)
- Connections to suspicious domains
- Outbound connections on common malware ports
- Data exfiltration patterns

### Process Indicators

- High CPU usage (>80% sustained)
- Multiple threads/processes
- Unusual process names
- Hidden or obfuscated processes

### Resource Abuse Indicators

- Sustained high CPU/memory usage
- Network connections to mining pools
- Unusual disk I/O patterns
- Process persistence mechanisms

## 🛡️ Common Malware Types

### Information Stealers

**Behavior**: Access sensitive files, capture credentials **Indicators**:

- Reading `/etc/passwd`, browser files
- Network connections to C&C servers
- File exfiltration patterns

### Backdoors/RATs

**Behavior**: Provide remote access to attackers **Indicators**:

- Listening on unusual ports
- Command execution capabilities
- Hidden web interfaces

### Cryptocurrency Miners

**Behavior**: Use system resources for mining **Indicators**:

- High CPU usage across multiple cores
- Connections to mining pools
- Long-running processes

### Ransomware

**Behavior**: Encrypt files and demand payment **Indicators**:

- Mass file encryption
- Creation of ransom notes
- File extension changes

## 🔧 Troubleshooting

### Common Issues

```bash
# Permission denied errors
sudo chmod +x script.py

# Container not accessible
docker-compose restart cybersec_sandbox

# Too much trace output
strace -e trace=file python script.py

# Process not found
ps aux | grep python
```

### Log Analysis Tips

```bash
# Count specific events
grep -c "openat" trace.log

# Show unique file accesses
grep "openat" trace.log | cut -d'"' -f2 | sort -u

# Filter by return codes
grep "= -1" trace.log  # Failed system calls
grep "= 0" trace.log   # Successful calls
```

## 📊 Quick Risk Assessment

### Severity Levels

- **CRITICAL**: Remote code execution, system compromise
- **HIGH**: Data theft, privilege escalation
- **MEDIUM**: Information disclosure, resource abuse
- **LOW**: Minor configuration issues

### Evidence Quality

- **STRONG**: Multiple indicators, clear malicious intent
- **MODERATE**: Some suspicious behavior, needs investigation
- **WEAK**: Minimal indicators, might be false positive

## 🎯 Analysis Workflow

### 1. Preparation (5 minutes)

- [ ] Set up monitoring tools
- [ ] Record baseline system state
- [ ] Prepare safe execution environment

### 2. Static Examination (10 minutes)

- [ ] Examine file without execution
- [ ] Check for obvious indicators
- [ ] Research any suspicious strings/URLs

### 3. Dynamic Execution (20 minutes)

- [ ] Start monitoring tools
- [ ] Execute application safely
- [ ] Observe behavior patterns
- [ ] Stop execution and analysis

### 4. Analysis (15 minutes)

- [ ] Review system call logs
- [ ] Analyze network activity
- [ ] Check resource consumption
- [ ] Identify malicious patterns

### 5. Documentation (10 minutes)

- [ ] Document findings
- [ ] Assess risk level
- [ ] Recommend actions
- [ ] Save evidence

## 📱 Mobile & Web App Testing

### Web Application Backdoors

```bash
# Common backdoor endpoints
/admin, /debug, /shell, /cmd, /backdoor
/admin.php, /shell.php, /c.php, /r.php
/wp-admin, /phpmyadmin, /admin/console

# Parameter testing
?cmd=whoami
?command=ls
?exec=id
?system=uname
```

### Mobile App Analysis

```bash
# Android APK analysis
unzip app.apk
grep -r "http://" .
grep -r "password" .

# iOS IPA analysis
unzip app.ipa
strings Payload/App.app/App | grep -E "(http|password|secret)"
```

## �️ Safety Reminders (Security by Design Principles)

### Professional Security Testing Standards

- ⚠️ **Never** run suspicious code outside containerized sandbox environments
- ⚠️ **Always** use isolated environments for **safe execution of untrusted
  code**
- ⚠️ **Verify** container isolation before testing malicious applications
- ⚠️ **Document** everything for evidence and **incident response** procedures
- ⚠️ **Report** confirmed threats following proper **disclosure protocols**

**Educational Value**: These practices mirror professional **security management
strategies** used in:

- **Malware analysis laboratories** (corporate security teams)
- **Incident response investigations** (forensics and containment)
- **Security research facilities** (vulnerability discovery)
- **Penetration testing engagements** (ethical hacking assessments)

### Container Security Verification

```bash
# Verify container isolation boundaries
docker inspect cybersec_sandbox | grep -A5 SecurityOpt

# Check resource limitations are active
docker stats cybersec_sandbox --no-stream

# Confirm network segmentation
docker network inspect docker_sandbox_network
```

**Why This Matters**: Container verification ensures our **application isolation
and containment** is functioning properly, providing the **safe execution
environment** necessary for analyzing potentially dangerous software.

### Emergency Commands (Incident Response Procedures)

```bash
# Kill runaway processes (containment)
pkill -f suspicious_script.py

# Reset sandbox environment (clean slate)
docker-compose down && docker-compose up -d

# Check container isolation (security verification)
docker inspect cybersec_sandbox | grep -A5 SecurityOpt
```

**Professional Connection**: These emergency procedures mirror real-world
**incident response and containment** protocols used when security threats are
detected in production environments.

---

**Duration**: 3-4 hours  
**Difficulty**: Intermediate  
**Prerequisites**: Basic Linux command line  
**Tools**: Docker, strace, netstat, top, lsof
