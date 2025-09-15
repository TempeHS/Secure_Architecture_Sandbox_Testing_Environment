# Sandbox Security Analysis - Quick Reference

## 🚀 Essential Commands

### Environment Setup
```bash
# Enter sandbox container
docker exec -it cybersec_sandbox bash

# Navigate to analysis workspace
cd /sandbox/analysis

# Check available tools
which strace netstat top lsof
```

### System Call Monitoring
```bash
# Basic system call tracing
strace -o trace.log python suspicious_script.py

# Trace specific system calls
strace -e trace=openat,connect,write python script.py

# Trace with timestamps
strace -t -o trace.log python script.py

# Follow child processes
strace -f -o trace.log python script.py
```

### Network Monitoring
```bash
# Current network connections
netstat -tupln

# Monitor active connections for a process
netstat -tupln | grep PID

# List files opened by process (including sockets)
lsof -p PID

# Show only network connections
lsof -p PID | grep ESTABLISHED
```

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
**Behavior**: Access sensitive files, capture credentials
**Indicators**: 
- Reading `/etc/passwd`, browser files
- Network connections to C&C servers
- File exfiltration patterns

### Backdoors/RATs
**Behavior**: Provide remote access to attackers
**Indicators**:
- Listening on unusual ports
- Command execution capabilities
- Hidden web interfaces

### Cryptocurrency Miners
**Behavior**: Use system resources for mining
**Indicators**:
- High CPU usage across multiple cores
- Connections to mining pools
- Long-running processes

### Ransomware
**Behavior**: Encrypt files and demand payment
**Indicators**:
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

## 🔒 Safety Reminders

### Always Remember
- ⚠️ **Never** run suspicious code outside sandbox
- ⚠️ **Always** use isolated environments
- ⚠️ **Verify** container isolation before testing
- ⚠️ **Document** everything for evidence
- ⚠️ **Report** confirmed threats to authorities

### Emergency Commands
```bash
# Kill runaway processes
pkill -f suspicious_script.py

# Reset sandbox environment
docker-compose down && docker-compose up -d

# Check container isolation
docker inspect cybersec_sandbox | grep -A5 SecurityOpt
```

---

**Duration**: 3-4 hours  
**Difficulty**: Intermediate  
**Prerequisites**: Basic Linux command line  
**Tools**: Docker, strace, netstat, top, lsof