# Network Traffic Analysis Exercise

## 📖 Overview

Network Traffic Analysis is a cybersecurity technique that monitors, captures, and analyzes network communications to detect security threats, unauthorized access, and malicious activities. Unlike SAST (which analyzes code), DAST (which tests applications), and Sandbox analysis (which monitors application behavior), network analysis focuses on communication patterns and data flows between systems.

**Think of it this way:** If your computer network is like a building, network traffic analysis is like being a security guard who watches all the doors and windows to see who comes in, who goes out, and what they're carrying.

**Key Learning Objectives:**
- ✅ Understand what network traffic analysis is and its role in cybersecurity
- ✅ Learn to monitor active network connections and identify suspicious activity
- ✅ Practice using network scanning tools to discover services and vulnerabilities
- ✅ Analyze network traffic patterns for signs of malicious behavior
- ✅ Detect network-based attacks like port scanning, data exfiltration, and C&C communication
- ✅ Generate comprehensive network security reports

## 📍 Getting Started - Important Navigation

**� Always start from the main project folder:**
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

## �🎯 Security Analysis Method Comparison

| Aspect | SAST (Static) | DAST (Dynamic) | Sandbox Analysis | Network Analysis |
|--------|---------------|----------------|------------------|------------------|
| **Focus** | Source code vulnerabilities | Runtime app testing | Behavioral monitoring | Network communication |
| **When to Use** | During development | During runtime | During execution | During operation |
| **Detection** | Code-level flaws | Runtime vulnerabilities | Malicious behavior | Network threats |
| **Examples** | Hardcoded secrets | XSS, SQL injection | Malware, data theft | Port scans, C&C traffic |
| **Real-World Analogy** | Proofreading essay | Testing a speech | Watching someone work | Monitoring building entrances |
| **Scope** | Application code | Application interface | System behavior | Network traffic |
| **Real-time** | No | Limited | Yes | Yes |

## 🌐 What is Network Traffic Analysis?

### Definition
Network Traffic Analysis involves monitoring, capturing, and analyzing network communications to understand data flows, detect security threats, and ensure network security compliance.

### 🔍 Real-World Analogy
Think of network traffic analysis like being a security guard at a busy building:
- **Monitoring entrances**: Watching who comes and goes (connections)
- **Checking IDs**: Verifying who people claim to be (authentication)
- **Noting suspicious behavior**: Someone trying every door (port scanning)
- **Tracking packages**: What people are carrying in and out (data transfer)
- **Spotting patterns**: Regular visitors vs. unusual activity

### Key Characteristics:
- **Real-time Monitoring**: Observes network activity as it happens
- **Pattern Recognition**: Identifies suspicious communication patterns
- **Protocol Analysis**: Understands different network protocols and their behaviors
- **Threat Detection**: Spots indicators of network-based attacks

### Why Network Analysis Matters:
- **Early Threat Detection**: Catches attacks as they traverse the network
- **Incident Response**: Provides crucial evidence during security incidents
- **Compliance Monitoring**: Ensures adherence to security policies
- **Performance Optimization**: Identifies network bottlenecks and issues

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

**Step 2: Test the network analysis tool**
```bash
python src/analyzer/network_cli.py --help
```
**Expected Output (first few lines):**
```
usage: network_cli.py [-h] [--monitor-connections] [--scan-services HOST] [--capture-traffic] [--dns-analysis] [--educational] [--verbose] [--duration DURATION] [--format {text,json}] [--output OUTPUT]

Network Traffic Analysis tool for educational purposes
```

**Step 3: Verify system network tools**
```bash
which netstat && echo "✅ netstat available" || echo "❌ netstat missing"
which ss && echo "✅ ss available" || echo "❌ ss missing" 
which nmap && echo "✅ nmap available" || echo "❌ nmap missing"
```
**Expected Output:**
```
✅ netstat available
✅ ss available  
✅ nmap available
```

**❌ If Something Goes Wrong:**
- **Tool not found?** Make sure you're in: `cd /workspaces/Docker_Sandbox_Demo`
- **Network tools missing?** This is normal in some environments - our custom tools will work
- **Permission errors?** Try the commands with educational flags - they simulate results safely

## 🛠️ Educational Network Analysis Tools

### Our Custom Tools (Safe for Learning):
- **network_cli.py**: Our custom educational network analysis tool with safety features
- **netstat**: Display network connections and statistics
- **ss**: Modern replacement for netstat with better performance  
- **nmap**: Network mapping and port scanning (educational mode)

### What Each Tool Does:
- **Connection Monitoring**: Who is talking to whom right now?
- **Service Discovery**: What services are running and accessible?
- **Traffic Pattern Analysis**: What kind of data is flowing through the network?
- **DNS Traffic Analysis**: What websites/servers are being contacted?

## 🎯 Network Analysis Techniques

### 1. Connection Monitoring
Monitor active network connections to identify suspicious activity:
```bash
# Monitor current connections
python src/analyzer/network_cli.py --monitor-connections --educational

# Quick connection check
netstat -tuln
ss -tuln
```

### 2. Service Discovery
Scan for network services and analyze their security posture:
```bash
# Scan localhost services
python src/analyzer/network_cli.py --scan-services localhost --educational

# Scan specific target
python src/analyzer/network_cli.py --scan-services 192.168.1.1
```

### 3. Traffic Pattern Analysis
Analyze network traffic for suspicious patterns:
```bash
# Capture and analyze traffic
python src/analyzer/network_cli.py --capture-traffic --duration 60 --educational

# Monitor specific protocols
python src/analyzer/network_cli.py --capture-traffic --filter "tcp port 80"
```

### 4. DNS Traffic Analysis
Monitor DNS queries for malicious domains and tunneling:
```bash
# Analyze DNS patterns
python src/analyzer/network_cli.py --dns-analysis --duration 30 --educational
```

## 📋 Hands-On Exercise 1: Network Connection Monitoring

### 🎯 Goal: Monitor active network connections to identify potentially suspicious communication patterns

### Step 1: Baseline Network State

**Make sure you're in the right place:**
```bash
cd /workspaces/Docker_Sandbox_Demo
pwd  # Should show /workspaces/Docker_Sandbox_Demo
```

**Record current network connections:**
```bash
python src/analyzer/network_cli.py --monitor-connections --educational
```

**Expected Output:**
```
🌐 NETWORK CONNECTION MONITORING
📅 Timestamp: 2025-XX-XX XX:XX:XX
🎓 Educational Mode: Enabled

ACTIVE CONNECTIONS:
🔍 TCP Connections:
  localhost:5000 (Flask App) - Status: LISTENING
  localhost:9090 (PWA App) - Status: LISTENING
  localhost:22 (SSH) - Status: LISTENING

📊 Connection Summary:
  Total Active: 15 connections
  Listening Services: 3
  Outbound Connections: 2
  Suspicious Patterns: 0
```

**Also try the manual approach:**
```bash
netstat -tuln | head -20
```
**Expected Output:**
```
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:9090          0.0.0.0:*               LISTEN
```

**What this means:**
- **LISTEN**: Service waiting for connections (like a store that's open)
- **Port 22**: SSH (secure remote access)
- **Port 5000**: Our Flask application
- **Port 9090**: Our PWA application

### Step 2: Analyze Connection Patterns

**Run comprehensive connection analysis:**
```bash
python src/analyzer/network_cli.py --monitor-connections --educational --verbose
```

**Expected Additional Output:**
```
🔍 DETAILED CONNECTION ANALYSIS:

NORMAL PATTERNS DETECTED:
✅ Web server listening on standard ports
✅ SSH service for remote administration
✅ Local application services

SECURITY ASSESSMENT:
🔵 Low Risk: Standard service ports detected
⚠️ Medium Risk: Debug services may be running
🚨 High Risk: No immediate threats detected

RECOMMENDATIONS:
💡 Monitor for connections to unusual ports (1337, 4444, 6666)
💡 Watch for excessive connections from single IPs
💡 Alert on connections to known malicious IPs
```

**Look for specific patterns:**
```bash
netstat -tuln | grep ":80\|:443\|:22\|:3389"
```

**What you're looking for:**
- **Port 80**: HTTP web traffic  
- **Port 443**: HTTPS secure web traffic
- **Port 22**: SSH (secure shell)
- **Port 3389**: Remote Desktop (potentially risky)

### Step 3: Identify Suspicious Activity

**Check for connections to unusual ports:**
```bash
netstat -tuln | grep -E ":4444|:6666|:1337|:31337"
```
**Expected Output:** 
```
(No output expected - these are malicious ports that shouldn't be in use)
```

**If you see output here, it could indicate:**
- **Port 4444**: Common backdoor/malware port
- **Port 6666**: Often used by malicious software
- **Port 1337/31337**: "Leet" ports used by hackers

**Look for excessive connections from single IPs:**
```bash
netstat -tuln | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr
```
**Expected Output:**
```
      5 127.0.0.1    (localhost - normal)
      2 0.0.0.0      (all interfaces - normal)
      1 192.168.1.10 (example internal IP)
```

### Step 4: Document Your Findings

**Create your assessment (fill this out):**

**Network Connection Assessment Worksheet:**

1. **Total Active Connections Found**: _____________

2. **Services Listening (check all that apply)**:
   - [ ] SSH (Port 22) - Remote access
   - [ ] HTTP (Port 80) - Web service
   - [ ] HTTPS (Port 443) - Secure web service  
   - [ ] Flask App (Port 5000) - Our test application
   - [ ] PWA App (Port 9090) - Our test application
   - [ ] Other: _______________

3. **Suspicious Activity Found**:
   - [ ] Connections to unusual ports (1337, 4444, 6666)
   - [ ] Excessive connections from single IP addresses
   - [ ] Connections to external IPs on non-standard ports
   - [ ] None detected ✅

4. **Risk Assessment**:
   - Overall Risk Level: ⚪ Low ⚪ Medium ⚪ High
   - Most Concerning Finding: ________________________
   - Recommended Actions: ___________________________

### Expected Results Summary
Students should identify:
- ✅ Normal web server connections (ports 5000, 9090)
- ✅ SSH connections (port 22) if present
- ✅ Any unusual or suspicious port usage
- ✅ External vs internal IP communications
- ✅ Difference between LISTENING services and active connections

**❌ Troubleshooting:**
- **No connections shown?** Try: `ss -tuln` instead of `netstat -tuln`
- **Permission denied?** Use our educational tools: `python src/analyzer/network_cli.py --monitor-connections --educational`
- **Too much output?** Add `| head -20` to any command to see just the first 20 lines

## 📋 Hands-On Exercise 2: Network Service Discovery

### Objective
Discover network services and assess their security implications.

### Steps

#### Step 1: Scan Local Services
```bash
# Comprehensive localhost scan
python src/analyzer/network_cli.py --scan-services localhost --educational --verbose

# Quick manual check
netstat -tuln | grep LISTEN
```

#### Step 2: Analyze Service Security
```bash
# Generate detailed service report
python src/analyzer/network_cli.py --scan-services localhost --format json --output service_scan.json

# Check for high-risk services
netstat -tuln | grep -E ":21|:23|:3389|:5900"
```

#### Step 3: Research Service Vulnerabilities
```bash
# Examine specific services found
# If SSH is running:
ssh -V

# If web server is running:
curl -I http://localhost:80 2>/dev/null | head -5
```

### Expected Results
Students should discover:
- ✅ Web services (HTTP/HTTPS)
- ✅ SSH services if available
- ✅ Any unusual or unnecessary services
- ✅ Security implications of each service

## 📋 Hands-On Exercise 3: Traffic Pattern Analysis

### Objective
Analyze network traffic patterns to identify potential security threats.

### Steps

#### Step 1: Baseline Traffic Capture
```bash
# Start traffic monitoring
python src/analyzer/network_cli.py --capture-traffic --duration 30 --educational
```

#### Step 2: Generate Network Activity
```bash
# In another terminal, generate some network activity
curl http://httpbin.org/get
curl http://httpbin.org/post -d "test=data"
ping -c 5 8.8.8.8

# Try some potentially suspicious activity
curl http://malicious-server.example.com 2>/dev/null || echo "Connection failed (expected)"
```

#### Step 3: Analyze Traffic Patterns
```bash
# Comprehensive traffic analysis with reporting
python src/analyzer/network_cli.py --capture-traffic --duration 60 --format json --output traffic_analysis.json --educational
```

### Expected Results
Students should observe:
- ✅ HTTP requests to legitimate servers
- ✅ DNS resolution activity
- ✅ Any failed connection attempts
- ✅ Protocol usage patterns

## 📋 Hands-On Exercise 4: DNS Traffic Analysis

### Objective
Monitor DNS queries to detect malicious domain communication and DNS tunneling.

### Steps

#### Step 1: Monitor DNS Activity
```bash
# Start DNS monitoring
python src/analyzer/network_cli.py --dns-analysis --duration 30 --educational
```

#### Step 2: Generate DNS Queries
```bash
# Generate legitimate DNS queries
nslookup google.com
nslookup github.com
dig @8.8.8.8 stackoverflow.com

# Simulate suspicious queries (these will fail)
nslookup malicious-c2.example.com 2>/dev/null || echo "Query failed (expected)"
nslookup very-long-subdomain-that-might-be-tunneling.evil.com 2>/dev/null || echo "Query failed (expected)"
```

#### Step 3: Analyze DNS Patterns
```bash
# Comprehensive DNS analysis
python src/analyzer/network_cli.py --dns-analysis --duration 60 --format json --educational --output dns_analysis.json
```

### Expected Results
Students should identify:
- ✅ Normal DNS resolution patterns
- ✅ Any suspicious domain queries
- ✅ DNS query frequency and patterns
- ✅ Potential DNS tunneling indicators

## 🎓 Learning Assessment

### Knowledge Check Questions

1. **What is the primary purpose of network traffic analysis?**
   - A) To optimize application performance
   - B) To monitor and detect network-based security threats
   - C) To fix code vulnerabilities
   - D) To test web applications

2. **Which tool would best detect a port scanning attack?**
   - A) Static code analyzer
   - B) Web application scanner
   - C) Network traffic monitor
   - D) File system monitor

3. **What does a connection to port 4444 typically indicate?**
   - A) Web server traffic
   - B) Email communication
   - C) Potentially malicious backdoor
   - D) DNS queries

4. **Which analysis method provides real-time threat detection?**
   - A) Static Application Security Testing (SAST)
   - B) Network Traffic Analysis
   - C) Code review
   - D) Binary analysis

### Practical Assessment

**Scenario**: Your organization's security team has detected unusual network activity. Multiple internal systems are making connections to an external IP address on port 4444, and there's been a significant increase in DNS queries to suspicious domains.

**Your Task**:
1. Use network analysis tools to investigate the activity
2. Identify the scope of the potential compromise
3. Document your findings with evidence
4. Recommend immediate actions

**Success Criteria**:
- ✅ Proper use of network monitoring tools
- ✅ Accurate identification of suspicious patterns
- ✅ Comprehensive documentation of findings
- ✅ Appropriate risk assessment and recommendations

## 🎯 Real-World Applications

### Industry Use Cases
- **Security Operations Centers (SOCs)**: 24/7 network monitoring and threat detection
- **Incident Response**: Investigating and containing network-based attacks
- **Compliance Auditing**: Ensuring network communications meet regulatory requirements
- **Threat Hunting**: Proactively searching for advanced persistent threats

### Career Connections
- **Network Security Analyst**: Monitors and analyzes network traffic for threats
- **SOC Analyst**: Operates security monitoring tools and responds to alerts
- **Incident Response Specialist**: Investigates and contains security breaches
- **Penetration Tester**: Uses network analysis to identify vulnerabilities

## 📚 Additional Resources

### Advanced Tools for Further Learning
- **Wireshark**: Comprehensive packet analysis and network protocol analyzer
- **Zeek (formerly Bro)**: Network security monitoring framework
- **Suricata**: Intrusion detection system with network monitoring
- **ntopng**: Web-based network traffic monitoring

### Reference Materials
- NIST Cybersecurity Framework - Network Security Guidelines
- MITRE ATT&CK Framework - Network-based Tactics and Techniques
- "Network Security Monitoring" by Richard Bejtlich
- "Applied Network Security Monitoring" by Hjelmvik & Sanders

### Next Steps
1. Learn advanced packet analysis with Wireshark
2. Study network protocols in depth (TCP/IP, HTTP, DNS)
3. Explore machine learning approaches to network anomaly detection
4. Practice with capture-the-flag (CTF) network challenges

---

**Duration**: 3-4 hours  
**Difficulty**: Intermediate  
**Prerequisites**: Basic networking knowledge and command line skills  
**Tools Required**: Network analysis CLI, netstat, ss, basic network utilities