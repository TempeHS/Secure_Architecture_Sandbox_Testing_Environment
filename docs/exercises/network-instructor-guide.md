# Network Traffic Analysis - Instructor Guide

## 📚 Overview

This instructor guide provides complete teaching materials, setup instructions, answer keys, and assessment tools for the Network Traffic Analysis exercise. This exercise teaches students how to monitor and analyze network communications to detect security threats and understand network-based attacks.

**Class Duration**: 3-4 hours  
**Student Level**: Intermediate (basic networking knowledge required)  
**Group Size**: 15-25 students (individual work recommended)

## 🎯 Learning Outcomes

### Primary Objectives
Students will demonstrate ability to:
1. **Explain network traffic analysis concepts** and differentiate from SAST/DAST/Sandbox methods
2. **Monitor network connections** and identify suspicious communication patterns
3. **Perform service discovery** and assess security implications
4. **Analyze traffic patterns** for indicators of compromise
5. **Generate professional reports** with evidence and recommendations

### Assessment Rubric

| Criteria | Excellent (4) | Proficient (3) | Developing (2) | Beginning (1) |
|----------|---------------|----------------|----------------|---------------|
| **Conceptual Understanding** | Clearly explains network analysis vs other methods | Understands core concepts with minor gaps | Shows partial understanding | Limited understanding |
| **Tool Usage** | Expertly uses all network analysis tools | Uses tools correctly with minimal help | Requires some guidance | Needs significant assistance |
| **Threat Detection** | Identifies all suspicious patterns with evidence | Identifies most threats accurately | Identifies some threats | Misses major indicators |
| **Professional Reporting** | Excellent documentation with clear evidence | Good reports with minor gaps | Basic documentation | Poor or incomplete reports |

## 🛠️ Pre-Class Setup (30 minutes)

### Environment Verification
```bash
# Test network analysis environment
cd /workspaces/Docker_Sandbox_Demo
python src/analyzer/network_cli.py --help

# Verify system network tools
which netstat ss nmap
```

### Network Analysis Tool Testing
```bash
# Test all analysis modes
python src/analyzer/network_cli.py --demo-network --educational --quiet
python src/analyzer/network_cli.py --monitor-connections --quiet
python src/analyzer/network_cli.py --scan-services localhost --quiet
```

### Sample Network Activity Setup
Create these demonstration scenarios:

1. **Normal Baseline Activity**:
```bash
# Script: /tmp/normal_activity.sh
#!/bin/bash
# Generate normal network activity
curl -s http://httpbin.org/get > /dev/null &
curl -s http://httpbin.org/post -d "data=test" > /dev/null &
ping -c 3 8.8.8.8 > /dev/null &
```

2. **Suspicious Activity Simulation**:
```bash
# Script: /tmp/suspicious_activity.sh  
#!/bin/bash
# Simulate suspicious network patterns
for port in 4444 6666 1337 31337; do
    timeout 1 nc -z suspicious-server.example.com $port 2>/dev/null &
done

# Simulate DNS queries to suspicious domains
for domain in c2-server.evil.com backdoor.malware.net; do
    nslookup $domain 2>/dev/null || true &
done
```

## 📋 Lesson Plan

### Introduction (30 minutes)

#### Opening Hook (5 minutes)
**Question**: "How would you know if your network was being attacked right now?"
- Discuss the importance of network visibility
- Introduce real-time threat detection concepts

#### Network Analysis Overview (15 minutes)
**Key Teaching Points**:
1. **Definition**: Monitoring and analyzing network communications for security
2. **Comparison**: Different from SAST/DAST/Sandbox - focuses on network layer
3. **Real-time capability**: Can detect attacks as they happen
4. **Evidence collection**: Provides forensic evidence for investigations

**Interactive Demo**:
```bash
# Show current network connections
netstat -tuln | head -10

# Compare with comprehensive analysis
python src/analyzer/network_cli.py --monitor-connections --educational
```

#### Tool Introduction (10 minutes)
**Essential Tools**:
- `network_cli.py`: Our educational network analysis tool
- `netstat`: Display network connections
- `ss`: Modern socket statistics
- `nmap`: Network mapping and scanning

### Hands-On Exercise 1: Connection Monitoring (45 minutes)

#### Setup Phase (10 minutes)
**Instructor Demonstration**:
```bash
# Show baseline monitoring
python src/analyzer/network_cli.py --monitor-connections --educational --verbose
```

**Student Activity**: Students establish baseline network state

#### Analysis Phase (25 minutes)
**Guided Discovery**:
1. **Normal Connections**:
   ```bash
   netstat -tuln | grep ":80\|:443\|:22"
   ```
   **Expected Finding**: Web services and SSH if present

2. **Suspicious Ports**:
   ```bash
   netstat -tuln | grep -E ":4444|:6666|:1337"
   ```
   **Expected Finding**: Should find none in normal environment

3. **External Communications**:
   ```bash
   netstat -tuln | grep -v "127.0.0.1\|::1"
   ```
   **Expected Finding**: External IP communications

#### Discussion Phase (10 minutes)
**Key Questions**:
- What constitutes normal vs suspicious network activity?
- How can attackers use network connections?
- What should you investigate further?

**Answer Key**:
- ✅ Ports 80/443 are normal for web traffic
- ✅ Ports 4444/6666/1337 are suspicious (common backdoor ports)
- ✅ Excessive connections to single IPs may indicate scanning
- ✅ External communications should be monitored and validated

### Hands-On Exercise 2: Service Discovery (45 minutes)

#### Discovery Phase (20 minutes)
**Student Task**: Discover services running on localhost

**Instructor Hints** (provide progressively):
1. "Start with localhost scanning"
2. "Look for both TCP and UDP services"
3. "Research any unusual services found"

**Answer Key - Common Services**:
- Port 22: SSH (secure, but monitor for brute force)
- Port 80: HTTP (insecure, should use HTTPS)
- Port 443: HTTPS (secure)
- Port 3389: RDP (high risk, should be firewalled)
- Port 5900: VNC (high risk, weak authentication)

#### Security Analysis Phase (15 minutes)
**Risk Assessment Activity**:
```bash
python src/analyzer/network_cli.py --scan-services localhost --educational --format json
```

**Expected Security Findings**:
- ✅ HTTP services (unencrypted risk)
- ✅ Remote access services (authentication risk)
- ✅ Unnecessary services (attack surface risk)

#### Documentation Phase (10 minutes)
Students document:
- Services discovered and their purpose
- Security risk level for each service
- Recommended security controls

### Hands-On Exercise 3: Traffic Pattern Analysis (40 minutes)

#### Baseline Establishment (10 minutes)
```bash
# Establish traffic baseline
python src/analyzer/network_cli.py --capture-traffic --duration 30 --educational
```

#### Activity Generation (15 minutes)
**Controlled Network Activity**:
```bash
# Generate legitimate traffic
curl http://httpbin.org/get
curl http://httpbin.org/post -d "test=data"

# Generate suspicious patterns (will fail safely)
for port in 4444 6666 1337; do
    timeout 1 nc -z malicious-server.example.com $port 2>/dev/null || true
done
```

#### Pattern Analysis (15 minutes)
**Key Metrics to Analyze**:
- Protocol distribution (TCP vs UDP)
- Port usage patterns
- External vs internal communications
- Failed connection attempts

**Expected Findings**:
- ✅ HTTP requests to legitimate servers
- ✅ DNS resolution activity
- ✅ Failed connections to suspicious ports/hosts
- ✅ Normal protocol usage patterns

### Hands-On Exercise 4: DNS Analysis (30 minutes)

#### DNS Monitoring Setup (10 minutes)
```bash
# Start DNS monitoring
python src/analyzer/network_cli.py --dns-analysis --duration 30 --educational
```

#### Query Generation (10 minutes)
**Legitimate vs Suspicious Queries**:
```bash
# Legitimate queries
nslookup google.com
nslookup github.com

# Suspicious queries (will fail)
nslookup very-long-suspicious-domain.evil.com 2>/dev/null || echo "Failed (expected)"
```

#### Pattern Recognition (10 minutes)
**DNS Threat Indicators**:
- Long subdomain names (potential tunneling)
- Queries to suspicious TLDs
- High frequency queries
- Failed resolution attempts

**Expected Findings**:
- ✅ Normal DNS resolution patterns
- ✅ Suspicious domain query attempts
- ✅ DNS query frequency analysis

### Assessment and Wrap-up (30 minutes)

#### Practical Assessment (20 minutes)
**Scenario**: Students analyze a simulated network incident

**Assessment Criteria**:
1. Proper tool usage and methodology
2. Accurate threat identification
3. Evidence documentation
4. Risk assessment and recommendations

#### Knowledge Check (10 minutes)
**Quick Quiz Questions**:
1. Which ports are commonly used by backdoors? (Answer: 4444, 6666, 1337, 31337)
2. What does excessive DNS queries indicate? (Answer: Possible DNS tunneling)
3. Name three types of suspicious network patterns (Answer: Port scanning, C&C communication, data exfiltration)

## 🎯 Common Student Challenges

### Technical Issues
**Problem**: Students can't see network connections
**Solution**: 
```bash
# Use alternative commands
ss -tuln  # instead of netstat
python src/analyzer/network_cli.py --demo-network  # for demonstration data
```

**Problem**: Permission denied for packet capture
**Solution**: 
```bash
# Use connection monitoring instead
python src/analyzer/network_cli.py --monitor-connections
# Explain that packet capture requires elevated privileges
```

### Conceptual Difficulties
**Challenge**: Students confuse network analysis with other methods
**Teaching Strategy**: Create comparison chart and emphasize real-time network focus

**Challenge**: Students miss subtle network indicators
**Teaching Strategy**: Provide guided discovery with progressive hints

## 🔧 Troubleshooting Guide

### Environment Issues
```bash
# Reset network analysis environment
python src/analyzer/network_cli.py --demo-network --educational

# Check tool functionality
python src/analyzer/network_cli.py --help
```

### Network Tool Issues
```bash
# If netstat unavailable, use ss
ss -tuln

# If nmap unavailable, use built-in scanning
python src/analyzer/network_cli.py --scan-services localhost
```

## 📊 Assessment Answer Keys

### Exercise 1 - Connection Monitoring
**Expected Findings**:
1. **Normal Web Traffic**: 
   - Connections on ports 80, 443 (Low Risk)
   - SSH connections on port 22 (Monitor for brute force)

2. **Suspicious Indicators**:
   - Connections to ports 4444, 6666, 1337 (High Risk)
   - Excessive connections from single IP (Medium Risk)

3. **External Communications**:
   - Connections to external IPs (Information/Low Risk)
   - Failed connection attempts (Medium Risk)

### Exercise 2 - Service Discovery
**Expected Findings**:
1. **Common Services**:
   - HTTP (Port 80) - Unencrypted risk
   - HTTPS (Port 443) - Generally secure
   - SSH (Port 22) - Secure but monitor access

2. **Risk Assessment**:
   - High-risk services: Telnet (23), RDP (3389), VNC (5900)
   - Medium-risk services: HTTP (80), FTP (21)
   - Low-risk services: HTTPS (443), SSH with proper config (22)

### Exercise 3 - Traffic Analysis
**Expected Findings**:
1. **Protocol Analysis**:
   - TCP dominance for web traffic
   - UDP for DNS queries
   - Normal protocol distribution

2. **Suspicious Patterns**:
   - Failed connections to suspicious ports
   - Unusual data transfer volumes
   - Connections to unknown external hosts

### Exercise 4 - DNS Analysis
**Expected Findings**:
1. **Normal DNS Patterns**:
   - Resolution of common domains
   - Appropriate query frequency
   - Standard query types (A, AAAA, MX)

2. **Suspicious Indicators**:
   - Queries to suspicious domains
   - Unusually long subdomain names
   - High frequency or unusual patterns

## 📚 Extension Activities

### Advanced Challenges
1. **Real-time Monitoring**: Set up continuous network monitoring
2. **Incident Simulation**: Create realistic attack scenarios
3. **Tool Integration**: Combine multiple analysis tools

### Real-World Connections
- **Guest Speaker**: Invite SOC analyst or network security professional
- **Case Studies**: Analyze real network security incidents
- **Tool Demos**: Demonstrate commercial network monitoring solutions

---

**Total Class Time**: 3-4 hours  
**Preparation Time**: 30 minutes  
**Assessment Time**: 20 minutes  
**Cleanup Time**: 10 minutes