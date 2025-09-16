# Network Traffic Analysis - Instructor Guide

## 📚 Overview

This instructor guide teaches students how to monitor computer networks for security threats. Think of it like being a security guard watching all the doors and windows of a building to see who's coming and going.

**Class Duration**: 3-4 hours  
**Student Level**: Beginner to Intermediate (basic computer skills required)  
**Group Size**: 15-25 students (individual work recommended)

### 💡 For Non-Technical Instructors
**Don't worry about networking expertise!** This guide explains everything in simple terms. Network analysis = watching computer communications to spot suspicious activity (like monitoring phone calls for fraud).

## 🎯 Learning Outcomes (Student-Friendly Goals)

Students will understand:
1. **Network monitoring basics** - How to watch computer communications for threats
2. **Suspicious patterns** - How to spot bad guys trying to break in
3. **Service discovery** - What programs are running and accepting connections
4. **Traffic analysis** - Understanding normal vs dangerous network activity
5. **Professional reporting** - How to document and communicate findings

## 📍 Important: Navigation Instructions

**All commands start from the main project folder. If you or students get lost:**
```bash
# Return to the main project folder (copy and paste this)
cd /workspaces/Docker_Sandbox_Demo

# Check you're in the right place (should see folders like 'src', 'samples', 'docker')
ls
```

## 🛠️ Pre-Class Setup (15 minutes)

### ✅ Environment Verification Checklist:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Test the network analysis tool (should show help information)
python src/analyzer/network_cli.py --help

# Step 3: Test basic network monitoring (should show current connections)
python src/analyzer/network_cli.py --monitor-connections --educational --quiet

# Step 4: Check that system tools work (should show version or usage info)
netstat --help
ss --help
```

### 🎯 What Should Happen:
- Network tool shows help information (means it's working)
- Monitor command shows connection data (even if empty)
- System tools respond with help text (means they're available)

### ❌ If Something's Wrong:
Use the troubleshooting section at the bottom of this guide

## 📋 Simple Lesson Plan

### 🚀 Introduction (30 minutes)

#### Opening Hook (5 minutes)
**🎯 Ask Students**: "How would you know if someone was secretly using your WiFi or trying to hack your computer?"
- Discuss the importance of monitoring network activity
- Share news stories about network attacks (like hospital ransomware)
- Introduce the concept of "network security guards"

#### 🌐 Network Analysis Overview (15 minutes)
**💬 Key Teaching Points (Use Simple Analogies)**:

**What is Network Analysis?**
- Like being a security guard monitoring all doors and windows
- Watching who comes and goes from your computer
- Different from other security methods we've learned:
  - **SAST** = Reading building blueprints for problems
  - **DAST** = Testing if doors and windows lock properly  
  - **Sandbox** = Watching suspicious people in a safe room
  - **Network** = Monitoring all foot traffic around the building

#### 💻 Simple Demo for Class:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Show current network connections (like seeing who's visiting)
netstat -tuln | head -10

# Step 3: Use our specialized monitoring tool
python src/analyzer/network_cli.py --monitor-connections --educational
```

**💬 Explain to Students**: "The first command shows basic connections, the second command is like having a professional security system that gives much more detail."

#### 🛠️ Tool Introduction (10 minutes)
**Essential Tools (Explain with Simple Analogies)**:
- **network_cli.py**: Our professional network security system
- **netstat**: Basic connection viewer (like looking out a window)
- **ss**: Modern version of netstat (like having security cameras)
- **nmap**: Network scanner (like walking around checking all doors and windows)

### 🔍 Exercise 1: Watching Network Connections (45 minutes)

#### 📍 Setup Phase (10 minutes)
**🎯 Instructor Demonstration**:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Start monitoring network activity
python src/analyzer/network_cli.py --monitor-connections --educational --verbose

# Step 3: Show what normal connections look like
echo "These are the current connections on our system"
```

**💬 Explain to Students**: "This shows us who our computer is talking to right now. Just like a phone bill shows who you called, this shows what websites and servers our computer is communicating with."

**👥 Student Activity**: Students run the same commands to see their baseline network state

#### 🕵️ Analysis Phase (25 minutes)
**🎯 Guided Discovery** (help students interpret what they see):

**1. 🌐 Looking for Normal Web Connections**:
```bash
# Look for standard web traffic (ports 80 and 443)
netstat -tuln | grep ":80\|:443\|:22"
```
**💬 Explain**: "Port 80 = regular websites, Port 443 = secure websites (HTTPS), Port 22 = secure remote access"
**✅ Expected Finding**: Should see web services if any websites are running

**2. ⚠️ Looking for Suspicious Ports**:
```bash
# Search for common hacker ports
netstat -tuln | grep -E ":4444|:6666|:1337|:31337"
```
**💬 Explain**: "These port numbers are commonly used by hackers for backdoors and remote control"
**✅ Expected Finding**: Should find NONE in a normal, secure environment

**3. 🌍 Looking for External Communications**:
```bash
# See what external servers we're talking to
netstat -tuln | grep -v "127.0.0.1\|::1"
```
**💬 Explain**: "127.0.0.1 means 'talking to ourselves' - anything else means talking to other computers"
**✅ Expected Finding**: May see connections to external websites and services

#### 💭 Discussion Phase (10 minutes)
**🎯 Key Questions for Class Discussion**:

**Q**: "What should you be worried about in network connections?"
**A**: Help students identify:
- ✅ Connections on ports 80/443 are normal for web browsing
- ⚠️ Connections on ports 4444/6666/1337 are suspicious (hacker favorites)
- ⚠️ Too many connections to the same IP might mean scanning
- ⚠️ Connections to unknown countries might be suspicious

**Q**: "How could attackers use network connections to hurt you?"
**A**: Discuss real scenarios:
- Steal personal files and send them to criminal servers
- Install remote control software (backdoors)
- Use your computer to attack other people

**Q**: "Why is monitoring network activity important?"
**A**: Emphasize that:
- You can catch attacks as they happen
- You can collect evidence for police/IT security
- You can block suspicious connections before damage occurs

### 🔍 Exercise 2: Finding What Services Are Running (45 minutes)

#### 🎯 Discovery Phase (20 minutes)
**💬 What Are Services?**
Services = programs that wait for other computers to connect to them
- Like having different employees at different desk numbers in a company
- Port numbers = desk numbers (Port 80 = web service desk, Port 22 = secure access desk)

**💻 Student Task**: Find what services are running on our computer
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Scan our own computer for services
python src/analyzer/network_cli.py --scan-services localhost --educational

# Step 3: Use built-in system tools to double-check
netstat -tuln | grep LISTEN
```

**🎯 Teaching Strategy - Provide Hints Progressively**:
1. **First hint**: "Look for common port numbers like 22, 80, 443"
2. **Second hint**: "LISTEN means a service is waiting for connections"
3. **Final hint**: "Research what each port number is typically used for"

#### ✅ Expected Services Students Should Find:
- **Port 22**: SSH (secure remote access - good but monitor for break-in attempts)
- **Port 80**: HTTP (insecure websites - should upgrade to HTTPS)
- **Port 443**: HTTPS (secure websites - good)
- **Port 3389**: RDP (Windows remote desktop - high risk, should be firewalled)
- **Port 5900**: VNC (remote screen sharing - high risk, weak security)

#### ⚠️ Security Analysis Phase (15 minutes)
**💻 Risk Assessment Commands for Students**:
```bash
# Step 1: Save service scan results
python src/analyzer/network_cli.py --scan-services localhost --educational > services_found.txt

# Step 2: Look for high-risk services
cat services_found.txt | grep -E "3389|5900|23|21"

# Step 3: Count total services found
cat services_found.txt | grep -c "Port"
```

**🎯 Teaching Students to Assess Risk**:
- **Green (Safe)**: Ports 443 (HTTPS), 53 (DNS)
- **Yellow (Monitor)**: Ports 22 (SSH), 80 (HTTP)
- **Red (Dangerous)**: Ports 23 (Telnet), 21 (FTP), 3389 (RDP), 5900 (VNC)

#### 📝 Documentation Phase (10 minutes)
**👥 Student Activity** - Have students fill out this table:

| Port Found | Service Name | Risk Level | Why Risky? |
|------------|-------------|------------|-------------|
| 22 | SSH | Medium | Could be brute-forced |
| 80 | HTTP | Medium | Unencrypted web traffic |
| 443 | HTTPS | Low | Encrypted and secure |
| 3389 | RDP | High | Weak authentication, often targeted |

### 🌐 Exercise 3: Analyzing Network Traffic Patterns (40 minutes)

#### 📊 Baseline Establishment (10 minutes)
**💬 What is a Baseline?**
Baseline = understanding what normal network activity looks like
- Like knowing your normal daily routine to spot when something unusual happens
- Helps distinguish between normal activity and potential attacks

**💻 Commands for Students**:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Capture normal network activity for 30 seconds
python src/analyzer/network_cli.py --capture-traffic --duration 30 --educational

# Step 3: Save baseline for comparison
echo "Baseline captured - this shows our normal network behavior"
```

#### 🎭 Activity Generation (15 minutes)
**💻 Generate Different Types of Network Activity**:
```bash
# Create legitimate network activity (safe to run)
curl http://httpbin.org/get
curl http://httpbin.org/post -d "test=data"

# Simulate suspicious activity (these will fail safely - that's the point)
for port in 4444 6666 1337; do
    timeout 1 nc -z malicious-server.example.com $port 2>/dev/null || echo "Suspicious connection attempt failed (expected)"
done
```

**💬 Explain to Students**: "We're creating both normal activity (like visiting websites) and suspicious activity (like trying to connect to hacker servers) to see the difference."

#### 📈 Pattern Analysis (15 minutes)
**🎯 Key Metrics Students Should Analyze**:

**💻 Analysis Commands**:
```bash
# Step 1: Look at protocol usage
netstat -s | grep -E "tcp|udp" | head -5

# Step 2: Check for failed connections (sign of scanning or attacks)
dmesg | grep -i "connection" | tail -5

# Step 3: Monitor active connections
python src/analyzer/network_cli.py --monitor-connections --educational
```

**✅ Expected Findings Students Should Observe**:
- **Normal Activity**: HTTP requests to legitimate servers (httpbin.org)
- **DNS Activity**: Name lookups for websites
- **Failed Connections**: Attempts to reach suspicious/non-existent servers
- **Protocol Patterns**: Mostly TCP for web traffic, some UDP for DNS

**🎯 Teaching Points**:
- **Many failed connections = possible scanning attack**
- **Connections to unusual countries = possible data theft**
- **High network usage = possible data exfiltration**
- **Regular, automated patterns = possible malware**

### 🔍 Exercise 4: DNS Analysis (30 minutes)

#### 💬 What is DNS?
**DNS = Domain Name System** (like a phone book for the internet)
- Converts website names (google.com) to computer addresses (172.217.164.110)
- Attackers often abuse DNS for hidden communication
- Monitoring DNS can reveal malware and data theft

#### 🎯 DNS Monitoring Setup (10 minutes)
**💻 Commands for Students**:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Start monitoring DNS activity
python src/analyzer/network_cli.py --dns-analysis --duration 30 --educational

# Step 3: Generate normal DNS activity in another terminal
# (Students can open a second terminal window)
```

#### 🌐 Query Generation (10 minutes)
**💻 Create Normal vs Suspicious DNS Activity**:
```bash
# Normal, legitimate DNS queries
nslookup google.com
nslookup github.com
nslookup youtube.com

# Suspicious DNS queries (these will fail - that's the point)
nslookup very-long-suspicious-domain.evil.com 2>/dev/null || echo "Suspicious domain failed (expected)"
nslookup c2-server.malware.net 2>/dev/null || echo "Malware domain failed (expected)"
```

**💬 Explain to Students**: "We're testing both normal website lookups and suspicious domain names that real malware might use."

#### 🚨 Pattern Recognition (10 minutes)
**🎯 DNS Threat Indicators Students Should Learn**:

**⚠️ Warning Signs in DNS Activity**:
- **Very long domain names** (might be hiding data in the name)
- **Random-looking domain names** (generated by malware)
- **Many failed DNS lookups** (malware trying to contact dead servers)
- **High frequency of DNS queries** (possible data tunneling)

**💻 Analysis Commands**:
```bash
# Look for failed DNS queries
grep -i "fail\|error" /var/log/syslog | grep -i dns | tail -5 2>/dev/null || echo "No DNS errors found"

# Check for unusual domain patterns
echo "Look for domains with random letters or very long names in your DNS monitoring output"
```

**✅ Expected Findings Students Should See**:
- **Normal DNS patterns**: Queries to major websites (google.com, etc.)
- **Suspicious query attempts**: Failed lookups to malware-related domains
- **Query frequency analysis**: Normal queries are sporadic, attacks are often frequent

**🎯 Real-World Examples to Share**:
- **DNSChanger malware** redirected users to fake websites through DNS
- **Conficker worm** used DNS to find new command servers
- **DNS tunneling** lets attackers steal data through DNS queries

### 📝 Assessment and Wrap-up (30 minutes)

#### 💼 Practical Assessment (20 minutes)
**📋 Scenario for Students**: "You're the IT security person for a small company. Analyze this simulated network activity and write a report."

**💻 Assessment Commands**:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Run comprehensive network analysis
python src/analyzer/network_cli.py --demo-network --educational

# Step 3: Students analyze results and write brief report
```

**✅ Assessment Criteria for Teachers**:
1. **Tool Usage**: Can students run commands correctly?
2. **Threat Identification**: Do they spot suspicious patterns?
3. **Evidence Documentation**: Can they explain what they found?
4. **Risk Assessment**: Do they understand which problems are most dangerous?

#### 🧠 Quick Knowledge Check (10 minutes)
**💭 Simple Quiz Questions for Class**:

**Q1**: "Which port numbers are commonly used by hackers for backdoors?"
**A**: 4444, 6666, 1337, 31337

**Q2**: "What might lots of failed DNS queries indicate?"
**A**: Possible malware trying to contact command servers, or DNS tunneling attempts

**Q3**: "Name three signs of suspicious network activity"
**A**: Port scanning (many connection attempts), unusual foreign connections, high data transfer to unknown servers

**Q4**: "Why is network monitoring important for cybersecurity?"
**A**: Catches attacks in real-time, provides evidence for investigations, helps block threats before damage

## 🚨 Simple Troubleshooting Guide

### ❌ Problem: Students can't see network connections
**✅ Solution**:
```bash
# Try alternative commands
ss -tuln  # newer version of netstat

# Use our demo data if no real connections
cd /workspaces/Docker_Sandbox_Demo
python src/analyzer/network_cli.py --demo-network --educational
```

### ❌ Problem: "Permission denied" for network monitoring
**✅ Solution**:
```bash
# Use connection monitoring instead of packet capture
python src/analyzer/network_cli.py --monitor-connections --educational

# Explain to students: "Full packet capture requires administrator privileges"
```

### ❌ Problem: Network tools not found
**✅ Solution**:
```bash
# Check what tools are available
which netstat ss nmap

# Use built-in Python tools if system tools missing
python src/analyzer/network_cli.py --scan-services localhost
```

### ❌ Problem: Students get confused by technical output
**✅ Teaching Strategy**:
- **Focus on patterns**: "Look for the port numbers we discussed (22, 80, 443, 4444)"
- **Use the grep commands provided**: They filter out most technical details
- **Emphasize concepts**: Understanding threat types is more important than reading every detail

**🎯 Pro Tip**: Practice all commands yourself before class and prepare simple explanations for common output patterns!
