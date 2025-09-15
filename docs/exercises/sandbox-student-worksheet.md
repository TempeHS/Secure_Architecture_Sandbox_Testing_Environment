# Sandbox Security Analysis - Student Worksheet

**Name**: ________________________  **Date**: ________________________  **Period**: ________

## 🎯 Learning Objectives

By completing this worksheet, I will:
- [ ] Understand what sandbox security analysis is and how it differs from SAST and DAST
- [ ] Practice setting up secure analysis environments for testing suspicious applications
- [ ] Learn to monitor system calls, network activity, and resource usage
- [ ] Identify malicious behavior patterns in applications
- [ ] Document security findings with proper evidence

## 📚 Pre-Exercise Knowledge Check

### 1. Security Testing Methods Comparison
Fill in the comparison table:

| Method | What it analyzes | When it runs | Safety level |
|--------|------------------|--------------|--------------|
| SAST | _________________ | _____________ | _____________ |
| DAST | _________________ | _____________ | _____________ |
| Sandbox | _________________ | _____________ | _____________ |

### 2. Risk Scenarios
**Scenario**: You receive an email with an attachment claiming to be a "System Performance Booster.exe"

**Question**: What are the potential risks of running this file directly on your computer?
____________________________________________________________________________
____________________________________________________________________________

**Question**: How could sandbox analysis help you safely determine if this file is malicious?
____________________________________________________________________________
____________________________________________________________________________

## 🧪 Exercise 1: Basic Behavioral Analysis

### Setup Phase
**Task**: Set up monitoring for the suspicious Python script

1. **Enter the sandbox environment**:
   ```bash
   Command to run: _________________________________________
   ```

2. **Navigate to the analysis workspace**:
   ```bash
   Command to run: _________________________________________
   ```

3. **Examine the script safely** (without running it):
   ```bash
   Command to run: _________________________________________
   ```

**Initial Observations**:
What does the script claim to do? ___________________________________________________
Do you notice any suspicious imports or functions? _____________________________
____________________________________________________________________________

### Monitoring Setup
4. **Set up system call tracing**:
   ```bash
   Command to run: _________________________________________
   ```

5. **Record baseline network state**:
   ```bash
   Command to run: _________________________________________
   ```

### Analysis Phase
6. **Execute the script under monitoring** and let it run for 30 seconds

7. **Analyze system calls for file operations**:
   ```bash
   Command to run: _________________________________________
   ```

**File Access Findings**:
What files did the script try to access? ___________________________________________
____________________________________________________________________________
Are any of these concerning? Why? ________________________________________________
____________________________________________________________________________

8. **Analyze system calls for network operations**:
   ```bash
   Command to run: _________________________________________
   ```

**Network Activity Findings**:
What network connections did the script attempt? ______________________________
____________________________________________________________________________
What data might have been transmitted? ____________________________________________

### Risk Assessment
**Question**: Based on your analysis, is this script malicious? Explain your reasoning:
____________________________________________________________________________
____________________________________________________________________________

**Question**: What potential damage could this script cause if run on a real system?
____________________________________________________________________________
____________________________________________________________________________

## 🌐 Exercise 2: Web Application Backdoor Detection

### Discovery Phase
**Task**: Find hidden functionality in the web application

1. **Test normal web pages**:
   ```bash
   URLs tested:
   - http://localhost:5000/ : _______________________________________________
   - http://localhost:5000/about : _________________________________________
   - http://localhost:5000/contact : _______________________________________
   ```

2. **Use directory enumeration to find hidden endpoints**:
   ```bash
   Command to run: _________________________________________
   ```

**Hidden Endpoints Discovered**:
List any suspicious or hidden URLs you found:
- ________________________________________________________________________
- ________________________________________________________________________
- ________________________________________________________________________

### Backdoor Analysis
3. **Test the hidden endpoints**:
   ```bash
   Command 1: ______________________________________________________________
   Result: _________________________________________________________________
   
   Command 2: ______________________________________________________________
   Result: _________________________________________________________________
   ```

**Backdoor Capabilities**:
What can an attacker do through these hidden endpoints?
____________________________________________________________________________
____________________________________________________________________________

### Security Impact Assessment
**Risk Level** (Circle one):   LOW    MEDIUM    HIGH    CRITICAL

**Justification**: Why did you choose this risk level?
____________________________________________________________________________
____________________________________________________________________________

**Potential Impact**: What could an attacker accomplish with this backdoor?
____________________________________________________________________________
____________________________________________________________________________

## ⚡ Exercise 3: Resource Abuse Detection

### Baseline Measurement
**Task**: Detect applications that abuse system resources

1. **Record initial system state**:
   ```bash
   Commands to run:
   - CPU usage: ____________________________________________________________
   - Memory usage: _________________________________________________________
   ```

**Baseline Measurements**:
- Current CPU usage: ______%
- Available memory: _____________
- Number of running processes: _____________

### Resource Monitoring
2. **Start the suspicious "maintenance tool"**:
   ```bash
   Command to run: _________________________________________
   ```

3. **Monitor resource consumption for 60 seconds**:
   ```bash
   Commands to run every 10 seconds:
   - ____________________________________________________________________
   - ____________________________________________________________________
   ```

**Resource Consumption Observations**:
Fill in the monitoring data:

| Time (seconds) | CPU Usage (%) | Memory Usage | Suspicious Activity |
|----------------|---------------|--------------|-------------------|
| 0 (baseline) | _____ | _____ | _________________ |
| 10 | _____ | _____ | _________________ |
| 20 | _____ | _____ | _________________ |
| 30 | _____ | _____ | _________________ |
| 40 | _____ | _____ | _________________ |
| 50 | _____ | _____ | _________________ |
| 60 | _____ | _____ | _________________ |

### Network Activity Analysis
4. **Check for suspicious network connections**:
   ```bash
   Command to run: _________________________________________
   ```

**Network Findings**:
What external servers is the application trying to connect to?
____________________________________________________________________________
____________________________________________________________________________

Why might these connections be suspicious?
____________________________________________________________________________
____________________________________________________________________________

### Behavioral Pattern Analysis
**Question**: What type of malicious software does this behavior pattern suggest?
____________________________________________________________________________

**Question**: How could you confirm your suspicion?
____________________________________________________________________________
____________________________________________________________________________

## 📊 Synthesis and Reflection

### Threat Summary
Complete the threat analysis table:

| Application | Threat Type | Risk Level | Key Evidence | Recommended Action |
|-------------|-------------|------------|--------------|-------------------|
| Suspicious Script | __________ | __________ | ____________ | _________________ |
| Backdoor Web App | __________ | __________ | ____________ | _________________ |
| Resource Abuser | __________ | __________ | ____________ | _________________ |

### Critical Thinking Questions

1. **Detection Evasion**: How might malicious software try to avoid detection in sandbox environments?
   ____________________________________________________________________________
   ____________________________________________________________________________

2. **Real-World Application**: In what professional situations would sandbox analysis be most valuable?
   ____________________________________________________________________________
   ____________________________________________________________________________

3. **Limitations**: What are the limitations of sandbox analysis? What might it miss?
   ____________________________________________________________________________
   ____________________________________________________________________________

4. **Defense Strategy**: Based on today's exercise, what defensive measures would you recommend for an organization?
   ____________________________________________________________________________
   ____________________________________________________________________________

### Tool Mastery Checklist
Check off the tools and techniques you've successfully used:

**System Monitoring**:
- [ ] `strace` - System call tracing
- [ ] `netstat` - Network connection monitoring
- [ ] `top`/`htop` - Resource usage monitoring
- [ ] `lsof` - File access monitoring

**Analysis Techniques**:
- [ ] Baseline establishment
- [ ] Behavioral pattern recognition
- [ ] Evidence collection and documentation
- [ ] Risk assessment and classification

**Security Concepts**:
- [ ] Sandbox isolation principles
- [ ] Malicious behavior indicators
- [ ] Network traffic analysis
- [ ] Resource abuse detection

## 🏆 Challenge Questions (Optional)

### Advanced Analysis
**Challenge 1**: Research a real-world malware family (e.g., Zeus, Conficker, WannaCry). How would sandbox analysis help identify its malicious behavior?
____________________________________________________________________________
____________________________________________________________________________

**Challenge 2**: Design a theoretical malware that could evade the detection techniques we used today. What would it do differently?
____________________________________________________________________________
____________________________________________________________________________

### Career Connection
**Challenge 3**: Research the role of a "Malware Analyst" or "Incident Response Specialist." How do they use sandbox analysis in their daily work?
____________________________________________________________________________
____________________________________________________________________________

## 📝 Self-Assessment

Rate your confidence level (1-5, where 5 = very confident):

- Understanding sandbox analysis concepts: _____/5
- Setting up monitoring environments: _____/5
- Identifying malicious behavior patterns: _____/5
- Using command-line analysis tools: _____/5
- Documenting security findings: _____/5

**What was the most challenging part of this exercise?**
____________________________________________________________________________
____________________________________________________________________________

**What was the most interesting discovery you made?**
____________________________________________________________________________
____________________________________________________________________________

**What would you like to learn more about?**
____________________________________________________________________________
____________________________________________________________________________

---

**Completed by**: ________________________  **Date**: ________________________  
**Instructor Review**: ________________________  **Grade**: ________________