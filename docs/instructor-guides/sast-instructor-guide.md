# Static Application Security Testing (SAST) Exercise - Instructor Guide

## 🎯 Teaching Objectives

This exercise teaches students how to find security problems in software code before the software is run. Students learn to use automated tools to scan code and identify vulnerabilities like a security code review.

**💡 For Non-Technical Instructors**: This guide includes step-by-step commands and simple explanations. You don't need programming expertise to teach this effectively!

## ⏱️ Time Requirements

- **Total Duration**: 3-4 hours (can be split across multiple sessions)
- **Session 1** (1.5 hours): Introduction and Basic Analysis (What is SAST + First scanning exercise)
- **Session 2** (1.5-2 hours): Analyzing Different Applications (Comparing security across different programs)
- **Session 3** (30-60 minutes): Making Recommendations (How to fix the problems found)

## 👥 Class Size and Setup

- **Optimal Class Size**: 12-20 students
- **Setup**: Individual computers with Docker Sandbox Demo running
- **Prerequisites**: Basic computer skills (no programming knowledge required)

## 📍 Important: Navigation Instructions

**All commands start from the main project folder. If students get lost:**
```bash
# Return to the main project folder (copy and paste this)
cd /workspaces/Docker_Sandbox_Demo

# Check you're in the right place (should see folders like 'src', 'samples', 'docker')
ls
```

## 📋 Pre-Class Preparation (15 minutes)

### ✅ Technical Setup Checklist:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Verify the scanning tool works (should show help information)
python src/analyzer/analyze_cli.py --help

# Step 3: Check sample applications exist (should show file lists)
ls samples/vulnerable-flask-app/
ls samples/unsecure-pwa/

# Step 4: Test a quick scan (should show security findings)
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational
```

**✅ What Should Happen**:
- Help information displays (tool is working)
- Sample folders show Python files (sample apps are there)
- Quick scan shows security issues found (usually 10-20 issues)

**❌ If Something's Wrong**: Use the troubleshooting section at the bottom of this guide

## 🎓 Learning Progression (Simple Explanation)

### 🔍 Session 1: Understanding Code Security Scanning
**What Students Learn**: 
- SAST = automatically reading code to find security problems (like spell-check for security)
- How this is different from testing running software
- Basic tool usage and understanding results

**💬 Student-Friendly Analogy**: "SAST is like a security guard reading building blueprints before construction to spot safety problems, while other testing is like inspecting the finished building."

### 🔧 Session 2: Comparing Different Applications  
**What Students Learn**:
- Different types of software have different security risks
- How to compare security between multiple applications
- Understanding why some problems are more serious than others

### 📋 Session 3: Making Security Recommendations
**What Students Learn**:
- How to prioritize which problems to fix first
- Writing professional security recommendations
- Understanding business impact of security problems

## 📚 Exercise-by-Exercise Teaching Guide

### Exercise 1: SAST Fundamentals

#### 🎯 Key Teaching Points (Use Simple Language):
**What is SAST?**
- Static = looking at code without running it
- Analysis = automatically finding problems
- Security = specifically looking for security vulnerabilities
- Testing = part of the software quality process

**💻 Basic Command for Students**:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Run a basic security scan (takes 30-60 seconds)
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational

# Step 3: Count the problems found
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep "Total findings:"
```

#### 💭 Common Student Questions & Simple Answers:
**Q**: "Why doesn't this find ALL security problems?"
**A**: "It's like spell-check - it catches common mistakes but humans still need to review for context and logic errors."

**Q**: "Are some of these findings wrong?"
**A**: "Yes! Just like spell-check sometimes flags correct words, security tools sometimes flag safe code. That's why cybersecurity professionals verify the findings."

#### ✅ Expected Results for Students:
- Students see 40-50 security findings
- Most findings are labeled "High" or "Medium" severity
- Students can identify the total count of issues

### Exercise 2: Flask Application Analysis

#### 🎯 Key Teaching Points (Keep It Simple):
**What is SQL Injection?** 
- Like tricking a librarian by changing your library card request
- Attackers change database requests to steal information
- One of the most dangerous web application vulnerabilities

**💻 Commands for Students**:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Scan the Flask web application (takes 1-2 minutes)
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational

# Step 3: Look specifically for SQL injection problems
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep -i "sql"

# Step 4: Save results to a file for review
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational > flask_security_results.txt
```

#### 🎭 Simple Demonstration for Class:
**Show Students the Problem** (use the whiteboard or screen):
```
Unsafe Code (the problem):
"SELECT * FROM users WHERE username = '" + username + "'"

Safe Code (the solution):  
"SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

**💬 Explain**: "The first version lets attackers change the database query. The second version keeps user input separate from the query."

#### ✅ Expected Findings Students Should See:
- **Total Issues**: About 47 security problems
- **High Priority**: About 17 critical issues (including SQL injection)
- **Main Problem Types**: SQL injection, weak passwords, debug mode enabled
- **Files with Most Issues**: app.py (the main application file)

#### 🎯 Teaching Moments:
- When students find SQL injection, mention it affected Equifax (143 million people affected)
- Explain that debug mode gives attackers too much information
- Show how one security problem often leads to others

### Exercise 3: PWA Application Analysis

#### 🎯 Key Teaching Points (Student-Friendly):
**What is a PWA?**
- Progressive Web App = website that acts like a mobile app
- Can work offline and send notifications like regular apps
- Different security concerns than traditional websites

**💻 Commands for Students**:
```bash
# Step 1: Make sure you're in the main folder  
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Scan the PWA application
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational

# Step 3: Compare with previous results
echo "PWA Security Issues:"
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational | grep "Total findings:"
echo "Flask Security Issues:"  
cat flask_security_results.txt | grep "Total findings:"
```

#### ✅ Expected Findings Students Should See:
- **Total Issues**: About 17 security problems (fewer than Flask app)
- **High Priority**: About 7 critical issues
- **Main Problems**: Open redirects, SQL injection, debug mode
- **PWA-Specific Issues**: Service worker problems, offline data storage issues

#### 💭 Class Discussion Questions:
**Q**: "Which application is more secure - Flask or PWA?"  
**A**: Help students compare numbers and understand that fewer issues doesn't always mean safer

**Q**: "Why do mobile-style apps have different security problems?"
**A**: Explain offline storage, push notifications, and device access differences

**Q**: "How would attackers use these vulnerabilities?"
**A**: Discuss phishing, data theft, and unauthorized access scenarios

### Exercise 4: Advanced SAST Techniques

#### 🎯 Key Teaching Points (Practical Focus):
**Automation = Making Security Part of Daily Work**
- Security scanning can happen automatically when developers save code
- Results can be sent to development teams immediately
- Helps catch problems before they reach customers

**💻 Comparison Commands for Students**:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Quick comparison of both applications
echo "=== Flask Web Application ==="
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep "Total findings:"

echo "=== PWA Mobile-Style Application ==="  
python src/analyzer/analyze_cli.py samples/unsecure-pwa --educational | grep "Total findings:"

# Step 3: Generate a JSON report (for automation)
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --output flask_report.json --format json
echo "JSON report saved for development team integration"
```

#### 🎯 For Advanced Students (Optional Challenge):
If some students finish early, challenge them to:
- Compare the JSON output format with the regular output
- Count specific types of vulnerabilities (SQL injection vs others)
- Research other security scanning tools used in industry

#### 💼 Real-World Connection:
**💬 Explain to Students**: "Companies like Google and Microsoft run security scans every time a programmer saves their work. This helps catch problems immediately instead of waiting until after the software is released."

### Exercise 5: Making Security Recommendations

#### 🎯 Key Teaching Points (Professional Skills):
**Risk-Based Thinking = Fix the Most Dangerous Problems First**
- Not all security problems are equally dangerous
- Business impact matters (what happens if this gets exploited?)
- Resources are limited, so prioritization is essential

**💻 Analysis Commands for Students**:
```bash
# Step 1: Make sure you're in the main folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Focus on high-priority issues only
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep -A 5 -B 5 "High"

# Step 3: Count different severity levels
echo "Critical Issues:"
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep "High" | wc -l
echo "Medium Issues:"  
python src/analyzer/analyze_cli.py samples/vulnerable-flask-app --educational | grep "Medium" | wc -l
```

#### 📝 Student Activity: Security Recommendation Report
**Students Should Write** (provide this template):
1. **Most Dangerous Problem**: SQL Injection (allows data theft)
2. **Business Impact**: Customer data could be stolen, company reputation damaged  
3. **Fix Priority**: Immediate (fix within 1 week)
4. **How to Fix**: Use parameterized database queries instead of string concatenation

#### ✅ Assessment Criteria for Teachers:
- Can students identify SQL injection as the top priority?
- Do they understand business impact beyond technical details?
- Can they explain fixes in simple, actionable terms?
- Do they consider realistic timelines for fixes?

## 🚨 Simple Troubleshooting Guide

### ❌ Problem: "Command not found" or tool doesn't work
**✅ Solution**: 
```bash
# Make sure you're in the right place
cd /workspaces/Docker_Sandbox_Demo

# Check the tool exists  
ls src/analyzer/analyze_cli.py

# If file doesn't exist, contact technical support
```

### ❌ Problem: Students get overwhelmed by technical output
**✅ Teaching Strategy**: 
- Focus on the summary numbers (total findings, high/medium/low counts)
- Use the grep commands provided to filter for specific issues
- Remind students they're learning to think like security professionals, not programmers

### ❌ Problem: Sample applications are missing
**✅ Solution**:
```bash
# Check sample folders exist
ls samples/vulnerable-flask-app/
ls samples/unsecure-pwa/

# If missing, verify Docker Sandbox Demo setup
```

**🎯 Pro Tip**: Practice running all commands yourself before class to build confidence with the tool output!