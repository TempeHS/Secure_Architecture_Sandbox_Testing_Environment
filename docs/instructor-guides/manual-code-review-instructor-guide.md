# Manual Code Review Exercise - Instructor Guide

## 🎯 Teaching Objectives

This exercise teaches students how to manually review source code for security
vulnerabilities using human intelligence and systematic methodology. Students
learn to identify complex security issues that automated tools often miss.

**💡 For Non-Technical Instructors**: This guide includes step-by-step
explanations and simple concepts. While some programming knowledge is helpful,
the focus is on teaching security thinking and systematic analysis.

## ⏱️ Time Requirements

- **Total Duration**: 1-2 hours (can be split into two sessions)
- **Session 1** (45-60 minutes): Introduction and Basic Review Methodology
  (Understanding code review + First vulnerability identification)
- **Session 2** (45-60 minutes): Advanced Analysis and Documentation (Complex
  vulnerabilities + Professional reporting)

## 👥 Class Size and Setup

- **Optimal Class Size**: 12-20 students
- **Setup**: Individual computers with access to the Unsecure PWA code
- **Prerequisites**: Basic understanding of web applications (no advanced
  programming required)

## 📍 Important: Navigation Instructions

**All activities start from the main project folder. If students get lost:**

```bash
# Return to the main project folder (copy and paste this)
cd /workspaces/Docker_Sandbox_Demo

# Check you're in the right place (should see folders like 'src', 'samples', 'docker')
ls
```

## 📋 Pre-Class Preparation (10 minutes)

### ✅ Technical Setup Checklist:

```bash
# Step 1: Navigate to the main project folder
cd /workspaces/Docker_Sandbox_Demo

# Step 2: Verify the Unsecure PWA exists
ls samples/unsecure-pwa/

# Step 3: Check main application files are accessible
cat samples/unsecure-pwa/main.py | head -20
cat samples/unsecure-pwa/user_management.py | head -20

# Step 4: Verify templates directory
ls samples/unsecure-pwa/templates/
```

**✅ What Should Happen**:

- Students should see the application files and be able to read the source code
- No commands are needed beyond file viewing and navigation
- Focus is on reading and understanding code, not running applications

### 📚 Key Concepts to Introduce

**Before starting the exercise, explain these fundamental concepts:**

1. **Manual vs Automated Review**:

   - Automated tools: Fast, pattern-based, high false positives
   - Manual review: Thoughtful, context-aware, identifies complex issues

2. **Security Review Mindset**:
   - Think like an attacker: "How could this be misused?"
   - Question assumptions: "What if input is malicious?"
   - Consider edge cases: "What happens when this fails?"

---

## 📖 Session 1: Introduction and Basic Review (45-60 minutes)

### Opening Discussion (10 minutes)

**Start with real-world context:** "Imagine you're a security consultant hired
to review a company's web application before it goes live. Your job is to find
security problems by reading the code - just like a teacher grading essays for
mistakes."

**Key Discussion Points:**

- Why do we need human reviewers when we have security scanners?
- What types of problems might humans catch that computers miss?
- How does code review fit into software development?

### Application Overview (10 minutes)

**Guide students through understanding the application:**

```bash
# Show students the application structure
cd /workspaces/Docker_Sandbox_Demo/samples/unsecure-pwa
ls -la
```

**Explain each component:**

- `main.py`: The main web application (like the front desk of a building)
- `user_management.py`: Handles users and database (like the security office)
- `templates/`: The web pages users see (like the lobby displays)

### First Vulnerability Hunt (20 minutes)

**Focus on SQL Injection in Authentication**

**Instructor Demonstration:**

1. Open `user_management.py` and find the `retrieveUsers` function
2. Point out this line:
   `cur.execute(f"SELECT * FROM users WHERE username = '{username}'")`
3. Explain: "This is like writing a check where someone else fills in the
   amount!"

**Guided Discovery Questions:**

- "What happens if someone types weird characters in the username field?"
- "Could someone type something that changes what this query does?"
- "What would happen if the username was: `admin' OR '1'='1`?"

**Student Activity (15 minutes):** Have students find the second SQL injection
vulnerability in the same file (password query).

### Learning Check (5 minutes)

**Quick Assessment Questions:**

1. "What makes SQL injection possible in this code?"
2. "How could we fix this vulnerability?"
3. "Why might automated tools miss this type of issue?"

---

## 📖 Session 2: Advanced Analysis and Documentation (45-60 minutes)

### XSS Vulnerability Analysis (15 minutes)

**Focus on Template Security**

**Instructor Demonstration:**

1. Open `templates/index.html` and find: `{{ msg|safe }}`
2. Explain: "The `|safe` filter is like turning off the safety on a power tool!"
3. Trace how `msg` gets into the template from `main.py`

**Student Activity (10 minutes):** Have students find where user feedback is
displayed and identify the XSS vulnerability in `listFeedback` function.

### Authentication Bypass Analysis (15 minutes)

**Focus on Business Logic Flaws**

**Guided Analysis:**

1. Walk through the `retrieveUsers` function logic
2. Point out the two separate queries for username and password
3. Explain: "This is like checking if someone has a key, then separately
   checking if they know the combination - but not checking if they're the same
   person!"

**Student Discovery:** Have students work out how this could be exploited (hint:
different usernames and passwords).

### Professional Documentation (15 minutes)

**Teach Security Reporting Skills**

**Template for Vulnerability Documentation:**

```
Vulnerability: [Type]
Location: [File:Line]
Risk: [Critical/High/Medium/Low]
Description: [What's wrong]
Impact: [What could happen]
Fix: [How to repair it]
```

**Student Activity:** Have students document one vulnerability using this
template.

---

## 🎯 Key Vulnerabilities Students Should Find

### 1. SQL Injection (Critical)

**Location**: `user_management.py`, lines with `f"SELECT * FROM..."`
**Problem**: String formatting in SQL queries **Impact**: Complete database
compromise **Fix**: Use parameterized queries with `?` placeholders

### 2. Cross-Site Scripting (High)

**Location**: `templates/index.html`, `{{ msg|safe }}` **Problem**: Unescaped
user input in templates **Impact**: JavaScript injection and session theft
**Fix**: Remove `|safe` filter and use proper escaping

### 3. Authentication Logic Flaw (High)

**Location**: `user_management.py`, `retrieveUsers` function **Problem**:
Separate username and password validation **Impact**: Authentication bypass with
mixed credentials **Fix**: Single query with both username AND password
validation

### 4. Stored XSS in Feedback (High)

**Location**: `user_management.py`, `listFeedback` function **Problem**: Direct
HTML writing without escaping **Impact**: Persistent JavaScript attacks **Fix**:
Use template escaping instead of direct HTML writing

### 5. Information Disclosure (Medium)

**Location**: Various locations with debug settings **Problem**: Debug mode
enabled, verbose error messages **Impact**: Information leakage to attackers
**Fix**: Disable debug mode, implement proper error handling

### 6. Open Redirect (Medium)

**Location**: `main.py`, `redirect(url, code=302)` without validation
**Problem**: Unvalidated redirect parameter **Impact**: Phishing and malicious
redirects **Fix**: Validate redirect URLs against whitelist

---

## 📊 Assessment Rubric

### Technical Skills (40 points)

**Vulnerability Identification (20 points)**

- **Excellent (18-20)**: Identifies 4+ vulnerabilities with accurate
  classification
- **Good (14-17)**: Identifies 3 vulnerabilities with mostly accurate
  classification
- **Satisfactory (10-13)**: Identifies 2 vulnerabilities with some accuracy
- **Needs Improvement (0-9)**: Identifies fewer than 2 vulnerabilities

**Analysis Methodology (20 points)**

- **Excellent (18-20)**: Systematic, thorough approach with clear reasoning
- **Good (14-17)**: Generally systematic with good reasoning
- **Satisfactory (10-13)**: Somewhat systematic approach
- **Needs Improvement (0-9)**: Unsystematic or unclear approach

### Knowledge Understanding (40 points)

**Security Concepts (20 points)**

- **Excellent (18-20)**: Demonstrates deep understanding of security principles
- **Good (14-17)**: Shows good understanding with minor gaps
- **Satisfactory (10-13)**: Basic understanding with some confusion
- **Needs Improvement (0-9)**: Limited or confused understanding

**Code Analysis Skills (20 points)**

- **Excellent (18-20)**: Accurately traces code flow and identifies security
  implications
- **Good (14-17)**: Generally accurate code analysis
- **Satisfactory (10-13)**: Basic code analysis with some errors
- **Needs Improvement (0-9)**: Inaccurate or confused code analysis

### Professional Communication (20 points)

**Documentation Quality (10 points)**

- **Excellent (9-10)**: Clear, professional vulnerability documentation
- **Good (7-8)**: Generally clear documentation with minor issues
- **Satisfactory (6-7)**: Basic documentation that communicates main points
- **Needs Improvement (0-5)**: Unclear or incomplete documentation

**Risk Assessment (10 points)**

- **Excellent (9-10)**: Accurate risk prioritization with sound reasoning
- **Good (7-8)**: Generally accurate risk assessment
- **Satisfactory (6-7)**: Basic risk understanding
- **Needs Improvement (0-5)**: Inaccurate or missing risk assessment

---

## 🚨 Common Student Challenges and Solutions

### Challenge 1: "I don't understand the code"

**Solution**: Focus on input/output flow rather than complex syntax

- "Where does user input come from?"
- "What happens to user input?"
- "Where does user input go?"

### Challenge 2: "Everything looks vulnerable"

**Solution**: Teach prioritization and impact assessment

- "What's the worst thing that could happen?"
- "How easy would this be to exploit?"
- "Who would be affected?"

### Challenge 3: "I can't find any vulnerabilities"

**Solution**: Provide guided discovery questions

- "What happens if someone types unusual characters?"
- "What if the input was much longer than expected?"
- "What if someone sent the wrong type of data?"

### Challenge 4: "I found something but I'm not sure if it's a problem"

**Solution**: Encourage exploration and hypothesis testing

- "What would you need to type to test this?"
- "What would happen if an attacker tried this?"
- "How would this affect other users?"

---

## 📚 Extension Activities

### For Advanced Students

1. **Architecture Review**: Evaluate the overall security design of the
   application
2. **Remediation Planning**: Create a prioritized fix schedule with timeline
   estimates
3. **Security Requirements**: Define security requirements the application
   should meet

### For Struggling Students

1. **Guided Vulnerability Hunt**: Use specific line numbers and focus on one
   vulnerability type
2. **Pattern Recognition**: Focus on recognizing dangerous patterns like string
   formatting in SQL
3. **Impact Scenarios**: Help students understand "what could go wrong" for each
   issue

---

## 🔧 Troubleshooting Guide

### Technical Issues

**Problem**: Students can't find the application files **Solution**:

```bash
cd /workspaces/Docker_Sandbox_Demo
ls samples/unsecure-pwa/
```

**Problem**: Students get overwhelmed by code complexity **Solution**: Use the
"one function at a time" approach - focus on small pieces

**Problem**: Students want to run the application **Solution**: Remind them this
is **code review**, not runtime testing - reading code is the skill being
developed

### Pedagogical Issues

**Problem**: Students find too many false positives **Solution**: Teach them to
distinguish between "could be exploited" vs "will be exploited"

**Problem**: Students miss obvious vulnerabilities **Solution**: Use guiding
questions to point them toward the right areas

**Problem**: Students don't understand the business impact **Solution**: Use
concrete scenarios: "What if someone could see all user passwords?"

---

## 📖 Answer Key Summary

**Quick Reference for Instructors:**

1. **SQL Injection**: Lines 13, 17 in `user_management.py` - string formatting
   in SQL
2. **XSS**: `|safe` filter in `templates/index.html` and HTML writing in
   `listFeedback`
3. **Auth Bypass**: Separate username/password queries in `retrieveUsers`
   function
4. **Open Redirect**: Unvalidated `url` parameter in redirect statements
5. **Info Disclosure**: Debug mode enabled, error message leakage

---

## 🎓 Learning Outcomes Assessment

### Students should demonstrate:

- **Understanding of manual review methodology**
- **Ability to identify common vulnerability patterns**
- **Skills in reading and analyzing source code for security issues**
- **Professional vulnerability documentation and communication**
- **Appreciation for the role of human judgment in security**

### Success Indicators:

- Students can explain why manual review complements automated testing
- Students can systematically analyze code for security vulnerabilities
- Students can clearly document and communicate security findings
- Students understand the business impact of security vulnerabilities

---

**🔍 Remember: The goal is to develop security thinking and systematic analysis
skills, not to create expert programmers. Focus on the process and mindset over
technical complexity!**
