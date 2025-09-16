# Manual Code Review - Quick Reference Guide

## 🎯 Purpose

This quick reference provides students with essential concepts, methodologies,
and checklists for conducting effective manual security code reviews.

---

## 📚 Key Concepts

### What is Manual Code Review?

**Manual code review** is the systematic examination of source code by human
reviewers to identify security vulnerabilities, logic flaws, and coding best
practice violations using human intelligence and context understanding.

### Why Manual Review Matters

- **Business Logic Flaws**: Only humans understand intended vs actual behavior
- **Complex Attack Chains**: Human reviewers can trace multi-step scenarios
- **Context Awareness**: Understanding application purpose and data sensitivity
- **False Positive Reduction**: Human judgment eliminates tool noise

---

## 🔍 Manual vs Automated Testing

| Aspect              | Manual Code Review            | Automated SAST/DAST          |
| ------------------- | ----------------------------- | ---------------------------- |
| **Detection**       | Complex logic, business flaws | Known vulnerability patterns |
| **False Positives** | Low (human judgment)          | High (pattern matching)      |
| **Speed**           | Slower, thorough              | Fast, repeatable             |
| **Context**         | Excellent understanding       | Limited context              |
| **Expertise**       | High security knowledge       | Basic tool operation         |

---

## 📋 Systematic Review Methodology

### 1. Application Understanding

- [ ] **Map application architecture** - Understand components and data flow
- [ ] **Identify entry points** - Forms, APIs, file uploads, URL parameters
- [ ] **Trace data flow** - Follow user input through the application
- [ ] **Understand business logic** - What is the application supposed to do?

### 2. Security Focus Areas

- [ ] **Authentication & Session Management**
- [ ] **Input Validation & Sanitization**
- [ ] **Output Encoding & XSS Prevention**
- [ ] **SQL Injection Prevention**
- [ ] **Authorization & Access Control**
- [ ] **Error Handling & Information Disclosure**
- [ ] **Configuration Security**

### 3. Code Analysis Process

- [ ] **Read systematically** - Don't skip around randomly
- [ ] **Question assumptions** - "What if this input is malicious?"
- [ ] **Think like an attacker** - "How could I misuse this?"
- [ ] **Consider edge cases** - What happens when things go wrong?

---

## 🚨 Common Vulnerability Patterns

### SQL Injection 🔴 CRITICAL

**Vulnerable Pattern:**

```python
cur.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
```

**Secure Pattern:**

```python
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

**Look For:** String formatting/concatenation in SQL queries

### Cross-Site Scripting (XSS) 🟠 HIGH

**Vulnerable Pattern:**

```html
<div>{{ user_input|safe }}</div>
```

**Secure Pattern:**

```html
<div>{{ user_input }}</div>
```

**Look For:** `|safe` filters, direct HTML writing, unescaped output

### Authentication Bypass 🟠 HIGH

**Vulnerable Pattern:**

```python
# Checking username and password separately
check_username(user)
check_password(pass)
```

**Secure Pattern:**

```python
# Checking both together
check_credentials(user, pass)
```

**Look For:** Separate validation logic, logic gaps

### Hard-coded Secrets 🟡 MEDIUM

**Vulnerable Pattern:**

```python
SECRET_KEY = "hardcoded_secret_123"
```

**Secure Pattern:**

```python
SECRET_KEY = os.environ.get('SECRET_KEY')
```

**Look For:** Passwords, API keys, tokens in source code

---

## ✅ Security Review Checklist

### Authentication Review

- [ ] Are passwords stored securely (hashed, not plain text)?
- [ ] Is password complexity enforced?
- [ ] Are there brute force protections?
- [ ] Is session management secure?
- [ ] Are authentication bypass scenarios possible?

### Input Validation Review

- [ ] Is all user input validated before processing?
- [ ] Are file uploads restricted and validated?
- [ ] Is input length/format/type checking implemented?
- [ ] Are special characters handled safely?
- [ ] Is input sanitized before database operations?

### SQL Injection Review

- [ ] Are parameterized queries used for all database operations?
- [ ] Is dynamic SQL query construction avoided?
- [ ] Are stored procedures used securely?
- [ ] Is user input properly escaped before database queries?

### XSS Prevention Review

- [ ] Is user output properly encoded in templates?
- [ ] Are `|safe` filters avoided or justified?
- [ ] Is user-generated content sanitized before display?
- [ ] Are Content Security Policy headers implemented?

### Authorization Review

- [ ] Are sensitive functions protected with access controls?
- [ ] Is user authorization checked on every privileged operation?
- [ ] Can users access data/functions they shouldn't?
- [ ] Are administrative functions properly protected?

### Error Handling Review

- [ ] Are detailed error messages hidden from users?
- [ ] Is sensitive information excluded from logs?
- [ ] Are database errors handled gracefully?
- [ ] Is debug mode disabled in production?

---

## 📊 Risk Assessment Framework

### Severity Levels

**🔴 CRITICAL**

- Direct system compromise
- Complete data access
- Administrative privilege escalation
- _Examples: SQL injection, authentication bypass_

**🟠 HIGH**

- Significant security impact
- User data compromise
- Cross-user access
- _Examples: XSS, authorization flaws_

**🟡 MEDIUM**

- Moderate security impact
- Limited data exposure
- Requires specific conditions
- _Examples: information disclosure, weak crypto_

**🟢 LOW**

- Minor security concerns
- Limited impact
- Difficult to exploit
- _Examples: minor info leaks, configuration issues_

### Impact Assessment Questions

1. **What data could be accessed?** (Confidentiality)
2. **What data could be modified?** (Integrity)
3. **What services could be disrupted?** (Availability)
4. **How many users would be affected?**
5. **How difficult is exploitation?**

---

## 📝 Vulnerability Documentation Template

```
VULNERABILITY: [Type - e.g., SQL Injection]
LOCATION: [File:Line or Function name]
SEVERITY: [Critical/High/Medium/Low]

DESCRIPTION:
[Clear explanation of what's wrong]

TECHNICAL DETAILS:
[Code snippets, specific implementation issues]

PROOF OF CONCEPT:
[Example input that demonstrates the vulnerability]

IMPACT:
[What could an attacker accomplish?]

REMEDIATION:
[Specific steps to fix the vulnerability]

TIMELINE:
[Recommended fix timeline based on severity]
```

---

## 🔧 Review Tips and Best Practices

### Effective Review Strategies

1. **Start with entry points** - Forms, URL parameters, file uploads
2. **Follow the data** - Trace user input through the application
3. **Focus on trust boundaries** - Where does untrusted data cross into trusted
   operations?
4. **Look for patterns** - Similar code often has similar vulnerabilities
5. **Consider the attacker mindset** - What would you target?

### Common Mistakes to Avoid

- **Don't rush** - Thorough analysis takes time
- **Don't assume** - Question everything, even "safe" operations
- **Don't ignore context** - Understanding business logic is crucial
- **Don't skip documentation** - Record everything you find

### Time Management

- **Set specific time limits** for each review area
- **Take breaks** to maintain focus and fresh perspective
- **Review systematically** rather than jumping around
- **Document as you go** to avoid losing findings

---

## 🎓 Learning Progression

### Beginner Level

- Recognize obvious vulnerable patterns (SQL injection, XSS)
- Understand basic security concepts
- Follow systematic review methodology

### Intermediate Level

- Identify business logic flaws
- Trace complex data flows
- Assess risk and prioritize findings

### Advanced Level

- Understand architectural security issues
- Identify subtle attack vectors
- Design comprehensive remediation strategies

---

## 📚 Additional Resources

### Industry Standards

- **OWASP Code Review Guide**: Comprehensive methodology
- **OWASP Top 10**: Most critical security risks
- **CWE (Common Weakness Enumeration)**: Vulnerability classification

### Professional Development

- **SANS Secure Code Review**: Industry training
- **Security Code Review Certification**: Professional credentials
- **Security Communities**: Forums and discussion groups

---

## 🚀 Next Steps After Manual Review

1. **Validate findings** with automated tools (SAST/DAST)
2. **Prioritize remediation** based on risk assessment
3. **Create fix timeline** with realistic deadlines
4. **Document lessons learned** for future reviews
5. **Establish review processes** for ongoing security

---

**🔍 Remember: Manual code review is both an art and a science. The more you
practice systematic analysis, the better you'll become at identifying security
vulnerabilities that automated tools miss!**
