# Static Application Security Testing (SAST) Exercise - Instructor Guide

## 🎯 Teaching Objectives

This exercise is designed to teach high school students fundamental cybersecurity concepts through hands-on static analysis of web applications. The exercise progresses from basic tool usage to advanced security analysis and remediation planning.

## ⏱️ Time Requirements

- **Total Duration**: 3-4 hours (can be split across multiple sessions)
- **Session 1** (1.5 hours): Introduction and Basic Analysis (Exercises 1-2)
- **Session 2** (1.5-2 hours): PWA Analysis and Advanced Techniques (Exercises 3-4)
- **Session 3** (30-60 minutes): Remediation and Assessment (Exercise 5)

## 👥 Class Size and Setup

- **Optimal Class Size**: 12-20 students
- **Setup**: Individual workstations with GitHub Codespaces access
- **Prerequisites**: Basic understanding of web applications, basic programming concepts

## 📋 Pre-Class Preparation

### Technical Setup:
1. ✅ Ensure all students have GitHub accounts
2. ✅ Verify Codespaces access and Docker Sandbox Demo deployment
3. ✅ Test all analysis commands work in the environment
4. ✅ Prepare sample outputs for demonstration

### Materials Needed:
- Student exercise handouts
- Instructor demonstration setup
- Answer keys and sample outputs
- Assessment rubrics

## 🎓 Learning Progression

### Foundation Concepts (Session 1):
Students learn what SAST is and how it differs from other testing approaches. They begin with basic tool usage and interpretation of security findings.

### Application Analysis (Session 2):
Students dive deeper into specific vulnerability types across different application architectures, learning to correlate tool outputs with actual security risks.

### Advanced Techniques (Session 3):
Students learn remediation planning, comparative analysis, and begin thinking like security professionals about risk prioritization.

## 📚 Exercise-by-Exercise Instructor Notes

### Exercise 1: SAST Fundamentals

#### Key Teaching Points:
- SAST vs DAST vs manual review
- When to use static analysis in SDLC
- Limitations of automated tools

#### Common Student Questions:
**Q**: "Why doesn't SAST find all vulnerabilities?"
**A**: Emphasize that SAST analyzes code patterns but can't understand business logic or runtime behavior. It's one tool in a comprehensive security strategy.

**Q**: "Are there false positives?"
**A**: Yes, and this is why security professionals need to validate findings. Use this to discuss the importance of human expertise in cybersecurity.

#### Expected Outputs:
Students should successfully run basic commands and understand the difference between output modes.

### Exercise 2: Flask Application Analysis

#### Key Teaching Points:
- SQL injection mechanics and prevention
- Authentication security best practices
- Configuration security importance

#### Demonstration Scripts:
```bash
# Show SQL injection in action
echo "Demonstrate with: samples/vulnerable-flask-app/app.py line 235"
echo "SELECT * FROM users WHERE username = '" + username + "'"
echo "Vulnerable input: admin'; DROP TABLE users; --"
```

#### Expected Findings (Answer Key):
- **Total Findings**: ~47 (17 high, 26 medium, 4 low)
- **Critical Issues**: SQL injection, debug mode, weak hashing
- **Most Common**: SQL injection variants

#### Teaching Moments:
- When students find SQL injection, explain the "Little Bobby Tables" XKCD
- Use real-world examples like the TalkTalk breach (2015)
- Emphasize the cascade effect of security vulnerabilities

### Exercise 3: PWA Application Analysis

#### Key Teaching Points:
- Mobile security considerations
- Progressive Web App specific risks
- Multi-file analysis complexity

#### Expected Findings (Answer Key):
- **Total Findings**: ~17 (7 high, 9 medium, 1 low)
- **Key Vulnerabilities**: Open redirects, SQL injection, Flask debug mode
- **PWA-Specific**: Service worker security, offline data handling

#### Discussion Points:
- How mobile apps differ from traditional web apps
- Offline security considerations
- Data storage in browser environments

### Exercise 4: Advanced SAST Techniques

#### Key Teaching Points:
- Automation and tooling integration
- Comparative security analysis
- JSON output for DevOps integration

#### Instructor Demonstration:
```bash
# Show how to compare applications systematically
for app in vulnerable-flask-app unsecure-pwa; do
    echo "=== $app ==="
    python src/analyzer/analyze_cli.py samples/$app --educational | grep "Total:"
done
```

#### Advanced Students:
- Challenge them to write custom Semgrep rules
- Discuss CI/CD integration strategies
- Explore other SAST tools (SonarQube, Checkmarx, etc.)

### Exercise 5: Remediation Planning

#### Key Teaching Points:
- Risk-based prioritization
- Business impact consideration
- Verification of fixes

#### Hands-On Remediation Example:
```python
# Show vulnerable code
query = f"SELECT * FROM users WHERE username = '{username}'"

# Show secure fix
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

#### Assessment Criteria:
- Can students identify the highest priority vulnerabilities?
- Do they understand the business impact of security issues?
- Can they articulate clear remediation steps?