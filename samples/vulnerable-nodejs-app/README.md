# Insecure Node.js Web Application

## Educational Cybersecurity Demonstration

**⚠️ WARNING: This application contains intentional security vulnerabilities for educational purposes only. Do NOT deploy in production environments!**

This Node.js application demonstrates common web application security vulnerabilities that students can identify, exploit, and learn to remediate. It's designed to complement the vulnerable Flask application in the cybersecurity sandbox environment.

## Features & Vulnerabilities

### 1. SQL Injection (SQLi)
- **Endpoint**: `/search`
- **Vulnerability**: Direct SQL query construction with user input
- **Demonstration**: User search functionality with unvalidated parameters
- **Payloads**: `'; DROP TABLE users; --`, `' OR '1'='1`

### 2. Cross-Site Scripting (XSS)
- **Types**: Stored, Reflected, and DOM-based XSS
- **Endpoints**: `/comment`, `/profile`, client-side DOM manipulation
- **Demonstration**: Comment system and profile updates
- **Payloads**: `<script>alert('XSS')</script>`, `<img src=x onerror=alert('XSS')>`

### 3. Command Injection
- **Endpoint**: `/ping`
- **Vulnerability**: Direct execution of shell commands with user input
- **Demonstration**: Network ping utility
- **Payloads**: `; ls -la`, `&& cat /etc/passwd`, `| whoami`

### 4. Path Traversal
- **Endpoint**: `/download`
- **Vulnerability**: Unrestricted file access
- **Demonstration**: File download functionality
- **Payloads**: `../../../etc/passwd`, `..\\..\\windows\\system32\\drivers\\etc\\hosts`

### 5. Server-Side Request Forgery (SSRF)
- **Endpoint**: `/fetch`
- **Vulnerability**: Unvalidated URL requests
- **Demonstration**: URL content fetching
- **Payloads**: `http://localhost:22`, `file:///etc/passwd`, `http://169.254.169.254/`

### 6. Insecure Direct Object References (IDOR)
- **Endpoint**: `/user/:id`
- **Vulnerability**: Direct database ID access without authorization
- **Demonstration**: User profile viewing
- **Exploitation**: Incrementing user IDs to access other profiles

### 7. Authentication & Session Management Flaws
- **Issues**: Weak password policies, predictable session IDs, client-side auth
- **Endpoints**: `/login`, `/dashboard`
- **Demonstration**: Login system with multiple weaknesses

### 8. Information Disclosure
- **Types**: Error messages, debug information, hardcoded secrets
- **Locations**: Console logs, HTTP headers, client-side JavaScript
- **Demonstration**: Detailed error pages and exposed configuration

### 9. Cross-Site Request Forgery (CSRF)
- **Endpoint**: `/admin/delete`
- **Vulnerability**: No CSRF token validation
- **Demonstration**: Admin actions without proper protection

### 10. Client-Side Security Issues
- **File**: `/public/app.js`
- **Issues**: DOM-based XSS, prototype pollution, insecure storage
- **Demonstration**: JavaScript vulnerabilities and browser-based attacks

## Installation & Setup

### Prerequisites
- Node.js (v14 or higher)
- npm package manager

### Installation
```bash
cd samples/unsecure-nodejs-app
npm install
```

### Running the Application
```bash
npm start
```

The application will start on `http://localhost:3001`

## Usage in Educational Environment

### For Instructors
1. **Pre-Class Setup**: Ensure Docker environment is running and application is accessible
2. **Demonstration**: Walk through each vulnerability type with examples
3. **Hands-On**: Guide students through exploitation techniques
4. **Remediation**: Discuss secure coding practices for each vulnerability
5. **Assessment**: Use provided worksheets to evaluate understanding

### For Students
1. **Exploration**: Navigate through the application and understand functionality
2. **Vulnerability Identification**: Use provided worksheets to identify security issues
3. **Exploitation**: Practice safe ethical hacking techniques
4. **Documentation**: Record findings and potential impacts
5. **Remediation Planning**: Propose fixes for identified vulnerabilities

## Testing Vulnerabilities

### SQL Injection Testing
```bash
# Test search functionality
curl -X POST http://localhost:3001/search \
  -H "Content-Type: application/json" \
  -d '{"query": "admin'\'' OR '\''1'\''='\''1"}'
```

### XSS Testing
```bash
# Test comment system
curl -X POST http://localhost:3001/comment \
  -H "Content-Type: application/json" \
  -d '{"comment": "<script>alert('XSS')</script>"}'
```

### Command Injection Testing
```bash
# Test ping functionality
curl -X POST http://localhost:3001/ping \
  -H "Content-Type: application/json" \
  -d '{"host": "127.0.0.1; ls -la"}'
```

## Integration with Security Tools

This application works with the following security analysis tools in the sandbox:

### Static Analysis (SAST)
- **ESLint**: JavaScript code quality analysis
- **Semgrep**: Pattern-based security scanning
- **Manual Code Review**: Guided vulnerability identification

### Dynamic Analysis (DAST)
- **Nikto**: Web server scanning
- **Custom Scripts**: Vulnerability-specific testing
- **Browser Developer Tools**: Client-side analysis

### Network Analysis
- **Nmap**: Port and service discovery
- **Wireshark**: Traffic analysis
- **Custom Monitoring**: Request/response inspection

## Database Schema

The application uses SQLite with the following tables:

```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user'
);

-- Comments table
CREATE TABLE comments (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## Default Credentials

**⚠️ These are intentionally weak for educational purposes:**

- **Admin**: `admin` / `admin123`
- **User**: `user` / `password`
- **Guest**: `guest` / `guest123`

## Educational Outcomes

Students completing exercises with this application will learn:

1. **Web Application Security Fundamentals**
2. **Common Vulnerability Types (OWASP Top 10)**
3. **Exploitation Techniques and Tools**
4. **Secure Coding Practices**
5. **Remediation Strategies**
6. **Risk Assessment and Impact Analysis**

## Security Reminders

- **Never use in production**: This application is intentionally vulnerable
- **Isolated environment only**: Run in contained Docker environment
- **Educational purpose**: For learning and demonstration only
- **Ethical considerations**: Discuss responsible disclosure and legal frameworks
- **Supervised use**: Instructor guidance recommended for all activities

## Integration with Course Materials

This application integrates with:
- **SAST Exercise**: Static code analysis activities
- **DAST Exercise**: Dynamic application testing
- **Network Analysis**: Traffic monitoring and analysis
- **Penetration Testing**: Comprehensive security assessment
- **Manual Code Review**: Guided vulnerability discovery

## Troubleshooting

### Common Issues
1. **Port conflicts**: Ensure port 3001 is available
2. **Database errors**: Check SQLite file permissions
3. **Module errors**: Run `npm install` to ensure dependencies
4. **Container access**: Verify Docker network configuration

### Debug Mode
Set `DEBUG=true` environment variable for additional logging:
```bash
DEBUG=true npm start
```

## Contributing

When adding new vulnerabilities or features:
1. Maintain educational focus
2. Add comprehensive comments explaining the security issue
3. Update documentation and exercise materials
4. Test in isolated environment only
5. Follow responsible disclosure practices

---

**Remember**: This application is a teaching tool. Real-world applications should implement proper security controls, input validation, authentication mechanisms, and follow secure development practices.