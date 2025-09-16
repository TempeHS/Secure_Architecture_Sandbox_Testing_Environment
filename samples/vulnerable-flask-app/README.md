# Vulnerable Flask Demo Application

⚠️ **WARNING: This application contains intentional security vulnerabilities for
educational purposes only!**

## Overview

This Flask application demonstrates Python web application security
vulnerabilities. It's specifically designed for cybersecurity education and
static analysis training using Python security tools.

## Technology Stack

- **Backend:** Python Flask
- **Database:** SQLite3
- **Template Engine:** Jinja2 (with unsafe configurations)
- **Authentication:** JWT (weak implementation)
- **Serialization:** Pickle (insecure)

## Security Vulnerabilities Included

### 🔴 Critical Vulnerabilities

1. **SQL Injection** - String concatenation in queries
2. **Server-Side Template Injection (SSTI)** - Unsafe Jinja2 rendering
3. **Command Injection** - Direct shell command execution
4. **Insecure Deserialization** - Pickle unpickling user data

### 🟡 High Severity Issues

5. **Cross-Site Scripting (XSS)** - Unescaped user input
6. **Path Traversal** - Direct file system access
7. **Weak Cryptographic Practices** - MD5 password hashing

### 🟠 Medium Severity Issues

8. **Missing Authorization** - Unprotected admin endpoints
9. **Information Disclosure** - Debug and API endpoints
10. **Insecure Direct Object References** - User profile access

## Installation & Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start the application
python app.py

# Access the application
# http://localhost:5000
```

## Testing Vulnerabilities

### SQL Injection (Login)

```
Username: admin' OR '1'='1' --
Password: anything
```

### SQL Injection (Search)

```
Search: ' UNION SELECT password,email,role FROM users --
```

### Server-Side Template Injection

```
Post Content: {{ 7*7 }}
Post Content: {{ ''.__class__.__mro__[1].__subclasses__() }}
```

### Command Injection (Ping)

```
Host: 127.0.0.1; cat /etc/passwd
Host: 127.0.0.1 && python -c "import os; os.system('whoami')"
```

### Path Traversal

```
GET /read_file?filename=../app.py
GET /read_file?filename=../../../etc/passwd
```

### XSS

```html
Post Content:
<script>
  alert("XSS in Flask!");
</script>
Post Content: <img src=x onerror=alert('XSS')>
```

## Python Security Analysis

### Static Analysis Tools

```bash
# Python security linter
bandit -r . -f json

# Dependency vulnerability scanning
safety check

# Pattern-based security analysis
semgrep --config=auto .

# Specific vulnerability patterns
semgrep --config=security.audit.dangerous-pickle-use .
```

### Code Quality Analysis

```bash
# Python code quality
flake8 app.py

# Type checking
mypy app.py

# Security-focused linting
pylint --load-plugins=pylint_flask app.py
```

## Educational Objectives

Students will learn to:

1. Identify Python-specific security issues
2. Understand template injection vulnerabilities
3. Recognize insecure deserialization risks
4. Use Python security tools effectively
5. Implement secure coding practices in Flask

## Default Credentials

- **Admin:** admin / admin123
- **User:** user / user123

## API Endpoints

- `GET /` - Home page with vulnerability demonstrations
- `POST /login` - SQL injection vulnerable login
- `GET /search` - SQL injection in search functionality
- `POST /create_post` - XSS and SSTI vulnerabilities
- `GET /posts` - Display posts (XSS output)
- `POST /ping` - Command injection endpoint
- `GET /read_file` - Path traversal vulnerability
- `POST /set_session` - Insecure deserialization
- `GET /get_session` - Pickle unpickling
- `GET /admin` - Missing authorization
- `GET /api/users` - Information disclosure
- `GET /profile/<id>` - Insecure direct object reference
- `GET /debug` - Debug information disclosure
- `POST /upload` - Unrestricted file upload

## Security Analysis Results

### Expected Bandit Findings

- High: Use of MD5 hash
- High: SQL string formatting
- High: Use of pickle
- Medium: Shell command execution
- Low: Debug mode enabled

### Expected Safety Findings

- Outdated Flask version (if using older version)
- Known vulnerabilities in dependencies

### Expected Semgrep Findings

- SQL injection patterns
- Command injection patterns
- Template injection risks
- Pickle deserialization issues

## File Structure

```
vulnerable-flask-app/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── files/             # Sample files for path traversal
│   └── sample.txt
├── uploads/           # File upload directory
└── vulnerable_flask.db # SQLite database (created on first run)
```

## Database Schema

```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,        -- MD5 hashed (insecure!)
    email TEXT,
    role TEXT DEFAULT 'user',
    api_key TEXT
);

-- Posts table
CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,         -- Vulnerable to XSS
    author TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Safety Reminders

- Designed for educational use only
- Contains intentionally vulnerable code
- Never use in production environments
- Practice responsible vulnerability disclosure
- Use learned skills ethically

Perfect for learning Python web security! 🐍🔒
