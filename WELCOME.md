# 🔒 Welcome to Secure Architecture Sandbox Testing Environment

This environment is ready for sandbox testing for secure architecture!

## Quick Start

1. **Test tools**: `python3 .devcontainer/test_tools.py`
2. **Comprehensive test**: `python3 .devcontainer/test_environment.py`
3. **Verify environment**: `python3 .devcontainer/verify_environment.py`
4. **Start Docker services**: `cd docker && docker-compose up -d`
5. **View logs**: `docker-compose logs -f`
6. **Stop services**: `docker-compose down`

## Available Security Tools

- **Nmap**: Network scanning and host discovery
- **Nikto**: Web vulnerability scanner
- **Gobuster**: Directory/file brute-forcer
- **WhatWeb**: Web technology identifier
- **Bandit**: Python security linter
- **Safety**: Python package vulnerability checker
- **Semgrep**: Static analysis tool

## Development Tools

- **Python 3.11+**: Main development language
- **Flask**: Web framework for sample apps
- **Docker**: Containerization
- **VS Code**: Fully configured IDE

## Ports for Testing

- **8080**: Sandbox web server
- **9090**: Vulnerable Flask application (samples/vulnerable-flask-app/app.py)
- **5000**: PWA Flask application (samples/unsecure-pwa)
- **8000**: Development server
- **3000**: Node.js applications

## Project Structure

```
/workspaces/Secure_Architecture_Sandbox_Testing_Environment/
├── src/           # Source code (Python packages)
├── samples/       # Sample vulnerable applications
├── docs/          # Documentation
├── docker/        # Docker configuration
├── reports/       # Generated security reports
└── logs/          # Application logs
```

## Flask Application Development

This environment supports Flask development! You can create Flask apps for:
- Security testing tools
- Vulnerable demo applications
- Report generation interfaces
- Educational web interfaces

Example Flask app:
```python
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello from Cybersecurity Sandbox!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

## Next Steps

1. Explore the `/workspaces/Secure_Architecture_Sandbox_Testing_Environment/src` directory
2. Check out sample vulnerable applications in `samples/`
3. Read documentation in `docs/`
4. Start building your cybersecurity analysis tools!
5. Use Docker services for isolated testing environments

Happy learning! 🎓🔍
