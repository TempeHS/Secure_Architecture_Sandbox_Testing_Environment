# 🔒 Welcome to Secure Architecture Sandbox Testing Environment

This environment is ready for secure architecture education and testing!

## Quick Start

1. **Test tools**: `python3 .devcontainer/test_tools.py`
2. **Comprehensive test**: `python3 .devcontainer/test_environment.py`
3. **Verify environment**: `python3 .devcontainer/verify_environment.py`
4. **Start Docker services**: `cd docker && docker-compose up -d`
5. **View logs**: `docker-compose logs -f`
6. **Stop services**: `docker-compose down`

## 🎯 Upload Your Own Flask App for Sandbox Testing

**Upload your Flask app to test for security vulnerabilities!**

### Quick Setup

```bash
# 1. Go to uploads folder
cd uploads/

# 2. Edit the Flask app template
code app.py

# 3. Install dependencies and run
docker exec cybersec_sandbox bash -c "cd /workspace/uploads && pip3 install -r requirements.txt"
docker exec -d cybersec_sandbox bash -c "cd /workspace/uploads && python3 app.py"

# 4. Test your app
curl http://localhost:8000
```

### Access Your App

- **Flask App**: `https://your-codespace-name-8000.app.github.dev`
- **File Browser**: `https://your-codespace-name-8080.app.github.dev/uploads/`

### Security Testing Your App

```bash
# Static Analysis
python3 src/analyzer/analyze_cli.py uploads/ --educational

# Dynamic Analysis
python3 src/analyzer/dast_cli.py http://localhost:8000 --educational

# Network Analysis
python3 src/analyzer/network_cli.py --monitor-connections --educational

# Penetration Testing
python3 src/analyzer/pentest_cli.py http://localhost:8000 --educational
```

📚 **Complete Guide**: [docs/setup-guide.md](docs/setup-guide.md)  
📁 **App Template**: [uploads/README.md](uploads/README.md)

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

- **8000**: **Your Flask app** (uploads folder)
- **8080**: Sandbox web server + file browser
- **9090**: Vulnerable Flask application (samples/vulnerable-flask-app/app.py)
- **5000**: PWA Flask application (samples/unsecure-pwa)
- **3000**: Node.js applications

## Project Structure

```
/workspaces/Docker_Sandbox_Demo/
├── uploads/       # 🎯 YOUR FLASK APP HERE (start here!)
├── src/           # Source code (Python packages)
├── samples/       # Sample vulnerable applications
├── docs/          # Documentation
├── docker/        # Docker configuration
├── reports/       # Generated security reports
└── logs/          # Application logs
```

## Upload Your Flask App for Testing

**The `uploads/` folder is ready for your Flask app testing!**

### Flask App Template

The `uploads/` folder contains a ready-to-use Flask template:

- `app.py` - Basic Flask app (edit this!)
- `requirements.txt` - Python dependencies
- `README.md` - Upload and testing instructions

### Testing Workflow

1. **Upload**: Place your Flask app in `uploads/app.py`
2. **Deploy**: Use Docker commands to install deps and run
3. **Test**: Access your app on port 8000
4. **Analyze**: Run security testing tools
5. **Iterate**: Fix issues and retest

### Example Flask App for Testing

```python
from flask import Flask, request
app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>My Security Testing App</h1>"

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Intentionally vulnerable for testing
    return f"<h2>Results for: {query}</h2>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
```

📚 **Complete Instructions**: [uploads/README.md](uploads/README.md)  
🛠️ **Setup Guide**: [docs/setup-guide.md](docs/setup-guide.md)

## Next Steps

### For Flask App Testing 🎓

1. **Start Here**: Check out the ready-to-use Flask template in `uploads/`
2. **Read Instructions**: Open [uploads/README.md](uploads/README.md) for
   step-by-step guidance
3. **Upload Your App**: Place your Flask app in `uploads/app.py`
4. **Security Test**: Use the 4 built-in security testing tools
5. **Learn More**: Explore exercises in `docs/exercises/`

### For Advanced Users 🔧

1. Explore the `/workspaces/Docker_Sandbox_Demo/src` directory
2. Check out sample vulnerable applications in `samples/`
3. Read documentation in `docs/`
4. Start building your cybersecurity analysis tools!
5. Use Docker services for isolated testing environments

**📖 Complete Setup Guide**: [docs/setup-guide.md](docs/setup-guide.md)

Happy learning! 🎓🔍
