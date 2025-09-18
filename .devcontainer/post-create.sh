#!/bin/bash

# Post-creation script for Codespaces setup
set -e  # Exit on any error

echo "🔧 Setting up Secure Architecture Sandbox environment..."

# Update package lists and install security tools
echo "📦 Updating system packages..."
sudo apt-get update -y

# Install essential security tools availableecho "✅ Environment setup complete!"
echo "📚 Check /workspaces/Secure_Architecture_Sandbox_Testing_Environment/WELCOME.md for getting started instructions"
echo "🧪 Run 'python3 .devcontainer/test_tools.py' to verify tool installation"
echo "🔍 Run 'python3 .devcontainer/verify_environment.py' for quick verification"
echo "🎯 Run 'python3 .devcontainer/test_environment.py' for comprehensive testing"
echo "🐳 Use 'cd docker && docker-compose up -d' to start isolated testing environment"

# Make sure WELCOME.md is prominently visible by echoing its location
echo ""
echo "📖 Opening WELCOME.md for getting started guide..."
echo "   File location: /workspaces/Secure_Architecture_Sandbox_Testing_Environment/WELCOME.md"t
echo "🔧 Installing security tools..."
sudo apt-get install -y --no-install-recommends \
    nmap \
    dirb \
    netcat-traditional \
    tcpdump \
    net-tools \
    dnsutils \
    curl \
    wget \
    jq \
    tree \
    htop \
    file \
    binutils \
    unzip \
    zip \
    git \
    build-essential \
    libpcap-dev

# Install Git LFS
echo "📥 Installing Git LFS..."
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
sudo apt-get install -y git-lfs

# Initialize Git LFS for the user
echo "🔧 Initializing Git LFS..."
git lfs install

# Create necessary directories with proper permissions
sudo mkdir -p /opt/security-tools
sudo chown -R vscode:vscode /opt/security-tools

# Install additional security tools manually
cd /opt/security-tools

# Install Nikto
echo "📥 Installing Nikto..."
if [ ! -d "nikto" ]; then
    git clone https://github.com/sullo/nikto.git
else
    echo "⚙️  Nikto directory already exists, skipping clone"
fi
cd nikto/program
chmod +x nikto.pl
sudo ln -sf /opt/security-tools/nikto/program/nikto.pl /usr/local/bin/nikto
cd /opt/security-tools

# Install Gobuster
echo "📥 Installing Gobuster..."
wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz
tar -xzf gobuster_Linux_x86_64.tar.gz
sudo mv gobuster /usr/local/bin/
rm gobuster_Linux_x86_64.tar.gz

# Install WhatWeb
echo "📥 Installing WhatWeb..."
if [ ! -d "WhatWeb" ]; then
    git clone https://github.com/urbanadventurer/WhatWeb.git
else
    echo "⚙️  WhatWeb directory already exists, skipping clone"
fi
cd WhatWeb
chmod +x whatweb
sudo ln -sf /opt/security-tools/WhatWeb/whatweb /usr/local/bin/whatweb
cd /opt/security-tools

# Clone the Unsecure PWA repository
echo "📥 Cloning Unsecure PWA repository..."
cd /workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples
if [ ! -d "unsecure-pwa/.git" ]; then
    if [ -d "unsecure-pwa" ] && [ "$(ls -A unsecure-pwa)" ]; then
        echo "⚠️  Unsecure PWA directory exists but is not empty, backing up..."
        mv unsecure-pwa unsecure-pwa.backup.$(date +%s)
    fi
    
    if git clone -b sandbox_version https://github.com/TempeHS/The_Unsecure_PWA.git unsecure-pwa; then
        echo "✅ Unsecure PWA cloned successfully from sandbox_version branch"
    else
        echo "❌ Failed to clone Unsecure PWA repository"
    fi
else
    echo "✅ Unsecure PWA repository already exists"
fi

# Ensure proper permissions for workspace
sudo chown -R vscode:vscode /workspaces/Secure_Architecture_Sandbox_Testing_Environment

# Install Python security packages for development and analysis
echo "🐍 Installing Python security packages..."
python3 -m pip install --upgrade pip

# Install from requirements.txt if it exists, otherwise install individually
if [ -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/requirements.txt" ]; then
    echo "📋 Installing from requirements.txt..."
    if python3 -m pip install -r /workspaces/Secure_Architecture_Sandbox_Testing_Environment/requirements.txt; then
        echo "✅ Python packages installed successfully from requirements.txt"
    else
        echo "⚠️  Some packages from requirements.txt failed, trying individual installation..."
        # Fallback to individual package installation
        python3 -m pip install --no-cache-dir \
            pytest pytest-cov black flake8 mypy \
            bandit safety semgrep \
            flask requests beautifulsoup4 jinja2 \
            reportlab pyyaml python-nmap scapy || true
    fi
else
    echo "📦 Installing packages individually..."
    # Install packages with better error handling
    if python3 -m pip install --no-cache-dir \
        pytest \
        pytest-cov \
        black \
        flake8 \
        mypy \
        bandit \
        safety \
        semgrep \
        requests \
        beautifulsoup4 \
        flask \
        reportlab \
        jinja2 \
        pyyaml \
        python-nmap; then
        echo "✅ Python packages installed successfully"
    else
        echo "⚠️  Some Python packages may have failed to install"
    fi

    # Try to install scapy separately (may need special handling)
    if python3 -m pip install --no-cache-dir scapy; then
        echo "✅ Scapy installed successfully"
    else
        echo "⚠️  Scapy installation failed (this is optional)"
    fi
fi

# Create a simple test script to verify security tools
cat > /workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/test_tools.py << 'EOF'
#!/usr/bin/env python3
"""
Quick test script to verify security tools are available.
"""
import subprocess
import sys

def test_tool(tool_name, command):
    """Test if a security tool is available"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        print(f"✅ {tool_name}: Available")
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print(f"❌ {tool_name}: Not available")
        return False

def main():
    print("🔍 Testing security tools availability...\n")
    
    tools = [
        ("Nmap", ["nmap", "--version"]),
        ("Nikto", ["nikto", "-Version"]),
        ("Gobuster", ["gobuster", "version"]),
        ("WhatWeb", ["whatweb", "--version"]),
        ("Python3", ["python3", "--version"]),
        ("Bandit", ["bandit", "--version"]),
        ("Safety", ["safety", "--version"]),
        ("Curl", ["curl", "--version"]),
        ("Docker", ["docker", "--version"]),
    ]
    
    available = 0
    for tool_name, command in tools:
        if test_tool(tool_name, command):
            available += 1
    
    print(f"\n📊 {available}/{len(tools)} tools are available")
    
    if available >= len(tools) - 1:  # Allow for one tool to be missing
        print("🎉 Security tools are ready for educational use!")
        return 0
    else:
        print("⚠️  Some tools may need additional setup")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x /workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/test_tools.py

# Set up git if not already configured
if [ ! -f ~/.gitconfig ]; then
    git config --global user.name "Cybersec Student"
    git config --global user.email "student@cybersec-sandbox.edu"
    git config --global init.defaultBranch main
    git config --global core.editor "code --wait"
fi

# Install docker-compose and start services
echo "📦 Installing docker-compose..."
sudo apt-get update -y && sudo apt-get install -y docker-compose

echo "🚀 Starting Docker Compose services..."
cd /workspaces/Secure_Architecture_Sandbox_Testing_Environment
docker-compose -f docker/docker-compose.yml up -d

# Create a welcome message
cat > /workspaces/Secure_Architecture_Sandbox_Testing_Environment/WELCOME.md << 'EOF'
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
EOF

echo "✅ Environment setup complete!"
echo "📚 Check /workspaces/Secure_Architecture_Sandbox_Testing_Environment/WELCOME.md for getting started instructions"
echo "🧪 Run 'python3 .devcontainer/test_tools.py' to verify tool installation"
echo "� Run 'python3 .devcontainer/verify_environment.py' for quick verification"
echo "🎯 Run 'python3 .devcontainer/test_environment.py' for comprehensive testing"
echo "�🐳 Use 'cd docker && docker-compose up -d' to start isolated testing environment"

# Run a quick verification test
echo ""
echo "🔍 Running comprehensive verification..."
if [ -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/verify_environment.py" ]; then
    python3 /workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/verify_environment.py
else
    echo "🔍 Quick verification test..."
    python3 --version
    echo "Flask check:"
    python3 -c "import flask; print(f'✅ Flask {flask.__version__} is available')" 2>/dev/null || echo "❌ Flask not available"
    echo "Security tools check:"
    which nmap >/dev/null && echo "✅ nmap available" || echo "❌ nmap not available"
    which nikto >/dev/null && echo "✅ nikto available" || echo "❌ nikto not available"
    which gobuster >/dev/null && echo "✅ gobuster available" || echo "❌ gobuster not available"
fi

echo ""
echo "🎉 Secure Architecture Sandbox Testing Environment is ready!"
echo ""
echo "📖 IMPORTANT: Please open WELCOME.md for complete setup instructions!"
echo "   • You can open it by clicking: WELCOME.md in the file explorer"
echo "   • Or run: code WELCOME.md"
echo "   • Or use Ctrl+P and type: WELCOME.md"
echo ""
