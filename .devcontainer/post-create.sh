#!/bin/bash
# Post-creation script for Codespaces setup
set -e  # Exit on any error

# Display early warning message in terminal
echo ""
echo "════════════════════════════════════════════════════════════"
echo "🏗️ SECURE ARCHITECTURE SANDBOX - BUILDING ENVIRONMENT"
echo ""
echo "⏱️  Please wait approximately 4 minutes for setup to complete..."
echo ""
echo "📦 Installing security tools (nmap, dirb, netcat, tcpdump)"
echo "🐳 Setting up Docker containers for vulnerable applications"
echo "🐍 Configuring Python security libraries"
echo "🔧 Preparing cybersecurity testing workspace"
echo ""
echo "☕ Perfect time for a coffee break!"
echo "════════════════════════════════════════════════════════════"
echo ""

# Source centralized build logger
source /workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/build-logger.sh
init_logging

# Start overall setup process
setup_pid=$(start_timer "SETUP" "Secure Architecture Sandbox environment setup")
log_message "INFO" "SETUP" "Starting Secure Architecture Sandbox environment setup" "$setup_pid"
log_system_info "SETUP"

echo "🔧 Setting up Secure Architecture Sandbox environment..."

# Update package lists and install security tools
update_pid=$(start_timer "SYSTEM" "Updating system packages")
echo "📦 Updating system packages..."
# Remove stale Yarn repo that has an expired GPG key (causes apt-get update to fail)
sudo rm -f /etc/apt/sources.list.d/yarn.list 2>/dev/null || true
sudo rm -f /etc/apt/keyrings/yarn.gpg 2>/dev/null || true
log_command "SYSTEM" "sudo apt-get update -y" "Update system packages" 120
# Ensure vscode user is in the docker group and Docker socket is accessible
docker_perm_pid=$(start_timer "DOCKER" "Setting up Docker permissions")
echo "🔒 Ensuring Docker permissions for non-admin users..."
log_message "INFO" "DOCKER" "Starting Docker permissions setup" "$docker_perm_pid"

# Wait for Docker daemon to be available
echo "⏳ Waiting for Docker daemon to be ready..."
log_message "INFO" "DOCKER" "Waiting for Docker daemon to be ready" "$docker_perm_pid"
for i in {1..30}; do
    if docker info >/dev/null 2>&1; then
        echo "✅ Docker daemon is ready"
        log_message "INFO" "DOCKER" "Docker daemon is ready after $i seconds" "$docker_perm_pid"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "⚠️ Docker daemon not ready after 30 seconds, continuing anyway"
        log_message "WARN" "DOCKER" "Docker daemon not ready after 30 seconds, continuing anyway" "$docker_perm_pid"
        break
    fi
    sleep 1
done

# Ensure docker group exists and add vscode user
if getent group docker >/dev/null; then
    echo "✅ Docker group exists"
    log_message "INFO" "DOCKER" "Docker group exists" "$docker_perm_pid"
    if id -nG vscode | grep -qw docker; then
        echo "✅ vscode user already in docker group"
        log_message "INFO" "DOCKER" "vscode user already in docker group" "$docker_perm_pid"
    else
        echo "🔧 Adding vscode user to docker group"
        log_message "INFO" "DOCKER" "Adding vscode user to docker group" "$docker_perm_pid"
        sudo usermod -aG docker vscode
    fi
    
    # Set Docker socket permissions if it exists
    if [ -S /var/run/docker.sock ]; then
        echo "🔧 Setting Docker socket permissions"
        log_message "INFO" "DOCKER" "Setting Docker socket permissions" "$docker_perm_pid"
        sudo chown root:docker /var/run/docker.sock || log_message "WARN" "DOCKER" "Could not change Docker socket ownership" "$docker_perm_pid"
        sudo chmod 660 /var/run/docker.sock || log_message "WARN" "DOCKER" "Could not change Docker socket permissions" "$docker_perm_pid"
        echo "✅ Docker socket permissions configured"
        log_message "INFO" "DOCKER" "Docker socket permissions configured successfully" "$docker_perm_pid"
    else
        echo "⚠️ Docker socket not found at /var/run/docker.sock"
        log_message "WARN" "DOCKER" "Docker socket not found at /var/run/docker.sock" "$docker_perm_pid"
    fi
else
    echo "⚠️ Docker group does not exist; Docker permissions may be limited."
    log_message "WARN" "DOCKER" "Docker group does not exist; Docker permissions may be limited." "$docker_perm_pid"
fi
end_timer "DOCKER" "Setting up Docker permissions" "$docker_perm_pid"

# Install essential security tools and PDF generation dependencies
pkg_install_pid=$(start_timer "PACKAGES" "Installing security tools and PDF generation libraries")
echo "📦 Installing security tools and PDF generation libraries..."
log_message "INFO" "PACKAGES" "Starting installation of security tools and PDF generation libraries" "$pkg_install_pid"

if sudo apt-get install -y --no-install-recommends \
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
    libpcap-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libfontconfig1 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    wkhtmltopdf \
    fonts-noto-color-emoji; then
    log_message "INFO" "PACKAGES" "Security tools and PDF libraries installed successfully" "$pkg_install_pid"
    end_timer "PACKAGES" "Installing security tools and PDF generation libraries" "$pkg_install_pid" "SUCCESS"
else
    log_message "ERROR" "PACKAGES" "Failed to install security tools and PDF libraries" "$pkg_install_pid"
    end_timer "PACKAGES" "Installing security tools and PDF generation libraries" "$pkg_install_pid" "FAILED"
fi

# Install essential security tools and PDF generation dependencies
echo "� Installing security tools and PDF generation libraries..."
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
    libpcap-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libfontconfig1 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    wkhtmltopdf \
    fonts-noto-color-emoji
# Install Git LFS
git_lfs_pid=$(start_timer "GIT" "Installing Git LFS")
echo "📥 Installing Git LFS..."
log_message "INFO" "GIT" "Installing Git LFS" "$git_lfs_pid"

if curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash && sudo apt-get install -y git-lfs; then
    log_message "INFO" "GIT" "Git LFS installed successfully" "$git_lfs_pid"
    end_timer "GIT" "Installing Git LFS" "$git_lfs_pid" "SUCCESS"
else
    log_message "ERROR" "GIT" "Git LFS installation failed" "$git_lfs_pid"
    end_timer "GIT" "Installing Git LFS" "$git_lfs_pid" "FAILED"
fi

# Initialise Git LFS for the user
git_init_pid=$(start_timer "GIT" "Initializing Git LFS")
echo "🔧 Initialising Git LFS..."
log_message "INFO" "GIT" "Initializing Git LFS for user" "$git_init_pid"

if git lfs install; then
    log_message "INFO" "GIT" "Git LFS initialized successfully" "$git_init_pid"
    end_timer "GIT" "Initializing Git LFS" "$git_init_pid" "SUCCESS"
else
    log_message "ERROR" "GIT" "Git LFS initialization failed" "$git_init_pid"
    end_timer "GIT" "Initializing Git LFS" "$git_init_pid" "FAILED"
fi

# Create necessary directories with proper permissions
dir_setup_pid=$(start_timer "DIRS" "Creating directory structure")
echo "📁 Creating directory structure with proper permissions..."
log_message "INFO" "DIRS" "Creating directory structure with proper permissions" "$dir_setup_pid"

sudo mkdir -p /opt/security-tools
sudo chown -R vscode:vscode /opt/security-tools

# Ensure workspace directories exist and have correct permissions
workspace_dirs=(
    "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/reports"
    "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/logs"
    "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/uploads"
)

for dir in "${workspace_dirs[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "📁 Creating directory: $dir"
        log_message "INFO" "DIRS" "Creating directory: $dir" "$dir_setup_pid"
        mkdir -p "$dir"
    fi
    # Ensure vscode user owns the directory
    chown -R vscode:vscode "$dir" 2>/dev/null || log_message "WARN" "DIRS" "Could not change ownership of $dir" "$dir_setup_pid"
    # Ensure directory is writable
    chmod 755 "$dir" 2>/dev/null || log_message "WARN" "DIRS" "Could not change permissions of $dir" "$dir_setup_pid"
done

echo "✅ Directory structure created with proper permissions"
log_message "INFO" "DIRS" "Directory structure created successfully" "$dir_setup_pid"
end_timer "DIRS" "Creating directory structure" "$dir_setup_pid" "SUCCESS"

# Install additional security tools manually
cd /opt/security-tools

# Install Nikto
nikto_pid=$(start_timer "TOOLS" "Installing Nikto")
echo "📥 Installing Nikto..."
log_message "INFO" "TOOLS" "Starting Nikto installation" "$nikto_pid"

if [ ! -d "nikto" ]; then
    for attempt in 1 2 3; do
        echo "🔄 Nikto installation attempt $attempt"
        log_message "INFO" "TOOLS" "Nikto installation attempt $attempt" "$nikto_pid"
        if timeout 60 git clone https://github.com/sullo/nikto.git; then
            echo "✅ Nikto cloned successfully"
            log_message "INFO" "TOOLS" "Nikto cloned successfully on attempt $attempt" "$nikto_pid"
            break
        else
            echo "⚠️ Nikto clone attempt $attempt failed"
            log_message "WARN" "TOOLS" "Nikto clone attempt $attempt failed" "$nikto_pid"
            if [ $attempt -eq 3 ]; then
                echo "❌ All Nikto installation attempts failed"
                log_message "ERROR" "TOOLS" "All Nikto installation attempts failed" "$nikto_pid"
            else
                sleep 5
            fi
        fi
    done
else
    echo "⚙️  Nikto directory already exists, skipping clone"
    log_message "INFO" "TOOLS" "Nikto directory already exists, skipping clone" "$nikto_pid"
fi

if [ -d "nikto/program" ]; then
    cd nikto/program
    chmod +x nikto.pl
    sudo ln -sf /opt/security-tools/nikto/program/nikto.pl /usr/local/bin/nikto
    cd /opt/security-tools
    echo "✅ Nikto installation completed"
    log_message "INFO" "TOOLS" "Nikto installation completed successfully" "$nikto_pid"
    end_timer "TOOLS" "Installing Nikto" "$nikto_pid" "SUCCESS"
else
    echo "⚠️ Nikto installation incomplete"
    log_message "ERROR" "TOOLS" "Nikto installation incomplete" "$nikto_pid"
    end_timer "TOOLS" "Installing Nikto" "$nikto_pid" "FAILED"
fi

# Install Gobuster
gobuster_pid=$(start_timer "TOOLS" "Installing Gobuster")
echo "📥 Installing Gobuster..."
log_message "INFO" "TOOLS" "Starting Gobuster installation" "$gobuster_pid"

for attempt in 1 2 3; do
    echo "🔄 Gobuster installation attempt $attempt"
    log_message "INFO" "TOOLS" "Gobuster installation attempt $attempt" "$gobuster_pid"
    if timeout 60 wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz; then
        if tar -xzf gobuster_Linux_x86_64.tar.gz && [ -f gobuster ]; then
            sudo mv gobuster /usr/local/bin/
            rm -f gobuster_Linux_x86_64.tar.gz
            echo "✅ Gobuster installation completed"
            log_message "INFO" "TOOLS" "Gobuster installation completed on attempt $attempt" "$gobuster_pid"
            end_timer "TOOLS" "Installing Gobuster" "$gobuster_pid" "SUCCESS"
            break
        else
            echo "⚠️ Gobuster extraction failed on attempt $attempt"
            log_message "WARN" "TOOLS" "Gobuster extraction failed on attempt $attempt" "$gobuster_pid"
        fi
    else
        echo "⚠️ Gobuster download attempt $attempt failed"
        log_message "WARN" "TOOLS" "Gobuster download attempt $attempt failed" "$gobuster_pid"
    fi
    
    if [ $attempt -eq 3 ]; then
        echo "❌ All Gobuster installation attempts failed"
        log_message "ERROR" "TOOLS" "All Gobuster installation attempts failed" "$gobuster_pid"
        end_timer "TOOLS" "Installing Gobuster" "$gobuster_pid" "FAILED"
    else
        sleep 5
    fi
done

# Install WhatWeb
whatweb_pid=$(start_timer "TOOLS" "Installing WhatWeb")
echo "📥 Installing WhatWeb..."
log_message "INFO" "TOOLS" "Starting WhatWeb installation" "$whatweb_pid"

if [ ! -d "WhatWeb" ]; then
    for attempt in 1 2 3; do
        echo "🔄 WhatWeb installation attempt $attempt"
        log_message "INFO" "TOOLS" "WhatWeb installation attempt $attempt" "$whatweb_pid"
        if timeout 60 git clone https://github.com/urbanadventurer/WhatWeb.git; then
            echo "✅ WhatWeb cloned successfully"
            log_message "INFO" "TOOLS" "WhatWeb cloned successfully on attempt $attempt" "$whatweb_pid"
            break
        else
            echo "⚠️ WhatWeb clone attempt $attempt failed"
            log_message "WARN" "TOOLS" "WhatWeb clone attempt $attempt failed" "$whatweb_pid"
            if [ $attempt -eq 3 ]; then
                echo "❌ All WhatWeb installation attempts failed"
                log_message "ERROR" "TOOLS" "All WhatWeb installation attempts failed" "$whatweb_pid"
            else
                sleep 5
            fi
        fi
    done
else
    echo "⚙️  WhatWeb directory already exists, skipping clone"
    log_message "INFO" "TOOLS" "WhatWeb directory already exists, skipping clone" "$whatweb_pid"
fi

if [ -d "WhatWeb" ]; then
    cd WhatWeb
    chmod +x whatweb
    sudo ln -sf /opt/security-tools/WhatWeb/whatweb /usr/local/bin/whatweb
    cd /opt/security-tools
    echo "✅ WhatWeb installation completed"
    log_message "INFO" "TOOLS" "WhatWeb installation completed successfully" "$whatweb_pid"
    end_timer "TOOLS" "Installing WhatWeb" "$whatweb_pid" "SUCCESS"
else
    echo "⚠️ WhatWeb installation incomplete"
    log_message "ERROR" "TOOLS" "WhatWeb installation incomplete" "$whatweb_pid"
    end_timer "TOOLS" "Installing WhatWeb" "$whatweb_pid" "FAILED"
fi




# Update the embedded Unsecure PWA repo (force fresh clone)
echo "🔄 Updating embedded Unsecure PWA repository..."
UNSECURE_PWA_DIR="/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/unsecure-pwa"

# Safely clean up existing directory
if [ -d "$UNSECURE_PWA_DIR" ]; then
    echo "🧹 Cleaning up existing unsecure-pwa directory"
    # Use more specific cleanup to avoid errors
    rm -rf "$UNSECURE_PWA_DIR" 2>/dev/null || {
        echo "⚠️ Could not remove existing directory, trying alternative cleanup"
        find "$UNSECURE_PWA_DIR" -mindepth 1 -delete 2>/dev/null || true
    }
fi

# Ensure parent directory exists
mkdir -p "$(dirname "$UNSECURE_PWA_DIR")"

# Clone with timeout and retry logic
echo "📥 Cloning Unsecure PWA repository..."
for attempt in 1 2 3; do
    echo "🔄 Clone attempt $attempt"
    if timeout 120 git clone --branch sandbox_version --depth 1 \
        https://github.com/TempeHS/The_Unsecure_PWA.git "$UNSECURE_PWA_DIR"; then
        echo "✅ Unsecure PWA repository cloned successfully"
        break
    else
        echo "⚠️ Clone attempt $attempt failed"
        if [ $attempt -eq 3 ]; then
            echo "❌ All clone attempts failed. Creating placeholder structure..."
            mkdir -p "$UNSECURE_PWA_DIR"
            echo "# Placeholder - Failed to clone The_Unsecure_PWA repository" > "$UNSECURE_PWA_DIR/README.md"
            echo "flask==2.3.3" > "$UNSECURE_PWA_DIR/requirements.txt"
            cat > "$UNSECURE_PWA_DIR/main.py" << 'EOF'
from flask import Flask
app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>Placeholder - Unsecure PWA</h1><p>The original repository could not be cloned.</p>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
EOF
            echo "✅ Placeholder structure created"
        else
            sleep 10
        fi
    fi
done

# Ensure proper ownership
chown -R vscode:vscode "$UNSECURE_PWA_DIR" 2>/dev/null || true

# Ensure proper permissions for workspace
echo "🔒 Setting final workspace permissions..."
sudo chown -R vscode:vscode /workspaces/Secure_Architecture_Sandbox_Testing_Environment 2>/dev/null || {
    echo "⚠️ Could not change ownership of entire workspace (this may be normal in some environments)"
    # Ensure critical directories are owned by vscode
    critical_dirs=(
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/reports"
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/logs"
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/uploads"
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer"
    )
    for dir in "${critical_dirs[@]}"; do
        if [ -d "$dir" ]; then
            chown -R vscode:vscode "$dir" 2>/dev/null || echo "⚠️ Could not change ownership of $dir"
        fi
    done
}

# Install Python security packages for development and analysis
python_pid=$(start_timer "PYTHON" "Installing Python security packages")
echo "🐍 Installing Python security packages..."
log_message "INFO" "PYTHON" "Starting Python security packages installation" "$python_pid"

python3 -m pip install --upgrade pip

# Install from requirements.txt if it exists, otherwise install individually
requirements_file="/workspaces/Secure_Architecture_Sandbox_Testing_Environment/requirements.txt"
if [ -f "$requirements_file" ]; then
    echo "📋 Installing from requirements.txt..."
    log_message "INFO" "PYTHON" "Installing from requirements.txt" "$python_pid"
    
    # Try installing with a single pip command first
    if python3 -m pip install --no-cache-dir -r "$requirements_file"; then
        echo "✅ Python packages installed successfully from requirements.txt"
        log_message "INFO" "PYTHON" "Python packages installed successfully from requirements.txt" "$python_pid"
        end_timer "PYTHON" "Installing Python security packages" "$python_pid" "SUCCESS"
    else
        echo "⚠️  Some packages from requirements.txt failed, trying safer installation..."
        log_message "WARN" "PYTHON" "Some packages from requirements.txt failed, trying individual installation" "$python_pid"
        
        # Parse requirements.txt and install essential packages individually
        essential_packages=(
            "pytest>=7.0.0"
            "black>=23.0.0"
            "flake8>=6.0.0"
            "bandit>=1.7.5"
            "safety>=2.3.0"
            "flask>=2.3.0"
            "requests>=2.31.0"
            "beautifulsoup4>=4.12.0"
            "jinja2>=3.1.0"
            "reportlab>=4.0.0"
            "pyyaml>=6.0"
        )
        
        # Install essential packages one by one
        for package in "${essential_packages[@]}"; do
            echo "📦 Installing $package"
            log_message "INFO" "PYTHON" "Installing package: $package" "$python_pid"
            if python3 -m pip install --no-cache-dir "$package"; then
                echo "✅ $package installed successfully"
                log_message "INFO" "PYTHON" "$package installed successfully" "$python_pid"
            else
                echo "⚠️ Failed to install $package"
                log_message "WARN" "PYTHON" "Failed to install $package" "$python_pid"
            fi
        done
        
        # Try optional packages with error tolerance
        optional_packages=(
            "python-nmap>=0.7.1"
            "scapy>=2.5.0"
            "weasyprint>=60.0"
            "semgrep>=1.0.0"
            "docker>=6.0.0"
        )
        
        echo "📦 Installing optional packages (failures are acceptable)..."
        log_message "INFO" "PYTHON" "Installing optional packages" "$python_pid"
        for package in "${optional_packages[@]}"; do
            echo "📦 Attempting to install $package"
            log_message "INFO" "PYTHON" "Attempting to install optional package: $package" "$python_pid"
            if python3 -m pip install --no-cache-dir "$package"; then
                echo "✅ $package installed successfully"
                log_message "INFO" "PYTHON" "Optional package $package installed successfully" "$python_pid"
            else
                echo "⚠️ Failed to install $package (this is optional)"
                log_message "INFO" "PYTHON" "Optional package $package failed (acceptable)" "$python_pid"
            fi
        done
        end_timer "PYTHON" "Installing Python security packages" "$python_pid" "PARTIAL_SUCCESS"
    fi
else
    echo "❌ requirements.txt not found at $requirements_file"
    log_message "ERROR" "PYTHON" "requirements.txt not found at $requirements_file" "$python_pid"
    echo "📦 Installing essential packages individually..."
    log_message "INFO" "PYTHON" "Installing essential packages individually" "$python_pid"
    
    # Install minimal essential packages
    essential_packages=(
        "pytest"
        "black"
        "flake8"
        "bandit"
        "safety"
        "flask"
        "requests"
        "beautifulsoup4"
        "reportlab"
        "pyyaml"
    )
    
    for package in "${essential_packages[@]}"; do
        echo "📦 Installing $package"
        log_message "INFO" "PYTHON" "Installing essential package: $package" "$python_pid"
        if python3 -m pip install --no-cache-dir "$package"; then
            echo "✅ $package installed successfully"
            log_message "INFO" "PYTHON" "$package installed successfully" "$python_pid"
        else
            echo "⚠️ Failed to install $package"
            log_message "ERROR" "PYTHON" "Failed to install essential package: $package" "$python_pid"
        fi
    done
    end_timer "PYTHON" "Installing Python security packages" "$python_pid" "PARTIAL_SUCCESS"
fi

echo "✅ Python package installation completed"
log_message "INFO" "PYTHON" "Python package installation process completed" "$python_pid"

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
        ("wkhtmltopdf", ["wkhtmltopdf", "--version"]),
    ]
    
    available = 0
    for tool_name, command in tools:
        if test_tool(tool_name, command):
            available += 1
    
    print(f"\n📊 {available}/{len(tools)} tools are available")
    
    # Test PDF generation capabilities
    print("\n🔍 Testing PDF generation capabilities...")
    try:
        import weasyprint
        print("✅ WeasyPrint: Available")
        pdf_available = True
    except ImportError as e:
        print(f"❌ WeasyPrint: Not available ({e})")
        pdf_available = False
    
    try:
        import reportlab
        print("✅ ReportLab: Available")
    except ImportError:
        print("❌ ReportLab: Not available")
    
    if available >= len(tools) - 1 and pdf_available:  # Allow for one tool to be missing
        print("🎉 Security tools and PDF generation are ready for educational use!")
        return 0
    elif available >= len(tools) - 1:
        print("🎉 Security tools are ready! PDF generation may need troubleshooting.")
        return 0
    else:
        print("⚠️  Some tools may need additional setup")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x /workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/test_tools.py

# Make debug scripts executable
chmod +x /workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/debug-git-clone.sh

# Set up git if not already configured
if [ ! -f ~/.gitconfig ]; then
    git config --global user.name "Cybersec Student"
    git config --global user.email "student@cybersec-sandbox.edu"
    git config --global init.defaultBranch main
    git config --global core.editor "code --wait"
fi

# Install docker-compose and start services
compose_pid=$(start_timer "DOCKER_COMPOSE" "Installing docker-compose and starting services")
echo "📦 Installing docker-compose..."
log_message "INFO" "DOCKER_COMPOSE" "Installing docker-compose" "$compose_pid"

if sudo apt-get update -y && sudo apt-get install -y docker-compose; then
    log_message "INFO" "DOCKER_COMPOSE" "docker-compose installed successfully" "$compose_pid"
else
    log_message "ERROR" "DOCKER_COMPOSE" "docker-compose installation failed" "$compose_pid"
fi

# Ensure Docker is ready
echo "� Waiting for Docker to be ready..."
timeout=60
for i in {1..60}; do
    if docker info >/dev/null 2>&1; then
        echo "✅ Docker is ready after ${i} seconds"
        break
    fi
    if [ $((i % 10)) -eq 0 ]; then
        echo "⏳ Still waiting for Docker... (${i}/60 seconds)"
    fi
    sleep 1
done

if docker info >/dev/null 2>&1; then
    echo "�🚀 Starting Docker Compose services..."
    # Use absolute paths to ensure reliability
    cd /workspaces/Secure_Architecture_Sandbox_Testing_Environment
    if [ -f "docker/docker-compose.yml" ]; then
        echo "📋 Using docker-compose file: $(pwd)/docker/docker-compose.yml"
        
        # Pull images first to avoid build timeouts
        echo "📥 Pulling base images..."
        docker-compose -f "$(pwd)/docker/docker-compose.yml" pull --ignore-pull-failures || echo "⚠️ Some base images could not be pulled"
        
        # Start services with timeout
        echo "🚀 Starting services..."
        if timeout 300 docker-compose -f "$(pwd)/docker/docker-compose.yml" up -d --build; then
            echo "✅ Docker services started successfully"
        else
            echo "⚠️ Docker services failed to start or timed out"
        fi
    else
        echo "❌ docker-compose.yml not found at $(pwd)/docker/docker-compose.yml"
    fi
else
    echo "❌ Docker is not available - services will not start"
fi

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
- **Docker**: Containerisation
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
|   └──examples/  # Example reports
├── tests/         # Unit and integration tests
└── uploads/       # Folder for students to upload a flask app for testing on port 8000
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
    return "Hello from the Secure Architecture Testing Sandbox!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
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
echo "🔍 Run 'python3 .devcontainer/verify_environment.py' for quick verification"
echo "🎯 Run 'python3 .devcontainer/test_environment.py' for comprehensive testing"
echo "🐳 Use 'cd docker && docker-compose up -d' to start isolated testing environment"
echo "🔧 If git clone issues occur, run 'bash .devcontainer/debug-git-clone.sh' for diagnostics"

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

# Complete the overall setup process
end_timer "SETUP" "Secure Architecture Sandbox environment setup" "$setup_pid" "SUCCESS"

# Generate final build report
report_file=$(generate_build_report "SETUP")
log_message "INFO" "SETUP" "Build completed. Report generated: $report_file"

# Show log status
echo ""
echo "📊 Build Process Summary:"
log_status
