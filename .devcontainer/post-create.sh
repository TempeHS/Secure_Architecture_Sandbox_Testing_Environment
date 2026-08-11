#!/bin/bash
# Post-creation script for Codespaces setup
set -e  # Exit on any error

# Display early warning message in terminal
echo ""
echo "════════════════════════════════════════════════════════════"
echo "🏗️ SECURE ARCHITECTURE SANDBOX - BUILDING ENVIRONMENT"
echo ""
echo "⏱️  Most tools are pre-installed in the container image, so this should be quick..."
echo ""
echo "🐳 Setting up Docker containers for vulnerable applications"
echo "🐍 Verifying Python security libraries"
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
# NOTE: apt packages (nmap, dirb, tcpdump, wkhtmltopdf, etc.) are now installed
# at image-build time in .devcontainer/Dockerfile for faster container startup.
# NOTE: git-lfs is now installed at image-build time in .devcontainer/Dockerfile.

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
# NOTE: Nikto, Gobuster and WhatWeb are now pre-installed at image-build time
# in .devcontainer/Dockerfile (pinned versions) for faster container startup.

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
# NOTE: Python packages from requirements.txt are now installed at image-build
# time in .devcontainer/Dockerfile for faster container startup.
# NOTE: .devcontainer/test_tools.py is now a static, version-controlled file.
# Edit it directly instead of regenerating it here.
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
# NOTE: docker-compose is now installed at image-build time in .devcontainer/Dockerfile.

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
- **httptap**: HTTP/TLS traffic visualization
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

# Force VS Code file watcher to detect the change so any open preview refreshes
sleep 1
touch /workspaces/Secure_Architecture_Sandbox_Testing_Environment/WELCOME.md

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
