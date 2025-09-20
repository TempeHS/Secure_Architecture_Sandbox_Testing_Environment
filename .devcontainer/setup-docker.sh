#!/bin/bash
# Pre-build validation and Docker setup script
# This script validates that all required files exist before attempting Docker builds

set -e

echo "🔍 Pre-build validation and Docker setup..."

# Define required files for each service
declare -A service_files=(
    ["unsecure-pwa"]="samples/unsecure-pwa/main.py samples/unsecure-pwa/requirements.txt"
    ["vulnerable-flask"]="samples/vulnerable-flask-app/app.py samples/vulnerable-flask-app/requirements.txt"
    ["student-uploads"]="uploads/app.py uploads/requirements.txt"
    ["vulnerable-nodejs"]="samples/vulnerable-nodejs-app/app.js samples/vulnerable-nodejs-app/package.json"
)

# Function to validate files exist
validate_service_files() {
    local service_name="$1"
    local files="$2"
    local all_files_exist=true
    
    echo "📋 Validating files for service: $service_name"
    
    for file in $files; do
        if [ -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/$file" ]; then
            echo "  ✅ $file exists"
        else
            echo "  ❌ $file missing"
            all_files_exist=false
        fi
    done
    
    if [ "$all_files_exist" = false ]; then
        echo "⚠️  Some files missing for $service_name - creating placeholders"
        create_placeholder_files "$service_name" "$files"
    fi
}

# Function to create placeholder files
create_placeholder_files() {
    local service_name="$1"
    local files="$2"
    
    case "$service_name" in
        "unsecure-pwa")
            mkdir -p "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/unsecure-pwa"
            if [ ! -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/unsecure-pwa/main.py" ]; then
                cat > "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/unsecure-pwa/main.py" << 'EOF'
from flask import Flask
app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>Placeholder - Unsecure PWA</h1><p>The original repository could not be cloned.</p>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
EOF
            fi
            if [ ! -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/unsecure-pwa/requirements.txt" ]; then
                echo "flask==2.3.3" > "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/unsecure-pwa/requirements.txt"
            fi
            ;;
        "vulnerable-flask")
            mkdir -p "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-flask-app"
            if [ ! -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-flask-app/app.py" ]; then
                cat > "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-flask-app/app.py" << 'EOF'
from flask import Flask
app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>Vulnerable Flask App</h1><p>Placeholder for security testing.</p>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9090, debug=True)
EOF
            fi
            if [ ! -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-flask-app/requirements.txt" ]; then
                echo "flask==2.3.3" > "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-flask-app/requirements.txt"
            fi
            ;;
        "vulnerable-nodejs")
            mkdir -p "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-nodejs-app"
            if [ ! -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-nodejs-app/app.js" ]; then
                cat > "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-nodejs-app/app.js" << 'EOF'
const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req, res) => {
    res.send('<h1>Vulnerable Node.js App</h1><p>Placeholder for security testing.</p>');
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Vulnerable Node.js app listening at http://0.0.0.0:${port}`);
});
EOF
            fi
            if [ ! -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-nodejs-app/package.json" ]; then
                cat > "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples/vulnerable-nodejs-app/package.json" << 'EOF'
{
  "name": "vulnerable-nodejs-app",
  "version": "1.0.0",
  "description": "Placeholder vulnerable Node.js application",
  "main": "app.js",
  "scripts": {
    "start": "node app.js"
  },
  "dependencies": {
    "express": "^4.18.0"
  }
}
EOF
            fi
            ;;
    esac
}

# Validate all services
echo "🔍 Starting pre-build validation..."
for service in "${!service_files[@]}"; do
    validate_service_files "$service" "${service_files[$service]}"
done

# Ensure Dockerfiles exist
dockerfiles=(
    "docker/Dockerfile.minimal"
    "docker/Dockerfile.unsecure-pwa"
    "docker/Dockerfile.vulnerable-flask"
    "docker/Dockerfile.student-uploads"
    "docker/Dockerfile.vulnerable-nodejs"
)

echo "📋 Validating Dockerfiles..."
for dockerfile in "${dockerfiles[@]}"; do
    if [ -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/$dockerfile" ]; then
        echo "  ✅ $dockerfile exists"
    else
        echo "  ❌ $dockerfile missing"
    fi
done

# Validate docker-compose.yml
if [ -f "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/docker/docker-compose.yml" ]; then
    echo "✅ docker-compose.yml exists"
else
    echo "❌ docker-compose.yml missing"
fi

# Set proper permissions
echo "🔒 Setting file permissions..."
chmod -R 755 "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples" 2>/dev/null || true
chmod -R 755 "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/uploads" 2>/dev/null || true

echo "✅ Pre-build validation completed"

# Check if Docker is available
if command -v docker >/dev/null 2>&1; then
    echo "✅ Docker is available"
    
    # Check Docker daemon
    if docker info >/dev/null 2>&1; then
        echo "✅ Docker daemon is running"
    else
        echo "⚠️ Docker daemon is not running"
    fi
else
    echo "⚠️ Docker command not found"
fi

echo "🎯 Docker setup script completed"