#!/bin/bash
# Comprehensive build validation script
# This script validates all aspects of the build process and identifies potential failures

set -e

echo "🔍 Comprehensive Build Process Validation"
echo "=========================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status="$1"
    local message="$2"
    case "$status" in
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ️  $message${NC}"
            ;;
    esac
}

# Validation functions
validate_file_permissions() {
    echo -e "\n${BLUE}🔒 Validating File Permissions${NC}"
    
    local critical_files=(
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/post-create.sh"
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/setup-docker.sh"
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/demo_tools.sh"
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/docker/install-tools.sh"
    )
    
    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            if [ -x "$file" ]; then
                print_status "SUCCESS" "$(basename "$file") is executable"
            else
                print_status "ERROR" "$(basename "$file") is not executable"
                chmod +x "$file" 2>/dev/null && print_status "SUCCESS" "Fixed permissions for $(basename "$file")"
            fi
        else
            print_status "ERROR" "$(basename "$file") not found"
        fi
    done
    
    # Check directory permissions
    local critical_dirs=(
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/reports"
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/logs"
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/uploads"
    )
    
    for dir in "${critical_dirs[@]}"; do
        if [ -d "$dir" ]; then
            if [ -w "$dir" ]; then
                print_status "SUCCESS" "$(basename "$dir") directory is writable"
            else
                print_status "ERROR" "$(basename "$dir") directory is not writable"
            fi
        else
            print_status "WARNING" "$(basename "$dir") directory does not exist"
            mkdir -p "$dir" 2>/dev/null && print_status "SUCCESS" "Created $(basename "$dir") directory"
        fi
    done
}

validate_docker_setup() {
    echo -e "\n${BLUE}🐳 Validating Docker Setup${NC}"
    
    # Check Docker installation
    if command -v docker >/dev/null 2>&1; then
        print_status "SUCCESS" "Docker command is available"
        
        # Check Docker daemon
        if docker info >/dev/null 2>&1; then
            print_status "SUCCESS" "Docker daemon is running"
        else
            print_status "ERROR" "Docker daemon is not running"
        fi
        
        # Check Docker group membership
        if groups | grep -q docker; then
            print_status "SUCCESS" "User is in docker group"
        else
            print_status "WARNING" "User is not in docker group"
        fi
        
        # Check Docker socket permissions
        if [ -S /var/run/docker.sock ]; then
            if [ -r /var/run/docker.sock ] && [ -w /var/run/docker.sock ]; then
                print_status "SUCCESS" "Docker socket has correct permissions"
            else
                print_status "ERROR" "Docker socket permissions incorrect"
            fi
        else
            print_status "ERROR" "Docker socket not found"
        fi
    else
        print_status "ERROR" "Docker command not found"
    fi
    
    # Check docker-compose
    if command -v docker-compose >/dev/null 2>&1; then
        print_status "SUCCESS" "docker-compose is available"
    else
        print_status "ERROR" "docker-compose not found"
    fi
}

validate_dockerfiles() {
    echo -e "\n${BLUE}📋 Validating Dockerfiles${NC}"
    
    local dockerfiles=(
        "docker/Dockerfile.minimal"
        "docker/Dockerfile.unsecure-pwa"
        "docker/Dockerfile.vulnerable-flask"
        "docker/Dockerfile.student-uploads"
        "docker/Dockerfile.vulnerable-nodejs"
    )
    
    for dockerfile in "${dockerfiles[@]}"; do
        local full_path="/workspaces/Secure_Architecture_Sandbox_Testing_Environment/$dockerfile"
        if [ -f "$full_path" ]; then
            print_status "SUCCESS" "$(basename "$dockerfile") exists"
            
            # Check for common Dockerfile issues
            if grep -q "COPY \.\." "$full_path"; then
                print_status "ERROR" "$(basename "$dockerfile") contains invalid COPY paths with '..' "
            else
                print_status "SUCCESS" "$(basename "$dockerfile") has valid COPY paths"
            fi
            
            # Check for RUN commands without proper packages
            if grep -E "RUN.*apt-get.*install.*&&.*rm -rf" "$full_path" | grep -E "install -y\s*&&" >/dev/null; then
                print_status "ERROR" "$(basename "$dockerfile") has empty package list in RUN command"
            else
                print_status "SUCCESS" "$(basename "$dockerfile") has valid RUN commands"
            fi
        else
            print_status "ERROR" "$(basename "$dockerfile") not found"
        fi
    done
}

validate_compose_file() {
    echo -e "\n${BLUE}📝 Validating docker-compose.yml${NC}"
    
    local compose_file="/workspaces/Secure_Architecture_Sandbox_Testing_Environment/docker/docker-compose.yml"
    
    if [ -f "$compose_file" ]; then
        print_status "SUCCESS" "docker-compose.yml exists"
        
        # Check for required services
        local required_services=("unsecure-pwa" "vulnerable-flask" "student-uploads" "vulnerable-nodejs")
        for service in "${required_services[@]}"; do
            if grep -q "$service:" "$compose_file"; then
                print_status "SUCCESS" "Service '$service' is defined"
            else
                print_status "ERROR" "Service '$service' is missing"
            fi
        done
        
        # Check for health checks
        if grep -q "healthcheck:" "$compose_file"; then
            print_status "SUCCESS" "Health checks are configured"
        else
            print_status "WARNING" "No health checks found"
        fi
        
        # Validate YAML syntax
        if command -v docker-compose >/dev/null 2>&1; then
            if docker-compose -f "$compose_file" config >/dev/null 2>&1; then
                print_status "SUCCESS" "docker-compose.yml syntax is valid"
            else
                print_status "ERROR" "docker-compose.yml has syntax errors"
            fi
        fi
    else
        print_status "ERROR" "docker-compose.yml not found"
    fi
}

validate_application_files() {
    echo -e "\n${BLUE}📱 Validating Application Files${NC}"
    
    # Check for required application files
    local required_files=(
        "samples/unsecure-pwa/main.py"
        "samples/vulnerable-flask-app/app.py"
        "uploads/app.py"
        "samples/vulnerable-nodejs-app/app.js"
    )
    
    for file in "${required_files[@]}"; do
        local full_path="/workspaces/Secure_Architecture_Sandbox_Testing_Environment/$file"
        if [ -f "$full_path" ]; then
            print_status "SUCCESS" "$(basename "$file") exists"
            
            # Check if file has content
            if [ -s "$full_path" ]; then
                print_status "SUCCESS" "$(basename "$file") has content"
            else
                print_status "ERROR" "$(basename "$file") is empty"
            fi
        else
            print_status "ERROR" "$(basename "$file") not found"
        fi
    done
    
    # Check for requirements files
    local requirements_files=(
        "samples/unsecure-pwa/requirements.txt"
        "samples/vulnerable-flask-app/requirements.txt"
        "uploads/requirements.txt"
        "samples/vulnerable-nodejs-app/package.json"
    )
    
    for file in "${requirements_files[@]}"; do
        local full_path="/workspaces/Secure_Architecture_Sandbox_Testing_Environment/$file"
        if [ -f "$full_path" ]; then
            print_status "SUCCESS" "$(basename "$file") exists"
        else
            print_status "ERROR" "$(basename "$file") not found"
        fi
    done
}

validate_python_environment() {
    echo -e "\n${BLUE}🐍 Validating Python Environment${NC}"
    
    # Check Python version
    if command -v python3 >/dev/null 2>&1; then
        local python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_status "SUCCESS" "Python $python_version is available"
    else
        print_status "ERROR" "Python3 not found"
    fi
    
    # Check pip
    if command -v pip3 >/dev/null 2>&1; then
        print_status "SUCCESS" "pip3 is available"
    else
        print_status "ERROR" "pip3 not found"
    fi
    
    # Check critical Python packages
    local critical_packages=("flask" "requests" "pytest")
    for package in "${critical_packages[@]}"; do
        if python3 -c "import $package" 2>/dev/null; then
            print_status "SUCCESS" "Python package '$package' is available"
        else
            print_status "WARNING" "Python package '$package' not found"
        fi
    done
}

validate_security_tools() {
    echo -e "\n${BLUE}🔧 Validating Security Tools${NC}"
    
    local tools=("nmap" "curl" "wget" "netcat" "dirb")
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            print_status "SUCCESS" "$tool is available"
        else
            print_status "WARNING" "$tool not found"
        fi
    done
}

validate_network_ports() {
    echo -e "\n${BLUE}🌐 Validating Network Port Availability${NC}"
    
    local ports=(5000 8000 9090 3000 8080)
    for port in "${ports[@]}"; do
        if ss -tuln | grep -q ":$port "; then
            print_status "WARNING" "Port $port is already in use"
        else
            print_status "SUCCESS" "Port $port is available"
        fi
    done
}

# Run all validations
main() {
    print_status "INFO" "Starting comprehensive build validation..."
    
    validate_file_permissions
    validate_docker_setup
    validate_dockerfiles
    validate_compose_file
    validate_application_files
    validate_python_environment
    validate_security_tools
    validate_network_ports
    
    echo -e "\n${BLUE}📊 Validation Summary${NC}"
    echo "======================================"
    
    # Count errors and warnings
    local error_count=$(grep -c "❌" /dev/stdout 2>/dev/null || echo "0")
    local warning_count=$(grep -c "⚠️" /dev/stdout 2>/dev/null || echo "0")
    
    if [ "$error_count" -eq 0 ]; then
        print_status "SUCCESS" "No critical errors found - build should succeed"
        return 0
    else
        print_status "ERROR" "Critical errors found - build may fail"
        return 1
    fi
}

# Run main function
main "$@"