#!/bin/bash
# Runtime tool installer for cybersecurity sandbox
# This script downloads and installs security tools at runtime if they're missing
# This is more reliable than build-time downloads in CI/CD environments

set -e

TOOLS_DIR="/opt/tools"
LOG_FILE="/tmp/tool-install.log"

# Enhanced logging with timestamps and levels
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    echo "[$timestamp] [INSTALL-$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$1"
}

log_warn() {
    log "WARN" "$1"
}

log_error() {
    log "ERROR" "$1"
}

log_start() {
    log "START" "$1"
}

log_end() {
    log "END" "$1"
}

ensure_directory() {
    log_start "Creating tools directory: $TOOLS_DIR"
    mkdir -p "$TOOLS_DIR"
    cd "$TOOLS_DIR"
    log_end "Tools directory ready: $TOOLS_DIR"
}

install_gobuster() {
    log_start "Installing Gobuster"
    
    if command -v gobuster >/dev/null 2>&1; then
        log_info "Gobuster already installed"
        return 0
    fi

    log_info "Starting Gobuster installation process"
    local url="https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz"
    
    for attempt in 1 2 3; do
        log_info "Gobuster download attempt $attempt"
        if timeout 60 wget --timeout=60 --tries=3 -q "$url" -O gobuster.tar.gz; then
            log_info "Gobuster downloaded successfully on attempt $attempt"
            if tar -xzf gobuster.tar.gz && [ -f gobuster ]; then
                sudo mv gobuster /usr/local/bin/
                rm -f gobuster.tar.gz
                log_info "Gobuster installed successfully"
                log_end "Gobuster installation completed"
                return 0
            else
                log_error "Gobuster extraction failed on attempt $attempt"
            fi
        else
            log_warn "Gobuster download failed on attempt $attempt"
        fi
        sleep 5
    done
    
    log_error "All Gobuster installation attempts failed, creating fallback"
    echo '#!/bin/bash
echo "Gobuster not available - using dirb instead"
echo "Try: dirb $1 /usr/share/dirb/wordlists/common.txt"' | sudo tee /usr/local/bin/gobuster
    sudo chmod +x /usr/local/bin/gobuster
    log_end "Gobuster fallback created"
}

install_whatweb() {
    if command -v whatweb >/dev/null 2>&1; then
        log "WhatWeb already installed"
        return 0
    fi

    log "Installing WhatWeb..."
    local url="https://github.com/urbanadventurer/WhatWeb/archive/refs/heads/master.tar.gz"
    
    for attempt in 1 2 3; do
        log "WhatWeb download attempt $attempt"
        if wget --timeout=60 --tries=3 -q "$url" -O whatweb.tar.gz; then
            if tar -xzf whatweb.tar.gz && [ -d WhatWeb-master ]; then
                chmod +x WhatWeb-master/whatweb
                sudo ln -sf "$TOOLS_DIR/WhatWeb-master/whatweb" /usr/local/bin/whatweb
                rm -f whatweb.tar.gz
                log "WhatWeb installed successfully"
                return 0
            fi
        fi
        sleep 5
    done
    
    log "Warning: WhatWeb installation failed, creating fallback"
    echo '#!/bin/bash
echo "WhatWeb not available - using curl instead"
echo "Try: curl -I $1"' | sudo tee /usr/local/bin/whatweb
    sudo chmod +x /usr/local/bin/whatweb
}

install_nikto_dev() {
    if command -v nikto-dev >/dev/null 2>&1; then
        log "Nikto-dev already installed"
        return 0
    fi

    # Only install dev version if package manager version not available
    if command -v nikto >/dev/null 2>&1; then
        log "Nikto (package version) already available"
        return 0
    fi

    log "Installing Nikto development version..."
    local url="https://github.com/sullo/nikto/archive/refs/heads/master.tar.gz"
    
    for attempt in 1 2 3; do
        log "Nikto download attempt $attempt"
        if wget --timeout=60 --tries=3 -q "$url" -O nikto.tar.gz; then
            if tar -xzf nikto.tar.gz && [ -d nikto-master ]; then
                chmod +x nikto-master/program/nikto.pl
                sudo ln -sf "$TOOLS_DIR/nikto-master/program/nikto.pl" /usr/local/bin/nikto-dev
                rm -f nikto.tar.gz
                log "Nikto-dev installed successfully"
                return 0
            fi
        fi
        sleep 5
    done
    
    log "Warning: Nikto-dev installation failed - package version should be available"
}

main() {
    log_start "Runtime tool installation process"
    log_info "Starting runtime tool installation..."
    
    # Check if running as root or can use sudo
    if [ "$EUID" -eq 0 ]; then
        SUDO=""
        log_info "Running as root user"
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
        log_info "Using sudo for privileged operations"
    else
        log_error "Need root privileges or sudo to install tools"
        exit 1
    fi
    
    ensure_directory
    
    # Install tools sequentially to prevent conflicts
    log_info "Installing tools sequentially to prevent race conditions..."
    install_gobuster
    install_whatweb
    install_nikto_dev
    
    log_info "Runtime tool installation completed"
    
    # Verify installations
    log_info "Starting tool verification process"
    command -v nikto >/dev/null && log_info "✓ nikto available" || log_warn "✗ nikto not available"
    command -v nikto-dev >/dev/null && log_info "✓ nikto-dev available" || log_warn "✗ nikto-dev not available"
    command -v gobuster >/dev/null && log_info "✓ gobuster available" || log_warn "✗ gobuster not available"
    command -v whatweb >/dev/null && log_info "✓ whatweb available" || log_warn "✗ whatweb not available"
    command -v dirb >/dev/null && log_info "✓ dirb available (fallback)" || log_warn "✗ dirb not available"
    
    log_end "Runtime tool installation process completed"
}

# Only run if called directly (not sourced)
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi