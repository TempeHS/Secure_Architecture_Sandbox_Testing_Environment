#!/bin/bash
# Universal Build Script with Logging
# Captures ALL build activities with timestamps

set -euo pipefail

# Create log directory in project
LOG_DIR="$(pwd)/logs"
mkdir -p "$LOG_DIR"

# Log files
MAIN_LOG="$LOG_DIR/build-process.log"
ERROR_LOG="$LOG_DIR/build-errors.log"

# Function to log with timestamp
log_with_timestamp() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    echo "[$timestamp] [$level] $message" | tee -a "$MAIN_LOG"
    if [[ "$level" == "ERROR" || "$level" == "FATAL" ]]; then
        echo "[$timestamp] [$level] $message" >> "$ERROR_LOG"
    fi
}

# Function to run command with logging
run_logged() {
    local description="$1"
    shift
    
    log_with_timestamp "START" "$description"
    
    if "$@" 2>&1 | while IFS= read -r line; do
        log_with_timestamp "INFO" "$line"
    done; then
        log_with_timestamp "SUCCESS" "$description completed successfully"
        return 0
    else
        log_with_timestamp "ERROR" "$description failed"
        return 1
    fi
}

# Start main logging
log_with_timestamp "START" "=== BUILD PROCESS STARTED ==="
log_with_timestamp "INFO" "Command: $0 $*"
log_with_timestamp "INFO" "Working Directory: $(pwd)"
log_with_timestamp "INFO" "User: $(whoami)"
log_with_timestamp "INFO" "Date: $(date)"

# Determine what to build based on arguments or context
if [[ $# -eq 0 ]]; then
    # No arguments - run full build
    log_with_timestamp "INFO" "No specific command provided - running full environment setup"
    
    # Run DevContainer setup
    if [[ -f ".devcontainer/post-create.sh" ]]; then
        run_logged "DevContainer Post-Create Setup" bash .devcontainer/post-create.sh
    fi
    
    # Run Docker setup
    if [[ -f ".devcontainer/setup-docker.sh" ]]; then
        run_logged "Docker Setup" bash .devcontainer/setup-docker.sh
    fi
    
    # Start Docker services
    if [[ -f "docker/docker-compose.yml" ]]; then
        run_logged "Docker Compose Services" docker-compose -f docker/docker-compose.yml up -d
    fi
    
else
    # Specific command provided
    log_with_timestamp "INFO" "Running specific command: $*"
    run_logged "Custom Command: $*" "$@"
fi

log_with_timestamp "END" "=== BUILD PROCESS COMPLETED ==="

# Show quick summary
echo ""
echo "🔍 BUILD SUMMARY:"
echo "=================="
echo "Log Location: $MAIN_LOG"
echo "Total Log Entries: $(wc -l < "$MAIN_LOG")"
if [[ -f "$ERROR_LOG" ]]; then
    echo "Errors Found: $(wc -l < "$ERROR_LOG")"
else
    echo "Errors Found: 0"
fi
echo ""
echo "View full log: cat $MAIN_LOG"
echo "View errors only: cat $ERROR_LOG"
echo "Analyze logs: ./.devcontainer/analyze-build-logs.py"