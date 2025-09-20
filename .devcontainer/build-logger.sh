#!/bin/bash

# Centralized Build Process Logger
# This script provides comprehensive logging for all build processes

# Configuration
LOG_DIR="/tmp/sandbox-build-logs"
MAIN_LOG_FILE="$LOG_DIR/build-process.log"
ERROR_LOG_FILE="$LOG_DIR/build-errors.log"
PERFORMANCE_LOG_FILE="$LOG_DIR/build-performance.log"

# Colors for console output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Initialize logging system
init_logging() {
    mkdir -p "$LOG_DIR"
    
    # Create log files with headers
    cat > "$MAIN_LOG_FILE" << EOF
# Secure Architecture Sandbox Build Process Log
# Started: $(date '+%Y-%m-%d %H:%M:%S')
# Host: $(hostname)
# User: $(whoami)
# PWD: $(pwd)
# Shell: $SHELL
# Environment: DevContainer
################################################################################

EOF

    cat > "$ERROR_LOG_FILE" << EOF
# Build Error Log
# Started: $(date '+%Y-%m-%d %H:%M:%S')
################################################################################

EOF

    cat > "$PERFORMANCE_LOG_FILE" << EOF
# Build Performance Log
# Started: $(date '+%Y-%m-%d %H:%M:%S')
################################################################################

EOF

    echo "$(timestamp) [INIT] Logging system initialized" | tee -a "$MAIN_LOG_FILE"
    echo "$(timestamp) [INIT] Log directory: $LOG_DIR" | tee -a "$MAIN_LOG_FILE"
}

# Generate timestamp
timestamp() {
    date '+%Y-%m-%d %H:%M:%S.%3N'
}

# Generate a unique process ID for tracking
generate_process_id() {
    echo "$$-$(date +%s%3N)"
}

# Log a message with different levels
log_message() {
    local level="$1"
    local component="$2"
    local message="$3"
    local process_id="${4:-$(generate_process_id)}"
    
    local timestamp="$(timestamp)"
    local log_entry="$timestamp [$level] [$component] [PID:$process_id] $message"
    
    # Write to main log
    echo "$log_entry" >> "$MAIN_LOG_FILE"
    
    # Write to error log if it's an error
    if [[ "$level" == "ERROR" || "$level" == "FATAL" ]]; then
        echo "$log_entry" >> "$ERROR_LOG_FILE"
    fi
    
    # Console output with colors
    case "$level" in
        "INFO")
            echo -e "${GREEN}✓${NC} $timestamp ${BOLD}[$component]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠${NC} $timestamp ${BOLD}[$component]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}✗${NC} $timestamp ${BOLD}[$component]${NC} $message"
            ;;
        "FATAL")
            echo -e "${RED}💀${NC} $timestamp ${BOLD}[$component]${NC} $message"
            ;;
        "START")
            echo -e "${BLUE}🚀${NC} $timestamp ${BOLD}[$component]${NC} STARTING: $message"
            ;;
        "END")
            echo -e "${GREEN}🏁${NC} $timestamp ${BOLD}[$component]${NC} COMPLETED: $message"
            ;;
        "PERF")
            echo -e "${MAGENTA}📊${NC} $timestamp ${BOLD}[$component]${NC} $message"
            echo "$log_entry" >> "$PERFORMANCE_LOG_FILE"
            ;;
        *)
            echo -e "${CYAN}ℹ${NC} $timestamp ${BOLD}[$component]${NC} $message"
            ;;
    esac
}

# Start timing a process
start_timer() {
    local component="$1"
    local process_name="$2"
    local process_id="$(generate_process_id)"
    
    local start_time=$(date +%s%3N)
    echo "$start_time" > "/tmp/timer_${process_id}"
    
    log_message "START" "$component" "$process_name" "$process_id"
    echo "$process_id"
}

# End timing a process
end_timer() {
    local component="$1"
    local process_name="$2"
    local process_id="$3"
    local status="${4:-SUCCESS}"
    
    if [ -f "/tmp/timer_${process_id}" ]; then
        local start_time=$(cat "/tmp/timer_${process_id}")
        local end_time=$(date +%s%3N)
        local duration=$(( (end_time - start_time) ))
        local duration_seconds=$(echo "scale=3; $duration / 1000" | bc -l 2>/dev/null || echo "$duration ms")
        
        log_message "END" "$component" "$process_name (Duration: ${duration_seconds}s, Status: $status)" "$process_id"
        log_message "PERF" "$component" "Process '$process_name' took ${duration_seconds}s [Status: $status]" "$process_id"
        
        rm -f "/tmp/timer_${process_id}"
    else
        log_message "END" "$component" "$process_name (Status: $status)" "$process_id"
    fi
}

# Log system information
log_system_info() {
    local component="$1"
    
    log_message "INFO" "$component" "System Information Collection Started"
    log_message "INFO" "$component" "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
    log_message "INFO" "$component" "Kernel: $(uname -r)"
    log_message "INFO" "$component" "Architecture: $(uname -m)"
    log_message "INFO" "$component" "CPU: $(nproc) cores"
    log_message "INFO" "$component" "Memory: $(free -h | grep '^Mem:' | awk '{print $2}') total"
    log_message "INFO" "$component" "Disk Space: $(df -h / | tail -1 | awk '{print $4}') available"
    log_message "INFO" "$component" "Current User: $(whoami) (UID: $(id -u))"
    log_message "INFO" "$component" "Home Directory: $HOME"
    log_message "INFO" "$component" "Working Directory: $(pwd)"
    log_message "INFO" "$component" "PATH: $PATH"
    
    # Docker information
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then
            log_message "INFO" "$component" "Docker: Available and running"
            log_message "INFO" "$component" "Docker Version: $(docker --version)"
        else
            log_message "WARN" "$component" "Docker: Installed but not running"
        fi
    else
        log_message "WARN" "$component" "Docker: Not installed"
    fi
    
    # Python information
    if command -v python3 >/dev/null 2>&1; then
        log_message "INFO" "$component" "Python: $(python3 --version)"
        log_message "INFO" "$component" "Pip: $(python3 -m pip --version)"
    else
        log_message "ERROR" "$component" "Python3: Not available"
    fi
}

# Log command execution with output capture
log_command() {
    local component="$1"
    local command="$2"
    local description="$3"
    local timeout_seconds="${4:-300}"
    
    local process_id=$(start_timer "$component" "$description")
    local temp_output="/tmp/cmd_output_${process_id}"
    local temp_error="/tmp/cmd_error_${process_id}"
    
    log_message "INFO" "$component" "Executing command: $command" "$process_id"
    
    # Execute command with timeout and capture output
    if timeout "$timeout_seconds" bash -c "$command" > "$temp_output" 2> "$temp_error"; then
        local exit_code=0
        log_message "INFO" "$component" "Command succeeded" "$process_id"
    else
        local exit_code=$?
        log_message "ERROR" "$component" "Command failed with exit code: $exit_code" "$process_id"
    fi
    
    # Log output if not empty
    if [ -s "$temp_output" ]; then
        log_message "INFO" "$component" "Command output:" "$process_id"
        while IFS= read -r line; do
            log_message "INFO" "$component" "OUT: $line" "$process_id"
        done < "$temp_output"
    fi
    
    # Log errors if not empty
    if [ -s "$temp_error" ]; then
        log_message "WARN" "$component" "Command stderr:" "$process_id"
        while IFS= read -r line; do
            log_message "WARN" "$component" "ERR: $line" "$process_id"
        done < "$temp_error"
    fi
    
    # Clean up temp files
    rm -f "$temp_output" "$temp_error"
    
    # End timer with status
    if [ $exit_code -eq 0 ]; then
        end_timer "$component" "$description" "$process_id" "SUCCESS"
    else
        end_timer "$component" "$description" "$process_id" "FAILED"
    fi
    
    return $exit_code
}

# Log network connectivity test
log_network_test() {
    local component="$1"
    local test_url="${2:-https://github.com}"
    
    local process_id=$(start_timer "$component" "Network connectivity test to $test_url")
    
    if curl -s --connect-timeout 10 --max-time 30 "$test_url" >/dev/null; then
        log_message "INFO" "$component" "Network connectivity: OK ($test_url)" "$process_id"
        end_timer "$component" "Network connectivity test" "$process_id" "SUCCESS"
        return 0
    else
        log_message "ERROR" "$component" "Network connectivity: FAILED ($test_url)" "$process_id"
        end_timer "$component" "Network connectivity test" "$process_id" "FAILED"
        return 1
    fi
}

# Generate build summary report
generate_build_report() {
    local component="$1"
    local report_file="$LOG_DIR/build-summary-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
################################################################################
# Secure Architecture Sandbox Build Summary Report
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
################################################################################

## Build Process Overview
$(grep -c "\[START\]" "$MAIN_LOG_FILE" 2>/dev/null || echo "0") processes started
$(grep -c "\[END\].*SUCCESS" "$MAIN_LOG_FILE" 2>/dev/null || echo "0") processes completed successfully
$(grep -c "\[END\].*FAILED" "$MAIN_LOG_FILE" 2>/dev/null || echo "0") processes failed
$(grep -c "\[ERROR\]" "$MAIN_LOG_FILE" 2>/dev/null || echo "0") errors encountered
$(grep -c "\[WARN\]" "$MAIN_LOG_FILE" 2>/dev/null || echo "0") warnings issued

## Performance Summary
$(tail -20 "$PERFORMANCE_LOG_FILE" 2>/dev/null || echo "No performance data available")

## Recent Errors
$(tail -10 "$ERROR_LOG_FILE" 2>/dev/null || echo "No errors logged")

## Log Files
- Main Log: $MAIN_LOG_FILE
- Error Log: $ERROR_LOG_FILE
- Performance Log: $PERFORMANCE_LOG_FILE
- This Report: $report_file

EOF

    log_message "INFO" "$component" "Build summary report generated: $report_file"
    echo "$report_file"
}

# Print current log status
log_status() {
    echo "################################################################################"
    echo "# Build Process Logging Status"
    echo "################################################################################"
    echo "Log Directory: $LOG_DIR"
    echo "Main Log: $MAIN_LOG_FILE ($(wc -l < "$MAIN_LOG_FILE" 2>/dev/null || echo "0") lines)"
    echo "Error Log: $ERROR_LOG_FILE ($(wc -l < "$ERROR_LOG_FILE" 2>/dev/null || echo "0") lines)"
    echo "Performance Log: $PERFORMANCE_LOG_FILE ($(wc -l < "$PERFORMANCE_LOG_FILE" 2>/dev/null || echo "0") lines)"
    echo ""
    echo "Recent Activity (last 5 entries):"
    tail -5 "$MAIN_LOG_FILE" 2>/dev/null || echo "No recent activity"
    echo "################################################################################"
}

# Export functions for use in other scripts
export -f init_logging
export -f timestamp
export -f generate_process_id
export -f log_message
export -f start_timer
export -f end_timer
export -f log_system_info
export -f log_command
export -f log_network_test
export -f generate_build_report
export -f log_status

# If script is run directly, show help
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo "Build Logger Functions Available:"
    echo "  init_logging               - Initialize the logging system"
    echo "  log_message LEVEL COMP MSG - Log a message"
    echo "  start_timer COMP NAME      - Start timing a process"
    echo "  end_timer COMP NAME PID    - End timing a process"
    echo "  log_system_info COMP       - Log system information"
    echo "  log_command COMP CMD DESC  - Execute and log a command"
    echo "  log_network_test COMP URL  - Test network connectivity"
    echo "  generate_build_report COMP - Generate summary report"
    echo "  log_status                 - Show current log status"
    echo ""
    echo "Example usage:"
    echo "  source $0"
    echo "  init_logging"
    echo "  PID=\$(start_timer 'SETUP' 'Installing packages')"
    echo "  # ... do work ..."
    echo "  end_timer 'SETUP' 'Installing packages' \"\$PID\" 'SUCCESS'"
fi