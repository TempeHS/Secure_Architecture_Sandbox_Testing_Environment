#!/bin/bash
# Build Failure Diagnosis and Monitoring Script
# Provides comprehensive build monitoring and failure analysis

set -euo pipefail

# Source logging functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/build-logger.sh"

init_logging "BUILD_MONITOR"
log_start "Build Monitoring and Diagnosis"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
LOG_DIR="/tmp/sandbox-build-logs"
WATCH_INTERVAL=5
MAX_LOG_SIZE=10485760  # 10MB
RETENTION_DAYS=7

show_usage() {
    cat << EOF
Build Failure Diagnosis Tool

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    monitor         Start real-time build monitoring
    analyze         Analyze existing build logs
    watch           Watch for build failures in real-time
    clean           Clean old logs and reports
    status          Show current build status
    test            Run build test sequence
    help            Show this help message

Options:
    --log-dir DIR   Set log directory (default: $LOG_DIR)
    --interval SEC  Set monitoring interval (default: ${WATCH_INTERVAL}s)
    --format FORMAT Output format: text|json (default: text)
    --output FILE   Write report to file
    --verbose       Enable verbose output

Examples:
    $0 analyze                    # Analyze all logs
    $0 monitor --interval 10      # Monitor with 10s interval
    $0 watch                      # Watch for failures
    $0 status                     # Show current status

EOF
}

setup_monitoring() {
    log_info "Setting up build monitoring environment"
    
    # Create log directory if it doesn't exist
    mkdir -p "$LOG_DIR"
    
    # Create monitoring scripts directory
    mkdir -p "$LOG_DIR/scripts"
    
    # Set up log rotation
    if command -v logrotate >/dev/null 2>&1; then
        cat > "$LOG_DIR/logrotate.conf" << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    maxsize ${MAX_LOG_SIZE}
}
EOF
        log_info "Log rotation configured"
    fi
    
    log_info "Monitoring environment ready"
}

monitor_build_processes() {
    local interval=${1:-$WATCH_INTERVAL}
    
    log_info "Starting build process monitoring (interval: ${interval}s)"
    
    local monitor_log="$LOG_DIR/monitor.log"
    
    while true; do
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        
        # Check Docker daemon status
        if ! docker info >/dev/null 2>&1; then
            echo "[$timestamp] ERROR: Docker daemon not accessible" >> "$monitor_log"
            log_error "Docker daemon not accessible"
        fi
        
        # Check for active build processes
        local build_procs=$(pgrep -f "docker.*build\|npm.*install\|pip.*install" 2>/dev/null || true)
        if [ -n "$build_procs" ]; then
            echo "[$timestamp] INFO: Active build processes: $build_procs" >> "$monitor_log"
            log_info "Active build processes detected: $build_procs"
        fi
        
        # Check system resources
        local memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
        local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
        
        if (( $(echo "$memory_usage > 90" | bc -l) )); then
            echo "[$timestamp] WARN: High memory usage: ${memory_usage}%" >> "$monitor_log"
            log_warn "High memory usage: ${memory_usage}%"
        fi
        
        if (( disk_usage > 90 )); then
            echo "[$timestamp] WARN: High disk usage: ${disk_usage}%" >> "$monitor_log"
            log_warn "High disk usage: ${disk_usage}%"
        fi
        
        # Check for recent errors
        if [ -f "$LOG_DIR/build-process.log" ]; then
            local recent_errors=$(tail -n 100 "$LOG_DIR/build-process.log" | grep -c "ERROR\|FATAL" || true)
            if (( recent_errors > 5 )); then
                echo "[$timestamp] WARN: High error rate detected: $recent_errors errors in last 100 entries" >> "$monitor_log"
                log_warn "High error rate detected: $recent_errors errors in last 100 entries"
            fi
        fi
        
        sleep "$interval"
    done
}

watch_for_failures() {
    log_info "Starting build failure watcher"
    
    local failure_log="$LOG_DIR/failures.log"
    
    # Watch all log files for errors
    if command -v inotifywait >/dev/null 2>&1; then
        log_info "Using inotify for real-time log monitoring"
        
        inotifywait -m -e modify "$LOG_DIR"/*.log 2>/dev/null | while read path action file; do
            if [[ "$action" == "MODIFY" ]]; then
                # Check for new errors in the modified file
                local new_errors=$(tail -n 5 "$path/$file" | grep -E "ERROR|FATAL" || true)
                if [ -n "$new_errors" ]; then
                    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                    echo "[$timestamp] FAILURE DETECTED in $file:" >> "$failure_log"
                    echo "$new_errors" >> "$failure_log"
                    echo "---" >> "$failure_log"
                    
                    log_error "Build failure detected in $file"
                    echo -e "${RED}🚨 BUILD FAILURE DETECTED${NC}"
                    echo -e "${YELLOW}File: $file${NC}"
                    echo -e "${YELLOW}Errors:${NC}"
                    echo "$new_errors"
                    echo ""
                fi
            fi
        done
    else
        log_warn "inotify not available, using polling method"
        
        local last_check=$(date +%s)
        while true; do
            local current_time=$(date +%s)
            
            # Check for new errors since last check
            find "$LOG_DIR" -name "*.log" -newer "/tmp/last_check_$$" 2>/dev/null | while read logfile; do
                local new_errors=$(grep -E "ERROR|FATAL" "$logfile" || true)
                if [ -n "$new_errors" ]; then
                    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                    echo "[$timestamp] FAILURE DETECTED in $(basename "$logfile"):" >> "$failure_log"
                    echo "$new_errors" >> "$failure_log"
                    echo "---" >> "$failure_log"
                    
                    log_error "Build failure detected in $(basename "$logfile")"
                fi
            done
            
            touch "/tmp/last_check_$$"
            sleep "$WATCH_INTERVAL"
        done
    fi
}

run_analysis() {
    local format=${1:-text}
    local output_file=${2:-}
    
    log_info "Running build log analysis"
    
    if [ ! -f "${SCRIPT_DIR}/analyze-build-logs.py" ]; then
        log_error "Analysis script not found: ${SCRIPT_DIR}/analyze-build-logs.py"
        return 1
    fi
    
    local python_cmd="python3"
    if ! command -v python3 >/dev/null 2>&1; then
        python_cmd="python"
    fi
    
    local cmd_args=(
        "${SCRIPT_DIR}/analyze-build-logs.py"
        "--log-dir" "$LOG_DIR"
        "--format" "$format"
    )
    
    if [ -n "$output_file" ]; then
        cmd_args+=("--output" "$output_file")
    fi
    
    log_command "$python_cmd ${cmd_args[*]}"
    
    if "$python_cmd" "${cmd_args[@]}"; then
        log_info "Analysis completed successfully"
        return 0
    else
        log_error "Analysis failed"
        return 1
    fi
}

show_status() {
    log_info "Checking build system status"
    
    echo -e "${BLUE}🔍 Build System Status${NC}"
    echo "=========================="
    
    # Docker status
    if docker info >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Docker daemon: Running${NC}"
    else
        echo -e "${RED}❌ Docker daemon: Not accessible${NC}"
    fi
    
    # Log directory status
    if [ -d "$LOG_DIR" ]; then
        local log_count=$(find "$LOG_DIR" -name "*.log" -type f | wc -l)
        local total_size=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1)
        echo -e "${GREEN}✅ Log directory: $LOG_DIR ($log_count files, $total_size)${NC}"
    else
        echo -e "${RED}❌ Log directory: Missing${NC}"
    fi
    
    # Active processes
    local build_procs=$(pgrep -f "docker.*build\|npm.*install\|pip.*install" 2>/dev/null | wc -l)
    if [ "$build_procs" -gt 0 ]; then
        echo -e "${YELLOW}⚠️  Active build processes: $build_procs${NC}"
    else
        echo -e "${GREEN}✅ No active build processes${NC}"
    fi
    
    # Recent activity
    if [ -f "$LOG_DIR/build-process.log" ]; then
        local last_entry=$(tail -n 1 "$LOG_DIR/build-process.log" 2>/dev/null || echo "No entries")
        echo -e "${BLUE}📝 Last log entry:${NC} ${last_entry:0:80}..."
        
        local recent_errors=$(tail -n 100 "$LOG_DIR/build-process.log" 2>/dev/null | grep -c "ERROR\|FATAL" || echo "0")
        if [ "$recent_errors" -gt 0 ]; then
            echo -e "${RED}🚨 Recent errors: $recent_errors${NC}"
        else
            echo -e "${GREEN}✅ No recent errors${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  No build log found${NC}"
    fi
    
    # System resources
    local memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    
    echo -e "${BLUE}💾 Memory usage: ${memory_usage}%${NC}"
    echo -e "${BLUE}💽 Disk usage: ${disk_usage}%${NC}"
    
    echo ""
}

run_build_test() {
    log_info "Running build test sequence"
    
    echo -e "${BLUE}🧪 Build Test Sequence${NC}"
    echo "======================="
    
    # Test 1: Docker connectivity
    echo -n "Testing Docker connectivity... "
    if docker info >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        log_error "Docker connectivity test failed"
    fi
    
    # Test 2: Python environment
    echo -n "Testing Python environment... "
    if python3 -c "import sys; print('Python', sys.version)" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        log_error "Python environment test failed"
    fi
    
    # Test 3: Log directory writable
    echo -n "Testing log directory access... "
    if [ -w "$LOG_DIR" ] || mkdir -p "$LOG_DIR" 2>/dev/null; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        log_error "Log directory access test failed"
    fi
    
    # Test 4: Analysis script
    echo -n "Testing analysis script... "
    if [ -f "${SCRIPT_DIR}/analyze-build-logs.py" ]; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        log_error "Analysis script test failed"
    fi
    
    echo ""
    log_info "Build test sequence completed"
}

clean_logs() {
    log_info "Cleaning old logs and reports"
    
    if [ ! -d "$LOG_DIR" ]; then
        log_warn "Log directory does not exist: $LOG_DIR"
        return 0
    fi
    
    # Remove logs older than retention period
    local cleaned_count=0
    while IFS= read -r -d '' file; do
        rm -f "$file"
        ((cleaned_count++))
    done < <(find "$LOG_DIR" -name "*.log" -type f -mtime +${RETENTION_DAYS} -print0 2>/dev/null || true)
    
    # Remove empty directories
    find "$LOG_DIR" -type d -empty -delete 2>/dev/null || true
    
    log_info "Cleaned $cleaned_count old log files"
    echo "Cleaned $cleaned_count files older than $RETENTION_DAYS days"
}

# Main script logic
main() {
    local command=${1:-help}
    shift || true
    
    # Parse options
    local format="text"
    local output_file=""
    local interval="$WATCH_INTERVAL"
    local verbose=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --log-dir)
                LOG_DIR="$2"
                shift 2
                ;;
            --interval)
                interval="$2"
                shift 2
                ;;
            --format)
                format="$2"
                shift 2
                ;;
            --output)
                output_file="$2"
                shift 2
                ;;
            --verbose)
                verbose=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Execute command
    case $command in
        monitor)
            setup_monitoring
            monitor_build_processes "$interval"
            ;;
        analyze)
            run_analysis "$format" "$output_file"
            ;;
        watch)
            setup_monitoring
            watch_for_failures
            ;;
        status)
            show_status
            ;;
        test)
            run_build_test
            ;;
        clean)
            clean_logs
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            echo "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Cleanup on exit
cleanup() {
    log_end "Build Monitoring and Diagnosis" "COMPLETED"
    rm -f "/tmp/last_check_$$" 2>/dev/null || true
}
trap cleanup EXIT

# Run main function with all arguments
main "$@"