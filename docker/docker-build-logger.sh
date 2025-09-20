#!/bin/bash
# Docker Build Logger
# This script is sourced in Dockerfiles to add logging capabilities

# Simple logging function for Docker builds
docker_log() {
    local level="$1"
    local stage="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    
    echo "[$timestamp] [DOCKER-$level] [$stage] $message" | tee -a /tmp/docker-build.log
}

# Log build stage start
docker_stage_start() {
    local stage="$1"
    local description="$2"
    docker_log "START" "$stage" "$description"
}

# Log build stage end
docker_stage_end() {
    local stage="$1"
    local description="$2"
    local status="${3:-SUCCESS}"
    docker_log "END" "$stage" "$description (Status: $status)"
}

# Log build command execution
docker_run_logged() {
    local stage="$1"
    local description="$2"
    shift 2
    
    docker_log "INFO" "$stage" "Executing: $description"
    
    if "$@"; then
        docker_log "INFO" "$stage" "Command succeeded: $description"
        return 0
    else
        local exit_code=$?
        docker_log "ERROR" "$stage" "Command failed with exit code $exit_code: $description"
        return $exit_code
    fi
}

# Export functions
export -f docker_log
export -f docker_stage_start
export -f docker_stage_end
export -f docker_run_logged