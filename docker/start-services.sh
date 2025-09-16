#!/bin/bash

# Cybersecurity Sandbox Startup Script
# This script automatically starts educational applications for security testing

set -e

echo "🚀 Starting Cybersecurity Sandbox Services..."

# Wait for the workspace to be mounted
echo "⏳ Waiting for workspace to be ready..."
while [ ! -d "/workspace/samples" ]; do
    sleep 1
done

# Set environment variables
export PYTHONPATH="/workspace/src"
export FLASK_ENV=development
export FLASK_DEBUG=1

# Create necessary directories
mkdir -p /workspace/logs /workspace/reports

# Function to start Flask vulnerable application
start_flask_app() {
    echo "🔴 Starting Vulnerable Flask Application on port 5000..."
    cd /workspace/samples/vulnerable-flask-app
    
    # Start Flask app in background with logging
    python app.py > /workspace/logs/flask-app.log 2>&1 &
    FLASK_PID=$!
    echo $FLASK_PID > /workspace/logs/flask-app.pid
    
    # Wait a moment and check if it started successfully
    sleep 3
    if kill -0 $FLASK_PID 2>/dev/null; then
        echo "✅ Flask app started successfully (PID: $FLASK_PID)"
    else
        echo "❌ Flask app failed to start. Check /workspace/logs/flask-app.log"
        cat /workspace/logs/flask-app.log
    fi
}

# Function to check if Flask app is running
check_flask_status() {
    if [ -f "/workspace/logs/flask-app.pid" ]; then
        PID=$(cat /workspace/logs/flask-app.pid)
        if kill -0 $PID 2>/dev/null; then
            echo "✅ Flask app is running (PID: $PID)"
            return 0
        fi
    fi
    echo "❌ Flask app is not running"
    return 1
}

# Function to start additional services if needed
start_additional_services() {
    echo "🔧 Checking for additional services..."
    
    # You can add more services here in the future
    # For example: start_network_monitors, start_log_analyzers, etc.
    
    echo "✅ All additional services checked"
}

# Function to cleanup on exit
cleanup() {
    echo "🛑 Stopping services..."
    if [ -f "/workspace/logs/flask-app.pid" ]; then
        PID=$(cat /workspace/logs/flask-app.pid)
        if kill -0 $PID 2>/dev/null; then
            kill $PID
            echo "✅ Flask app stopped"
        fi
        rm -f /workspace/logs/flask-app.pid
    fi
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Start services
start_flask_app
start_additional_services

echo "🎯 Cybersecurity Sandbox is ready!"
echo "📊 Services status:"
check_flask_status
echo "🌐 Access vulnerable Flask app at: http://localhost:5000"
echo "🌐 Access PWA application at: http://localhost:9090"
echo "📝 Logs are available in: /workspace/logs/"

# Keep the container running and monitor services
while true; do
    sleep 30
    
    # Check if Flask app is still running, restart if needed
    if ! check_flask_status; then
        echo "🔄 Restarting Flask application..."
        start_flask_app
    fi
done