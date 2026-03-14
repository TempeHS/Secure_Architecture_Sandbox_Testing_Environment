#!/bin/bash
# Entrypoint script for student uploads container
# Auto-detects the student's application entry point file
# Supports: app.py, main.py, run.py, manage.py (Django)

set -e

APP_DIR="/app"
cd "$APP_DIR"

# Detect the application entry point in priority order
if [ -f "app.py" ]; then
    ENTRY_FILE="app.py"
elif [ -f "main.py" ]; then
    ENTRY_FILE="main.py"
elif [ -f "run.py" ]; then
    ENTRY_FILE="run.py"
elif [ -f "manage.py" ]; then
    ENTRY_FILE="manage.py"
else
    echo "ERROR: No application entry point found."
    echo "Place one of the following in the uploads/ folder:"
    echo "  - app.py    (Flask)"
    echo "  - main.py   (Flask)"
    echo "  - run.py    (Flask)"
    echo "  - manage.py (Django)"
    exit 1
fi

echo "=== Student Application Launcher ==="
echo "Detected entry point: $ENTRY_FILE"

# Django apps use manage.py runserver
if [ "$ENTRY_FILE" = "manage.py" ]; then
    echo "Django application detected - running manage.py runserver"
    exec python manage.py runserver 0.0.0.0:8000
else
    echo "Flask application detected - running $ENTRY_FILE"
    exec python "$ENTRY_FILE"
fi
