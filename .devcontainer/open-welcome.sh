#!/bin/bash

# Script to open WELCOME.md in VS Code after environment setup
echo "📖 Opening WELCOME.md for getting started..."

# Get the workspace folder dynamically
WORKSPACE_DIR="${CODESPACE_VSCODE_FOLDER:-$(pwd)}"
if [ ! -d "$WORKSPACE_DIR" ]; then
    WORKSPACE_DIR="/workspaces/$(basename $(pwd))"
fi

# Wait a moment for VS Code to be fully ready
sleep 3

# Open WELCOME.md in VS Code
code "$WORKSPACE_DIR/WELCOME.md"

echo "✅ WELCOME.md should now be open in your editor"