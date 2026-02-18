#!/bin/bash

# Script to open welcome files after environment setup is complete
echo "📖 Opening welcome files..."

WELCOME_FILE="/workspaces/Secure_Architecture_Sandbox_Testing_Environment/WELCOME.md"

# Wait a moment for VS Code to be fully ready
sleep 3

# Touch the file to update its timestamp — this nudges VS Code's file watcher
# to detect the change and refresh any already-open markdown preview
touch "$WELCOME_FILE"
sleep 1

# Close any stale preview of WELCOME.md first, then reopen it fresh.
# The --wait flag on the first open ensures the tab is focused before we
# trigger the reopen cycle, but we use --goto to force VS Code to treat
# it as a new navigation.
code --reuse-window "$WELCOME_FILE"

echo "✅ WELCOME.md should now be open in your editor"
