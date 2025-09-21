#!/bin/bash

# Script to open welcome files after environment setup is complete
echo "📖 Opening welcome files..."

# Wait a moment for VS Code to be fully ready
sleep 3

# Open WELCOME.md for getting started instructions
code /workspaces/Secure_Architecture_Sandbox_Testing_Environment/WELCOME.md

echo "✅ WELCOME.md should now be open in your editor"
