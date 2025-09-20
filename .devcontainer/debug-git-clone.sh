#!/bin/bash

# Debug script to help diagnose git clone issues
echo "🔍 GitHub Clone Diagnostics"
echo "=========================="
echo ""

# Check Git installation
echo "📦 Git Installation:"
if command -v git >/dev/null 2>&1; then
    git --version
    echo "✅ Git is installed"
else
    echo "❌ Git is not installed"
    exit 1
fi
echo ""

# Check Git configuration
echo "⚙️  Git Configuration:"
echo "User name: $(git config --global user.name 2>/dev/null || echo 'Not set')"
echo "User email: $(git config --global user.email 2>/dev/null || echo 'Not set')"
echo ""

# Check GitHub connectivity
echo "🌐 GitHub Connectivity:"
if curl -s --connect-timeout 10 https://github.com >/dev/null; then
    echo "✅ Can reach GitHub"
else
    echo "❌ Cannot reach GitHub"
fi
echo ""

# Check if repository is accessible
echo "🔐 Repository Access Test:"
repo_url="https://github.com/TempeHS/The_Unsecure_PWA.git"
echo "Testing access to: $repo_url"

# Try to get repository info without cloning
if git ls-remote --heads "$repo_url" >/dev/null 2>&1; then
    echo "✅ Repository is accessible"
    echo "Available branches:"
    git ls-remote --heads "$repo_url" | sed 's/.*refs\/heads\//  - /'
else
    echo "❌ Repository is not accessible or does not exist"
    echo "This could mean:"
    echo "  - Repository is private and you don't have access"
    echo "  - You're not a member of the TempeHS organization"
    echo "  - Repository doesn't exist"
    echo "  - Network/authentication issues"
fi
echo ""

# Check for authentication
echo "🔑 Authentication Status:"
if git config --global credential.helper >/dev/null 2>&1; then
    echo "Credential helper: $(git config --global credential.helper)"
else
    echo "No credential helper configured"
fi

# Check environment variables
if [ -n "$GITHUB_TOKEN" ]; then
    echo "✅ GITHUB_TOKEN environment variable is set"
else
    echo "⚠️  GITHUB_TOKEN environment variable is not set"
fi

if [ -n "$CODESPACE_NAME" ]; then
    echo "✅ Running in GitHub Codespace: $CODESPACE_NAME"
else
    echo "⚠️  Not running in GitHub Codespace"
fi
echo ""

# Test clone with verbose output
echo "🧪 Test Clone (dry run):"
echo "Attempting to clone with verbose output..."
git clone --dry-run -v "$repo_url" test-clone 2>&1 || echo "Clone test failed"
echo ""

echo "💡 Troubleshooting Tips:"
echo "1. Ensure you're a member of the TempeHS GitHub organization"
echo "2. Check if the repository is public or if you have access"
echo "3. Verify the 'sandbox_version' branch exists"
echo "4. Try authenticating with GitHub if needed"
echo "5. Contact your instructor if issues persist"