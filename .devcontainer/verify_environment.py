#!/usr/bin/env python3
"""
Verification script to test the Cybersecurity Sandbox environment
This script confirms that all dependencies are correctly installed
"""

import sys
import subprocess
import importlib

def test_python_package(package_name, import_name=None):
    """Test if a Python package can be imported"""
    if import_name is None:
        import_name = package_name
    
    try:
        importlib.import_module(import_name)
        print(f"✅ {package_name}: Available")
        return True
    except ImportError:
        print(f"❌ {package_name}: Not available")
        return False

def test_command_tool(tool_name, command):
    """Test if a command-line tool is available"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ {tool_name}: Available")
            return True
        else:
            print(f"❌ {tool_name}: Available but returned error")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print(f"❌ {tool_name}: Not available")
        return False
    except Exception as e:
        print(f"❌ {tool_name}: Error - {str(e)}")
        return False

def main():
    print("🔍 Verifying Cybersecurity Sandbox Environment...\n")
    
    # Test Python packages
    print("📦 Testing Python packages:")
    python_packages = [
        ("Flask", "flask"),
        ("Requests", "requests"),
        ("BeautifulSoup4", "bs4"),
        ("PyYAML", "yaml"),
        ("Bandit", "bandit"),
        ("Safety", "safety"),
        ("Pytest", "pytest"),
        ("Black", "black"),
        ("Flake8", "flake8"),
        ("Jinja2", "jinja2"),
        ("ReportLab", "reportlab"),
        ("Python-nmap", "nmap"),
    ]
    
    python_available = 0
    for package_name, import_name in python_packages:
        if test_python_package(package_name, import_name):
            python_available += 1
    
    print(f"\n📊 {python_available}/{len(python_packages)} Python packages available\n")
    
    # Test command-line tools
    print("🔧 Testing command-line tools:")
    cli_tools = [
        ("Python3", ["python3", "--version"]),
        ("Pip3", ["python3", "-m", "pip", "--version"]),
        ("Nmap", ["nmap", "--version"]),
        ("Nikto", ["nikto", "-Version"]),
        ("Gobuster", ["gobuster", "version"]),
        ("WhatWeb", ["whatweb", "--version"]),
        ("Curl", ["curl", "--version"]),
        ("Wget", ["wget", "--version"]),
        ("Git", ["git", "--version"]),
        ("Docker", ["docker", "--version"]),
    ]
    
    cli_available = 0
    for tool_name, command in cli_tools:
        if test_command_tool(tool_name, command):
            cli_available += 1
    
    print(f"\n📊 {cli_available}/{len(cli_tools)} command-line tools available\n")
    
    # Test Flask specifically
    print("🌐 Testing Flask application capability:")
    try:
        import flask
        print(f"✅ Flask version: {flask.__version__}")
        
        # Test creating a simple Flask app
        app = flask.Flask(__name__)
        
        @app.route('/test')
        def test():
            return "Flask is working!"
        
        print("✅ Flask app creation: Success")
        flask_working = True
    except Exception as e:
        print(f"❌ Flask test failed: {e}")
        flask_working = False
    
    # Summary
    print("\n" + "="*50)
    print("📋 ENVIRONMENT VERIFICATION SUMMARY")
    print("="*50)
    
    total_available = python_available + cli_available + (1 if flask_working else 0)
    total_expected = len(python_packages) + len(cli_tools) + 1
    
    print(f"📦 Python packages: {python_available}/{len(python_packages)}")
    print(f"🔧 CLI tools: {cli_available}/{len(cli_tools)}")
    print(f"🌐 Flask capability: {'✅' if flask_working else '❌'}")
    print(f"📊 Overall: {total_available}/{total_expected} components working")
    
    if total_available >= total_expected * 0.9:  # 90% threshold
        print("\n🎉 Environment is ready for cybersecurity education!")
        print("🚀 You can start developing Flask applications and using security tools.")
        return 0
    else:
        print("\n⚠️  Environment setup may be incomplete.")
        print("🔧 Some tools or packages may need manual installation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())