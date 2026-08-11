#!/usr/bin/env python3
"""
Quick test script to verify security tools are available.
"""
import subprocess
import sys


def test_tool(tool_name, command):
    """Test if a security tool is available"""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=10)
        print(f"✅ {tool_name}: Available")
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print(f"❌ {tool_name}: Not available")
        return False


def main():
    print("🔍 Testing security tools availability...\n")

    tools = [
        ("Nmap", ["nmap", "--version"]),
        ("Nikto", ["nikto", "-Version"]),
        ("Gobuster", ["gobuster", "--version"]),
        ("WhatWeb", ["whatweb", "--version"]),
        ("httptap", ["httptap", "--help"]),
        ("Python3", ["python3", "--version"]),
        ("Bandit", ["bandit", "--version"]),
        ("Safety", ["safety", "--version"]),
        ("Curl", ["curl", "--version"]),
        ("Docker", ["docker", "--version"]),
        ("wkhtmltopdf", ["wkhtmltopdf", "--version"]),
    ]

    available = 0
    for tool_name, command in tools:
        if test_tool(tool_name, command):
            available += 1

    print(f"\n📊 {available}/{len(tools)} tools are available")

    # Test PDF generation capabilities
    print("\n🔍 Testing PDF generation capabilities...")
    try:
        import weasyprint
        print("✅ WeasyPrint: Available")
        pdf_available = True
    except ImportError as e:
        print(f"❌ WeasyPrint: Not available ({e})")
        pdf_available = False

    try:
        import reportlab
        print("✅ ReportLab: Available")
    except ImportError:
        print("❌ ReportLab: Not available")

    # Allow for a couple of tools to be missing
    if available >= len(tools) - 2 and pdf_available:
        print("🎉 Security tools and PDF generation are ready for educational use!")
        return 0
    elif available >= len(tools) - 1:
        print("🎉 Security tools are ready! PDF generation may need troubleshooting.")
        return 0
    else:
        print("⚠️  Some tools may need additional setup")
        return 1


if __name__ == "__main__":
    sys.exit(main())
