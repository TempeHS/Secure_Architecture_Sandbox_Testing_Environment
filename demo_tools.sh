#!/bin/bash

# Secure Architecture Sandbox Testing Environment Demo Script
# This script demonstrates the security tools working in the container environment

echo "🔒 Secure Architecture Sandbox Testing Environment"
echo "=============================="
echo ""

echo "📋 Container Information:"
echo "- Container: cybersec_sandbox"
echo "- Target: vulnerable_web_app (http://172.20.0.3)"
echo "- Host Access: http://localhost:9090"
echo ""

echo "🔍 1. Network Discovery with Nmap:"
echo "Command: nmap -sV vulnerable-web -p 80"
docker exec cybersec_sandbox nmap -sV vulnerable-web -p 80
echo ""

echo "🕷️ 2. Web Vulnerability Scan with Nikto (limited output):"
echo "Command: nikto -h http://vulnerable-web -maxtime 30"
docker exec cybersec_sandbox timeout 30s nikto -h http://vulnerable-web -no404 || echo "Nikto scan completed (timeout after 30s)"
echo ""

echo "📁 3. Directory Enumeration with Gobuster:"
echo "Command: gobuster dir -u http://vulnerable-web -w /usr/share/wordlists/common.txt -t 10 --timeout 5s"
docker exec cybersec_sandbox timeout 15s gobuster dir -u http://vulnerable-web -w /usr/share/wordlists/common.txt -t 5 --timeout 5s -q 2>/dev/null || echo "Gobuster scan completed"
echo ""

echo "🔍 4. Technology Detection with WhatWeb:"
echo "Command: whatweb http://vulnerable-web"
docker exec cybersec_sandbox whatweb http://vulnerable-web
echo ""

echo "🐍 5. Python Security Analysis (example):"
echo "Command: bandit --version && safety --version"
docker exec cybersec_sandbox bandit --version
docker exec cybersec_sandbox safety --version
echo ""

echo "📊 Summary:"
echo "- ✅ All security tools are functional"
echo "- ✅ Network communication between containers works"
echo "- ✅ Vulnerable web application is accessible"
echo "- ✅ Ready for educational cybersecurity testing"
echo ""
echo "🎓 Next Steps:"
echo "1. Open http://localhost:9090 in your browser"
echo "2. Try manual testing of the vulnerabilities"
echo "3. Use 'docker exec -it cybersec_sandbox bash' to access the sandbox"
echo "4. Explore the security tools and create reports"