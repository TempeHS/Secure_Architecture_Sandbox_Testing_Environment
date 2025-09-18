#!/usr/bin/env python3
"""
Comprehensive test script to verify all security tools and environment setup
for the Secure Architecture Sandbox Testing Environment project.
"""
import subprocess
import sys
import os
import importlib.util
from pathlib import Path


class Colors:
    """ANSI color codes for colored output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_header(text):
    """Print a formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(60)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")


def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")


def print_error(text):
    """Print error message"""
    print(f"{Colors.RED}❌ {text}{Colors.END}")


def print_warning(text):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")


def print_info(text):
    """Print info message"""
    print(f"{Colors.CYAN}ℹ️  {text}{Colors.END}")


def test_command_tool(tool_name, command, expected_in_output=None):
    """Test if a command-line tool is available and working"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            shell=False
        )

        if result.returncode == 0:
            if expected_in_output and expected_in_output.lower() not in result.stdout.lower():
                print_warning(f"{tool_name}: Available but unexpected output")
                return False
            print_success(f"{tool_name}: Available and working")
            return True
        else:
            print_error(
                f"{tool_name}: Command failed (return code: {result.returncode})")
            return False

    except subprocess.TimeoutExpired:
        print_error(f"{tool_name}: Command timed out")
        return False
    except FileNotFoundError:
        print_error(f"{tool_name}: Command not found")
        return False
    except Exception as e:
        print_error(f"{tool_name}: Unexpected error - {str(e)}")
        return False


def test_python_package(package_name, import_name=None):
    """Test if a Python package is available"""
    if import_name is None:
        import_name = package_name

    try:
        spec = importlib.util.find_spec(import_name)
        if spec is not None:
            print_success(f"Python package '{package_name}': Available")
            return True
        else:
            print_error(f"Python package '{package_name}': Not found")
            return False
    except Exception as e:
        print_error(f"Python package '{package_name}': Error - {str(e)}")
        return False


def test_directory_structure():
    """Test if the required directory structure exists"""
    print_header("Testing Directory Structure")

    required_dirs = [
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/src",
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/src/sandbox",
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/src/analyzer",
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/src/reporter",
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/samples",
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/docs",
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/reports",
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/logs"
    ]

    all_good = True
    for directory in required_dirs:
        if os.path.exists(directory) and os.path.isdir(directory):
            print_success(f"Directory exists: {directory}")
        else:
            print_error(f"Directory missing: {directory}")
            all_good = False

    return all_good


def test_security_tools():
    """Test all security tools"""
    print_header("Testing Security Tools")

    tools = [
        ("Nmap", ["nmap", "--version"], "nmap"),
        ("Nikto", ["nikto", "-Version"], "nikto"),
        ("Gobuster", ["gobuster", "version"], "gobuster"),
        ("WhatWeb", ["whatweb", "--version"], "whatweb"),
        ("Dirb", ["dirb"], "dirb"),  # dirb shows help when no args
        ("Netcat", ["nc", "-h"], None),  # nc shows help with -h
        ("Curl", ["curl", "--version"], "curl"),
        ("Wget", ["wget", "--version"], "wget"),
    ]

    passed = 0
    total = len(tools)

    for tool_name, command, expected in tools:
        if test_command_tool(tool_name, command, expected):
            passed += 1

    print(f"\n{Colors.BOLD}Security Tools: {passed}/{total} available{Colors.END}")
    return passed >= total - 1  # Allow one tool to fail


def test_python_tools():
    """Test Python security and analysis packages"""
    print_header("Testing Python Security Packages")

    packages = [
        ("bandit", "bandit"),
        ("safety", "safety"),
        ("semgrep", "semgrep"),
        ("requests", "requests"),
        ("beautifulsoup4", "bs4"),
        ("flask", "flask"),
        ("reportlab", "reportlab"),
        ("jinja2", "jinja2"),
        ("pyyaml", "yaml"),
        ("python-nmap", "nmap"),
        ("scapy", "scapy"),
        ("pytest", "pytest"),
        ("black", "black"),
        ("flake8", "flake8"),
    ]

    passed = 0
    total = len(packages)

    for package_name, import_name in packages:
        if test_python_package(package_name, import_name):
            passed += 1

    print(f"\n{Colors.BOLD}Python Packages: {passed}/{total} available{Colors.END}")
    return passed >= total - 2  # Allow two packages to fail


def test_system_tools():
    """Test basic system tools"""
    print_header("Testing System Tools")

    tools = [
        ("Python3", ["python3", "--version"], "python"),
        ("Git", ["git", "--version"], "git"),
        ("Docker", ["docker", "--version"], "docker"),
        ("Node.js", ["node", "--version"], None),
        ("NPM", ["npm", "--version"], None),
        ("Tree", ["tree", "--version"], None),
        ("JQ", ["jq", "--version"], "jq"),
    ]

    passed = 0
    total = len(tools)

    for tool_name, command, expected in tools:
        if test_command_tool(tool_name, command, expected):
            passed += 1

    print(f"\n{Colors.BOLD}System Tools: {passed}/{total} available{Colors.END}")
    return passed >= total - 2  # Allow two tools to fail


def test_environment():
    """Test environment variables and settings"""
    print_header("Testing Environment")

    env_vars = [
        ("PYTHONPATH", "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/src"),
        ("USER", "vscode"),
    ]

    all_good = True
    for var_name, expected in env_vars:
        actual = os.environ.get(var_name)
        if actual:
            if expected and expected not in actual:
                print_warning(
                    f"{var_name}: Set to '{actual}' (expected to contain '{expected}')")
            else:
                print_success(f"{var_name}: {actual}")
        else:
            print_warning(f"{var_name}: Not set")
            all_good = False

    # Check Python version
    python_version = sys.version_info
    if python_version >= (3, 8):
        print_success(
            f"Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
    else:
        print_error(
            f"Python version too old: {python_version.major}.{python_version.minor}.{python_version.micro}")
        all_good = False

    return all_good


def test_file_permissions():
    """Test file permissions and accessibility"""
    print_header("Testing File Permissions")

    test_files = [
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/.devcontainer/test_tools.py",
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/WELCOME.md",
        "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/src/__init__.py",
    ]

    all_good = True
    for file_path in test_files:
        if os.path.exists(file_path):
            if os.access(file_path, os.R_OK):
                print_success(f"Can read: {file_path}")
            else:
                print_error(f"Cannot read: {file_path}")
                all_good = False
        else:
            print_warning(f"File not found: {file_path}")

    # Test write permission to reports directory
    reports_dir = "/workspaces/Secure_Architecture_Sandbox_Testing_Environment/reports"
    if os.path.exists(reports_dir) and os.access(reports_dir, os.W_OK):
        print_success(f"Can write to: {reports_dir}")
    else:
        print_error(f"Cannot write to: {reports_dir}")
        all_good = False

    return all_good


def run_comprehensive_test():
    """Run all tests and provide a comprehensive report"""
    print_header("Cybersecurity Sandbox Environment Test")
    print_info(
        "This script will verify that all tools and dependencies are properly installed")

    tests = [
        ("Directory Structure", test_directory_structure),
        ("Environment Settings", test_environment),
        ("System Tools", test_system_tools),
        ("Security Tools", test_security_tools),
        ("Python Packages", test_python_tools),
        ("File Permissions", test_file_permissions),
    ]

    results = []

    for test_name, test_function in tests:
        try:
            result = test_function()
            results.append((test_name, result))
        except Exception as e:
            print_error(f"Test '{test_name}' failed with exception: {str(e)}")
            results.append((test_name, False))

    # Final report
    print_header("Test Results Summary")

    passed_tests = 0
    total_tests = len(results)

    for test_name, passed in results:
        if passed:
            print_success(f"{test_name}: PASSED")
            passed_tests += 1
        else:
            print_error(f"{test_name}: FAILED")

    print(f"\n{Colors.BOLD}{Colors.MAGENTA}Overall Result: {passed_tests}/{total_tests} tests passed{Colors.END}")

    if passed_tests == total_tests:
        print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 All tests passed! Your cybersecurity sandbox is ready for use!{Colors.END}")
        return 0
    elif passed_tests >= total_tests - 2:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}✅ Most tests passed! The environment should work for basic educational use.{Colors.END}")
        return 0
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}❌ Several tests failed. Please check the setup and try again.{Colors.END}")
        return 1


if __name__ == "__main__":
    try:
        exit_code = run_comprehensive_test()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Test interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Unexpected error: {str(e)}{Colors.END}")
        sys.exit(1)
