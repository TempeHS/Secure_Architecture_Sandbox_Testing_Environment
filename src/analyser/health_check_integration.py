#!/usr/bin/env python3
"""
Health Check Integration Module

This module provides health check functionality for all security analysis tools.
It ensures target applications are running before attempting security testing.
"""

import sys
from pathlib import Path
from typing import List, Optional
import re

# Add the tests directory to the path to import the health checker
tests_dir = Path(__file__).parent.parent.parent / 'tests'
sys.path.append(str(tests_dir))

try:
    from ondemand_app_unittest import run_health_check
    HEALTH_CHECK_AVAILABLE = True
except ImportError:
    HEALTH_CHECK_AVAILABLE = False


def extract_ports_from_url(url: str) -> List[int]:
    """
    Extract port numbers from URLs.

    Args:
        url: URL string to parse

    Returns:
        List of port numbers found in the URL
    """
    ports = []

    # Extract explicit port from URL
    port_match = re.search(r':(\d+)', url)
    if port_match:
        ports.append(int(port_match.group(1)))
    else:
        # Default ports for protocols
        if url.startswith('https://'):
            ports.append(443)
        elif url.startswith('http://'):
            ports.append(80)

    return ports


def extract_ports_from_target(target: str) -> List[int]:
    """
    Extract port numbers from various target formats.

    Args:
        target: Target string (URL, hostname:port, IP:port, etc.)

    Returns:
        List of port numbers to check
    """
    ports = []

    # If it's a URL, extract ports from URL
    if target.startswith(('http://', 'https://')):
        return extract_ports_from_url(target)

    # If it contains a port (hostname:port or IP:port)
    if ':' in target:
        parts = target.split(':')
        try:
            port = int(parts[-1])
            ports.append(port)
        except ValueError:
            pass

    # For localhost or 127.0.0.1, check common development ports
    if target.lower() in ['localhost', '127.0.0.1', '0.0.0.0']:
        ports.extend([3000, 5000, 8000, 9090])

    return ports


def check_target_health(target: Optional[str] = None,
                        demo_apps: bool = False,
                        verbose: bool = False) -> bool:
    """
    Check if target applications are healthy and deploy if needed.

    Args:
        target: Target URL/hostname to check
        demo_apps: If True, check all demo application ports
        verbose: Enable verbose output

    Returns:
        True if all targets are healthy, False otherwise
    """
    if not HEALTH_CHECK_AVAILABLE:
        if verbose:
            print("⚠️  Health check not available - skipping app validation")
        return True

    print("🏥 Checking target application health...")

    # Determine which ports to check
    ports_to_check = []

    if demo_apps:
        # Check all configured demo app ports
        ports_to_check = [3000, 5000, 8000, 9090]
        print("🎯 Checking all demo application ports...")
    elif target:
        # Extract ports from target
        ports_to_check = extract_ports_from_target(target)
        if ports_to_check:
            print(f"🎯 Checking target: {target} (ports: {ports_to_check})")
        else:
            print(f"🎯 No specific ports identified for target: {target}")
            return True
    else:
        print("🎯 No specific target provided - skipping health check")
        return True

    if not ports_to_check:
        if verbose:
            print("📝 No ports to check - continuing...")
        return True

    # Run health check
    try:
        results = run_health_check(ports_to_check)

        # Check results
        failed_ports = [port for port,
                        healthy in results.items() if not healthy]

        if failed_ports:
            print(f"❌ Health check failed for ports: {failed_ports}")
            print("💡 Some target applications may not be accessible")
            return False
        else:
            print("✅ All target applications are healthy!")
            return True

    except Exception as e:
        if verbose:
            print(f"⚠️  Health check error: {e}")
        print("⚠️  Could not verify application health - continuing anyway...")
        return True


def ensure_apps_running(target: Optional[str] = None,
                        demo_apps: bool = False,
                        force_check: bool = True,
                        verbose: bool = False) -> bool:
    """
    Ensure target applications are running before security testing.

    Args:
        target: Target URL/hostname
        demo_apps: If True, ensure all demo apps are running
        force_check: If True, always run health check
        verbose: Enable verbose output

    Returns:
        True if apps are running or check was skipped, False if failed
    """
    if not force_check:
        return True

    print("🚀 Ensuring target applications are ready for security testing...")

    success = check_target_health(target, demo_apps, verbose)

    if success:
        print("🎉 Target applications are ready for testing!")
    else:
        print("⚠️  Some applications may not be available")
        print("💡 Security tests may fail if applications are not running")

    print()  # Add spacing before main analysis
    return success


def get_health_check_args(parser: 'argparse.ArgumentParser') -> None:
    """
    Add health check arguments to an argument parser.

    Args:
        parser: ArgumentParser to add arguments to
    """
    health_group = parser.add_argument_group('Health Check Options')
    health_group.add_argument(
        '--skip-health-check',
        action='store_true',
        help='Skip application health check before testing'
    )
    health_group.add_argument(
        '--health-check-verbose',
        action='store_true',
        help='Enable verbose health check output'
    )
