#!/usr/bin/env python3
"""
On-Demand App Unit Test

General purpose test to check if applications are running on specified ports.
If apps are down, attempts to deploy Docker containers and retry.
Designed to be called by other scripts to fix ongoing Docker issues.
"""

import unittest
import requests
import time
import subprocess
import sys
import os
from typing import Dict, List, Tuple, Optional


class OnDemandAppTest(unittest.TestCase):
    """Test class for checking and deploying on-demand applications."""

    # Configuration for each port
    APP_CONFIG = {
        3000: {
            'name': 'Vulnerable Node.js App',
            'expected_head_content': ['vulnerable node.js demo'],
            'docker_service': 'vulnerable-nodejs',
            'max_retries': 3,
            'wait_time': 15
        },
        5000: {
            'name': 'Unsecure PWA',
            'expected_head_content': ['the unsecure pwa'],
            'docker_service': 'unsecure-pwa',
            'max_retries': 3,
            'wait_time': 15
        },
        9090: {
            'name': 'Vulnerable Flask App',
            'expected_head_content': ['vulnerable flask demo'],
            'docker_service': 'vulnerable-flask',
            'max_retries': 3,
            'wait_time': 15
        },
        8000: {
            'name': 'Student Upload App',
            'expected_head_content': None,  # Only check for 200 status
            'docker_service': 'student-uploads',
            'max_retries': 3,
            'wait_time': 15
        }
    }

    def setUp(self):
        """Set up test environment."""
        self.base_url = 'http://localhost'
        self.timeout = 10
        compose_file = ('/workspaces/Secure_Architecture_Sandbox_Testing_'
                        'Environment/docker/docker-compose.yml')
        self.docker_compose_file = compose_file

    def check_app_health(self, port: int) -> Tuple[bool, str]:
        """
        Check if an application is healthy on the specified port.

        Args:
            port: Port number to check

        Returns:
            Tuple of (is_healthy, message)
        """
        try:
            url = f"{self.base_url}:{port}"
            response = requests.get(url, timeout=self.timeout)

            # For port 8000, only check status code
            if port == 8000:
                if response.status_code == 200:
                    return True, f"Port {port} responding with 200 OK"
                else:
                    msg = f"Port {port} returned status {response.status_code}"
                    return False, msg

            # For other ports, check status code and head content
            if response.status_code != 200:
                msg = f"Port {port} returned status {response.status_code}"
                return False, msg

            # Check if expected content is in the head section
            config = self.APP_CONFIG.get(port, {})
            expected_content = config.get('expected_head_content', [])

            if expected_content:
                html_content = response.text.lower()
                head_section = self._extract_head_section(html_content)

                for expected in expected_content:
                    if expected.lower() in head_section:
                        msg = f"Port {port} - Correct app detected"
                        return True, msg

                return False, f"Port {port} - Wrong app or content not found"

            return True, f"Port {port} responding correctly"

        except requests.exceptions.ConnectionError:
            return False, f"Port {port} - Connection refused"
        except requests.exceptions.Timeout:
            return False, f"Port {port} - Request timeout"
        except Exception as e:
            return False, f"Port {port} - Error: {str(e)}"

    def _extract_head_section(self, html: str) -> str:
        """Extract the head section from HTML content."""
        start = html.find('<head')
        if start == -1:
            return html[:1000]  # Fallback to first 1000 chars

        end = html.find('</head>', start)
        if end == -1:
            return html[start:start+1000]

        return html[start:end + 7]

    def deploy_docker_service(self, service_name: str) -> bool:
        """
        Deploy a specific Docker service.

        Args:
            service_name: Name of the Docker service to deploy

        Returns:
            True if deployment was successful, False otherwise
        """
        try:
            print(f"🚀 Deploying Docker service: {service_name}")

            # Check if docker-compose file exists
            if not os.path.exists(self.docker_compose_file):
                print("❌ Docker compose file not found")
                return False

            # Stop any existing instance first
            stop_cmd = [
                'docker-compose', '-f', self.docker_compose_file,
                'stop', service_name
            ]
            subprocess.run(stop_cmd, capture_output=True, text=True)

            # Remove any existing container
            rm_cmd = [
                'docker-compose', '-f', self.docker_compose_file,
                'rm', '-f', service_name
            ]
            subprocess.run(rm_cmd, capture_output=True, text=True)

            # Start the service
            start_cmd = [
                'docker-compose', '-f', self.docker_compose_file,
                'up', '-d', service_name
            ]

            result = subprocess.run(start_cmd, capture_output=True, text=True)

            if result.returncode == 0:
                # Verify container is actually running
                check_cmd = [
                    'docker-compose', '-f', self.docker_compose_file,
                    'ps', '-q', service_name
                ]
                check_result = subprocess.run(
                    check_cmd, capture_output=True, text=True)

                if check_result.stdout.strip():
                    print(f"✅ Successfully deployed {service_name}")
                    return True
                else:
                    msg = f"❌ Container {service_name} not running"
                    print(msg)
                    return False
            else:
                error_msg = (result.stderr.strip() if result.stderr
                             else "Unknown error")
                print(f"❌ Failed to deploy {service_name}: {error_msg}")
                return False

        except Exception as e:
            print(f"❌ Exception while deploying {service_name}: {str(e)}")
            return False

    def check_app_on_port(self, port: int) -> bool:
        """
        Test application on a specific port with retry logic.

        Args:
            port: Port number to test

        Returns:
            True if app is healthy, False otherwise
        """
        config = self.APP_CONFIG.get(port, {})
        app_name = config.get('name', f'App on port {port}')
        service_name = config.get('docker_service', f'service-{port}')
        max_retries = config.get('max_retries', 3)
        wait_time = config.get('wait_time', 15)

        print(f"\n🔍 Testing {app_name} on port {port}")

        for attempt in range(max_retries):
            is_healthy, message = self.check_app_health(port)

            if is_healthy:
                print(f"✅ {message}")
                return True

            print(f"❌ Attempt {attempt + 1}/{max_retries}: {message}")

            if attempt < max_retries - 1:  # Don't deploy on the last attempt
                deploy_msg = f"🔄 Deploying {service_name}"
                print(f"{deploy_msg} and waiting {wait_time} seconds...")

                deployment_success = self.deploy_docker_service(service_name)
                if deployment_success:
                    wait_msg = f"⏳ Waiting {wait_time} seconds for service"
                    print(f"{wait_msg}...")
                    time.sleep(wait_time)

                    # Verify deployment actually worked
                    print(f"🔍 Verifying {service_name} deployment...")
                    is_healthy_after, verify_msg = self.check_app_health(port)
                    if is_healthy_after:
                        print(f"✅ Deployment verified: {verify_msg}")
                        return True
                    else:
                        print(f"❌ Deployment failed: {verify_msg}")
                else:
                    print(f"❌ Failed to deploy {service_name}")

        terminal_msg = (f"❌ TERMINAL MESSAGE: {app_name} on port {port} "
                        f"failed after {max_retries} attempts")
        print(terminal_msg)
        service_msg = (f"   Service '{service_name}' could not be started "
                       f"or is not responding correctly")
        print(service_msg)
        return False

    def test_port_3000(self):
        """Test application on port 3000."""
        result = self.check_app_on_port(3000)
        self.assertTrue(result, "App on port 3000 failed")

    def test_port_5000(self):
        """Test application on port 5000."""
        result = self.check_app_on_port(5000)
        self.assertTrue(result, "App on port 5000 failed")

    def test_port_9090(self):
        """Test application on port 9090."""
        result = self.check_app_on_port(9090)
        self.assertTrue(result, "App on port 9090 failed")

    def test_port_8000(self):
        """Test application on port 8000 (only checks for 200 status)."""
        result = self.check_app_on_port(8000)
        self.assertTrue(result, "App on port 8000 failed")

    def test_all_apps(self):
        """Test all configured applications."""
        failed_ports = []

        for port in self.APP_CONFIG.keys():
            if not self.check_app_on_port(port):
                failed_ports.append(port)

        if failed_ports:
            self.fail(f"The following ports failed: {failed_ports}")


def run_health_check(ports: Optional[List[int]] = None) -> Dict[int, bool]:
    """
    Standalone function to run health checks on specified ports.
    Can be called by other scripts.

    Args:
        ports: List of ports to check. If None, checks all configured ports.

    Returns:
        Dictionary mapping port numbers to health status
    """
    test_instance = OnDemandAppTest()
    test_instance.setUp()

    if ports is None:
        ports = list(OnDemandAppTest.APP_CONFIG.keys())

    results = {}

    for port in ports:
        if port in OnDemandAppTest.APP_CONFIG:
            results[port] = test_instance.check_app_on_port(port)
        else:
            print(f"⚠️  Port {port} not configured in APP_CONFIG")
            results[port] = False

    return results


def main():
    """Main function for command-line usage."""
    import argparse

    description = 'On-demand app health checker and deployer'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--ports', nargs='+', type=int,
                        help='Specific ports to check (default: all ports)')
    parser.add_argument('--test', action='store_true',
                        help='Run as unittest suite')

    args = parser.parse_args()

    if args.test:
        # Run as unittest
        unittest.main(argv=[''], exit=False, verbosity=2)
    else:
        # Run health check
        results = run_health_check(args.ports)

        print("\n📊 SUMMARY:")
        all_healthy = True
        for port, is_healthy in results.items():
            status = "✅ HEALTHY" if is_healthy else "❌ FAILED"
            print(f"  Port {port}: {status}")
            if not is_healthy:
                all_healthy = False

        if all_healthy:
            print("\n🎉 All applications are healthy!")
            sys.exit(0)
        else:
            print("\n💥 Some applications failed health checks!")
            sys.exit(1)


if __name__ == '__main__':
    main()
