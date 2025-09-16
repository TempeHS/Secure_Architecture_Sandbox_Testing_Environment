#!/usr/bin/env python3
"""
Docker Sandbox Environment Validation Tests

This test suite validates that the Docker sandbox environment is properly
configured and all sample applications are accessible for security testing.
"""

import unittest
import subprocess
import time
import socket
import requests
import docker
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DockerSandboxValidationTest(unittest.TestCase):
    """Test suite to validate Docker sandbox environment setup."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.project_root = Path(__file__).parent.parent
        os.chdir(cls.project_root)
        cls.docker_client = docker.from_env()
        # Flask on 9090, PWA on 5000
        cls.expected_ports = [9090, 5000]
        cls.timeout = 30  # seconds

    def test_01_docker_containers_running(self):
        """Test that required Docker containers are running."""
        logger.info("Testing Docker container status...")

        try:
            # Check if cybersec_sandbox container is running
            container = self.docker_client.containers.get("cybersec_sandbox")
            self.assertEqual(
                container.status, "running", "cybersec_sandbox container is not running"
            )
            logger.info("✅ cybersec_sandbox container is running")

        except docker.errors.NotFound:
            self.fail(
                "cybersec_sandbox container not found. "
                "Run 'docker-compose up -d' first."
            )
        except Exception as e:
            self.fail(f"Docker container check failed: {e}")

    def test_02_docker_compose_services(self):
        """Test that docker-compose services are properly configured."""
        logger.info("Testing docker-compose services...")

        try:
            # Run docker-compose ps to check service status
            cmd = [
                "docker-compose",
                "-f",
                "docker/docker-compose.yml",
                "ps",
                "--services",
                "--filter",
                "status=running",
            ]
            result = subprocess.run(
                cmd, cwd=self.project_root, capture_output=True, text=True, timeout=10
            )

            self.assertEqual(
                result.returncode, 0, f"docker-compose ps failed: {result.stderr}"
            )

            running_services = result.stdout.strip().split("\n")
            expected_services = ["sandbox", "pwa-flask"]
            for service in expected_services:
                self.assertIn(
                    service, running_services, f"{service} service not running"
                )

            logger.info(f"✅ Running services: {running_services}")

        except subprocess.TimeoutExpired:
            self.fail("docker-compose ps command timed out")
        except FileNotFoundError:
            self.fail("docker-compose command not found")

    def test_03_flask_application_availability(self):
        """Test that Flask vulnerable application is accessible."""
        logger.info("Testing Flask application availability...")

        # First check if port 5000 is open
        # Vulnerable Flask app now runs on port 9090
        self._wait_for_port("localhost", 9090)

        try:
            response = requests.get("http://localhost:9090", timeout=10)
            self.assertEqual(
                response.status_code,
                200,
                f"Flask app returned status {response.status_code}",
            )

            # Check for expected content
            self.assertIn(
                "Vulnerable",
                response.text,
                "Flask app doesn't contain expected 'Vulnerable' content",
            )

            logger.info("✅ Flask vulnerable application is accessible")

        except requests.exceptions.RequestException as e:
            self.fail(f"Failed to connect to Flask app: {e}")

    def test_04_pwa_application_availability(self):
        """Test that PWA unsecure application is accessible."""
        logger.info("Testing PWA application availability...")

        # First check if port 9090 is open
        # PWA Flask app now runs on port 5000
        self._wait_for_port("localhost", 5000)

        try:
            response = requests.get("http://localhost:5000", timeout=10)
            self.assertEqual(
                response.status_code,
                200,
                f"PWA app returned status {response.status_code}",
            )

            # Check for expected PWA content
            content_lower = response.text.lower()
            # Check PWA-specific keywords
            has_pwa = any(
                kw in content_lower for kw in [
                    "manifest", "progressive", "pwa"
                ]
            )
            self.assertTrue(
                has_pwa,
                "PWA content not found"
            )
            # Verify manifest link is present
            self.assertIn(
                'link rel="manifest"',
                content_lower,
                "PWA missing manifest link"
            )

            logger.info("✅ PWA unsecure application is accessible")

        except requests.exceptions.RequestException as e:
            self.fail(f"Failed to connect to PWA app: {e}")

    def test_05_sample_applications_exist(self):
        """Test that all sample applications exist in the file system."""
        logger.info("Testing sample application file existence...")

        required_samples = [
            "samples/vulnerable-flask-app/app.py",
            "samples/unsecure-pwa/main.py",
            "samples/backdoor-apps/backdoor_app.py",
            "samples/suspicious-scripts/suspicious_script.py",
            "samples/resource-abuse/crypto_miner.py",
        ]

        for sample_path in required_samples:
            full_path = self.project_root / sample_path
            self.assertTrue(
                full_path.exists(
                ), f"Sample application not found: {sample_path}"
            )

            # Check if it's a valid Python file
            if sample_path.endswith(".py"):
                with open(full_path, "r") as f:
                    content = f.read()
                    self.assertGreater(
                        len(content),
                        10,
                        f"Sample file {sample_path} appears to be empty",
                    )

        logger.info(f"✅ All {len(required_samples)} sample applications exist")

    def test_06_analyzer_tools_exist(self):
        """Test that all analyzer CLI tools exist and are executable."""
        logger.info("Testing analyzer tool existence...")

        required_tools = [
            "src/analyzer/analyze_cli.py",
            "src/analyzer/dast_cli.py",
            "src/analyzer/network_cli.py",
        ]

        for tool_path in required_tools:
            full_path = self.project_root / tool_path
            self.assertTrue(full_path.exists(),
                            f"Analyzer tool not found: {tool_path}")

            # Test if the tool can show help
            try:
                result = subprocess.run(
                    ["python", str(full_path), "--help"],
                    cwd=self.project_root,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    f"Tool {tool_path} --help failed: {result.stderr}",
                )

            except subprocess.TimeoutExpired:
                self.fail(f"Tool {tool_path} --help timed out")

        logger.info(f"✅ All {len(required_tools)} analyzer tools available")

    def test_07_network_scenarios_exist(self):
        """Test that network scenario generators exist."""
        logger.info("Testing network scenario availability...")

        network_scenarios = [
            "samples/network-scenarios/basic_network_activity.py",
            "samples/network-scenarios/suspicious_traffic_generator.py",
            "samples/network-scenarios/backdoor_simulation.py",
            "samples/network-scenarios/dns_threat_scenarios.py",
        ]

        for scenario_path in network_scenarios:
            full_path = self.project_root / scenario_path
            self.assertTrue(
                full_path.exists(
                ), f"Network scenario not found: {scenario_path}"
            )

            # Test if scenario can be imported (syntax check)
            try:
                result = subprocess.run(
                    ["python", "-m", "py_compile", str(full_path)],
                    cwd=self.project_root,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    f"Network scenario {scenario_path} has syntax errors",
                )

            except subprocess.TimeoutExpired:
                self.fail(f"Syntax check for {scenario_path} timed out")

        logger.info(f"✅ All {len(network_scenarios)} network scenarios exist")

    def test_08_reports_directory_writable(self):
        """Test that reports directory exists and is writable."""
        logger.info("Testing reports directory...")

        reports_dir = self.project_root / "reports"

        # Create reports directory if it doesn't exist
        reports_dir.mkdir(exist_ok=True)

        # Test write permissions
        test_file = reports_dir / "test_write_permissions.txt"
        try:
            with open(test_file, "w") as f:
                f.write("test")

            self.assertTrue(test_file.exists(), "Failed to write test file")

            # Clean up
            test_file.unlink()

            logger.info("✅ Reports directory is writable")

        except PermissionError:
            self.fail("Reports directory is not writable")
        except Exception as e:
            self.fail(f"Reports directory test failed: {e}")

    def _wait_for_port(self, host, port, timeout=30):
        """Wait for a port to become available."""
        logger.info(f"Waiting for {host}:{port} to become available...")

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                with socket.create_connection((host, port), timeout=1):
                    logger.info(f"✅ Port {port} is available")
                    return True
            except (socket.timeout, ConnectionRefusedError, OSError):
                time.sleep(1)
                continue

        self.fail(f"Port {port} not available after {timeout} seconds")


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
