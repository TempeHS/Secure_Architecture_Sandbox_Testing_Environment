#!/usr/bin/env python3
"""
Secure Architecture Sandbox Testing Environment Validation Tests

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
    """Test suite to validate secure architecture sandbox environment setup."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.project_root = Path(__file__).parent.parent
        os.chdir(cls.project_root)
        cls.docker_client = docker.from_env()
        # All service ports: PWA on 5000, Vulnerable Flask on 9090,
        # Student Uploads on 8000, Node.js on 3000
        cls.expected_ports = [5000, 9090, 8000, 3000]
        cls.expected_containers = [
            "cybersec_sandbox",
            "unsecure_pwa",
            "vulnerable_flask",
            "student_uploads",
            "vulnerable_nodejs"
        ]
        cls.timeout = 30  # seconds

    def test_01_docker_containers_running(self):
        """Test that required Docker containers are running."""
        logger.info("Testing Docker container status...")

        # Essential service containers (must be running)
        essential_containers = [
            "unsecure_pwa",
            "vulnerable_flask",
            "student_uploads",
            "vulnerable_nodejs"
        ]

        # Optional containers (sandbox may have build issues)
        optional_containers = [
            "cybersec_sandbox"
        ]

        # Test essential containers
        for container_name in essential_containers:
            try:
                container = self.docker_client.containers.get(container_name)
                self.assertEqual(
                    container.status, "running",
                    f"{container_name} container is not running"
                )
                logger.info(f"✅ {container_name} container is running")

            except docker.errors.NotFound:
                self.fail(
                    f"{container_name} container not found. "
                    f"Run 'docker-compose up -d' first."
                )
            except Exception as e:
                self.fail(f"Docker container check failed for "
                          f"{container_name}: {e}")

        # Test optional containers
        for container_name in optional_containers:
            try:
                container = self.docker_client.containers.get(container_name)
                if container.status == "running":
                    logger.info(f"✅ {container_name} container is running")
                else:
                    logger.warning(f"⚠️ {container_name} container found but "
                                   f"not running (status: {container.status})")

            except docker.errors.NotFound:
                logger.warning(f"⚠️ {container_name} container not found "
                               f"(this is optional for core functionality)")
            except Exception as e:
                logger.warning(f"⚠️ Docker container check failed for "
                               f"{container_name}: {e}")

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
                cmd, cwd=self.project_root, capture_output=True,
                text=True, timeout=10
            )

            self.assertEqual(
                result.returncode, 0,
                f"docker-compose ps failed: {result.stderr}"
            )

            running_services = result.stdout.strip().split("\n")

            # Essential services that must be running
            essential_services = [
                "unsecure-pwa", "vulnerable-flask",
                "student-uploads", "vulnerable-nodejs"
            ]

            # Optional services
            optional_services = ["sandbox"]

            # Check essential services
            for service in essential_services:
                self.assertIn(
                    service, running_services,
                    f"{service} service not running"
                )

            # Check optional services
            for service in optional_services:
                if service in running_services:
                    logger.info(f"✅ Optional service {service} is running")
                else:
                    logger.warning(f"⚠️ Optional service {service} "
                                   f"not running")

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

    def test_05_student_uploads_application_availability(self):
        """Test that Student Uploads Flask application is accessible."""
        logger.info("Testing Student Uploads application availability...")

        # Check if port 8000 is open
        self._wait_for_port("localhost", 8000)

        try:
            response = requests.get("http://localhost:8000", timeout=10)
            self.assertEqual(
                response.status_code,
                200,
                f"Student Uploads app returned status {response.status_code}",
            )

            # Check for expected content (should be the uploaded Flask app)
            self.assertTrue(
                len(response.text) > 0,
                "Student Uploads app returned empty response"
            )

            logger.info("✅ Student Uploads Flask application is accessible")

        except requests.exceptions.RequestException as e:
            self.fail(f"Failed to connect to Student Uploads app: {e}")

    def test_06_vulnerable_nodejs_application_availability(self):
        """Test that Vulnerable Node.js application is accessible."""
        logger.info("Testing Vulnerable Node.js application availability...")

        # Check if port 3000 is open
        self._wait_for_port("localhost", 3000)

        try:
            response = requests.get("http://localhost:3000", timeout=10)
            self.assertEqual(
                response.status_code,
                200,
                f"Node.js app returned status {response.status_code}",
            )

            # Check for expected content
            self.assertTrue(
                len(response.text) > 0,
                "Node.js app returned empty response"
            )

            logger.info("✅ Vulnerable Node.js application is accessible")

        except requests.exceptions.RequestException as e:
            self.fail(f"Failed to connect to Node.js app: {e}")

    def test_07_all_service_ports_available(self):
        """Test that all expected service ports are available."""
        logger.info("Testing all service port availability...")

        port_mapping = {
            5000: "PWA Flask Application",
            9090: "Vulnerable Flask Application",
            8000: "Student Uploads Flask Application",
            3000: "Vulnerable Node.js Application"
        }

        for port, service_name in port_mapping.items():
            try:
                self._wait_for_port("localhost", port)
                logger.info(f"✅ Port {port} ({service_name}) is available")
            except Exception as e:
                self.fail(f"Port {port} ({service_name}) not available: {e}")

        logger.info(f"✅ All {len(port_mapping)} service ports are available")

    def test_08_sample_applications_exist(self):
        """Test that all sample applications exist in the file system."""
        logger.info("Testing sample application file existence...")

        required_samples = [
            "samples/vulnerable-flask-app/app.py",
            "samples/unsecure-pwa/main.py",
            "samples/vulnerable-nodejs-app/app.js",
            "samples/backdoor-apps/backdoor_app.py",
            "samples/suspicious-scripts/suspicious_script.py",
            "samples/resource-abuse/crypto_miner.py",
        ]

        for sample_path in required_samples:
            full_path = self.project_root / sample_path
            self.assertTrue(
                full_path.exists(),
                f"Sample application not found: {sample_path}"
            )

            # Check if it's a valid file with content
            with open(full_path, "r") as f:
                content = f.read()
                self.assertGreater(
                    len(content),
                    10,
                    f"Sample file {sample_path} appears to be empty",
                )

        logger.info(f"✅ All {len(required_samples)} sample applications exist")

    def test_09_analyzer_tools_exist(self):
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

    def test_10_network_scenarios_exist(self):
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

    def test_11_reports_directory_writable(self):
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
