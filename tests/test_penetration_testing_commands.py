#!/usr/bin/env python3
"""
Penetration Testing Workflow Command Validation Tests

This test suite validates penetration testing workflow commands from the quick
reference guide to ensure integrated testing methodologies work correctly.
"""

import unittest
import subprocess
import requests
import json
import time
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PenetrationTestingValidationTest(unittest.TestCase):
    """Test suite to validate penetration testing workflow commands."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.project_root = Path(__file__).parent.parent
        os.chdir(cls.project_root)
        cls.timeout = 120  # seconds - Pentest workflows take longer
        cls.reports_dir = cls.project_root / "reports"
        cls.reports_dir.mkdir(exist_ok=True)
        cls.pwa_url = "http://localhost:5000"
        cls.flask_url = "http://localhost:9090"

        # Wait for applications to be available
        cls._wait_for_applications()

    @classmethod
    def _wait_for_applications(cls):
        """Wait for test applications to be available."""
        logger.info("Waiting for test applications to be available...")

        for url in [cls.flask_url, cls.pwa_url]:
            start_time = time.time()
            while time.time() - start_time < 60:  # 1 minute timeout
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        logger.info(f"✅ {url} is available")
                        break
                except requests.exceptions.RequestException:
                    time.sleep(2)
                    continue
            else:
                logger.warning(f"⚠️ {url} may not be available")

    def test_01_pentest_methodology_phase1_reconnaissance(self):
        """Test Phase 1: Reconnaissance - Network and DAST scans."""
        logger.info("Testing penetration testing Phase 1: Reconnaissance...")

        # Network reconnaissance
        try:
            result_network = subprocess.run(
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--scan-services",
                    "localhost",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            self.assertEqual(
                result_network.returncode,
                0,
                f"Network reconnaissance failed: " f"{result_network.stderr}",
            )

            # DAST quick scan
            result_dast = subprocess.run(
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    self.pwa_url,
                    "--quick",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            self.assertEqual(
                result_dast.returncode,
                0,
                f"DAST reconnaissance failed: " f"{result_dast.stderr}",
            )

            logger.info("✅ Phase 1: Reconnaissance completed successfully")

        except subprocess.TimeoutExpired:
            self.fail("Phase 1 reconnaissance timed out")

    def test_02_pentest_methodology_phase2_vulnerability_assessment(self):
        """Test Phase 2: Vulnerability Assessment - SAST and deep DAST."""
        logger.info(
            "Testing penetration testing Phase 2: Vulnerability Assessment..."
        )

        try:
            # Static analysis
            result_sast = subprocess.run(
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/unsecure-pwa",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            self.assertEqual(
                result_sast.returncode,
                0,
                f"SAST vulnerability assessment failed: {result_sast.stderr}",
            )

            # Deep DAST scan
            result_deep_dast = subprocess.run(
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    self.pwa_url,
                    "--deep-scan",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,  # Deep scan takes longer
            )
            self.assertEqual(
                result_deep_dast.returncode,
                0,
                f"Deep DAST assessment failed: " f"{result_deep_dast.stderr}",
            )

            logger.info("✅ Phase 2: Vulnerability Assessment completed")

        except subprocess.TimeoutExpired:
            self.fail("Phase 2 vulnerability assessment timed out")

    def test_03_pentest_methodology_phase3_controlled_exploitation(self):
        """Test Phase 3: Controlled Exploitation - Manual testing."""
        logger.info(
            "Testing penetration testing Phase 3: Controlled Exploitation..."
        )

        # Test SQL injection attempts (should be safe in educational context)
        try:
            # Basic authentication bypass attempt
            response = requests.post(
                f"{self.pwa_url}/login",
                data={"username": "admin' OR '1'='1", "password": "test"},
                timeout=10,
                allow_redirects=False,
            )
            # We're just testing that the request completes,
            # not that it succeeds
            self.assertIsNotNone(
                response.status_code, "SQL injection test request failed"
            )

            # XSS testing attempt
            response = requests.get(
                f"{self.pwa_url}/search",
                params={"q": "<script>alert('XSS')</script>"},
                timeout=10,
            )
            self.assertIsNotNone(
                response.status_code, "XSS test request failed"
            )

            logger.info("✅ Phase 3: Controlled Exploitation completed")

        except requests.exceptions.RequestException as e:
            logger.warning(f"⚠️ Manual exploitation tests failed: {e}")
            # This is acceptable since the apps might not have these
            # vulnerabilities

    def test_04_pentest_methodology_phase4_post_exploitation(self):
        """Test Phase 4: Post-Exploitation Analysis - Network monitoring."""
        logger.info(
            "Testing penetration testing Phase 4: " "Post-Exploitation...")

        try:
            # Network monitoring for suspicious activity
            result = subprocess.run(
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--monitor-connections",
                    "--duration",
                    "30",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            self.assertEqual(
                result.returncode,
                0,
                f"Post-exploitation monitoring failed: " f"{result.stderr}",
            )

            logger.info("✅ Phase 4: Post-Exploitation Analysis completed")

        except subprocess.TimeoutExpired:
            self.fail("Phase 4 post-exploitation analysis timed out")

    def test_05_integrated_full_security_assessment(self):
        """Test integrated full security assessment across all modules."""
        logger.info("Testing integrated full security assessment...")

        output_files = [
            self.reports_dir / "pentest_sast.json",
            self.reports_dir / "pentest_dast.json",
            self.reports_dir / "pentest_network.json",
        ]

        try:
            # SAST assessment
            result_sast = subprocess.run(
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/",
                    "--educational",
                    "--output",
                    str(output_files[0]),
                    "--format",
                    "json",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # DAST assessment
            result_dast = subprocess.run(
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    "--demo-apps",
                    "--educational",
                    "--output",
                    str(output_files[1]),
                    "--format",
                    "json",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,
            )

            # Network assessment
            result_network = subprocess.run(
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--demo-network",
                    "--educational",
                    "--output",
                    str(output_files[2]),
                    "--format",
                    "json",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Check that at least one assessment succeeded
            success_count = 0
            if result_sast.returncode == 0:
                success_count += 1
            if result_dast.returncode == 0:
                success_count += 1
            if result_network.returncode == 0:
                success_count += 1

            self.assertGreater(
                success_count, 0, "No integrated assessments succeeded")

            # Validate any created JSON files
            for output_file in output_files:
                if output_file.exists():
                    with open(output_file, "r") as f:
                        try:
                            json.load(f)
                            logger.info(f"✅ Valid JSON report: {output_file}")
                        except json.JSONDecodeError:
                            logger.warning(f"⚠️ Invalid JSON: {output_file}")

            logger.info("✅ Integrated full security assessment completed")

        except subprocess.TimeoutExpired:
            self.fail("Integrated security assessment timed out")
        finally:
            # Clean up output files
            for output_file in output_files:
                if output_file.exists():
                    output_file.unlink()

    def test_06_network_discovery_workflow(self):
        """Test comprehensive network discovery workflow."""
        logger.info("Testing network discovery workflow...")

        try:
            # Service discovery
            result1 = subprocess.run(
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--scan-services",
                    "localhost",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Connection monitoring
            result2 = subprocess.run(
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--monitor-connections",
                    "--educational",
                    "--duration",
                    "30",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # DNS analysis
            result3 = subprocess.run(
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--dns-analysis",
                    "--educational",
                    "--duration",
                    "30",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # At least one network discovery method should work
            success_count = sum(
                [
                    result1.returncode == 0,
                    result2.returncode == 0,
                    result3.returncode == 0,
                ]
            )
            self.assertGreater(
                success_count, 0, "No network discovery methods succeeded"
            )

            logger.info("✅ Network discovery workflow completed")

        except subprocess.TimeoutExpired:
            self.fail("Network discovery workflow timed out")

    def test_07_web_application_enumeration(self):
        """Test web application enumeration techniques."""
        logger.info("Testing web application enumeration...")

        try:
            # Basic enumeration
            result1 = subprocess.run(
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    self.pwa_url,
                    "--quick",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Deep enumeration - check result but don't enforce success
            subprocess.run(
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    self.pwa_url,
                    "--deep-scan",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,
            )

            # At least basic enumeration should work
            self.assertEqual(
                result1.returncode,
                0,
                f"Basic web enumeration failed: " f"{result1.stderr}",
            )

            # Manual enumeration with curl (test common endpoints)
            manual_tests = [
                f"{self.pwa_url}/",
                f"{self.pwa_url}/robots.txt",
                f"{self.pwa_url}/admin",
            ]

            for url in manual_tests:
                try:
                    response = requests.get(url, timeout=10)
                    logger.info(f"Manual test {url}: {response.status_code}")
                except requests.exceptions.RequestException:
                    logger.info(f"Manual test {url}: Connection failed")

            logger.info("✅ Web application enumeration completed")

        except subprocess.TimeoutExpired:
            self.fail("Web application enumeration timed out")

    def test_08_technology_stack_analysis(self):
        """Test technology stack analysis workflow."""
        logger.info("Testing technology stack analysis...")

        try:
            # Static analysis for tech stack
            result1 = subprocess.run(
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/unsecure-pwa",
                    "--educational",
                    "--verbose",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            result2 = subprocess.run(
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/vulnerable-flask-app",
                    "--educational",
                    "--verbose",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # At least one analysis should succeed
            success_count = sum(
                [result1.returncode == 0, result2.returncode == 0])
            self.assertGreater(
                success_count, 0, "No technology stack analysis succeeded"
            )

            logger.info("✅ Technology stack analysis completed")

        except subprocess.TimeoutExpired:
            self.fail("Technology stack analysis timed out")

    def test_10_sql_injection_testing_methodology(self):
        """Test SQL injection testing methodology."""
        logger.info("Testing SQL injection methodology...")

        # Test various SQL injection payloads (safe educational testing)
        test_payloads = [
            "admin' OR '1'='1",
            "admin' OR 1=1--",
            "' UNION SELECT 1,2,3--",
        ]

        successful_tests = 0
        failed_payloads = []

        for payload in test_payloads:
            try:
                response = requests.post(
                    f"{self.pwa_url}/login",
                    data={"username": payload, "password": "test"},
                    timeout=10,
                    allow_redirects=False,
                )
                # We're testing that requests complete, not that they succeed
                if response.status_code is not None:
                    successful_tests += 1
                    logger.info(
                        f"SQL payload test completed: " f"{response.status_code}"
                    )
            except requests.exceptions.RequestException as e:
                failed_payloads.append((payload, str(e)))

        self.assertEqual(
            failed_payloads,
            [],
            f"Target did not respond to SQL injection payloads: "
            f"{failed_payloads}",
        )
        self.assertEqual(
            successful_tests,
            len(test_payloads),
            "Not every SQL injection payload received an HTTP response",
        )

        logger.info(
            f"✅ SQL injection methodology tested "
            f"({successful_tests}/{len(test_payloads)} payloads)"
        )

    def test_11_xss_testing_methodology(self):
        """Test Cross-Site Scripting (XSS) testing methodology."""
        logger.info("Testing XSS methodology...")

        # Test various XSS payloads (safe educational testing)
        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
        ]

        statuses = {}
        failed_payloads = []

        for payload in test_payloads:
            try:
                response = requests.get(
                    f"{self.pwa_url}/search", params={"q": payload}, timeout=10
                )
                statuses[payload] = response.status_code
                logger.info(
                    f"XSS payload test completed: " f"{response.status_code}")
            except requests.exceptions.RequestException as e:
                failed_payloads.append((payload, str(e)))

        self.assertEqual(
            failed_payloads,
            [],
            f"Target did not respond to XSS payloads: {failed_payloads}",
        )
        self.assertEqual(
            len(statuses),
            len(test_payloads),
            "Not every XSS payload received an HTTP response",
        )

        logger.info("✅ XSS testing methodology completed")

    def test_12_configuration_testing_methodology(self):
        """Test configuration vulnerability testing methodology."""
        logger.info("Testing configuration methodology...")

        # Test common configuration endpoints
        config_endpoints = ["/debug", "/config", "/admin", "/status", "/info"]

        statuses = {}
        unreachable = []

        for endpoint in config_endpoints:
            try:
                response = requests.get(
                    f"{self.pwa_url}{endpoint}", timeout=10)
                statuses[endpoint] = response.status_code
                logger.info(f"Config test {endpoint}: {response.status_code}")
            except requests.exceptions.RequestException as e:
                unreachable.append((endpoint, str(e)))

        self.assertEqual(
            unreachable,
            [],
            f"Target did not respond on configuration endpoints: "
            f"{unreachable}",
        )
        # Every probe must produce a real HTTP status (404 is a valid result;
        # a missing/garbled response is not).
        self.assertTrue(
            all(100 <= status < 600 for status in statuses.values()),
            f"Configuration probes returned invalid HTTP statuses: {statuses}",
        )

        logger.info("✅ Configuration testing methodology completed")

    def test_13_integrated_threat_simulation(self):
        """Test integrated threat simulation workflow."""
        logger.info("Testing integrated threat simulation...")

        try:
            # Background threat simulation with network monitoring
            # This simulates the workflow from the quick reference
            result = subprocess.run(
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--monitor-connections",
                    "--duration",
                    "30",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"Threat simulation monitoring failed: " f"{result.stderr}",
            )

            logger.info("✅ Integrated threat simulation completed")

        except subprocess.TimeoutExpired:
            self.fail("Threat simulation timed out")

    def test_14_professional_workflow_validation(self):
        """Test professional penetration testing workflow validation."""
        logger.info("Testing professional workflow validation...")

        # This test validates that the complete workflow can be executed
        # as described in the quick reference guide
        workflow_steps = [
            # Step 1: Reconnaissance
            (
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--scan-services",
                    "localhost",
                    "--educational",
                ],
                "Reconnaissance",
            ),
            # Step 2: SAST Analysis
            (
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/unsecure-pwa",
                    "--educational",
                ],
                "Static Analysis",
            ),
            # Step 3: DAST Analysis
            (
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    self.pwa_url,
                    "--quick",
                    "--educational",
                ],
                "Dynamic Analysis",
            ),
        ]

        successful_steps = 0

        for command, step_name in workflow_steps:
            try:
                result = subprocess.run(
                    command,
                    cwd=self.project_root,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
                if result.returncode == 0:
                    successful_steps += 1
                    logger.info(f"✅ {step_name}: Success")
                else:
                    logger.warning(f"⚠️ {step_name}: Failed")
            except subprocess.TimeoutExpired:
                logger.warning(f"⚠️ {step_name}: Timed out")

        # Require at least 2 out of 3 steps to succeed
        self.assertGreaterEqual(
            successful_steps,
            2,
            f"Professional workflow failed: only "
            f"{successful_steps}/3 steps succeeded",
        )

        logger.info("✅ Professional workflow validation completed")

    def test_15_automated_penetration_testing_tool(self):
        """Test the new automated penetration testing analyser tool."""
        logger.info("Testing automated penetration testing tool...")

        # Test if the penetration analyser tool exists and can be called
        analyser = self.project_root / "src/analyser/penetration_analyser.py"
        self.assertTrue(
            analyser.exists(),
            f"Documented penetration analyser tool is missing: {analyser}",
        )

        try:
            # Test help functionality
            result = subprocess.run(
                [
                    "python",
                    "src/analyser/penetration_analyser.py",
                    "--help"
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=30
            )

            self.assertEqual(
                result.returncode,
                0,
                f"Penetration analyser --help failed: {result.stderr}",
            )
            self.assertIn(
                "usage",
                result.stdout.lower(),
                "Penetration analyser --help did not print usage information",
            )
            logger.info(
                "✅ Automated penetration testing tool help available"
            )

        except subprocess.TimeoutExpired:
            self.fail("Penetration analyser tool help command timed out")

        # Test penetration testing against localhost applications
        for port in [5000, 9090]:
            try:
                result = subprocess.run(
                    [
                        "python",
                        "src/analyser/penetration_analyser.py",
                        f"localhost:{port}"
                    ],
                    cwd=self.project_root,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )

                self.assertEqual(
                    result.returncode,
                    0,
                    f"Penetration testing failed for port {port}: "
                    f"{result.stderr}",
                )
                output = (result.stdout + result.stderr).lower()
                self.assertTrue(
                    "penetration" in output or "vulnerability" in output,
                    f"Penetration testing output for port {port} is missing "
                    f"expected findings content",
                )
                logger.info(
                    f"✅ Automated penetration testing completed "
                    f"for port {port}"
                )

            except subprocess.TimeoutExpired:
                self.fail(f"Penetration testing timed out for port {port}")

        logger.info(
            "✅ Automated penetration testing tool validation completed"
        )

    def test_16_sast_advanced_options(self):
        """Test SAST commands with advanced options from documentation."""
        logger.info("Testing SAST advanced options...")

        advanced_commands = [
            # Dependency vulnerability scanning is safety's job
            (
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/unsecure-pwa",
                    "--tools",
                    "safety"
                ],
                "dependency check"
            ),
            # Test multiple specific tools
            (
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/unsecure-pwa",
                    "--tools",
                    "bandit",
                    "semgrep"
                ],
                "multiple tool selection"
            ),
            # Test verbose output
            (
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/unsecure-pwa",
                    "--educational",
                    "--verbose"
                ],
                "verbose output"
            ),
            # Test suspicious scripts analysis
            (
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/suspicious-scripts",
                    "--educational"
                ],
                "suspicious scripts analysis"
            ),
            # Test unsecure PWA analysis
            (
                [
                    "python",
                    "src/analyser/analyse_cli.py",
                    "samples/unsecure-pwa",
                    "--educational"
                ],
                "unsecure PWA analysis"
            )
        ]

        self._assert_all_commands_succeed(advanced_commands, "SAST")

        logger.info("✅ SAST advanced options testing completed")

    def _assert_all_commands_succeed(self, commands, label):
        """Run each documented command and require it to exit cleanly."""
        for command, description in commands:
            with self.subTest(command=description):
                try:
                    result = subprocess.run(
                        command,
                        cwd=self.project_root,
                        capture_output=True,
                        text=True,
                        timeout=self.timeout
                    )
                except subprocess.TimeoutExpired:
                    self.fail(
                        f"{label} {description} timed out after "
                        f"{self.timeout}s: {' '.join(command)}")

                self.assertEqual(
                    result.returncode,
                    0,
                    f"{label} {description} failed "
                    f"(exit {result.returncode}): {' '.join(command)}\n"
                    f"{result.stderr[-500:]}",
                )
                logger.info(f"✅ {label} {description} completed successfully")

    def test_17_dast_specific_vulnerability_testing(self):
        """Test DAST commands with specific vulnerability testing options."""
        logger.info("Testing DAST specific vulnerability testing...")

        specific_vuln_commands = [
            # Built-in checks cover XSS/SQLi probing
            (
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    self.pwa_url,
                    "--tools",
                    "basic_tests",
                    "--educational"
                ],
                "XSS and SQL injection testing"
            ),
            # Security headers are part of the basic scan
            (
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    self.pwa_url,
                    "--quick",
                    "--educational"
                ],
                "security headers analysis"
            ),
            # Test demo apps mode
            (
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    "--demo-apps",
                    "--educational"
                ],
                "demo apps testing"
            ),
            # Test the secondary application
            (
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    self.flask_url,
                    "--quick",
                    "--educational"
                ],
                "alternative port testing"
            )
        ]

        self._assert_all_commands_succeed(specific_vuln_commands, "DAST")

        logger.info("✅ DAST specific vulnerability testing completed")

    def test_17b_dast_reports_unreachable_target_as_error(self):
        """An unreachable target must never be reported as a clean scan."""
        logger.info("Testing DAST unreachable target handling...")

        dead_url = "http://localhost:8081"
        try:
            result = subprocess.run(
                [
                    "python",
                    "src/analyser/dast_cli.py",
                    dead_url,
                    "--quick"
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            self.fail("DAST scan of unreachable target timed out")

        self.assertEqual(
            result.returncode,
            2,
            "DAST must exit 2 when the target was never reached, so a dead "
            "app cannot be mistaken for a passing scan",
        )
        output = result.stdout.lower()
        self.assertIn(
            "unreachable",
            output,
            "DAST must tell the student the target was unreachable",
        )
        self.assertNotIn(
            "no security issues found",
            output,
            "DAST must not report a clean bill of health for a target it "
            "never reached",
        )

        logger.info("✅ DAST reports unreachable targets as errors")

    def test_18_network_analysis_advanced_options(self):
        """Test network analysis commands with advanced options from documentation."""
        logger.info("Testing network analysis advanced options...")

        advanced_network_commands = [
            # Service scanning (network_cli scans its own default port set)
            (
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--scan-services",
                    "localhost"
                ],
                "service scanning"
            ),
            # Test extended connection monitoring
            (
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--monitor-connections",
                    "--educational",
                    "--duration",
                    "30"
                ],
                "extended connection monitoring"
            ),
            # Test traffic capture with extended duration
            (
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--capture-traffic",
                    "--duration",
                    "30",
                    "--educational"
                ],
                "extended traffic capture"
            ),
            # Test DNS analysis with shorter duration for testing
            (
                [
                    "python",
                    "src/analyser/network_cli.py",
                    "--dns-analysis",
                    "--educational",
                    "--duration",
                    "30"
                ],
                "DNS analysis"
            )
        ]

        self._assert_all_commands_succeed(
            advanced_network_commands, "Network")

        logger.info("✅ Network analysis advanced options testing completed")

    def test_20_manual_testing_curl_commands(self):
        """Test manual penetration testing curl commands from documentation."""
        logger.info("Testing manual penetration testing curl commands...")

        # These are safe educational tests in our controlled environment
        manual_test_commands = [
            # Basic connectivity tests
            (f"curl -I {self.pwa_url}", "PWA app connectivity"),
            (f"curl -I {self.flask_url}", "Flask app connectivity"),

            # Basic endpoint discovery
            (f"curl {self.pwa_url}/robots.txt", "robots.txt discovery"),
            (f"curl {self.pwa_url}/sitemap.xml", "sitemap.xml discovery"),

            # Header analysis
            (f"curl -I {self.pwa_url}", "header analysis"),
        ]

        successful_tests = 0

        for command, description in manual_test_commands:
            with self.subTest(command=description):
                try:
                    result = subprocess.run(
                        command.split(),
                        cwd=self.project_root,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                except subprocess.TimeoutExpired:
                    self.fail(f"Manual test '{description}' timed out")

                # curl exits non-zero only when it cannot reach the server;
                # a 404 response is still a successful request.
                self.assertEqual(
                    result.returncode,
                    0,
                    f"Manual test '{description}' could not reach the target "
                    f"(curl exit {result.returncode}): {command}",
                )
                successful_tests += 1
                logger.info(f"✅ Manual test '{description}' executed")

        self.assertEqual(
            successful_tests,
            len(manual_test_commands),
            "Not every documented manual curl command reached its target",
        )

        logger.info("✅ Manual testing curl commands validation completed")

    def test_21_sample_application_execution(self):
        """Test sample application commands mentioned in documentation."""
        logger.info("Testing sample application execution...")

        # Test sample applications that should be safe to run briefly
        sample_commands = [
            # Network scenario generators (run briefly for testing)
            (
                [
                    "python",
                    "samples/network-scenarios/basic_network_activity.py",
                    "5"  # Run for 5 seconds only
                ],
                "basic network activity generator"
            ),
        ]

        successful_samples = 0
        failures = []

        for command, description in sample_commands:
            script = self.project_root / command[1]
            self.assertTrue(
                script.exists(),
                f"Documented sample application is missing: {script}",
            )

            try:
                # Start the process
                process = subprocess.Popen(
                    command,
                    cwd=self.project_root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                # Let it run briefly then terminate
                time.sleep(2)
                process.terminate()

                # Wait for clean termination
                try:
                    process.wait(timeout=5)
                    logger.info(
                        f"✅ Sample application '{description}' executed successfully")
                    successful_samples += 1
                except subprocess.TimeoutExpired:
                    process.kill()
                    failures.append(
                        f"'{description}' ignored SIGTERM and had to be "
                        f"killed")

            except Exception as e:
                failures.append(f"'{description}' failed to start: {e}")

        self.assertEqual(
            failures, [],
            f"Documented sample applications did not run cleanly: {failures}",
        )
        self.assertEqual(
            successful_samples,
            len(sample_commands),
            "Not every documented sample application executed successfully",
        )

        logger.info(
            f"✅ Sample application execution testing completed "
            f"({successful_samples} successful)")


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
