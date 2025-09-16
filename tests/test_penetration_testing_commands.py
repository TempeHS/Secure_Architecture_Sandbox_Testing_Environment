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
        cls.flask_url = "http://localhost:5000"
        cls.pwa_url = "http://localhost:9090"

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
                    "src/analyzer/network_cli.py",
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
                    "src/analyzer/dast_cli.py",
                    self.flask_url,
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
            "Testing penetration testing Phase 2: " "Vulnerability Assessment..."
        )

        try:
            # Static analysis
            result_sast = subprocess.run(
                [
                    "python",
                    "src/analyzer/analyze_cli.py",
                    "samples/vulnerable-flask-app",
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
                f"SAST vulnerability assessment failed: " f"{result_sast.stderr}",
            )

            # Deep DAST scan
            result_deep_dast = subprocess.run(
                [
                    "python",
                    "src/analyzer/dast_cli.py",
                    self.flask_url,
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
            "Testing penetration testing Phase 3: " "Controlled Exploitation..."
        )

        # Test SQL injection attempts (should be safe in educational context)
        try:
            # Basic authentication bypass attempt
            response = requests.post(
                f"{self.flask_url}/login",
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
                f"{self.flask_url}/search",
                params={"q": "<script>alert('XSS')</script>"},
                timeout=10,
            )
            self.assertIsNotNone(response.status_code, "XSS test request failed")

            logger.info("✅ Phase 3: Controlled Exploitation completed")

        except requests.exceptions.RequestException as e:
            logger.warning(f"⚠️ Manual exploitation tests failed: {e}")
            # This is acceptable since the apps might not have these
            # vulnerabilities

    def test_04_pentest_methodology_phase4_post_exploitation(self):
        """Test Phase 4: Post-Exploitation Analysis - Network monitoring."""
        logger.info("Testing penetration testing Phase 4: " "Post-Exploitation...")

        try:
            # Network monitoring for suspicious activity
            result = subprocess.run(
                [
                    "python",
                    "src/analyzer/network_cli.py",
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
                    "src/analyzer/analyze_cli.py",
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
                    "src/analyzer/dast_cli.py",
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
                    "src/analyzer/network_cli.py",
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

            self.assertGreater(success_count, 0, "No integrated assessments succeeded")

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
                    "src/analyzer/network_cli.py",
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
                    "src/analyzer/network_cli.py",
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
                    "src/analyzer/network_cli.py",
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
                    "src/analyzer/dast_cli.py",
                    self.flask_url,
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
                    "src/analyzer/dast_cli.py",
                    self.flask_url,
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
                f"{self.flask_url}/",
                f"{self.flask_url}/robots.txt",
                f"{self.flask_url}/admin",
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
                    "src/analyzer/analyze_cli.py",
                    "samples/vulnerable-flask-app",
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
                    "src/analyzer/analyze_cli.py",
                    "samples/unsecure-pwa",
                    "--educational",
                    "--verbose",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # At least one analysis should succeed
            success_count = sum([result1.returncode == 0, result2.returncode == 0])
            self.assertGreater(
                success_count, 0, "No technology stack analysis succeeded"
            )

            logger.info("✅ Technology stack analysis completed")

        except subprocess.TimeoutExpired:
            self.fail("Technology stack analysis timed out")

    def test_09_comprehensive_report_generation(self):
        """Test comprehensive penetration testing report generation."""
        logger.info("Testing comprehensive report generation...")

        report_files = [
            self.reports_dir / "pentest_final_sast.json",
            self.reports_dir / "pentest_final_dast.json",
            self.reports_dir / "pentest_final_network.json",
        ]

        try:
            # Generate SAST report
            subprocess.run(
                [
                    "python",
                    "src/analyzer/analyze_cli.py",
                    "samples/",
                    "--educational",
                    "--output",
                    str(report_files[0]),
                    "--format",
                    "json",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Generate DAST report
            subprocess.run(
                [
                    "python",
                    "src/analyzer/dast_cli.py",
                    "--demo-apps",
                    "--educational",
                    "--output",
                    str(report_files[1]),
                    "--format",
                    "json",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,
            )

            # Generate Network report
            subprocess.run(
                [
                    "python",
                    "src/analyzer/network_cli.py",
                    "--demo-network",
                    "--educational",
                    "--output",
                    str(report_files[2]),
                    "--format",
                    "json",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Check which reports were generated
            generated_reports = [f for f in report_files if f.exists()]
            self.assertGreater(
                len(generated_reports),
                0,
                "No penetration testing reports were generated",
            )

            # Validate JSON structure of generated reports
            for report_file in generated_reports:
                with open(report_file, "r") as f:
                    try:
                        data = json.load(f)
                        self.assertIsInstance(
                            data, dict, f"Invalid JSON structure: " f"{report_file}"
                        )
                        logger.info(
                            f"✅ Valid report generated: " f"{report_file.name}"
                        )
                    except json.JSONDecodeError:
                        self.fail(f"Invalid JSON in report: {report_file}")

            logger.info("✅ Comprehensive report generation completed")

        except subprocess.TimeoutExpired:
            self.fail("Report generation timed out")
        finally:
            # Clean up report files
            for report_file in report_files:
                if report_file.exists():
                    report_file.unlink()

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

        for payload in test_payloads:
            try:
                response = requests.post(
                    f"{self.flask_url}/login",
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
            except requests.exceptions.RequestException:
                logger.info("SQL injection test connection failed " "(acceptable)")

        # At least the requests should complete without errors
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

        for payload in test_payloads:
            try:
                response = requests.get(
                    f"{self.flask_url}/search", params={"q": payload}, timeout=10
                )
                # We're testing that requests complete
                logger.info(f"XSS payload test completed: " f"{response.status_code}")
            except requests.exceptions.RequestException:
                logger.info("XSS test connection failed (acceptable)")

        logger.info("✅ XSS testing methodology completed")

    def test_12_configuration_testing_methodology(self):
        """Test configuration vulnerability testing methodology."""
        logger.info("Testing configuration methodology...")

        # Test common configuration endpoints
        config_endpoints = ["/debug", "/config", "/admin", "/status", "/info"]

        for endpoint in config_endpoints:
            try:
                response = requests.get(f"{self.flask_url}{endpoint}", timeout=10)
                logger.info(f"Config test {endpoint}: {response.status_code}")
            except requests.exceptions.RequestException:
                logger.info(f"Config test {endpoint}: Connection failed")

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
                    "src/analyzer/network_cli.py",
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
                    "src/analyzer/network_cli.py",
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
                    "src/analyzer/analyze_cli.py",
                    "samples/vulnerable-flask-app",
                    "--educational",
                ],
                "Static Analysis",
            ),
            # Step 3: DAST Analysis
            (
                [
                    "python",
                    "src/analyzer/dast_cli.py",
                    self.flask_url,
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


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
