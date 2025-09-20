#!/usr/bin/env python3
"""
DAST (Dynamic Application Security Testing) Command Validation Tests

This test suite validates all DAST commands from the quick reference guide
to ensure they work correctly and produce expected output.
"""

import unittest
import subprocess
import requests
import time
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DASTCommandValidationTest(unittest.TestCase):
    """Test suite to validate DAST analyser commands."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.project_root = Path(__file__).parent.parent
        os.chdir(cls.project_root)
        cls.dast_cli = "src/analyser/dast_cli.py"
        cls.timeout = 120  # seconds - DAST takes longer
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

    def test_01_dast_help_command(self):
        """Test DAST analyser help command."""
        logger.info("Testing DAST help command...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, "--help"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(
                result.returncode, 0, f"DAST help command failed: {result.stderr}"
            )
            self.assertIn(
                "Dynamic Application Security Testing",
                result.stdout,
                "Help output missing expected content",
            )
            self.assertIn(
                "--educational", result.stdout, "Help missing --educational option"
            )
            self.assertIn(
                "--deep-scan", result.stdout, "Help missing --deep-scan option"
            )

            logger.info("✅ DAST help command works correctly")

        except subprocess.TimeoutExpired:
            self.fail("DAST help command timed out")

    def test_02_dast_basic_scan_pwa(self):
        """Test basic DAST scan on PWA application (primary target)."""
        logger.info("Testing basic DAST scan on PWA app...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.pwa_url],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"DAST basic scan failed: {result.stderr}"
            )
            self.assertIn(
                "DYNAMIC SECURITY ANALYSIS REPORT",
                result.stdout,
                "Scan output missing report header",
            )

            logger.info("✅ Basic DAST scan on PWA app works")

        except subprocess.TimeoutExpired:
            self.fail("DAST basic scan timed out")

    def test_03_dast_quick_scan_pwa(self):
        """Test quick DAST scan on PWA application."""
        logger.info("Testing quick DAST scan on PWA app...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.pwa_url, "--quick"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout // 2,  # Quick scan should be faster
            )

            self.assertEqual(
                result.returncode, 0, f"DAST quick scan failed: {result.stderr}"
            )

            logger.info("✅ Quick DAST scan on PWA app works")

        except subprocess.TimeoutExpired:
            self.fail("DAST quick scan timed out")

    def test_04_dast_educational_mode_pwa(self):
        """Test DAST analysis with educational explanations on PWA app."""
        logger.info("Testing DAST educational mode on PWA app...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.pwa_url, "--educational"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"DAST educational scan failed: {result.stderr}"
            )
            self.assertIn(
                "Description:", result.stdout, "Educational mode missing detailed descriptions"
            )

            logger.info("✅ DAST educational mode on PWA app works")

        except subprocess.TimeoutExpired:
            self.fail("DAST educational scan timed out")

    def test_05_dast_deep_scan_pwa(self):
        """Test DAST deep scan on PWA application."""
        logger.info("Testing DAST deep scan on PWA app...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.pwa_url, "--deep-scan"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,  # Deep scan takes longer
            )

            self.assertEqual(
                result.returncode, 0, f"DAST deep scan failed: {result.stderr}"
            )

            logger.info("✅ DAST deep scan on PWA app works")

        except subprocess.TimeoutExpired:
            self.fail("DAST deep scan timed out")

    def test_08_dast_verbose_mode_flask(self):
        """Test DAST analysis with verbose output on Flask app."""
        logger.info("Testing DAST verbose mode on Flask app...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.flask_url, "--verbose"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"DAST verbose scan failed: {result.stderr}"
            )
            # Verbose mode should produce more detailed output
            self.assertGreater(
                len(result.stdout), 500, "Verbose output seems too short"
            )

            logger.info("✅ DAST verbose mode on Flask app works")

        except subprocess.TimeoutExpired:
            self.fail("DAST verbose scan timed out")

    def test_09_dast_quiet_mode_flask(self):
        """Test DAST analysis in quiet mode on Flask app."""
        logger.info("Testing DAST quiet mode on Flask app...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.flask_url, "--quiet"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"DAST quiet scan failed: {result.stderr}"
            )
            # Quiet mode should run successfully (currently only affects logging level)
            self.assertGreater(
                len(result.stdout), 0, "Quiet mode should still produce output"
            )

            logger.info("✅ DAST quiet mode on Flask app works")

        except subprocess.TimeoutExpired:
            self.fail("DAST quiet scan timed out")

    def test_10_dast_nikto_tool_only(self):
        """Test DAST analysis with nikto tool only."""
        logger.info("Testing DAST with nikto tool only...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.flask_url, "--tools", "nikto"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"DAST nikto scan failed: {result.stderr}"
            )

            logger.info("✅ DAST nikto-only scan works")

        except subprocess.TimeoutExpired:
            self.fail("DAST nikto scan timed out")

    def test_11_dast_gobuster_tool_only(self):
        """Test DAST analysis with gobuster tool only."""
        logger.info("Testing DAST with gobuster tool only...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.flask_url, "--tools", "gobuster"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"DAST gobuster scan failed: {result.stderr}"
            )

            logger.info("✅ DAST gobuster-only scan works")

        except subprocess.TimeoutExpired:
            self.fail("DAST gobuster scan timed out")

    def test_12_dast_multiple_tools(self):
        """Test DAST analysis with multiple tools."""
        logger.info("Testing DAST with multiple tools...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.dast_cli,
                    self.flask_url,
                    "--tools",
                    "nikto",
                    "gobuster",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,  # Multiple tools take longer
            )

            self.assertEqual(
                result.returncode, 0, f"DAST multi-tool scan failed: {result.stderr}"
            )

            logger.info("✅ DAST multi-tool scan works")

        except subprocess.TimeoutExpired:
            self.fail("DAST multi-tool scan timed out")

    def test_13_dast_all_tools(self):
        """Test DAST analysis with all available tools."""
        logger.info("Testing DAST with all tools...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.flask_url, "--tools", "all"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,  # All tools take longer
            )

            self.assertEqual(
                result.returncode, 0, f"DAST all-tools scan failed: {result.stderr}"
            )

            logger.info("✅ DAST all-tools scan works")

        except subprocess.TimeoutExpired:
            self.fail("DAST all-tools scan timed out")

    def test_14_dast_demo_apps_scan(self):
        """Test DAST scan on all demo applications."""
        logger.info("Testing DAST demo apps scan...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, "--demo-apps", "--educational"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 3,  # Multiple apps take much longer
            )

            self.assertEqual(
                result.returncode, 0, f"DAST demo apps scan failed: {result.stderr}"
            )
            self.assertIn(
                "localhost:5000", result.stdout, "Demo apps scan missing PWA app"
            )

            logger.info("✅ DAST demo apps scan works")

        except subprocess.TimeoutExpired:
            self.fail("DAST demo apps scan timed out")

    def test_15_dast_scan_flask_secondary(self):
        """Test DAST scan on Flask application (secondary target)."""
        logger.info("Testing DAST scan on Flask app...")

        try:
            result = subprocess.run(
                ["python", self.dast_cli, self.flask_url, "--educational"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"DAST Flask scan failed: {result.stderr}"
            )

            logger.info("✅ DAST scan on Flask app works")

        except subprocess.TimeoutExpired:
            self.fail("DAST Flask scan timed out")


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
