#!/usr/bin/env python3
"""
SAST (Static Application Security Testing) Command Validation Tests

This test suite validates all SAST commands from the quick reference guide
to ensure they work correctly and produce expected output.
"""

import unittest
import subprocess
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SASTCommandValidationTest(unittest.TestCase):
    """Test suite to validate SAST analyser commands."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.project_root = Path(__file__).parent.parent
        os.chdir(cls.project_root)
        cls.sast_cli = "src/analyser/analyse_cli.py"
        cls.timeout = 60  # seconds
        cls.reports_dir = cls.project_root / "reports"
        cls.reports_dir.mkdir(exist_ok=True)

    def test_01_sast_help_command(self):
        """Test SAST analyser help command."""
        logger.info("Testing SAST help command...")

        try:
            result = subprocess.run(
                ["python", self.sast_cli, "--help"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(
                result.returncode, 0, f"SAST help command failed: {result.stderr}"
            )
            self.assertIn(
                "Educational Security Analysis Tool",
                result.stdout,
                "Help output missing expected content",
            )
            self.assertIn(
                "--educational", result.stdout, "Help missing --educational option"
            )

            logger.info("✅ SAST help command works correctly")

        except subprocess.TimeoutExpired:
            self.fail("SAST help command timed out")

    def test_02_sast_simple_analysis_pwa(self):
        """Test simple SAST analysis on PWA application (primary target)."""
        logger.info("Testing simple SAST analysis on PWA app...")

        try:
            result = subprocess.run(
                ["python", self.sast_cli, "samples/unsecure-pwa"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"SAST analysis failed: {result.stderr}"
            )
            self.assertIn(
                "Total:",
                result.stdout,
                "Analysis output missing findings summary",
            )
            self.assertIn(
                "High", result.stdout, "Analysis output missing severity levels"
            )

            logger.info("✅ Simple SAST analysis on PWA app works")

        except subprocess.TimeoutExpired:
            self.fail("SAST analysis timed out")

    def test_03_sast_educational_mode_pwa(self):
        """Test SAST analysis with educational explanations on PWA app."""
        logger.info("Testing SAST educational mode on PWA app...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.sast_cli,
                    "samples/unsecure-pwa",
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
                f"SAST educational analysis failed: {result.stderr}",
            )
            self.assertIn(
                "🎓 Educational Note",
                result.stdout,
                "Educational mode missing explanations",
            )
            self.assertIn(
                "SQL", result.stdout, "Missing expected SQL injection findings"
            )

            logger.info("✅ SAST educational mode on PWA app works")

        except subprocess.TimeoutExpired:
            self.fail("SAST educational analysis timed out")

    def test_04_sast_verbose_mode_pwa(self):
        """Test SAST analysis with verbose output on PWA app."""
        logger.info("Testing SAST verbose mode on PWA app...")

        try:
            result = subprocess.run(
                ["python", self.sast_cli, "samples/unsecure-pwa", "--verbose"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"SAST verbose analysis failed: {result.stderr}"
            )
            # Verbose mode should produce more detailed output
            self.assertGreater(
                len(result.stdout), 1000, "Verbose output seems too short"
            )

            logger.info("✅ SAST verbose mode on PWA app works")

        except subprocess.TimeoutExpired:
            self.fail("SAST verbose analysis timed out")

    def test_05_sast_json_output_mode(self):
        """Test SAST analysis with JSON output format."""
        logger.info("Testing SAST JSON output mode...")

        try:
            import json
            import tempfile

            # Create a temporary file for JSON output
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as tmp:
                json_output_path = tmp.name

            result = subprocess.run(
                [
                    "python",
                    self.sast_cli,
                    "samples/unsecure-pwa",
                    "--output",
                    json_output_path,
                    "--format",
                    "json",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"SAST JSON output failed: {result.stderr}"
            )

            # Read the JSON output file
            with open(json_output_path, "r") as f:
                json_content = f.read()

            # Clean up temp file
            os.unlink(json_output_path)

            # JSON output should be valid JSON structure
            self.assertIn(
                "{", json_content, "JSON output missing opening brace"
            )
            self.assertIn(
                "}", json_content, "JSON output missing closing brace"
            )
            # Verify it's valid JSON
            try:
                json_data = json.loads(json_content)
                self.assertIsInstance(
                    json_data, dict, "JSON output should be a dictionary")
            except json.JSONDecodeError:
                self.fail("JSON output is not valid JSON")

            logger.info("✅ SAST JSON output mode works")

        except subprocess.TimeoutExpired:
            self.fail("SAST JSON output timed out")

    def test_05b_sast_educational_verbose_combined(self):
        """Test SAST analysis with both --educational and --verbose flags."""
        logger.info("Testing SAST with combined --educational --verbose...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.sast_cli,
                    "samples/unsecure-pwa",
                    "--educational",
                    "--verbose",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"SAST educational+verbose analysis failed: {result.stderr}",
            )
            # Should have educational content
            self.assertIn(
                "🎓 Educational Note",
                result.stdout,
                "Combined mode missing educational explanations",
            )
            # Verbose mode should produce detailed output
            self.assertGreater(
                len(result.stdout), 1000, "Combined output seems too short"
            )

            logger.info("✅ SAST educational+verbose combined mode works")

        except subprocess.TimeoutExpired:
            self.fail("SAST educational+verbose analysis timed out")

    def test_06_sast_analysis_flask_secondary(self):
        """Test SAST analysis on Flask application (secondary target)."""
        logger.info("Testing SAST analysis on Flask app...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.sast_cli,
                    "samples/vulnerable-flask-app",
                    "--educational",
                    "--verbose",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"SAST Flask analysis failed: {result.stderr}"
            )
            self.assertIn(
                "Total:",
                result.stdout,
                "Flask analysis output missing findings summary",
            )
            # Verify educational content is present
            self.assertIn(
                "🎓 Educational Note",
                result.stdout,
                "Flask analysis missing educational explanations",
            )

            logger.info("✅ SAST analysis on Flask app works")

        except subprocess.TimeoutExpired:
            self.fail("SAST Flask analysis timed out")

    def test_07_sast_demo_apps_analysis(self):
        """Test SAST analysis on all demo applications."""
        logger.info("Testing SAST demo apps analysis...")

        try:
            result = subprocess.run(
                ["python", self.sast_cli, "--demo-apps", "--educational"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,  # Give more time for multiple apps
            )

            self.assertEqual(
                result.returncode, 0, f"SAST demo apps analysis failed: {result.stderr}"
            )
            self.assertIn(
                "vulnerable-flask-app",
                result.stdout,
                "Demo apps analysis missing Flask app",
            )
            self.assertIn(
                "unsecure-pwa", result.stdout, "Demo apps analysis missing PWA app"
            )

            logger.info("✅ SAST demo apps analysis works")

        except subprocess.TimeoutExpired:
            self.fail("SAST demo apps analysis timed out")

    def test_08_sast_specific_tools_bandit(self):
        """Test SAST analysis with specific tool (bandit)."""
        logger.info("Testing SAST with bandit tool only...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.sast_cli,
                    "samples/unsecure-pwa",
                    "--tools",
                    "bandit",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"SAST bandit analysis failed: {result.stderr}"
            )
            self.assertIn(
                "bandit", result.stdout.lower(), "Bandit tool not mentioned in output"
            )

            logger.info("✅ SAST bandit-only analysis works")

        except subprocess.TimeoutExpired:
            self.fail("SAST bandit analysis timed out")

    def test_09_sast_specific_tools_safety(self):
        """Test SAST analysis with specific tool (safety)."""
        logger.info("Testing SAST with safety tool only...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.sast_cli,
                    "samples/unsecure-pwa",
                    "--tools",
                    "safety",
                    "--educational",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"SAST safety analysis failed: {result.stderr}"
            )
            # Safety cheques dependencies, so output might be different
            # Just ensure it runs without error

            logger.info("✅ SAST safety-only analysis works")

        except subprocess.TimeoutExpired:
            self.fail("SAST safety analysis timed out")

    def test_10_sast_multiple_tools(self):
        """Test SAST analysis with multiple specific tools."""
        logger.info("Testing SAST with multiple tools...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.sast_cli,
                    "samples/unsecure-pwa",
                    "--tools",
                    "bandit",
                    "safety",
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
                f"SAST multi-tool analysis failed: {result.stderr}",
            )

            logger.info("✅ SAST multi-tool analysis works")

        except subprocess.TimeoutExpired:
            self.fail("SAST multi-tool analysis timed out")

    def test_11_sast_quiet_mode(self):
        """Test SAST analysis in quiet mode."""
        logger.info("Testing SAST quiet mode...")

        try:
            result = subprocess.run(
                ["python", self.sast_cli, "samples/unsecure-pwa", "--quiet"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"SAST quiet analysis failed: {result.stderr}"
            )
            # Quiet mode should run successfully (currently only affects logging level)
            self.assertGreater(
                len(result.stdout), 0, "Quiet mode should still produce output"
            )

            logger.info("✅ SAST quiet mode works")

        except subprocess.TimeoutExpired:
            self.fail("SAST quiet analysis timed out")


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
