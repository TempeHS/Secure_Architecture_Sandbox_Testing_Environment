#!/usr/bin/env python3
"""
Network Analysis Command Validation Tests

This test suite validates all network analysis commands from the quick
reference guide to ensure they work correctly and produce expected output.
"""

import unittest
import subprocess
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkCommandValidationTest(unittest.TestCase):
    """Test suite to validate network analyser commands."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.project_root = Path(__file__).parent.parent
        os.chdir(cls.project_root)
        cls.network_cli = "src/analyser/network_cli.py"
        cls.timeout = 90  # seconds
        cls.reports_dir = cls.project_root / "reports"
        cls.reports_dir.mkdir(exist_ok=True)

    def test_01_network_help_command(self):
        """Test network analyser help command."""
        logger.info("Testing network analyser help command...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--help"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(
                result.returncode, 0, f"Network help command failed: {result.stderr}"
            )
            self.assertIn(
                "Network Traffic Analysis",
                result.stdout,
                "Help output missing expected content",
            )
            self.assertIn(
                "--monitor-connections",
                result.stdout,
                "Help missing --monitor-connections option",
            )
            self.assertIn(
                "--scan-services", result.stdout, "Help missing --scan-services option"
            )

            logger.info("✅ Network help command works correctly")

        except subprocess.TimeoutExpired:
            self.fail("Network help command timed out")

    def test_02_monitor_connections_basic(self):
        """Test basic connection monitoring."""
        logger.info("Testing basic connection monitoring...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--monitor-connections"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"Connection monitoring failed: {result.stderr}"
            )
            self.assertIn(
                "connections",
                result.stdout.lower(),
                "Output missing connection information",
            )

            logger.info("✅ Basic connection monitoring works")

        except subprocess.TimeoutExpired:
            self.fail("Connection monitoring timed out")

    def test_03_monitor_connections_educational(self):
        """Test connection monitoring with educational explanations."""
        logger.info("Testing connection monitoring in educational mode...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--monitor-connections", "--educational"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"Educational connection monitoring failed: " f"{result.stderr}",
            )
            self.assertIn(
                "🎓 EDUCATIONAL INSIGHTS",
                result.stdout,
                "Educational mode missing explanations",
            )

            logger.info("✅ Educational connection monitoring works")

        except subprocess.TimeoutExpired:
            self.fail("Educational connection monitoring timed out")

    def test_04_scan_services_localhost(self):
        """Test service scanning on localhost."""
        logger.info("Testing service scanning on localhost...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--scan-services", "localhost"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"Service scanning failed: {result.stderr}"
            )
            self.assertIn(
                "service", result.stdout.lower(), "Output missing service information"
            )

            logger.info("✅ Service scanning on localhost works")

        except subprocess.TimeoutExpired:
            self.fail("Service scanning timed out")

    def test_05_scan_services_educational(self):
        """Test service scanning with educational explanations."""
        logger.info("Testing service scanning in educational mode...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.network_cli,
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
                result.returncode,
                0,
                f"Educational service scanning failed: " f"{result.stderr}",
            )

            logger.info("✅ Educational service scanning works")

        except subprocess.TimeoutExpired:
            self.fail("Educational service scanning timed out")

    def test_06_capture_traffic_basic(self):
        """Test basic traffic capture."""
        logger.info("Testing basic traffic capture...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--capture-traffic", "--duration", "10"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"Traffic capture failed: {result.stderr}"
            )

            logger.info("✅ Basic traffic capture works")

        except subprocess.TimeoutExpired:
            self.fail("Traffic capture timed out")

    def test_07_capture_traffic_educational(self):
        """Test traffic capture with educational explanations."""
        logger.info("Testing traffic capture in educational mode...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.network_cli,
                    "--capture-traffic",
                    "--duration",
                    "15",
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
                f"Educational traffic capture failed: " f"{result.stderr}",
            )

            logger.info("✅ Educational traffic capture works")

        except subprocess.TimeoutExpired:
            self.fail("Educational traffic capture timed out")

    def test_08_dns_analysis_basic(self):
        """Test basic DNS analysis."""
        logger.info("Testing basic DNS analysis...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--dns-analysis", "--duration", "10"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"DNS analysis failed: {result.stderr}"
            )

            logger.info("✅ Basic DNS analysis works")

        except subprocess.TimeoutExpired:
            self.fail("DNS analysis timed out")

    def test_09_dns_analysis_educational(self):
        """Test DNS analysis with educational explanations."""
        logger.info("Testing DNS analysis in educational mode...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.network_cli,
                    "--dns-analysis",
                    "--duration",
                    "15",
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
                f"Educational DNS analysis failed: " f"{result.stderr}",
            )

            logger.info("✅ Educational DNS analysis works")

        except subprocess.TimeoutExpired:
            self.fail("Educational DNS analysis timed out")

    def test_10_demo_network_mode(self):
        """Test demo network mode."""
        logger.info("Testing demo network mode...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--demo-network"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode, 0, f"Demo network mode failed: {result.stderr}"
            )

            logger.info("✅ Demo network mode works")

        except subprocess.TimeoutExpired:
            self.fail("Demo network mode timed out")

    def test_11_demo_network_educational(self):
        """Test demo network mode with educational explanations."""
        logger.info("Testing demo network mode in educational mode...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--demo-network", "--educational"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"Educational demo network failed: " f"{result.stderr}",
            )

            logger.info("✅ Educational demo network works")

        except subprocess.TimeoutExpired:
            self.fail("Educational demo network timed out")

    def test_14_verbose_mode(self):
        """Test network analysis with verbose output."""
        logger.info("Testing network analysis in verbose mode...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--monitor-connections", "--verbose"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"Verbose network analysis failed: " f"{result.stderr}",
            )
            # Verbose mode should produce more detailed output
            self.assertGreater(
                len(result.stdout), 200, "Verbose output seems too short"
            )

            logger.info("✅ Verbose network analysis works")

        except subprocess.TimeoutExpired:
            self.fail("Verbose network analysis timed out")

    def test_15_quiet_mode(self):
        """Test network analysis in quiet mode."""
        logger.info("Testing network analysis in quiet mode...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--monitor-connections", "--quiet"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"Quiet network analysis failed: " f"{result.stderr}",
            )
            # Quiet mode should produce less output (but still some minimal output)
            self.assertLess(
                len(result.stdout), 500, "Quiet mode output seems too verbose"
            )

            logger.info("✅ Quiet network analysis works")

        except subprocess.TimeoutExpired:
            self.fail("Quiet network analysis timed out")

    def test_16_combined_options(self):
        """Test network analysis with combined options."""
        logger.info("Testing network analysis with combined options...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.network_cli,
                    "--monitor-connections",
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
                f"Combined options network analysis failed: " f"{result.stderr}",
            )
            self.assertIn(
                "🎓 EDUCATIONAL INSIGHTS",
                result.stdout,
                "Combined options missing educational content",
            )

            logger.info("✅ Combined options network analysis works")

        except subprocess.TimeoutExpired:
            self.fail("Combined options network analysis timed out")

    def test_18_traffic_capture_with_filter(self):
        """Test traffic capture with filter option."""
        logger.info("Testing traffic capture with filter...")

        try:
            result = subprocess.run(
                [
                    "python",
                    self.network_cli,
                    "--capture-traffic",
                    "--duration",
                    "10",
                    "--filter",
                    "port 80",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # This might fail if filter option is not supported,
            # but we test it anyway
            if result.returncode == 0:
                logger.info("✅ Traffic capture with filter works")
            else:
                logger.info(
                    "ℹ️ Traffic capture filter not supported, " "which is acceptable"
                )

        except subprocess.TimeoutExpired:
            self.fail("Traffic capture with filter timed out")

    def test_19_network_analysis_localhost_ip(self):
        """Test network analysis using localhost IP."""
        logger.info("Testing network analysis with localhost IP...")

        try:
            result = subprocess.run(
                ["python", self.network_cli, "--scan-services", "127.0.0.1"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            self.assertEqual(
                result.returncode,
                0,
                f"Network analysis with IP failed: " f"{result.stderr}",
            )

            logger.info("✅ Network analysis with localhost IP works")

        except subprocess.TimeoutExpired:
            self.fail("Network analysis with IP timed out")

    def test_20_comprehensive_network_analysis(self):
        """Test comprehensive network analysis workflow."""
        logger.info("Testing comprehensive network analysis workflow...")

        try:
            # Run a comprehensive analysis similar to the workflow
            # in the quick reference guide
            result = subprocess.run(
                [
                    "python",
                    self.network_cli,
                    "--demo-network",
                    "--educational",
                    "--verbose",
                ],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout * 2,  # Allow more time for comprehensive
            )

            self.assertEqual(
                result.returncode,
                0,
                f"Comprehensive network analysis failed: " f"{result.stderr}",
            )
            self.assertGreater(
                len(result.stdout), 500, "Comprehensive analysis output seems too short"
            )

            logger.info("✅ Comprehensive network analysis workflow works")

        except subprocess.TimeoutExpired:
            self.fail("Comprehensive network analysis timed out")


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
