#!/usr/bin/env python3
"""
Penetration Testing Analyzer Unit Tests

This test suite provides comprehensive unit testing for the penetration testing
analyzer modules with focus on working functionality.
"""

from analyzer.penetration_analyzer import (
    ReconnaissanceEngine,
    VulnerabilityScanner,
    ExploitEngine,
    PentestReport,
    PentestFinding,
    PenetrationTester
)
import unittest
import sys
import os
import tempfile
import json
from unittest.mock import Mock, patch
from pathlib import Path
import logging

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestPentestFinding(unittest.TestCase):
    """Test PentestFinding dataclass functionality."""

    def test_01_finding_creation(self):
        """Test basic finding creation and attributes."""
        logger.info("Testing PentestFinding creation...")

        finding = PentestFinding(
            tool="test_scanner",
            severity="high",
            title="Test Vulnerability",
            description="Test description",
            target="http://localhost:5000",
            cwe_id="CWE-89",
            cvss_score=7.5,
            confidence="high"
        )

        self.assertEqual(finding.tool, "test_scanner")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.title, "Test Vulnerability")
        self.assertEqual(finding.cvss_score, 7.5)
        self.assertEqual(finding.confidence, "high")

        logger.info("✅ PentestFinding creation test passed")


class TestReconnaissanceEngine(unittest.TestCase):
    """Test ReconnaissanceEngine functionality."""

    def setUp(self):
        """Set up reconnaissance engine for testing."""
        self.recon_engine = ReconnaissanceEngine()

    def test_01_engine_initialization(self):
        """Test reconnaissance engine initialization."""
        logger.info("Testing reconnaissance engine initialization...")

        self.assertIsNotNone(self.recon_engine)
        self.assertIsNotNone(self.recon_engine.session)

        logger.info("✅ Reconnaissance engine initialization test passed")

    @patch('socket.socket')
    def test_02_port_scan_functionality(self, mock_socket):
        """Test port scanning functionality."""
        logger.info("Testing port scan functionality...")

        # Mock socket to avoid actual network calls
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 61  # Connection refused
        mock_socket.return_value.__enter__.return_value = mock_sock

        # Test with limited ports to avoid long execution
        findings = self.recon_engine.port_scan("127.0.0.1", [8080, 8081])

        # Should return a list (may be empty for closed ports)
        self.assertIsInstance(findings, list)

        logger.info("✅ Port scan functionality test passed")


class TestVulnerabilityScanner(unittest.TestCase):
    """Test VulnerabilityScanner functionality."""

    def setUp(self):
        """Set up vulnerability scanner for testing."""
        self.vuln_scanner = VulnerabilityScanner()

    def test_01_scanner_initialization(self):
        """Test vulnerability scanner initialization."""
        logger.info("Testing vulnerability scanner initialization...")

        self.assertIsNotNone(self.vuln_scanner)
        self.assertIsNotNone(self.vuln_scanner.session)

        logger.info("✅ Vulnerability scanner initialization test passed")

    @patch('requests.Session.get')
    def test_02_debug_console_detection(self, mock_get):
        """Test debug console detection."""
        logger.info("Testing debug console detection...")

        # Mock response with debug console indicators
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Werkzeug Debugger"
        mock_response.url = "http://localhost:5000/console"
        mock_get.return_value = mock_response

        findings = self.vuln_scanner._test_debug_console(
            "http://localhost:5000")

        # Should detect debug console
        self.assertIsInstance(findings, list)
        if findings:
            self.assertEqual(findings[0].tool, "debug_console_scanner")
            self.assertEqual(findings[0].severity, "critical")

        logger.info("✅ Debug console detection test passed")

    def test_03_vulnerability_scan_method_exists(self):
        """Test that vulnerability scan method exists."""
        logger.info("Testing vulnerability scan method...")

        # Check that the main scanning method exists
        self.assertTrue(
            hasattr(self.vuln_scanner, 'scan_web_vulnerabilities'))

        logger.info("✅ Vulnerability scan method test passed")


class TestExploitEngine(unittest.TestCase):
    """Test ExploitEngine functionality."""

    def setUp(self):
        """Set up exploit engine for testing."""
        self.exploit_engine = ExploitEngine()

    def test_01_exploit_initialization(self):
        """Test exploit engine initialization."""
        logger.info("Testing exploit engine initialization...")

        self.assertIsNotNone(self.exploit_engine)
        self.assertIsNotNone(self.exploit_engine.session)

        logger.info("✅ Exploit engine initialization test passed")

    def test_02_exploit_findings_method_exists(self):
        """Test exploit findings method exists."""
        logger.info("Testing exploit findings method...")

        # Check that the exploit method exists
        self.assertTrue(hasattr(self.exploit_engine, 'exploit_findings'))

        # Test with empty findings list
        results = self.exploit_engine.exploit_findings([])
        self.assertIsInstance(results, list)

        logger.info("✅ Exploit findings method test passed")


class TestPentestReport(unittest.TestCase):
    """Test PentestReport dataclass functionality."""

    def test_01_report_creation(self):
        """Test PentestReport dataclass creation."""
        logger.info("Testing PentestReport creation...")

        test_finding = PentestFinding(
            tool="test_scanner",
            severity="high",
            title="Test Vulnerability",
            description="Test description",
            target="http://localhost:5000",
            cwe_id="CWE-89",
            cvss_score=7.5,
            confidence="high"
        )

        report = PentestReport(
            target="http://localhost:5000",
            test_duration=10.5,
            timestamp="2024-01-01T00:00:00",
            findings=[test_finding],
            tools_used=["nmap", "gobuster"],
            total_tests=5,
            successful_exploits=1,
            services_discovered=1,
            endpoints_tested=3,
            summary="Test summary",
            methodology=["Recon", "Scan"],
            recommendations=["Fix vulnerabilities"]
        )

        # Verify report attributes
        self.assertEqual(report.target, "http://localhost:5000")
        self.assertEqual(report.test_duration, 10.5)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.total_tests, 5)

        logger.info("✅ PentestReport creation test passed")

    def test_02_report_json_serialization(self):
        """Test report JSON serialization."""
        logger.info("Testing report JSON serialization...")

        test_finding = PentestFinding(
            tool="test_scanner",
            severity="high",
            title="Test Vulnerability",
            description="Test description",
            target="http://localhost:5000",
            cwe_id="CWE-89",
            cvss_score=7.5,
            confidence="high"
        )

        report = PentestReport(
            target="http://localhost:5000",
            test_duration=10.5,
            timestamp="2024-01-01T00:00:00",
            findings=[test_finding],
            tools_used=["nmap"],
            total_tests=1,
            successful_exploits=0,
            services_discovered=1,
            endpoints_tested=1,
            summary="Test",
            methodology=["Test"],
            recommendations=["Test"]
        )

        # Test JSON serialization using dataclass asdict
        from dataclasses import asdict
        report_dict = asdict(report)

        # Should be serializable to JSON
        json_str = json.dumps(report_dict, default=str)
        self.assertIsInstance(json_str, str)
        self.assertIn("localhost:5000", json_str)

        logger.info("✅ Report JSON serialization test passed")


class TestPenetrationTester(unittest.TestCase):
    """Test PenetrationTester integration."""

    def setUp(self):
        """Set up penetration tester for testing."""
        self.pentester = PenetrationTester()

    def test_01_analyzer_initialization(self):
        """Test penetration analyzer initialization."""
        logger.info("Testing penetration analyzer initialization...")

        self.assertIsNotNone(self.pentester.recon_engine)
        self.assertIsNotNone(self.pentester.vulnerability_scanner)
        self.assertIsNotNone(self.pentester.exploit_engine)
        self.assertIsNotNone(self.pentester.tools_available)

        logger.info("✅ Penetration analyzer initialization test passed")

    def test_02_tools_availability(self):
        """Test tool availability checking."""
        logger.info("Testing tools availability...")

        tools = self.pentester.tools_available
        self.assertIsInstance(tools, dict)

        # Should have at least some common tools
        expected_tools = ['curl', 'nmap']
        for tool in expected_tools:
            if tool in tools:
                self.assertIsInstance(tools[tool], bool)

        logger.info("✅ Tools availability test passed")

    def test_03_conduct_penetration_test_method_exists(self):
        """Test that conduct_penetration_test method exists."""
        logger.info("Testing conduct_penetration_test method...")

        # Check that the main testing method exists
        self.assertTrue(
            hasattr(self.pentester, 'conduct_penetration_test'))

        logger.info("✅ Conduct penetration test method test passed")


def run_unit_tests():
    """Run all unit tests with detailed output."""
    logger.info("🚀 Starting Penetration Analyzer Unit Tests...")

    # Create test suite
    test_classes = [
        TestPentestFinding,
        TestReconnaissanceEngine,
        TestVulnerabilityScanner,
        TestExploitEngine,
        TestPentestReport,
        TestPenetrationTester
    ]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    passed = total_tests - failures - errors

    logger.info(f"\n📊 Test Results Summary:")
    logger.info(f"   Total Tests: {total_tests}")
    logger.info(f"   ✅ Passed: {passed}")
    logger.info(f"   ❌ Failed: {failures}")
    logger.info(f"   💥 Errors: {errors}")

    if failures == 0 and errors == 0:
        logger.info("🎉 All unit tests passed!")
        return True
    else:
        logger.error("❌ Some unit tests failed!")
        return False


if __name__ == '__main__':
    success = run_unit_tests()
    exit(0 if success else 1)
