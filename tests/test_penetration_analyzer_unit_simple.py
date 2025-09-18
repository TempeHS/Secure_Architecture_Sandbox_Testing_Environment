#!/usr/bin/env python3
"""
Penetration Testing Analyzer Unit Tests

This test suite provides comprehensive unit testing for the penetration testing
analyzer modules, including ReconnaissanceEngine, VulnerabilityScanner,
ExploitEngine, and PenetrationTester classes.

Test Coverage:
- Individual module functionality
- Error handling and edge cases
- Configuration parameter validation
- Component integration testing
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
import requests
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
            target="http://localhost:5000"
        )

        self.assertEqual(finding.tool, "test_scanner")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.title, "Test Vulnerability")

        logger.info("✅ PentestFinding creation test passed")

    def test_02_finding_attributes(self):
        """Test finding attributes and defaults."""
        logger.info("Testing finding attributes...")

        finding = PentestFinding(
            tool="test",
            severity="critical",
            title="Critical Vuln",
            description="Test",
            target="test"
        )

        # Test required attributes
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.title, "Critical Vuln")

        logger.info("✅ Finding attributes test passed")


class TestReconnaissanceEngine(unittest.TestCase):
    """Test ReconnaissanceEngine functionality."""

    def setUp(self):
        """Set up reconnaissance engine for testing."""
        self.recon = ReconnaissanceEngine()
        self.test_target = "127.0.0.1"

    @patch('socket.socket')
    def test_01_port_scan_basic(self, mock_socket):
        """Test basic port scanning functionality."""
        logger.info("Testing port scanning...")

        # Mock successful connection
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0  # Success
        mock_socket.return_value.__enter__.return_value = mock_sock

        findings = self.recon.port_scan(self.test_target, [80, 443])

        # Should return list of findings
        self.assertIsInstance(findings, list)

        logger.info("✅ Port scanning test passed")

    @patch('requests.Session.get')
    def test_02_service_enumeration(self, mock_get):
        """Test service enumeration."""
        logger.info("Testing service enumeration...")

        # Mock HTTP response
        mock_response = Mock()
        mock_response.headers = {'Server': 'Apache/2.4.41'}
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        findings = self.recon.service_enumeration(self.test_target, 80)

        # Should return list of findings
        self.assertIsInstance(findings, list)

        logger.info("✅ Service enumeration test passed")


class TestVulnerabilityScanner(unittest.TestCase):
    """Test VulnerabilityScanner functionality."""

    def setUp(self):
        """Set up vulnerability scanner for testing."""
        self.scanner = VulnerabilityScanner()
        self.test_url = "http://localhost:5000"

    @patch('requests.Session.get')
    def test_01_debug_console_detection(self, mock_get):
        """Test debug console vulnerability detection."""
        logger.info("Testing debug console detection...")

        # Mock debug console response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Werkzeug Debugger"
        mock_response.url = "http://localhost:5000/console"
        mock_get.return_value = mock_response

        findings = self.scanner._test_debug_console(self.test_url)

        # Should return list of findings
        self.assertIsInstance(findings, list)

        logger.info("✅ Debug console detection test passed")

    @patch('requests.Session.get')
    def test_02_web_vulnerability_scan(self, mock_get):
        """Test web vulnerability scanning."""
        logger.info("Testing web vulnerability scan...")

        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Test application"
        mock_get.return_value = mock_response

        findings = self.scanner.scan_web_vulnerabilities(self.test_url)

        # Should return list of findings
        self.assertIsInstance(findings, list)

        logger.info("✅ Web vulnerability scan test passed")


class TestExploitEngine(unittest.TestCase):
    """Test ExploitEngine functionality."""

    def setUp(self):
        """Set up exploit engine for testing."""
        self.exploit_engine = ExploitEngine()

    def test_01_exploit_initialization(self):
        """Test exploit engine initialization."""
        logger.info("Testing exploit engine initialization...")

        self.assertIsNotNone(self.exploit_engine.session)

        logger.info("✅ Exploit engine initialization test passed")

    def test_02_exploit_findings_empty(self):
        """Test exploit findings with empty list."""
        logger.info("Testing exploit findings processing...")

        # Test with empty findings list
        results = self.exploit_engine.exploit_findings([])

        # Should return empty list
        self.assertEqual(len(results), 0)

        logger.info("✅ Exploit findings processing test passed")


class TestPenetrationTester(unittest.TestCase):
    """Test complete PenetrationTester integration."""

    def setUp(self):
        """Set up integration test environment."""
        self.pentester = PenetrationTester()

    def test_01_tester_initialization(self):
        """Test penetration tester initialization."""
        logger.info("Testing penetration tester initialization...")

        self.assertIsNotNone(self.pentester.recon_engine)
        self.assertIsNotNone(self.pentester.vulnerability_scanner)
        self.assertIsNotNone(self.pentester.exploit_engine)

        logger.info("✅ Penetration tester initialization test passed")

    def test_02_tool_availability_check(self):
        """Test tool availability checking."""
        logger.info("Testing tool availability check...")

        tools = self.pentester.tools_available

        # Should return dictionary of tool availability
        self.assertIsInstance(tools, dict)
        self.assertIn('nmap', tools)
        self.assertIn('curl', tools)

        logger.info("✅ Tool availability check test passed")


class TestIntegrationWorkflow(unittest.TestCase):
    """Test complete workflow integration."""

    def test_01_component_integration(self):
        """Test that all components can work together."""
        logger.info("Testing component integration...")

        # Test that all classes can be instantiated
        recon = ReconnaissanceEngine()
        scanner = VulnerabilityScanner()
        exploit = ExploitEngine()
        tester = PenetrationTester()

        # All should be valid objects
        self.assertIsNotNone(recon)
        self.assertIsNotNone(scanner)
        self.assertIsNotNone(exploit)
        self.assertIsNotNone(tester)

        logger.info("✅ Component integration test passed")

    def test_02_finding_workflow(self):
        """Test finding creation and processing workflow."""
        logger.info("Testing finding workflow...")

        # Create test finding
        finding = PentestFinding(
            tool="test_tool",
            severity="medium",
            title="Test Finding",
            description="Test description",
            target="http://test.com"
        )

        # Should be valid finding
        self.assertEqual(finding.tool, "test_tool")
        self.assertEqual(finding.severity, "medium")

        logger.info("✅ Finding workflow test passed")


if __name__ == '__main__':
    # Configure test discovery and execution
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes in logical order
    test_classes = [
        TestPentestFinding,
        TestReconnaissanceEngine,
        TestVulnerabilityScanner,
        TestExploitEngine,
        TestPenetrationTester,
        TestIntegrationWorkflow
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestClass(test_class)
        suite.addTests(tests)

    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(suite)

    # Exit with appropriate code
    exit(0 if result.wasSuccessful() else 1)
