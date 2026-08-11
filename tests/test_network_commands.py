#!/usr/bin/env python3
"""
Network Analysis Command Validation Tests

This test suite validates all network analysis commands from the quick
reference guide to ensure they work correctly and produce expected output.
"""

import unittest
import subprocess
import os
import socket
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkCommandValidationTest(unittest.TestCase):
    """Test suite to validate network analyser commands."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests.

        Verifies the sandbox's sample apps are actually running BEFORE any
        test executes. If they're not, this raises immediately — unittest
        then errors out every test in this class without running any of
        them, instead of each test failing individually with a confusing
        "connection refused"/"http_code 000" error. This is deliberately a
        hard failure, not a skip: a broken sample-app stack is a real setup
        problem that must be fixed, not silently ignored.
        """
        cls.project_root = Path(__file__).parent.parent
        os.chdir(cls.project_root)
        cls.network_cli = "src/analyser/network_cli.py"
        cls.timeout = 90  # seconds
        cls.reports_dir = cls.project_root / "reports"
        cls.reports_dir.mkdir(exist_ok=True)

        required_ports = {
            5000: "unsecure-pwa",
            9090: "vulnerable-flask-app",
        }
        unreachable = []
        for port, name in required_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            try:
                if sock.connect_ex(("localhost", port)) != 0:
                    unreachable.append(f"port {port} ({name})")
            finally:
                sock.close()

        if unreachable:
            raise RuntimeError(
                "Sandbox sample apps are not running — cannot proceed with "
                f"network command tests. Unreachable: {', '.join(unreachable)}.\n"
                "Fix: run the following, then re-run the tests:\n"
                "  cd docker && docker-compose up -d"
            )

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
        """Test service scanning on localhost.

        Asserts that at least one service is actually discovered (not just
        that the word "service" appears in the output) — the scanner used
        to check only classic ports (21/22/23/.../5900) and completely miss
        this sandbox's own sample-app ports (3000/5000/8000/8080/9090),
        silently reporting "Services Discovered: 0" even with services
        running. Requires the docker-compose sample apps to be up."""
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
            self.assertNotIn(
                "Services Discovered: 0", result.stdout,
                "Scanner found no services — it should detect the sandbox's "
                "own sample apps on ports 3000/5000/8000/8080/9090 "
                "(are the docker-compose services running?)",
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

            self.assertEqual(
                result.returncode, 0,
                f"Traffic capture with filter failed: {result.stderr}",
            )
            self.assertIn(
                "Filter: port 80", result.stdout,
                "Output does not confirm the filter was applied",
            )

            logger.info("✅ Traffic capture with filter works")

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

    def test_21_dig_shows_dns_query_and_answer(self):
        """Test the `dig` DNS lookup command from Exercise 5 Activity 6,
        which shows the actual DNS query/response before the timing/TLS
        steps."""
        logger.info("Testing dig DNS query/answer output...")

        try:
            result = subprocess.run(
                ["dig", "example.com"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            self.fail("dig is not installed on PATH")
        except subprocess.TimeoutExpired:
            self.fail("dig example.com timed out")

        self.assertEqual(
            result.returncode, 0, f"dig command failed: {result.stderr}"
        )
        for marker in ("QUESTION SECTION", "ANSWER SECTION", "Query time"):
            self.assertIn(
                marker, result.stdout,
                f"dig output missing expected section: {marker!r}",
            )

        logger.info("✅ dig shows the DNS question and answer sections")

    def test_22_curl_timing_breakdown_local(self):
        """Test the curl -w DNS/TCP/TLS/transfer timing breakdown command
        from Exercise 5 Activity 6, against a local (non-TLS) sample app so
        the test has no external network dependency."""
        logger.info("Testing curl -w phase timing breakdown (local target)...")

        timing_format = (
            "namelookup:%{time_namelookup}\n"
            "connect:%{time_connect}\n"
            "appconnect:%{time_appconnect}\n"
            "starttransfer:%{time_starttransfer}\n"
            "total:%{time_total}\n"
        )

        try:
            result = subprocess.run(
                [
                    "curl", "-w", timing_format,
                    "-o", "/dev/null", "-s", "--max-time", "10",
                    "http://localhost:9090/",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )

            self.assertEqual(
                result.returncode, 0, f"curl timing command failed: {result.stderr}"
            )

            fields = {}
            for line in result.stdout.strip().splitlines():
                name, _, value = line.partition(":")
                fields[name] = float(value)

            for field in ("namelookup", "connect", "appconnect",
                          "starttransfer", "total"):
                self.assertIn(field, fields, f"Missing timing field: {field}")
                self.assertGreaterEqual(
                    fields[field], 0, f"{field} should not be negative"
                )

            # Each phase includes the time of the phases before it, so the
            # values must never decrease.
            self.assertLessEqual(fields["namelookup"], fields["connect"])
            self.assertLessEqual(fields["connect"], fields["starttransfer"])
            self.assertLessEqual(fields["starttransfer"], fields["total"])

            logger.info(
                "✅ curl -w timing breakdown produces valid, ordered fields")

        except subprocess.TimeoutExpired:
            self.fail("curl timing command timed out")

    def test_23_curl_timing_breakdown_real_tls(self):
        """Test the same timing breakdown against a real HTTPS endpoint, to
        confirm the TLS handshake (appconnect) actually completes with a
        non-zero duration. This requires outbound internet access; it fails
        (not skips) if that's unavailable, since a broken TLS handshake here
        is a real problem for Exercise 5 Activity 6, not something to hide."""
        logger.info("Testing curl -w phase timing breakdown (real TLS)...")

        timing_format = (
            "namelookup:%{time_namelookup}\n"
            "connect:%{time_connect}\n"
            "appconnect:%{time_appconnect}\n"
            "starttransfer:%{time_starttransfer}\n"
            "total:%{time_total}\n"
        )

        try:
            result = subprocess.run(
                [
                    "curl", "-w", timing_format,
                    "-o", "/dev/null", "-s", "--max-time", "10",
                    "https://example.com",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            self.fail("curl to https://example.com timed out")

        self.assertEqual(
            result.returncode, 0,
            f"curl to https://example.com failed: {result.stderr}",
        )

        fields = {}
        for line in result.stdout.strip().splitlines():
            name, _, value = line.partition(":")
            fields[name] = float(value)

        self.assertGreater(
            fields["appconnect"], 0,
            "appconnect should be > 0 for a real TLS handshake",
        )
        self.assertLessEqual(fields["connect"], fields["appconnect"])
        self.assertLessEqual(fields["appconnect"], fields["starttransfer"])

        logger.info("✅ Real HTTPS request shows a non-zero TLS handshake time")

    def test_24_curl_verbose_tls_handshake(self):
        """Test the primary Exercise 5 Activity 6 tool: `curl -v` showing
        the individual TLS handshake messages and full request/response
        headers. Needs no extra tools or container permissions, so this is
        the recommended command over httptap."""
        logger.info("Testing curl -v TLS handshake visibility...")

        try:
            result = subprocess.run(
                ["curl", "-v", "--http1.1", "--max-time", "10",
                 "-o", "/dev/null", "https://example.com"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            self.fail("curl -v request timed out")

        self.assertEqual(
            result.returncode, 0,
            f"curl -v request failed: {result.stderr}",
        )

        # curl -v writes its diagnostic trace to stderr
        trace = result.stderr
        for marker in (
            "Client hello",
            "Server hello",
            "Certificate",
            "SSL connection using TLSv1",
            "GET / HTTP/1.1",
            "HTTP/1.1 200",
        ):
            self.assertIn(
                marker, trace,
                f"curl -v output missing expected marker: {marker!r}",
            )

        logger.info("✅ curl -v shows the full TLS handshake and headers")

    def test_27_netstat_listening_services(self):
        """Test `netstat -tuln` (Activities 1/2/3/5, quick reference)."""
        logger.info("Testing netstat -tuln...")

        try:
            result = subprocess.run(
                ["netstat", "-tuln"],
                capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            self.fail("netstat is not installed on PATH")
        except subprocess.TimeoutExpired:
            self.fail("netstat -tuln timed out")

        self.assertEqual(
            result.returncode, 0, f"netstat -tuln failed: {result.stderr}"
        )
        self.assertIn("LISTEN", result.stdout,
                      "netstat output missing LISTEN entries")

        logger.info("✅ netstat -tuln shows listening services")

    def test_28_ss_listening_services(self):
        """Test `ss -tuln` (quick reference)."""
        logger.info("Testing ss -tuln...")

        try:
            result = subprocess.run(
                ["ss", "-tuln"],
                capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            self.fail("ss is not installed on PATH")
        except subprocess.TimeoutExpired:
            self.fail("ss -tuln timed out")

        self.assertEqual(
            result.returncode, 0, f"ss -tuln failed: {result.stderr}"
        )
        self.assertIn(
            "Local Address", result.stdout,
            "ss output missing expected column header",
        )

        logger.info("✅ ss -tuln shows listening services")

    def test_29_lsof_network_connections(self):
        """Test `lsof -i` (quick reference)."""
        logger.info("Testing lsof -i...")

        try:
            result = subprocess.run(
                ["lsof", "-i"],
                capture_output=True, text=True, timeout=15,
            )
        except FileNotFoundError:
            self.fail("lsof is not installed on PATH")
        except subprocess.TimeoutExpired:
            self.fail("lsof -i timed out")

        self.assertEqual(
            result.returncode, 0, f"lsof -i failed: {result.stderr}"
        )
        self.assertIn(
            "COMMAND", result.stdout,
            "lsof output missing expected column header",
        )

        logger.info("✅ lsof -i shows network connections")

    def test_30_nslookup_external_domain(self):
        """Test `nslookup google.com` (Activity 4, quick reference)."""
        logger.info("Testing nslookup google.com...")

        try:
            result = subprocess.run(
                ["nslookup", "google.com"],
                capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            self.fail("nslookup is not installed on PATH")
        except subprocess.TimeoutExpired:
            self.fail("nslookup google.com timed out")

        self.assertEqual(
            result.returncode, 0, f"nslookup google.com failed: {result.stderr}"
        )
        self.assertIn("Address", result.stdout,
                      "nslookup output missing an Address")

        logger.info("✅ nslookup resolves an external domain")

    def test_31_dig_external_dns_server(self):
        """Test `dig @8.8.8.8 example.com` (quick reference — query a
        specific DNS server directly)."""
        logger.info("Testing dig @8.8.8.8 example.com...")

        try:
            result = subprocess.run(
                ["dig", "@8.8.8.8", "example.com"],
                capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            self.fail("dig is not installed on PATH")
        except subprocess.TimeoutExpired:
            self.fail("dig @8.8.8.8 example.com timed out")

        self.assertEqual(
            result.returncode, 0, f"dig @8.8.8.8 example.com failed: {result.stderr}"
        )
        self.assertIn("ANSWER SECTION", result.stdout,
                      "dig output missing ANSWER SECTION")

        logger.info("✅ dig queries a specific external DNS server")

    def test_32_ping_tool_available(self):
        """Test `ping -c 3 8.8.8.8` (Activity 3, quick reference).

        This environment's network policy blocks outbound ICMP entirely
        (confirmed: 100% packet loss to both 8.8.8.8 and 1.1.1.1, even
        though the `ping` binary has the correct cap_net_raw capability) —
        this is a permanent characteristic of the sandbox network, not a
        bug in the `ping` tool itself. So this test validates that `ping`
        is installed and produces its correct diagnostic output format
        (proving the tool itself works), rather than asserting real ICMP
        connectivity, which cannot succeed here regardless of any fix."""
        logger.info("Testing ping tool invocation...")

        try:
            result = subprocess.run(
                ["ping", "-c", "3", "-W", "3", "8.8.8.8"],
                capture_output=True, text=True, timeout=15,
            )
        except FileNotFoundError:
            self.fail("ping is not installed on PATH")
        except subprocess.TimeoutExpired:
            self.fail("ping -c 3 -W 3 8.8.8.8 timed out")

        self.assertIn(
            "PING 8.8.8.8", result.stdout,
            "ping did not produce its expected diagnostic header",
        )
        self.assertIn(
            "packets transmitted", result.stdout,
            "ping did not produce its expected summary line",
        )

        logger.info("✅ ping is installed and produces correct diagnostic output "
                    "(ICMP to the internet is blocked by this sandbox's network "
                    "policy — that's expected here, not a bug)")

    def test_33_traceroute_tool_available(self):
        """Test `traceroute <host>` (quick reference)."""
        logger.info("Testing traceroute...")

        try:
            result = subprocess.run(
                ["traceroute", "-m", "5", "8.8.8.8"],
                capture_output=True, text=True, timeout=15,
            )
        except FileNotFoundError:
            self.fail("traceroute is not installed on PATH")
        except subprocess.TimeoutExpired:
            self.fail("traceroute 8.8.8.8 timed out")

        self.assertEqual(
            result.returncode, 0, f"traceroute failed: {result.stderr}"
        )
        self.assertIn(
            "traceroute to 8.8.8.8", result.stdout,
            "traceroute did not produce its expected header",
        )

        logger.info("✅ traceroute is installed and runs correctly")

    def test_34_curl_post_local_sample_app(self):
        """Test `curl -X POST http://localhost:9090/login -d "..."` (Activity 3
        traffic generation). Uses the sandbox's own vulnerable Flask app
        instead of the third-party httpbin.org service, which was flaky/
        unreliable from this environment — matches this sandbox's intent of
        self-contained, reproducible exercises with no external dependency.
        Invalid credentials are expected to return 401, deterministically."""
        logger.info("Testing curl -X POST http://localhost:9090/login...")

        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "-X", "POST", "--max-time", "8",
                 "-d", "username=test&password=test",
                 "http://localhost:9090/login"],
                capture_output=True, text=True, timeout=12,
            )
        except subprocess.TimeoutExpired:
            self.fail("curl -X POST http://localhost:9090/login timed out")

        self.assertEqual(
            result.returncode, 0,
            f"curl POST to localhost:9090/login failed: {result.stderr}",
        )
        self.assertEqual(
            result.stdout.strip(), "401",
            f"Expected HTTP 401 (invalid credentials) from the sandbox's "
            f"vulnerable Flask app, got {result.stdout!r}",
        )

        logger.info("✅ curl generates POST traffic against the sandbox's own "
                    "sample app")

    def test_35_curl_local_sample_app(self):
        """Test `curl http://localhost:5000` (quick reference — generate
        web traffic against the sandbox's own PWA sample app)."""
        logger.info("Testing curl http://localhost:5000...")

        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "8", "http://localhost:5000"],
                capture_output=True, text=True, timeout=12,
            )
        except subprocess.TimeoutExpired:
            self.fail("curl http://localhost:5000 timed out")

        self.assertEqual(
            result.returncode, 0,
            f"curl to localhost:5000 failed: {result.stderr}",
        )
        self.assertEqual(
            result.stdout.strip(), "200",
            f"Expected HTTP 200 from the sandbox's PWA app, got {result.stdout!r}",
        )

        logger.info("✅ curl reaches the sandbox's own PWA sample app")

    def test_36_nmap_available(self):
        """Test `nmap --version` (instructor guide pre-class checklist,
        student worksheet). nmap is referenced across the network module's
        docs but had no dedicated test until now."""
        logger.info("Testing nmap --version...")

        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            self.fail("nmap is not installed on PATH")
        except subprocess.TimeoutExpired:
            self.fail("nmap --version timed out")

        self.assertEqual(
            result.returncode, 0, f"nmap --version failed: {result.stderr}"
        )
        self.assertIn(
            "Nmap version", result.stdout,
            f"nmap --version output missing expected banner: {result.stdout!r}",
        )

        logger.info("✅ nmap is installed and reports its version")


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
