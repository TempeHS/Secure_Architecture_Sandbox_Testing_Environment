#!/usr/bin/env python3
"""
Sandbox Security Analysis Command Validation Tests

This test suite validates sandbox commands and tools from the quick
reference guide to ensure they work correctly within the Docker container.
"""

import unittest
import docker
import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SandboxCommandValidationTest(unittest.TestCase):
    """Test suite to validate sandbox security analysis commands."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.project_root = Path(__file__).parent.parent
        os.chdir(cls.project_root)
        cls.timeout = 60  # seconds
        cls.docker_client = docker.from_env()
        cls.container_name = "cybersec_sandbox"

        # Get the container
        try:
            cls.container = cls.docker_client.containers.get(
                cls.container_name)
            if cls.container.status != "running":
                cls.container.start()
        except docker.errors.NotFound:
            logger.warning(f"Container {cls.container_name} not found")
            cls.container = None

    def _exec_in_container(self, command, timeout=None):
        """Execute command in the sandbox container."""
        if self.container is None:
            self.skipTest("Sandbox container not available")

        try:
            # Use sh -c to properly handle shell commands including redirections
            shell_command = ["sh", "-c", command]
            result = self.container.exec_run(shell_command)
            return result.exit_code, result.output.decode("utf-8", errors="ignore")
        except Exception as e:
            logger.error(f"Container exec failed: {e}")
            return 1, str(e)

    def test_01_container_accessibility(self):
        """Test that the sandbox container is accessible."""
        logger.info("Testing sandbox container accessibility...")

        if self.container is None:
            self.skipTest("Sandbox container not found")

        self.assertEqual(
            self.container.status, "running", "Sandbox container is not running"
        )

        # Test basic command execution
        exit_code, output = self._exec_in_container("echo test")
        self.assertEqual(exit_code, 0, "Cannot execute commands in container")
        self.assertIn("test", output, "Command execution failed")

        logger.info("✅ Sandbox container is accessible")

    def test_02_essential_tools_available(self):
        """Test that essential security analysis tools are available."""
        logger.info("Testing essential tools availability...")

        tools = ["strace", "netstat", "top", "lsof", "ps", "grep", "find"]

        for tool in tools:
            exit_code, output = self._exec_in_container(f"which {tool}")
            self.assertEqual(
                exit_code, 0, f"Tool {tool} is not available in container")

        logger.info("✅ Essential tools are available")

    def test_03_workspace_directory_access(self):
        """Test access to the analysis workspace."""
        logger.info("Testing workspace directory access...")

        exit_code, output = self._exec_in_container("pwd")
        self.assertEqual(exit_code, 0, "Cannot access workspace directory")
        self.assertIn("/workspace", output,
                      "Not in correct workspace directory")

        # Test write permissions in /tmp (which is writable)
        exit_code, output = self._exec_in_container(
            "touch /tmp/test_write_permission.txt")
        self.assertEqual(exit_code, 0, "Cannot write to tmp directory")

        # Clean up
        self._exec_in_container("rm -f test_write_permission.txt")

        logger.info("✅ Workspace directory is accessible")

    def test_04_system_call_tracing_basic(self):
        """Test basic system call tracing with strace."""
        logger.info("Testing basic system call tracing...")

        # Create a simple test script in /tmp
        cmd = ('printf "%s\\n%s\\n%s\\n" "#!/bin/bash" '
               '"echo Hello from test script" "ls /tmp" > /tmp/test_script.sh')
        exit_code, _ = self._exec_in_container(cmd)
        self.assertEqual(exit_code, 0, "Cannot create test script")

        exit_code, _ = self._exec_in_container("chmod +x /tmp/test_script.sh")
        self.assertEqual(exit_code, 0, "Cannot make script executable")

        # Run strace on the script
        exit_code, output = self._exec_in_container(
            "strace -o /tmp/trace.log /tmp/test_script.sh"
        )

        # Check if trace file was created
        exit_code_check, _ = self._exec_in_container("test -f /tmp/trace.log")
        self.assertEqual(exit_code_check, 0, "Trace log file not created")

        # Check trace content
        exit_code_content, trace_content = self._exec_in_container(
            "head -5 /tmp/trace.log")
        self.assertEqual(exit_code_content, 0, "Cannot read trace log")
        self.assertGreater(len(trace_content), 50, "Trace log seems too short")

        # Clean up
        self._exec_in_container("rm -f test_script.sh trace.log")

        logger.info("✅ System call tracing works")

    def test_05_strace_specific_syscalls(self):
        """Test tracing specific system calls."""
        logger.info("Testing specific system call tracing...")

        # Create a test script that opens a file in /tmp
        cmd = ("printf '%s\\n%s\\n' '#!/bin/bash' "
               "'cat /etc/hostname > /tmp/test_output' > /tmp/file_test.sh")
        exit_code, _ = self._exec_in_container(cmd)
        self.assertEqual(exit_code, 0, "Cannot create file test script")

        exit_code, _ = self._exec_in_container("chmod +x /tmp/file_test.sh")
        self.assertEqual(
            exit_code, 0, "Cannot make file test script executable")

        # Trace only openat system calls
        exit_code, output = self._exec_in_container(
            "strace -e trace=openat -o /tmp/openat_trace.log /tmp/file_test.sh"
        )

        # Check trace content for openat calls
        exit_code_check, trace_content = self._exec_in_container(
            "cat /tmp/openat_trace.log")
        self.assertEqual(exit_code_check, 0, "Cannot read openat trace log")
        self.assertIn("openat", trace_content,
                      "Trace log missing openat system calls")

        # Clean up
        self._exec_in_container(
            "rm -f file_test.sh openat_trace.log " "/tmp/test_output"
        )

        logger.info("✅ Specific system call tracing works")

    def test_06_network_monitoring_netstat(self):
        """Test network monitoring with netstat."""
        logger.info("Testing network monitoring with netstat...")

        # Test basic netstat functionality
        exit_code, output = self._exec_in_container("netstat -tupln")
        self.assertEqual(exit_code, 0, "netstat command failed")
        self.assertGreater(len(output), 50, "netstat output seems too short")

        # Test filtering for listening ports
        exit_code, output = self._exec_in_container(
            "netstat -tupln | grep LISTEN")
        self.assertEqual(exit_code, 0, "netstat LISTEN filter failed")

        logger.info("✅ Network monitoring with netstat works")

    def test_07_process_monitoring_top(self):
        """Test process monitoring with top."""
        logger.info("Testing process monitoring with top...")

        # Test single snapshot with top
        exit_code, output = self._exec_in_container("top -b -n 1")
        self.assertEqual(exit_code, 0, "top command failed")
        self.assertIn("PID", output, "top output missing PID column")
        self.assertIn("CPU", output, "top output missing CPU information")

        logger.info("✅ Process monitoring with top works")

    def test_08_file_system_monitoring_find(self):
        """Test file system monitoring with find."""
        logger.info("Testing file system monitoring...")

        # Create a test file to find
        exit_code, _ = self._exec_in_container(
            "touch /tmp/test_recent_file.txt")
        self.assertEqual(exit_code, 0, "Cannot create test file")

        # Find recently created files (within last hour)
        exit_code, output = self._exec_in_container(
            'find /tmp -name "test_recent_file.txt" -type f -mmin -60'
        )
        self.assertEqual(exit_code, 0, "find command failed")
        self.assertIn("test_recent_file.txt", output,
                      "find did not locate recent file")

        # Clean up
        self._exec_in_container("rm -f /tmp/test_recent_file.txt")

        logger.info("✅ File system monitoring works")

    def test_09_process_tree_pstree(self):
        """Test process tree visualization with pstree."""
        logger.info("Testing process tree visualization...")

        # Test pstree (if available)
        exit_code, output = self._exec_in_container("which pstree")
        if exit_code != 0:
            logger.info("ℹ️ pstree not available, using ps instead")
            exit_code, output = self._exec_in_container("ps aux")
            self.assertEqual(exit_code, 0, "ps command failed")
        else:
            exit_code, output = self._exec_in_container("pstree")
            self.assertEqual(exit_code, 0, "pstree command failed")

        self.assertGreaterEqual(
            len(output), 5, "Process output seems too short for minimal container")

        logger.info("✅ Process tree visualization works")

    def test_10_memory_monitoring(self):
        """Test memory monitoring with free command."""
        logger.info("Testing memory monitoring...")

        exit_code, output = self._exec_in_container("free -h")
        self.assertEqual(exit_code, 0, "free command failed")
        self.assertIn("Mem:", output, "free output missing memory info")
        self.assertIn("total", output, "free output missing total column")

        logger.info("✅ Memory monitoring works")

    def test_11_log_analysis_patterns(self):
        """Test log analysis with grep patterns."""
        logger.info("Testing log analysis patterns...")

        # Create a sample log file in /tmp using multiple echo commands
        self._exec_in_container(
            'echo "openat test entry" > /tmp/sample_trace.log')
        self._exec_in_container(
            'echo "connect network call" >> /tmp/sample_trace.log')
        self._exec_in_container(
            'echo "write data operation" >> /tmp/sample_trace.log')
        self._exec_in_container(
            'echo "socket creation" >> /tmp/sample_trace.log')

        # Test pattern matching for file operations
        exit_code, output = self._exec_in_container(
            'grep -E "(openat|read|write)" /tmp/sample_trace.log'
        )
        self.assertEqual(exit_code, 0, "grep pattern matching failed")
        self.assertIn("openat", output, "Pattern matching missing openat")

        # Test pattern matching for network operations
        exit_code, output = self._exec_in_container(
            'grep -E "(socket|connect|bind)" /tmp/sample_trace.log'
        )
        self.assertEqual(exit_code, 0, "Network pattern matching failed")
        self.assertIn("connect", output, "Pattern matching missing connect")

        # Clean up
        self._exec_in_container("rm -f /tmp/sample_trace.log")

        logger.info("✅ Log analysis patterns work")

    def test_12_file_access_monitoring(self):
        """Test file access monitoring for sensitive files."""
        logger.info("Testing file access monitoring...")

        # Create a trace that includes sensitive file access in /tmp
        # Clean up any previous files first
        self._exec_in_container("rm -f /tmp/sensitive_trace.log")

        self._exec_in_container(
            'echo passwd_access > /tmp/sensitive_trace.log')
        self._exec_in_container(
            'echo shadow_access >> /tmp/sensitive_trace.log')

        # Verify the file was created
        exit_code, content = self._exec_in_container(
            "cat /tmp/sensitive_trace.log")
        self.assertEqual(exit_code, 0, "Cannot read created trace file")
        exit_code, output = self._exec_in_container(
            'grep "passwd" /tmp/sensitive_trace.log'
        )
        self.assertEqual(exit_code, 0, "Sensitive file search failed")
        self.assertIn("passwd", output,
                      "Sensitive file access not detected")

        # Clean up
        self._exec_in_container("rm -f /tmp/sensitive_trace.log")

        logger.info("✅ File access monitoring works")

    def test_13_network_connection_analysis(self):
        """Test network connection analysis workflow."""
        logger.info("Testing network connection analysis...")

        # Take a baseline network snapshot
        exit_code, baseline = self._exec_in_container("netstat -tupln")
        self.assertEqual(exit_code, 0, "Baseline network capture failed")

        # Simulate some network activity by checking current connections
        exit_code, current = self._exec_in_container("netstat -tupln")
        self.assertEqual(exit_code, 0, "Current network capture failed")

        # Test filtering for external connections
        exit_code, external = self._exec_in_container(
            'netstat -tupln | grep -v "127.0.0.1\\|::1"'
        )
        # This might return 1 if no external connections, which is okay
        if exit_code == 0:
            logger.info("✅ External connections found and filtered")
        else:
            logger.info("ℹ️ No external connections found (acceptable)")

        logger.info("✅ Network connection analysis works")

    def test_14_sample_suspicious_script_execution(self):
        """Test execution of sample suspicious script with monitoring."""
        logger.info("Testing sample suspicious script execution...")

        # Check if suspicious script exists in samples
        exit_code, _ = self._exec_in_container(
            "test -f /workspace/samples/suspicious-scripts/suspicious_script.py"
        )

        if exit_code != 0:
            # Create a simple suspicious script for testing
            suspicious_script = """#!/usr/bin/env python3
import os
import time
print("Starting suspicious activity simulation...")
# Simulate file access
try:
    with open("/etc/hostname", "r") as f:
        hostname = f.read().strip()
    print(f"Read hostname: {hostname}")
except:
    print("Could not read hostname")
time.sleep(1)
print("Suspicious activity complete")"""

            exit_code, _ = self._exec_in_container(
                f"echo '{suspicious_script}' > test_suspicious.py"
            )
            self.assertEqual(exit_code, 0, "Cannot create suspicious script")

            script_path = "test_suspicious.py"
        else:
            script_path = "/workspace/samples/suspicious-scripts/suspicious_script.py"

        # Run the script with strace monitoring
        exit_code, output = self._exec_in_container(
            f"strace -o suspicious_trace.log python3 {script_path}", timeout=30
        )

        # Check if trace was created
        exit_code_check, _ = self._exec_in_container(
            "test -f suspicious_trace.log")
        self.assertEqual(exit_code_check, 0,
                         "Suspicious trace log not created")

        # Analyse the trace
        exit_code_analysis, trace_output = self._exec_in_container(
            "head -10 suspicious_trace.log"
        )
        self.assertEqual(exit_code_analysis, 0, "Cannot analyse trace")
        self.assertGreater(len(trace_output), 20,
                           "Suspicious trace seems too short")

        # Clean up
        self._exec_in_container(
            "rm -f test_suspicious.py " "suspicious_trace.log")

        logger.info("✅ Suspicious script execution monitoring works")

    def test_15_emergency_cleanup_commands(self):
        """Test emergency cleanup and reset commands."""
        logger.info("Testing emergency cleanup commands...")

        # Create some test processes/files to clean up
        exit_code, _ = self._exec_in_container("touch /tmp/cleanup_test.txt")
        self.assertEqual(exit_code, 0, "Cannot create cleanup test file")

        # Test file cleanup
        exit_code, _ = self._exec_in_container("rm -f /tmp/cleanup_test.txt")
        self.assertEqual(exit_code, 0, "File cleanup failed")

        # Verify cleanup
        exit_code, _ = self._exec_in_container("test -f /tmp/cleanup_test.txt")
        self.assertNotEqual(exit_code, 0, "File was not properly cleaned up")

        # Test process listing (for pkill testing)
        exit_code, output = self._exec_in_container("ps aux")
        self.assertEqual(exit_code, 0, "Process listing failed")
        self.assertIn("PID", output, "Process listing missing PID column")

        logger.info("✅ Emergency cleanup commands work")


if __name__ == "__main__":
    # Run with verbose output
    unittest.main(verbosity=2)
