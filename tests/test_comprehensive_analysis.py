#!/usr/bin/env python3
"""
Comprehensive Analysis Command Validation Tests

This test suite runs comprehensive analysis commands against all 4 applications
(ports 3000, 5000, 8000, 9090) and validates the output files are created with
appropriate sizes. Files are deleted on success, kept on failure for investigation.
"""

import unittest
import subprocess
import json
import os
import time
import requests
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComprehensiveAnalysisTest(unittest.TestCase):
    """Test suite to validate comprehensive analysis commands across all applications."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment once for all tests."""
        cls.project_root = Path(__file__).parent.parent
        os.chdir(cls.project_root)
        cls.timeout = 300  # 5 minutes for comprehensive tests
        cls.reports_dir = cls.project_root / "reports"
        cls.reports_dir.mkdir(exist_ok=True)

        # Application URLs
        cls.apps = {
            'nodejs': {'url': 'http://localhost:3000', 'name': 'vulnerable-nodejs'},
            'pwa': {'url': 'http://localhost:5000', 'name': 'unsecure-pwa'},
            'uploads': {'url': 'http://localhost:8000', 'name': 'student-uploads'},
            'flask': {'url': 'http://localhost:9090', 'name': 'vulnerable-flask'}
        }

        # Wait for applications to be available
        cls._wait_for_applications()

    @classmethod
    def _wait_for_applications(cls):
        """Wait for test applications to be available."""
        logger.info("Waiting for test applications to be available...")

        for app_name, app_info in cls.apps.items():
            url = app_info['url']
            start_time = time.time()
            while time.time() - start_time < 60:  # 1 minute timeout
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code < 500:  # Accept any response except server errors
                        logger.info(
                            f"{app_name} application is available at {url}")
                        break
                except (requests.RequestException, ConnectionError):
                    pass
                time.sleep(2)
            else:
                logger.warning(
                    f"{app_name} application at {url} may not be available")

    def _cleanup_files(self, files, test_passed, file_results=None):
        """Clean up test files based on test result."""
        if test_passed:
            for file_path in files:
                # Get base name without extension to clean up related files
                base_name = Path(file_path).stem
                file_extensions = ['.pdf', '.json', '.md', '.txt']

                # If we have file results with actual paths, use those
                if file_results and file_path in file_results and file_results[file_path].get('exists') and 'actual_path' in file_results[file_path]:
                    actual_path = file_results[file_path]['actual_path']
                    if os.path.exists(actual_path):
                        os.remove(actual_path)
                        logger.info(f"Cleaned up: {actual_path}")

                    # Also clean up related files (JSON, MD) in the same directory
                    actual_dir = os.path.dirname(actual_path)
                    for ext in file_extensions:
                        related_file = os.path.join(
                            actual_dir, base_name + ext)
                        if os.path.exists(related_file) and related_file != actual_path:
                            os.remove(related_file)
                            logger.info(
                                f"Cleaned up related file: {related_file}")
                else:
                    # Fallback to checking multiple locations for files to clean up
                    paths_to_check = [
                        file_path,
                        os.path.join(self.project_root, file_path),
                        os.path.join(self.project_root, "reports", file_path)
                    ]

                    for path in paths_to_check:
                        if os.path.exists(path):
                            os.remove(path)
                            logger.info(f"Cleaned up: {path}")

                            # Also clean up related files in the same directory
                            path_dir = os.path.dirname(path)
                            for ext in file_extensions:
                                related_file = os.path.join(
                                    path_dir, base_name + ext)
                                if os.path.exists(related_file) and related_file != path:
                                    os.remove(related_file)
                                    logger.info(
                                        f"Cleaned up related file: {related_file}")
                            break  # Only clean from the first location found
        else:
            logger.info(
                f"Test failed - keeping files for investigation: {files}")

    def _validate_file_sizes(self, files):
        """Validate that output files exist and have appropriate sizes."""
        results = {}
        for file_path in files:
            # Check both current directory and reports directory
            paths_to_check = [
                file_path,
                os.path.join(self.project_root, file_path),
                os.path.join(self.project_root, "reports", file_path)
            ]

            found_file = None
            for path in paths_to_check:
                if os.path.exists(path):
                    found_file = path
                    break

            if not found_file:
                results[file_path] = {'exists': False, 'size': 0}
                continue

            size = os.path.getsize(found_file)
            ext = Path(file_path).suffix.lower()

            # Define minimum expected sizes based on file type
            min_sizes = {
                '.json': 100,    # JSON files should have at least 100 bytes
                '.md': 500,      # Markdown reports should be substantial
                '.pdf': 1000     # PDF files should be at least 1KB
            }

            min_size = min_sizes.get(ext, 50)
            results[file_path] = {
                'exists': True,
                'size': size,
                'valid_size': size >= min_size,
                'min_expected': min_size,
                'actual_path': found_file
            }

        return results

    def test_01_sast_analysis_unsecure_pwa(self):
        """Test SAST analysis on unsecure-pwa sample."""
        logger.info("Testing SAST analysis on unsecure-pwa...")

        output_file = "detailed_sast_unsecure_pwa.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            # Run SAST analysis
            result = subprocess.run([
                "python", "src/analyser/analyse_cli.py",
                "samples/unsecure-pwa",
                "--tools", "all",
                "--educational",
                "--output", output_file,
                "--format", "pdf",
                "--verbose"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            # Validate command execution
            self.assertEqual(result.returncode, 0,
                             f"SAST analysis failed: {result.stderr}")

            # Validate output files
            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes "
                                f"(expected at least {result_info['min_expected']} bytes)")

            test_passed = True
            logger.info(f"SAST analysis successful - created {output_file}")

        except Exception as e:
            self.fail(f"SAST analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_02_penetration_analysis_port_3000(self):
        """Test penetration analysis on port 3000 (vulnerable-nodejs)."""
        logger.info("Testing penetration analysis on port 3000...")

        output_file = "comprehensive_security_report_port3000.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/penetration_analyser.py",
                "http://localhost:3000",
                "--deep",
                "--exploit",
                "--output", output_file
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Penetration analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Penetration analysis on port 3000 successful")

        except Exception as e:
            self.fail(f"Penetration analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_03_penetration_analysis_port_5000(self):
        """Test penetration analysis on port 5000 (unsecure-pwa)."""
        logger.info("Testing penetration analysis on port 5000...")

        output_file = "comprehensive_security_report_port5000.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/penetration_analyser.py",
                "http://localhost:5000",
                "--deep",
                "--exploit",
                "--output", output_file
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Penetration analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Penetration analysis on port 5000 successful")

        except Exception as e:
            self.fail(f"Penetration analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_04_penetration_analysis_port_8000(self):
        """Test penetration analysis on port 8000 (student-uploads)."""
        logger.info("Testing penetration analysis on port 8000...")

        output_file = "comprehensive_security_report_port8000.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/penetration_analyser.py",
                "http://localhost:8000",
                "--deep",
                "--exploit",
                "--output", output_file
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Penetration analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Penetration analysis on port 8000 successful")

        except Exception as e:
            self.fail(f"Penetration analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_05_penetration_analysis_port_9090(self):
        """Test penetration analysis on port 9090 (vulnerable-flask)."""
        logger.info("Testing penetration analysis on port 9090...")

        output_file = "comprehensive_security_report_port9090.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/penetration_analyser.py",
                "http://localhost:9090",
                "--deep",
                "--exploit",
                "--output", output_file
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Penetration analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Penetration analysis on port 9090 successful")

        except Exception as e:
            self.fail(f"Penetration analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_06_dast_analysis_port_3000(self):
        """Test DAST analysis on port 3000 (vulnerable-nodejs)."""
        logger.info("Testing DAST analysis on port 3000...")

        output_file = "detailed_dast_nodejs.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/dast_cli.py",
                "http://localhost:3000",
                "--deep-scan",
                "--educational",
                "--output", output_file,
                "--format", "pdf",
                "--verbose"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"DAST analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"DAST analysis on port 3000 successful")

        except Exception as e:
            self.fail(f"DAST analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_07_dast_analysis_port_5000(self):
        """Test DAST analysis on port 5000 (unsecure-pwa)."""
        logger.info("Testing DAST analysis on port 5000...")

        output_file = "detailed_dast_unsecure_pwa.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/dast_cli.py",
                "http://localhost:5000",
                "--deep-scan",
                "--educational",
                "--output", output_file,
                "--format", "pdf",
                "--verbose"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"DAST analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"DAST analysis on port 5000 successful")

        except Exception as e:
            self.fail(f"DAST analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_08_dast_analysis_port_8000(self):
        """Test DAST analysis on port 8000 (student-uploads)."""
        logger.info("Testing DAST analysis on port 8000...")

        output_file = "detailed_dast_uploads.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/dast_cli.py",
                "http://localhost:8000",
                "--deep-scan",
                "--educational",
                "--output", output_file,
                "--format", "pdf",
                "--verbose"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"DAST analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"DAST analysis on port 8000 successful")

        except Exception as e:
            self.fail(f"DAST analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_09_dast_analysis_port_9090(self):
        """Test DAST analysis on port 9090 (vulnerable-flask)."""
        logger.info("Testing DAST analysis on port 9090...")

        output_file = "detailed_dast_flask.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/dast_cli.py",
                "http://localhost:9090",
                "--deep-scan",
                "--educational",
                "--output", output_file,
                "--format", "pdf",
                "--verbose"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"DAST analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"DAST analysis on port 9090 successful")

        except Exception as e:
            self.fail(f"DAST analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_10_detailed_pentest_port_3000(self):
        """Test detailed penetration testing on port 3000 (vulnerable-nodejs)."""
        logger.info("Testing detailed penetration testing on port 3000...")

        output_file = "detailed_pentest_nodejs.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/penetration_analyser.py",
                "http://localhost:3000",
                "--deep",
                "--output", output_file
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Detailed pentest failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Detailed pentest on port 3000 successful")

        except Exception as e:
            self.fail(f"Detailed pentest test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_11_detailed_pentest_port_5000(self):
        """Test detailed penetration testing on port 5000 (unsecure-pwa)."""
        logger.info("Testing detailed penetration testing on port 5000...")

        output_file = "detailed_pentest_unsecure_pwa.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/penetration_analyser.py",
                "http://localhost:5000",
                "--deep",
                "--output", output_file
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Detailed pentest failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Detailed pentest on port 5000 successful")

        except Exception as e:
            self.fail(f"Detailed pentest test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_12_detailed_pentest_port_8000(self):
        """Test detailed penetration testing on port 8000 (student-uploads)."""
        logger.info("Testing detailed penetration testing on port 8000...")

        output_file = "detailed_pentest_uploads.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/penetration_analyser.py",
                "http://localhost:8000",
                "--deep",
                "--output", output_file
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Detailed pentest failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Detailed pentest on port 8000 successful")

        except Exception as e:
            self.fail(f"Detailed pentest test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_13_detailed_pentest_port_9090(self):
        """Test detailed penetration testing on port 9090 (vulnerable-flask)."""
        logger.info("Testing detailed penetration testing on port 9090...")

        output_file = "detailed_pentest_flask.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            result = subprocess.run([
                "python", "src/analyser/penetration_analyser.py",
                "http://localhost:9090",
                "--deep",
                "--output", output_file
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Detailed pentest failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Detailed pentest on port 9090 successful")

        except Exception as e:
            self.fail(f"Detailed pentest test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_14_network_analysis_port_3000(self):
        """Test network analysis monitoring on port 3000 (vulnerable-nodejs)."""
        logger.info("Testing network analysis on port 3000...")

        output_file = "detailed_network_nodejs.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            # Shorter duration for testing - 30 seconds instead of 300
            result = subprocess.run([
                "python", "src/analyser/network_cli.py",
                "--monitor-connections",
                "--educational",
                "--duration", "30",
                "--output", output_file,
                "--format", "pdf",
                "--verbose"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Network analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Network analysis successful")

        except Exception as e:
            self.fail(f"Network analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_15_network_analysis_port_5000(self):
        """Test network analysis monitoring on port 5000 (unsecure-pwa)."""
        logger.info("Testing network analysis on port 5000...")

        output_file = "detailed_network_unsecure_pwa.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            # Shorter duration for testing - 30 seconds instead of 300
            result = subprocess.run([
                "python", "src/analyser/network_cli.py",
                "--monitor-connections",
                "--educational",
                "--duration", "30",
                "--output", output_file,
                "--format", "pdf",
                "--verbose"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Network analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Network analysis successful")

        except Exception as e:
            self.fail(f"Network analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_16_network_analysis_port_8000(self):
        """Test network analysis monitoring on port 8000 (student-uploads)."""
        logger.info("Testing network analysis on port 8000...")

        output_file = "detailed_network_uploads.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            # Shorter duration for testing - 30 seconds instead of 300
            result = subprocess.run([
                "python", "src/analyser/network_cli.py",
                "--monitor-connections",
                "--educational",
                "--duration", "30",
                "--output", output_file,
                "--format", "pdf",
                "--verbose"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Network analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Network analysis successful")

        except Exception as e:
            self.fail(f"Network analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)

    def test_17_network_analysis_port_9090(self):
        """Test network analysis monitoring on port 9090 (vulnerable-flask)."""
        logger.info("Testing network analysis on port 9090...")

        output_file = "detailed_network_flask.pdf"
        files_to_check = [output_file]
        test_passed = False

        try:
            # Shorter duration for testing - 30 seconds instead of 300
            result = subprocess.run([
                "python", "src/analyser/network_cli.py",
                "--monitor-connections",
                "--educational",
                "--duration", "30",
                "--output", output_file,
                "--format", "pdf",
                "--verbose"
            ], cwd=self.project_root, capture_output=True, text=True, timeout=self.timeout)

            self.assertEqual(result.returncode, 0,
                             f"Network analysis failed: {result.stderr}")

            file_results = self._validate_file_sizes(files_to_check)

            for file_path, result_info in file_results.items():
                self.assertTrue(result_info['exists'],
                                f"Output file {file_path} was not created")
                self.assertTrue(result_info['valid_size'],
                                f"Output file {file_path} is too small: {result_info['size']} bytes")

            test_passed = True
            logger.info(f"Network analysis successful")

        except Exception as e:
            self.fail(f"Network analysis test failed: {str(e)}")
        finally:
            self._cleanup_files(files_to_check, test_passed,
                                file_results if 'file_results' in locals() else None)


if __name__ == '__main__':
    unittest.main(verbosity=2)
