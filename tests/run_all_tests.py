#!/usr/bin/env python3
"""
Comprehensive System Test Runner

This is the master test runner that executes all unit tests in the correct
order and provides comprehensive validation of the entire Secure Architecture
Sandbox Testing Environment system.
"""

import unittest
import sys
import time
import logging
from pathlib import Path
from io import StringIO

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_test_suite():
    """Run the complete test suite with proper ordering and reporting."""

    # Change to project root
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root / "tests"))

    print("=" * 80)
    print("SECURE ARCHITECTURE SANDBOX TESTING ENVIRONMENT - "
          "COMPREHENSIVE SYSTEM TEST SUITE")
    print("=" * 80)
    print(f"Project Root: {project_root}")
    print(f"Test Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Test modules in logical order
    test_modules = [
        {
            "name": "Docker Environment Validation",
            "module": "test_docker_environment",
            "description": "Validates Docker containers and services",
        },
        {
            "name": "SAST Command Validation",
            "module": "test_sast_commands",
            "description": "Tests Static Application Security Testing CLI",
        },
        {
            "name": "DAST Command Validation",
            "module": "test_dast_commands",
            "description": "Tests Dynamic Application Security Testing CLI",
        },
        {
            "name": "Network Analysis Validation",
            "module": "test_network_commands",
            "description": "Tests Network Traffic Analysis CLI commands",
        },
        {
            "name": "Sandbox Command Validation",
            "module": "test_sandbox_commands",
            "description": "Tests Sandbox Security Analysis commands",
        },
        {
            "name": "Penetration Testing Validation",
            "module": "test_penetration_testing_commands",
            "description": "Tests integrated penetration testing workflows",
        },
        {
            "name": "Penetration Analyzer Unit Tests",
            "module": "test_penetration_analyzer_unit",
            "description": "Unit tests for penetration analyzer modules and components",
        },
    ]

    overall_results = {
        "total_modules": len(test_modules),
        "passed_modules": 0,
        "failed_modules": 0,
        "total_tests": 0,
        "passed_tests": 0,
        "failed_tests": 0,
        "errors": 0,
        "module_results": [],
    }

    # Run each test module
    for i, test_info in enumerate(test_modules, 1):
        print(f"\n[{i}/{len(test_modules)}] Running {test_info['name']}...")
        print(f"Description: {test_info['description']}")
        print("-" * 60)

        # Capture test output
        test_output = StringIO()

        # Create test suite for this module
        try:
            # Import the test module
            test_module = __import__(test_info["module"])

            # Create test suite
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromModule(test_module)

            # Run tests with custom result handler
            runner = unittest.TextTestRunner(
                stream=test_output, verbosity=2, buffer=True
            )

            result = runner.run(suite)

            # Process results
            module_result = {
                "name": test_info["name"],
                "module": test_info["module"],
                "tests_run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "success": result.wasSuccessful(),
                "output": test_output.getvalue(),
            }

            overall_results["module_results"].append(module_result)
            overall_results["total_tests"] += result.testsRun
            overall_results["failed_tests"] += len(result.failures)
            overall_results["errors"] += len(result.errors)

            if result.wasSuccessful():
                overall_results["passed_modules"] += 1
                overall_results["passed_tests"] += result.testsRun
                print(
                    f"✅ {test_info['name']}: PASSED " f"({result.testsRun} tests)")
            else:
                overall_results["failed_modules"] += 1
                print(
                    f"❌ {test_info['name']}: FAILED "
                    f"({len(result.failures)} failures, "
                    f"{len(result.errors)} errors)"
                )

                # Show first few failures for quick diagnosis
                if result.failures:
                    print("   First failure:")
                    print(f"   {result.failures[0][0]}")
                    print(f"   {result.failures[0][1][:200]}...")

                if result.errors:
                    print("   First error:")
                    print(f"   {result.errors[0][0]}")
                    print(f"   {result.errors[0][1][:200]}...")

        except ImportError as e:
            print(f"❌ {test_info['name']}: IMPORT ERROR")
            print(f"   Could not import {test_info['module']}: {e}")
            overall_results["failed_modules"] += 1
            overall_results["module_results"].append(
                {
                    "name": test_info["name"],
                    "module": test_info["module"],
                    "tests_run": 0,
                    "failures": 0,
                    "errors": 1,
                    "success": False,
                    "output": f"Import error: {e}",
                }
            )

        except Exception as e:
            print(f"❌ {test_info['name']}: UNEXPECTED ERROR")
            print(f"   {e}")
            overall_results["failed_modules"] += 1
            overall_results["errors"] += 1
            overall_results["module_results"].append(
                {
                    "name": test_info["name"],
                    "module": test_info["module"],
                    "tests_run": 0,
                    "failures": 0,
                    "errors": 1,
                    "success": False,
                    "output": f"Unexpected error: {e}",
                }
            )

    # Print comprehensive summary
    print("\n" + "=" * 80)
    print("COMPREHENSIVE TEST RESULTS SUMMARY")
    print("=" * 80)

    print(
        f"Test Modules: {overall_results['passed_modules']}/"
        f"{overall_results['total_modules']} passed"
    )
    print(
        f"Individual Tests: {overall_results['passed_tests']}/"
        f"{overall_results['total_tests']} passed"
    )
    print(f"Failures: {overall_results['failed_tests']}")
    print(f"Errors: {overall_results['errors']}")

    print("\nModule Results:")
    print("-" * 40)
    for result in overall_results["module_results"]:
        status = "✅ PASS" if result["success"] else "❌ FAIL"
        print(f"{status} {result['name']}: {result['tests_run']} tests")
        if not result["success"]:
            print(
                f"     Failures: {result['failures']}, " f"Errors: {result['errors']}"
            )

    # Overall system status
    print("\n" + "=" * 80)
    if overall_results["passed_modules"] == overall_results["total_modules"]:
        print("🎉 SYSTEM STATUS: ALL TESTS PASSED!")
        print("✅ Secure Architecture Sandbox Testing Environment is fully operational and validated.")
        print("✅ All command workflows are working correctly.")
        print("✅ All security analysis tools are functional.")
        exit_code = 0
    else:
        print("⚠️  SYSTEM STATUS: SOME TESTS FAILED")
        print(
            f"❌ {overall_results['failed_modules']} out of "
            f"{overall_results['total_modules']} modules failed."
        )
        print("🔧 Review failed tests and fix issues before deployment.")
        exit_code = 1

    print("=" * 80)

    # Detailed failure analysis if needed
    if overall_results["failed_modules"] > 0:
        print("\nDETAILED FAILURE ANALYSIS:")
        print("-" * 40)
        for result in overall_results["module_results"]:
            if not result["success"]:
                print(f"\n❌ {result['name']} ({result['module']}):")
                print(f"   Tests run: {result['tests_run']}")
                print(f"   Failures: {result['failures']}")
                print(f"   Errors: {result['errors']}")
                if len(result["output"]) > 500:
                    print("   Output (truncated):")
                    print(f"   {result['output'][:500]}...")
                else:
                    print("   Output:")
                    print(f"   {result['output']}")

    # Return overall results for programmatic use
    return overall_results, exit_code


def main():
    """Main entry point for the system test runner."""
    try:
        print(
            "Starting Secure Architecture Sandbox Testing Environment System Test Suite...")
        results, exit_code = run_test_suite()

        # Save results to file for future reference
        results_dir = Path(__file__).parent.parent / "reports"
        results_dir.mkdir(exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        results_file = results_dir / f"system_test_results_{timestamp}.txt"

        with open(results_file, "w") as f:
            f.write(
                "Secure Architecture Sandbox Testing Environment - System Test Results\n")
            f.write("=" * 50 + "\n")
            f.write(f"Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Modules: {results['total_modules']}\n")
            f.write(f"Passed Modules: {results['passed_modules']}\n")
            f.write(f"Failed Modules: {results['failed_modules']}\n")
            f.write(f"Total Tests: {results['total_tests']}\n")
            f.write(f"Passed Tests: {results['passed_tests']}\n")
            f.write(f"Failed Tests: {results['failed_tests']}\n")
            f.write(f"Errors: {results['errors']}\n")
            f.write("\nModule Details:\n")
            f.write("-" * 30 + "\n")

            for result in results["module_results"]:
                status = "PASS" if result["success"] else "FAIL"
                f.write(f"{result['name']}: {status}\n")
                f.write(
                    f"  Tests: {result['tests_run']}, "
                    f"Failures: {result['failures']}, "
                    f"Errors: {result['errors']}\n"
                )

        print(f"\nDetailed results saved to: {results_file}")

        # Exit with appropriate code
        sys.exit(exit_code)

    except KeyboardInterrupt:
        print("\n\n⚠️ Test suite interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n❌ System test runner failed: {e}")
        logger.exception("System test runner exception")
        sys.exit(2)


if __name__ == "__main__":
    main()
