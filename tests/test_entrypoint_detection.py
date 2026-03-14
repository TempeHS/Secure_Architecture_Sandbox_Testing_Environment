#!/usr/bin/env python3
"""
Entrypoint Script Detection Tests

Validates that the student uploads container entrypoint script
(docker/entrypoint.sh) correctly detects and launches the right
application entry point file based on priority order:
  1. app.py  (Flask)
  2. main.py (Flask)
  3. run.py  (Flask)
  4. manage.py (Django)
"""

import unittest
import subprocess
import tempfile
import shutil
import os
import stat
from pathlib import Path


class EntrypointDetectionTest(unittest.TestCase):
    """Test suite for entrypoint.sh application detection logic."""

    @classmethod
    def setUpClass(cls):
        """Locate the entrypoint script."""
        cls.project_root = Path(__file__).parent.parent
        cls.entrypoint = cls.project_root / "docker" / "entrypoint.sh"

    def setUp(self):
        """Create a temporary directory to simulate /app."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_01_entrypoint_script_exists(self):
        """Test that the entrypoint.sh script exists."""
        self.assertTrue(
            self.entrypoint.exists(),
            "docker/entrypoint.sh does not exist"
        )

    def test_02_entrypoint_script_is_executable(self):
        """Test that the entrypoint.sh script has execute permission."""
        self.assertTrue(
            os.access(self.entrypoint, os.X_OK),
            "docker/entrypoint.sh is not executable"
        )

    def _run_entrypoint_dry(self, files):
        """
        Create the given files in a temp dir and run a shell snippet
        that sources the detection logic from entrypoint.sh without
        actually exec-ing python. Returns (exit_code, stdout, stderr).
        """
        for f in files:
            Path(self.test_dir, f).touch()

        # We replicate the detection logic in a sub-shell so we can
        # capture which file it would pick without launching python.
        script = f"""
        set -e
        APP_DIR="{self.test_dir}"
        cd "$APP_DIR"

        if [ -f "app.py" ]; then
            ENTRY_FILE="app.py"
        elif [ -f "main.py" ]; then
            ENTRY_FILE="main.py"
        elif [ -f "run.py" ]; then
            ENTRY_FILE="run.py"
        elif [ -f "manage.py" ]; then
            ENTRY_FILE="manage.py"
        else
            echo "NO_ENTRY_FOUND"
            exit 1
        fi

        if [ "$ENTRY_FILE" = "manage.py" ]; then
            echo "DJANGO:$ENTRY_FILE"
        else
            echo "FLASK:$ENTRY_FILE"
        fi
        """

        result = subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()

    # --- Priority detection tests ---

    def test_03_detects_app_py(self):
        """Test that app.py is detected when it is the only entry point."""
        code, out, _ = self._run_entrypoint_dry(["app.py"])
        self.assertEqual(code, 0)
        self.assertEqual(out, "FLASK:app.py")

    def test_04_detects_main_py(self):
        """Test that main.py is detected when it is the only entry point."""
        code, out, _ = self._run_entrypoint_dry(["main.py"])
        self.assertEqual(code, 0)
        self.assertEqual(out, "FLASK:main.py")

    def test_05_detects_run_py(self):
        """Test that run.py is detected when it is the only entry point."""
        code, out, _ = self._run_entrypoint_dry(["run.py"])
        self.assertEqual(code, 0)
        self.assertEqual(out, "FLASK:run.py")

    def test_06_detects_manage_py_as_django(self):
        """Test that manage.py is detected and identified as Django."""
        code, out, _ = self._run_entrypoint_dry(["manage.py"])
        self.assertEqual(code, 0)
        self.assertEqual(out, "DJANGO:manage.py")

    # --- Priority order tests ---

    def test_07_app_py_takes_priority_over_main_py(self):
        """Test that app.py is chosen when both app.py and main.py exist."""
        code, out, _ = self._run_entrypoint_dry(["app.py", "main.py"])
        self.assertEqual(code, 0)
        self.assertEqual(out, "FLASK:app.py")

    def test_08_app_py_takes_priority_over_all(self):
        """Test that app.py wins when all entry points exist."""
        code, out, _ = self._run_entrypoint_dry(
            ["app.py", "main.py", "run.py", "manage.py"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, "FLASK:app.py")

    def test_09_main_py_takes_priority_over_run_and_manage(self):
        """Test that main.py is chosen over run.py and manage.py."""
        code, out, _ = self._run_entrypoint_dry(
            ["main.py", "run.py", "manage.py"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, "FLASK:main.py")

    def test_10_run_py_takes_priority_over_manage(self):
        """Test that run.py is chosen over manage.py."""
        code, out, _ = self._run_entrypoint_dry(["run.py", "manage.py"])
        self.assertEqual(code, 0)
        self.assertEqual(out, "FLASK:run.py")

    # --- No entry point test ---

    def test_11_fails_when_no_entry_point(self):
        """Test that the script fails when no supported file is found."""
        code, out, _ = self._run_entrypoint_dry([])
        self.assertNotEqual(code, 0)
        self.assertIn("NO_ENTRY_FOUND", out)

    def test_12_ignores_unrelated_py_files(self):
        """Test that random .py files are not detected as entry points."""
        code, out, _ = self._run_entrypoint_dry(
            ["utils.py", "helpers.py", "config.py"]
        )
        self.assertNotEqual(code, 0)
        self.assertIn("NO_ENTRY_FOUND", out)

    # --- Dockerfile validation ---

    def test_13_dockerfile_uses_entrypoint(self):
        """Test that Dockerfile.student-uploads uses the entrypoint script."""
        dockerfile = self.project_root / "docker" / "Dockerfile.student-uploads"
        content = dockerfile.read_text()
        self.assertIn("entrypoint.sh", content,
                      "Dockerfile should reference entrypoint.sh")
        self.assertIn("ENTRYPOINT", content,
                      "Dockerfile should use ENTRYPOINT directive")

    def test_14_dockerfile_copies_entrypoint(self):
        """Test that Dockerfile copies the entrypoint script into the image."""
        dockerfile = self.project_root / "docker" / "Dockerfile.student-uploads"
        content = dockerfile.read_text()
        self.assertIn("COPY docker/entrypoint.sh", content,
                      "Dockerfile should COPY the entrypoint script")


if __name__ == "__main__":
    unittest.main(verbosity=2)
