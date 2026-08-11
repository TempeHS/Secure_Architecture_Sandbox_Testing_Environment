#!/usr/bin/env python3
"""
Documentation Command Coverage & Test Quality Validation

Meta-tests that check the *test suite itself* is trustworthy for **every**
lesson's documentation (Exercises 1-7), not just one of them:

1. Every lesson has its full set of documentation files (exercise, quick
   reference, student worksheet, answer sheet, instructor guide).
2. Every core command/tool referenced in a lesson's docs has at least one
   dedicated test in that lesson's test file(s).
3. Every project script (``src/**/*.py``) a lesson's docs tell students to
   run actually exists, so a renamed or deleted tool can't leave students
   with a "No such file or directory" error mid-lesson.
4. Every long option used with a project CLI in a lesson's docs is a real
   option of that CLI, so the docs (and the tests that mirror them) cannot
   drift onto flags that argparse rejects.
5. Every test method in every lesson test file contains at least one real
   assertion (self.assert*/self.fail) — a test with zero assertions always
   "passes" regardless of what the command actually returned, which is
   worse than having no test at all.

Apart from invoking each CLI's ``--help`` to learn its real options, this
does not run the documented commands; it statically inspects the test
files' source code and the documentation files.
"""

import ast
import re
import subprocess
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent
TESTS_DIR = PROJECT_ROOT / "tests"

# Documentation folders every lesson must have a file in. Filenames are not
# consistently slugged across folders (e.g. "3.static-application-security-
# testing-exercise.md" vs "3.sast-quick-reference.md"), so lesson files are
# matched by their numeric prefix.
DOC_DIRS = {
    "exercise": PROJECT_ROOT / "docs/exercises",
    "quick reference": PROJECT_ROOT / "docs/quick-reference-guides",
    "student worksheet": PROJECT_ROOT / "docs/student-worksheets",
    "answer sheet": PROJECT_ROOT / "docs/student-worksheet-answers",
    "instructor guide": PROJECT_ROOT / "docs/instructor-guides",
}

# Per-lesson configuration.
#
# "test_files": the test module(s) that provide coverage for the lesson.
# "tools": core commands/tools that must have dedicated, real test coverage.
#   Deliberately curated rather than auto-extracted from the docs: shell
#   plumbing like `cd`/`echo`/`cat`/`ls` isn't a "tool" that needs its own
#   correctness test. Some tools are referenced in test methods via a class
#   attribute rather than their literal name (e.g. `self.dast_cli` instead
#   of the string "dast_cli.py"), so each entry lists all acceptable source
#   patterns.
LESSONS = {
    1: {
        "name": "Manual Code Review",
        "test_files": [],
        # Entirely manual: the docs only use file inspection (cat/ls/grep),
        # there is no project tool to regression-test.
        "tools": {},
    },
    2: {
        "name": "Sandbox Security Analysis",
        "test_files": [
            "test_sandbox_commands.py",
            "test_docker_environment.py",
        ],
        "tools": {
            "docker": ["docker"],
            "strace": ["strace"],
            "netstat": ["netstat"],
            "lsof": ["lsof"],
            "top": ["top"],
            "free": ["free"],
            "find": ["find"],
            "curl": ["curl", "requests"],
        },
    },
    3: {
        "name": "Static Application Security Testing",
        "test_files": ["test_sast_commands.py"],
        "tools": {
            "analyse_cli.py": ["analyse_cli.py", "self.sast_cli"],
            "bandit": ["bandit"],
            "safety": ["safety"],
            "semgrep": ["semgrep"],
        },
    },
    4: {
        "name": "Dynamic Application Security Testing",
        "test_files": ["test_dast_commands.py"],
        "tools": {
            "dast_cli.py": ["dast_cli.py", "self.dast_cli"],
            "nikto": ["nikto"],
            "gobuster": ["gobuster"],
        },
    },
    5: {
        "name": "Network Traffic Analysis",
        "test_files": ["test_network_commands.py"],
        "tools": {
            "network_cli.py": ["network_cli.py", "self.network_cli"],
            "dig": ["dig"],
            "curl": ["curl"],
            "netstat": ["netstat"],
            "ss": ["ss"],
            "lsof": ["lsof"],
            "nslookup": ["nslookup"],
            "ping": ["ping"],
            "traceroute": ["traceroute"],
            "nmap": ["nmap"],
        },
    },
    6: {
        "name": "Penetration Testing",
        "test_files": [
            "test_penetration_testing_commands.py",
            "test_network_commands.py",
        ],
        "tools": {
            "penetration_analyser.py": ["penetration_analyser.py"],
            "network_cli.py": ["network_cli.py", "self.network_cli"],
            "dast_cli.py": ["dast_cli.py", "self.dast_cli"],
            "analyse_cli.py": ["analyse_cli.py", "self.sast_cli"],
            "curl": ["curl"],
            "nmap": ["nmap"],
        },
    },
    7: {
        "name": "Organisational Vulnerability Assessment",
        "test_files": ["test_comprehensive_analysis.py"],
        # A synthesis lesson: students re-read the reports produced in
        # lessons 3-6 rather than running a new tool of their own.
        "tools": {},
    },
}

# Methods that indicate a real assertion was made in a test.
ASSERT_METHOD_PREFIXES = ("assert", "fail")

# Matches project scripts invoked in the docs, e.g.
# `python src/analyser/dast_cli.py`.
PROJECT_SCRIPT_PATTERN = re.compile(r"src/[\w/]+\.py")

# Captures a documented CLI invocation and the rest of its command line, e.g.
# `python src/analyser/dast_cli.py http://localhost:5000 --quick --educational`.
CLI_INVOCATION_PATTERN = re.compile(
    r"python3?\s+(src/[\w/]+\.py)([^\n|>]*)")

# Long options appearing after a documented CLI invocation.
LONG_OPTION_PATTERN = re.compile(r"--[a-z][a-z0-9-]+")

# Argparse renders a mutually exclusive group in its usage line as
# `(--a | --b TARGET | --c)`.
EXCLUSIVE_GROUP_PATTERN = re.compile(r"\(([^()]*\|[^()]*)\)", re.DOTALL)


def _lesson_doc_files(lesson: int):
    """Return {doc_type: [matching paths]} for a lesson's numeric prefix."""
    return {
        doc_type: sorted(doc_dir.glob(f"{lesson}.*.md"))
        for doc_type, doc_dir in DOC_DIRS.items()
    }


def _parse_test_methods(source: str):
    """Return {method_name: source_snippet} for every test_* method."""
    methods = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if not isinstance(item, ast.FunctionDef):
                continue
            if item.name.startswith("test_"):
                methods[item.name] = ast.get_source_segment(source, item)
    return methods


def _assertion_count(method_source: str) -> int:
    """Count assertion calls, including delegation to an _assert_* helper."""
    return len(re.findall(
        r"self\._?(?:" + "|".join(ASSERT_METHOD_PREFIXES) + r")\w*\s*\(",
        method_source,
    ))


class DocumentationCommandCoverageTest(unittest.TestCase):
    """Validates that documented commands are tested, and that those tests
    have genuine (non-trivial) assertions."""

    @classmethod
    def setUpClass(cls):
        cls._cli_help_cache = {}
        cls._cli_option_cache = {}
        cls._cli_group_cache = {}
        cls.doc_text = {}
        for lesson in LESSONS:
            found = _lesson_doc_files(lesson)
            cls.doc_text[lesson] = "\n".join(
                path.read_text()
                for paths in found.values()
                for path in paths
            )

        cls.test_methods = {}
        for name in sorted({
            test_file
            for config in LESSONS.values()
            for test_file in config["test_files"]
        }):
            path = TESTS_DIR / name
            if not path.exists():
                raise RuntimeError(f"Expected test file missing: {path}")
            cls.test_methods[name] = _parse_test_methods(path.read_text())

    def _methods_for_lesson(self, lesson: int):
        """All test method sources providing coverage for a lesson."""
        return [
            source
            for test_file in LESSONS[lesson]["test_files"]
            for source in self.test_methods[test_file].values()
        ]

    def test_lesson_config_covers_every_exercise(self):
        """LESSONS must describe every exercise in docs/exercises (adding a
        new lesson without extending this config would leave it silently
        unvalidated)."""
        documented = sorted(
            int(path.name.split(".", 1)[0])
            for path in DOC_DIRS["exercise"].glob("*.md")
            if path.name.split(".", 1)[0].isdigit()
        )
        self.assertEqual(
            documented, sorted(LESSONS),
            "docs/exercises does not match the LESSONS config — add the new "
            "lesson (test files + required tools) to LESSONS.",
        )

    def test_every_lesson_has_a_complete_doc_set(self):
        """Each lesson needs exactly one file of each documentation type."""
        for lesson, config in LESSONS.items():
            with self.subTest(lesson=lesson, name=config["name"]):
                found = _lesson_doc_files(lesson)
                broken = {
                    doc_type: [p.name for p in paths]
                    for doc_type, paths in found.items()
                    if len(paths) != 1
                }
                self.assertEqual(
                    broken, {},
                    f"Lesson {lesson} ({config['name']}) must have exactly "
                    f"one file per documentation type; got: {broken}",
                )

    def test_every_required_tool_has_documented_usage(self):
        """Sanity check: every tool we require coverage for is actually
        referenced somewhere in that lesson's docs (catches a stale tool
        list before it starts asserting nonsense)."""
        for lesson, config in LESSONS.items():
            with self.subTest(lesson=lesson, name=config["name"]):
                undocumented = [
                    tool for tool in config["tools"]
                    if tool not in self.doc_text[lesson]
                ]
                self.assertEqual(
                    undocumented, [],
                    f"Lesson {lesson} lists tools not found anywhere in its "
                    f"docs (LESSONS config is stale): {undocumented}",
                )

    def test_every_documented_project_script_exists(self):
        """Every src/**.py script a lesson's docs tell students to run must
        exist on disk — a renamed or removed tool otherwise leaves students
        with a "No such file or directory" error mid-lesson."""
        for lesson, config in LESSONS.items():
            with self.subTest(lesson=lesson, name=config["name"]):
                referenced = sorted(set(
                    PROJECT_SCRIPT_PATTERN.findall(self.doc_text[lesson])
                ))
                broken = [
                    path for path in referenced
                    if not (PROJECT_ROOT / path).exists()
                ]
                self.assertEqual(
                    broken, [],
                    f"Lesson {lesson} ({config['name']}) docs tell students "
                    f"to run scripts that do not exist: {broken}",
                )

    @classmethod
    def _cli_help(cls, script: str) -> str:
        """Cached --help output for a project CLI."""
        if script not in cls._cli_help_cache:
            result = subprocess.run(
                [sys.executable, script, "--help"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                timeout=180,
            )
            cls._cli_help_cache[script] = result.stdout
        return cls._cli_help_cache[script]

    @classmethod
    def _cli_supported_options(cls, script: str):
        """Long options a CLI actually accepts, read from its --help."""
        if script not in cls._cli_option_cache:
            cls._cli_option_cache[script] = set(
                LONG_OPTION_PATTERN.findall(cls._cli_help(script)))
        return cls._cli_option_cache[script]

    def test_documented_cli_options_exist(self):
        """Every long option the docs use with a project CLI must be a real
        option of that CLI. Without this, docs and tests can drift onto
        invented flags that argparse rejects the moment a student runs
        them."""
        for lesson, config in LESSONS.items():
            with self.subTest(lesson=lesson, name=config["name"]):
                unknown = {}
                invocations = CLI_INVOCATION_PATTERN.findall(
                    self.doc_text[lesson])
                for script, arg_tail in invocations:
                    if not (PROJECT_ROOT / script).exists():
                        continue  # reported by the script-existence test
                    supported = self._cli_supported_options(script)
                    if not supported:
                        continue  # CLI has no long options to check against
                    for option in LONG_OPTION_PATTERN.findall(arg_tail):
                        if option not in supported:
                            unknown.setdefault(
                                Path(script).name, set()).add(option)

                reported = {
                    name: sorted(options)
                    for name, options in sorted(unknown.items())
                }
                self.assertEqual(
                    reported, {},
                    f"Lesson {lesson} ({config['name']}) docs use options "
                    f"that these CLIs do not accept: {reported}",
                )

    @classmethod
    def _cli_exclusive_groups(cls, script: str):
        """Sets of options argparse refuses to accept together."""
        if script not in cls._cli_group_cache:
            help_text = cls._cli_help(script)
            usage = help_text.split("\n\n", 1)[0]
            cls._cli_group_cache[script] = [
                set(LONG_OPTION_PATTERN.findall(group))
                for group in EXCLUSIVE_GROUP_PATTERN.findall(usage)
            ]
        return cls._cli_group_cache[script]

    def test_documented_commands_avoid_exclusive_option_clashes(self):
        """Docs must not combine options argparse treats as mutually
        exclusive; such a command dies with a usage error before doing any
        work."""
        for lesson, config in LESSONS.items():
            with self.subTest(lesson=lesson, name=config["name"]):
                clashes = []
                invocations = CLI_INVOCATION_PATTERN.findall(
                    self.doc_text[lesson])
                for script, arg_tail in invocations:
                    if not (PROJECT_ROOT / script).exists():
                        continue
                    used = set(LONG_OPTION_PATTERN.findall(arg_tail))
                    for group in self._cli_exclusive_groups(script):
                        conflicting = sorted(used & group)
                        if len(conflicting) > 1:
                            clashes.append(
                                f"{Path(script).name}: {conflicting}")

                self.assertEqual(
                    sorted(set(clashes)), [],
                    f"Lesson {lesson} ({config['name']}) docs combine "
                    f"mutually exclusive options: {sorted(set(clashes))}",
                )

    def test_every_required_tool_has_a_dedicated_test(self):
        """Every core tool referenced in a lesson's docs must have at least
        one test in that lesson's test file(s) that actually invokes it (not
        just mentions it in a comment/docstring elsewhere)."""
        for lesson, config in LESSONS.items():
            with self.subTest(lesson=lesson, name=config["name"]):
                method_sources = self._methods_for_lesson(lesson)
                missing = [
                    tool
                    for tool, patterns in config["tools"].items()
                    if not any(
                        re.search(r"\b" + re.escape(pattern) + r"\b", source)
                        for source in method_sources
                        for pattern in patterns
                    )
                ]
                self.assertEqual(
                    missing, [],
                    f"Lesson {lesson} ({config['name']}) documents these "
                    f"commands with NO dedicated test in "
                    f"{config['test_files']}: {missing}. Add a test_* method "
                    f"that invokes each one with a real assertion.",
                )

    def test_every_test_method_has_a_real_assertion(self):
        """Every test_* method must contain at least one self.assert*/
        self.fail(...) call. A test with zero assertions always passes
        regardless of what the command under test actually returned, which
        silently hides broken commands behind a green checkmark."""
        for test_file, methods in self.test_methods.items():
            with self.subTest(test_file=test_file):
                zero_assertion_tests = sorted(
                    name for name, source in methods.items()
                    if _assertion_count(source) == 0
                )
                self.assertEqual(
                    zero_assertion_tests, [],
                    f"These {test_file} methods have ZERO assertions (they "
                    f"cannot ever fail, regardless of command output): "
                    f"{zero_assertion_tests}",
                )

    def test_no_test_method_only_logs_on_failure_path(self):
        """Flags the specific anti-pattern of checking `if returncode == 0`
        and only logging (not asserting/failing) in the else branch — a
        command can fail completely and the test still reports PASSED."""
        for test_file, methods in self.test_methods.items():
            with self.subTest(test_file=test_file):
                offenders = sorted(
                    name for name, source in methods.items()
                    # A conditional on returncode with no assert/fail anywhere
                    # in the method is the tell-tale sign of this anti-pattern.
                    if re.search(r"if\s+result\.returncode\s*==\s*0", source)
                    and _assertion_count(source) == 0
                )
                self.assertEqual(
                    offenders, [],
                    f"These {test_file} tests check `if result.returncode "
                    f"== 0` but never assert/fail — they always report "
                    f"PASSED either way: {offenders}",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
