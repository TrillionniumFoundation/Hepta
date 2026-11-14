"""Actual unittest outcomes must not turn empty, skipped or partial runs green."""
import io
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

from tools.run_hia_unittest_gate import load_declared_suite, run_suite


class QualificationTestGateTests(unittest.TestCase):
    def test_each_declared_module_must_contribute_real_tests_before_any_run(self):
        observed = []
        module = types.ModuleType("hia_gate_fixture")
        module.Good = type("Good", (unittest.TestCase,), {
            "__module__": module.__name__,
            "test_real": lambda self: observed.append("ran"),
        })
        module.Empty = type("Empty", (unittest.TestCase,), {
            "__module__": module.__name__,
        })
        with patch.dict(sys.modules, {module.__name__: module}):
            for selectors, reason in (
                (("hia_gate_fixture.Good", "hia_gate_fixture.Empty"), "empty test selector"),
                (("hia_gate_fixture.Good", "hia_gate_fixture.missing"), "discovery failed"),
                (("hia_gate_fixture", "hia_gate_fixture.Good"), "overlapping"),
                ((), "empty"),
            ):
                with self.subTest(selectors=selectors), self.assertRaisesRegex(ValueError, reason):
                    load_declared_suite(selectors)
                self.assertEqual(observed, [])
            suite, planned = load_declared_suite(("hia_gate_fixture.Good",))
            self.assertEqual(planned, ("hia_gate_fixture.Good.test_real",))
            self.assertTrue(run_suite(suite, stream=io.StringIO()))
            self.assertEqual(observed, ["ran"])

    def test_command_refuses_a_real_empty_group_even_with_a_valid_test(self):
        root = Path(__file__).resolve().parents[1]
        child = subprocess.run([
            sys.executable, "-I", "-S", "-B", str(root / "tools/run_hia_unittest_gate.py"),
            "tests.test_hia_unittest_gate.QualificationTestGateTests.test_partial_runner_cannot_attest_a_complete_declared_suite",
            "tests.test_hia_release_parity_tail_gate",
        ], cwd="/", capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 1)
        self.assertIn(b"empty test selector: tests.test_hia_release_parity_tail_gate", child.stderr)
        self.assertNotIn(b"Ran ", child.stderr)

    def test_actual_empty_success_failure_error_and_skip_outcomes(self):
        def success():
            pass

        def failure():
            raise AssertionError("observed failure")

        def error():
            raise ValueError("observed error")

        def skip():
            raise unittest.SkipTest("observed skip")

        for function, accepted in ((success, True), (failure, False),
                                   (error, False), (skip, False)):
            with self.subTest(outcome=function.__name__):
                suite = unittest.TestSuite([unittest.FunctionTestCase(function)])
                self.assertEqual(run_suite(suite, stream=io.StringIO()), accepted)
        self.assertFalse(run_suite(unittest.TestSuite(), stream=io.StringIO()))

    def test_actual_expected_failure_and_unexpected_success_are_not_qualification(self):
        class ExpectedFailure(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                self.fail("observed expected failure")

        class UnexpectedSuccess(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                pass

        for case in (ExpectedFailure, UnexpectedSuccess):
            with self.subTest(case=case.__name__):
                self.assertFalse(run_suite(unittest.TestSuite([case()]), stream=io.StringIO()))

    def test_partial_runner_cannot_attest_a_complete_declared_suite(self):
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None),
                                    unittest.FunctionTestCase(lambda: None)])
        partial = types.SimpleNamespace(testsRun=1, errors=[], failures=[], skipped=[],
                                        expectedFailures=[], unexpectedSuccesses=[],
                                        wasSuccessful=lambda: True)
        with patch.object(unittest.TextTestRunner, "run", return_value=partial):
            self.assertFalse(run_suite(suite, stream=io.StringIO()))

    def test_missing_actual_test_module_refuses_through_the_command_entry(self):
        root = Path(__file__).resolve().parents[1]
        child = subprocess.run([sys.executable, "-I", "-S", "-B",
                                str(root / "tools/run_hia_unittest_gate.py"),
                                "tests.unavailable_gate_fixture"],
                               cwd="/", capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 1)
        self.assertIn(b"ModuleNotFoundError", child.stderr)


if __name__ == "__main__":
    unittest.main()
