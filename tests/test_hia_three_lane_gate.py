"""Independent adversarial self-tests for the source-bound no-skips gate."""
from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
from io import StringIO
import os
import unittest

from tools.qualify_hia_three_lane import (
    ROOT, SUITES, _IdentityRecordingResult, _outcome_admissible,
    _planned_test_ids, _verified_receipt_destination, git,
)


class _Synthetic(unittest.TestCase):
    def runTest(self):
        return None


def result(count=2, **overrides):
    defaults = dict(testsRun=count, errors=[], failures=[], skipped=[],
                    expectedFailures=[], unexpectedSuccesses=[],
                    started_ids=["one", "two"], finished_ids=["one", "two"])
    defaults.update(overrides)
    return SimpleNamespace(**defaults, wasSuccessful=lambda: (
        not defaults["errors"] and not defaults["failures"]
        and not defaults["unexpectedSuccesses"]))


class HIAThreeLaneGateTests(unittest.TestCase):
    def test_normal_two_discovered_tests_admit_only_stable_complete_outcome(self):
        ids = ("one", "two")
        self.assertTrue(_outcome_admissible(result(), ids, immutable=True))
        self.assertFalse(_outcome_admissible(result(), ids, immutable=False))
        self.assertFalse(_outcome_admissible(result(1), ids, immutable=True))
        self.assertFalse(_outcome_admissible(result(3), ids, immutable=True))

    def test_expected_failure_is_not_a_passing_proof(self):
        fake = _Synthetic()
        self.assertFalse(_outcome_admissible(
            result(expectedFailures=[(fake, "expected failing program")]),
            ("one", "two"), immutable=True))

    def test_skipped_expected_and_unexpected_successes_all_refuse(self):
        obj = _Synthetic()
        for key, value in (
            ("skipped", [(obj, "no compiler")]),
            ("errors", [(obj, "error")]),
            ("failures", [(obj, "failure")]),
            ("unexpectedSuccesses", [obj]),
        ):
            with self.subTest(reason=key):
                self.assertFalse(_outcome_admissible(
                    result(**{key: value}), ("one", "two"), immutable=True))

    def test_no_discovered_tests_or_duplicate_ids_cannot_pass(self):
        self.assertFalse(_outcome_admissible(result(0), (), immutable=True))
        self.assertFalse(_outcome_admissible(result(), ("one", "one"), immutable=True))
        self.assertFalse(_outcome_admissible(result(1), ("one", "two"), immutable=True))

    def test_matching_count_cannot_hide_other_or_unfinished_tests(self):
        for changed in (
            {"started_ids": ["one", "substituted"]},
            {"started_ids": ["two", "one"]},
            {"started_ids": ["one"]},
            {"started_ids": ["one", "one"]},
            {"finished_ids": ["one"]},
            {"finished_ids": ["two", "one"]},
        ):
            with self.subTest(changed=changed):
                self.assertFalse(_outcome_admissible(
                    result(**changed), ("one", "two"), immutable=True))

    def test_real_result_records_exact_start_and_stop(self):
        class Actual(unittest.TestCase):
            def test_1(self): self.assertTrue(True)
            def test_2(self): self.assertTrue(True)
        ids_suite = unittest.defaultTestLoader.loadTestsFromTestCase(Actual)
        expected = _planned_test_ids(ids_suite)
        execution_suite = unittest.defaultTestLoader.loadTestsFromTestCase(Actual)
        outcome = unittest.TextTestRunner(
            stream=StringIO(), resultclass=_IdentityRecordingResult,
        ).run(execution_suite)
        self.assertEqual(tuple(outcome.started_ids), expected)
        self.assertEqual(tuple(outcome.finished_ids), expected)
        self.assertTrue(_outcome_admissible(outcome, expected, immutable=True))

    def test_git_identity_uses_repository_root_not_foreign_cwd(self):
        original = Path.cwd()
        with TemporaryDirectory(prefix="hia-foreign-cwd-") as outside:
            try:
                os.chdir(outside)
                self.assertEqual(Path(git("rev-parse", "--show-toplevel")).resolve(),
                                 ROOT.resolve())
            finally:
                os.chdir(original)

    def test_receipt_cannot_write_into_checkout_or_via_alias(self):
        with self.assertRaisesRegex(ValueError, "must be absolute"):
            _verified_receipt_destination(Path("receipt.json"))
        with self.assertRaisesRegex(ValueError, "outside"):
            _verified_receipt_destination(ROOT / "proofs" / "receipt.json")
        with TemporaryDirectory(prefix="hia-external-receipt-") as outside:
            candidate = Path(outside) / "receipt.json"
            self.assertEqual(_verified_receipt_destination(candidate), candidate)

    def test_nested_suite_freezes_actual_order_and_test_count(self):
        class A(unittest.TestCase):
            def test_a(self): pass
            def test_b(self): pass
        class B(unittest.TestCase):
            def test_c(self): pass
        nested = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(A),
                                     unittest.defaultTestLoader.loadTestsFromTestCase(B)])
        ids = _planned_test_ids(nested)
        self.assertEqual(len(ids), 3)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual([i.rsplit(".", 1)[-1] for i in ids],
                         ["test_a", "test_b", "test_c"])

    def test_separate_exact_suite_inventory_and_non_authority(self):
        self.assertEqual(SUITES["gate"], ("tests.test_hia_three_lane_gate",))
        self.assertEqual(set(SUITES), {
            "gate", "core", "native", "rust", "legacy", "llvm", "migration"})
        for key, sources in SUITES.items():
            self.assertTrue(sources)
            self.assertEqual(len(sources), len(set(sources)), key)


if __name__ == "__main__":
    unittest.main()
