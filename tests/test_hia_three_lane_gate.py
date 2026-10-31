"""Independent adversarial self-tests for the source-bound no-skips gate."""
from __future__ import annotations

from types import SimpleNamespace
import unittest

from tools.qualify_hia_three_lane import (
    SUITES, _outcome_admissible, _planned_test_ids,
)


class _Synthetic(unittest.TestCase):
    def runTest(self):
        return None


def result(count=2, **overrides):
    defaults = dict(testsRun=count, errors=[], failures=[], skipped=[],
                    expectedFailures=[], unexpectedSuccesses=[])
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
