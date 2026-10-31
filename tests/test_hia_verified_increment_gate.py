"""Real and adversarial checks of the broad, source-bound HIA qualification gate.

The older gate treated unittest.expectedFailure as an admissible success and
trusted testsRun alone. These tests assert that the actual runner's outcome,
plan/start/stop identities, and source/worktree consistency are all mandatory.
"""
from __future__ import annotations

from io import StringIO
from types import SimpleNamespace
import unittest

from tools.qualify_hia_verified_increment import (
    MODULES, _IdentityRecordingResult, _outcome_admissible,
    _planned_test_ids, _ids_digest,
)


def fake_result(**changes):
    state = {
        "testsRun": 2, "started_ids": ["one", "two"], "finished_ids": ["one", "two"],
        "errors": [], "failures": [], "skipped": [], "expectedFailures": [],
        "unexpectedSuccesses": [],
    }
    state.update(changes)
    return SimpleNamespace(**state, wasSuccessful=lambda: True)


def accepted(result, planned=("one", "two"), source=True, worktree=True):
    return _outcome_admissible(
        result, planned, source_unchanged=source, worktree_unchanged=worktree
    )


class VerifiedIncrementAdmissionTests(unittest.TestCase):
    def test_full_gate_includes_its_independent_adversarial_tests(self):
        self.assertEqual(MODULES.count("tests.test_hia_verified_increment_gate"), 1)
        self.assertEqual(len(MODULES), len(set(MODULES)))

    def test_clean_complete_outcome_and_source_are_necessary(self):
        self.assertTrue(accepted(fake_result()))
        self.assertFalse(accepted(fake_result(), source=False))
        self.assertFalse(accepted(fake_result(), worktree=False))
        self.assertFalse(accepted(fake_result(testsRun=1)))
        self.assertFalse(accepted(fake_result(testsRun=3)))

    def test_real_expected_failure_is_not_a_certificate(self):
        class Expected(unittest.TestCase):
            @unittest.expectedFailure
            def test_expected_failure(self):
                self.assertEqual(0, 1)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Expected)
        planned = _planned_test_ids(suite)
        result = unittest.TextTestRunner(
            stream=StringIO(), resultclass=_IdentityRecordingResult
        ).run(suite)
        self.assertTrue(result.wasSuccessful())  # Standard unittest semantics!
        self.assertEqual(result.testsRun, 1)
        self.assertEqual(len(result.expectedFailures), 1)
        self.assertEqual(tuple(result.started_ids), planned)
        self.assertEqual(tuple(result.finished_ids), planned)
        self.assertFalse(accepted(result, planned))

    def test_skipped_failed_unexpected_success_and_error_all_refuse(self):
        marker = unittest.FunctionTestCase(lambda: None)
        for key, value in (
            ("skipped", [(marker, "skipped a required compiler test")]),
            ("expectedFailures", [(marker, "false proof through expected failure")]),
            ("unexpectedSuccesses", [marker]),
            ("errors", [(marker, "synthetic error")]),
            ("failures", [(marker, "synthetic failure")]),
        ):
            with self.subTest(key=key):
                self.assertFalse(accepted(fake_result(**{key: value})))

    def test_matching_count_cannot_mask_missing_replaced_or_reordered_tests(self):
        for change in (
            {"started_ids": ["one", "other"]},
            {"started_ids": ["two", "one"]},
            {"finished_ids": ["one"]},
            {"finished_ids": ["two", "one"]},
            {"started_ids": ["one", "one"]},
            {"finished_ids": ["one", "one"]},
        ):
            with self.subTest(change=change):
                self.assertFalse(accepted(fake_result(**change)))

    def test_no_tests_duplicate_ids_or_noncanonical_plan_refuse(self):
        self.assertFalse(accepted(fake_result(testsRun=0, started_ids=[], finished_ids=[]), ()))
        self.assertFalse(accepted(fake_result(), ("one", "one")))
        self.assertFalse(accepted(fake_result(), ["one", "two"]))
        self.assertFalse(accepted(fake_result(), ("one", "")))

    def test_real_nested_suite_tracks_exact_order(self):
        class A(unittest.TestCase):
            def test_a(self): self.assertTrue(True)
            def test_b(self): self.assertTrue(True)
        class B(unittest.TestCase):
            def test_c(self): self.assertTrue(True)
        suite = unittest.TestSuite([
            unittest.defaultTestLoader.loadTestsFromTestCase(A),
            unittest.defaultTestLoader.loadTestsFromTestCase(B),
        ])
        planned = _planned_test_ids(suite)
        result = unittest.TextTestRunner(
            stream=StringIO(), resultclass=_IdentityRecordingResult
        ).run(suite)
        self.assertEqual(len(planned), 3)
        self.assertEqual(tuple(result.started_ids), planned)
        self.assertEqual(tuple(result.finished_ids), planned)
        self.assertTrue(accepted(result, planned))
        self.assertEqual(_ids_digest(planned), _ids_digest(result.started_ids))
        self.assertNotEqual(_ids_digest(planned), _ids_digest(tuple(reversed(planned))))


if __name__ == "__main__":
    unittest.main()
