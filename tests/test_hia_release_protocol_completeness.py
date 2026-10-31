"""Finite invalid-registration counterexamples for HIA release parity.

All timing vectors here are synthetic. These tests only check rejection
semantics; they do not measure native performance or establish production value.
"""
from __future__ import annotations

import unittest

from tests.test_hia_release_parity_tail_gate import ReleaseParityTailGateTests
from tools.qualify_hia_release_parity import assess


class ReleaseProtocolCompletenessTests(unittest.TestCase):
    @staticmethod
    def cohort():
        return ReleaseParityTailGateTests.cohort()

    def assert_reject(self, rows, spec):
        with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
            assess(rows, spec)

    def test_vacuous_empty_campaign_cannot_pass(self):
        _, spec = self.cohort()
        spec["training_sizes"] = []
        spec["holdout_sizes"] = []
        self.assert_reject([], spec)

    def test_missing_holdout_axis_cannot_pass(self):
        rows, spec = self.cohort()
        spec["holdout_sizes"] = []
        self.assert_reject([row for row in rows if row["phase"] == "training"], spec)

    def test_missing_training_seed_axis_cannot_pass(self):
        rows, spec = self.cohort()
        spec["training_seeds"] = []
        self.assert_reject([row for row in rows if row["phase"] == "holdout"], spec)

    def test_duplicated_registered_seed_cannot_satisfy_set_comparison(self):
        rows, spec = self.cohort()
        spec["training_seeds"].append(spec["training_seeds"][0])
        self.assert_reject(rows, spec)

    def test_duplicated_registered_baseline_cannot_be_silently_deduplicated(self):
        rows, spec = self.cohort()
        spec["backends"].append("rust")
        self.assert_reject(rows, spec)

    def test_nonfinite_limits_cannot_admit_bad_tail(self):
        rows, spec = ReleaseParityTailGateTests.cohort(
            slow_phase="holdout", last_sample_ns=999)
        spec["performance_gate"]["hia_median_ratio_maximum"] = float("inf")
        spec["performance_gate"]["hia_tail_ratio_maximum"] = float("inf")
        self.assert_reject(rows, spec)

    def test_disabling_complete_baseline_requirement_is_invalid(self):
        rows, spec = self.cohort()
        spec["performance_gate"]["all_baselines_and_sizes_required"] = False
        self.assert_reject(rows, spec)


if __name__ == "__main__":
    unittest.main()
