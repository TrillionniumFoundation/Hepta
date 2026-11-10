"""Finite invalid-registration counterexamples for HIA release parity.

All timing vectors here are synthetic. These tests only check rejection
semantics; they do not measure native performance or establish production value.
"""
from __future__ import annotations

import unittest

from tests import test_hia_release_parity_tail_gate as tail


class ReleaseProtocolCompletenessTests(unittest.TestCase):
    @staticmethod
    def cohort():
        return tail.ReleaseParityTailGateTests.cohort()


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
        rows, spec = tail.ReleaseParityTailGateTests.cohort(
            slow_phase="holdout", last_sample_ns=999)
        spec["performance_gate"]["hia_median_ratio_maximum"] = float("inf")
        spec["performance_gate"]["hia_tail_ratio_maximum"] = float("inf")
        self.assert_reject(rows, spec)

    def test_disabling_complete_baseline_requirement_is_invalid(self):
        rows, spec = self.cohort()
        spec["performance_gate"]["all_baselines_and_sizes_required"] = False
        self.assert_reject(rows, spec)


    def test_holdout_size_replay_is_not_an_unseen_length(self):
        rows, spec = self.cohort()
        spec["holdout_sizes"] = list(spec["training_sizes"])
        for row in rows:
            if row["phase"] == "holdout":
                row["n"] = spec["holdout_sizes"][0]
        self.assert_reject(rows, spec)

    def test_holdout_seed_replay_is_not_an_unseen_seed(self):
        rows, spec = self.cohort()
        spec["holdout_seeds"] = list(spec["training_seeds"])
        for row in rows:
            if row["phase"] == "holdout":
                row["seed"] = spec["holdout_seeds"][0]
        self.assert_reject(rows, spec)

    def test_boolean_request_size_cannot_impersonate_integer_axis(self):
        rows, spec = self.cohort()
        spec["training_sizes"] = [1]
        for row in rows:
            if row["phase"] == "training":
                row["n"] = 1
        rows[0]["n"] = True  # True == 1, but not the registered native integer.
        self.assert_reject(rows, spec)

    def test_float_request_seed_cannot_impersonate_integer_axis(self):
        rows, spec = self.cohort()
        rows[0]["seed"] = 11.0  # 11.0 == 11, not an integer native receipt.
        self.assert_reject(rows, spec)

    def test_zero_duration_cannot_count_as_unmeasured_hia_speedup(self):
        rows, spec = self.cohort()
        for row in rows:
            if row["backend"] == "hia":
                row["times_ns"] = [0] * spec["samples"]
        self.assert_reject(rows, spec)

    def test_tuple_timing_vector_cannot_impersonate_json_sample_list(self):
        rows, spec = self.cohort()
        rows[0]["times_ns"] = tuple(rows[0]["times_ns"])
        self.assert_reject(rows, spec)


if __name__ == "__main__":
    unittest.main()
