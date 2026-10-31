"""Independent finite cohort regressions for the HIA release p99 acceptance gate.

These use synthetic batch timing samples only. They do not measure native speed,
qualify compiler refinement, or establish parity with optimized Rust.
"""
from __future__ import annotations

import unittest

from tools.qualify_hia_release_parity import assess


class ReleaseParityTailGateTests(unittest.TestCase):
    @staticmethod
    def cohort(*, slow_phase=None, last_sample_ns=100):
        # Twenty samples make p95 the 19th and p99 the 20th observation.
        # A single HIA tail spike thus cannot be hidden inside median/p95.
        spec = {
            "backends": ["c", "cpp", "rust", "hia"],
            "training_sizes": [64], "training_seeds": [11],
            "holdout_sizes": [257], "holdout_seeds": [13],
            "samples": 20,
            "performance_gate": {
                "hia_median_ratio_maximum": 1.1,
                "hia_tail_ratio_maximum": 1.2,
                "all_baselines_and_sizes_required": True,
            },
        }
        rows = []
        for phase, n, seed in (("training", 64, 11), ("holdout", 257, 13)):
            for backend in spec["backends"]:
                times = [100] * 20
                if backend == "hia" and phase == slow_phase:
                    times[-1] = last_sample_ns
                rows.append({
                    "phase": phase, "backend": backend,
                    "n": n, "seed": seed, "times_ns": times,
                })
        return rows, spec

    def test_single_holdout_p99_spike_rejects_all_three_baselines(self):
        rows, spec = self.cohort(slow_phase="holdout", last_sample_ns=121)
        result = assess(rows, spec)
        holdout = [row for row in result["comparisons"] if row["phase"] == "holdout"]
        self.assertEqual(len(holdout), 3)
        # Before the repair all three rows incorrectly pass despite 1.21 > 1.2.
        for row in holdout:
            self.assertEqual(row["median_ratio"], 1)
            self.assertEqual(row["p95_ratio"], 1)
            self.assertEqual(row["p99_ratio"], 1.21)
            self.assertFalse(row["passed"], row)
        self.assertFalse(result["holdout_gate_passed"])
        self.assertFalse(result["performance_gate_passed"])
        self.assertEqual(result["rust_comparisons_passed"], 1)
        self.assertEqual(result["all_rust_comparisons"], 2)

    def test_exact_registered_tail_threshold_is_admitted(self):
        rows, spec = self.cohort(slow_phase="holdout", last_sample_ns=120)
        result = assess(rows, spec)
        self.assertTrue(result["holdout_gate_passed"])
        self.assertTrue(result["performance_gate_passed"])
        self.assertTrue(all(row["passed"] for row in result["comparisons"]))

    def test_training_only_p99_failure_is_not_hidden_by_holdout(self):
        rows, spec = self.cohort(slow_phase="training", last_sample_ns=130)
        result = assess(rows, spec)
        self.assertTrue(result["holdout_gate_passed"])
        self.assertFalse(result["performance_gate_passed"])
        self.assertTrue(all(not row["passed"] for row in result["comparisons"]
                            if row["phase"] == "training"))

    def test_missing_or_duplicated_observation_is_rejected(self):
        rows, spec = self.cohort()
        with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
            assess(rows[:-1], spec)
        with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
            assess(rows + [dict(rows[0])], spec)

    def test_finite_sample_success_never_claims_broad_rust_parity(self):
        rows, spec = self.cohort()
        result = assess(rows, spec)
        self.assertTrue(result["performance_gate_passed"])
        self.assertIs(result["broad_rust_performance_parity_established"], False)


if __name__ == "__main__":
    unittest.main()
