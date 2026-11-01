"""P0 release admission: pooled-size parity must not hide paired-seed regressions.

Synthetic timing controls only; no actual native performance is measured and
no production, compiler-refinement, or Rust parity result is implied.
"""
from __future__ import annotations

import unittest

from tools.qualify_hia_release_parity import assess


class ReleasePairedSeedTests(unittest.TestCase):
    @staticmethod
    def fixture(*, swap_phase=None):
        # Each size has two independently registered seeds.  Swapping only HIA
        # seed-to-timing assignments preserves EVERY pooled summary exactly,
        # while one matched workload becomes ten times slower than baseline.
        spec = {
            "backends": ["c", "cpp", "rust", "hia"],
            "training_sizes": [64], "training_seeds": [11, 12],
            "holdout_sizes": [257], "holdout_seeds": [13, 14],
            "samples": 20,
            "performance_gate": {
                "hia_median_ratio_maximum": 1.1,
                "hia_tail_ratio_maximum": 1.2,
                "all_baselines_and_sizes_required": True,
            },
        }
        rows = []
        for phase in ("training", "holdout"):
            size = spec[phase + "_sizes"][0]
            for index, seed in enumerate(spec[phase + "_seeds"]):
                baseline_ns = 100 if index == 0 else 1000
                for backend in spec["backends"]:
                    value = (1000 if index == 0 else 100) if (
                        phase == swap_phase and backend == "hia") else baseline_ns
                    rows.append({"phase": phase, "backend": backend,
                                 "n": size, "seed": seed, "times_ns": [value] * 20})
        return rows, spec

    def test_unseen_holdout_seed_swap_must_fail_despite_identical_pooled_p99(self):
        rows, spec = self.fixture(swap_phase="holdout")
        result = assess(rows, spec)
        self.assertTrue(all(row["passed"] for row in result["comparisons"]))
        self.assertFalse(result["holdout_gate_passed"])
        self.assertFalse(result["performance_gate_passed"])
        witnesses = [row for row in result["seed_comparisons"]
                     if row["phase"] == "holdout" and row["seed"] == 13]
        self.assertEqual(len(witnesses), 3)
        self.assertTrue(all(row["p99_ratio"] == 10 and not row["passed"] for row in witnesses))

    def test_training_seed_swap_must_fail_even_if_holdout_remains_clean(self):
        rows, spec = self.fixture(swap_phase="training")
        result = assess(rows, spec)
        self.assertTrue(all(row["passed"] for row in result["comparisons"]))
        self.assertFalse(result["performance_gate_passed"])
        self.assertTrue(result["holdout_gate_passed"])
        witnesses = [row for row in result["seed_comparisons"]
                     if row["phase"] == "training" and row["seed"] == 11]
        self.assertEqual(len(witnesses), 3)
        self.assertTrue(all(not row["passed"] for row in witnesses))

    def test_identical_seed_matched_native_timings_still_pass(self):
        rows, spec = self.fixture()
        result = assess(rows, spec)
        self.assertTrue(result["performance_gate_passed"])
        self.assertTrue(result["holdout_gate_passed"])
        self.assertEqual(len(result["comparisons"]), 6)
        self.assertEqual(len(result["seed_comparisons"]), 12)
        self.assertTrue(all(row["passed"] for row in result["seed_comparisons"]))

    def test_full_registered_request_coverage_remains_mandatory(self):
        rows, spec = self.fixture()
        with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
            assess(rows[:-1], spec)
        with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
            assess(rows + [dict(rows[0])], spec)


if __name__ == "__main__":
    unittest.main()
