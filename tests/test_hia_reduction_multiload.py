"""Prospective multi-load denominators and retained negative timing gates."""
from copy import deepcopy
from hashlib import sha256
import json
import unittest

from tools.qualify_hia_reduction_release import (
    ARMS, INDUCTION_PROFILE, assess, specification,
)


class ReductionMultiloadTests(unittest.TestCase):
    @staticmethod
    def cohort():
        spec = specification(INDUCTION_PROFILE)
        rows = [{"workload": workload, "phase": phase, "backend": arm,
                 "n": n, "seed": seed, "calls": calls,
                 "samples": spec["samples"], "elapsed_ns": 1000 * spec["samples"],
                 "times_ns": [1000] * spec["samples"]}
                for workload in spec["workloads"]
                for phase in ("regression", "holdout")
                for arm in ARMS for n in spec[phase + "_sizes"]
                for seed in spec["seeds"] for calls in spec["batch_loads"]]
        return spec, rows

    def test_original_protocol_identity_is_preserved(self):
        wire = json.dumps(specification(), sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode()
        self.assertEqual(sha256(wire).hexdigest(),
                         "4641c52985ab1b25168117ffac3fc142daf59197948836d3932c67d23c84c8e7")

    def test_all_lengths_loads_workloads_and_seeds_are_separate_observations(self):
        spec, rows = self.cohort()
        result = assess(rows, spec)
        self.assertEqual(len(rows), spec["timing_requests"])
        self.assertEqual(sum(len(r["times_ns"]) for r in rows), spec["timed_batches"])
        self.assertEqual(sum(r["calls"] * len(r["times_ns"]) for r in rows),
                         spec["timed_kernel_calls"])
        self.assertEqual((len(rows), spec["timed_batches"], spec["timed_kernel_calls"]),
                         (1080, 22680, 612360))
        self.assertEqual(len(result["cohorts"]), 90)
        self.assertEqual(result["rust_comparisons_total"], 180)
        self.assertTrue(result["all_rust_gate_passed"])
        self.assertFalse(set(specification()["holdout_sizes"]) & set(spec["holdout_sizes"]))
        self.assertFalse(set(specification()["seeds"]) & set(spec["seeds"]))

    def test_one_tail_spike_cannot_be_pooled_away_by_a_different_batch_load(self):
        spec, rows = self.cohort()
        row = next(r for r in rows if r["backend"] == "hia_reduction"
                   and r["phase"] == "holdout" and r["calls"] == 1)
        row["times_ns"][-1] = 1201
        row["elapsed_ns"] = sum(row["times_ns"])
        result = assess(rows, spec)
        self.assertFalse(result["all_rust_gate_passed"])
        self.assertFalse(result["independent_holdout_passed"])
        affected = [r for r in result["comparisons"] if not r["passed"]]
        self.assertEqual(len(affected), 3)
        self.assertTrue(all(r["calls"] == 1 for r in affected))

    def test_multiload_receipts_retain_sample_count_and_elapsed_identity(self):
        for calls in (1, 16, 64):
            for field in ("samples", "elapsed_ns", "seed"):
                spec, rows = self.cohort()
                row = next(r for r in rows if r["calls"] == calls)
                row[field] = float(row[field])
                with self.subTest(calls=calls, field=field), self.assertRaises(ValueError):
                    assess(rows, spec)

    def test_missing_load_changed_work_and_relaxed_protocol_cannot_qualify(self):
        spec, rows = self.cohort()
        for changed in (rows[:-1], rows + [rows[0]],
                        [r for r in rows if r["calls"] != 16]):
            with self.assertRaises(ValueError):
                assess(changed, spec)
        changed = deepcopy(rows)
        changed[0]["calls"] = True
        with self.assertRaises(ValueError):
            assess(changed, spec)
        for key in ("median_ratio_maximum", "p95_ratio_maximum", "p99_ratio_maximum"):
            changed = deepcopy(spec)
            changed["performance_gate"][key] = 2.0
            with self.subTest(gate=key), self.assertRaises(ValueError):
                assess(rows, changed)


if __name__ == "__main__":
    unittest.main()
