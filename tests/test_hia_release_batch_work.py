"""Synthetic receipt mutation audits, not native timing observations."""
from __future__ import annotations

import unittest

from tools.qualify_hia_release_parity import assess, specification


def native_shaped_cohort():
    spec = specification("verified-reduction-narrowed-release-v1")
    rows = [{"phase": phase, "backend": backend, "n": n, "seed": seed,
             "calls": spec["batch_calls"], "samples": spec["samples"],
             "times_ns": [100] * spec["samples"]}
            for phase in ("training", "holdout") for backend in spec["backends"]
            for n in spec[phase + "_sizes"] for seed in spec[phase + "_seeds"]]
    return rows, spec


class ReleaseBatchWorkTests(unittest.TestCase):
    def test_complete_equal_work_keeps_the_existing_thresholds(self):
        rows, spec = native_shaped_cohort()
        result = assess(rows, spec)
        self.assertTrue(result["performance_gate_passed"])
        self.assertTrue(result["native_batch_work_identity_checked"])
        self.assertFalse(result["broad_rust_performance_parity_established"])

    def test_fewer_calls_cannot_look_like_equal_work_speedup(self):
        rows, spec = native_shaped_cohort()
        for row in rows:
            if row["backend"] == "hia":
                row.update(calls=1, times_ns=[2] * spec["samples"])
        with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
            assess(rows, spec)

    def test_missing_or_noninteger_native_work_identity_is_rejected(self):
        for field in ("calls", "samples"):
            for value in (None, True, 21.0 if field == "samples" else 64.0):
                rows, spec = native_shaped_cohort()
                if value is None:
                    rows[0].pop(field)
                else:
                    rows[0][field] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
                    assess(rows, spec)

    def test_receipt_sample_count_cannot_contradict_its_timing_vector(self):
        rows, spec = native_shaped_cohort()
        rows[0]["samples"] = 1
        with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
            assess(rows, spec)

    def test_formal_registration_cannot_reduce_frozen_batch_or_sample_work(self):
        for field in ("batch_calls", "samples", "warmup_calls"):
            rows, spec = native_shaped_cohort()
            spec[field] = 1
            for row in rows:
                row.update(calls=spec["batch_calls"], samples=spec["samples"],
                           times_ns=[100] * spec["samples"])
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
                assess(rows, spec)


if __name__ == "__main__":
    unittest.main()
