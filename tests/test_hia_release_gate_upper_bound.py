"""Synthetic adversarial checks: frozen P0 release thresholds cannot be widened.

These test the release acceptance function only. They are not native performance,
full-cost NDU, Rust parity, or production qualification evidence.
"""
from __future__ import annotations

import unittest

from tests import test_hia_release_parity_tail_gate as tail
from tools.qualify_hia_release_parity import assess


class ReleaseGateUpperBoundTests(unittest.TestCase):
    @staticmethod
    def cohort(**kwargs):
        return tail.ReleaseParityTailGateTests.cohort(**kwargs)

    def assert_reject(self, rows, spec):
        with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
            assess(rows, spec)

    def test_finite_relaxed_median_must_not_override_frozen_protocol(self):
        rows, spec = self.cohort()
        spec["performance_gate"]["hia_median_ratio_maximum"] = 2.0
        self.assert_reject(rows, spec)

    def test_finite_relaxed_tail_must_not_admit_999_percent_regression(self):
        rows, spec = self.cohort(slow_phase="holdout", last_sample_ns=999)
        spec["performance_gate"]["hia_tail_ratio_maximum"] = 10.0
        self.assert_reject(rows, spec)

    def test_exact_frozen_thresholds_remain_accepted(self):
        rows, spec = self.cohort()
        result = assess(rows, spec)
        self.assertTrue(result["performance_gate_passed"])
        self.assertTrue(result["holdout_gate_passed"])

    def test_tighter_tail_limit_keeps_negative_witness(self):
        rows, spec = self.cohort(slow_phase="holdout", last_sample_ns=121)
        spec["performance_gate"]["hia_tail_ratio_maximum"] = 1.1
        result = assess(rows, spec)
        self.assertFalse(result["performance_gate_passed"])
        self.assertFalse(result["holdout_gate_passed"])


if __name__ == "__main__":
    unittest.main()
