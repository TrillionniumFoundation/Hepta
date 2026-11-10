"""Synthetic adversarial checks: frozen P0 release thresholds cannot be widened.

These test the release acceptance function only. They are not native performance,
full-cost NDU, Rust parity, or production qualification evidence.
"""
from __future__ import annotations

import unittest

from tests import test_hia_release_parity_tail_gate as tail


class ReleaseGateUpperBoundTests(unittest.TestCase):
    @staticmethod
    def cohort(**kwargs):
        return tail.ReleaseParityTailGateTests.cohort(**kwargs)


    def test_finite_relaxed_median_must_not_override_frozen_protocol(self):
        rows, spec = self.cohort()
        spec["performance_gate"]["hia_median_ratio_maximum"] = 2.0
        self.assert_reject(rows, spec)

    def test_finite_relaxed_tail_must_not_admit_999_percent_regression(self):
        rows, spec = self.cohort(slow_phase="holdout", last_sample_ns=999)
        spec["performance_gate"]["hia_tail_ratio_maximum"] = 10.0
        self.assert_reject(rows, spec)




if __name__ == "__main__":
    unittest.main()
