"""Adversarial finite input checks for native NDU benchmark acceptance.

These are synthetic training-summary contract tests, NOT real C/Rust/HIA timing
evidence. Their only purpose is to prevent a false performance qualification.
"""
from __future__ import annotations

import unittest

from tools.qualify_hia_native_ndu import evaluate
from tests.test_hia_native_cohort_gate import cohort_fixture


class NativePerformanceAcceptanceTests(unittest.TestCase):
    @staticmethod
    def fixture():
        return cohort_fixture(native_calls=0, ndu_cost=150, control_cost=100)

    def test_single_p99_spike_rejects_the_native_performance_gate(self):
        report, spec = self.fixture()
        n = spec["sizes"][1]
        report["training_summary"]["hia"][str(n)]["p99"] = 121
        result = evaluate(report, spec)
        affected = [r for r in result["performance_comparisons"] if r["size"] == n]
        self.assertEqual(len(affected), 3)
        self.assertFalse(result["performance_gate_passed"])
        for row in affected:
            self.assertEqual(row["median_ratio"], 1)
            self.assertEqual(row["p95_ratio"], 1)
            self.assertEqual(row["p99_ratio"], 1.21)
            self.assertFalse(row["passed"], row)

    def test_registered_tail_limit_is_authoritative_not_hardcoded(self):
        report, spec = self.fixture()
        spec["performance_gate"]["hia_tail_ratio_maximum"] = 1.05
        report["training_summary"]["hia"][str(spec["sizes"][0])]["p95"] = 110
        report["training_summary"]["hia"][str(spec["sizes"][0])]["p99"] = 110
        self.assertFalse(evaluate(report, spec)["performance_gate_passed"])

    def test_registered_median_limit_is_authoritative_not_hardcoded(self):
        report, spec = self.fixture()
        spec["performance_gate"]["hia_median_ratio_maximum"] = 1.05
        n = str(spec["sizes"][0])
        report["training_summary"]["hia"][n].update(median=108, p95=110, p99=110)
        self.assertFalse(evaluate(report, spec)["performance_gate_passed"])

    def test_exact_p99_boundary_passes_only_finite_scope(self):
        report, spec = self.fixture()
        report["training_summary"]["hia"][str(spec["sizes"][0])]["p99"] = 120
        result = evaluate(report, spec)
        self.assertTrue(result["performance_gate_passed"])
        self.assertFalse(result["whole_lifecycle_net_ndu_benefit_established"])
        self.assertFalse(result["complete_lifecycle_cost_known"])
        self.assertFalse(result["service_scope_net_ndu_benefit_established"])

    def test_full_baseline_requirement_must_not_be_opted_out(self):
        report, spec = self.fixture()
        spec["performance_gate"]["all_baselines_and_sizes_required"] = False
        with self.assertRaisesRegex(ValueError, "E_HIA_NATIVE_ECONOMICS"):
            evaluate(report, spec)

    def test_missing_baseline_is_rejected_not_silently_ignored(self):
        report, spec = self.fixture()
        del report["training_summary"]["rust"][str(spec["sizes"][0])]
        with self.assertRaises((KeyError, ValueError)):
            evaluate(report, spec)


if __name__ == "__main__":
    unittest.main()
