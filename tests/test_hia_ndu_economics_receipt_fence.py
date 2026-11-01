"""P5: fail closed on incomplete, failed or spoofed native NDU cost receipts.

Synthetic acceptance contract cases only. Positive service-scope arithmetic
on fabricated costs is not measured NDU advantage or lifecycle qualification.
"""
from __future__ import annotations

from copy import deepcopy
import unittest

from tools.qualify_hia_native_ndu import evaluate, protocol


class NativeNduReceiptFenceTests(unittest.TestCase):
    @staticmethod
    def fixture():
        spec = protocol()
        samples = {name: {str(n): {"median": 100, "p95": 100, "p99": 100}
                          for n in spec["sizes"]} for name in spec["backends"]}
        rows = [
            {"episode": episode, "arm": arm, "status": "passed",
             "service_total_ns": 1 if arm == "native_ndu" else 2,
             "native_invocations": 1 if arm == "native_ndu" else 0}
            for episode in range(len(spec["episodes"]))
            for arm in spec["policy_arms"]
        ]
        return {"training_summary": samples, "policy_runs": rows}, spec

    def test_exact_passed_same_information_cost_cohort_is_accepted(self):
        report, spec = self.fixture()
        result = evaluate(report, spec)
        self.assertTrue(result["service_scope_gated_policy_benefit_established"])
        self.assertTrue(result["service_scope_net_ndu_benefit_established"])
        self.assertFalse(result["whole_lifecycle_net_ndu_benefit_established"])

    def test_failed_native_policy_must_not_be_counted_as_winning(self):
        report, spec = self.fixture()
        native = next(row for row in report["policy_runs"] if row["arm"] == "native_ndu")
        native["status"] = "failed"
        with self.assertRaisesRegex(ValueError, "E_HIA_NATIVE_ECONOMICS"):
            evaluate(report, spec)

    def test_replayed_duplicate_native_receipt_must_not_be_silently_overwritten(self):
        report, spec = self.fixture()
        duplicate = deepcopy(next(row for row in report["policy_runs"] if row["arm"] == "native_ndu"))
        duplicate["service_total_ns"] = 1000  # Old dict-comprehension drops this observation.
        report["policy_runs"].insert(0, duplicate)
        with self.assertRaisesRegex(ValueError, "E_HIA_NATIVE_ECONOMICS"):
            evaluate(report, spec)

    def test_unregistered_extra_episode_must_not_be_ignored(self):
        report, spec = self.fixture()
        extra = deepcopy(report["policy_runs"][0])
        extra["episode"] = len(spec["episodes"])
        report["policy_runs"].append(extra)
        with self.assertRaisesRegex(ValueError, "E_HIA_NATIVE_ECONOMICS"):
            evaluate(report, spec)

    def test_bool_negative_and_zero_cost_receipts_fail_closed(self):
        for value in (True, -1, 0, 1.0):
            report, spec = self.fixture()
            next(row for row in report["policy_runs"] if row["arm"] == "native_ndu")["service_total_ns"] = value
            with self.subTest(cost=value):
                with self.assertRaisesRegex(ValueError, "E_HIA_NATIVE_ECONOMICS"):
                    evaluate(report, spec)

    def test_boolean_native_invocation_cannot_impersonate_a_measured_call(self):
        report, spec = self.fixture()
        for row in report["policy_runs"]:
            if row["arm"] == "native_ndu":
                row["native_invocations"] = True
        with self.assertRaisesRegex(ValueError, "E_HIA_NATIVE_ECONOMICS"):
            evaluate(report, spec)


if __name__ == "__main__":
    unittest.main()
