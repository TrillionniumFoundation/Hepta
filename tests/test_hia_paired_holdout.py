"""Independent adversarial checks for conditional P5/P6 paired evidence."""
from copy import deepcopy
import json
import unittest

from hepta.hia_full_cost_gate import FullCostRejected
from hepta.hia_paired_holdout import (
    SCHEMA, assess_paired_holdout,
)
from tests.test_hia_full_cost_gate import fixture, wire


class HIAPairedHoldoutTests(unittest.TestCase):
    def test_complete_synthetic_all_task_win_requires_deny_all(self):
        report = assess_paired_holdout(wire(fixture()))
        self.assertEqual(report["schema"], SCHEMA)
        self.assertTrue(report["paired_evidence_supported"])
        self.assertEqual(report["authority"], "DENY_ALL")
        self.assertFalse(report["production_activation_allowed"])
        self.assertFalse(report["limitations"]["task_independence_verified"])
        self.assertFalse(report["limitations"]["observer_authenticated"])
        self.assertFalse(report["limitations"]["statistical_generalization_proved"])
        for control in ("baseline", "fixed", "dp"):
            cmp = report["paired_comparisons"][control]
            self.assertEqual((cmp["wins"], cmp["losses"], cmp["ties"]), (8, 0, 0))
            self.assertEqual((cmp["one_sided_sign_p_numerator"],
                              cmp["one_sided_sign_p_denominator"]), (1, 256))
            self.assertTrue(cmp["passes_conditional_threshold"])

    def test_large_outliers_cannot_masquerade_as_robust_task_advantage(self):
        data = fixture()
        # An aggregate win is produced by just two large task improvements,
        # although NDU loses on the six remaining registered tasks.
        rows = data["arms"][3]["observations"]
        for row in rows[:2]:
            row["execution_ns"] = 1
        for row in rows[2:]:
            row["execution_ns"] = 1050
        report = assess_paired_holdout(wire(data))
        self.assertTrue(report["existing_full_cost_verdict"]["economic_scope_positive"])
        self.assertFalse(report["paired_evidence_supported"])
        self.assertEqual((report["paired_comparisons"]["dp"]["wins"],
                          report["paired_comparisons"]["dp"]["losses"]), (2, 6))
        self.assertIn("paired_sign_threshold_not_met", report["reasons"])

    def test_seven_of_eight_wins_fails_familywise_exact_threshold(self):
        data = fixture()
        data["arms"][3]["observations"][0]["execution_ns"] = 1100
        report = assess_paired_holdout(wire(data))
        self.assertTrue(report["existing_full_cost_verdict"]["economic_scope_positive"])
        self.assertFalse(report["paired_evidence_supported"])
        cmp = report["paired_comparisons"]["dp"]
        self.assertEqual((cmp["wins"], cmp["losses"]), (7, 1))
        self.assertEqual((cmp["one_sided_sign_p_numerator"],
                          cmp["one_sided_sign_p_denominator"]), (9, 256))
        self.assertFalse(cmp["passes_conditional_threshold"])

    def test_ties_do_not_inflate_effective_task_count(self):
        data = fixture()
        rows = data["arms"][3]["observations"]
        for row in rows[:5]:
            row["execution_ns"] = 900  # exact tie with DP, including controller
        for row in rows[5:]:
            row["execution_ns"] = 100
        result = assess_paired_holdout(wire(data))
        self.assertTrue(result["existing_full_cost_verdict"]["economic_scope_positive"])
        self.assertFalse(result["paired_evidence_supported"])
        cmp = result["paired_comparisons"]["dp"]
        self.assertEqual((cmp["wins"], cmp["ties"], cmp["non_tied_trials"]),
                         (3, 5, 3))

    def test_complete_one_time_and_unknown_costs_override_significance(self):
        data = fixture()
        data["arms"][3]["one_time_ns"]["candidate_build"] = 2000
        result = assess_paired_holdout(wire(data))
        self.assertFalse(result["paired_evidence_supported"])
        self.assertIn("full_cost_gate_not_positive", result["reasons"])
        data = fixture()
        data["arms"][3]["unknown_costs"] = ["human_review_unmeasured"]
        result = assess_paired_holdout(wire(data))
        self.assertFalse(result["paired_evidence_supported"])
        self.assertIn("full_cost_gate_not_positive", result["reasons"])

    def test_permuted_observation_rows_are_joined_by_registered_identity(self):
        data = fixture()
        original = assess_paired_holdout(wire(data))
        for arm in data["arms"]:
            arm["observations"].reverse()
        permuted = assess_paired_holdout(wire(data))
        self.assertEqual(original["paired_comparisons"], permuted["paired_comparisons"])
        self.assertTrue(permuted["paired_evidence_supported"])

    def test_full_cost_immutability_and_failed_or_forged_control_still_reject(self):
        bad = (fixture(), b'{"a":1,"a":2}', b'{"a":NaN}',
               bytes([0xff]), b"x" * 262145)
        for raw in bad:
            with self.subTest(data=type(raw).__name__):
                with self.assertRaises(FullCostRejected):
                    assess_paired_holdout(raw)
        for change in (
            lambda d: d["arms"][0]["observations"][2].update(completed=False),
            lambda d: d["arms"][1]["observations"][0].update(result_digest="9"*64),
            lambda d: d["arms"][3].update(candidate_bank_digest="a"*64),
            lambda d: d["arms"][3]["one_time_ns"].pop("verification"),
        ):
            data = fixture()
            change(data)
            with self.subTest(mutation=repr(change)):
                with self.assertRaises(FullCostRejected):
                    assess_paired_holdout(wire(data))

    def test_exact_large_integer_combinatorics_and_limits(self):
        data = fixture()
        data["registered_trials"] = [
            dict(id=f"task{i:03d}", input_digest="a"*64,
                 expected_result_digest="b"*64) for i in range(128)
        ]
        for arm in data["arms"]:
            row = deepcopy(arm["observations"][0])
            arm["observations"] = [dict(row, trial_id=f"task{i:03d}")
                                   for i in range(128)]
        result = assess_paired_holdout(wire(data))
        self.assertTrue(result["paired_evidence_supported"])
        cmp = result["paired_comparisons"]["dp"]
        self.assertEqual(cmp["one_sided_sign_p_numerator"], 1)
        self.assertEqual(cmp["one_sided_sign_p_denominator"], 1 << 128)
        self.assertEqual(result["registered_trials"], 128)


if __name__ == "__main__":
    unittest.main()
