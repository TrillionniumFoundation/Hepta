"""Independent finite contract checks for bounded native scalar result tuples."""
from __future__ import annotations

import unittest

from tools.hia_selfhost_multi_results import cases, refusals, independent_reference


class SelfhostMultiResultSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = independent_reference()

    def test_tuple_values_match_independent_full_width_core_vm_observations(self):
        self.assertEqual(len(self.reference["cases"]), 63)
        self.assertEqual(len({case["program"] for case in self.reference["cases"]}), 20)
        for case in self.reference["cases"]:
            self.assertEqual(case["reference_result"]["status"], "returned")
            expected = ([0, *bytes.fromhex(case["expected_hex"])] if case["reference_entry"] == "reference_entry"
                        else case["expected_values"])
            self.assertEqual(case["reference_result"]["values"], expected)

    def test_combinations_include_all_scalars_cfg_direction_tail_and_resource_arguments(self):
        programs = {case["program"] for case in cases()}
        self.assertTrue({"pair-" + typ for typ in ("u8", "u16", "u32", "u64", "usize", "bool")} <= programs)
        self.assertTrue({"triple-mixed", "triple-backward-call", "pair-branch", "pair-loop",
                         "pair-tail", "pair-borrowed-argument", "pair-owned-argument"} <= programs)
        values = [value for case in cases() for value in case["expected_values"]]
        self.assertIn((1 << 64) - 1, values)
        self.assertIn(1 << 63, values)
        self.assertTrue(any(case["owned_elf_only"] for case in cases()))
        self.assertFalse(self.reference["returned_resources_supported"])
        self.assertFalse(self.reference["public_entry_abi_changed"])
        self.assertFalse(self.reference["all_input_correctness_proved"])

    def test_empty_results_observe_effects_and_do_not_discard_scalars(self):
        void = [case for case in self.reference["cases"] if case["program"].startswith("void-")]
        self.assertEqual(len(void), 20)
        self.assertEqual({case["program"] for case in void}, {
            "void-empty", "void-write", "void-backward", "void-branch", "void-loop", "void-tail", "void-owned"})
        old = [case for case in self.reference["cases"] if not case["program"].startswith("void-")]
        self.assertEqual(len(old), 43)
        negatives = {case["id"]: case for case in self.reference["refusals"]}
        self.assertEqual(negatives["call-discarded-results"]["reference_result"]["status"], "rejected")
        for name in ("void-call-invented-result", "void-return-invented-result", "void-owner-leaked",
                     "void-owner-live-loan", "void-write-effect-missing"):
            self.assertEqual(negatives[name]["reference_result"]["status"], "rejected")

    def test_invalid_core_and_valid_outside_profile_remain_distinct(self):
        self.assertEqual(len(self.reference["refusals"]), len(refusals()))
        outside = {case["id"] for case in self.reference["refusals"]
                   if case["reference_result"]["status"] == "accepted"}
        self.assertEqual(outside, {"entry-multiple-results", "four-scalar-results", "tail-results-reordered",
                                  "tail-result-replaced", "tail-result-then-operation", "returned-owner-second",
                                  "void-entry", "void-tail-not-immediate"})
        for case in self.reference["refusals"]:
            self.assertEqual(case["reference_result"]["status"], case["general_core_expected"])


if __name__ == "__main__":
    unittest.main()
