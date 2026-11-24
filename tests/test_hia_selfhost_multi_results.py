"""Independent finite contract checks for bounded native scalar result tuples."""
from __future__ import annotations

import unittest

from tools.hia_selfhost_multi_results import cases, refusals, independent_reference


class SelfhostMultiResultSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = independent_reference()

    def test_tuple_values_match_independent_full_width_core_vm_observations(self):
        self.assertEqual(len(self.reference["cases"]), 166)
        self.assertEqual(len({case["program"] for case in self.reference["cases"]}), 52)
        self.assertEqual(sum(not row["program"].startswith("recursion-promoted-") for row in self.reference["cases"]), 144)
        for case in self.reference["cases"]:
            self.assertEqual(case["reference_result"]["status"], "returned")
            expected = ([case["expected_result"], *bytes.fromhex(case["expected_hex"])] if case["reference_entry"] == "reference_entry"
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
        self.assertTrue(self.reference["returned_resources_supported"])
        self.assertTrue(self.reference["returned_loans_supported"])
        self.assertFalse(self.reference["public_entry_abi_changed"])
        self.assertFalse(self.reference["all_input_correctness_proved"])

    def test_empty_results_observe_effects_and_do_not_discard_scalars(self):
        void = [case for case in self.reference["cases"] if case["program"].startswith("void-")]
        self.assertEqual(len(void), 20)
        self.assertEqual({case["program"] for case in void}, {
            "void-empty", "void-write", "void-backward", "void-branch", "void-loop", "void-tail", "void-owned"})
        old = [case for case in self.reference["cases"] if not case["program"].startswith(("void-", "owner-", "loan-", "extended-", "recursion-promoted-"))]
        self.assertEqual(len(old), 43)
        negatives = {case["id"]: case for case in self.reference["refusals"]}
        self.assertEqual(negatives["call-discarded-results"]["reference_result"]["status"], "rejected")
        for name in ("void-call-invented-result", "void-return-invented-result", "void-owner-leaked",
                     "void-owner-live-loan", "void-write-effect-missing"):
            self.assertEqual(negatives[name]["reference_result"]["status"], "rejected")

    def test_owned_returns_keep_full_descriptors_and_linear_cleanup(self):
        owned = [c for c in self.reference["cases"] if c["program"].startswith("owner-")]
        self.assertEqual(len(owned), 25)
        self.assertTrue({"owner-previously-refused", "owner-three-descriptors", "owner-backward-transfer",
            "owner-fallible-empty", "owner-chain-node-return", "owner-tail-transfer"}
            <= {c["program"] for c in owned})
        for case in owned:
            resources = case["reference_result"]["resources"]
            self.assertEqual(resources["live_owners"], 0, case["id"])
            self.assertEqual(resources["live_local_loans"], 0, case["id"])
        rejected = {c["id"]: c for c in self.reference["refusals"]}
        for name in ("duplicate", "live-child", "dropped", "leaked-sibling",
                     "caller-use-after-drop", "caller-live-child", "wrong-scalar-type"):
            self.assertEqual(rejected["owner-return-" + name]["reference_result"]["status"], "rejected")

    def test_four_to_six_results_cover_scalars_tail_loans_and_owners(self):
        extended = [r for r in self.reference["cases"] if r["program"].startswith("extended-")]
        self.assertEqual(len(extended), 20)
        self.assertEqual({r["program"] for r in extended}, {
            "extended-four-previously-refused", "extended-4-mixed", "extended-5-mixed",
            "extended-6-mixed", "extended-six-backward", "extended-six-tail", "extended-six-loan-owner"})
        for row in extended:
            self.assertEqual(row["reference_result"]["resources"]["live_owners"], 0, row["id"])
            self.assertEqual(row["reference_result"]["resources"]["live_local_loans"], 0, row["id"])
        refused = {r["id"]: r for r in self.reference["refusals"]}
        self.assertEqual(refused["seven-scalar-results"]["reference_result"]["status"], "accepted")
        for name in ("six-fourth-wrong-formal-origin", "six-sixth-wrong-type"):
            self.assertEqual(refused[name]["reference_result"]["status"], "rejected")

    def test_reference_wrapper_materializes_exact_zero_repeated_and_mixed_bytes(self):
        from tools.hia_selfhost_cases import HEADER
        from tools.hia_selfhost_loans import reference_source
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program import execute_program
        samples = (bytes(96), bytes([165]) * 96,
                   bytes([0, 0, 7, 7, 7, 0, 255, 1, 255, 0]) * 9)
        for raw in samples:
            source = (HEADER + '  v3:usize = const() {"value":' + str(len(raw)) + '}\n'
                '  _ = buffer.copy(v1,v0,v3)\n  v4:u32 = const() {"value":0}\n  ret(v4)\nend\n')
            case = {"source": source, "source_hex": raw.hex(), "initial_hex": "a5" * len(raw)}
            result = execute_program(assemble_program(reference_source(case)), "reference_entry", [])
            self.assertEqual(result["values"], [0, *raw])
            self.assertEqual(result["resources"]["live_owners"], 0)

    def test_invalid_core_and_valid_outside_profile_remain_distinct(self):
        self.assertEqual(len(self.reference["refusals"]), len(refusals()))
        outside = {case["id"] for case in self.reference["refusals"]
                   if case["reference_result"]["status"] == "accepted" and case["native_profile_expected"] == "rejected"}
        self.assertEqual(outside, {"entry-multiple-results", "seven-scalar-results",
                                  "void-entry", "owner-return-flat-output"})
        from tools.hia_selfhost_recursion import MULTI_PROMOTIONS
        self.assertEqual({row["id"] for row in self.reference["refusals"]
            if row["native_profile_expected"] == "compiled"}, MULTI_PROMOTIONS)
        promoted = [row for row in self.reference["cases"] if "historical_refusal_id" in row]
        self.assertEqual(len(promoted), 22)
        frozen = {row["id"]: row["source"] for row in refusals()}
        self.assertTrue(all(row["source"] == frozen[row["historical_refusal_id"]] for row in promoted))
        for case in self.reference["refusals"]:
            self.assertEqual(case["reference_result"]["status"], case["general_core_expected"])


if __name__ == "__main__":
    unittest.main()
