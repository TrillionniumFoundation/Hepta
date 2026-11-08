"""Independent Core reference checks for the finite owned-flow native corpus."""
from __future__ import annotations

import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected
from tools.hia_selfhost_owned_elf_cases import reference
from tools.hia_selfhost_owned_flow_cases import cases, refusals, profile_refusal_ids


class OwnedFlowSourceTests(unittest.TestCase):
    def test_positive_flows_release_every_owned_value_and_local_loan(self):
        rows = cases()
        self.assertEqual(len(rows), 14)
        self.assertEqual(len({row["id"] for row in rows}), len(rows))
        for case in rows:
            with self.subTest(case=case["id"]):
                report = reference(case)
                self.assertEqual(report["status"], "returned")
                self.assertEqual(report["result"], case["expected_result"])
                self.assertEqual(report["external_output_hex"], case["expected_output_hex"])
                for field in ("live_owners", "live_bytes", "live_local_loans", "live_chains", "live_chain_nodes"):
                    self.assertEqual(report["resources"][field], 0)
                self.assertEqual(report["resources"]["loans_started"], report["resources"]["loans_ended"])
                self.assertFalse(report["claims"]["whole_language_soundness_proved"])

    def test_core_rejections_and_valid_profile_exclusions_stay_distinct(self):
        rows, outside = refusals(), profile_refusal_ids()
        self.assertEqual(len(rows), 34)
        self.assertEqual(len(outside), 8)
        for name, source in rows.items():
            with self.subTest(case=name):
                if name in outside:
                    assemble_program(source)
                else:
                    with self.assertRaises(HIAProgramRejected):
                        assemble_program(source)

    def test_flat_type_exclusions_do_not_depend_on_allocator_opcodes(self):
        rows = refusals()
        for suffix in ("owner-parameter", "owner-tail"):
            checked = assemble_program(rows["flow-profile-flat-dormant-" + suffix]).as_dict()
            self.assertEqual(checked["module"], "selfhost")
            ops = {op["op"] for fn in checked["functions"] for block in fn["blocks"] for op in block["ops"]}
            self.assertTrue(ops <= {"const", "call"})
            self.assertTrue(any(param["type"] == "buffer" for fn in checked["functions"] for param in fn["params"]))


if __name__ == "__main__":
    unittest.main()
