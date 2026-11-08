"""Core references for finite dynamic-chain successor witnesses."""
from __future__ import annotations

import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import HIAProgramRejected
from tools.hia_selfhost_chain_cases import cases
from tools.hia_selfhost_chain_flow_cases import cases as flow_cases, refusals, profile_refusal_ids
from tools.hia_selfhost_owned_elf_cases import reference
from tools.hia_selfhost_parameter_cases import cases as parameter_cases, refusals as parameter_refusals


class ChainSourceTests(unittest.TestCase):
    def test_all_six_operations_have_valid_typed_core_witnesses(self):
        observed = set()
        for case in cases():
            checked = assemble_program(case["source"]).as_dict()
            observed.update(op["op"] for fn in checked["functions"] for block in fn["blocks"] for op in block["ops"])
        self.assertEqual({op for op in observed if op.startswith("chain.")},
            {"chain.empty", "chain.try_push", "chain.pop", "chain.is_empty", "chain.head_read", "chain.head_mut"})

    def test_independent_core_observes_results_traps_and_prior_writes(self):
        rows = cases()
        self.assertEqual(len(rows), 12)
        self.assertEqual(len({case["id"] for case in rows}), len(rows))
        for case in rows:
            with self.subTest(case=case["id"]):
                result = reference(case)
                self.assertEqual(result["external_output_hex"], case["expected_output_hex"])
                if "expected_trap" in case:
                    self.assertEqual(result["status"], "trapped")
                    self.assertEqual(result["error"]["code"], "bounds")
                else:
                    self.assertEqual(result["result"], case["expected_result"])
                    for field in ("live_owners", "live_bytes", "live_local_loans", "live_chains", "live_chain_nodes"):
                        self.assertEqual(result["resources"][field], 0)
                    self.assertEqual(result["resources"]["loans_started"], result["resources"]["loans_ended"])

    def test_runtime_sized_chains_release_payload_and_node_storage(self):
        for case in cases():
            if case["id"] in {"lifo-pop-loop-5000", "iterative-drop-loop-5000"}:
                with self.subTest(case=case["id"]):
                    resources = reference(case)["resources"]
                    self.assertEqual(resources["chain_nodes_created"], 5000)
                    self.assertEqual(resources["chain_nodes_dropped"], 5000)
                    self.assertEqual(resources["allocations"], 10000)
                    self.assertEqual(resources["frees"], 10000)

    def test_independent_flow_inputs_close_chain_roots_and_nested_loans(self):
        rows = flow_cases()
        self.assertEqual(len(rows), 13)
        for case in rows:
            with self.subTest(case=case["id"]):
                resources = reference(case)["resources"]
                for field in ("live_owners", "live_bytes", "live_local_loans", "live_chains", "live_chain_nodes"):
                    self.assertEqual(resources[field], 0)

    def test_invalid_core_stays_distinct_from_valid_profile_exclusions(self):
        rows, outside = refusals(), profile_refusal_ids()
        self.assertEqual(len(rows), 75)
        self.assertEqual(len(outside), 19)
        for name, source in rows.items():
            with self.subTest(case=name):
                if name in outside:
                    assemble_program(source)
                else:
                    with self.assertRaises(HIAProgramRejected):
                        assemble_program(source)

    def test_resource_block_parameters_reach_the_exact_ssa_boundary(self):
        rows = parameter_cases()
        self.assertEqual(len(rows), 4)
        for case in rows:
            with self.subTest(case=case["id"]):
                result = reference(case)
                self.assertEqual(result["status"], "returned")
                self.assertEqual(result["result"], case["expected_result"])

    def test_high_resource_parameter_names_are_valid_core_profile_exclusions(self):
        rows = parameter_refusals()
        self.assertEqual(len(rows), 24)
        for name, source in rows.items():
            with self.subTest(case=name):
                assemble_program(source)


if __name__ == "__main__":
    unittest.main()
