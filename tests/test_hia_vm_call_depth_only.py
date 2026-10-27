"""Narrow v7 synchronous VM-call frame bound; never promote v7 tick/heap proofs."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from hepta.hia_program import HIAProgramRejected, SCHEMA_V7, verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramBudgetExceeded
from hepta.hia_static_budget import (
    HIAStaticBudgetRejected, analyze_static_budget, qualify_vm_call_depth,
)
from tests.test_hia_vm_call_depth import sequential_calls, recursively_nested


def v7(program):
    program = deepcopy(program)
    program["schema"] = SCHEMA_V7
    program["exports"] = [f["name"] for f in program["functions"]]
    return program


def cyclic_cfg():
    # Legal infinite CFG loop with no recursive function call.
    return {
        "schema": SCHEMA_V7, "module": "vm_frames_loop", "exports": ["spin"],
        "functions": [{
            "name": "spin", "params": [], "returns": [], "effects": [],
            "entry": "entry", "blocks": [
                {"id": "entry", "params": [], "ops": [],
                 "term": {"op": "jump", "target": "repeat", "args": []}},
                {"id": "repeat", "params": [], "ops": [],
                 "term": {"op": "jump", "target": "repeat", "args": []}},
            ],
        }],
    }


def chain_drop():
    return {
        "schema": SCHEMA_V7, "module": "vm_frames_chain", "exports": [],
        "functions": [{
            "name": "destroy", "params": [{"name": "tree", "type": "chain"}],
            "returns": [], "effects": ["alloc"], "entry": "entry", "blocks": [{
                "id": "entry", "params": [{"name": "tree", "type": "chain"}],
                "ops": [{"op": "owner.drop", "args": ["tree"],
                         "out": [], "attrs": {}}],
                "term": {"op": "ret", "values": []},
            }],
        }],
    }


class V7SynchronousFrameBudgetTests(unittest.TestCase):
    def test_valid_v7_bytes_and_source_have_identical_depth_receipt(self):
        source = v7(sequential_calls())
        canonical = verify_program(source)
        via_source = qualify_vm_call_depth(source, max_call_depth=2)
        via_bytes = qualify_vm_call_depth(canonical.canonical_bytes, max_call_depth=2)
        self.assertEqual(via_source, via_bytes)
        self.assertEqual(via_source["core_sha256"], canonical.sha256)
        self.assertEqual(via_source["core_schema"], SCHEMA_V7)
        depths = {r["function"]: r["max_call_depth"] for r in via_source["functions"]}
        self.assertEqual(depths, {"inner": 1, "outer": 2})
        self.assertTrue(via_source["claims"]["synchronous_hia_vm_frames_bounded"])
        for claim in ("vm_ticks_bounded", "allocator_interactions_bounded",
                      "process_rss_or_native_stack_bytes_bounded",
                      "async_task_stacks_bounded", "whole_language_soundness_proved"):
            self.assertIs(via_source["claims"][claim], False)
        self.assertEqual(execute_program(canonical, "outer", [7], max_call_depth=2)["result"], 7)
        with self.assertRaises(HIAProgramBudgetExceeded):
            execute_program(canonical, "outer", [7], max_call_depth=1)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_EXCEEDED"):
            qualify_vm_call_depth(canonical, max_call_depth=1)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_PROFILE"):
            analyze_static_budget(canonical)

    def test_v7_chain_drop_only_qualifies_synchronous_call_frames(self):
        canonical = verify_program(chain_drop())
        proof = qualify_vm_call_depth(canonical, max_call_depth=1)
        self.assertEqual(proof["functions"], [{"function": "destroy", "max_call_depth": 1}])
        self.assertFalse(proof["claims"]["allocator_interactions_bounded"])
        self.assertFalse(proof["claims"]["vm_ticks_bounded"])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_PROFILE"):
            analyze_static_budget(canonical, max_allocator_interactions=1)

    def test_cfg_loop_does_not_inflate_synchronous_stack(self):
        canonical = verify_program(cyclic_cfg())
        proof = qualify_vm_call_depth(canonical, max_call_depth=1)
        self.assertEqual(proof["functions"][0]["max_call_depth"], 1)
        self.assertFalse(proof["claims"]["vm_ticks_bounded"])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_PROFILE"):
            analyze_static_budget(canonical)

    def test_direct_recursion_remains_unknown_without_a_finite_proof(self):
        source = v7(recursively_nested())
        verify_program(source)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            qualify_vm_call_depth(source, max_call_depth=256)

    def test_typed_budget_and_untrusted_receipt_fail_closed(self):
        source = v7(sequential_calls())
        for budget in (None, False, True, 0, -1, 257, "2", 2.0):
            with self.subTest(budget=budget):
                with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_POLICY"):
                    qualify_vm_call_depth(source, max_call_depth=budget)
        forged = deepcopy(source)
        forged["claims"] = {"bounded": True}
        with self.assertRaises(HIAProgramRejected):
            qualify_vm_call_depth(forged, max_call_depth=2)


if __name__ == "__main__":
    unittest.main()
