"""Fresh composed resource admission on the real VM and native build routes.

Finite native observations below do not discharge the checker/model or
LLVM/machine-code refinement obligations. The production profile reuses the
canonical checker and existing independent event/payload analyses.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_heap_bound import HIAHeapBoundRejected
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import HIAStaticBudgetRejected, qualify_bounded_resources
from tests.test_hia_program import arithmetic, b, c, f, i, ret
from tests.test_hia_heap_bound import local_buffers, unknown_size
from tests.test_hia_returned_loans import CANONICAL_CLANG, build_allocator_observer
from tests.test_hia_returned_loan_budgets import (
    fixed_loan_program, looping_loan_program, temporary_loan_program,
)
from tests.test_hia_static_budget import cyclic_calls, cyclic_control_flow


def policy(**changes):
    return {"max_allocator_interactions": 6, "max_vm_ticks": 32,
            "max_call_depth": 3, "max_live_heap_bytes": 12, **changes}


def exported(source, *names):
    source = deepcopy(source)
    source["exports"] = list(names) or [source["functions"][-1]["name"]]
    return source


def fallible_module():
    """All three allocation failures are ordinary error-as-value returns."""
    source = temporary_loan_program(nested=True)
    relay, main = source["functions"][1:]
    relay["blocks"][0]["ops"].append(
        i("bool.and", ["allocated", "ok"], [("both", "bool")]))
    relay["blocks"][0]["term"]["values"][1] = "both"
    ops = main["blocks"][0]["ops"]
    allocation = next(op for op in ops if op["op"] == "buffer.new")
    allocation["op"] = "buffer.try_new"
    allocation["out"].append({"name": "outer_ok", "type": "bool"})
    ops[:] = [op for op in ops if op["op"] != "buffer.load"]
    result = next(op for op in ops if op["op"] == "select")
    ops.insert(ops.index(result), i("bool.and", ["outer_ok", "ok"], [("all_ok", "bool")]))
    result["args"][0] = "all_ok"
    return source


class BoundedProfileTests(unittest.TestCase):
    def qualify(self, source, **limits):
        return qualify_bounded_resources(source, limits=policy(**limits))

    def test_existing_v1_analysis_and_explicit_inventory(self):
        source = exported(local_buffers())
        result = self.qualify(source)
        self.assertEqual(result["exports"], [{"function": "finite",
            "max_allocator_interactions": 4, "max_vm_ticks": 9,
            "max_call_depth": 1, "max_live_heap_bytes": 12}])
        self.assertEqual(result["core_sha256"], verify_program(source).sha256)
        self.assertEqual(result["borrowed_entry_payload"], [])
        unsigned = {key: value for key, value in result.items() if key != "sha256"}
        raw = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertEqual(result["sha256"], sha256(raw).hexdigest())

    def test_v8_calls_and_returned_loans_use_existing_entry_payload_analyses(self):
        source = fallible_module()
        result = self.qualify(source, max_live_heap_bytes=8)
        self.assertEqual(result["exports"][0]["max_live_heap_bytes"], 8)
        self.assertEqual(result["exports"][0]["max_call_depth"], 3)
        self.assertEqual(result["borrowed_entry_payload"][0]["peak_bound_bytes"], 8)
        self.assertEqual(result["static_events"]["schema"], "hepta.hia.static-budget.v2")
        self.assertFalse(result["claims"]["checker_to_formal_model_refinement_proved"])
        self.assertFalse(result["claims"]["source_to_core_or_native_backend_refinement_proved"])
        self.assertFalse(result["claims"]["retained_receipt_grants_admission"])


    def test_empty_owners_are_not_allocator_success_assumptions(self):
        source = fallible_module()
        for fn in source["functions"]:
            for op in fn["blocks"][0]["ops"]:
                if op["op"] == "const" and op["out"][0]["type"] == "usize":
                    op["attrs"]["value"] = 0
        observed = execute_program(source, "fallible_entry", [], allocation_fail_at=1,
            bounded_resource_limits=policy(max_live_heap_bytes=0))
        self.assertEqual(observed["result"], 1)
        self.assertEqual(observed["resources"]["allocation_attempts"], 0)
        self.assertEqual(observed["resources"]["peak_bytes"], 0)
        self.assertEqual(observed["resources"]["owners_created"], 3)
        self.assertEqual(observed["resources"]["owners_dropped"], 3)




    def qualify_with(self, source, limits):
        return qualify_bounded_resources(source, limits=limits)

    def test_policy_requires_all_exact_typed_fields_and_captures_values(self):
        source = fallible_module()
        bad = [None, [], {}, {**policy(), "sha256": "0" * 64},
               {key: value for key, value in policy().items() if key != "max_call_depth"}]
        for key in policy():
            for value in (True, False, -1, 1.0, "1", None):
                bad.append(policy(**{key: value}))
        bad.extend([policy(max_vm_ticks=0), policy(max_vm_ticks=10_000_001),
                    policy(max_call_depth=0), policy(max_call_depth=257),
                    policy(max_live_heap_bytes=1024 * 1024 * 1024 + 1)])
        for limits in bad:
            with self.subTest(limits=limits), self.assertRaises(HIAStaticBudgetRejected):
                self.qualify_with(source, limits)
        limits = policy()
        result = self.qualify_with(source, limits)
        limits["max_live_heap_bytes"] = 0
        self.assertEqual(result["limits"]["max_live_heap_bytes"], 12)

    def test_unsupported_cfg_calls_schema_and_implicit_exports_fail_closed(self):
        for source in (exported(cyclic_calls()), exported(cyclic_control_flow()), looping_loan_program()):
            with self.subTest(schema=source["schema"]), self.assertRaisesRegex(
                    HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
                self.qualify(source)
        for source in (local_buffers(), {**exported(local_buffers()), "exports": []},
                       {**exported(local_buffers()), "schema": "hepta.hia.program.v7"}):
            with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_PROFILE"):
                self.qualify(source)

    def test_unreviewed_private_chain_cannot_hide_behind_a_byte_export(self):
        source = fallible_module()
        source["functions"].append(f("drop_chain", [("x", "chain")], [], ["alloc"], [
            b("entry", [("x", "chain")], [i("owner.drop", ["x"])], ret())]))
        verify_program(source)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_PROFILE"):
            self.qualify(source)

    def test_explicit_normal_error_still_requires_canonical_cleanup(self):
        source = fallible_module()
        ops = source["functions"][-1]["blocks"][0]["ops"]
        ops[:] = [op for op in ops if op["op"] != "owner.drop"]
        with self.assertRaises(HIAProgramRejected):
            self.qualify(source)







if __name__ == "__main__":
    unittest.main()
