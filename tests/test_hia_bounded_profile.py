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

from hepta.core import build_core, execute_core
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

    def test_every_allocator_denial_preserves_normal_error_cleanup(self):
        source = fallible_module()
        expected = self.qualify(source, max_live_heap_bytes=8)
        for denial in (None, 1, 2, 3, 4):
            with self.subTest(denial=denial):
                observed = execute_core(source, "fallible_entry", [], allocation_fail_at=denial,
                    bounded_resource_limits=policy(max_live_heap_bytes=8))
                self.assertEqual(observed["result"], 0 if denial in (1, 2, 3) else 1)
                ledger = observed["resources"]
                self.assertEqual(ledger["live_owners"], 0)
                self.assertEqual(ledger["live_local_loans"], 0)
                self.assertEqual(ledger["allocations"], ledger["frees"])
                self.assertLessEqual(ledger["peak_bytes"], 8)
                self.assertLessEqual(ledger["allocation_attempts"] + ledger["frees"], 6)
                self.assertEqual(observed["bounded_resources"], expected)
                self.assertLessEqual(observed["steps"], expected["exports"][0]["max_vm_ticks"])

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

    def test_mutable_and_shared_returned_loans_keep_the_same_canonical_rules(self):
        for mode in ("read", "mut"):
            for construction in ("forward", "child", "cfg"):
                source = fixed_loan_program(mode, construction)
                name = source["exports"][0]
                limits = policy(max_live_heap_bytes=8)
                observed = execute_core(source, name, [37], bounded_resource_limits=limits)
                self.assertEqual(observed["resources"]["live_local_loans"], 0)
                self.assertEqual(observed["resources"]["peak_bytes"], 8)
                self.assertEqual(observed["bounded_resources"]["core_sha256"], verify_program(source).sha256)

    def test_all_exports_are_qualified_even_when_running_only_one(self):
        source = fallible_module()
        source["functions"].extend(unknown_size()["functions"])
        source["exports"].append("dynamic")
        with patch("hepta.hia_program_runtime._Machine.invoke") as invoked:
            with self.assertRaises(HIAHeapBoundRejected):
                execute_core(source, "fallible_entry", [], bounded_resource_limits=policy())
            invoked.assert_not_called()

    def test_a_saved_report_is_not_an_admission_token(self):
        source = fallible_module()
        receipt = self.qualify(source)
        source["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 500
        # Even using the same limit fields performs a fresh analysis of the
        # changed Core. A complete receipt is rejected as an unknown policy.
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
            execute_core(source, "fallible_entry", [], bounded_resource_limits=receipt["limits"])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_POLICY"):
            self.qualify_with(source, receipt)

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

    def test_smaller_runtime_limits_reject_before_running(self):
        source = fallible_module()
        for override in ({"max_steps": 2}, {"max_heap_bytes": 7}, {"max_call_depth": 2}):
            with patch("hepta.hia_program_runtime._Machine.invoke") as invoked:
                with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_POLICY"):
                    execute_core(source, "fallible_entry", [], bounded_resource_limits=policy(), **override)
                invoked.assert_not_called()

    def test_bounded_profile_does_not_turn_checked_overflow_into_an_error_value(self):
        source = exported(arithmetic(typ="u8"))
        with self.assertRaises(HIAProgramTrap) as stopped:
            execute_core(source, "calculate", [255, 1], bounded_resource_limits=policy())
        self.assertEqual(stopped.exception.code, "overflow")
        self.assertEqual(stopped.exception.report["status"], "trapped")
        self.assertFalse(stopped.exception.report["bounded_resources"]["claims"]["program_traps_excluded"])
        wrapped = exported(arithmetic("int.add.wrap", "u8"))
        self.assertEqual(execute_core(wrapped, "calculate", [255, 1],
            bounded_resource_limits=policy())["result"], 0)

    def test_existing_profile_remains_unchanged_when_not_requested(self):
        source = local_buffers()
        result = execute_core(source, "finite", [])
        self.assertEqual(result["result"], 8)
        self.assertNotIn("bounded_resources", result)

    def test_budget_failure_is_before_native_emission_and_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "bounded.so"
            with patch("hepta.hia_program_llvm.emit_program_llvm") as emitted:
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
                    build_core(fallible_module(), destination,
                        bounded_resource_limits=policy(max_live_heap_bytes=7))
                emitted.assert_not_called()
                self.assertFalse(destination.exists())

    @unittest.skipUnless(CANONICAL_CLANG, "actual Clang 20+ required")
    def test_actual_native_allocation_denials_match_bounded_vm_observations(self):
        source = fallible_module()
        limits = policy(max_live_heap_bytes=8)
        # Reuse the existing independent allocator observer, with its actual
        # production object build entering the new optional profile.
        def bounded_builder(*args, **kwargs):
            return build_program_native(*args, **kwargs, bounded_resource_limits=limits)
        with tempfile.TemporaryDirectory() as folder:
            with patch("tests.test_hia_returned_loans.build_program_native", bounded_builder):
                binary, receipt = build_allocator_observer(source, folder,
                    {"fallible_entry": ("void", "fallible_entry()")})
            self.assertEqual(receipt["core_sha256"], receipt["bounded_resources"]["core_sha256"])
            self.assertFalse(receipt["claims"]["backend_refinement_proved"])
            for denial in range(5):
                native = subprocess.run([str(binary), "fallible_entry", str(denial)],
                    check=True, capture_output=True, text=True, timeout=10)
                got = json.loads(native.stdout)
                vm = execute_core(source, "fallible_entry", [],
                    allocation_fail_at=denial or None, bounded_resource_limits=limits)
                self.assertEqual(got["result"], vm["result"])
                for native_key, vm_key in (("attempts", "allocation_attempts"),
                        ("allocations", "allocations"), ("frees", "frees"),
                        ("peak_bytes", "peak_bytes"), ("live_bytes", "live_bytes")):
                    self.assertEqual(got[native_key], vm["resources"][vm_key])
                self.assertEqual(got["bad_frees"], 0)
                self.assertEqual(got["live_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
