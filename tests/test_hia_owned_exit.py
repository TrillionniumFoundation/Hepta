"""Actual selected owner/exit boundaries and resource-event counterexamples.

These tests exercise the production checker/VM and independent projection.
The mandatory standalone qualifier executes pinned Lean and never skips;
these dependency-free unit tests do not claim to execute a proof kernel.
"""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_owned_exit_core import (
    OwnedExitRejected, check_call_erasure, erase_calls, evaluate_model, export_core,
)
from tools import qualify_hia_owned_exit as qualification


def operation(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args),
            "out": [{"name": n, "type": t} for n, t in out], "attrs": attrs}


def entry(document):
    return next(fn for fn in document["functions"] if fn["name"] == "run")


def block(document, ident):
    return next(b for b in entry(document)["blocks"] if b["id"] == ident)


class OwnedExitProjectionTests(unittest.TestCase):
    def setUp(self):
        self.core = json.loads(qualification.SELECTED.read_bytes())

    def test_actual_closed_call_and_candidate_project_independently(self):
        source, candidate, generated, mappings = qualification.generated_pair(self.core)
        self.assertNotEqual(source.core_sha256, candidate.core_sha256)
        self.assertEqual(source.tree.tag, "call_allocate")
        self.assertEqual(candidate.tree.tag, "allocate")
        self.assertEqual(erase_calls(source.tree), candidate.tree)
        self.assertEqual(mappings["source"]["allocator_body"]["ops"][0]["op"], "buffer.try_new")
        self.assertIn("selected_trap_retains_owner", generated)
        self.assertIn("selected_call_erasure", generated)

    def test_ssa_alpha_renaming_does_not_replace_actual_semantics(self):
        changed = deepcopy(self.core)
        for fn in changed["functions"]:
            names = {p["name"]: "renamed_" + p["name"]
                     for b in fn["blocks"] for p in b["params"]}
            names.update({p["name"]: "renamed_" + p["name"]
                          for b in fn["blocks"] for op in b["ops"] for p in op["out"]})
            for p in fn["params"]:
                p["name"] = names[p["name"]]
            for b in fn["blocks"]:
                for p in b["params"]:
                    p["name"] = names[p["name"]]
                for op in b["ops"]:
                    op["args"] = [names[n] for n in op["args"]]
                    for p in op["out"]:
                        p["name"] = names[p["name"]]
                term = b["term"]
                if term["op"] == "ret":
                    term["values"] = [names[n] for n in term["values"]]
                if term["op"] == "branch":
                    term["cond"] = names[term["cond"]]
                    for side in ("then", "else"):
                        term[side]["args"] = [names[n] for n in term[side]["args"]]
        old, new = export_core(self.core), export_core(changed)
        self.assertEqual(old.tree, new.tree)
        self.assertNotEqual(old.core_sha256, new.core_sha256)
        self.assertEqual(qualification.generated_pair(changed)[0].tree, old.tree)

    def test_explicit_v7_and_v8_share_only_the_admitted_resource_profile(self):
        older = deepcopy(self.core)
        older["schema"] = "hepta.hia.program.v7"
        self.assertEqual(export_core(older).tree, export_core(self.core).tree)
        older["schema"] = "hepta.hia.program.v5"
        with self.assertRaises((OwnedExitRejected, HIAProgramRejected)):
            export_core(older)

    def test_missing_drop_and_duplicate_drop_are_real_core_rejections(self):
        for ops in ("missing", "duplicate"):
            changed = deepcopy(self.core)
            finished = block(changed, "finished")
            if ops == "missing":
                finished["ops"].pop(0)
            else:
                finished["ops"].insert(1, deepcopy(finished["ops"][0]))
            with self.subTest(ops=ops), self.assertRaises(HIAProgramRejected):
                export_core(changed)

    def test_wrong_callee_return_order_is_rejected_before_projection(self):
        changed = deepcopy(self.core)
        maker = next(fn for fn in changed["functions"] if fn["name"] == "make")
        maker["blocks"][0]["term"]["values"].reverse()
        with self.assertRaises(HIAProgramRejected):
            export_core(changed)

    def test_false_flag_substitution_in_valid_callee_is_outside_profile(self):
        changed = deepcopy(self.core)
        maker = next(fn for fn in changed["functions"] if fn["name"] == "make")
        maker["blocks"][0]["ops"].append(operation("const", out=[("replacement", "bool")], value=False))
        maker["blocks"][0]["term"]["values"][1] = "replacement"
        verify_program(changed)
        with self.assertRaisesRegex(OwnedExitRejected, "exactly one"):
            export_core(changed)

    def test_second_simultaneous_owner_cannot_inherit_single_owner_proof(self):
        changed = deepcopy(self.core)
        finished = block(changed, "finished")
        finished["ops"][:0] = [
            operation("const", out=[("second_extent", "usize")], value=4),
            operation("buffer.try_new", ["second_extent"], [("second_owner", "buffer"), ("second_ok", "bool")]),
            operation("owner.drop", ["second_owner"]),
        ]
        verify_program(changed)
        with self.assertRaisesRegex(OwnedExitRejected, "empty owner phase"):
            export_core(changed)

    def test_valid_owner_move_does_not_silently_expand_profile(self):
        changed = deepcopy(self.core)
        first = block(changed, "entry")
        first["ops"].append(operation("owner.move", ["owned"], [("moved", "buffer")]))
        for side in ("then", "else"):
            first["term"][side]["args"][0] = "moved"
        verify_program(changed)
        with self.assertRaisesRegex(OwnedExitRejected, "unsupported actual opcode owner.move"):
            export_core(changed)

    def test_valid_owner_carrying_loop_is_rejected_by_finite_projection(self):
        changed = deepcopy(self.core)
        finished = block(changed, "finished")
        finished["ops"] = []
        finished["term"] = {"op": "jump", "target": "finished", "args": ["finished_owned"]}
        verify_program(changed)
        with self.assertRaisesRegex(OwnedExitRejected, "cycles"):
            export_core(changed)

    def test_valid_changed_cancellation_result_cannot_inherit_transform(self):
        source, candidate, _, _ = qualification.mutation_inputs(self.core)[
            "actual_candidate_changes_cancel_result"]
        verify_program(candidate.core_bytes)
        with self.assertRaisesRegex(OwnedExitRejected, "call-erasure relation"):
            check_call_erasure(source.core_bytes, candidate.core_bytes)

    def test_older_success_flag_cannot_be_confused_with_latest_allocation(self):
        changed = deepcopy(self.core)
        first = block(changed, "entry")
        first["ops"].extend([
            operation("owner.drop", ["owned"]),
            operation("buffer.try_new", ["size"], [("later_owner", "buffer"), ("later_ok", "bool")]),
        ])
        for side in ("then", "else"):
            first["term"][side]["args"][0] = "later_owner"
        verify_program(changed)
        with self.assertRaisesRegex(OwnedExitRejected, "older allocation flag"):
            export_core(changed)

    def test_sequential_allocation_drop_cycles_compose_with_failure_ordinal(self):
        changed = deepcopy(self.core)
        finished = block(changed, "finished")
        finished["ops"][1:1] = [
            operation("const", out=[("later_extent", "usize")], value=4),
            operation("buffer.try_new", ["later_extent"], [("later_owner", "buffer"), ("later_ok", "bool")]),
            operation("owner.drop", ["later_owner"]),
        ]
        exported = export_core(changed)
        model = evaluate_model(exported.tree, 8, False, False, quota=8, allocation_fail_at=2)
        actual = qualification.observe_vm(exported.core_bytes, [8, False, False], quota=8, fail_at=2)
        self.assertEqual(model["resource_events"], actual["resource_events"])
        for name in qualification.MODELED_COUNTERS:
            self.assertEqual(model["resources"][name], actual["resources"][name])
        self.assertEqual(actual["resources"]["owners_created"], 2)
        self.assertEqual(actual["resources"]["owners_dropped"], 2)
        self.assertEqual(actual["resources"]["allocation_attempts"], 2)
        self.assertEqual(actual["resources"]["allocations"], 1)
        self.assertEqual(actual["resources"]["frees"], 1)

    def test_mapping_is_fresh_and_contains_actual_opcode_identity(self):
        exported = export_core(self.core)
        mapping = exported.mapping()
        mapping["instructions"].clear()
        self.assertTrue(exported.mapping()["instructions"])
        self.assertIn("hepta/hia_opcodes.py", qualification.SOURCE_FILES)
        self.assertIn("hepta/hia_program_runtime.py", qualification.SOURCE_FILES)

    def test_exact_machine_values_reject_boolean_size_or_integer_cancel(self):
        tree = export_core(self.core).tree
        for arguments in ((True, False, False), (0, 1, False), (1 << 64, False, False)):
            with self.subTest(arguments=arguments), self.assertRaises(OwnedExitRejected):
                evaluate_model(tree, *arguments, quota=8)

    def test_unpinned_tool_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            fake, evidence = Path(temp) / "lean", Path(temp) / "evidence"
            fake.write_text("#!/bin/sh\nexit 99\n")
            fake.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "fixed pin"):
                qualification.qualify(fake, evidence)
            self.assertFalse(evidence.exists())


class OwnedExitRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source, cls.candidate, _, _ = qualification.generated_pair(
            qualification.SELECTED.read_bytes())

    def run_case(self, arguments, quota=8, fail_at=None):
        return qualification.observe_vm(self.source.core_bytes, arguments, quota=quota, fail_at=fail_at)

    def test_zero_success_is_owner_capability_without_allocator_attempt(self):
        result = self.run_case([0, False, False], quota=0, fail_at=1)
        ledger = result["resources"]
        self.assertEqual((result["status"], result["value"]), ("returned", 0))
        self.assertEqual((ledger["owners_created"], ledger["owners_dropped"]), (1, 1))
        self.assertEqual((ledger["allocation_attempts"], ledger["allocations"], ledger["frees"]), (0, 0, 0))

    def test_oversize_refusal_precedes_quota_and_attempt(self):
        result = self.run_case([1 << 63, True, True], quota=0, fail_at=1)
        self.assertEqual((result["status"], result["value"]), ("returned", 1))
        self.assertEqual(result["resources"]["allocation_attempts"], 0)
        self.assertEqual(result["resources"]["owners_dropped"], 1)

    def test_quota_stop_does_not_become_fallible_refusal(self):
        result = self.run_case([1, True, True], quota=0, fail_at=1)
        self.assertEqual((result["status"], result["error"]), ("budget_exceeded", "heap"))
        self.assertIsNone(result["value"])
        self.assertEqual(result["resources"]["owners_created"], 0)
        self.assertEqual(result["resources"]["allocation_attempts"], 0)
        self.assertEqual(result["resource_events"], [{"kind": "heap_stop", "requested": 1}])

    def test_positive_allocator_refusal_consumes_attempt_and_drops_empty_owner(self):
        result = self.run_case([8, True, True], fail_at=1)
        ledger = result["resources"]
        self.assertEqual(result["value"], 1)
        self.assertEqual((ledger["allocation_attempts"], ledger["owners_created"], ledger["owners_dropped"]), (1, 1, 1))
        self.assertEqual((ledger["allocations"], ledger["frees"]), (0, 0))

    def test_cooperative_cancellation_after_success_releases_before_return(self):
        result = self.run_case([8, True, True])
        self.assertEqual((result["status"], result["value"]), ("returned", 2))
        self.assertEqual((result["resources"]["allocations"], result["resources"]["frees"]), (1, 1))
        self.assertEqual(result["resources"]["live_owners"], 0)
        self.assertEqual([e["kind"] for e in result["events"]],
                         ["call_enter", "allocate", "call_return", "drop"])

    def test_explicit_trap_retains_actual_payload_and_owner_ledger(self):
        result = self.run_case([8, False, True])
        ledger = result["resources"]
        self.assertEqual((result["status"], result["error"]), ("trapped", "division_by_zero"))
        self.assertEqual((ledger["live_owners"], ledger["live_bytes"], ledger["peak_bytes"]), (1, 8, 8))
        self.assertEqual((ledger["owners_dropped"], ledger["frees"]), (0, 0))
        self.assertEqual(len(result["resource_events"]), 1)

    def test_empty_owner_is_still_live_on_trap(self):
        result = self.run_case([0, False, True], quota=0)
        self.assertEqual(result["resources"]["live_owners"], 1)
        self.assertEqual(result["resources"]["live_bytes"], 0)
        self.assertEqual(result["resources"]["allocations"], 0)

    def test_step_and_depth_limits_must_be_requalified(self):
        observed = qualification.budget_observations(self.source, self.candidate)
        self.assertEqual(set(observed["stops"]), {"steps", "calls"})
        for case in observed["stops"].values():
            self.assertEqual(case["source"]["status"], "budget_exceeded")
            self.assertEqual(case["candidate"]["status"], "returned")

    def test_frozen_cases_compare_actual_vm_full_ledger_trace_and_model(self):
        cases = qualification.vm_observations(self.source, self.candidate)
        self.assertEqual(len(cases), 192)
        self.assertEqual({row["source"]["status"] for row in cases},
                         {"returned", "trapped", "budget_exceeded"})


if __name__ == "__main__":
    unittest.main()
