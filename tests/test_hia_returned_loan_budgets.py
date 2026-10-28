"""Actual v8 resource analyses against canonical Core and interpreter ledgers."""
from copy import deepcopy
from hashlib import sha256
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, analyze_constant_live_heap, qualify_entry_live_heap_budget,
)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import (
    HIAProgramBudgetExceeded, HIAProgramTrap, execute_program,
)
from hepta.hia_static_budget import (
    HIAStaticBudgetRejected, analyze_static_budget, qualify_vm_call_depth,
)
from tests.test_hia_program import b, branch, c, f, i, jump, resource_program, ret
from tests.test_hia_returned_loans import (
    document, fallible_return_program, helper, loan_program, multiple_shared, swapped_mutable,
)
from tests.test_hia_returned_chain_loans import chain_program
from tests.test_hia_vm_call_depth_only import chain_drop


def fixed_loan_program(mode="read", construction="forward", size=8):
    source = loan_program(mode, construction)
    main = source["functions"][1]
    main["params"] = [{"name": "byte", "type": "u8"}]
    main["blocks"][0]["params"] = deepcopy(main["params"])
    main["blocks"][0]["ops"].insert(0, c("length", "usize", size))
    return source


def temporary_loan_program(*, nested=False, extra_owner=False):
    source = fallible_return_program()
    callee, main = source["functions"]
    # An independently fixed callee extent, not a caller-supplied size promise.
    callee["params"].pop()
    callee["blocks"][0]["params"].pop()
    callee["blocks"][0]["ops"].insert(0, c("size", "usize", 5))
    call = next(op for op in main["blocks"][0]["ops"] if op["op"] == "call")
    call["args"].pop()
    if extra_owner:
        ops = main["blocks"][0]["ops"]
        position = ops.index(call)
        ops[position:position] = [c("other_size", "usize", 3),
            i("buffer.new", ["other_size"], [("other", "buffer")])]
        ops.insert(next(n for n, op in enumerate(ops) if op["op"] == "owner.drop"),
                   i("owner.drop", ["other"]))
    if nested:
        params = [("input", "readbuf")]
        relay = f("relay", params, ["readbuf", "bool"], ["alloc"], [
            b("entry", params, [c("two", "usize", 2),
                i("buffer.try_new", ["two"], [("local", "buffer"), ("allocated", "bool")]),
                i("call", ["input"], [("child", "readbuf"), ("ok", "bool")], function="fallible"),
                i("owner.drop", ["local"])], ret("child", "ok"))])
        relay["return_loans"] = ["input", None]
        call["attrs"]["function"] = "relay"
        source["functions"].insert(1, relay)
    return source


def branch_loan_program():
    source = fixed_loan_program(size=4)
    callee, main = source["functions"]
    params = [("input", "readbuf"), ("flag", "bool")]
    callee["params"] = [{"name": name, "type": typ} for name, typ in params]
    callee["effects"] = ["alloc"]
    callee["blocks"] = [
        b("entry", params, [], branch("flag", ("left", "input"), ("right", "input"))),
        b("left", [("a", "readbuf")], [c("small", "usize", 3),
            i("buffer.try_new", ["small"], [("local_a", "buffer"), ("ok_a", "bool")]),
            i("owner.drop", ["local_a"])], jump("joined", "a")),
        b("right", [("z", "readbuf")], [c("large", "usize", 7),
            i("buffer.try_new", ["large"], [("local_z", "buffer"), ("ok_z", "bool")]),
            i("owner.drop", ["local_z"])], jump("joined", "z")),
        b("joined", [("root_again", "readbuf")], [], ret("root_again")),
    ]
    main["params"].append({"name": "flag", "type": "bool"})
    main["blocks"][0]["params"] = deepcopy(main["params"])
    next(op for op in main["blocks"][0]["ops"] if op["op"] == "call")["args"].append("flag")
    return source


def looping_loan_program():
    source = fixed_loan_program()
    main = source["functions"][1]
    ops = main["blocks"][0]["ops"]
    position = next(n for n, op in enumerate(ops) if op["op"] == "call")
    prefix, call = ops[:position], ops[position]
    call["args"] = ["loop_parent"]
    params = [("loop_owner", "buffer"), ("loop_parent", "readbuf")]
    main["returns"] = []
    main["blocks"] = [b("entry", [("byte", "u8")], prefix, jump("again", "owner", "parent")),
        b("again", params, [call, i("loan.end", ["returned"])],
          jump("again", "loop_owner", "loop_parent"))]
    return source


def returned_length_program():
    source = fixed_loan_program(size=8)
    ops = source["functions"][1]["blocks"][0]["ops"]
    position = next(n for n, op in enumerate(ops) if op["op"] == "call") + 1
    ops[position:position] = [i("buffer.len", ["returned"], [("returned_size", "usize")]),
        i("buffer.try_new", ["returned_size"], [("second", "buffer"), ("ok", "bool")]),
        i("owner.drop", ["second"])]
    return source


def external_length_program(*, checked_cast=False):
    source = temporary_loan_program()
    callee = source["functions"][0]
    ops = callee["blocks"][0]["ops"]
    ops[0:1] = [i("buffer.len", ["input"], [("extent", "usize")])]
    if checked_cast:
        ops[1:1] = [i("int.cast", ["extent"], [("small", "u8")], mode="checked"),
                    i("int.cast", ["small"], [("size", "usize")], mode="checked")]
        callee["effects"].append("trap")
    else:
        ops[1]["args"] = ["extent"]
    return source


class ReturnedLoanBudgetTests(unittest.TestCase):
    def assert_digest(self, report):
        unsigned = {key: value for key, value in report.items() if key != "sha256"}
        raw = json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode()
        self.assertEqual(report["sha256"], sha256(raw).hexdigest())

    def entry_heap(self, source, limit):
        return qualify_entry_live_heap_budget(source, source["exports"][0], max_live_heap_bytes=limit)

    def test_forward_child_cfg_and_multiple_results_have_actual_event_bounds(self):
        sources = [fixed_loan_program(mode, construction)
                   for mode in ("read", "mut") for construction in ("forward", "child", "cfg")]
        sources += [multiple_shared(form) for form in ("forward", "children", "mixed")]
        sources += [swapped_mutable()]
        for source in sources:
            name = source["exports"][0]
            with self.subTest(function=name):
                bound = analyze_static_budget(source)
                self.assertEqual(bound["schema"], "hepta.hia.static-budget.v2")
                self.assertEqual(bound["profile"], "acyclic-byte-owner-parameter-loans-v8")
                row = next(item for item in bound["functions"] if item["function"] == name)
                args = [] if name == "swapped" else [37]
                observed = execute_program(source, name, args, max_steps=row["max_vm_ticks"],
                                           max_call_depth=row["max_call_depth"])
                self.assertEqual(observed["steps"], row["max_vm_ticks"])
                events = observed["resources"]["allocation_attempts"] + observed["resources"]["frees"]
                self.assertLessEqual(events, row["max_allocator_interactions"])
                self.assertEqual(observed["resources"]["live_local_loans"], 0)
                self.assert_digest(bound)

    def test_nested_calls_count_live_frames_not_returned_view_handles(self):
        source = temporary_loan_program(nested=True)
        name = source["exports"][0]
        proof = qualify_vm_call_depth(source, max_call_depth=3)
        self.assertEqual(proof["schema"], "hepta.hia.vm-call-depth-budget.v2")
        self.assertEqual(proof["profile"], "parameter-loan-synchronous-frames-v8")
        self.assertEqual({row["function"]: row["max_call_depth"] for row in proof["functions"]},
                         {"fallible": 1, "relay": 2, "fallible_entry": 3})
        self.assertFalse(proof["claims"]["returned_view_creation_adds_synchronous_frames"])
        observed = execute_program(source, name, [], max_call_depth=3)
        self.assertEqual(observed["result"], 1)
        with self.assertRaises(HIAProgramBudgetExceeded) as stopped:
            execute_program(source, name, [], max_call_depth=2)
        self.assertEqual(stopped.exception.code, "calls")
        self.assertGreater(stopped.exception.report["resources"]["live_owners"], 0)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_EXCEEDED"):
            qualify_vm_call_depth(source, max_call_depth=2)
        self.assert_digest(proof)

    def test_cfg_loop_with_returned_loans_has_frame_bound_but_no_tick_bound(self):
        source = looping_loan_program()
        proof = qualify_vm_call_depth(source, max_call_depth=2)
        self.assertFalse(proof["claims"]["vm_ticks_bounded"])
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(source)
        with self.assertRaises(HIAProgramBudgetExceeded) as stopped:
            execute_program(source, source["exports"][0], [37], max_call_depth=2, max_steps=70)
        self.assertEqual(stopped.exception.code, "steps")
        self.assertEqual(stopped.exception.report["resources"]["peak_bytes"], 8)

    def test_recursive_returns_never_receive_a_finite_dag_certificate(self):
        source = fixed_loan_program(construction="recursive")
        self.assertEqual(execute_program(source, source["exports"][0], [37])["result"], 37)
        for analyze in (analyze_static_budget,
                        lambda program: qualify_vm_call_depth(program, max_call_depth=256),
                        lambda program: self.entry_heap(program, 100)):
            with self.subTest(analyzer=analyze), self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_UNBOUNDED"):
                analyze(source)

    def test_chain_destructors_only_receive_synchronous_frame_qualification(self):
        source = chain_program("read", "child")
        proof = qualify_vm_call_depth(source, max_call_depth=2)
        self.assertEqual(execute_program(source, source["exports"][0], [37], max_call_depth=2)["result"], 37)
        for claim in ("vm_ticks_bounded", "allocator_interactions_bounded",
                      "process_rss_or_native_stack_bytes_bounded"):
            self.assertFalse(proof["claims"][claim])
        for analyze in (analyze_static_budget, lambda program: self.entry_heap(program, 100)):
            with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_PROFILE"):
                analyze(source)
        hidden = fixed_loan_program()
        hidden["functions"] += chain_drop()["functions"]
        # No chain.* opcode is needed to hide an unbounded destructor.
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_PROFILE"):
            analyze_static_budget(hidden)

    def test_canonical_core_rejects_wrong_origin_and_exclusive_alias_before_analysis(self):
        bad_origin = fixed_loan_program()
        bad_origin["functions"][0]["return_loans"] = ["missing"]
        bad_alias = swapped_mutable()
        call = next(op for op in bad_alias["functions"][1]["blocks"][0]["ops"] if op["op"] == "call")
        call["args"] = ["left", "left"]
        for source in (bad_origin, bad_alias):
            for analyze in (analyze_static_budget,
                            lambda program: qualify_vm_call_depth(program, max_call_depth=3),
                            lambda program: self.entry_heap(program, 100)):
                with self.subTest(analyzer=analyze), self.assertRaisesRegex(HIAProgramRejected, "E_HIA_LOAN"):
                    analyze(source)

    def test_uncalled_future_opcode_cannot_inherit_event_or_frame_accounting(self):
        source = fixed_loan_program()
        source["functions"].append(f("hidden", [], [], [], [
            b("entry", [], [i("future.implicit_callback")], ret())]))
        stub = SimpleNamespace(as_dict=lambda: source)
        for analyze in (analyze_static_budget,
                        lambda program: qualify_vm_call_depth(program, max_call_depth=3)):
            with patch("hepta.hia_program.verify_program", return_value=stub):
                with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_PROFILE"):
                    analyze(source)
        with patch("hepta.hia_heap_bound.verify_program", return_value=stub):
            with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_PROFILE"):
                self.entry_heap(source, 100)

    def test_old_receipts_and_old_native_consumer_do_not_acquire_v8_authority(self):
        from hepta.hia_source_bridge import _validate_static_budget_receipt
        old = analyze_static_budget(resource_program())
        self.assertEqual(old["schema"], "hepta.hia.static-budget.v1")
        self.assertNotIn("profile", old)
        self.assertEqual(qualify_vm_call_depth(resource_program(), max_call_depth=1)["schema"],
                         "hepta.hia.vm-call-depth-budget.v1")
        source = fixed_loan_program()
        core = verify_program(source)
        current = analyze_static_budget(core, max_vm_ticks=100)
        with self.assertRaisesRegex(ValueError, "schema, claims or source identity"):
            _validate_static_budget_receipt(core, {"max_vm_ticks": 100}, current)
        with self.assertRaises(HIAHeapBoundRejected):
            analyze_constant_live_heap(core)
        with self.assertRaises(HIAHeapBoundRejected):
            analyze_static_budget(core, max_live_heap_bytes=8)

    def test_scalar_entry_total_adds_callee_local_peak_without_duplicate_borrow_payload(self):
        for source, expected in ((fixed_loan_program(), 8), (multiple_shared(), 1),
                                 (swapped_mutable(), 2),
                                 (temporary_loan_program(extra_owner=True), 9),
                                 (temporary_loan_program(nested=True), 8)):
            with self.subTest(expected=expected, function=source["exports"][0]):
                proof = self.entry_heap(source, expected)
                self.assertEqual(proof["peak_bound_bytes"], expected)
                name = source["exports"][0]
                args = [] if name in {"swapped", "fallible_entry"} else [37]
                observed = execute_program(source, name, args, max_heap_bytes=expected)
                self.assertEqual(observed["resources"]["peak_bytes"], expected)
                self.assertEqual(observed["resources"]["live_bytes"], 0)
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_EXCEEDED"):
                    self.entry_heap(source, expected - 1)
                self.assert_digest(proof)

    def test_external_loan_root_survives_cfg_renaming_and_branch_join(self):
        source = branch_loan_program()
        proof = self.entry_heap(source, 11)
        self.assertEqual(proof["peak_bound_bytes"], 11)
        self.assertEqual(proof["local_peak_summaries"][0]["max_additional_local_payload_bytes"], 7)
        for flag, expected in ((True, 7), (False, 11)):
            observed = execute_program(source, source["exports"][0], [37, flag], max_heap_bytes=11)
            self.assertEqual(observed["resources"]["peak_bytes"], expected)

    def test_returned_loan_length_retains_actual_caller_owner_bound(self):
        source = returned_length_program()
        proof = self.entry_heap(source, 16)
        self.assertEqual(proof["peak_bound_bytes"], 16)
        observed = execute_program(source, source["exports"][0], [37], max_heap_bytes=16)
        self.assertEqual(observed["resources"]["peak_bytes"], 16)
        self.assertEqual(observed["resources"]["allocations"], 2)
        self.assertEqual(observed["resources"]["frees"], 2)

    def test_unknown_external_length_is_not_a_zero_length_or_caller_promise(self):
        source = external_length_program()
        self.assertEqual(execute_program(source, source["exports"][0], [])["resources"]["peak_bytes"], 2)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "allocator extent"):
            self.entry_heap(source, 1000)
        source = external_length_program(checked_cast=True)
        proof = self.entry_heap(source, 256)
        self.assertEqual(proof["peak_bound_bytes"], 256)
        self.assertEqual(proof["local_peak_summaries"][0]["max_additional_local_payload_bytes"], 255)
        self.assertEqual(execute_program(source, source["exports"][0], [])["resources"]["peak_bytes"], 2)

    def test_failure_and_every_tick_prefix_stay_within_peak_without_claimed_cleanup(self):
        source = temporary_loan_program(nested=True)
        name = source["exports"][0]
        proof = self.entry_heap(source, 8)
        maximum = execute_program(source, name, [])["steps"]
        retained_live_prefix = False
        for cut in range(1, maximum):
            with self.subTest(step_limit=cut), self.assertRaises(HIAProgramBudgetExceeded) as stopped:
                execute_program(source, name, [], max_steps=cut)
            ledger = stopped.exception.report["resources"]
            self.assertLessEqual(ledger["peak_bytes"], proof["peak_bound_bytes"])
            retained_live_prefix |= ledger["live_bytes"] > 0
        self.assertTrue(retained_live_prefix)
        for failed in (1, 2, 3, 4):
            try:
                observed = execute_program(source, name, [], allocation_fail_at=failed)
            except HIAProgramTrap as stopped:
                observed = stopped.report
            self.assertLessEqual(observed["resources"]["peak_bytes"], proof["peak_bound_bytes"])
        self.assertFalse(proof["claims"]["termination_or_unwinding_proved"])

    def test_owned_call_boundaries_and_private_entry_remain_unqualified(self):
        source = document(
            f("consume", [("owned", "buffer")], [], ["alloc"], [
                b("entry", [("owned", "buffer")], [i("owner.drop", ["owned"])], ret())]),
            f("main", [], [], ["alloc", "trap"], [b("entry", [], [c("n", "usize", 1),
                i("buffer.new", ["n"], [("owner", "buffer")]),
                i("call", ["owner"], function="consume")], ret())]))
        source["exports"] = ["main"]
        verify_program(source)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "resource arguments"):
            self.entry_heap(source, 1)
        source = fixed_loan_program()
        with self.assertRaisesRegex(HIAHeapBoundRejected, "public scalar"):
            qualify_entry_live_heap_budget(source, source["functions"][0]["name"], max_live_heap_bytes=8)

    def test_receipts_replay_from_actual_bytes_and_bind_changed_inputs(self):
        source = fixed_loan_program()
        core = verify_program(source)
        for analyze in (analyze_static_budget,
                        lambda program: qualify_vm_call_depth(program, max_call_depth=2),
                        lambda program: qualify_entry_live_heap_budget(program, source["exports"][0], max_live_heap_bytes=9)):
            with self.subTest(analyzer=analyze):
                before = analyze(core)
                self.assertEqual(before, analyze(core.canonical_bytes))
                self.assertEqual(before, analyze(source))
                changed = deepcopy(source)
                changed["functions"][1]["blocks"][0]["ops"][0]["attrs"]["value"] = 9
                after = analyze(changed)
                self.assertNotEqual(before["core_sha256"], after["core_sha256"])
                self.assertNotEqual(before["sha256"], after["sha256"])

    def test_invalid_policy_future_schema_and_forged_producer_claims_fail_closed(self):
        source = fixed_loan_program()
        for bad in (True, False, -1, "8", 8.0, None, [], {}):
            with self.subTest(policy=repr(bad)), self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_POLICY"):
                self.entry_heap(source, bad)
        for bad in (True, False, 0, 257, "2", 2.0, None):
            with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_POLICY"):
                qualify_vm_call_depth(source, max_call_depth=bad)
        for field, value in (("schema", "hepta.hia.program.v9"), ("budget_receipt", {"bounded": True})):
            changed = deepcopy(source)
            changed[field] = value
            with self.assertRaises(HIAProgramRejected):
                self.entry_heap(changed, 8)


if __name__ == "__main__":
    unittest.main()
