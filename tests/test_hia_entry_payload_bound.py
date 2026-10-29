"""All-input structural bounds plus operational negative controls, no native build."""
from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_heap_bound import HIAHeapBoundRejected, analyze_entry_payload_bound
from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from hepta.hia_program_runtime import (HIAProgramBudgetExceeded, HIAProgramTrap,
                                       execute_program)
from tests.test_hia_heap_bound import joined_max, local_buffers, unknown_size
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret

LEGACY = Path(__file__).parent / "fixtures/hia_payload_bound/legacy_core.hia.json"
LEGACY_SHA256 = "1044e28ea68a18d6a0681cff9cd5f835e26e91c9a669dab01256b9592f64ca51"


def allocator(name="make", size=9, *, returns_owner=False):
    operations = [c("extent", "usize", size),
                  i("buffer.try_new", ["extent"], [("owner", "buffer"), ("ok", "bool")])]
    if not returns_owner:
        operations.append(i("owner.drop", ["owner"]))
    return f(name, [], ["buffer"] if returns_owner else [], ["alloc"],
             [b("entry", [], operations, ret("owner") if returns_owner else ret())])


def borrowed_call_loop():
    reader = f("read", [("view", "readbuf")], ["u8"], ["read", "trap"], [
        b("entry", [("view", "readbuf")], [c("index", "usize", 0),
            i("buffer.load", ["view", "index"], [("byte", "u8")])], ret("byte"))])
    caller = f("loop", [("n", "u32")], [], ["alloc", "read", "trap"], [
        b("entry", [("n", "u32")], [c("size", "usize", 4),
            i("buffer.new", ["size"], [("initial", "buffer")])], jump("head", "initial", "n")),
        b("head", [("owner", "buffer"), ("count", "u32")], [c("zero", "u32", 0),
            i("compare.gt", ["count", "zero"], [("more", "bool")])],
          branch("more", ("body", "owner", "count"), ("exit", "owner"))),
        b("body", [("body_owner", "buffer"), ("remaining", "u32")], [
            i("borrow.read", ["body_owner"], [("loan", "readbuf")]),
            i("call", ["loan"], [("observed", "u8")], function="read"),
            i("loan.end", ["loan"]), c("one", "u32", 1),
            i("int.sub.checked", ["remaining", "one"], [("next", "u32")])],
          jump("head", "body_owner", "next")),
        b("exit", [("final", "buffer")], [i("owner.drop", ["final"])], ret()),
    ])
    return m(reader, caller)


class EntryPayloadBoundTests(unittest.TestCase):
    def test_actual_legacy_core_has_three_requests_and_32_byte_bound(self):
        raw = LEGACY.read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), LEGACY_SHA256)
        report = analyze_entry_payload_bound(raw, "legacy_checksum_chunk")
        self.assertEqual(report["core_sha256"], LEGACY_SHA256)
        self.assertEqual(report["entry_bounds"], {
            "max_allocation_op_executions": 3, "max_nonzero_allocation_requests": 3,
            "max_cumulative_requested_payload_bytes": 32, "max_live_payload_bytes": 32})
        self.assertEqual(len(report["function_summaries"]), 16)
        sites = [(row["function"], block["block"], site["constant_bytes"])
                 for row in report["function_summaries"] for block in row["blocks"]
                 for site in block["allocation_sites"]]
        self.assertEqual(sites, [("legacy_checksum_chunk", "b128", 16),
                                 ("legacy_checksum_chunk", "b129", 8),
                                 ("legacy_checksum_chunk", "b131", 8)])
        self.assertTrue(any(row["cyclic_components"] for row in report["function_summaries"]))
        self.assertFalse(report["claims"]["native_runtime_or_optimizer_admission_authority"])

    def test_branch_sum_is_conservative_and_does_not_claim_tight_peak(self):
        source = joined_max()
        result = analyze_entry_payload_bound(source, "select_heap")
        self.assertEqual(result["entry_bounds"]["max_nonzero_allocation_requests"], 2)
        self.assertEqual(result["entry_bounds"]["max_live_payload_bytes"], 11)
        for flag in (False, True):
            for failure in (None, 1):
                observed = execute_program(source, "select_heap", [flag], allocation_fail_at=failure)
                self.assertLessEqual(observed["resources"]["allocation_attempts"], 2)
                self.assertLessEqual(observed["resources"]["peak_bytes"], 11)

    def test_owner_returns_and_moves_transfer_payload_without_reallocating(self):
        child = allocator(returns_owner=True)
        caller = f("caller", [], [], ["alloc"], [b("entry", [], [
            i("call", [], [("a", "buffer")], function="make"),
            i("call", [], [("z", "buffer")], function="make"),
            i("owner.move", ["a"], [("moved", "buffer")]),
            i("owner.drop", ["moved"]), i("owner.drop", ["z"])], ret())])
        source = m(child, caller)
        result = analyze_entry_payload_bound(source, "caller")
        self.assertEqual(result["entry_bounds"]["max_nonzero_allocation_requests"], 2)
        self.assertEqual(result["entry_bounds"]["max_live_payload_bytes"], 18)
        for failure in (None, 1, 2, 3):
            observed = execute_program(source, "caller", [], allocation_fail_at=failure)
            self.assertEqual(observed["resources"]["allocation_attempts"], 2)
            self.assertLessEqual(observed["resources"]["peak_bytes"], 18)
            self.assertEqual(observed["resources"]["live_bytes"], 0)

    def test_resource_access_and_borrowed_calls_in_cycle_need_no_new_payload(self):
        source = borrowed_call_loop()
        result = analyze_entry_payload_bound(source, "loop")
        self.assertEqual(result["entry_bounds"]["max_nonzero_allocation_requests"], 1)
        self.assertEqual(result["entry_bounds"]["max_live_payload_bytes"], 4)
        for count in (0, 1, 4):
            observed = execute_program(source, "loop", [count])
            self.assertEqual(observed["resources"]["peak_bytes"], 4)
            self.assertEqual(observed["resources"]["live_bytes"], 0)
        # Stopping mid-loop retains the same bounded owner. No forced cleanup
        # or termination is silently inferred from the payload certificate.
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(source, "loop", [100], max_steps=30)
        self.assertEqual(caught.exception.report["resources"]["live_bytes"], 4)

    def test_allocator_in_acyclic_exit_of_cycle_is_counted_once(self):
        source = m(f("exit_alloc", [("flag", "bool")], [], ["alloc"], [
            b("entry", [("flag", "bool")], [], jump("head", "flag")),
            b("head", [("condition", "bool")], [],
              branch("condition", ("body", "condition"), ("exit",))),
            b("body", [("again", "bool")], [], jump("head", "again")),
            b("exit", [], [c("size", "usize", 4),
                i("buffer.try_new", ["size"], [("owner", "buffer"), ("ok", "bool")]),
                i("owner.drop", ["owner"])], ret()),
        ]))
        report = analyze_entry_payload_bound(source, "exit_alloc")
        self.assertEqual(report["entry_bounds"]["max_live_payload_bytes"], 4)
        self.assertEqual(report["function_summaries"][0]["cyclic_components"], [["body", "head"]])
        with self.assertRaises(HIAProgramBudgetExceeded) as caught:
            execute_program(source, "exit_alloc", [True], max_steps=10)
        self.assertEqual(caught.exception.report["resources"]["allocation_attempts"], 0)

    def test_direct_allocator_in_cycle_refuses_even_zero_size(self):
        for size in (0, 8):
            with self.subTest(size=size):
                fn = allocator(size=size)
                fn["blocks"][0]["id"] = "loop"
                fn["blocks"][0]["term"] = jump("loop")
                fn["blocks"].insert(0, b("entry", [], [], jump("loop")))
                fn["entry"] = "entry"
                core = verify_program(m(fn))
                with self.assertRaisesRegex(HIAHeapBoundRejected, "allocator opcode in a CFG cycle"):
                    analyze_entry_payload_bound(core, "make")

    def test_transitive_allocator_call_in_cycle_refuses(self):
        for size in (0, 8):
            with self.subTest(size=size):
                leaf = allocator("leaf", size)
                middle = f("middle", [], [], ["alloc"], [
                    b("entry", [], [i("call", function="leaf")], ret())])
                outer = f("outer", [], [], ["alloc"], [
                    b("entry", [], [], jump("loop")),
                    b("loop", [], [i("call", function="middle")], jump("loop"))])
                core = verify_program(m(outer, middle, leaf))
                with self.assertRaisesRegex(HIAHeapBoundRejected, "cycle calls allocator-bearing middle"):
                    analyze_entry_payload_bound(core, "outer")

    def test_recursive_call_graph_refuses_including_unused_definition(self):
        recursive = f("recursive", [], [], [], [b("entry", [], [
            i("call", function="recursive")], ret())])
        for source, entry in ((m(recursive), "recursive"),
                              (m(allocator(), recursive), "make")):
            with self.subTest(entry=entry):
                core = verify_program(source)
                with self.assertRaisesRegex(HIAHeapBoundRejected, "recursion"):
                    analyze_entry_payload_bound(core, entry)

    def test_dynamic_allocation_size_refuses(self):
        core = verify_program(unknown_size())
        with self.assertRaisesRegex(HIAHeapBoundRejected, "earlier same-block const"):
            analyze_entry_payload_bound(core, "dynamic")

    def test_cross_block_constant_does_not_inherit_an_unproved_extent(self):
        source = m(f("across", [], [], ["alloc"], [
            b("entry", [], [c("size", "usize", 8)], jump("target", "size")),
            b("target", [("extent", "usize")], [
                i("buffer.try_new", ["extent"], [("owner", "buffer"), ("ok", "bool")]),
                i("owner.drop", ["owner"])], ret()),
        ]))
        core = verify_program(source)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "earlier same-block const"):
            analyze_entry_payload_bound(core, "across")

    def test_oversize_object_refuses_even_though_optional_runtime_can_fail(self):
        core = verify_program(m(allocator(size=1 << 63)))
        with self.assertRaisesRegex(HIAHeapBoundRejected, r"0..2\^63-1"):
            analyze_entry_payload_bound(core, "make")

    def test_zero_size_counts_opcode_but_not_allocator_attempt(self):
        source = m(allocator(size=0))
        report = analyze_entry_payload_bound(source, "make")
        self.assertEqual(report["entry_bounds"], {
            "max_allocation_op_executions": 1, "max_nonzero_allocation_requests": 0,
            "max_cumulative_requested_payload_bytes": 0, "max_live_payload_bytes": 0})
        observed = execute_program(source, "make", [])
        self.assertEqual(observed["resources"]["allocation_attempts"], 0)
        self.assertEqual(observed["resources"]["owners_created"], 1)

    def test_forged_verified_program_rechecks_owner_linear_flow(self):
        source = m(allocator())
        source["functions"][0]["blocks"][0]["ops"].pop()
        forged = VerifiedProgram(json.dumps(source).encode())
        with self.assertRaises(HIAProgramRejected):
            analyze_entry_payload_bound(forged, "make")

    def test_unknown_opcode_and_foreign_allocator_refuse(self):
        for operation in (i("buffer.foreign_allocator"), i("call", function="malloc")):
            with self.subTest(op=operation):
                source = m(allocator())
                source["functions"][0]["blocks"][0]["ops"].insert(0, operation)
                with self.assertRaises(HIAProgramRejected):
                    analyze_entry_payload_bound(source, "make")

    def test_future_verifier_cannot_silently_expand_closed_payload_profile(self):
        for mutation in ("opcode", "schema", "type"):
            with self.subTest(mutation=mutation):
                core = verify_program(m(allocator()))
                document = core.as_dict()
                if mutation == "opcode":
                    document["functions"][0]["blocks"][0]["ops"].insert(0, i("future.alloc"))
                elif mutation == "schema":
                    document["schema"] = "hepta.hia.program.v2"
                else:
                    document["functions"][0]["blocks"][0]["ops"][1]["out"][0]["type"] = "chain"
                future = VerifiedProgram(json.dumps(document).encode())
                with patch("hepta.hia_heap_bound.verify_program", return_value=future):
                    with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_PROFILE"):
                        analyze_entry_payload_bound(future, "make")

    def test_resource_boundary_is_not_treated_as_empty_scalar_entry(self):
        child = allocator(returns_owner=True)
        with self.assertRaisesRegex(HIAHeapBoundRejected, "public scalar entry"):
            analyze_entry_payload_bound(m(child), "make")

    def test_trap_and_failing_required_allocation_keep_prefix_bound(self):
        source = local_buffers()
        report = analyze_entry_payload_bound(source, "finite")
        self.assertEqual(report["entry_bounds"]["max_live_payload_bytes"], 12)
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(source, "finite", [], allocation_fail_at=1)
        self.assertLessEqual(caught.exception.report["resources"]["peak_bytes"], 12)
        changed = copy.deepcopy(source)
        changed["functions"][0]["blocks"][0]["term"] = {"op": "trap", "code": "user"}
        changed["functions"][0]["blocks"][0]["ops"] = changed["functions"][0]["blocks"][0]["ops"][:-2]
        analyze_entry_payload_bound(changed, "finite")
        with self.assertRaises(HIAProgramTrap) as caught:
            execute_program(changed, "finite", [])
        self.assertEqual(caught.exception.report["resources"]["live_bytes"], 12)

    def test_same_core_replay_is_deterministic_and_input_snapshot_is_detached(self):
        source = m(allocator())
        checked = verify_program(source)
        first = analyze_entry_payload_bound(checked, "make")
        source["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 100
        self.assertEqual(first, analyze_entry_payload_bound(checked, "make"))
        self.assertEqual(analyze_entry_payload_bound(source, "make")["entry_bounds"]["max_live_payload_bytes"], 100)

    def test_historical_admission_is_not_widened_by_the_new_analysis(self):
        from hepta.hia_heap_bound import analyze_constant_live_heap
        from hepta.hia_static_budget import HIAStaticBudgetRejected, analyze_static_budget
        source = borrowed_call_loop()
        analyze_entry_payload_bound(source, "loop")
        with self.assertRaises(ValueError):
            analyze_constant_live_heap(source)
        with self.assertRaises(HIAStaticBudgetRejected):
            analyze_static_budget(source)


if __name__ == "__main__":
    unittest.main()
