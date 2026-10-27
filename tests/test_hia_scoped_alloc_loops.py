"""Finite live HIA heap-payload proof for balanced block-local allocating loops.

The existing verify_program authority checks the full SSA/CFG/ownership graph;
this analyzer adds only a narrow *peak live bytes* invariant. It must not
claim a bound for total allocations, CPU, VM ticks, process RSS or termination.
"""
from __future__ import annotations

from copy import deepcopy
import unittest

from hepta.hia_heap_bound import analyze_constant_live_heap
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_static_budget import HIAStaticBudgetRejected, analyze_static_budget
from tests.test_hia_program import b, c, i, jump
from tests.test_hia_zero_heap_loops import scalar_loop


def scoped_loop(*, two_allocations=False, in_entry=False):
    source = scalar_loop()
    fn = source["functions"][0]
    fn["effects"] = ["alloc", "trap"]
    body = next(block for block in fn["blocks"] if block["id"] == "body")
    operations = [
        c("scope_bytes", "usize", 9),
        i("buffer.new", ["scope_bytes"], [("local", "buffer")]),
        i("owner.move", ["local"], [("transferred", "buffer")]),
    ]
    if two_allocations:
        operations.extend([
            c("second_size", "usize", 4),
            i("buffer.new", ["second_size"], [("second_owner", "buffer")]),
            i("owner.drop", ["second_owner"]),
        ])
    operations.append(i("owner.drop", ["transferred"]))
    body["ops"] = operations + body["ops"]
    if in_entry:
        entry = next(block for block in fn["blocks"] if block["id"] == "entry")
        entry["ops"] = [
            c("entry_bytes", "usize", 3),
            i("buffer.new", ["entry_bytes"], [("entry_owner", "buffer")]),
            i("owner.drop", ["entry_owner"]),
        ] + entry["ops"]
    return source


class ScopedAllocatingLoopTests(unittest.TestCase):
    def test_true_native_hia_vm_loop_peak_is_iteration_independent(self):
        verified = verify_program(scoped_loop())
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 9})
        for n in (0, 1, 2, 5, 25):
            with self.subTest(iterations=n):
                observed = execute_program(verified, "count_down", [n])
                self.assertEqual(observed["result"], 0)
                self.assertEqual(observed["resources"]["peak_bytes"], 9 if n else 0)
                self.assertEqual(observed["resources"]["live_bytes"], 0)
                self.assertEqual(observed["resources"]["allocations"], n)
        # A finite peak does NOT bound the cumulative number of allocations.
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(verified, max_live_heap_bytes=9)

    def test_two_concurrently_live_block_local_owners_are_summed(self):
        verified = verify_program(scoped_loop(two_allocations=True))
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 13})
        for n in (1, 7):
            result = execute_program(verified, "count_down", [n])
            self.assertEqual(result["resources"]["peak_bytes"], 13)
            self.assertEqual(result["resources"]["live_bytes"], 0)
            self.assertEqual(result["resources"]["allocations"], 2 * n)

    def test_independent_scopes_on_distinct_blocks_take_max_not_sum(self):
        verified = verify_program(scoped_loop(in_entry=True))
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 9})
        for n, expected in ((0, 3), (1, 9), (10, 9)):
            with self.subTest(iterations=n):
                report = execute_program(verified, "count_down", [n])
                self.assertEqual(report["resources"]["peak_bytes"], expected)
                self.assertEqual(report["resources"]["live_bytes"], 0)

    def test_try_new_zero_length_loop_keeps_historical_rejection(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"][1] = i("buffer.try_new", ["scope_bytes"],
                            [("local", "buffer"), ("allocated", "bool")])
        # The loop profile is intentionally *not* a generic fallible owner
        # lifetime/allocator proof. It preserves the preexisting fail-closed
        # cyclic try_new handling.
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(verify_program(source))

    def test_dynamic_extent_cannot_be_assumed_constant_across_backedge(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"] = [
            i("int.cast", ["r"], [("dynamic_size", "usize")], mode="checked"),
            i("buffer.new", ["dynamic_size"], [("dynamic_owner", "buffer")]),
            i("owner.drop", ["dynamic_owner"]),
            *body["ops"][4:],
        ]
        verified = verify_program(source)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(verified)

    def test_owner_transferred_across_block_boundary_remains_unqualified(self):
        source = scoped_loop()
        fn = source["functions"][0]
        body = next(x for x in fn["blocks"] if x["id"] == "body")
        body["ops"] = [
            c("bytes_for_cleanup", "usize", 5),
            i("buffer.new", ["bytes_for_cleanup"], [("pending_owner", "buffer")]),
        ]
        body["term"] = jump("release", "pending_owner", "r", "s")
        release = b("release", [("carried", "buffer"), ("carry_n", "u32"), ("carry_step", "u32")], [
            i("owner.drop", ["carried"]),
            i("int.sub.checked", ["carry_n", "carry_step"], [("next_n", "u32")]),
        ], jump("head", "next_n", "carry_step"))
        fn["blocks"].insert(3, release)
        verified = verify_program(source)
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(verified)

    def test_unknown_opcode_has_no_new_cyclic_resource_authority(self):
        source = scoped_loop()
        body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
        body["ops"].insert(0, i("call", ["r"], [("renamed", "u32")], function="other"))
        # The *canonical* verifier must refuse the missing callee before
        # any derived numeric/resource bound can attempt to handle it.
        from hepta.hia_program import HIAProgramRejected
        with self.assertRaises(HIAProgramRejected):
            analyze_constant_live_heap(source)


if __name__ == "__main__":
    unittest.main()
