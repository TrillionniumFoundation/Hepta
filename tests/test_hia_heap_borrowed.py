"""Actual checked HIA Owner/Loan SSA byte-bound regressions.

The canonical HIA verifier must accept the positive Owner/Loan programs first.
The opt-in heap analyzer must conservatively bound peak live payload bytes,
including nested loans, cross-block remapping and joins. This is NOT RSS or
native LLVM qualification.
"""
from __future__ import annotations

import copy
import unittest

from hepta.hia_heap_bound import analyze_constant_live_heap
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def local_borrow_length():
    return m(f("local_borrow_length", [], ["usize"], ["alloc", "trap"], [
        b("entry", [], [
            c("seven", "usize", 7),
            i("buffer.new", ["seven"], [("first", "buffer")]),
            i("borrow.read", ["first"], [("reader", "readbuf")]),
            i("buffer.len", ["reader"], [("length", "usize")]),
            i("loan.end", ["reader"]),
            i("buffer.try_new", ["length"], [("second", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["second"]),
            i("owner.drop", ["first"]),
        ], ret("length"))
    ]))


def nested_reborrow_cross_block():
    return m(f("nested_cross_block", [], ["usize"], ["alloc", "trap"], [
        b("entry", [], [
            c("four", "usize", 4),
            i("buffer.new", ["four"], [("first", "buffer")]),
            i("borrow.mut", ["first"], [("writer", "mutbuf")]),
            i("borrow.read", ["writer"], [("nested", "readbuf")]),
        ], jump("finish", "first", "writer", "nested")),
        b("finish", [("owner", "buffer"), ("mut_view", "mutbuf"),
                     ("reader", "readbuf")], [
            i("buffer.len", ["reader"], [("n", "usize")]),
            i("loan.end", ["reader"]),
            i("loan.end", ["mut_view"]),
            i("buffer.try_new", ["n"], [("copy", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["copy"]),
            i("owner.drop", ["owner"]),
        ], ret("n"))
    ]))


def diamond_view_join():
    return m(f("diamond_view", [("flag", "bool")], ["usize"],
               ["alloc", "trap"], [
        b("entry", [("flag", "bool")], [],
          branch("flag", ("left",), ("right",))),
        b("left", [], [
            c("small", "usize", 3),
            i("buffer.new", ["small"], [("left_owner", "buffer")]),
            i("borrow.read", ["left_owner"], [("left_view", "readbuf")]),
        ], jump("join", "left_owner", "left_view")),
        b("right", [], [
            c("large", "usize", 11),
            i("buffer.new", ["large"], [("right_owner", "buffer")]),
            i("borrow.read", ["right_owner"], [("right_view", "readbuf")]),
        ], jump("join", "right_owner", "right_view")),
        b("join", [("owner", "buffer"), ("reader", "readbuf")], [
            i("buffer.len", ["reader"], [("extent", "usize")]),
            i("loan.end", ["reader"]),
            i("buffer.try_new", ["extent"], [("second", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["second"]),
            i("owner.drop", ["owner"]),
        ], ret("extent")),
    ]))


class HIAHeapBorrowedExtentTests(unittest.TestCase):
    def test_same_block_borrow_length_never_uses_unproved_exact_allocation(self):
        core = verify_program(local_borrow_length())
        result = analyze_constant_live_heap(core)
        self.assertEqual(result, {"local_borrow_length": 14})
        for denial in (None, 2):
            observed = execute_program(core, "local_borrow_length", [],
                                       allocation_fail_at=denial)
            self.assertEqual(observed["result"], 7)
            self.assertLessEqual(observed["resources"]["peak_bytes"], 14)
        row = analyze_static_budget(core, max_live_heap_bytes=14)["functions"][0]
        self.assertEqual(row["max_live_heap_bytes"], 14)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=13)

    def test_nested_reborrow_root_survives_real_cfg_ssa_transfer(self):
        core = verify_program(nested_reborrow_cross_block())
        self.assertEqual(analyze_constant_live_heap(core), {"nested_cross_block": 8})
        observed = execute_program(core, "nested_cross_block", [])
        self.assertEqual(observed["result"], 4)
        self.assertLessEqual(observed["resources"]["peak_bytes"], 8)

    def test_diamond_joins_views_by_normalized_owner_root(self):
        core = verify_program(diamond_view_join())
        self.assertEqual(analyze_constant_live_heap(core), {"diamond_view": 22})
        for flag, size in ((True, 3), (False, 11)):
            observed = execute_program(core, "diamond_view", [flag])
            self.assertEqual(observed["result"], size)
            self.assertLessEqual(observed["resources"]["peak_bytes"], 22)

    def test_borrow_without_forwarded_root_rejected_by_canonical_core(self):
        malformed = nested_reborrow_cross_block()
        malformed["functions"][0]["blocks"][0]["term"]["args"] = [
            "first", "writer", "writer"
        ]
        # Third argument type also breaks the expected reader identity.
        with self.assertRaises(HIAProgramRejected):
            verify_program(malformed)

    def test_ended_loan_cannot_supply_new_allocation_size(self):
        malformed = local_borrow_length()
        ops = malformed["functions"][0]["blocks"][0]["ops"]
        # Move the loan.end before buffer.len: this is a use-after-end.
        ops[3], ops[4] = ops[4], ops[3]
        with self.assertRaises(HIAProgramRejected):
            verify_program(malformed)


if __name__ == "__main__":
    unittest.main()
