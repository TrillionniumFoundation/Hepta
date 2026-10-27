"""Executed HIA byte-budget interval proofs against real Core/VM fixtures.

The analyzer is a conservative admission gate, NOT a source/LLVM refinement
proof. Every accepted upper bound must exceed observed peak VM payload bytes.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import HIAHeapBoundRejected, analyze_constant_live_heap
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, branch, c, f, i, jump, m, ret


def selected():
    return m(f("select_alloc", [("flag", "bool")], ["usize"], ["alloc", "trap"], [
        b("entry", [("flag", "bool")], [
            c("eight", "usize", 8), c("twelve", "usize", 12),
            i("select", ["flag", "eight", "twelve"], [("n", "usize")]),
            i("buffer.new", ["n"], [("owner", "buffer")]),
            i("buffer.len", ["owner"], [("observed", "usize")]),
            i("owner.drop", ["owner"]),
        ], ret("observed")),
    ]))


def computed():
    return m(f("computed", [], ["usize"], ["alloc", "trap"], [
        b("entry", [], [
            c("six", "usize", 6), c("seven", "usize", 7),
            i("int.add.checked", ["six", "seven"], [("size", "usize")]),
            i("buffer.new", ["size"], [("first", "buffer")]),
            i("buffer.len", ["first"], [("n", "usize")]),
            i("buffer.try_new", ["n"], [("second", "buffer"), ("success", "bool")]),
            i("owner.drop", ["second"]), i("owner.drop", ["first"]),
        ], ret("n")),
    ]))


def diamond():
    return m(f("diamond_alloc", [("flag", "bool")], [], ["alloc", "trap"], [
        b("entry", [("flag", "bool")], [], branch("flag", ("left",), ("right",))),
        b("left", [], [c("small", "usize", 2)], jump("join", "small")),
        b("right", [], [c("large", "usize", 9)], jump("join", "large")),
        b("join", [("joined_size", "usize")], [
            i("buffer.new", ["joined_size"], [("o", "buffer")]),
            i("owner.drop", ["o"]),
        ], ret()),
    ]))


def wrapped_zero():
    return m(f("wrap_to_zero", [], ["usize"], ["alloc", "trap"], [
        b("entry", [], [
            c("maximum", "u64", (1 << 64) - 1), c("one", "u64", 1),
            i("int.add.wrap", ["maximum", "one"], [("result", "u64")]),
            i("int.cast", ["result"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("o", "buffer")]),
            i("owner.drop", ["o"]),
        ], ret("size")),
    ]))


def dynamic_unknown():
    return m(f("dynamic", [("size", "usize")], [], ["alloc"], [
        b("entry", [("size", "usize")], [
            i("buffer.try_new", ["size"], [("o", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["o"]),
        ], ret()),
    ]))


def checked_overflow_unknown():
    return m(f("checked_overflow", [], [], ["alloc", "trap"], [
        b("entry", [], [
            c("maximum", "usize", (1 << 64) - 1), c("one", "usize", 1),
            i("int.add.checked", ["maximum", "one"], [("bad", "usize")]),
            i("buffer.new", ["bad"], [("o", "buffer")]),
            i("owner.drop", ["o"]),
        ], ret()),
    ]))


class HIAHeapIntervalTests(unittest.TestCase):
    def test_nonconstant_select_never_underbounds_either_real_vm_path(self):
        core = verify_program(selected())
        bounds = analyze_constant_live_heap(core)
        self.assertEqual(bounds, {"select_alloc": 12})
        for flag, expected in ((True, 8), (False, 12)):
            actual = execute_program(core, "select_alloc", [flag])
            self.assertEqual(actual["result"], expected)
            self.assertLessEqual(actual["resources"]["peak_bytes"], bounds["select_alloc"])
        self.assertEqual(analyze_static_budget(core, max_live_heap_bytes=12)
                         ["functions"][0]["max_live_heap_bytes"], 12)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=11)

    def test_checked_arithmetic_and_owner_length_with_fallible_second_allocation(self):
        core = verify_program(computed())
        self.assertEqual(analyze_constant_live_heap(core), {"computed": 26})
        for fail in (None, 2):
            report = execute_program(core, "computed", [], allocation_fail_at=fail)
            self.assertEqual(report["result"], 13)
            self.assertLessEqual(report["resources"]["peak_bytes"], 26)

    def test_diamond_join_retains_safe_interval_instead_of_dropping_constant(self):
        core = verify_program(diamond())
        self.assertEqual(analyze_constant_live_heap(core), {"diamond_alloc": 9})
        for flag in (True, False):
            report = execute_program(core, "diamond_alloc", [flag])
            self.assertLessEqual(report["resources"]["peak_bytes"], 9)

    def test_exact_wrapping_semantics_cannot_forge_nonzero_owner_extent(self):
        core = verify_program(wrapped_zero())
        self.assertEqual(analyze_constant_live_heap(core), {"wrap_to_zero": 0})
        result = execute_program(core, "wrap_to_zero", [])
        self.assertEqual(result["result"], 0)
        self.assertEqual(result["resources"]["peak_bytes"], 0)

    def test_unknown_dynamic_and_checked_overflow_cannot_claim_small_budget(self):
        for source in (dynamic_unknown(), checked_overflow_unknown()):
            core = verify_program(source)
            with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                analyze_constant_live_heap(core)
            with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_UNBOUNDED"):
                analyze_static_budget(core, max_live_heap_bytes=4096)


if __name__ == "__main__":
    unittest.main()
