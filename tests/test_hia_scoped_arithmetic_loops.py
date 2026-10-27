"""Canonical HIA + VM conformance for sound same-block arithmetic Owner-loop bounds.

This tests the strict opt-in live-payload upper bound, NOT finite runtime,
allocator interaction count, RSS, CPU time, or native LLVM refinement.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, analyze_constant_live_heap, qualify_live_heap_budget,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from tests.test_hia_program import c, i
from tests.test_hia_scoped_alloc_loops import scoped_loop


def arithmetic_owner_loop(operations):
    source = scoped_loop()
    body = next(block for block in source["functions"][0]["blocks"]
                if block["id"] == "body")
    # Drop the example's constant-size Owner sequence but retain its genuine
    # checked count-down loop, PHIs, branches and normal return.
    body["ops"] = operations + body["ops"][4:]
    return source


def owner_with_size(name):
    return [
        i("buffer.new", [name], [("bounded_owner", "buffer")]),
        i("owner.drop", ["bounded_owner"]),
    ]


class ScopedArithmeticOwnerLoops(unittest.TestCase):
    def test_checked_wide_addition_from_proven_u8_interval(self):
        source = arithmetic_owner_loop([
            i("int.cast", ["r"], [("narrow", "u8")], mode="checked"),
            i("int.cast", ["narrow"], [("wide", "usize")], mode="checked"),
            c("extra", "usize", 3),
            i("int.add.checked", ["wide", "extra"], [("length", "usize")]),
            *owner_with_size("length"),
        ])
        verified = verify_program(source)
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 258})
        accepted = qualify_live_heap_budget(verified, max_live_heap_bytes=258)
        self.assertEqual(accepted["peak_bounds"], {"count_down": 258})
        for field in ("vm_ticks_bounded", "allocator_interactions_bounded",
                      "native_backend_refinement_proved", "process_rss_bounded"):
            self.assertIs(accepted["claims"][field], False)
        with self.assertRaises(HIAHeapBoundRejected):
            qualify_live_heap_budget(verified, max_live_heap_bytes=257)
        for n in (0, 1, 2, 7, 63, 255):
            with self.subTest(n=n):
                result = execute_program(verified, "count_down", [n])
                self.assertEqual(result["resources"]["peak_bytes"], n + 3 if n else 0)
                self.assertEqual(result["resources"]["live_bytes"], 0)
        with self.assertRaises(HIAProgramTrap):
            execute_program(verified, "count_down", [256])

    def test_checked_wide_multiplication_has_interval_peak(self):
        verified = verify_program(arithmetic_owner_loop([
            i("int.cast", ["r"], [("narrow", "u8")], mode="checked"),
            i("int.cast", ["narrow"], [("wide", "usize")], mode="checked"),
            c("multiplier", "usize", 4),
            i("int.mul.checked", ["wide", "multiplier"], [("length", "usize")]),
            *owner_with_size("length"),
        ]))
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 1020})
        for n in (1, 3, 17):
            result = execute_program(verified, "count_down", [n])
            self.assertEqual(result["resources"]["peak_bytes"], n * 4)

    def test_exact_wrapping_pair_remains_bounded(self):
        verified = verify_program(arithmetic_owner_loop([
            c("high", "u8", 250), c("plus", "u8", 10),
            i("int.add.wrap", ["high", "plus"], [("wrapped", "u8")]),
            i("int.cast", ["wrapped"], [("length", "usize")], mode="checked"),
            *owner_with_size("length"),
        ]))
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 4})
        self.assertEqual(execute_program(verified, "count_down", [4])["resources"]["peak_bytes"], 4)

    def test_subtraction_interval_checked_or_wrapped_without_underflow(self):
        for op in ("int.sub.checked", "int.sub.wrap"):
            with self.subTest(op=op):
                verified = verify_program(arithmetic_owner_loop([
                    i("int.cast", ["r"], [("narrow", "u8")], mode="checked"),
                    i("int.cast", ["narrow"], [("wide", "usize")], mode="checked"),
                    c("fixed", "usize", 260),
                    i(op, ["fixed", "wide"], [("length", "usize")]),
                    *owner_with_size("length"),
                ]))
                self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 260})
                for n in (1, 2, 7):
                    result = execute_program(verified, "count_down", [n])
                    self.assertEqual(result["resources"]["peak_bytes"], 259)
                    self.assertEqual(result["resources"]["live_bytes"], 0)

    def test_multiplication_without_wrapping_also_admits_wrap_mode(self):
        verified = verify_program(arithmetic_owner_loop([
            i("int.cast", ["r"], [("narrow", "u8")], mode="checked"),
            i("int.cast", ["narrow"], [("wide", "usize")], mode="checked"),
            c("times", "usize", 4),
            i("int.mul.wrap", ["wide", "times"], [("length", "usize")]),
            *owner_with_size("length"),
        ]))
        self.assertEqual(analyze_constant_live_heap(verified), {"count_down": 1020})
        self.assertEqual(execute_program(verified, "count_down", [7])["resources"]["peak_bytes"], 28)

    def test_partial_modular_wrap_cannot_mint_positive_budget(self):
        for op in ("int.add.wrap", "int.add.checked"):
            with self.subTest(op=op):
                verified = verify_program(arithmetic_owner_loop([
                    i("int.cast", ["r"], [("narrow", "u8")], mode="checked"),
                    c("one", "u8", 1),
                    i(op, ["narrow", "one"], [("new_small", "u8")]),
                    i("int.cast", ["new_small"], [("length", "usize")], mode="checked"),
                    *owner_with_size("length"),
                ]))
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(verified)


if __name__ == "__main__":
    unittest.main()
