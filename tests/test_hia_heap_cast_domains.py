"""P1: finite successful-cast bounds from *verified* HIA scalar types.

The same checked HIA Core, interpreter, and static resource gate are used.
These tests do not prove total correctness or backend translation soundness.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _Span, _bounded_cast, analyze_constant_live_heap,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, f, i, m, ret


def cast_allocation(source_type, destination_type, first_mode):
    """Cast a caller value to its destination, then checked usize, then alloc."""
    params = [("value", source_type)]
    return m(f("cast_size", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, [
            i("int.cast", ["value"], [("converted", destination_type)], mode=first_mode),
            i("int.cast", ["converted"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("size")),
    ]))


def no_cast_allocation():
    params = [("size", "usize")]
    return m(f("unknown_size", params, [], ["alloc"], [
        b("entry", params, [
            i("buffer.try_new", ["size"], [("owner", "buffer"), ("ok", "bool")]),
            i("owner.drop", ["owner"]),
        ], ret()),
    ]))


class HIASuccessfulCastBudgetTests(unittest.TestCase):
    def test_signed_small_type_through_checked_usize_has_nonnegative_bound(self):
        cases = [
            ("i8", 127, [-128, -1, 0, 1, 17, 127]),
            ("i16", 32767, [-32768, -1, 0, 91, 1024]),
            ("i32", 2147483647, [-2147483648, -1, 0, 101, 1024]),
        ]
        for source_type, maximum, samples in cases:
            with self.subTest(source_type=source_type):
                program = verify_program(cast_allocation(source_type, "usize", "checked"))
                self.assertEqual(analyze_constant_live_heap(program), {"cast_size": maximum})
                self.assertEqual(
                    analyze_static_budget(program, max_live_heap_bytes=maximum)
                    ["functions"][0]["max_live_heap_bytes"], maximum)
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                    analyze_static_budget(program, max_live_heap_bytes=maximum - 1)
                for value in samples:
                    with self.subTest(value=value):
                        if value < 0:
                            with self.assertRaises(HIAProgramTrap) as failed:
                                execute_program(program, "cast_size", [value])
                            self.assertEqual(failed.exception.code, "overflow")
                        else:
                            report = execute_program(program, "cast_size", [value])
                            self.assertEqual(report["result"], value)
                            self.assertLessEqual(report["resources"]["peak_bytes"], maximum)

    def test_dynamic_wide_checked_narrowing_only_bounds_successful_inputs(self):
        core = verify_program(cast_allocation("usize", "u8", "checked"))
        self.assertEqual(analyze_constant_live_heap(core), {"cast_size": 255})
        self.assertEqual(
            analyze_static_budget(core, max_live_heap_bytes=255)
            ["functions"][0]["max_live_heap_bytes"], 255)
        for value in (0, 1, 127, 255):
            report = execute_program(core, "cast_size", [value])
            self.assertEqual(report["result"], value)
            self.assertLessEqual(report["resources"]["peak_bytes"], 255)
        for value in (256, 65535, (1 << 64) - 1):
            with self.assertRaises(HIAProgramTrap) as failed:
                execute_program(core, "cast_size", [value])
            self.assertEqual(failed.exception.code, "overflow")

    def test_dynamic_wide_wrapping_cast_bounds_any_representable_input(self):
        core = verify_program(cast_allocation("usize", "u8", "wrap"))
        self.assertEqual(analyze_constant_live_heap(core), {"cast_size": 255})
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=254)
        for value in (0, 1, 255, 256, 257, 65535, (1 << 64) - 1):
            observed = execute_program(core, "cast_size", [value])
            self.assertEqual(observed["result"], value & 255)
            self.assertLessEqual(observed["resources"]["peak_bytes"], 255)

    def test_signed_wrapping_to_unsigned_is_not_treated_as_positive_identity(self):
        core = verify_program(cast_allocation("i8", "u8", "wrap"))
        self.assertEqual(analyze_constant_live_heap(core), {"cast_size": 255})
        for value in (-128, -2, -1, 0, 1, 127):
            observed = execute_program(core, "cast_size", [value])
            self.assertEqual(observed["result"], value & 255)
            self.assertLessEqual(observed["resources"]["peak_bytes"], 255)

    def test_partial_checked_interval_is_intersection_not_unsigned_wrap(self):
        self.assertEqual(_bounded_cast(_Span(-128, 127), "usize", "checked"),
                         _Span(0, 127))
        self.assertEqual(_bounded_cast(_Span(100, 300), "u8", "checked"),
                         _Span(100, 255))
        self.assertIsNone(_bounded_cast(_Span(-9, -1), "usize", "checked"))
        self.assertEqual(_bounded_cast(None, "u8", "wrap"), _Span(0, 255))
        self.assertEqual(_bounded_cast(None, "i8", "checked"), _Span(-128, 127))
        self.assertIsNone(_bounded_cast(None, "usize", "checked"))
        self.assertIsNone(_bounded_cast(_Span(-128, 127), "usize", "wrap"))

    def test_unknown_full_width_allocation_still_refuses_before_native_codegen(self):
        core = verify_program(no_cast_allocation())
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(core, max_live_heap_bytes=255)


if __name__ == "__main__":
    unittest.main()
