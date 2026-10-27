"""HIA v6 P1: conservative checked-shift intervals and real VM heap bounds.

HIA checked shifts trap on an out-of-range count; a valid left shift wraps
at the declared machine width. Interval propagation must never use
unwrapped mathematical endpoints as a smaller memory bound.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _Span, _bounded_shift, _span,
    _wrap, analyze_constant_live_heap,
)
from hepta.hia_program import integer_range, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def shift_choices(*, operation="int.shl.checked", left=(2, 4),
                  counts=(1, 2), typ="u8"):
    return m(f("bounded_shift", [("choose", "bool")], ["usize"], ["alloc", "trap"], [
        b("entry", [("choose", "bool")], [
            c("left_a", typ, left[0]),
            c("left_b", typ, left[1]),
            c("count_a", typ, counts[0]),
            c("count_b", typ, counts[1]),
            i("select", ["choose", "left_a", "left_b"], [("value", typ)]),
            i("select", ["choose", "count_a", "count_b"], [("amount", typ)]),
            i(operation, ["value", "amount"], [("shifted", typ)]),
            i("int.cast", ["shifted"], [("extent", "usize")], mode="checked"),
            i("buffer.new", ["extent"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("extent")),
    ]))


def shift_constant(value, amount, typ="u8"):
    return m(f("constant_shift", [], ["usize"], ["alloc", "trap"], [
        b("entry", [], [
            c("value", typ, value),
            c("amount", typ, amount),
            i("int.shl.checked", ["value", "amount"], [("shifted", typ)]),
            i("int.cast", ["shifted"], [("extent", "usize")], mode="checked"),
            i("buffer.new", ["extent"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("extent")),
    ]))


def shift_unknown():
    return m(f("dynamic_shift", [("amount", "u8")], [], ["alloc", "trap"], [
        b("entry", [("amount", "u8")], [
            c("base", "u8", 8),
            i("int.shr.checked", ["base", "amount"], [("shifted", "u8")]),
            i("int.cast", ["shifted"], [("extent", "usize")], mode="checked"),
            i("buffer.new", ["extent"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret()),
    ]))


class HIAHeapShiftIntervalTests(unittest.TestCase):
    def test_verified_choice_and_real_vm_shifted_allocation(self):
        core = verify_program(shift_choices())
        bound = analyze_constant_live_heap(core)
        self.assertEqual(bound, {"bounded_shift": 16})
        self.assertEqual(analyze_static_budget(core, max_live_heap_bytes=16)
                         ["functions"][0]["max_live_heap_bytes"], 16)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=15)
        for choice, result in ((True, 4), (False, 16)):
            observed = execute_program(core, "bounded_shift", [choice])
            self.assertEqual(observed["result"], result)
            self.assertLessEqual(observed["resources"]["peak_bytes"], 16)

    def test_right_shift_interval_matches_vm(self):
        core = verify_program(shift_choices(
            operation="int.shr.checked", left=(80, 80), counts=(2, 3)))
        self.assertEqual(analyze_constant_live_heap(core), {"bounded_shift": 20})
        for choice, result in ((True, 20), (False, 10)):
            report = execute_program(core, "bounded_shift", [choice])
            self.assertEqual(report["result"], result)
            self.assertLessEqual(report["resources"]["peak_bytes"], 20)

    def test_exact_unsigned_wrapping_left_shift_must_use_modular_value(self):
        core = verify_program(shift_constant(200, 1))
        self.assertEqual(analyze_constant_live_heap(core), {"constant_shift": 144})
        report = execute_program(core, "constant_shift", [])
        self.assertEqual(report["result"], 144)
        self.assertEqual(report["resources"]["peak_bytes"], 144)

    def test_partial_wrapping_and_unknown_amount_cannot_admit_budget(self):
        for source in (
            shift_choices(left=(120, 200), counts=(1, 1)),
            shift_unknown(),
        ):
            core = verify_program(source)
            with self.subTest(func=core.as_dict()["functions"][0]["name"]):
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_static_budget(core, max_live_heap_bytes=256)

    def test_invalid_constant_shift_count_rejects_and_vm_traps(self):
        for value, count, typ in ((1, 8, "u8"), (1, -1, "i8")):
            with self.subTest(count=count, type=typ):
                core = verify_program(shift_constant(value, count, typ))
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)
                with self.assertRaises(HIAProgramTrap) as trapped:
                    execute_program(core, "constant_shift", [])
                self.assertEqual(trapped.exception.code, "overflow")

    def test_pure_interval_transfer_never_underestimates_i8_u8_samples(self):
        # Independent concrete enumeration around signed extrema, zero and
        # bit-discard boundaries. Full-CFG VM tests above use the real Core.
        for typ in ("i8", "u8"):
            minimum, maximum = integer_range(typ)
            selected = sorted({v for v in
                (minimum, minimum + 1, -16, -8, -1, 0, 1, 8, 16, maximum - 1, maximum)
                if minimum <= v <= maximum})
            for lo in selected:
                for hi in selected:
                    if lo > hi:
                        continue
                    for first, last in ((0, 0), (0, 1), (1, 3), (3, 7)):
                        for opcode in ("int.shl.checked", "int.shr.checked"):
                            admitted = _bounded_shift(opcode, _Span(lo, hi),
                                                       _Span(first, last), typ)
                            if admitted is None:
                                continue
                            output = _span(admitted)
                            for value in range(lo, hi + 1):
                                for amount in range(first, last + 1):
                                    concrete = (_wrap(value << amount, typ)
                                                if opcode == "int.shl.checked"
                                                else value >> amount)
                                    self.assertLessEqual(output.lo, concrete)
                                    self.assertLessEqual(concrete, output.hi)


if __name__ == "__main__":
    unittest.main()
