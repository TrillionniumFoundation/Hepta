"""HIA exact scalar byte-budget transfer on genuinely verified Core/VM inputs.

The analyzer only gains knowledge of already known exact values. Unknown input
and dynamic overflow must still fail closed; VM and budget are independent.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _exact_scalar, analyze_constant_live_heap,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def allocation(name, operations, value_name, value_type, *, parameters=()):
    ops = list(operations)
    ops.extend([
        i("int.cast", [value_name], [("extent", "usize")], mode="checked"),
        i("buffer.new", ["extent"], [("owner", "buffer")]),
        i("owner.drop", ["owner"]),
    ])
    return m(f(name, list(parameters), ["usize"], ["alloc", "trap"], [
        b("entry", list(parameters), ops, ret("extent")),
    ]))


def masked_size():
    return allocation("masked", [
        c("hi", "u8", 240), c("lo", "u8", 15), c("bit4", "u8", 4),
        i("bit.not", ["hi"], [("inv", "u8")]),
        i("bit.and", ["hi", "lo"], [("cleared", "u8")]),
        i("bit.or", ["cleared", "inv"], [("combined", "u8")]),
        i("bit.xor", ["combined", "bit4"], [("size", "u8")]),
    ], "size", "u8")


def quotient_size():
    return allocation("quotient", [
        c("hundred", "u16", 100), c("nine", "u16", 9),
        c("one", "u16", 1),
        i("int.div.checked", ["hundred", "nine"], [("quot", "u16")]),
        i("int.rem.checked", ["hundred", "nine"], [("rem", "u16")]),
        i("int.shl.checked", ["quot", "one"], [("doubled", "u16")]),
        i("int.shr.checked", ["doubled", "one"], [("restored", "u16")]),
        i("int.add.checked", ["restored", "rem"], [("size", "u16")]),
    ], "size", "u16")


def compared_size():
    return allocation("comparison", [
        c("small", "u8", 6), c("large", "u8", 8),
        i("compare.lt", ["small", "large"], [("choose", "bool")]),
        i("select", ["choose", "small", "large"], [("size", "u8")]),
    ], "size", "u8")


def negative_remainder():
    return allocation("negative_rem", [
        c("negative", "i8", -17), c("five", "i8", 5),
        i("int.rem.checked", ["negative", "five"], [("rem", "i8")]),
        i("int.neg.checked", ["rem"], [("size", "i8")]),
    ], "size", "i8")


def compared_bool():
    return allocation("bool_compare", [
        c("true", "bool", True), c("false", "bool", False),
        c("small", "u8", 3), c("large", "u8", 9),
        i("compare.ne", ["true", "false"], [("choose", "bool")]),
        i("select", ["choose", "small", "large"], [("size", "u8")]),
    ], "size", "u8")


def arithmetic_trap(op, left, right, typ):
    return allocation("failing", [
        c("a", typ, left), c("z", typ, right),
        i(op, ["a", "z"], [("size", typ)]),
    ], "size", typ)


def unknown_operand():
    return allocation("unknown", [
        i("bit.not", ["value"], [("size", "u8")]),
    ], "size", "u8", parameters=[("value", "u8")])



def bounded_input(typ):
    return allocation("bounded_input", [], "value", typ,
                      parameters=[("value", typ)])


def masked_unknown(mask=15, typ="u8"):
    return allocation("masked_unknown", [
        c("mask", typ, mask),
        i("bit.and", ["value", "mask"], [("size", typ)]),
    ], "size", typ, parameters=[("value", typ)])


class HIAExactScalarBudgetTests(unittest.TestCase):
    def test_bitwise_division_shift_compare_and_signed_remainder_native_vm(self):
        for document, expected in [
            (masked_size(), 11), (quotient_size(), 12),
            (compared_size(), 6), (negative_remainder(), 2),
            (compared_bool(), 3),
        ]:
            with self.subTest(function=document["functions"][0]["name"]):
                core = verify_program(document)
                name = document["functions"][0]["name"]
                self.assertEqual(analyze_constant_live_heap(core), {name: expected})
                self.assertEqual(
                    analyze_static_budget(core, max_live_heap_bytes=expected)
                    ["functions"][0]["max_live_heap_bytes"], expected)
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                    analyze_static_budget(core, max_live_heap_bytes=expected - 1)
                outcome = execute_program(core, name, [])
                self.assertEqual(outcome["result"], expected)
                self.assertLessEqual(outcome["resources"]["peak_bytes"], expected)

    def test_provably_trapping_exact_scalar_arithmetic_never_qualifies(self):
        for operation, left, right, typ, code in [
            ("int.div.checked", 17, 0, "u8", "division_by_zero"),
            ("int.rem.checked", -128, -1, "i8", "overflow"),
            ("int.shl.checked", 1, 8, "u8", "overflow"),
            ("int.shr.checked", 1, 8, "u8", "overflow"),
        ]:
            with self.subTest(operation=operation, operands=(left, right)):
                core = verify_program(arithmetic_trap(operation, left, right, typ))
                with self.assertRaisesRegex(
                        HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)
                with self.assertRaises(HIAProgramTrap) as observed:
                    execute_program(core, "failing", [])
                self.assertEqual(observed.exception.code, code)

    def test_unknown_scalar_inputs_cannot_certify_heap_size(self):
        core = verify_program(unknown_operand())
        with self.assertRaisesRegex(
                HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(core, max_live_heap_bytes=15)
        self.assertEqual(execute_program(core, "unknown", [23])["result"], (~23) & 255)

    def test_proved_nonnegative_bitmask_bounds_dynamic_byte_extents(self):
        # Unlike arbitrary dynamic arithmetic, masking by a verified
        # nonnegative constant yields a finite upper bound for EVERY input.
        for typ, mask, inputs in [
            ("u8", 15, range(256)),
            ("u8", 0, range(256)),
            ("i8", 7, range(-128, 128)),
        ]:
            with self.subTest(typ=typ, mask=mask):
                core = verify_program(masked_unknown(mask, typ))
                self.assertEqual(analyze_constant_live_heap(core),
                                 {"masked_unknown": mask})
                self.assertEqual(
                    analyze_static_budget(core, max_live_heap_bytes=mask)
                    ["functions"][0]["max_live_heap_bytes"], mask)
                if mask:
                    with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                        analyze_static_budget(core, max_live_heap_bytes=mask - 1)
                for value in inputs:
                    observed = execute_program(core, "masked_unknown", [value])
                    self.assertEqual(observed["result"], value & mask)
                    self.assertLessEqual(observed["resources"]["peak_bytes"], mask)

    def test_unsigned_small_public_parameters_have_type_bounds(self):
        # The type itself, not a sample runtime value, bounds every call.
        for typ, limit, samples in [
            ("u8", 255, (0, 1, 255)),
            ("u16", 65535, (0, 200, 1024)),
            ("u32", 4294967295, (0, 37, 1024)),
        ]:
            with self.subTest(typ=typ):
                core = verify_program(bounded_input(typ))
                self.assertEqual(analyze_constant_live_heap(core),
                                 {"bounded_input": limit})
                self.assertEqual(
                    analyze_static_budget(core, max_live_heap_bytes=limit)
                    ["functions"][0]["max_live_heap_bytes"], limit)
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                    analyze_static_budget(core, max_live_heap_bytes=limit - 1)
                for size in samples:
                    report = execute_program(core, "bounded_input", [size])
                    self.assertEqual(report["result"], size)
                    self.assertLessEqual(report["resources"]["peak_bytes"], limit)

    def test_wide_dynamic_parameters_remain_unbounded_without_a_small_cast(self):
        # Small signed parameters now admit a checked nonnegative subset;
        # full-width parameters still lack a usable small payload bound.
        for typ in ("u64", "usize", "i64", "isize"):
            with self.subTest(typ=typ):
                core = verify_program(bounded_input(typ))
                with self.assertRaisesRegex(
                        HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)

    def test_signed_negative_mask_is_not_a_valid_static_payload_bound(self):
        core = verify_program(masked_unknown(-1, "i8"))
        with self.assertRaisesRegex(
                HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)
        with self.assertRaises(HIAProgramTrap) as trapped:
            execute_program(core, "masked_unknown", [-1])
        self.assertEqual(trapped.exception.code, "overflow")

    def test_exact_signed_bitwise_machine_width(self):
        for value in range(-128, 128):
            self.assertEqual(_exact_scalar("bit.not", [value], "i8"), ~value)
        for value in range(256):
            for shift in range(8):
                self.assertEqual(
                    _exact_scalar("int.shl.checked", [value, shift], "u8"),
                    (value << shift) & 255)
                self.assertEqual(
                    _exact_scalar("int.shr.checked", [value, shift], "u8"),
                    value >> shift)
        for value in range(-128, 128):
            for divisor in (-7, -1, 1, 7):
                if value == -128 and divisor == -1:
                    continue
                quotient = abs(value) // abs(divisor)
                if (value < 0) != (divisor < 0):
                    quotient = -quotient
                self.assertEqual(
                    _exact_scalar("int.div.checked", [value, divisor], "i8"), quotient)
                self.assertEqual(
                    _exact_scalar("int.rem.checked", [value, divisor], "i8"),
                    value - quotient * divisor)

    def test_bool_is_not_treated_as_integer_for_byte_extents(self):
        self.assertIsNone(_exact_scalar("bit.and", [True, 7], "u8"))
        self.assertIs(_exact_scalar("compare.eq", [False, False], "bool"), True)
        self.assertIs(_exact_scalar("compare.ne", [False, False], "bool"), False)
        self.assertIsNone(_exact_scalar("compare.lt", [True, False], "bool"))


if __name__ == "__main__":
    unittest.main()
