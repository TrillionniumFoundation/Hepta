"""HIA v6 P1: exact checked div/rem numeric heap bounds.

No new parser, verifier or native emitter: this proves only a finite
resource size derived from fully constant SSA arithmetic. Unknown intervals
still reject the requested heap policy rather than silently assuming bounds.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _bounded_divrem, analyze_constant_live_heap,
)
from hepta.hia_program import integer_range, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def quotient_extent(op, a, divisor, typ="u8"):
    return m(f("finite_division", [], ["usize"], ["alloc", "trap"], [
        b("entry", [], [
            c("numerator", typ, a),
            c("denominator", typ, divisor),
            i(op, ["numerator", "denominator"], [("derived", typ)]),
            i("int.cast", ["derived"], [("extent", "usize")], mode="checked"),
            i("buffer.new", ["extent"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("extent")),
    ]))


def unknown_dividend():
    return m(f("unknown_dividend", [("source", "u8")], [], ["alloc", "trap"], [
        b("entry", [("source", "u8")], [
            c("denominator", "u8", 2),
            i("int.div.checked", ["source", "denominator"], [("derived", "u8")]),
            i("int.cast", ["derived"], [("extent", "usize")], mode="checked"),
            i("buffer.new", ["extent"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret()),
    ]))


class HIAHeapDivisionTests(unittest.TestCase):
    def test_exact_division_and_remainder_admit_real_vm_heap(self):
        for operation, answer in (("int.div.checked", 9), ("int.rem.checked", 1)):
            with self.subTest(op=operation):
                core = verify_program(quotient_extent(operation, 37, 4))
                self.assertEqual(analyze_constant_live_heap(core),
                                 {"finite_division": answer})
                self.assertEqual(analyze_static_budget(
                    core, max_live_heap_bytes=answer
                )["functions"][0]["max_live_heap_bytes"], answer)
                if answer:
                    with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                        analyze_static_budget(core, max_live_heap_bytes=answer - 1)
                observed = execute_program(core, "finite_division", [])
                self.assertEqual(observed["result"], answer)
                self.assertEqual(observed["resources"]["peak_bytes"], answer)

    def test_checked_zero_and_min_signed_overflow_must_refuse_and_trap(self):
        for op, a, divisor, typ in (
            ("int.div.checked", 1, 0, "u8"),
            ("int.rem.checked", 1, 0, "u8"),
            ("int.div.checked", -128, -1, "i8"),
            ("int.rem.checked", -128, -1, "i8"),
        ):
            with self.subTest(op=op, a=a, divisor=divisor, type=typ):
                core = verify_program(quotient_extent(op, a, divisor, typ))
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)
                with self.assertRaises(HIAProgramTrap) as trapped:
                    execute_program(core, "finite_division", [])
                expected = "division_by_zero" if divisor == 0 else "overflow"
                self.assertEqual(trapped.exception.code, expected)

    def test_unbounded_dynamic_division_refuses_finite_policy(self):
        core = verify_program(unknown_dividend())
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(core, max_live_heap_bytes=255)

    def test_exact_transfer_matches_entire_i8_u8_divrem_domain(self):
        # Exhaustive finite machine scalar pairs; signed Python // and %
        # are intentionally NOT used as the expected quotient/remainder.
        for typ in ("i8", "u8"):
            minimum, maximum = integer_range(typ)
            for a in range(minimum, maximum + 1):
                for divisor in range(minimum, maximum + 1):
                    traps = divisor == 0 or (typ == "i8" and
                                                a == minimum and divisor == -1)
                    if traps:
                        for operation in ("int.div.checked", "int.rem.checked"):
                            with self.assertRaises(HIAHeapBoundRejected):
                                _bounded_divrem(operation, a, divisor, typ)
                        continue
                    magnitude = abs(a) // abs(divisor)
                    quotient = (-magnitude if (a < 0) != (divisor < 0)
                                else magnitude)
                    remainder = a - quotient * divisor
                    self.assertEqual(_bounded_divrem(
                        "int.div.checked", a, divisor, typ), quotient)
                    self.assertEqual(_bounded_divrem(
                        "int.rem.checked", a, divisor, typ), remainder)


if __name__ == "__main__":
    unittest.main()
