"""Prove finite unsigned remainder resource bounds using actual verified HIA Core.

This is an optional *payload* bound, not a proof of process RSS or native
back-end equivalence. Zero/potentially-zero divisors and signed unknown
dividends must never create an allocation-size certificate.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _Span, _bounded_divrem, analyze_constant_live_heap,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def modulo_source(typ="u64", divisor=16, *, choose_divisor=False):
    params = [("value", typ)]
    ops = []
    if choose_divisor:
        params.append(("pick", "bool"))
        ops.extend([
            c("three", typ, 3),
            c("seven", typ, 7),
            i("select", ["pick", "three", "seven"], [("denom", typ)]),
        ])
    else:
        ops.append(c("denom", typ, divisor))
    ops.extend([
        i("int.rem.checked", ["value", "denom"], [("residue", typ)]),
        i("int.cast", ["residue"], [("extent", "usize")], mode="checked"),
        i("buffer.new", ["extent"], [("storage", "buffer")]),
        i("owner.drop", ["storage"]),
    ])
    return m(f("modulus", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, ops, ret("extent")),
    ]))


class HIADynamicModuloHeapTests(unittest.TestCase):
    def test_full_width_dynamic_unsigned_dividend_is_soundly_bounded(self):
        for typ, divisor, samples in [
            ("u8", 7, range(256)),
            ("u64", 16, (0, 1, 15, 16, 12345, (1 << 64) - 1)),
            ("usize", 9, (0, 8, 9, 90, (1 << 64) - 1)),
        ]:
            with self.subTest(typ=typ, divisor=divisor):
                core = verify_program(modulo_source(typ, divisor))
                bound = divisor - 1
                self.assertEqual(analyze_constant_live_heap(core),
                                 {"modulus": bound})
                accepted = analyze_static_budget(core, max_live_heap_bytes=bound)
                self.assertEqual(accepted["functions"][0]["max_live_heap_bytes"], bound)
                if bound:
                    with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                        analyze_static_budget(core, max_live_heap_bytes=bound - 1)
                for value in samples:
                    actual = execute_program(core, "modulus", [value])
                    self.assertEqual(actual["result"], value % divisor)
                    self.assertLessEqual(actual["resources"]["peak_bytes"], bound)

    def test_positive_interval_divisor_has_conservative_worst_case(self):
        # A public bool can choose 3 or 7. The unknown path must not
        # assume a particular value, but both possibilities are nonzero.
        core = verify_program(modulo_source("u64", choose_divisor=True))
        self.assertEqual(analyze_constant_live_heap(core), {"modulus": 6})
        for pick, divisor in [(True, 3), (False, 7)]:
            for value in (0, 1, 6, 7, 1234, (1 << 64) - 1):
                with self.subTest(pick=pick, value=value):
                    actual = execute_program(core, "modulus", [value, pick])
                    self.assertEqual(actual["result"], value % divisor)
                    self.assertLessEqual(actual["resources"]["peak_bytes"], 6)

    def test_unsigned_u8_remainder_proof_exhaustive(self):
        # Independent mathematical oracle; not a substitute for real
        # compiler/VM integration on the precise source commit.
        for divisor in range(1, 256):
            bound = _bounded_divrem("int.rem.checked", None, divisor, "u8")
            maximum = bound.hi if isinstance(bound, _Span) else bound
            self.assertEqual(maximum, divisor - 1)
            for dividend in range(256):
                self.assertLessEqual(dividend % divisor, maximum)

    def test_unknown_zero_and_signed_profiles_remain_rejected(self):
        for ty, divisor in [("u64", 0), ("i64", 7), ("usize", (1 << 64) - 1)]:
            with self.subTest(type=ty, divisor=divisor):
                core = verify_program(modulo_source(ty, divisor))
                with self.assertRaisesRegex(HIAHeapBoundRejected,
                                            "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)
        self.assertIsNone(
            _bounded_divrem("int.rem.checked", None, _Span(0, 7), "u8"))
        self.assertIsNone(_bounded_divrem("int.div.checked", None, 7, "u64"))
        self.assertIsNone(_bounded_divrem("int.rem.checked", None, 7, "i64"))

    def test_zero_divisor_still_traps_in_actual_vm(self):
        core = verify_program(modulo_source("u64", 0))
        with self.assertRaises(HIAProgramTrap) as trapped:
            execute_program(core, "modulus", [1234])
        self.assertEqual(trapped.exception.code, "division_by_zero")

    def test_exact_remainder_and_signed_division_preserve_prior_values(self):
        self.assertEqual(_bounded_divrem("int.rem.checked", 100, 9, "u8"), 1)
        self.assertEqual(_bounded_divrem("int.div.checked", -17, 5, "i8"), -3)
        self.assertEqual(_bounded_divrem("int.rem.checked", -17, 5, "i8"), -2)
        with self.assertRaisesRegex(HIAHeapBoundRejected,
                                    "E_HIA_BUDGET_UNBOUNDED"):
            _bounded_divrem("int.rem.checked", 1, 0, "u8")


if __name__ == "__main__":
    unittest.main()
