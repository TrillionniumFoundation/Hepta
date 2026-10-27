"""True HIA v6 P1 convergence: dynamic quotient -> bitwise SSA -> owned heap.

This test is a reviewed acceptance input for one canonical verifier, VM, and
resource analyzer. A source commit alone is not a passing execution receipt.
"""
from __future__ import annotations

import unittest

from hepta.hia_heap_bound import analyze_constant_live_heap
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


_MAX_U64 = (1 << 64) - 1


def converged():
    params = [("value", "u64"), ("low", "bool")]
    return m(f("converged", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, [
            c("denom", "u64", _MAX_U64),
            i("int.div.checked", ["value", "denom"], [("quot", "u64")]),
            i("int.cast", ["quot"], [("byte", "u8")], mode="checked"),
            i("bit.not", ["byte"], [("complement", "u8")]),
            c("mask3", "u8", 3), c("mask7", "u8", 7),
            i("select", ["low", "mask3", "mask7"], [("mask", "u8")]),
            i("bit.and", ["complement", "mask"], [("masked", "u8")]),
            c("four", "u8", 4),
            i("bit.or", ["masked", "four"], [("ored", "u8")]),
            c("one", "u8", 1),
            i("bit.xor", ["ored", "one"], [("mixed", "u8")]),
            i("int.cast", ["mixed"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("size")),
    ]))


class HIAQuotientBitwiseConvergence(unittest.TestCase):
    def test_all_proofs_compose_into_one_verified_owned_program(self):
        checked = verify_program(converged())
        # This limit requires all four numeric transfer rules to survive
        # integration into the one resource SSA authority.
        self.assertEqual(analyze_constant_live_heap(checked), {"converged": 7})
        accepted = analyze_static_budget(checked, max_live_heap_bytes=7)
        self.assertEqual(accepted["functions"][0]["max_live_heap_bytes"], 7)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(checked, max_live_heap_bytes=6)
        for value in (0, 1, 7, 1234, _MAX_U64 - 1, _MAX_U64):
            for low, mask in ((True, 3), (False, 7)):
                with self.subTest(value=value, low=low):
                    quot = value // _MAX_U64
                    expected = (((((~quot) & 255) & mask) | 4) ^ 1)
                    observed = execute_program(checked, "converged", [value, low])
                    self.assertEqual(observed["result"], expected)
                    self.assertEqual(observed["resources"]["live_bytes"], 0)
                    self.assertEqual(observed["resources"]["live_owners"], 0)
                    self.assertLessEqual(observed["resources"]["peak_bytes"], 7)


if __name__ == "__main__":
    unittest.main()
