"""Signed checked division/remainder interval transfer on verified HIA v6.

Proof applies only to independently proven strictly positive signed divisors.
The result bounds are valid on nontrapping VM/native paths, not a source or
backend refinement theorem.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _Span, _bounded_divrem,
    analyze_constant_live_heap,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret

SIGNED64_MAX = (1 << 63) - 1


def signed_alloc(op="int.div.checked", typ="i64", divisor=7, selected=False):
    params = [("value", typ)] + ([("pick", "bool")] if selected else [])
    init = []
    if selected:
        init = [
            c("three", typ, 3), c("seven", typ, 7),
            i("select", ["pick", "three", "seven"], [("d", typ)]),
        ]
    else:
        init = [c("d", typ, divisor)]
    operations = init + [
        i(op, ["value", "d"], [("quotrem", typ)]),
        i("int.cast", ["quotrem"], [("extent", "usize")], mode="checked"),
        i("buffer.new", ["extent"], [("owner", "buffer")]),
        i("owner.drop", ["owner"]),
    ]
    return m(f("signed", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, operations, ret("extent")),
    ]))


def trunc_divrem(n, d):
    quot = abs(n) // abs(d)
    if (n < 0) != (d < 0):
        quot = -quot
    return quot, n - quot * d


class HIASignedDivRemBounds(unittest.TestCase):
    def test_unknown_i64_signed_quotient_divided_by_signed_max_is_bounded_one(self):
        core = verify_program(signed_alloc(divisor=SIGNED64_MAX))
        self.assertEqual(analyze_constant_live_heap(core), {"signed": 1})
        self.assertEqual(
            analyze_static_budget(core, max_live_heap_bytes=1)
            ["functions"][0]["max_live_heap_bytes"], 1)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=0)
        for value in (-(1 << 63), -(1 << 63) + 1, -1, 0, 1, SIGNED64_MAX):
            expected, _ = trunc_divrem(value, SIGNED64_MAX)
            if expected < 0:
                with self.assertRaises(HIAProgramTrap) as result:
                    execute_program(core, "signed", [value])
                self.assertEqual(result.exception.code, "overflow")
            else:
                result = execute_program(core, "signed", [value])
                self.assertEqual(result["result"], expected)
                self.assertLessEqual(result["resources"]["peak_bytes"], 1)

    def test_unknown_i64_positive_remainder_has_proven_signed_envelope(self):
        core = verify_program(signed_alloc(op="int.rem.checked", divisor=7))
        self.assertEqual(analyze_constant_live_heap(core), {"signed": 6})
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=5)
        for value in (-(1 << 63), -100, -14, -7, -1, 0, 1, 6, 7, 15, SIGNED64_MAX):
            _, expected = trunc_divrem(value, 7)
            if expected < 0:
                with self.assertRaises(HIAProgramTrap) as result:
                    execute_program(core, "signed", [value])
                self.assertEqual(result.exception.code, "overflow")
            else:
                result = execute_program(core, "signed", [value])
                self.assertEqual(result["result"], expected)
                self.assertLessEqual(result["resources"]["peak_bytes"], 6)

    def test_i8_unknown_and_selected_positive_divisor(self):
        for op, bound in (("int.div.checked", 42), ("int.rem.checked", 6)):
            with self.subTest(op=op):
                core = verify_program(signed_alloc(op, "i8", selected=True))
                self.assertEqual(analyze_constant_live_heap(core), {"signed": bound})
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                    analyze_static_budget(core, max_live_heap_bytes=bound - 1)
                for pick, divisor in ((True, 3), (False, 7)):
                    for value in range(-128, 128):
                        quot, rem = trunc_divrem(value, divisor)
                        expected = quot if op == "int.div.checked" else rem
                        if expected < 0:
                            with self.assertRaises(HIAProgramTrap):
                                execute_program(core, "signed", [value, pick])
                        else:
                            result = execute_program(core, "signed", [value, pick])
                            self.assertEqual(result["result"], expected)
                            self.assertLessEqual(result["resources"]["peak_bytes"], bound)

    def test_zero_negative_ambiguous_or_malformed_divisors_cannot_prove(self):
        for denominator in (_Span(0, 7), _Span(-1, 7), _Span(-7, -1)):
            for op in ("int.div.checked", "int.rem.checked"):
                self.assertIsNone(_bounded_divrem(op, None, denominator, "i64"))
        self.assertIsNone(_bounded_divrem("int.div.checked", _Span(-(1 << 63) - 1, 10), 7, "i64"))
        self.assertIsNone(_bounded_divrem("int.rem.checked", _Span(0, 10), _Span(1, 1 << 63), "i64"))
        self.assertEqual(_bounded_divrem("int.div.checked", -17, 5, "i8"), -3)
        self.assertEqual(_bounded_divrem("int.rem.checked", -17, 5, "i8"), -2)
        self.assertEqual(_bounded_divrem("int.div.checked", None, SIGNED64_MAX, "i64"), _Span(-1, 1))
        self.assertEqual(_bounded_divrem("int.rem.checked", None, 7, "i64"), _Span(-6, 6))
        core = verify_program(signed_alloc("int.div.checked", "i8", -1))
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)
        with self.assertRaises(HIAProgramTrap) as error:
            execute_program(core, "signed", [-128])
        self.assertEqual(error.exception.code, "overflow")

    @unittest.skipUnless(
        shutil.which(os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")),
        "pinned Clang20 absent: actual HIA Core LLVM native execution unqualified",
    )
    def test_actual_emitted_llvm_qualified_i64_positive_division(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        core = verify_program(signed_alloc(divisor=SIGNED64_MAX))
        self.assertEqual(analyze_constant_live_heap(core), {"signed": 1})
        ir = emit_program_llvm(core)
        with tempfile.TemporaryDirectory(prefix="hia-signed-div-") as tmp:
            artifact = Path(tmp) / "signed.so"
            result = compile_program_llvm(
                ir, program=core, output=artifact,
                clang=os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang"))
            self.assertEqual(result["kind"], "shared")
            native = ctypes.CDLL(str(artifact)).signed
            native.argtypes = [ctypes.c_int64]
            native.restype = ctypes.c_size_t
            for value in (0, 1, 27, SIGNED64_MAX):
                self.assertEqual(native(value),
                                 execute_program(core, "signed", [value])["result"])


if __name__ == "__main__":
    unittest.main()
