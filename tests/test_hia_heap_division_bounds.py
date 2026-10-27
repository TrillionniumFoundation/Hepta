"""P1: sound bounded unsigned quotient from verified HIA typed SSA.

The analyzer still refuses unsigned division with possible zero or an
unbounded allocation upper limit. These tests combine canonical Core/VM
and static admission; native evidence is a separate optional qualification.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import random
import shutil
import tempfile
import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _Span, _bounded_divrem, analyze_constant_live_heap,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def quotient_source(typ="u64", divisors=((1 << 64) - 1,)):
    params = [("value", typ)]
    ops = []
    if len(divisors) == 1:
        ops.append(c("denom", typ, divisors[0]))
    else:
        if len(divisors) != 2:
            raise ValueError("only singleton or two-way divisor controls")
        params.append(("pick", "bool"))
        ops.extend((
            c("first", typ, divisors[0]),
            c("second", typ, divisors[1]),
            i("select", ["pick", "first", "second"], [("denom", typ)]),
        ))
    ops.extend((
        i("int.div.checked", ["value", "denom"], [("quotient", typ)]),
        i("int.cast", ["quotient"], [("bytes", "usize")], mode="checked"),
        i("buffer.new", ["bytes"], [("storage", "buffer")]),
        i("owner.drop", ["storage"]),
    ))
    return m(f("quotient", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, ops, ret("bytes")),
    ]))


class HIADynamicQuotientBudgetTests(unittest.TestCase):
    def test_full_width_unknown_dividend_has_proven_small_allocation(self):
        profiles = [
            ("u8", (251,), (0, 1, 250, 251, 255)),
            ("u64", ((1 << 64) - 1,), (0, 1, (1 << 63), (1 << 64) - 1)),
            ("usize", (1 << 63,), (0, 1, (1 << 63) - 1, (1 << 64) - 1)),
        ]
        for typ, divisors, samples in profiles:
            with self.subTest(typ=typ):
                program = verify_program(quotient_source(typ, divisors))
                self.assertEqual(analyze_constant_live_heap(program), {"quotient": 1})
                receipt = analyze_static_budget(program, max_live_heap_bytes=1)
                self.assertEqual(receipt["functions"][0]["max_live_heap_bytes"], 1)
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                    analyze_static_budget(program, max_live_heap_bytes=0)
                for value in samples:
                    report = execute_program(program, "quotient", [value])
                    self.assertEqual(report["result"], value // divisors[0])
                    self.assertLessEqual(report["resources"]["peak_bytes"], 1)

    def test_interval_divisor_from_dynamic_select_remains_sound(self):
        least = 1 << 63
        greatest = (1 << 64) - 1
        core = verify_program(quotient_source("u64", (least, greatest)))
        self.assertEqual(analyze_constant_live_heap(core), {"quotient": 1})
        for choose, divisor in ((True, least), (False, greatest)):
            for value in (0, 1, least - 1, least, greatest):
                with self.subTest(choice=choose, value=value):
                    report = execute_program(core, "quotient", [value, choose])
                    self.assertEqual(report["result"], value // divisor)
                    self.assertLessEqual(report["resources"]["peak_bytes"], 1)

    def test_unsigned_quotient_transfer_exhaustive_u8(self):
        for divisor in range(1, 256):
            result = _bounded_divrem("int.div.checked", None, divisor, "u8")
            low = result.lo if isinstance(result, _Span) else result
            high = result.hi if isinstance(result, _Span) else result
            self.assertEqual((low, high), (0, 255 // divisor))
            for dividend in range(256):
                self.assertTrue(low <= dividend // divisor <= high)

    def test_unsigned_interval_quotient_random_64bit(self):
        randomizer = random.Random(0xC0DE2026)
        top = (1 << 64) - 1
        for _ in range(50000):
            low = randomizer.randrange(1, top + 1)
            high = randomizer.randrange(low, top + 1)
            bound = _bounded_divrem("int.div.checked", None, _Span(low, high), "u64")
            self.assertIsInstance(bound, (_Span, int))
            actual_x = randomizer.randrange(top + 1)
            actual_d = randomizer.randrange(low, high + 1)
            got = actual_x // actual_d
            below = bound.lo if isinstance(bound, _Span) else bound
            above = bound.hi if isinstance(bound, _Span) else bound
            self.assertTrue(below <= got <= above, (low, high, actual_x, actual_d, bound))

    def test_unknown_zero_and_overbudget_still_reject(self):
        self.assertIsNone(_bounded_divrem("int.div.checked", None, _Span(0, 7), "u64"))
        self.assertEqual(_bounded_divrem("int.div.checked", None, 7, "i64"),
                         _Span(-((1 << 63) // 7), ((1 << 63) - 1) // 7))
        self.assertIsNone(_bounded_divrem("int.div.checked", _Span(-1, 3), 2, "u8"))
        with self.assertRaises(HIAHeapBoundRejected):
            _bounded_divrem("int.div.checked", None, 0, "u64")
        for divisors in ((1,), (0,)):
            with self.subTest(divisors=divisors):
                core = verify_program(quotient_source("u64", divisors))
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)
        zero = verify_program(quotient_source("u64", (0,)))
        with self.assertRaises(HIAProgramTrap) as error:
            execute_program(zero, "quotient", [123])
        self.assertEqual(error.exception.code, "division_by_zero")
        self.assertEqual(_bounded_divrem("int.div.checked", -17, 5, "i8"), -3)

    @unittest.skipUnless(
        shutil.which(os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")),
        "pinned native Clang20 absent: actual HIA LLVM differential NOT qualified",
    )
    def test_real_hia_llvm_native_quotient_matches_vm(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        core = verify_program(quotient_source("u64", ((1 << 64) - 1,)))
        self.assertEqual(analyze_constant_live_heap(core), {"quotient": 1})
        emitted = emit_program_llvm(core)
        with tempfile.TemporaryDirectory(prefix="hia-unsigned-div-") as temporary:
            dest = Path(temporary) / "quotient.so"
            receipt = compile_program_llvm(
                emitted, program=core, output=dest,
                clang=os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang"))
            self.assertEqual(receipt["kind"], "shared")
            entry = ctypes.CDLL(str(dest)).quotient
            entry.argtypes = [ctypes.c_uint64]
            entry.restype = ctypes.c_size_t
            for value in (0, 1, 251, (1 << 63), (1 << 64) - 1):
                self.assertEqual(entry(value),
                                 execute_program(core, "quotient", [value])["result"])


if __name__ == "__main__":
    unittest.main()
