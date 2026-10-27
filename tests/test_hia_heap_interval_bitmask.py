"""Typed HIA interval mask proof: bitwise AND of unknown value and known mask.

A nonnegative mask in an independently proven interval [0,M] bounds
x & mask by M for signed/unsigned fixed-width x. Uncertain signed masks
remain unqualified. HIA Core, VM and static resource checks are required.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _Span, _bounded_nonnegative_and_mask,
    analyze_constant_live_heap,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def masked_source(typ="u64", masks=(7, 15)):
    params = [("value", typ), ("pick", "bool")]
    ops = [
        c("small", typ, masks[0]),
        c("large", typ, masks[1]),
        i("select", ["pick", "small", "large"], [("mask", typ)]),
        i("bit.and", ["value", "mask"], [("masked", typ)]),
        i("int.cast", ["masked"], [("bytes", "usize")], mode="checked"),
        i("buffer.new", ["bytes"], [("storage", "buffer")]),
        i("owner.drop", ["storage"]),
    ]
    return m(f("masked", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, ops, ret("bytes")),
    ]))


class HIADynamicIntervalBitmaskTests(unittest.TestCase):
    def test_dynamic_mask_bounds_unknown_u64_and_signed_i8_inputs(self):
        for typ, samples in (
            ("u64", (0, 1, 7, 15, 255, (1 << 64) - 1)),
            ("i8", (-128, -127, -16, -1, 0, 1, 7, 127)),
        ):
            with self.subTest(typ=typ):
                core = verify_program(masked_source(typ))
                self.assertEqual(analyze_constant_live_heap(core), {"masked": 15})
                gate = analyze_static_budget(core, max_live_heap_bytes=15)
                self.assertEqual(gate["functions"][0]["max_live_heap_bytes"], 15)
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                    analyze_static_budget(core, max_live_heap_bytes=14)
                for pick, mask in ((True, 7), (False, 15)):
                    for value in samples:
                        observed = execute_program(core, "masked", [value, pick])
                        self.assertEqual(observed["result"], value & mask)
                        self.assertLessEqual(observed["resources"]["peak_bytes"], 15)

    def test_complete_signed_mask_interval_may_not_mint_budget(self):
        core = verify_program(masked_source("i8", (-1, 7)))
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)

    def test_malformed_or_negative_abstract_mask_rejects(self):
        self.assertIsNone(_bounded_nonnegative_and_mask(None, None, "u8"))
        self.assertIsNone(_bounded_nonnegative_and_mask(None, _Span(-1, 15), "i8"))
        self.assertIsNone(_bounded_nonnegative_and_mask(None, _Span(0, 128), "i8"))
        self.assertIsNone(_bounded_nonnegative_and_mask(None, _Span(0, 256), "u8"))
        self.assertEqual(_bounded_nonnegative_and_mask(
            _Span(-128, 127), _Span(7, 15), "i8"), _Span(0, 15))
        self.assertEqual(_bounded_nonnegative_and_mask(
            _Span(0, 7), _Span(0, 15), "u8"), _Span(0, 7))
        # Historical exact nonnegative masks remain admitted.
        self.assertEqual(_bounded_nonnegative_and_mask(None, 15, "u64"),
                         _Span(0, 15))

    def test_exhaustive_small_machine_domains(self):
        checked = 0
        for typ, values, masks in (
            ("u8", range(256), range(256)),
            ("i8", range(-128, 128), range(128)),
        ):
            for mask in masks:
                predicted = _bounded_nonnegative_and_mask(
                    None, _Span(0, mask), typ)
                self.assertIsNotNone(predicted)
                lo = predicted.lo if isinstance(predicted, _Span) else predicted
                hi = predicted.hi if isinstance(predicted, _Span) else predicted
                for x in values:
                    for selected in (0, mask, mask // 2):
                        got = x & selected
                        self.assertLessEqual(lo, got)
                        self.assertLessEqual(got, hi)
                        checked += 1
        self.assertEqual(checked, 294912)

    @unittest.skipUnless(
        shutil.which(os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")),
        "pinned native Clang20 absent: HIA -> LLVM differential not qualified",
    )
    def test_real_llvm_emitter_masked_u64_matches_independent_vm(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        core = verify_program(masked_source("u64"))
        self.assertEqual(analyze_constant_live_heap(core), {"masked": 15})
        ir = emit_program_llvm(core)
        with tempfile.TemporaryDirectory(prefix="hia-interval-mask-") as temporary:
            output = Path(temporary) / "masked.so"
            native = compile_program_llvm(
                ir, program=core, output=output,
                clang=os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang"))
            self.assertEqual(native["kind"], "shared")
            entry = ctypes.CDLL(str(output)).masked
            entry.argtypes = [ctypes.c_uint64, ctypes.c_bool]
            entry.restype = ctypes.c_size_t
            for value in (0, 1, 7, 15, 255, (1 << 64) - 1):
                for pick in (False, True):
                    self.assertEqual(entry(value, pick),
                                     execute_program(core, "masked", [value, pick])["result"])


if __name__ == "__main__":
    unittest.main()
