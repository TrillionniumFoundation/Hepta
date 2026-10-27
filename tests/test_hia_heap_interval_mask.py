"""HIA P1: proof-bounded dynamic nonnegative bitmask heap admission.

Tests use the canonical verified HIA Core, independent VM and resource
budget gate. Standalone mathematics and optional native LLVM are separately
scoped; no whole-language, C++ or physical hardware claims are made.
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
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def selected_interval_mask(typ="u64", *, negative=False):
    params = [("value", typ), ("pick", "bool")]
    first, second = ((-1, 7) if negative else
                     (7, 31) if typ == "i64" else (15, 63))
    return m(f("masked_interval", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, [
            c("low_mask", typ, first), c("high_mask", typ, second),
            i("select", ["pick", "low_mask", "high_mask"], [("mask", typ)]),
            i("bit.and", ["value", "mask"], [("bits", typ)]),
            i("int.cast", ["bits"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("size")),
    ]))


def input_derived_mask():
    params = [("value", "u64"), ("mask8", "u8")]
    return m(f("dynamic_mask", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, [
            i("int.cast", ["mask8"], [("mask64", "u64")], mode="checked"),
            i("bit.and", ["value", "mask64"], [("bits", "u64")]),
            i("int.cast", ["bits"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("size")),
    ]))


class HIABitmaskIntervalTests(unittest.TestCase):
    def test_nonexact_positive_mask_is_a_valid_verified_heap_bound(self):
        for typ, maximum, masks, values in [
            ("u64", 63, (15, 63), (0, 1, 15, 63, 65, 0xFFFFFFFFFFFFFFFF)),
            ("i64", 31, (7, 31), (-(1 << 63), -1, -99, 0, 37, (1 << 63) - 1)),
        ]:
            with self.subTest(typ=typ):
                core = verify_program(selected_interval_mask(typ))
                self.assertEqual(analyze_constant_live_heap(core), {"masked_interval": maximum})
                self.assertEqual(
                    analyze_static_budget(core, max_live_heap_bytes=maximum)
                    ["functions"][0]["max_live_heap_bytes"], maximum)
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                    analyze_static_budget(core, max_live_heap_bytes=maximum - 1)
                for index, mask in enumerate(masks):
                    for value in values:
                        with self.subTest(mask=mask, value=value):
                            actual = execute_program(core, "masked_interval", [value, index == 0])
                            self.assertEqual(actual["result"], value & mask)
                            self.assertLessEqual(actual["resources"]["peak_bytes"], maximum)

    def test_mask_from_independent_u8_public_input_bounds_any_u64(self):
        core = verify_program(input_derived_mask())
        self.assertEqual(analyze_constant_live_heap(core), {"dynamic_mask": 255})
        self.assertEqual(
            analyze_static_budget(core, max_live_heap_bytes=255)
            ["functions"][0]["max_live_heap_bytes"], 255)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=254)
        for mask in (0, 1, 3, 15, 63, 127, 255):
            for value in (0, 1, 255, 256, 1234567, (1 << 64) - 1):
                actual = execute_program(core, "dynamic_mask", [value, mask])
                self.assertEqual(actual["result"], value & mask)
                self.assertLessEqual(actual["resources"]["peak_bytes"], 255)

    def test_negative_or_unknown_mask_does_not_forge_heap_certificate(self):
        core = verify_program(selected_interval_mask("i64", negative=True))
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_static_budget(core, max_live_heap_bytes=7)
        self.assertIsNone(_bounded_nonnegative_and_mask(None, _Span(-1, 7), "i64"))
        self.assertIsNone(_bounded_nonnegative_and_mask(None, _Span(-128, -1), "i64"))
        self.assertEqual(_bounded_nonnegative_and_mask(_Span(0, 7), _Span(-1, 31), "i64"),
                         _Span(0, 7))
        self.assertEqual(_bounded_nonnegative_and_mask(_Span(0, 15), _Span(0, 7), "i64"),
                         _Span(0, 7))
        positive = execute_program(core, "masked_interval", [3, False])
        self.assertEqual(positive["result"], 3)
        with self.assertRaises(HIAProgramTrap) as failed:
            execute_program(core, "masked_interval", [-1, True])
        self.assertEqual(failed.exception.code, "overflow")

    def test_exhaustive_u8_mask_intervals_and_signed_inputs(self):
        # 8-bit signed/unsigned control, independent of the graph verifier.
        for signed in (False, True):
            values = range(-128, 128) if signed else range(256)
            for mask in range(0, 128 if signed else 256):
                bound = _bounded_nonnegative_and_mask(None, _Span(0, mask), "i8" if signed else "u8")
                upper = bound if type(bound) is int else bound.hi
                for value in values:
                    self.assertLessEqual(0, value & mask)
                    self.assertLessEqual(value & mask, upper)

    @unittest.skipUnless(
        shutil.which(os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")),
        "pinned LLVM Clang20 not present: genuine Core native comparison unqualified",
    )
    def test_real_core_to_llvm_native_u64_mask_interval(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        core = verify_program(selected_interval_mask("u64"))
        self.assertEqual(analyze_constant_live_heap(core), {"masked_interval": 63})
        ir = emit_program_llvm(core)
        with tempfile.TemporaryDirectory(prefix="hia-mask-native-") as temp:
            artifact = Path(temp) / "mask.so"
            result = compile_program_llvm(
                ir, program=core, output=artifact,
                clang=os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang"))
            self.assertEqual(result["kind"], "shared")
            native = ctypes.CDLL(str(artifact)).masked_interval
            native.argtypes = [ctypes.c_uint64, ctypes.c_bool]
            native.restype = ctypes.c_size_t
            for mask_choice, mask in [(True, 15), (False, 63)]:
                for value in (0, 1, 15, 63, 64, 123456789, (1 << 64) - 1):
                    self.assertEqual(native(value, mask_choice),
                                     execute_program(core, "masked_interval",
                                                     [value, mask_choice])["result"])


if __name__ == "__main__":
    unittest.main()
