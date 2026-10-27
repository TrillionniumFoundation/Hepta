"""HIA P1 finite OR/XOR intervals after real verified SSA transfers.

The interval upper envelope is a resource-admission fact, not a new
machine operation, ABI rule or code-generation proof.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _Span, _bounded_positive_or_xor,
    analyze_constant_live_heap,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def chained_bitwise(typ="u64"):
    params = [("value", typ), ("pick", "bool")]
    return m(f("chained", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, [
            c("small", typ, 3), c("larger", typ, 5),
            i("select", ["pick", "small", "larger"], [("mask", typ)]),
            i("bit.and", ["value", "mask"], [("masked", typ)]),
            c("six", typ, 6),
            i("bit.or", ["masked", "six"], [("joined", typ)]),
            c("one", typ, 1),
            i("bit.xor", ["joined", "one"], [("bits", typ)]),
            i("int.cast", ["bits"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("size")),
    ]))


def two_unknown_u16(op):
    params = [("left", "u16"), ("right", "u16")]
    return m(f("small_word", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, [
            i(op, ["left", "right"], [("bits", "u16")]),
            i("int.cast", ["bits"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("size")),
    ]))


def unbounded_wide(op):
    params = [("value", "u64")]
    return m(f("unknown_wide", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, [
            c("mask", "u64", 6),
            i(op, ["value", "mask"], [("bits", "u64")]),
            i("int.cast", ["bits"], [("size", "usize")], mode="checked"),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("owner.drop", ["owner"]),
        ], ret("size")),
    ]))


class HIAOrXorIntervalTests(unittest.TestCase):
    def test_chained_bitwise_proof_bounds_unknown_signed_and_unsigned_wide_inputs(self):
        for typ, values in (
            ("u64", (0, 1, 5, 15, 255, (1 << 64) - 1)),
            ("i64", (-(1 << 63), -1, -73, 0, 3, (1 << 63) - 1)),
        ):
            with self.subTest(typ=typ):
                core = verify_program(chained_bitwise(typ))
                self.assertEqual(analyze_constant_live_heap(core), {"chained": 7})
                self.assertEqual(
                    analyze_static_budget(core, max_live_heap_bytes=7)
                    ["functions"][0]["max_live_heap_bytes"], 7)
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                    analyze_static_budget(core, max_live_heap_bytes=6)
                for value in values:
                    for flag, mask in ((True, 3), (False, 5)):
                        actual = execute_program(core, "chained", [value, flag])
                        expected = ((value & mask) | 6) ^ 1
                        self.assertEqual(actual["result"], expected)
                        self.assertLessEqual(actual["resources"]["peak_bytes"], 7)

    def test_typed_dynamic_u16_or_xor_have_conservative_full_domain(self):
        for op in ("bit.or", "bit.xor"):
            with self.subTest(op=op):
                core = verify_program(two_unknown_u16(op))
                self.assertEqual(analyze_constant_live_heap(core), {"small_word": 65535})
                with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
                    analyze_static_budget(core, max_live_heap_bytes=65534)
                for left, right in ((0, 0), (1, 2), (1, 65535),
                                    (32767, 32768), (65535, 65535)):
                    result = execute_program(core, "small_word", [left, right])
                    self.assertEqual(result["result"],
                                     left | right if op == "bit.or" else left ^ right)
                    self.assertLessEqual(result["resources"]["peak_bytes"], 65535)

    def test_unknown_u64_or_xor_and_signed_negative_domains_fail_closed(self):
        for op in ("bit.or", "bit.xor"):
            core = verify_program(unbounded_wide(op))
            with self.subTest(op=op):
                with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
                    analyze_constant_live_heap(core)
        self.assertIsNone(_bounded_positive_or_xor(None, 3, "u64"))
        self.assertIsNone(_bounded_positive_or_xor(_Span(-1, 7), 3, "i64"))
        self.assertIsNone(_bounded_positive_or_xor(_Span(0, 7), _Span(-1, 3), "i64"))
        self.assertEqual(_bounded_positive_or_xor(_Span(0, 5), 6, "u64"),
                         _Span(0, 7))
        self.assertEqual(_bounded_positive_or_xor(_Span(0, 31), _Span(0, 11), "u64"),
                         _Span(0, 31))

    def test_exhaustive_small_nonnegative_upper_envelopes(self):
        for top_a in range(16):
            for top_b in range(16):
                result = _bounded_positive_or_xor(_Span(0, top_a), _Span(0, top_b), "u8")
                limit = result if type(result) is int else result.hi
                for a in range(top_a + 1):
                    for b in range(top_b + 1):
                        self.assertLessEqual(a | b, limit)
                        self.assertLessEqual(a ^ b, limit)

    @unittest.skipUnless(
        shutil.which(os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")),
        "pinned Clang20 missing: Core LLVM/native end-to-end unqualified",
    )
    def test_genuine_hia_llvm_or_xor_dynamic_native(self):
        from hepta.hia_program_llvm import emit_program_llvm, compile_program_llvm
        core = verify_program(chained_bitwise())
        llvm = emit_program_llvm(core)
        with tempfile.TemporaryDirectory(prefix="hia-or-xor-") as temp:
            so = Path(temp) / "bitwise.so"
            report = compile_program_llvm(
                llvm, program=core, output=so,
                clang=os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang"))
            self.assertEqual(report["kind"], "shared")
            native = ctypes.CDLL(str(so)).chained
            native.argtypes = [ctypes.c_uint64, ctypes.c_bool]
            native.restype = ctypes.c_size_t
            for value in (0, 1, 7, 255, (1 << 64) - 1):
                for flag in (True, False):
                    self.assertEqual(native(value, flag),
                                     execute_program(core, "chained", [value, flag])["result"])


if __name__ == "__main__":
    unittest.main()
