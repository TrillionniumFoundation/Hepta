"""HIA P1: sound interval transfer for fixed-width bit.not.

Canonical verified Core, static-budget and independent interpreter determine
the accepted successful-path payload bound. Native emitter test is opt-in.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_heap_bound import (
    HIAHeapBoundRejected, _Span, _bounded_bitnot,
    analyze_constant_live_heap,
)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_program import b, c, f, i, m, ret


def complement(source="u8", *, selected=False):
    params = [("value", source)] if not selected else [("choose", "bool")]
    operations = []
    if selected:
        operations = [
            c("small", source, 240), c("large", source, 254),
            i("select", ["choose", "small", "large"], [("input", source)]),
        ]
    operations.extend([
        i("bit.not", ["input" if selected else "value"], [("bits", source)]),
        i("int.cast", ["bits"], [("size", "usize")], mode="checked"),
        i("buffer.new", ["size"], [("o", "buffer")]),
        i("owner.drop", ["o"]),
    ])
    return m(f("complement", params, ["usize"], ["alloc", "trap"], [
        b("entry", params, operations, ret("size")),
    ]))


class HIABitNotIntervalTests(unittest.TestCase):
    def test_nonexact_selected_interval_is_precisely_complemented(self):
        core = verify_program(complement(selected=True))
        self.assertEqual(analyze_constant_live_heap(core), {"complement": 15})
        self.assertEqual(
            analyze_static_budget(core, max_live_heap_bytes=15)
            ["functions"][0]["max_live_heap_bytes"], 15)
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=14)
        for flag, expected in ((True, 15), (False, 1)):
            actual = execute_program(core, "complement", [flag])
            self.assertEqual(actual["result"], expected)
            self.assertLessEqual(actual["resources"]["peak_bytes"], 15)

    def test_dynamic_u8_input_has_full_proven_finite_ones_complement(self):
        core = verify_program(complement("u8"))
        self.assertEqual(analyze_constant_live_heap(core), {"complement": 255})
        with self.assertRaisesRegex(ValueError, "E_HIA_BUDGET_EXCEEDED"):
            analyze_static_budget(core, max_live_heap_bytes=254)
        for value in range(256):
            actual = execute_program(core, "complement", [value])
            self.assertEqual(actual["result"], 255 - value)
            self.assertLessEqual(actual["resources"]["peak_bytes"], 255)

    def test_signed_i8_successful_cast_interval_respects_traps(self):
        core = verify_program(complement("i8"))
        self.assertEqual(analyze_constant_live_heap(core), {"complement": 127})
        for value in (-128, -64, -8, -1, 0, 1, 127):
            with self.subTest(value=value):
                if value >= 0:
                    with self.assertRaises(HIAProgramTrap) as raised:
                        execute_program(core, "complement", [value])
                    self.assertEqual(raised.exception.code, "overflow")
                else:
                    actual = execute_program(core, "complement", [value])
                    self.assertEqual(actual["result"], -value - 1)
                    self.assertLessEqual(actual["resources"]["peak_bytes"], 127)

    def test_full_width_unknown_and_out_of_domain_intervals_reject(self):
        core = verify_program(complement("u64"))
        with self.assertRaisesRegex(HIAHeapBoundRejected, "E_HIA_BUDGET_UNBOUNDED"):
            analyze_constant_live_heap(core)
        self.assertIsNone(_bounded_bitnot(None, "u8"))
        self.assertIsNone(_bounded_bitnot(_Span(-1, 255), "u8"))
        self.assertIsNone(_bounded_bitnot(_Span(-129, 127), "i8"))
        self.assertEqual(_bounded_bitnot(_Span(240, 254), "u8"), _Span(1, 15))
        self.assertEqual(_bounded_bitnot(_Span(-128, -1), "i8"), _Span(0, 127))

    def test_exhaustive_exact_byte_values_match_machine_ones_complement(self):
        for typ, values, width in [
            ("u8", range(256), 8), ("i8", range(-128, 128), 8),
        ]:
            for source in values:
                result = _bounded_bitnot(source, typ)
                expected = ~source if typ == "i8" else (~source) & ((1 << width) - 1)
                self.assertEqual(result, expected)

    @unittest.skipUnless(
        shutil.which(os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")),
        "pinned Clang20 absent: genuine HIA Core LLVM native execution unqualified",
    )
    def test_real_core_to_llvm_for_dynamic_complement(self):
        from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
        core = verify_program(complement("u8"))
        ir = emit_program_llvm(core)
        with tempfile.TemporaryDirectory(prefix="hia-not-native-") as temp:
            output = Path(temp) / "not.so"
            result = compile_program_llvm(
                ir, program=core, output=output,
                clang=os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang"))
            self.assertEqual(result["kind"], "shared")
            native = ctypes.CDLL(str(output)).complement
            native.argtypes = [ctypes.c_uint8]
            native.restype = ctypes.c_size_t
            for value in (0, 1, 13, 127, 128, 240, 254, 255):
                self.assertEqual(native(value),
                                 execute_program(core, "complement", [value])["result"])


if __name__ == "__main__":
    unittest.main()
