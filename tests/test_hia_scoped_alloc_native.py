"""Optional exact native HIA Core->LLVM->C ABI differential for scoped heap loops.

Must run with an actual pinned Clang20+ Linux x86-64 native backend. Do not
count an unrun/skip as native evidence. The VM measures live owner payload;
native return parity alone cannot attest real allocator cleanup.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_heap_bound import qualify_live_heap_budget
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from hepta.hia_program_runtime import execute_program
from tests.test_hia_program import i
from tests.test_hia_scoped_alloc_loops import scoped_loop

CLANG = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")


def _bounded_narrow_loop():
    source = scoped_loop()
    body = next(x for x in source["functions"][0]["blocks"] if x["id"] == "body")
    body["ops"] = [
        i("int.cast", ["r"], [("small", "u8")], mode="checked"),
        i("int.cast", ["small"], [("size", "usize")], mode="checked"),
        i("buffer.new", ["size"], [("dynamic_owner", "buffer")]),
        i("owner.drop", ["dynamic_owner"]),
        *body["ops"][4:],
    ]
    return source


@unittest.skipUnless(shutil.which(CLANG),
                     "exact Clang20+ standalone native HIA qualification unavailable")
class ScopedAllocatingNativeDifferential(unittest.TestCase):
    def test_scoped_owners_native_return_values_match_core_vm(self):
        cases = (
            (scoped_loop(), 9),
            (scoped_loop(two_allocations=True), 13),
            (scoped_loop(in_entry=True), 9),
            (_bounded_narrow_loop(), 255),
        )
        with tempfile.TemporaryDirectory(prefix="hia-scoped-native-") as temp:
            root = Path(temp)
            for index, (document, bound) in enumerate(cases):
                with self.subTest(profile=index):
                    core = verify_program(document)
                    admitted = qualify_live_heap_budget(core, max_live_heap_bytes=bound)
                    ir = emit_program_llvm(core)
                    path = root / f"hia-scoped-{index}.so"
                    receipt = compile_program_llvm(
                        ir, program=core, output=path, clang=CLANG)
                    self.assertEqual(receipt["core_sha256"], core.sha256)
                    self.assertEqual(receipt["llvm_ir_sha256"], ir.sha256)
                    self.assertTrue(receipt["claims"]["standalone_core_reverified"])
                    self.assertFalse(receipt["claims"]["backend_refinement_proved"])
                    self.assertFalse(receipt["claims"]["native_execution_qualified"])
                    self.assertEqual(admitted["program_sha256"], core.sha256)
                    library = ctypes.CDLL(str(path))
                    entry = library.count_down
                    entry.argtypes = [ctypes.c_uint32]
                    entry.restype = ctypes.c_uint32
                    for n in (0, 1, 2, 7, 31):
                        oracle = execute_program(core, "count_down", [n])
                        self.assertEqual(entry(n), oracle["result"])
                        self.assertLessEqual(oracle["resources"]["peak_bytes"], bound)
                        self.assertEqual(oracle["resources"]["live_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
