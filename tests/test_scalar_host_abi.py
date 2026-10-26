"""Native Linux/x86-64 scalar LLVM shared-library symbol qualification.

This runs real Clang IR→ELF→libc linkage without a Hepta/Rust checkout. It
does not imply full source/LLVM refinement, cross-platform ABI or memory safety.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from hepta.elf_shared_abi import ELFSharedABIRejected, inspect_owned_shared_elf


_NATIVE = (platform.system() == "Linux" and platform.machine() == "x86_64"
           and shutil.which("clang") is not None)

GOOD = """\
define i32 @hepta_scalar_probe(i32 %x) {
entry:
  %result = add i32 %x, 1
  ret i32 %result
}
"""


@unittest.skipUnless(_NATIVE, "Clang and Linux x86-64 native ELF are required")
class ScalarNativeSharedABITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-scalar-host-elf-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def compile(self, source):
        input_path = self.root / "source.ll"
        output_path = self.root / "candidate.so"
        input_path.write_text(source)
        command = [shutil.which("clang"), "-x", "ir", "-O3", "-fPIC",
                   "-shared", str(input_path), "-o", str(output_path)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output_path.is_file())
        return output_path

    def test_real_native_elf_only_exposes_source_C_export(self):
        library = self.compile(GOOD)
        report = inspect_owned_shared_elf(library.read_bytes(), ("hepta_scalar_probe",))
        self.assertEqual(report["dynamic_exports"], ["hepta_scalar_probe"])
        self.assertTrue(report["source_exports_rechecked"])
        self.assertFalse(report["claims"]["native_execution_proven"])
        self.assertFalse(report["claims"]["whole_language_memory_safety_proven"])
        function = ctypes.CDLL(str(library)).hepta_scalar_probe
        function.argtypes = [ctypes.c_int32]
        function.restype = ctypes.c_int32
        for n in (0, 1, 17, 41):
            with self.subTest(value=n):
                self.assertEqual(function(n), n + 1)

    def test_hidden_extra_export_is_rejected(self):
        extra = """\
define i32 @unreviewed_public_data_function(i32 %x) {
entry:
  ret i32 %x
}
"""
        data = self.compile(GOOD + extra).read_bytes()
        with self.assertRaisesRegex(ELFSharedABIRejected, "source|public"):
            inspect_owned_shared_elf(data, ("hepta_scalar_probe",))

    def test_unreviewed_dynamic_external_import_is_rejected(self):
        source = """\
declare i32 @getpid()
define i32 @hepta_scalar_probe(i32 %x) {
entry:
  %pid = call i32 @getpid()
  %result = add i32 %x, %pid
  ret i32 %result
}
"""
        data = self.compile(source).read_bytes()
        with self.assertRaisesRegex(ELFSharedABIRejected, "unreviewed external import"):
            inspect_owned_shared_elf(data, ("hepta_scalar_probe",))

    def test_corrupted_elf_or_forged_expected_export_is_rejected(self):
        data = self.compile(GOOD).read_bytes()
        with self.assertRaises(ELFSharedABIRejected):
            inspect_owned_shared_elf(data[:36], ("hepta_scalar_probe",))
        with self.assertRaises(ELFSharedABIRejected):
            inspect_owned_shared_elf(data, ("unrelated_c_function",))


if __name__ == "__main__":
    unittest.main()
