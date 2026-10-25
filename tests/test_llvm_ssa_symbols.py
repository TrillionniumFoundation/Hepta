"""Five-platform defined-export checks; no cross-runtime execution or ABI claim."""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
import shutil
import subprocess
import tempfile
import unittest

from hepta.llvm_ssa_backend import SSA_LLVM_IR, LLVMSSARejected
from hepta.llvm_ssa_target import (
    _TARGETS, _qualified_header, _defined_exports, compile_ssa_target_object,
)

_LLVM = """define i32 @hepta_target_symbol(i32 %x) {
entry:
  ret i32 %x
}
"""


@unittest.skipUnless(shutil.which("clang"), "Real Clang object emission is required")
class NativeObjectSymbols(unittest.TestCase):
    def test_five_targets_reject_missing_defined_function_symbols(self):
        with tempfile.TemporaryDirectory(prefix="hepta-object-symbol-") as folder:
            root = Path(folder)
            src = root / "module.ll"
            src.write_text(_LLVM, encoding="utf-8")
            for target in sorted(_TARGETS):
                with self.subTest(target=target):
                    obj = root / (target + ".o")
                    built = subprocess.run(
                        ["clang", "--target=" + target, "-x", "ir", "-O3",
                         "-c", str(src), "-o", str(obj)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(built.returncode, 0, built.stderr)
                    artifact = obj.read_bytes()
                    self.assertTrue(_qualified_header(artifact, target))
                    self.assertIn("hepta_target_symbol", _defined_exports(artifact, target))
                    self.assertIn(b"hepta_target_symbol", artifact)
                    # Keep format and offsets intact; relabel the exported name.
                    forged = artifact.replace(b"hepta_target_symbol",
                                              b"hepta_target_symbxl", 1)
                    self.assertEqual(len(forged), len(artifact))
                    self.assertTrue(_qualified_header(forged, target))
                    self.assertNotIn("hepta_target_symbol", _defined_exports(forged, target))

    def test_backend_rejects_missing_export_without_publishing(self):
        ir = SSA_LLVM_IR(
            _LLVM, sha256(_LLVM.encode()).hexdigest(),
            ("hepta_target_symbol",), "a" * 64, "b" * 64,
        )
        ir.check_identity()
        with tempfile.TemporaryDirectory(prefix="hepta-exports-") as tmp:
            output = Path(tmp) / "valid.o"
            receipt = compile_ssa_target_object(
                ir, target="x86_64-unknown-linux-gnu", output=output)
            self.assertIn("hepta_target_symbol", receipt["verified_defined_exports"])
            self.assertGreater(output.stat().st_size, 0)
            missing = Path(tmp) / "missing.o"
            with patch("hepta.llvm_ssa_target._defined_exports", return_value=frozenset()):
                with self.assertRaisesRegex(LLVMSSARejected, "E_LLVM_SSA_SYMBOLS"):
                    compile_ssa_target_object(
                        ir, target="x86_64-unknown-linux-gnu", output=missing)
            self.assertFalse(missing.exists())

    def test_truncated_objects_do_not_produce_export_claims(self):
        with tempfile.TemporaryDirectory(prefix="hepta-exports-") as tmp:
            src = Path(tmp) / "module.ll"
            src.write_text(_LLVM, encoding="utf-8")
            output = Path(tmp) / "native.o"
            subprocess.run(["clang", "-x", "ir", "-c", str(src), "-o", str(output)],
                           check=True, capture_output=True, timeout=30)
            data = output.read_bytes()
            self.assertEqual(_defined_exports(data[:20], "x86_64-unknown-linux-gnu"),
                             frozenset())


if __name__ == "__main__":
    unittest.main()
