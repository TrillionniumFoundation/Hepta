"""P1/P2: true zero-length bulk memory is a no-op even with empty/null owners.

Core v2/v3/v5 retain their original checked bounds and loan obligations.
No new verifier, compiler or ABI profile is introduced. This checks the
actual HIA LLVM emitter and, when available, executes its *emitted* LLVM.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_program import SCHEMA_V2, SCHEMA_V3, SCHEMA_V5, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_program_llvm import emit_program_llvm, TARGET_AARCH64


def param(name, typ):
    return {"name": name, "type": typ}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args),
            "out": [param(*value) for value in out], "attrs": attrs}


def zero_bulk_program(kind):
    """One verified function, owns all storage, no user-supplied pointers."""
    params = [param("length", "usize"),
              param("dst", "usize"), param("src", "usize"),
              param("count", "usize")]
    ops = [ins("buffer.new", ["length"], [("destination", "buffer")])]
    if kind in {"fill_and_copy", "copy_range"}:
        ops.append(ins("buffer.new", ["length"], [("source", "buffer")]))
    ops.append(ins("borrow.mut", ["destination"], [("writer", "mutbuf")]))
    if kind == "fill_and_copy":
        ops.extend((
            ins("const", out=[("fill_byte", "u8")], value=123),
            ins("buffer.fill", ["writer", "fill_byte"]),
            ins("loan.end", ["writer"]),
            ins("borrow.read", ["destination"], [("reader", "readbuf")]),
            ins("borrow.mut", ["source"], [("target", "mutbuf")]),
            ins("buffer.copy", ["target", "reader", "count"]),
            ins("loan.end", ["target"]),
            ins("loan.end", ["reader"]),
        ))
    elif kind == "move_within":
        ops.extend((
            ins("buffer.move_within", ["writer", "dst", "src", "count"]),
            ins("loan.end", ["writer"]),
        ))
    elif kind == "copy_range":
        ops.extend((
            ins("borrow.read", ["source"], [("reader", "readbuf")]),
            ins("buffer.copy_range", ["writer", "reader", "dst", "src", "count"]),
            ins("loan.end", ["reader"]),
            ins("loan.end", ["writer"]),
        ))
    else:
        raise ValueError("unsupported fixture")
    ops.append(ins("owner.drop", ["destination"]))
    if kind in {"fill_and_copy", "copy_range"}:
        ops.append(ins("owner.drop", ["source"]))
    ops.append(ins("const", out=[("answer", "u8")], value=77))
    fn = {"name": "zero_bulk", "params": params, "returns": ["u8"],
          "effects": ["alloc", "read", "write", "trap"],
          "entry": "entry",
          "blocks": [{"id": "entry", "params": params, "ops": ops,
                      "term": {"op": "ret", "values": ["answer"]}}]}
    return {"schema": {"fill_and_copy": SCHEMA_V2, "move_within": SCHEMA_V3,
                        "copy_range": SCHEMA_V5}[kind],
            "module": "zero_bulk_regression", "functions": [fn]}


def function_llvm(text):
    match = re.search(r"define internal i8 @__hia_fn_0\([^\n]*\) \{([\s\S]*?)\n\}", text)
    if match is None:
        raise AssertionError("expected exact internal scalar return function")
    return match.group(1)


class HIAZeroLengthBulkTests(unittest.TestCase):
    KINDS = ("fill_and_copy", "move_within", "copy_range")

    def test_verified_empty_owners_have_no_bulk_pointer_side_effects(self):
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                verified = verify_program(zero_bulk_program(kind))
                receipt = execute_program(verified, "zero_bulk", [0, 0, 0, 0])
                self.assertEqual(receipt["result"], 77)
                self.assertEqual(receipt["resources"]["allocations"], 0)
                self.assertEqual(receipt["resources"]["frees"], 0)
                self.assertEqual(receipt["resources"]["live_owners"], 0)
                self.assertEqual(receipt["resources"]["live_local_loans"], 0)

                ir = emit_program_llvm(verified)
                self.assertEqual(ir.core_sha256, verified.sha256)
                function = function_llvm(ir.text)
                labels = re.findall(r"(?m)^(bulk_nonzero_(\d+)):$", function)
                self.assertEqual(len(labels), 2 if kind == "fill_and_copy" else 1)
                for label, number in labels:
                    # The zero-length edge bypasses *all* memory intrinsics
                    # and GEPs introduced for the corresponding bulk action.
                    after = "bulk_after_" + number
                    branch = "label %" + label + ", label %" + after
                    self.assertIn(branch, function)
                    begin = function.index(label + ":\n")
                    end = function.index(after + ":\n", begin)
                    body = function[begin:end]
                    self.assertRegex(body, r"call void @llvm\.mem(?:set|cpy|move)")
                    self.assertTrue(body.rstrip().endswith("br label %" + after))
                for match in re.finditer(r"call void @llvm\.mem(?:set|cpy|move)", function):
                    self.assertTrue(any(
                        function.index(label + ":\n") < match.start()
                        < function.index("bulk_after_" + n + ":\n",
                                         function.index(label + ":\n"))
                        for label, n in labels))

                arm = emit_program_llvm(verified, target=TARGET_AARCH64)
                self.assertEqual(arm.core_sha256, verified.sha256)
                self.assertIn("bulk_nonzero_", arm.text)

    def test_zero_count_does_not_skip_original_bounds_checks(self):
        scenarios = (
            ("fill_and_copy", [0, 0, 0, 1]),
            ("move_within", [0, 1, 0, 0]),
            ("copy_range", [0, 0, 1, 0]),
        )
        for kind, args in scenarios:
            with self.subTest(kind=kind, args=args):
                with self.assertRaises(HIAProgramTrap) as trap:
                    execute_program(zero_bulk_program(kind), "zero_bulk", args)
                self.assertEqual(trap.exception.code, "bounds")

    @unittest.skipUnless(shutil.which("clang") and platform.system() == "Linux"
                         and platform.machine() in {"x86_64", "amd64"},
                         "native Clang/Linux x86-64 required")
    def test_real_emitted_llvm_null_empty_owners_match_interpreter(self):
        compiler = shutil.which("clang")
        with tempfile.TemporaryDirectory(prefix="hia-zero-bulk-") as directory:
            root = Path(directory)
            for index, kind in enumerate(self.KINDS):
                with self.subTest(kind=kind):
                    verified = verify_program(zero_bulk_program(kind))
                    emitted = emit_program_llvm(verified)
                    source = root / ("bulk" + str(index) + ".ll")
                    library = root / ("bulk" + str(index) + ".so")
                    source.write_text(emitted.text, encoding="ascii")
                    compiled = subprocess.run(
                        [compiler, "-x", "ir", "-O2", "-shared", "-fPIC",
                         str(source), "-o", str(library)],
                        capture_output=True, text=True, timeout=60)
                    self.assertEqual(compiled.returncode, 0, compiled.stderr)
                    native = ctypes.CDLL(str(library)).zero_bulk
                    native.argtypes = [ctypes.c_uint64] * 4
                    native.restype = ctypes.c_uint8
                    for args in ((0, 0, 0, 0), (5, 5, 5, 0),
                                 (8, 0, 0, 3)):
                        expected = execute_program(verified, "zero_bulk", list(args))["result"]
                        self.assertEqual(native(*args), expected)


if __name__ == "__main__":
    unittest.main()
