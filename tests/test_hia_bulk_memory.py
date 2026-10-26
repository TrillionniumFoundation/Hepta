"""HIA v2 bulk memory operations: verifier, interpreter and exact LLVM lowering.

The native-smoke section checks IR text; the complete pinned Clang20 runtime
and hardware qualifications remain separate acceptance gates.
"""
from __future__ import annotations

import copy
import unittest

from hepta.hia_program import SCHEMA, SCHEMA_V2, HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_program_llvm import emit_program_llvm, _can_elide_zero_initialization


def arg(name, typ):
    return {"name": name, "type": typ}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args),
            "out": [arg(name, typ) for name, typ in out], "attrs": attrs}


def bulk_program(schema=SCHEMA_V2):
    params = [arg("size", "usize"), arg("count", "usize"), arg("byte", "u8")]
    ops = [
        ins("buffer.new", ["size"], [("source", "buffer")]),
        ins("buffer.new", ["size"], [("destination", "buffer")]),
        ins("borrow.mut", ["source"], [("writer", "mutbuf")]),
        ins("buffer.fill", ["writer", "byte"]),
        ins("loan.end", ["writer"]),
        ins("borrow.read", ["source"], [("reader", "readbuf")]),
        ins("borrow.mut", ["destination"], [("target", "mutbuf")]),
        ins("buffer.copy", ["target", "reader", "count"]),
        ins("loan.end", ["target"]),
        ins("loan.end", ["reader"]),
        ins("borrow.read", ["destination"], [("check", "readbuf")]),
        ins("const", out=[("zero", "usize")], value=0),
        ins("buffer.load", ["check", "zero"], [("answer", "u8")]),
        ins("loan.end", ["check"]),
        ins("owner.drop", ["source"]),
        ins("owner.drop", ["destination"]),
    ]
    return {"schema": schema, "module": "bulk_memory",
            "functions": [{
                "name": "bulk", "params": params, "returns": ["u8"],
                "effects": ["alloc", "read", "write", "trap"], "entry": "entry",
                "blocks": [{"id": "entry", "params": copy.deepcopy(params),
                            "ops": ops, "term": {"op": "ret", "values": ["answer"]}}]
            }]}


class BulkMemoryV2Tests(unittest.TestCase):
    def test_runtime_fill_copy_and_cleanup(self):
        doc = bulk_program()
        verified = verify_program(doc)
        self.assertEqual(verified.as_dict()["schema"], SCHEMA_V2)
        for n, count, value, expected in ((1, 1, 255, 255),
                                          (16, 10, 7, 7),
                                          (16, 0, 7, 0),
                                          (128, 128, 0, 0)):
            with self.subTest(n=n, count=count, value=value):
                receipt = execute_program(verified, "bulk", [n, count, value])
                self.assertEqual(receipt["result"], expected)
                self.assertEqual(receipt["resources"]["live_owners"], 0)
                self.assertEqual(receipt["resources"]["live_local_loans"], 0)
                self.assertEqual(receipt["resources"]["allocations"], 2 if n else 0)
                self.assertEqual(receipt["resources"]["frees"], 2 if n else 0)

    def test_zero_length_and_short_destination_are_traps_not_resource_leaks(self):
        doc = bulk_program()
        for n, count, byte in ((0, 0, 7), (1, 2, 7), (7, 8, 31)):
            with self.subTest(n=n, count=count):
                with self.assertRaises(HIAProgramTrap) as failure:
                    execute_program(doc, "bulk", [n, count, byte])
                self.assertEqual(failure.exception.code, "bounds")
                self.assertEqual(failure.exception.report["status"], "trapped")

    def test_old_v1_cannot_silently_accept_new_opcodes(self):
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_OPCODE"):
            verify_program(bulk_program(SCHEMA))
        legacy = {"schema": SCHEMA, "module": "old",
                  "functions": [{"name": "id", "params": [arg("x", "u8")],
                                 "returns": ["u8"], "effects": [], "entry": "entry",
                                 "blocks": [{"id": "entry", "params": [arg("x", "u8")],
                                             "ops": [], "term": {"op": "ret", "values": ["x"]}}]}]}
        self.assertEqual(execute_program(legacy, "id", [9])["result"], 9)

    def test_mutable_loan_and_exact_types_required(self):
        for operation, arguments in (("buffer.fill", ["writer", "count"]),
                                     ("buffer.copy", ["reader", "target", "count"]),
                                     ("buffer.copy", ["target", "target", "count"])):
            with self.subTest(operation=operation, args=arguments):
                doc = bulk_program()
                index = 3 if operation == "buffer.fill" else 7
                doc["functions"][0]["blocks"][0]["ops"][index]["args"] = arguments
                with self.assertRaises(HIAProgramRejected):
                    verify_program(doc)

    def test_effect_and_schema_forgery_fail_closed(self):
        doc = bulk_program()
        doc["functions"][0]["effects"].remove("write")
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_EFFECT"):
            verify_program(doc)
        doc = bulk_program()
        doc["functions"][0]["blocks"][0]["ops"][3]["attrs"]["unproved_proof"] = False
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_FORMAT"):
            verify_program(doc)

    def test_actual_emitted_llvm_host_execution_and_trap(self):
        # Finite native differential using the EXACT HIA emitter output, not
        # a handwritten LLVM stand-in. This does not establish compiler proof.
        import ctypes
        import platform
        import shutil
        import signal
        import subprocess
        import tempfile
        from pathlib import Path

        compiler = shutil.which("clang")
        if compiler is None or platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
            self.skipTest("Linux x86-64 with Clang required for native smoke")
        checked = verify_program(bulk_program())
        emitted = emit_program_llvm(checked)
        with tempfile.TemporaryDirectory(prefix="hia-v2-native-") as root:
            root = Path(root)
            assembly = root / "bulk.ll"
            library = root / "libbulk.so"
            assembly.write_text(emitted.text, encoding="ascii")
            command = [compiler, "-x", "ir", "-O2", "-shared", "-fPIC",
                       str(assembly), "-o", str(library)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            native = ctypes.CDLL(str(library)).bulk
            native.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint8]
            native.restype = ctypes.c_uint8
            for args in ((1, 1, 255), (16, 10, 7), (16, 0, 7),
                         (128, 128, 0), (4096, 4096, 197)):
                with self.subTest(args=args):
                    self.assertEqual(native(*args),
                                     execute_program(checked, "bulk", list(args))["result"])

            # Wrong runtime extent must SIGABRT in a child process, not merely
            # return a plausible value from unchecked LLVM memcpy.
            harness = root / "bounds.c"
            exe = root / "bounds"
            harness.write_text("#include <stdint.h>\\n"
                               "uint8_t bulk(uint64_t,uint64_t,uint8_t);\\n"
                               "int main(void){return bulk(1,2,7); }\\n")
            linked = subprocess.run([compiler, str(harness), str(library),
                                     "-Wl,-rpath," + str(root), "-o", str(exe)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            child = subprocess.run([str(exe)], capture_output=True, timeout=30)
            self.assertEqual(child.returncode, -signal.SIGABRT)

    def test_real_llvm_lowerer_consumes_v2_and_keeps_v1_unmodified(self):
        verified = verify_program(bulk_program())
        generated = emit_program_llvm(verified)
        text = generated.text
        self.assertEqual(generated.core_sha256, verified.sha256)
        self.assertTrue(generated.profile.endswith(".v2"))
        self.assertIn("declare void @llvm.memset.p0.i64(", text)
        self.assertIn("declare void @llvm.memcpy.p0.p0.i64(", text)
        self.assertIn("call void @llvm.memset.p0.i64(", text)
        self.assertIn("call void @llvm.memcpy.p0.p0.i64(", text)
        self.assertIn("icmp ule i64 ", text)
        self.assertFalse(_can_elide_zero_initialization(bulk_program()["functions"][0]))


if __name__ == "__main__":
    unittest.main()
