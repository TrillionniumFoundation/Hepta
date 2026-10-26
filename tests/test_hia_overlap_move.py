"""HIA v3 overlap-safe in-place byte moves: actual Core verifier/VM/LLVM tests.

A memmove intrinsic is deliberately required: unlike v2 memcpy, src/dst here
share one owner and may overlap. These tests do not qualify whole-language
provenance, LLVM semantic refinement, physical hardware or arbitrary C++.
"""
from __future__ import annotations

import ctypes
import copy
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.hia_program import SCHEMA, SCHEMA_V2, SCHEMA_V3, HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_program_llvm import (
    PROFILE_V3, PROFILE_AARCH64_V3, TARGET_AARCH64,
    _can_elide_zero_initialization, emit_program_llvm,
)


def param(name, typ):
    return {"name": name, "type": typ}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": [param(*x) for x in out],
            "attrs": attrs}


def move_program(schema=SCHEMA_V3):
    params = [param(name, "usize") for name in
              ("length", "destination", "source", "count", "probe")]
    ops = [
        ins("buffer.new", ["length"], [("owned", "buffer")]),
        ins("borrow.mut", ["owned"], [("writer", "mutbuf")]),
    ]
    for n, value in enumerate((11, 22, 33, 44, 55)):
        ops += [ins("const", out=[("idx" + str(n), "usize")], value=n),
                ins("const", out=[("byte" + str(n), "u8")], value=value),
                ins("buffer.store", ["writer", "idx" + str(n), "byte" + str(n)])]
    ops += [
        ins("buffer.move_within", ["writer", "destination", "source", "count"]),
        ins("buffer.load", ["writer", "probe"], [("answer", "u8")]),
        ins("loan.end", ["writer"]),
        ins("owner.drop", ["owned"]),
    ]
    return {"schema": schema, "module": "overlapping_byte_moves",
            "functions": [{"name": "move_bytes", "params": params,
                           "returns": ["u8"], "effects": ["alloc", "read", "write", "trap"],
                           "entry": "entry",
                           "blocks": [{"id": "entry", "params": params, "ops": ops,
                                      "term": {"op": "ret", "values": ["answer"]}}]}]}


def empty_program():
    params = [param("length", "usize")]
    ops = [
        ins("buffer.new", ["length"], [("owner", "buffer")]),
        ins("borrow.mut", ["owner"], [("loan", "mutbuf")]),
        ins("const", out=[("zero", "usize")], value=0),
        ins("buffer.move_within", ["loan", "zero", "zero", "zero"]),
        ins("loan.end", ["loan"]),
        ins("owner.drop", ["owner"]),
        ins("const", out=[("answer", "u8")], value=42),
    ]
    return {"schema": SCHEMA_V3, "module": "empty_byte_moves",
            "functions": [{"name": "empty", "params": params,
                           "returns": ["u8"], "effects": ["alloc", "read", "write", "trap"],
                           "entry": "entry",
                           "blocks": [{"id": "entry", "params": params, "ops": ops,
                                      "term": {"op": "ret", "values": ["answer"]}}]}]}


class HIAOverlapMoveTests(unittest.TestCase):
    def test_right_and_left_overlaps_and_exact_same_range(self):
        checked = verify_program(move_program())
        scenarios = (
            ((5, 1, 0, 4), [11, 11, 22, 33, 44]),
            ((5, 0, 1, 4), [22, 33, 44, 55, 55]),
            ((5, 2, 2, 3), [11, 22, 33, 44, 55]),
            ((5, 5, 5, 0), [11, 22, 33, 44, 55]),
            ((5, 0, 0, 0), [11, 22, 33, 44, 55]),
        )
        for (length, dst, src, count), expected in scenarios:
            for index, byte in enumerate(expected):
                args = [length, dst, src, count, index]
                with self.subTest(args=args):
                    report = execute_program(checked, "move_bytes", args)
                    self.assertEqual(report["result"], byte)
                    self.assertEqual(report["resources"]["live_owners"], 0)
                    self.assertEqual(report["resources"]["live_bytes"], 0)
                    self.assertEqual(report["resources"]["loans_started"], 1)
                    self.assertEqual(report["resources"]["loans_ended"], 1)

    def test_empty_nonallocating_move_and_boundaries(self):
        checked = verify_program(empty_program())
        report = execute_program(checked, "empty", [0])
        self.assertEqual(report["result"], 42)
        self.assertEqual(report["resources"]["allocations"], 0)
        self.assertEqual(report["resources"]["frees"], 0)
        self.assertEqual(report["resources"]["live_owners"], 0)

    def test_range_bounds_trap_before_memmove(self):
        checked = verify_program(move_program())
        for dst, src, size in ((6, 0, 0), (0, 6, 0),
                               (5, 0, 1), (0, 5, 1),
                               (3, 0, 3), (0, 4, 2),
                               (0, 0, 2**64 - 1)):
            with self.subTest(dst=dst, src=src, size=size):
                with self.assertRaises(HIAProgramTrap) as error:
                    execute_program(checked, "move_bytes",
                                    [5, dst, src, size, 0])
                self.assertEqual(error.exception.code, "bounds")

    def test_v1_v2_never_silently_admit_v3_opcode(self):
        for schema in (SCHEMA, SCHEMA_V2):
            with self.subTest(schema=schema):
                with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_OPCODE"):
                    verify_program(move_program(schema=schema))

    def test_unique_mutable_borrow_and_strict_offsets(self):
        cases = {
            "shared_loan": lambda ops, idx: (ops[1].update(
                op="borrow.read", out=[param("writer", "readbuf")])),
            "wrong_offset_type": lambda ops, idx: ops[idx].update(args=[
                "writer", "destination", "byte0", "count"]),
            "missing_read_effect": lambda ops, idx: None,
            "unknown_proof": lambda ops, idx: ops[idx]["attrs"].update(assumed_nonalias=True),
            "illegal_output": lambda ops, idx: ops[idx].update(out=[param("copied", "usize")]),
        }
        for case, mutate in cases.items():
            with self.subTest(case=case):
                doc = move_program()
                ops = doc["functions"][0]["blocks"][0]["ops"]
                index = next(i for i, op in enumerate(ops) if op["op"] == "buffer.move_within")
                mutate(ops, index)
                if case == "missing_read_effect":
                    doc["functions"][0]["effects"].remove("read")
                with self.assertRaises(HIAProgramRejected):
                    verify_program(doc)

    def test_verified_v3_emitter_uses_memmove_not_memcpy_and_guards(self):
        checked = verify_program(move_program())
        emitted = emit_program_llvm(checked)
        self.assertEqual(emitted.profile, PROFILE_V3)
        self.assertEqual(emitted.core_sha256, checked.sha256)
        self.assertIn("call void @llvm.memmove.p0.p0.i64", emitted.text)
        self.assertIn("declare void @llvm.memmove.p0.p0.i64", emitted.text)
        self.assertNotIn("call void @llvm.memcpy.p0.p0.i64", emitted.text)
        self.assertGreaterEqual(emitted.text.count("icmp ule i64"), 4)
        self.assertFalse(_can_elide_zero_initialization(move_program()["functions"][0]))
        arm = emit_program_llvm(checked, target=TARGET_AARCH64)
        self.assertEqual(arm.profile, PROFILE_AARCH64_V3)
        self.assertIn("llvm.memmove.p0.p0.i64", arm.text)

    @unittest.skipUnless(shutil.which("clang") and platform.system() == "Linux"
                         and platform.machine() in {"x86_64", "amd64"},
                         "actual Linux x86-64 Clang required")
    def test_real_llvm_host_overlap_and_bounds_abort(self):
        checked = verify_program(move_program())
        emitted = emit_program_llvm(checked)
        with tempfile.TemporaryDirectory(prefix="hia-memmove-native-") as root:
            directory = Path(root)
            ll, so = directory / "move.ll", directory / "move.so"
            ll.write_text(emitted.text, encoding="ascii")
            compiled = subprocess.run(
                [shutil.which("clang"), "-x", "ir", "-O2", "-shared", "-fPIC",
                 str(ll), "-o", str(so)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            native = ctypes.CDLL(str(so)).move_bytes
            native.argtypes = [ctypes.c_uint64] * 5
            native.restype = ctypes.c_uint8
            for args in ((5, 1, 0, 4, 0), (5, 1, 0, 4, 2),
                         (5, 1, 0, 4, 4), (5, 0, 1, 4, 0),
                         (5, 0, 1, 4, 3), (5, 2, 2, 3, 4),
                         (5, 5, 5, 0, 0), (5, 0, 0, 0, 4)):
                with self.subTest(args=args):
                    self.assertEqual(native(*args),
                                     execute_program(checked, "move_bytes", list(args))["result"])

            cfile, exe = directory / "bounds.c", directory / "bounds"
            cfile.write_text(
                "#include <stdint.h>\n"
                "uint8_t move_bytes(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);\n"
                "int main(void){return move_bytes(5,3,0,3,0);}\n", encoding="ascii")
            linked = subprocess.run(
                [shutil.which("clang"), str(cfile), str(so),
                 "-Wl,-rpath," + str(directory), "-o", str(exe)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            child = subprocess.run([str(exe)], capture_output=True, timeout=30)
            self.assertEqual(child.returncode, -signal.SIGABRT)


if __name__ == "__main__":
    unittest.main()
