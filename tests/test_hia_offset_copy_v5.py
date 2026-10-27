"""HIA v5: two distinct byte owners, checked offset copy, VM/native parity."""
from __future__ import annotations

import ctypes
import platform
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.hia_program import (
    SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5,
    HIAProgramRejected, verify_program,
)
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_program_llvm import (
    PROFILE_V5, PROFILE_AARCH64_V5, TARGET_AARCH64, emit_program_llvm,
)


def param(name, typ):
    return {"name": name, "type": typ}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": [param(*x) for x in out],
            "attrs": attrs}


def copy_program(schema=SCHEMA_V5):
    params = [param(x, "usize") for x in ("length", "dst", "src", "count", "probe")]
    ops = [
        ins("buffer.new", ["length"], [("destination", "buffer")]),
        ins("buffer.new", ["length"], [("source", "buffer")]),
        ins("borrow.mut", ["source"], [("source_writer", "mutbuf")]),
    ]
    for index, value in enumerate((11, 22, 33, 44, 55)):
        ops.extend((
            ins("const", out=[("idx" + str(index), "usize")], value=index),
            ins("const", out=[("byte" + str(index), "u8")], value=value),
            ins("buffer.store", ["source_writer", "idx" + str(index), "byte" + str(index)]),
        ))
    ops.extend((
        ins("loan.end", ["source_writer"]),
        ins("borrow.read", ["source"], [("reader", "readbuf")]),
        ins("borrow.mut", ["destination"], [("writer", "mutbuf")]),
        ins("buffer.copy_range", ["writer", "reader", "dst", "src", "count"]),
        ins("buffer.load", ["writer", "probe"], [("answer", "u8")]),
        ins("loan.end", ["writer"]),
        ins("loan.end", ["reader"]),
        ins("owner.drop", ["destination"]),
        ins("owner.drop", ["source"]),
    ))
    return {
        "schema": schema, "module": "distinct_owner_copy",
        "functions": [{
            "name": "copy_offset", "params": params, "returns": ["u8"],
            "effects": ["alloc", "read", "write", "trap"], "entry": "entry",
            "blocks": [{"id": "entry", "params": params, "ops": ops,
                        "term": {"op": "ret", "values": ["answer"]}}],
        }],
    }


class OffsetCopyTests(unittest.TestCase):
    def test_finite_exact_values_and_cleanup(self):
        program = verify_program(copy_program())
        original = [11, 22, 33, 44, 55]
        for dst, src, count in ((0, 0, 5), (1, 2, 2),
                                (2, 1, 2), (5, 5, 0)):
            expected = [0] * 5
            expected[dst:dst + count] = original[src:src + count]
            for probe, answer in enumerate(expected):
                args = [5, dst, src, count, probe]
                with self.subTest(args=args):
                    report = execute_program(program, "copy_offset", args)
                    self.assertEqual(report["result"], answer)
                    self.assertEqual(report["resources"]["live_owners"], 0)
                    self.assertEqual(report["resources"]["live_local_loans"], 0)
                    self.assertEqual(report["resources"]["allocations"],
                                     report["resources"]["frees"])

    def test_old_version_isolation(self):
        for schema in (SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4):
            with self.subTest(schema=schema):
                with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_OPCODE"):
                    verify_program(copy_program(schema))

    def test_all_four_overrun_conditions_trap(self):
        program = verify_program(copy_program())
        for dst, src, count in ((5, 0, 1), (0, 5, 1),
                                (2**64 - 1, 0, 1), (0, 2**64 - 1, 1),
                                (1, 1, 5), (5, 5, 2)):
            with self.subTest(dst=dst, src=src, count=count):
                with self.assertRaises(HIAProgramTrap) as trap:
                    execute_program(program, "copy_offset", [5, dst, src, count, 0])
                self.assertEqual(trap.exception.code, "bounds")

    def test_no_unsafe_alias_effect_or_unreviewed_attributes(self):
        for case in ("no_exclusive", "not_read_only", "wrong_offset",
                     "missing_read", "extra_proof", "extra_output", "alias"):
            doc = copy_program()
            fn = doc["functions"][0]
            ops = fn["blocks"][0]["ops"]
            idx = next(i for i, op in enumerate(ops) if op["op"] == "buffer.copy_range")
            if case == "no_exclusive":
                ops[idx]["args"][0] = "reader"
            elif case == "not_read_only":
                ops[idx]["args"][1] = "writer"
            elif case == "wrong_offset":
                ops[idx]["args"][2] = "byte0"
            elif case == "missing_read":
                fn["effects"].remove("read")
            elif case == "extra_proof":
                ops[idx]["attrs"]["non_alias_proved"] = True
            elif case == "extra_output":
                ops[idx]["out"] = [param("forged", "u8")]
            else:
                # Replace source immutable loan with a same-owner shared loan,
                # while a mutable loan still exists: the verifier must reject.
                ops[19]["args"][0] = "destination"
            with self.subTest(case=case), self.assertRaises(HIAProgramRejected):
                verify_program(doc)

    def test_native_codegen_consumes_exact_checked_core(self):
        checked = verify_program(copy_program())
        native = emit_program_llvm(checked)
        self.assertEqual(native.profile, PROFILE_V5)
        self.assertEqual(native.core_sha256, checked.sha256)
        self.assertIn("call void @llvm.memcpy.p0.p0.i64(", native.text)
        self.assertNotIn("call void @llvm.memmove.p0.p0.i64(", native.text)
        self.assertGreaterEqual(native.text.count("icmp ule i64"), 4)
        aarch = emit_program_llvm(checked, target=TARGET_AARCH64)
        self.assertEqual(aarch.profile, PROFILE_AARCH64_V5)

    @unittest.skipUnless(shutil.which("clang") and platform.system() == "Linux"
                         and platform.machine() in {"x86_64", "amd64"},
                         "Native Linux x86-64 Clang unavailable")
    def test_true_host_native_vs_core_vm_and_abort(self):
        program = verify_program(copy_program())
        ll = emit_program_llvm(program)
        with tempfile.TemporaryDirectory(prefix="hia-v5-offset-") as folder:
            root = Path(folder)
            path = root / "copy.ll"
            library = root / "copy.so"
            path.write_text(ll.text, encoding="ascii")
            compiled = subprocess.run(
                [shutil.which("clang"), "-O2", "-x", "ir", "-fPIC",
                 "-shared", str(path), "-o", str(library)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            native = ctypes.CDLL(str(library)).copy_offset
            native.argtypes = [ctypes.c_uint64] * 5
            native.restype = ctypes.c_uint8
            for dst, src, count in ((0, 0, 5), (1, 2, 2),
                                    (2, 1, 2), (5, 5, 0)):
                for probe in range(5):
                    args = (5, dst, src, count, probe)
                    with self.subTest(args=args):
                        self.assertEqual(native(*args),
                                         execute_program(program, "copy_offset", list(args))["result"])
            bad_c = root / "negative.c"
            exe = root / "negative"
            bad_c.write_text(
                "#include <stdint.h>\n"
                "uint8_t copy_offset(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);\n"
                "int main(void){return copy_offset(5,4,0,2,0);}\n", encoding="ascii")
            linked = subprocess.run(
                [shutil.which("clang"), str(bad_c), str(library),
                 "-Wl,-rpath," + str(root), "-o", str(exe)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            wrong = subprocess.run([str(exe)], capture_output=True, timeout=30)
            self.assertEqual(wrong.returncode, -signal.SIGABRT)


if __name__ == "__main__":
    unittest.main()
