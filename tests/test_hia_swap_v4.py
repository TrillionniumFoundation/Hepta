"""Version-isolated safe byte swap: typed Core, interpreter and direct LLVM."""
from __future__ import annotations

import ctypes
import copy
import platform
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.hia_program import (
    SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, HIAProgramRejected, verify_program
)
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_program_llvm import (
    PROFILE_V4, PROFILE_AARCH64_V4, TARGET_AARCH64,
    _can_elide_zero_initialization, emit_program_llvm
)


def param(name, typ):
    return {"name": name, "type": typ}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": [param(*item) for item in out], "attrs": attrs}


def swap_program(schema=SCHEMA_V4):
    params = [param(name, "usize") for name in ("length", "left", "right", "probe")]
    ops = [ins("buffer.new", ["length"], [("owned", "buffer")]),
           ins("borrow.mut", ["owned"], [("writer", "mutbuf")])]
    for i, value in enumerate((11, 22, 33, 44, 55)):
        ops.extend((ins("const", out=[("idx" + str(i), "usize")], value=i),
                    ins("const", out=[("byte" + str(i), "u8")], value=value),
                    ins("buffer.store", ["writer", "idx" + str(i), "byte" + str(i)])))
    ops.extend((ins("buffer.swap", ["writer", "left", "right"]),
                ins("buffer.load", ["writer", "probe"], [("answer", "u8")]),
                ins("loan.end", ["writer"]), ins("owner.drop", ["owned"])))
    return {
        "schema": schema, "module": "safe_byte_exchange",
        "functions": [{"name": "swap_bytes", "params": params, "returns": ["u8"],
                       "effects": ["alloc", "read", "write", "trap"], "entry": "entry",
                       "blocks": [{"id": "entry", "params": params, "ops": ops,
                                  "term": {"op": "ret", "values": ["answer"]}}]}]
    }


class HIASwapV4Tests(unittest.TestCase):
    def test_v4_actual_owner_and_loan_execution(self):
        core = verify_program(swap_program())
        values = [11, 22, 33, 44, 55]
        for left, right in ((0, 4), (4, 0), (2, 2), (1, 3)):
            expected = values.copy()
            expected[left], expected[right] = expected[right], expected[left]
            for probe, answer in enumerate(expected):
                with self.subTest(left=left, right=right, probe=probe):
                    result = execute_program(core, "swap_bytes", [5, left, right, probe])
                    self.assertEqual(result["result"], answer)
                    self.assertEqual(result["resources"]["live_owners"], 0)
                    self.assertEqual(result["resources"]["live_local_loans"], 0)
                    self.assertEqual(result["resources"]["allocations"],
                                     result["resources"]["frees"])

    def test_v1_v2_v3_keep_closed_opcode_sets(self):
        for schema in (SCHEMA, SCHEMA_V2, SCHEMA_V3):
            with self.subTest(schema=schema):
                with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_OPCODE"):
                    verify_program(swap_program(schema))

    def test_both_bounds_checked_before_any_write(self):
        core = verify_program(swap_program())
        for left, right in ((5, 0), (0, 5), (2**64-1, 0), (0, 2**64-1)):
            with self.subTest(left=left, right=right):
                with self.assertRaises(HIAProgramTrap) as error:
                    execute_program(core, "swap_bytes", [5, left, right, 0])
                self.assertEqual(error.exception.code, "bounds")

    def test_mutability_types_effects_and_fields_rejected(self):
        cases = ("borrow.read", "offset_type", "missing_effect",
                 "extra_proof", "spurious_output")
        for case in cases:
            doc = swap_program()
            fn = doc["functions"][0]
            ops = fn["blocks"][0]["ops"]
            idx = next(i for i, op in enumerate(ops) if op["op"] == "buffer.swap")
            if case == "borrow.read":
                ops[1]["op"] = "borrow.read"
                ops[1]["out"] = [param("writer", "readbuf")]
            elif case == "offset_type":
                ops[idx]["args"][1] = "byte0"
            elif case == "missing_effect":
                fn["effects"].remove("read")
            elif case == "extra_proof":
                ops[idx]["attrs"]["trusted_bounds"] = True
            else:
                ops[idx]["out"] = [param("forged", "u8")]
            with self.subTest(case=case), self.assertRaises(HIAProgramRejected):
                verify_program(doc)

    def test_direct_llvm_profile_and_prewrite_guards(self):
        core = verify_program(swap_program())
        ir = emit_program_llvm(core)
        self.assertEqual(ir.profile, PROFILE_V4)
        self.assertEqual(ir.core_sha256, core.sha256)
        self.assertFalse(_can_elide_zero_initialization(swap_program()["functions"][0]))
        self.assertGreaterEqual(ir.text.count("icmp ult i64"), 2)
        self.assertIn("load i8, ptr ", ir.text)
        self.assertIn("store i8 ", ir.text)
        self.assertNotIn("call void @llvm.memmove.p0.p0.i64", ir.text)
        arm = emit_program_llvm(core, target=TARGET_AARCH64)
        self.assertEqual(arm.profile, PROFILE_AARCH64_V4)

    @unittest.skipUnless(shutil.which("clang") and platform.system() == "Linux"
                         and platform.machine() in {"x86_64", "amd64"},
                         "native Linux x86-64 LLVM execution unavailable")
    def test_native_output_matches_actual_core_vm(self):
        core = verify_program(swap_program())
        ir = emit_program_llvm(core)
        with tempfile.TemporaryDirectory(prefix="hia-v4-swap-") as root:
            directory = Path(root)
            ll, so = directory / "swap.ll", directory / "swap.so"
            ll.write_text(ir.text, encoding="ascii")
            built = subprocess.run([shutil.which("clang"), "-x", "ir", "-O2",
                                    "-fPIC", "-shared", str(ll), "-o", str(so)],
                                   capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            native = ctypes.CDLL(str(so)).swap_bytes
            native.argtypes = [ctypes.c_uint64] * 4
            native.restype = ctypes.c_uint8
            for a, b in ((0, 4), (4, 0), (2, 2), (1, 3)):
                for index in range(5):
                    args = [5, a, b, index]
                    with self.subTest(args=args):
                        self.assertEqual(native(*args),
                                         execute_program(core, "swap_bytes", args)["result"])
            cfile, exe = directory / "bad.c", directory / "bad"
            cfile.write_text(
                "#include <stdint.h>\n"
                "uint8_t swap_bytes(uint64_t,uint64_t,uint64_t,uint64_t);\n"
                "int main(void){return swap_bytes(5,0,5,0);}\n", encoding="ascii")
            linked = subprocess.run(
                [shutil.which("clang"), str(cfile), str(so),
                 "-Wl,-rpath," + str(directory), "-o", str(exe)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            child = subprocess.run([str(exe)], capture_output=True, timeout=30)
            self.assertEqual(child.returncode, -signal.SIGABRT)


if __name__ == "__main__":
    unittest.main()
