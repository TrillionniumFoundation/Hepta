"""HIA v3: overlap-safe same-owner byte moves use ONE unique loan.

These are real standalone verifier/interpreter/LLVM tests when run on a complete
Hepta checkout. Native tests require local Linux/x86_64 + Clang and do not
certify LLVM/compiler refinement, C++ ABI, or physical target execution.
"""
from __future__ import annotations

import copy
import ctypes
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import unittest

from hepta.hia_program import SCHEMA, SCHEMA_V2, SCHEMA_V3, HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_program_llvm import emit_program_llvm, _can_elide_zero_initialization


def arg(name, typ):
    return {"name": name, "type": typ}


def ins(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args),
            "out": [arg(name, typ) for name, typ in out], "attrs": attrs}


def overlap_program(schema=SCHEMA_V3):
    params = [arg("dst", "usize"), arg("src", "usize"),
              arg("count", "usize"), arg("probe", "usize")]
    operations = [
        ins("const", out=[("extent", "usize")], value=8),
        ins("buffer.new", ["extent"], [("owner", "buffer")]),
        ins("borrow.mut", ["owner"], [("writer", "mutbuf")]),
    ]
    for index, value in enumerate((11, 22, 33, 44, 55, 66, 77, 88)):
        operations.append(ins("const", out=[("i" + str(index), "usize")], value=index))
        operations.append(ins("const", out=[("v" + str(index), "u8")], value=value))
        operations.append(ins("buffer.store", ["writer", "i" + str(index), "v" + str(index)]))
    operations += [
        ins("buffer.move_within", ["writer", "dst", "src", "count"]),
        ins("buffer.load", ["writer", "probe"], [("answer", "u8")]),
        ins("loan.end", ["writer"]),
        ins("owner.drop", ["owner"]),
    ]
    return {
        "schema": schema, "module": "overlap_semantics",
        "functions": [{
            "name": "move_bytes", "params": params, "returns": ["u8"],
            "effects": ["alloc", "read", "write", "trap"], "entry": "entry",
            "blocks": [{"id": "entry", "params": copy.deepcopy(params),
                        "ops": operations,
                        "term": {"op": "ret", "values": ["answer"]}}]
        }]
    }


def empty_program():
    params = [arg("size", "usize"), arg("offset", "usize")]
    operations = [
        ins("buffer.new", ["size"], [("owner", "buffer")]),
        ins("borrow.mut", ["owner"], [("writer", "mutbuf")]),
        ins("const", out=[("zero", "usize")], value=0),
        ins("buffer.move_within", ["writer", "offset", "offset", "zero"]),
        ins("loan.end", ["writer"]),
        ins("owner.drop", ["owner"]),
        ins("const", out=[("answer", "u8")], value=0),
    ]
    return {"schema": SCHEMA_V3, "module": "empty_move",
            "functions": [{
                "name": "empty_move", "params": params, "returns": ["u8"],
                "effects": ["alloc", "read", "write", "trap"], "entry": "entry",
                "blocks": [{"id": "entry", "params": copy.deepcopy(params),
                            "ops": operations, "term": {"op": "ret", "values": ["answer"]}}]
            }]}


class HIAOverlapV3Tests(unittest.TestCase):
    def test_both_overlap_directions_identity_and_zero_count(self):
        checked = verify_program(overlap_program())
        self.assertEqual(checked.as_dict()["schema"], SCHEMA_V3)
        values = [11, 22, 33, 44, 55, 66, 77, 88]
        cases = ((2, 0, 6), (0, 2, 6), (1, 0, 7),
                 (0, 1, 7), (3, 3, 5), (0, 0, 8),
                 (8, 8, 0), (0, 8, 0), (8, 0, 0))
        for dst, src, count in cases:
            expected = list(values)
            expected[dst:dst + count] = values[src:src + count]
            for index in range(8):
                with self.subTest(dst=dst, src=src, count=count, index=index):
                    output = execute_program(checked, "move_bytes", [dst, src, count, index])
                    self.assertEqual(output["result"], expected[index])
                    self.assertEqual(output["resources"]["live_owners"], 0)
                    self.assertEqual(output["resources"]["live_local_loans"], 0)

    def test_v1_and_v2_reject_new_opcode(self):
        for schema in (SCHEMA, SCHEMA_V2):
            with self.subTest(schema=schema), self.assertRaisesRegex(
                    HIAProgramRejected, "E_HIA_OPCODE"):
                verify_program(overlap_program(schema))

    def test_mutable_view_and_usize_operands_required(self):
        for index, substitute in ((0, "owner"), (1, "v0"), (2, "v1"), (3, "v2")):
            with self.subTest(index=index, substitute=substitute):
                doc = overlap_program()
                move = doc["functions"][0]["blocks"][0]["ops"][-4]
                move["args"][index] = substitute
                with self.assertRaises(HIAProgramRejected):
                    verify_program(doc)

    def test_missing_effect_and_forged_attrs_refuse(self):
        for effect in ("read", "write", "trap"):
            doc = overlap_program()
            doc["functions"][0]["effects"].remove(effect)
            with self.subTest(effect=effect), self.assertRaisesRegex(
                    HIAProgramRejected, "E_HIA_EFFECT"):
                verify_program(doc)
        doc = overlap_program()
        doc["functions"][0]["blocks"][0]["ops"][-4]["attrs"]["certified"] = False
        with self.assertRaisesRegex(HIAProgramRejected, "E_HIA_FORMAT"):
            verify_program(doc)

    def test_checked_offsets_do_not_wrap_and_empty_buffers_do_not_deref_null(self):
        document = overlap_program()
        for dst, src, count in ((8, 0, 1), (0, 8, 1), (7, 4, 2),
                                (0, 7, 2), (2**64-1, 0, 1),
                                (0, 2**64-1, 1), (0, 0, 2**64-1)):
            with self.subTest(dst=dst, src=src, count=count):
                with self.assertRaises(HIAProgramTrap) as failure:
                    execute_program(document, "move_bytes", [dst, src, count, 0])
                self.assertEqual(failure.exception.code, "bounds")
                self.assertEqual(failure.exception.report["status"], "trapped")
        for size, offset in ((0, 0), (1, 1)):
            result = execute_program(empty_program(), "empty_move", [size, offset])
            self.assertEqual(result["result"], 0)
            self.assertEqual(result["resources"]["live_owners"], 0)
        with self.assertRaises(HIAProgramTrap):
            execute_program(empty_program(), "empty_move", [0, 1])

    def test_llvm_uses_actual_memmove_and_versioned_native_profile(self):
        program = verify_program(overlap_program())
        native = emit_program_llvm(program)
        self.assertTrue(native.profile.endswith(".v3"))
        self.assertEqual(native.core_sha256, program.sha256)
        self.assertIn("call void @llvm.memmove.p0.p0.i64(", native.text)
        self.assertIn("declare void @llvm.memmove.p0.p0.i64(", native.text)
        self.assertIn("icmp ule i64 ", native.text)
        self.assertFalse(_can_elide_zero_initialization(overlap_program()["functions"][0]))
        from hepta.hia_program_llvm import TARGET_AARCH64
        other = emit_program_llvm(program, target=TARGET_AARCH64)
        self.assertTrue(other.profile.endswith(".v3"))
        old = verify_program({"schema": SCHEMA, "module": "old",
            "functions": [{"name": "id", "params": [arg("n", "u8")],
                "returns": ["u8"], "effects": [], "entry": "entry",
                "blocks": [{"id": "entry", "params": [arg("n", "u8")],
                    "ops": [], "term": {"op": "ret", "values": ["n"]}}]}]})
        self.assertNotIn("@llvm.memmove", emit_program_llvm(old).text)

    def test_real_emitted_native_memmove_matches_interpreter(self):
        compiler = shutil.which("clang")
        if compiler is None or platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
            self.skipTest("actual Linux x86-64 Clang required")
        program = verify_program(overlap_program())
        ir = emit_program_llvm(program)
        with tempfile.TemporaryDirectory(prefix="hia-overlap-v3-") as root:
            root = Path(root)
            assembly, library = root / "overlap.ll", root / "overlap.so"
            assembly.write_text(ir.text, encoding="ascii")
            built = subprocess.run(
                [compiler, "-x", "ir", "-O2", "-shared", "-fPIC",
                 str(assembly), "-o", str(library)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr)
            native = ctypes.CDLL(str(library)).move_bytes
            native.argtypes = [ctypes.c_uint64] * 4
            native.restype = ctypes.c_uint8
            for dst, src, count in ((2, 0, 6), (0, 2, 6), (1, 0, 7),
                                    (0, 1, 7), (3, 3, 5),
                                    (8, 8, 0), (0, 8, 0)):
                for probe in range(8):
                    args = (dst, src, count, probe)
                    with self.subTest(args=args):
                        self.assertEqual(native(*args),
                                         execute_program(program, "move_bytes", list(args))["result"])

            # The true output must abort on an out-of-extent move, rather than
            # return a plausible result after an unchecked native memmove.
            harness = root / "bounds.c"
            exe = root / "bounds"
            harness.write_text("#include <stdint.h>\n"
                "uint8_t move_bytes(uint64_t,uint64_t,uint64_t,uint64_t);\n"
                "int main(void){return move_bytes(1,7,2,0);}\n")
            linked = subprocess.run(
                [compiler, str(harness), str(library), "-Wl,-rpath," + str(root), "-o", str(exe)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(linked.returncode, 0, linked.stderr)
            child = subprocess.run([str(exe)], capture_output=True, timeout=30)
            self.assertEqual(child.returncode, -signal.SIGABRT)


if __name__ == "__main__":
    unittest.main()
