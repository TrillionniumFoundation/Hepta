"""Experimental HIA Core kernel-fence entry: exact source -> verifier -> native x86.

A single MFENCE instruction is not an SMP/privilege or Linux completeness result.
The native machine byte is checked against GNU as independently. The deliberate
no-op codegen mutation must fail the required instruction-presence oracle.
"""
from __future__ import annotations

from copy import deepcopy
import ctypes
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_native import build_program_machine, emit_program_machine
from hepta.hia_machine_x64 import Code
from hepta.hia_program_runtime import execute_program
from hepta.hia_schema import KERNEL_FENCE_SCHEMA
from hepta.hia_opcodes import opcode_catalog

FENCE = bytes.fromhex("0f ae f0")


def example():
    return {
        "schema": KERNEL_FENCE_SCHEMA,
        "module": "experimental_kernel_fence",
        "exports": ["fenced_value"],
        "functions": [{
            "name": "fenced_value",
            "params": [{"name": "x", "type": "u64"}],
            "returns": ["u64"],
            "effects": ["atomic"],
            "entry": "entry",
            "blocks": [{
                "id": "entry",
                "params": [{"name": "x", "type": "u64"}],
                "ops": [{"op": "x86.fence.mfence", "args": [], "out": [], "attrs": {}}],
                "term": {"op": "ret", "values": ["x"]},
            }],
        }],
    }


class KernelFenceCoreTests(unittest.TestCase):
    def test_explicit_schema_effect_and_closed_arity(self):
        doc = example()
        self.assertEqual(verify_program(doc).as_dict()["schema"], KERNEL_FENCE_SCHEMA)
        catalog = opcode_catalog(KERNEL_FENCE_SCHEMA)
        fence_rows = [row for row in catalog["instructions"] if row["name"] == "x86.fence.mfence"]
        self.assertEqual(len(fence_rows), 1)
        self.assertEqual(fence_rows[0]["effects"], ("atomic",))
        self.assertNotIn("x86.fence.mfence", [row["name"] for row in opcode_catalog()["instructions"]])
        for variant in ("missing_effect", "legacy", "unknown", "operand", "attribute", "output"):
            altered = deepcopy(doc)
            op = altered["functions"][0]["blocks"][0]["ops"][0]
            if variant == "missing_effect":
                altered["functions"][0]["effects"] = []
            elif variant == "legacy":
                altered["schema"] = "hepta.hia.program.v8"
            elif variant == "unknown":
                op["op"] = "x86.invlpg"
            elif variant == "operand":
                op["args"] = ["x"]
            elif variant == "attribute":
                op["attrs"]["impersonate_cpl0"] = True
            elif variant == "output":
                op["out"] = [{"name": "fake", "type": "u64"}]
            with self.subTest(variant=variant), self.assertRaises(HIAProgramRejected):
                verify_program(altered)

    def test_interpreter_fails_closed(self):
        with self.assertRaisesRegex(HIAProgramRejected, "native execution"):
            execute_program(example(), "fenced_value", [123])

    def test_direct_native_exact_byte_identity_and_malicious_noop(self):
        admitted = verify_program(example())
        first = emit_program_machine(admitted)
        second = emit_program_machine(verify_program(admitted.canonical_bytes))
        self.assertEqual(first.object_bytes, second.object_bytes)
        self.assertEqual(first.text_bytes, second.text_bytes)
        self.assertEqual(first.text_bytes.count(FENCE), 1)
        with patch.object(Code, "mfence", lambda self: self.emit(b"\\x90")):
            dishonest = emit_program_machine(admitted)
        # An output-only smoke test cannot detect missing ordering.
        self.assertNotIn(FENCE, dishonest.text_bytes)
        self.assertNotEqual(dishonest.object_bytes, first.object_bytes)

    @unittest.skipUnless(platform.machine().lower() in {"x86_64", "amd64"} and platform.system() == "Linux",
                         "requires isolated x86-64 Linux runner")
    def test_gnu_as_byte_oracle_and_actual_native_execution(self):
        self.assertIsNotNone(shutil.which("as"))
        self.assertIsNotNone(shutil.which("objcopy"))
        with tempfile.TemporaryDirectory(prefix="hia-mfence-") as root:
            p = Path(root)
            (p / "oracle.s").write_text(".text\\n.globl oracle\\noracle:\\n mfence\\n")
            subprocess.run(["as", "--64", "-o", str(p / "oracle.o"), str(p / "oracle.s")],
                           check=True, capture_output=True)
            subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                            str(p / "oracle.o"), str(p / "oracle.bin")],
                           check=True, capture_output=True)
            self.assertEqual((p / "oracle.bin").read_bytes(), FENCE)
            result = build_program_machine(example(), str(p / "native.so"), kind="shared", linker="cc")
            self.assertTrue(result["ok"])
            fn = ctypes.CDLL(str(p / "native.so")).fenced_value
            fn.argtypes = [ctypes.c_uint64]
            fn.restype = ctypes.c_uint64
            for x in (0, 1, 0x123456789abcdef0, (1 << 64) - 1):
                self.assertEqual(fn(x), x)


if __name__ == "__main__":
    unittest.main()
