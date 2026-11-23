"""Experimental typed HIA Core INVLPG: independent source-to-native checks.

Never execute the generated privileged instruction from an ordinary Linux host
process. The GNU assembler is an independent *byte* oracle only.
"""
from __future__ import annotations

from copy import deepcopy
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_native import emit_program_machine
from hepta.hia_machine_x64 import KernelCode as Code, MachineEncodingError
from hepta.hia_program_runtime import execute_program
from hepta.hia_opcodes import opcode_catalog
from hepta.hia_schema import KERNEL_TLB_SCHEMA


def sample():
    return {
        "schema": KERNEL_TLB_SCHEMA, "module": "kernel_tlb_experimental",
        "exports": ["f0"],
        "functions": [{
            "name": "f0", "params": [{"name": "address", "type": "u64"}],
            "returns": ["u64"], "effects": ["privilege"], "entry": "b0",
            "blocks": [{"id": "b0", "params": [{"name": "address", "type": "u64"}],
                        "ops": [{"op": "x86.tlb.invlpg", "args": ["address"],
                                 "out": [], "attrs": {}}],
                        "term": {"op": "ret", "values": ["address"]}}]
        }]
    }


class KernelTlbCoreTests(unittest.TestCase):
    def test_typed_privilege_admission_and_legacy_refusal(self):
        doc = sample()
        self.assertEqual(verify_program(doc).as_dict()["schema"], KERNEL_TLB_SCHEMA)
        names = [row["name"] for row in opcode_catalog(KERNEL_TLB_SCHEMA)["instructions"]]
        self.assertIn("x86.tlb.invlpg", names)
        self.assertNotIn("x86.tlb.invlpg", [row["name"] for row in opcode_catalog()["instructions"]])
        for change in ("legacy", "fence_schema", "missing_effect", "bad_type", "extra_result",
                       "extra_operand", "extra_attr", "unknown_op", "legacy_privilege_only"):
            altered = deepcopy(doc)
            fn = altered["functions"][0]
            op = fn["blocks"][0]["ops"][0]
            if change == "legacy":
                altered["schema"] = "hepta.hia.program.v8"
            elif change == "fence_schema":
                altered["schema"] = "hepta.hia.program.kernel-fence.v1"
            elif change == "missing_effect":
                fn["effects"] = []
            elif change == "bad_type":
                fn["params"][0]["type"] = "u32"
                fn["blocks"][0]["params"][0]["type"] = "u32"
            elif change == "extra_result":
                op["out"] = [{"name": "madeup", "type": "u64"}]
            elif change == "extra_operand":
                op["args"].append("address")
            elif change == "extra_attr":
                op["attrs"] = {"trust_me": True}
            elif change == "unknown_op":
                op["op"] = "x86.tlb.flush_all"
            elif change == "legacy_privilege_only":
                altered["schema"] = "hepta.hia.program.v8"
                fn["blocks"][0]["ops"] = []
            with self.subTest(change=change), self.assertRaises(HIAProgramRejected):
                verify_program(altered)

    def test_interpreter_never_reports_privileged_success(self):
        with self.assertRaisesRegex(HIAProgramRejected, "CPL0"):
            execute_program(sample(), "f0", [0x4000])

    def test_direct_native_object_binding_and_malicious_nop(self):
        admitted = verify_program(sample())
        first = emit_program_machine(admitted)
        second = emit_program_machine(verify_program(admitted.canonical_bytes))
        self.assertEqual(first.object_bytes, second.object_bytes)
        self.assertEqual(first.text_bytes, second.text_bytes)
        self.assertIn(bytes.fromhex("0f0138"), first.text_bytes)
        with patch.object(Code, "invlpg", lambda self, base, disp=0: self.emit(b"\x90")):
            attack = emit_program_machine(admitted)
        self.assertNotEqual(attack.object_bytes, first.object_bytes)
        self.assertNotIn(bytes.fromhex("0f0138"), attack.text_bytes)

    @unittest.skipUnless(platform.machine().lower() in {"x86_64", "amd64"}
                         and platform.system() == "Linux",
                         "GNU as independent oracle needs x86-64 Linux")
    def test_independent_gnu_as_80_addressing_modes(self):
        self.assertIsNotNone(shutil.which("as"))
        self.assertIsNotNone(shutil.which("objcopy"))
        regs = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
        rows = [(reg, disp) for reg in regs for disp in (0, 127, 128, -129, 0x12345678)]
        with tempfile.TemporaryDirectory(prefix="hia-invlpg-") as root:
            p = Path(root)
            (p / "oracle.s").write_text(".text\n" + "".join(
                f" invlpg {disp}(%{reg})\n" for reg, disp in rows))
            subprocess.run(["as", "--64", "-o", str(p / "oracle.o"), str(p / "oracle.s")],
                           check=True, capture_output=True)
            subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                            str(p / "oracle.o"), str(p / "oracle.bin")],
                           check=True, capture_output=True)
            code = Code()
            for reg, disp in rows:
                code.invlpg(reg, disp)
            self.assertEqual(code.finalize()[0], (p / "oracle.bin").read_bytes())
            self.assertEqual(code.finalize(), code.finalize())
        for bad in ("eax", "r16", None, [], 17):
            code = Code()
            with self.subTest(base=bad), self.assertRaises(MachineEncodingError):
                code.invlpg(bad)
            self.assertEqual(code.finalize()[0], b"")
        for bad in (True, 1.0, -(1 << 31) - 1, 1 << 31):
            code = Code()
            with self.subTest(disp=bad), self.assertRaises(MachineEncodingError):
                code.invlpg("rax", bad)
            self.assertEqual(code.finalize()[0], b"")


if __name__ == "__main__":
    unittest.main()
