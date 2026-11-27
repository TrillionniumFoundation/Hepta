"""Independent GNU-as byte oracle for the UNPROMOTED locked x86-64 CAS.

This does not admit an HIA Core privilege/atomic effect or assert SMP safety.
The emitted bytes execute only in the separately isolated QEMU test harness.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code, MachineEncodingError, PrivilegedCode

REGS = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
DISP = (0, 1, -1, 127, -128, 128, -129, 4096, -4096,
        (1 << 31) - 1, -(1 << 31))


class AtomicStagingOracle(unittest.TestCase):
    def test_not_available_on_regular_hia_code_or_core(self):
        self.assertFalse(hasattr(Code(), "lock_cmpxchg64"))
        self.assertTrue(hasattr(PrivilegedCode(), "lock_cmpxchg64"))
        from hepta.hia_opcodes import EFFECTS, OPCODES
        self.assertEqual(EFFECTS, {"alloc", "read", "write", "trap"})
        self.assertNotIn("x86.lock_cmpxchg64", OPCODES)

    def test_invalid_operands_rejected_without_byte_emission(self):
        for bad in ("eax", "rip", "xmm0", "cr3", None, True, 7, []):
            for which in ("base", "replacement"):
                with self.subTest(which=which, bad=repr(bad)):
                    code = PrivilegedCode()
                    args = (bad, "rdx") if which == "base" else ("r10", bad)
                    with self.assertRaises(MachineEncodingError):
                        code.lock_cmpxchg64(*args, 4096)
                    self.assertEqual(code.finalize(), (b"", []))
        for bad in ("0", None, True, 1.5, 1 << 31, -(1 << 31) - 1):
            code = PrivilegedCode()
            with self.subTest(displacement=repr(bad)), self.assertRaises(MachineEncodingError):
                code.lock_cmpxchg64("r10", "rdx", bad)
            self.assertEqual(code.finalize(), (b"", []))
        for base, src in (("rax", "rdx"), ("r10", "rax"), ("r10", "r10")):
            code = PrivilegedCode()
            with self.subTest(base=base, replacement=src), self.assertRaises(MachineEncodingError):
                code.lock_cmpxchg64(base, src)
            self.assertEqual(code.finalize(), (b"", []))

    @unittest.skipUnless(all(shutil.which(x) for x in ("as", "objcopy", "objdump")),
                         "GNU binutils independent ISA reference required")
    def test_all_address_classes_rex_bits_and_boundary_displacements(self):
        code = PrivilegedCode()
        asm = [".text", ".global atomic_oracle", "atomic_oracle:"]
        cases = 0
        for base in REGS:
            if base == "rax":
                continue
            for replacement in ("rcx", "rdx", "rsp", "r13", "r15"):
                if replacement == base:
                    continue
                for disp in DISP:
                    code.lock_cmpxchg64(base, replacement, disp)
                    asm.append(f"  lock cmpxchgq %{replacement}, {disp}(%{base})")
                    cases += 1
        actual, relocations = code.finalize()
        self.assertEqual(relocations, [])
        self.assertGreater(cases, 700)
        with tempfile.TemporaryDirectory(prefix="hia-atomic-as-") as tmp:
            root = Path(tmp)
            (root / "oracle.s").write_text("\n".join(asm) + "\n")
            subprocess.run(["as", "--64", "-o", str(root / "oracle.o"),
                            str(root / "oracle.s")], check=True, capture_output=True)
            subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                            str(root / "oracle.o"), str(root / "oracle.bin")],
                           check=True, capture_output=True)
            self.assertEqual(actual, (root / "oracle.bin").read_bytes())
            result = subprocess.run(["objdump", "-d", str(root / "oracle.o")],
                                    check=True, capture_output=True, text=True).stdout
            self.assertEqual(result.count("lock cmpxchg"), cases)


if __name__ == "__main__":
    unittest.main()
