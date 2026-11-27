"""Real GNU decoding rejects operand-byte and duplicate-instruction false witnesses."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from tools.qualify_hia_kernel_selfhost_invlpg import instruction_occurrences

# Exact .text captured from the original e273 irq-disable failure. 0xfa at
# offset 10 is CMP's ModRM; the actual CLI is the full instruction at 57.
ORIGINAL = bytes.fromhex(
    "f7c2ff01000074094881fa0160050073020f0b4881ea01600500554889e54881eca0020000"
    "488b0424488955f0488975f8488b4700488945e0fa488b45e0488b55f848894200c9c35548"
    "89e54881ec500000004889f8488945b0488d7db0488d75c0ba000100c0e894ffffff488b45c0c9c3")


@unittest.skipUnless(sys.platform == "linux" and shutil.which("objdump"),
                     "original GNU x86 decoder requires Linux")
class KernelInstructionOracleTests(unittest.TestCase):
    def observe(self, raw, oracle=b"\xfa"):
        with tempfile.TemporaryDirectory(prefix="hia-kernel-instruction-oracle-") as d:
            return instruction_occurrences(Path(d), "case", raw, oracle)

    def test_exact_failed_image_contains_one_real_cli_and_one_operand_byte(self):
        self.assertEqual(ORIGINAL.count(b"\xfa"), 2)
        self.assertEqual(self.observe(ORIGINAL), [57])

    def test_nop_does_not_pass_using_the_remaining_cmp_operand(self):
        changed = ORIGINAL[:57] + b"\x90" + ORIGINAL[58:]
        self.assertEqual(changed.count(b"\xfa"), 1)
        self.assertEqual(self.observe(changed), [])

    def test_duplicate_real_cli_and_immediate_only_bytes_remain_distinct(self):
        self.assertEqual(self.observe(ORIGINAL + b"\xfa"), [57, len(ORIGINAL)])
        self.assertEqual(self.observe(b"\xb8\xfa\x00\x00\x00\xc3"), [])

    def test_incomplete_opcode_and_nonbytes_cannot_be_an_oracle(self):
        with self.assertRaises(AssertionError):
            self.observe(b"\x0f")
        with self.assertRaises(ValueError):
            self.observe(bytearray(ORIGINAL))
        with self.assertRaises(ValueError):
            self.observe(ORIGINAL, b"")


if __name__ == "__main__":
    unittest.main()
