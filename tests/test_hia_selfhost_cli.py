"""Independent references and structural refusals for the native filter entry."""
from __future__ import annotations

import struct
import unittest

from hepta.hia_agent_assembly import assemble_program
from tools.qualify_hia_selfhost_cli import (CAPACITY, independent_reference,
    inspect_executable, limit_source, output_capacity_source, padded_source)


class SelfhostExecutableSourceTests(unittest.TestCase):
    def test_vm_echo_observations_close_resources_before_seed(self):
        report = independent_reference()
        self.assertTrue(report["before_B0"])
        self.assertFalse(report["whole_stack_rewrite_complete"])
        self.assertFalse(report["all_input_correctness_proved"])
        self.assertEqual([row["result"]["values"] for row in report["echo"]],
            [[1, 0], [1, 73], [1, 255]])

    def test_exact_source_capacity_is_same_ordinary_core_not_blank_line_failure(self):
        source = limit_source(); padded = padded_source(source)
        self.assertEqual(len(padded), CAPACITY)
        self.assertEqual(assemble_program(padded).sha256, assemble_program(source).sha256)
        self.assertLessEqual(max(map(len, padded.splitlines())), 16384)
        self.assertEqual(len(padded.splitlines()), len(source.splitlines()))

    def test_output_capacity_control_is_real_acyclic_core_inside_old_caps(self):
        source = output_capacity_source()
        program = assemble_program(source).as_dict()
        self.assertLess(len(source), CAPACITY)
        self.assertEqual(len(program["functions"]), 121)
        self.assertLessEqual(sum(len(block["ops"]) for fn in program["functions"]
            for block in fn["blocks"]), 8192)

    def test_elf_inspection_rejects_loader_writable_code_stack_and_size_mutations(self):
        raw = (b"\x7fELF\x02\x01\x01" + bytes(9)
            + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
            + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 178, 178, 4096)
            + struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16) + b"\x0f\x0b")
        self.assertIsNone(inspect_executable(raw)["interpreter"])
        for offset in (0, 4, 5, 6, 7, 16, 18, 20, 24, 32, 40, 48, 52, 54,
                56, 58, 60, 62, 64, 68, 72, 80, 88, 96, 104, 112, 120, 124,
                128, 136, 144, 152, 160, 168):
            changed = bytearray(raw); changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                inspect_executable(changed)
        header_only = bytearray(raw[:176])
        struct.pack_into("<QQ", header_only, 96, 176, 176)
        for changed in (raw[:175], raw[:-1], raw + b"\0", header_only):
            with self.assertRaises(ValueError):
                inspect_executable(changed)


if __name__ == "__main__":
    unittest.main()
