"""Compare HIA's URI boundary with the public MCP artifact namespace."""
from __future__ import annotations

from pathlib import Path
import re
import struct
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from tests.test_hia_elf_linker import reference
from tools.generate_hia_mcp_request import INVALID_ENVELOPE
from tools.generate_hia_mcp_uri import DESCRIPTOR_BYTES, MAGIC, PREFIX, SOURCE, render
from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = re.compile(rb'hia://artifacts/[A-Za-z0-9][A-Za-z0-9._~-]{0,191}')


class UriCases:
    def check(self, wire):
        status, output = self.run_wire(wire)
        if ALLOWED.fullmatch(wire):
            self.assertEqual(status, DESCRIPTOR_BYTES)
            self.assertEqual(struct.unpack('<8s2Q', output), (MAGIC, len(wire), len(wire) - len(PREFIX)))
        else:
            self.assertEqual(status, INVALID_ENVELOPE)
            self.assertEqual(output, b'\xa5' * DESCRIPTOR_BYTES)

    def test_all_bytes_in_both_positions(self):
        for value in range(256):
            letter = bytes([value])
            self.check(PREFIX + letter)
            self.check(PREFIX + b'A' + letter)

    def test_lengths_non_ascii_and_unowned_uris(self):
        for size in (0, 1, 191, 192, 193):
            self.check(PREFIX + b'a' * size)
        for wire in (b'', b'hia://', b'hia://artifacts-other/A', b'HIA://artifacts/A',
                     b'octofs://jobs/A', b'hia://artifacts/A%2E', b'hia://artifacts/A/../B',
                     'hia://artifacts/Aé'.encode()):
            self.check(wire)


class McpUriSourceTests(UriCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / SOURCE).read_text()
        if render() != source:
            raise AssertionError('generated resource URI source drifted')
        cls.checked = assemble_program(source)

    def run_wire(self, wire):
        return reference(self.checked, wire, capacity=DESCRIPTOR_BYTES, workspace=0)


class McpUriNativeTests(UriCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix='hia-mcp-uri-')
        cls.addClassCleanup(temp.cleanup)
        cls.folder = Path(temp.name)
        seed, _ = build_seed(cls.folder)
        compiler, _ = compile_stage(cls.folder, 'B1', seed,
                                     (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes(),
                                     image_format='seed-shared')
        cls.image, _ = compile_stage(cls.folder, 'uri', compiler, (ROOT / SOURCE).read_bytes())
        cls.sequence = 0

    def run_wire(self, wire):
        self.__class__.sequence += 1
        result, output = invoke(self.folder, f'wire-{self.sequence}', self.image, wire,
                                capacity=DESCRIPTOR_BYTES, workspace_size=0,
                                output_initial=b'\xa5' * DESCRIPTOR_BYTES, observe_trap_writes=True)
        self.assertEqual(result['status'], 'returned', result)
        self.assertEqual(result['abi_status'], 0, result)
        return result['core_u32'], output
