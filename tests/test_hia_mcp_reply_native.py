"""Independent interpreters check MCP reply framing and refusal boundaries."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from hepta.hia_agent_assembly import assemble_program
from tests.test_hia_elf_linker import reference
from tools.generate_hia_mcp_reply import ERROR, PREFIX, RESULT, SOURCE, render
from tools.generate_hia_mcp_request import INVALID_ENVELOPE, OUTPUT_BYTES
from tools.qualify_hia_selfhost import build_seed, compile_stage, invoke

ROOT = Path(__file__).resolve().parents[1]


class ReplyCases:
    def test_wire_preserved_for_string_and_signed_numeric_ids(self):
        for ident in (rb'""', rb'"\u00221\/\u0394"', b'9223372036854775807', b'-9223372036854775808'):
            payload = rb'{ "x":1e-99, "integer": 9007199254740993, "s":"\ud83d\ude00" }'
            wire = rb' {"result":' + payload + rb',"i\u0064" : ' + ident + b'}'
            expected = PREFIX + ident + RESULT + payload + b'}\n'
            answer, data = self.run_reply(wire)
            self.assertEqual((answer, data[:answer]), (len(expected), expected))

    def test_correlated_error_and_null_parse_id(self):
        payload = rb'{"message":"parse failed\n", "code": -32700, "data":{"x":[]}}'
        for ident in (b'18', b'null', rb'"surrogate-pair-\ud83d\ude00"'):
            expected = PREFIX + ident + ERROR + payload + b'}\n'
            answer, data = self.run_reply(b'{"id":' + ident + b',"error":' + payload + b'}')
            self.assertEqual((answer, data[:answer]), (len(expected), expected))

    def test_no_reply_for_ambiguous_invalid_or_multiline_owner_frame(self):
        for wire in (
            b'{"id":null,"result":{}}', b'{"id":1.0,"result":{}}', b'{"id":1,"result":[]}',
            b'{"id":1,"result":{},"error":{"code":-1,"message":"x"}}',
            b'{"id":1,"error":{"code":-1,"message":null}}',
            b'{"id":1,"error":{"code":1e23,"message":"x"}}',
            b'{"id":1,"error":{"code":-1}}',
            b'{"id":1,"result":{\n"n":1}}',
        ):
            with self.subTest(wire=wire):
                self.assertEqual(self.run_reply(wire)[0], INVALID_ENVELOPE)


class McpReplySourceTests(ReplyCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / SOURCE).read_text()
        if render() != source:
            raise AssertionError('generated MCP reply source drifted')
        cls.checked = assemble_program(source)

    def run_reply(self, wire):
        return reference(self.checked, wire, capacity=OUTPUT_BYTES, workspace=1 << 14)


class McpReplyNativeTests(ReplyCases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(prefix='hia-mcp-reply-')
        cls.addClassCleanup(temp.cleanup)
        cls.folder = Path(temp.name)
        seed, _ = build_seed(cls.folder)
        compiler, _ = compile_stage(cls.folder, 'B1', seed,
                                     (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes(),
                                     image_format='seed-shared')
        cls.image, _ = compile_stage(cls.folder, 'reply', compiler, (ROOT / SOURCE).read_bytes())
        cls.sequence = 0

    def run_reply(self, wire):
        self.__class__.sequence += 1
        result, output = invoke(self.folder, f'wire-{self.sequence}', self.image, wire,
                                capacity=OUTPUT_BYTES, workspace_size=1 << 14)
        self.assertEqual(result['status'], 'returned', result)
        self.assertEqual(result['abi_status'], 0, result)
        return result['core_u32'], output
