"""Verify the keyed schema handoff, response fragments, and null cost scope in HIA."""
import ast
from pathlib import Path
import struct
import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.generate_hia_worker_evaluate_closeout_flow import SOURCE, program


class KeyedSchemaCloseoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        checked = assemble_program((root / SOURCE).read_bytes())
        functions = {fn['name']: fn for fn in checked.as_dict()['functions']}
        cls.functions = {node.name: functions[f'f{i}'] for i, node in enumerate(ast.parse(program()).body)}
        cls.checked = checked

    def header(self):
        frame = bytearray(740)
        struct.pack_into('<8s6Q', frame, 64, b'HIAESR01', 1, 2, 256, 512, 64, 8)
        frame[156:164] = b'HIAJRN02'
        frame[220:284] = b'a' * 64
        frame[284:348] = b'b' * 64
        frame[348:414] = b'r-' + b'a' * 64
        struct.pack_into('<8s7Q', frame, 668, b'HIAJMO01', 2, 11, 0, 0, 0, 0, 512)
        frame[732:740] = b'HIASTCP1'
        return frame

    def run_header(self, frame, diagnostic_size=154):
        vm = _Machine(self.checked, 1000000, 16 << 20, None, 128)
        work = _View(_Owner(-3, bytearray(16384)), True)
        result = _Owner(-2, bytearray(2048))
        vm.invoke(self.functions['keep'], [work, 0, 0, 676 + diagnostic_size])
        count, = vm.invoke(self.functions['refusal_header'], [
            _View(_Owner(-1, frame), False), _View(result, True), work])
        return count, result.data

    def test_error_document_uses_only_admitted_descriptor_fragments(self):
        count, output = self.run_header(self.header())
        self.assertGreater(count, 512)
        self.assertLessEqual(count, 2048)
        self.assertEqual(struct.unpack_from('<Q', output, 40)[0], 2)
        self.assertEqual(struct.unpack_from('<3Q', output, 64), (0, 676, 154))
        _, offset, size = struct.unpack_from('<3Q', output, 88)
        self.assertGreaterEqual(offset, 384)
        self.assertLessEqual(offset + size, 512)
        self.assertIn(b'"request_id":"r-' + b'a' * 64 + b'"', output[offset:offset+size])

    def test_rejects_a_nonempty_context_forged_route_or_mismatched_reason(self):
        for position in (64, 88, 121, 156, 350, 668, 684, 732):
            with self.subTest(position=position):
                frame = self.header()
                frame[position] ^= 1
                self.assertEqual(self.run_header(frame)[0], 0xfffffffd)
        for size in (2, 65537):
            with self.subTest(size=size):
                self.assertEqual(self.run_header(self.header(), size)[0], 0xfffffffd)
