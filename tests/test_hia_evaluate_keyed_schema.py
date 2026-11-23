"""Verify the keyed schema handoff, response fragments, and null cost scope in HIA."""
import ast
import json
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

    def test_expectation_error_preserves_the_authenticated_case_index(self):
        for index in (0, 9, 10, 99, 100, 255, 511, 512):
            with self.subTest(index=index):
                frame = self.header()
                frame[64:72] = b'HIAERJ01'
                struct.pack_into('<Q', frame, 88, 512 + index)
                frame[120:156] = b'ctx-' + b'c' * 32
                count, output = self.run_header(frame, diagnostic_size=0)
                if index == 512:
                    self.assertEqual(count, 0xfffffffd)
                    continue
                self.assertGreater(count, 512)
                body = json.loads(output[512:count])
                self.assertEqual(body['request_id'], 'r-' + 'a' * 64)
                self.assertEqual(body['error']['code'], 'E_HIA_WORKLOAD_EXPECTATION')
                self.assertEqual(body['error']['message'],
                                 f'declared case expectation differs from baseline Core at index {index}')

    def test_build_profile_and_abi_have_distinct_execution_errors(self):
        for reason, code, message in (
                (24, 'E_HIA_EXECUTION_PROFILE', 'evaluation requires retained direct shared images'),
                (25, 'E_HIA_ABI', 'baseline and candidate frozen public ABI differ')):
            with self.subTest(reason=reason):
                frame = self.header()
                frame[64:72] = b'HIAERJ01'
                frame[120:156] = b'ctx-' + b'c' * 32
                struct.pack_into('<Q', frame, 88, reason)
                count, output = self.run_header(frame, diagnostic_size=0)
                self.assertGreater(count, 512)
                self.assertEqual(json.loads(output[512:count])['error'],
                                 {'code': code, 'details_artifact': None, 'message': message,
                                  'phase': 'execution', 'retry_action': 'correct_input'})

class BuildRefusalDigestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.generate_hia_worker_evaluate_launcher import bindings, inventory
        from tools.generate_hia_worker_launcher_flow import program as launcher_program
        from tools.generate_hia_worker_flow_packer import FULL_LAUNCHER_POLICY
        root = Path(__file__).resolve().parents[1]
        cls.checked = assemble_program((root / FULL_LAUNCHER_POLICY).read_bytes())
        nodes = ast.parse(launcher_program(evaluate_full=True)).body
        index = next(i for i,node in enumerate(nodes) if node.name == 'verified_build_digest')
        cls.verify = next(fn for fn in cls.checked.as_dict()['functions'] if fn['name'] == f'f{index}')
        cls.fields = bindings(inventory())

    def confirmed(self, digest, data):
        work = bytearray(16384)
        at = self.fields['BUILD_DIGEST']
        work[at:at+64] = digest
        struct.pack_into('<Q',work,self.fields['ADMITTED_LENGTH'],1234)
        vm = _Machine(self.checked, 1000000, 1 << 20, None, 128)
        result, = vm.invoke(self.verify, [_View(_Owner(-1,bytearray(64)+data),False),
                                          _View(_Owner(-2,work),True),len(data)])
        return result

    def test_rejection_requires_hash_and_size_of_the_same_admitted_request(self):
        digest = b'c' * 64
        line = b'{"sha256":"' + digest + b'","bytes":1234}\n'
        self.assertTrue(self.confirmed(digest,line))
        for altered in (line.replace(b'c',b'd',1), line.replace(b'1234',b'1235'),
                        line.replace(b'1234',b'01234'), line.replace(b'bytes',b'octet'),
                        line[:-1], line+b' '):
            with self.subTest(altered=altered):
                self.assertFalse(self.confirmed(digest,altered))
