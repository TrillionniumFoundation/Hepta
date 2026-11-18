"""Exercise the actual no-libc HIA call runner under the ordinary Agent budget."""
from hashlib import sha256
from io import BytesIO
import os
from pathlib import Path
import signal
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_agent_buffers import buffer_observation
from hepta.hia_agent_runner import _REPORT_TOO_LARGE, _write_child_report, run_native_batch, run_reference_batch
from hepta.hia_agent_service import _signatures
from hepta.hia_agent_store import wire
from hepta.hia_elf_shared_linker_native import SELECTOR
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_native import build_program_machine
from tests.test_hia_agent_buffer_lifecycle import byte_program, trap_program
from tests.test_hia_program_native import minimal_document, scalar_document
from tools.generate_hia_direct_load_plan import PACKER_PATH, ROOT, SOURCE_PATH, cli_document, document
from tools.qualify_hia_program import qualification_program



INCREMENT_ASSEMBLY = '''hia-asm.v1 hepta.hia.program.v8 increment_fixture
fn increment(buffer:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(buffer:mutbuf)
  index:usize = const() {"value":0}
  original:u8 = buffer.load(buffer,index)
  one:u8 = const() {"value":1}
  new:u8 = int.add.wrap(original,one)
  _ = buffer.store(buffer,index,new)
  result:u32 = int.cast(new) {"mode":"wrap"}
  ret(result)
end
'''


class DirectCallSourceTests(unittest.TestCase):
    def test_exact_hia_plan_and_packer(self):
        for path, source in ((SOURCE_PATH, document), (PACKER_PATH, cli_document)):
            self.assertEqual((ROOT / path).read_text(), render_assembly(source()))

    def test_report_keeps_the_exact_canonical_wire_and_aggregate_limit(self):
        report = {'observations': [{'number': 2, 'text': 'λ'}, {'text': 'longer' * 3000}],
                  'schema': 'controlled', 'complete': True}
        expected = wire(report) + b'\n'
        out = BytesIO()
        with patch('hepta.hia_agent_runner._REPORT_LIMIT', len(expected)):
            self.assertEqual(_write_child_report(report, out), 0)
        self.assertEqual(out.getvalue(), expected)
        out = BytesIO()
        with patch('hepta.hia_agent_runner._REPORT_LIMIT', len(expected) - 1):
            self.assertEqual(_write_child_report(report, out), _REPORT_TOO_LARGE)
        self.assertTrue(expected.startswith(out.getvalue()))


@unittest.skipUnless(os.environ.get('HIA_TEST_DIRECT_CALL'), 'cold-built direct runner is required')
class DirectCallRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory(prefix='hia-direct-call-test-')
        cls.addClassCleanup(cls._temporary.cleanup)
        base = Path(cls._temporary.name)
        cls.raw = Path(os.environ['HIA_TEST_DIRECT_CALL']).read_bytes()
        cls.sha = sha256(cls.raw).hexdigest()
        scalar = qualification_program()
        scalar['functions'].append(next(fn for fn in scalar_document()['functions'] if fn['name'] == 'nine_arguments'))
        cls.documents = {'simple': (minimal_document(), ()), 'scalar': (scalar, ()),
                         'bytes': (byte_program(), (('copy_bytes', 4096), ('mixed', 4096))),
                         'trap': (trap_program(), (('write_then_trap', 4096),)),
                         'increment': (assemble_program(INCREMENT_ASSEMBLY), (('increment', 4096),))}
        cls.inputs = {}
        for label, (doc, exports) in cls.documents.items():
            program = verify_program(doc)
            path = base / (label + '.so')
            with patch.dict(os.environ, {SELECTOR: os.environ['HIA_TEST_DIRECT_LINKER']}):
                build_program_machine(program, path, foreign_buffer_exports=exports)
            cls.inputs[label] = (path.read_bytes(), _signatures(program, exports))

    def run_case(self, label, name, arguments, *, expected=None, raw=None,
                 protocol=1, warmup=0, repetitions=1):
        image, signatures = self.inputs[label]
        case = {'function': name, 'arguments': arguments}
        if expected is not None:
            case['expected'] = expected
        with (patch('hepta.hia_native_helpers.pinned_direct_call_executable',
                    return_value=(self.raw, self.sha)),
              patch('hepta.hia_native_helpers.pinned_direct_call_protocol', return_value=protocol),
              patch('ctypes.CDLL', side_effect=AssertionError('end-to-end direct route entered host loader'))):
            result = run_native_batch(image if raw is None else raw, signatures, [case],
                                      timeout_ms=3000, memory_bytes=64 << 20, capture_buffers=True,
                                      warmup=warmup, repetitions=repetitions)
        self.assertEqual(result['direct_call_executable_sha256'], self.sha)
        self.assertTrue(result['termination_confirmed'])
        return result

    def test_returns_match_independent_core_and_preserve_stack_arguments(self):
        cases = [('simple', 'answer', [0]), ('simple', 'answer', [(1 << 64) - 1]),
                 ('scalar', 'bool_gate', [True, False]), ('scalar', 'scalar_mix', [-37, 29, False]),
                 ('scalar', 'no_result', []), ('scalar', 'lifecycle', [8193, 153]),
                 ('scalar', 'fill_sum', [8193, 41]),
                 ('scalar', 'nine_arguments', [-1, 65535, -900, 42, 231, -7, 95, 4000, True])]
        for label, name, arguments in cases:
            with self.subTest(name=name, arguments=arguments):
                expected = execute_program(self.documents[label][0], name, arguments)['values']
                result = self.run_case(label, name, arguments,
                                       expected={'status': 'returned', 'values': expected})
                self.assertEqual(result['status'], 'returned', result)
                observed = result['report']['observations'][0]
                self.assertEqual(observed['values'], expected)
                self.assertFalse(observed['mismatch'])
                self.assertGreater(int(observed['elapsed_ns']), 0)

    def test_bytes_and_real_abort_retain_exact_writes(self):
        data = [{'bytes_hex': '0061ff'}, {'bytes_hex': 'aaaaaa0700'}]
        expected_bytes = [buffer_observation(0, 'readbuf', bytes.fromhex('0061ff')),
                          buffer_observation(1, 'mutbuf', bytes.fromhex('0061ff0700'))]
        result = self.run_case('bytes', 'copy_bytes', data,
                               expected={'status': 'returned', 'values': [0], 'buffers': expected_bytes})
        self.assertEqual(result['status'], 'returned')
        self.assertFalse(result['report']['observations'][0]['mismatch'])
        self.assertEqual([row['data'].hex() for row in result['captured_buffers']], ['0061ff', '0061ff0700'])
        result = self.run_case('trap', 'write_then_trap', [{'bytes_hex': '010203'}])
        self.assertEqual(result['returncode'], -signal.SIGABRT)
        self.assertEqual(result['status'], 'trapped')
        self.assertEqual(result['captured_buffers'][0]['data'].hex(), '5b0203')

    def test_native_repetitions_reset_snapshot_and_account_for_only_measured_calls(self):
        expected = {'status': 'returned', 'values': [2],
                    'buffers': [buffer_observation(0, 'mutbuf', b'\x02')]}
        result = self.run_case('increment', 'increment', [{'bytes_hex': '01'}], expected=expected,
                               protocol=2, warmup=4, repetitions=10)
        self.assertEqual(result['status'], 'returned', result)
        self.assertEqual(result['report']['measured_calls'], 10)
        self.assertFalse(result['report']['observations'][0]['mismatch'])
        self.assertEqual(result['captured_buffers'][0]['data'], b'\x02')
        result = self.run_case('simple', 'answer', [3], protocol=2, warmup=100, repetitions=10000)
        self.assertEqual(result['status'], 'returned', result)
        self.assertEqual(result['report']['measured_calls'], 10000)
        self.assertEqual(result['report']['observations'][0]['values'], [10])

    @unittest.skipUnless(os.environ.get('HIA_TEST_REPORT_WIRE'), 'cold-built HIA report wire is required')
    def test_selected_report_wire_fits_actual_minimum_agent_budget(self):
        cases = [{'function': 'answer', 'arguments': [i]} for i in range(512)]
        with patch.dict(os.environ, {'HEPTA_HIA_JSON_WIRE_MANIFEST': os.environ['HIA_TEST_REPORT_WIRE']}):
            result = run_reference_batch(verify_program(minimal_document()), cases,
                                         timeout_ms=15000, memory_bytes=64 << 20)
        self.assertEqual(result['status'], 'returned', result)
        self.assertTrue(result['report']['complete'])
        self.assertEqual([row['values'] for row in result['report']['observations']],
                         [[i + 7] for i in range(512)])

    def test_out_of_profile_metadata_refuses_without_mutating_owned_bytes(self):
        image = self.inputs['trap'][0]
        offsets = (16, 24, 48, 64, 120, 176, 232, 288, 344)
        for offset in offsets:
            with self.subTest(offset=offset):
                changed = bytearray(image)
                struct.pack_into('<Q', changed, offset, 0xffffffffffffffff)
                result = self.run_case('trap', 'write_then_trap', [{'bytes_hex': '010203'}], raw=bytes(changed))
                self.assertEqual(result['status'], 'faulted')
                self.assertEqual(result['returncode'], 2)
                self.assertEqual(result['captured_buffers'][0]['data'].hex(), '010203')


if __name__ == '__main__':
    unittest.main()
