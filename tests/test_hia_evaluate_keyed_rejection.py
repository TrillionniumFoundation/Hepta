"""Check the retained ABI and admitted workload at the native Evaluate boundary."""
from pathlib import Path
import struct
import unittest

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_agent_store import wire
from hepta.hia_program_runtime import _Machine, _Owner, _View
from tools.generate_hia_worker_evaluate_input_binding import SOURCE


class TypedWorkloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.program = assemble_program((root / SOURCE).read_bytes())
        cls.entry = next(fn for fn in cls.program.as_dict()['functions'] if fn['name'] == 'f0')

    def evaluate(self, arguments, *, signature=None, name="transform", argument_lists=False):
        metadata = {'signatures': {'transform': signature or {'params': ['u8'], 'returns': ['u8']}}}
        workload = {'cases': [{'function': name, 'arguments': arg if argument_lists else [arg]} for arg in arguments]}
        source = _Owner(-1, bytearray(wire([metadata, workload])))
        output = _Owner(-2, bytearray(1 << 20))
        work = _Owner(-3, bytearray(1 << 20))
        machine = _Machine(self.program, 10000000, 16 << 20, None, 128)
        size, = machine.invoke(self.entry, [_View(source, False), _View(output, True), _View(work, True)])
        self.assertEqual(size, 16)
        return struct.unpack('<8sQ', output.data[:size])

    def test_integer_matches_the_retained_unsigned_byte(self):
        self.assertEqual(self.evaluate((0, 255)), (b'HIAEQB01', 0))

    def test_first_scalar_type_mismatch_is_an_admission_refusal(self):
        self.assertEqual(self.evaluate((0, True)), (b'HIAEQB01', 2))

    def test_unknown_entry_and_call_shape(self):
        self.assertEqual(self.evaluate((0,), name='absent'), (b'HIAEQB01', 11))
        self.assertEqual(self.evaluate(([],), argument_lists=True), (b'HIAEQB01', 20))

    def test_borrowed_snapshot_refusals_follow_the_original_signature(self):
        signature = {'params': ['readbuf'], 'returns': ['u32'],
                     'abi': 'hepta.hia.agent.borrowed-byte-snapshots.v1', 'max_buffer_bytes': 4}
        unbound = dict(signature, abi='unavailable')
        self.assertEqual(self.evaluate(({},), signature=unbound), (b'HIAEQB01', 13))
        cases = [(True, 14), ({'bytes_hex': 'AZ'}, 15),
                 ({'byte_length': 1, 'fill_byte': 256}, 16),
                 ({'extra': 1}, 17), ({'bytes_hex': '0000000000'}, 18)]
        for argument, reason in cases:
            with self.subTest(argument=argument):
                self.assertEqual(self.evaluate((argument,), signature=signature), (b'HIAEQB01', reason))
        self.assertEqual(self.evaluate(({'bytes_hex': 'ffff'},), signature=signature), (b'HIAEQB01', 0))

    def test_aggregate_snapshot_budget(self):
        signature = {'params': ['mutbuf'], 'returns': ['u32'],
                     'abi': 'hepta.hia.agent.borrowed-byte-snapshots.v1', 'max_buffer_bytes': 1048576}
        arguments = [{'byte_length': 1048576, 'fill_byte': 0}] * 33
        self.assertEqual(self.evaluate(arguments, signature=signature), (b'HIAEQB01', 19))
