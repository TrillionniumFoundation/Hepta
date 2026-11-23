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

    def evaluate(self, arguments):
        metadata = {'signatures': {'transform': {'params': ['u8'], 'returns': ['u8']}}}
        workload = {'cases': [{'function': 'transform', 'arguments': [arg]} for arg in arguments]}
        source = _Owner(-1, bytearray(wire([metadata, workload])))
        output = _Owner(-2, bytearray(8192))
        work = _Owner(-3, bytearray(65536))
        machine = _Machine(self.program, 10000000, 16 << 20, None, 128)
        size, = machine.invoke(self.entry, [_View(source, False), _View(output, True), _View(work, True)])
        self.assertEqual(size, 16)
        return struct.unpack('<8sQ', output.data[:size])

    def test_integer_matches_the_retained_unsigned_byte(self):
        self.assertEqual(self.evaluate((0, 255)), (b'HIAEQB01', 0))

    def test_first_scalar_type_mismatch_is_an_admission_refusal(self):
        self.assertEqual(self.evaluate((0, True)), (b'HIAEQB01', 2))
