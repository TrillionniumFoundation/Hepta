"""Compare physical Store and per-arm observations with the HIA budget VM's requests."""
from pathlib import Path
import struct
import subprocess
import unittest

from tests.test_hia_execution_budget_native import CONTEXT, OWNER, VM, witnesses
from tools.generate_hia_evaluate_budget_observation import PACKER, PACK_MAGIC, SOURCE
from tools.qualify_hia_selfhost import compile_stage


ROOT = Path(__file__).resolve().parents[1]


class BudgetObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_execution_budget_session import BudgetSessionTests

        BudgetSessionTests.setUpClass()
        cls.addClassCleanup(BudgetSessionTests.doClassCleanups)
        root = BudgetSessionTests.session.parent
        compiler = root / 'B2.image.bin'
        image, _ = compile_stage(root, 'observation', compiler, (ROOT / SOURCE).read_bytes())
        packer, _ = compile_stage(root, 'observation-packer', compiler, (ROOT / PACKER).read_bytes())
        raw = image.read_bytes()
        cls.exe, _ = compile_stage(root, 'budget-observation', packer,
            struct.pack('<2Q', PACK_MAGIC, len(raw)) + raw, output_extension='.elf')
        cls.exe.chmod(0o500)
        cls.events = witnesses(VM())

    def project(self, index, mode, authority, *, ordinal=0, generation=7, now=2_000_000,
                deadline=12_000_000, owner=OWNER, sequence=None):
        req, _ = self.events[index]
        seq = struct.unpack_from('<Q', req, 16)[0] if sequence is None else sequence
        receipt = self.events[index - 1][1][1] if index else b''
        header = struct.pack('<8s13Q', b'HIAEBO01', mode, ordinal, generation, seq,
            now, deadline, 5, 11, 17, 31, 37, len(receipt), len(authority))
        reply = subprocess.run([self.exe], input=header+CONTEXT+owner+receipt+authority,
                               capture_output=True, env={'PATH': ''}, timeout=5)
        self.assertEqual(reply.stderr, b'')
        return reply.returncode, reply.stdout

    def test_start_store_ack_run_grants_charges_and_finish(self):
        def ack(ordinal, kind, generation, changes=0, row=0):
            return struct.pack('<8s9Q', b'HIATXR01', 1, ordinal, kind, 0, changes, generation, 0, row, 0)

        def gate(op, arm, seq, clock, limit, wall, cumulative):
            return struct.pack('<8s7Q', b'HIAEPGT1', op, arm, seq, clock, limit, wall, cumulative)

        cases = [
            (0, 0, b'', {'now':1_000_000}),
            (1, 1, ack(0,0,7), {}),
            (3, 1, ack(2,27,8,1,2), {'ordinal':2}),
            (6, 2, gate(5,0,6,2_000_000,12_000_000,0,0), {}),
            (7, 2, gate(6,0,7,3_000_000,12_000_000,1234567,1234567), {'now':3_000_000}),
            (8, 2, gate(5,1,8,3_000_000,4_000_000,0,1234567), {'now':3_000_000,'deadline':4_000_000}),
            (9, 2, gate(6,1,9,9_000_000,12_000_000,7654321,8888888), {'now':9_000_001}),
            (10, 3, b'', {}),
            (11, 1, ack(5,21,8), {'ordinal':5,'generation':8}),
        ]
        for index, mode, data, options in cases:
            with self.subTest(event=index):
                self.assertEqual(self.project(index, mode, data, **options), (0, self.events[index][0]))
                if index:
                    self.assertEqual(self.project(index, mode, data, owner=b'b'*64, **options), (2,b''))
                    self.assertEqual(self.project(index, mode, data, sequence=51, **options), (2,b''))

    def test_missing_budget_row_requires_complete_authentic_summary_and_ack(self):
        q = struct.pack('<8s7Q', b'HIAQRF01', 4, 10, 0, 0, 416, 1, 0)
        summary = bytes(384) + struct.pack('<4Q', 14, 7, 0, 0)
        ack = struct.pack('<8s9Q', b'HIATXR01', 1, 1, 27, 0, 0, 7, 0, 0, 0)
        data = q + summary + ack
        from tests.test_hia_execution_budget_native import row_packet
        self.assertEqual(self.project(2, 1, data, ordinal=1), (0, row_packet(2,None,None)))
        for index in (0,16,32,40,56,448,456,464,472,480,496,504,512,528):
            changed = bytearray(data)
            changed[index] ^= 1
            with self.subTest(offset=index):
                self.assertEqual(self.project(2, 1, changed, ordinal=1), (2,b''))
        self.assertEqual(self.project(2, 1, data[:-8], ordinal=1), (2,b''))
