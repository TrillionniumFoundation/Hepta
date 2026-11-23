"""Compare budget-driven native Store commands with the independently bound Store operations."""
from pathlib import Path
import struct
import subprocess
import unittest

from hepta.hia_agent_store_native import _parameters
from tests.test_hia_agent_store_runtime import command
from tests.test_hia_execution_budget_native import CONTEXT, OWNER, VM, decoded, witnesses
from tools.generate_hia_evaluate_budget_store import PACKER, PACK_MAGIC, SOURCE
from tools.qualify_hia_selfhost import compile_stage

ROOT = Path(__file__).resolve().parents[1]


class StoreCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_execution_budget_session import BudgetSessionTests

        BudgetSessionTests.setUpClass()
        cls.addClassCleanup(BudgetSessionTests.doClassCleanups)
        folder = BudgetSessionTests.session.parent
        compiler = folder / 'B2.image.bin'
        image, _ = compile_stage(folder, 'store-command', compiler, (ROOT / SOURCE).read_bytes())
        packer, _ = compile_stage(folder, 'store-packer', compiler, (ROOT / PACKER).read_bytes())
        raw = image.read_bytes()
        cls.exe, _ = compile_stage(folder, 'project', packer, struct.pack('<2Q', PACK_MAGIC, len(raw)) + raw,
                                   output_extension='.elf')
        cls.exe.chmod(0o500)
        cls.records = [reply for _, reply in witnesses(VM())]

    def run_command(self, raw, *, sequence=1, context=CONTEXT, owner=OWNER):
        prefix = struct.pack('<8sQ', b'HIAEBC01', sequence) + context + owner
        result = subprocess.run([self.exe], input=prefix + raw, capture_output=True, env={'PATH': ''}, timeout=5)
        self.assertFalse(result.stderr)
        return result.returncode, result.stdout

    def test_all_original_actions_have_their_exact_store_effect_or_no_command(self):
        for number, record in enumerate(self.records, 1):
            fields, values = decoded(record)
            action = fields[2]
            raw = record[1]
            context, used, owner, updated, _ = [item.decode() for item in values]
            with self.subTest(event=number, action=action):
                if action == 1:
                    expected = command(number, 21)
                elif action == 2:
                    expected = command(number, 27, 17, _parameters((context,), 14, None))
                elif action == 4:
                    expected = command(number, 27, 1, _parameters((owner, context, used), 6, b'HIAUPB01'))
                elif action == 5:
                    expected = command(number, 27, 1, _parameters((updated, context, used, owner), 7, b'HIAUPB01'))
                elif action == 6:
                    expected = command(number, 2)
                else:
                    self.assertEqual(self.run_command(raw, sequence=number), (2, b''))
                    continue
                self.assertEqual(self.run_command(raw, sequence=number), (0, expected))

    def test_identity_phase_sequence_and_decimal_tampering_emit_nothing(self):
        raw = next(row[1] for row in self.records if decoded(row)[0][2] == 5)
        for options in ({'owner': b'b'*64}, {'context': b'ctx-'+b'2'*32}, {'sequence': 0}):
            self.assertEqual(self.run_command(raw, **options), (2, b''))
        for offset, value in ((0,0), (8,7), (16,7), (24,0), (32,86400001), (40,5),
                              (48,0), (56,2), (64,35), (72,4301), (80,63), (104,0), (112,0), (120,1)):
            altered = bytearray(raw)
            struct.pack_into('<Q', altered, offset, value)
            with self.subTest(offset=offset):
                self.assertEqual(self.run_command(altered), (2, b''))
        self.assertEqual(self.run_command(raw[:-1]), (2, b''))
        fields = struct.unpack_from('<16Q', raw)
        updated = 128 + fields[8] + fields[9] + fields[10]
        for replacement in (b'0', b'1', b'x'):
            altered = raw[:updated] + replacement + raw[updated+1:]
            self.assertEqual(self.run_command(altered), (2, b''))
