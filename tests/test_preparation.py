"""Preparation refusals; no native or original business test is executed."""
from pathlib import Path
from hashlib import sha256
import ast
import base64
import copy
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'inputs'))
import run_development as driver
from workflow_process import run_workflow_step


class PreparationTests(unittest.TestCase):
    def packet(self):
        raw = (ROOT / 'inputs/SOURCE-SERVICE.zlib.json').read_bytes()
        return raw, driver.decode_packet(raw)

    def encoded(self, packet):
        raw = json.dumps(packet, sort_keys=True).encode()
        return json.dumps({'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                           'payload': base64.b64encode(zlib.compress(raw)).decode()}).encode()

    def test_exact_overlay_and_all_declared_member_bytes(self):
        raw, packet = self.packet()
        self.assertEqual(sha256(raw).hexdigest(), driver.PACKET_SHA)
        self.assertEqual(len(packet['files']), 28)
        self.assertEqual(len(packet['source_manifest']), 3323)
        self.assertEqual(sum(row['before'] is None for row in packet['files'].values()), 17)

    def test_outer_tamper_is_rejected_before_decode(self):
        raw, _ = self.packet()
        with self.assertRaises(AssertionError):
            driver.decode_packet(raw + b' ')

    def test_member_tamper_with_reencoded_container_is_rejected(self):
        _, packet = self.packet()
        name = 'hepta/hia_agent_contract_native.py'
        packet['files'][name]['text'] += '\n'
        raw = self.encoded(packet)
        with patch.object(driver, 'PACKET_SHA', sha256(raw).hexdigest()), self.assertRaises(AssertionError):
            driver.decode_packet(raw)

    def test_unsafe_path_is_rejected_even_with_matching_member_identity(self):
        _, packet = self.packet()
        old = 'hepta/hia_agent_contract_native.py'
        unsafe = '../outside.py'
        packet['files'][unsafe] = packet['files'].pop(old)
        packet['source_manifest'][unsafe] = packet['source_manifest'].pop(old)
        raw = self.encoded(packet)
        with patch.object(driver, 'PACKET_SHA', sha256(raw).hexdigest()), self.assertRaises(AssertionError):
            driver.decode_packet(raw)

    def test_declared_final_identity_mismatch_is_rejected(self):
        _, packet = self.packet()
        packet['source_manifest']['hepta/hia_agent_contract_native.py']['sha256'] = '0' * 64
        raw = self.encoded(packet)
        with patch.object(driver, 'PACKET_SHA', sha256(raw).hexdigest()), self.assertRaises(AssertionError):
            driver.decode_packet(raw)

    def test_snapshot_observes_extra_files_and_refuses_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'a.py').write_bytes(b'first\n')
            first = driver.snapshot(root)
            (root / 'extra').write_bytes(b'new\n')
            self.assertNotEqual(driver.snapshot(root), first)
            (root / 'link').symlink_to(root / 'a.py')
            with self.assertRaisesRegex(ValueError, 'unexpected source symlink'):
                driver.snapshot(root)

    def test_original_workflow_supervisor_records_nonzero_and_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, code, seconds, timed_out in (
                    ('failure', 'raise SystemExit(7)', 2, False),
                    ('timeout', 'import time; time.sleep(5)', 0.05, True)):
                result = run_workflow_step([sys.executable, '-B', '-c', code], cwd=root,
                    env=dict(os.environ), stdout_path=root / (label + '.out'),
                    stderr_path=root / (label + '.err'), receipt_path=root / (label + '.json'), seconds=seconds)
                self.assertEqual(result['status'], 'WORKFLOW_STEP_HOLD')
                self.assertEqual(result['timed_out'], timed_out)
                self.assertTrue(result['cleanup']['complete'])
                self.assertEqual(result['cleanup']['errors'], [])
                self.assertFalse(result['selfhost_qualification_gate_modified'])

    def test_all_harness_inputs_and_python_syntax_are_bound(self):
        record = json.loads((ROOT / 'inputs/INPUTS.json').read_bytes())
        actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()
                  and '.git' not in p.parts and '__pycache__' not in p.parts
                  and p != ROOT / 'inputs/INPUTS.json'}
        self.assertEqual(actual, set(record['files']))
        for name, expected in record['files'].items():
            raw = (ROOT / name).read_bytes()
            self.assertEqual(len(raw), expected['bytes'], name)
            self.assertEqual(sha256(raw).hexdigest(), expected['sha256'], name)
            if name.endswith('.py'):
                ast.parse(raw, filename=name)
        workflow = (ROOT / '.github/workflows/hia-agent-contract-service-development.yml').read_text()
        self.assertIn('runs-on: ubuntu-latest', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertNotIn('contents: write', workflow)
        self.assertIn(driver.BASE, workflow)


if __name__ == '__main__':
    unittest.main()
