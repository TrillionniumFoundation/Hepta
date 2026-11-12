"""New recovery harness controls, run on real temporary Git repositories."""
from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import run_proof_development as driver

HERE = Path(__file__).resolve().parent


class HarnessControls(unittest.TestCase):
    def test_actual_git_source_bytes_mode_and_extra_files_are_checked(self):
        with tempfile.TemporaryDirectory(prefix='proof-recovery-git-') as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', root], check=True)
            source = root / 'a.py'; source.write_bytes(b'value = 7\n'); source.chmod(0o644)
            subprocess.run(['git', '-C', root, 'add', '--', 'a.py'], check=True)
            tree = subprocess.run(['git', '-C', root, 'write-tree'], capture_output=True, check=True).stdout.decode().strip()
            rows = subprocess.run(['git', '-C', root, 'ls-tree', '-r', '-z', tree], capture_output=True, check=True).stdout
            driver.admit_git_snapshot(root, driver.files(root), rows)
            source.write_bytes(b'value = 8\n')
            with self.assertRaises(ValueError): driver.admit_git_snapshot(root, driver.files(root), rows)
            source.write_bytes(b'value = 7\n'); source.chmod(0o755)
            with self.assertRaises(ValueError): driver.admit_git_snapshot(root, driver.files(root), rows)
            source.chmod(0o644); (root / 'extra').write_bytes(b'x')
            with self.assertRaises(ValueError): driver.admit_git_snapshot(root, driver.files(root), rows)
            (root / 'extra').unlink()
            with self.assertRaises(ValueError): driver.admit_git_snapshot(root, driver.files(root), rows + rows)

    def test_real_source_symlink_is_not_admitted(self):
        with tempfile.TemporaryDirectory(prefix='proof-recovery-link-') as directory:
            root = Path(directory); (root / 'target').write_bytes(b'original')
            (root / 'alias').symlink_to('target')
            with self.assertRaises(ValueError): driver.files(root)

    def test_exact_acknowledged_r6_capsule_is_still_complete(self):
        value = driver.read_overlay(HERE / 'verification-r6-overlay.json')
        self.assertEqual(len(value['files']), 41)
        self.assertEqual(len(value['source_manifest']), 3186)
        self.assertEqual(value['deleted'], [])

    def test_new_packet_and_expected_inputs_are_distinct_from_lost_candidate(self):
        value = driver.read_proof_overlay(HERE / 'proof-recovery-overlay.json')
        self.assertEqual(len(value['files']), 21)
        self.assertIs(value['lost64_qualification_inherited'], False)
        self.assertFalse(value['lost3202_recovered'])
        original = driver.read_overlay(HERE / 'verification-r6-overlay.json')['source_manifest']
        driver.admit_overlay_base(value, original)
        changed = deepcopy(original)
        changed['hepta/hia_agent_service.py']['sha256'] = '0' * 64
        with self.assertRaises(ValueError): driver.admit_overlay_base(value, changed)

    def test_actual_packet_byte_change_is_rejected(self):
        raw = (HERE / 'proof-recovery-overlay.json').read_bytes()
        with tempfile.TemporaryDirectory(prefix='proof-recovery-packet-') as directory:
            path = Path(directory) / 'packet.json'
            path.write_bytes(raw + b'\n')
            with self.assertRaises(ValueError): driver.read_proof_overlay(path)
            path.write_bytes(raw[:-1] + b' ')
            with self.assertRaises(ValueError): driver.read_proof_overlay(path)

    def test_export_verifies_real_bytes_and_modes_without_git_claim(self):
        with tempfile.TemporaryDirectory(prefix='proof-recovery-export-') as directory:
            root = Path(directory) / 'source'; root.mkdir()
            output = Path(directory) / 'out'; output.mkdir()
            (root / 'a').write_bytes(b'a\n'); (root / 'a').chmod(0o644)
            (root / 'b').write_bytes(b'b\n'); (root / 'b').chmod(0o755)
            observed = driver.files(root)
            result = driver.export_source(root, output, observed)
            self.assertGreater(result['bytes'], 0)
            wrong = deepcopy(observed); wrong['a']['sha256'] = '0' * 64
            other = Path(directory) / 'bad'; other.mkdir()
            with self.assertRaises(ValueError): driver.export_source(root, other, wrong)


if __name__ == '__main__':
    unittest.main(verbosity=2)
