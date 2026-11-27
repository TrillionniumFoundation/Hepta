"""Controlled byte-custody checks; fixtures are never executed as bridges."""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import retain_six_bridge_inputs as retain


class SixBridgeRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hia-retain-six-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.prepared = self.root / 'prepared'
        self.prepared.mkdir()
        self.output = self.root / 'prerequisite-inputs'
        self.receipts = {}
        self.binaries = {}
        self.pins = {label: format(index, '040x')
                     for index, (label, _, _) in enumerate(retain.ROLES, 1)}
        self.preparation = {
            'status': 'READY',
            'source_head': '1' * 40,
            'source_tree': '2' * 40,
            'upstream_pins': self.pins,
        }
        (self.prepared / 'CI-PREPARATION.json').write_text(
            json.dumps(self.preparation, indent=2) + '\n')
        for index, (label, relative, schema) in enumerate(retain.ROLES, 1):
            # Deliberately different from Cargo target conventions. The helper
            # must obey each actual receipt path, including recursive-family
            # durable copies, rather than guessing one build layout.
            binary = (self.prepared / 'prerequisites' / 'nonstandard' /
                      ('private-' + label) / ('actual-' + str(index) + '.bin'))
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'controlled-nonexecuted-bytes-' +
                               label.encode() + b'\x00\x80\xff' * index)
            binary.chmod(0o700)
            receipt = {
                'schema': schema,
                'binary': str(binary),
                'binary_sha256': sha256(binary.read_bytes()).hexdigest(),
                'upstream': {'commit': self.pins[label]},
                'identity': {'source_commit': self.pins[label]},
            }
            path = self.prepared / 'prerequisites/evidence' / relative
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(receipt, indent=2) + '\n')
            self.receipts[label] = path
            self.binaries[label] = binary

    def snapshot(self):
        return {
            path.relative_to(self.prepared).as_posix():
                (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
            for path in self.prepared.rglob('*') if path.is_file()
        }

    def row(self, report, label):
        return next(row for row in report['roles'] if row['role'] == label)

    def rewrite_receipt(self, label, change):
        path = self.receipts[label]
        value = json.loads(path.read_bytes())
        change(value)
        path.write_text(json.dumps(value, indent=2) + '\n')

    def test_all_six_receipt_named_bytes_and_original_receipts_are_saved_without_execution(self):
        before = self.snapshot()
        report = retain.retain(self.prepared, self.output)
        self.assertEqual(report['status'], 'SIX_BRIDGE_RECEIPT_BYTES_RETAINED')
        self.assertEqual(report['retained_roles'], [row[0] for row in retain.ROLES])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(report['bridges_executed'])
        self.assertFalse(report['qualification_executed'])
        self.assertFalse(report['prerequisite_admission_changed'])
        self.assertFalse(report['source_files_modified_by_helper'])
        self.assertFalse(report['original_receipts_modified_by_helper'])
        self.assertFalse(report['whole_native_delivery_qualified'])
        for label, relative, _ in retain.ROLES:
            row = self.row(report, label)
            source = self.binaries[label]
            saved = self.output / label / 'bridge.bin'
            self.assertEqual(row['binary']['original_path'], str(source))
            self.assertEqual(row['binary']['resolved_path'], str(source.resolve()))
            self.assertEqual(saved.read_bytes(), source.read_bytes())
            self.assertEqual(row['binary']['sha256'],
                             sha256(source.read_bytes()).hexdigest())
            self.assertEqual(row['binary']['bytes'], source.stat().st_size)
            self.assertEqual(row['binary']['source_stat']['mode'], 0o700)
            self.assertEqual(stat.S_IMODE(saved.stat().st_mode), 0o500)
            self.assertEqual((self.output / label / Path(relative).name).read_bytes(),
                             self.receipts[label].read_bytes())
            self.assertIs(row['receipt_matches_preparation_pin'], True)
            self.assertFalse((self.output / label / 'bridge.bin.partial').exists())
        self.assertEqual(len(list(self.output.glob('progress-*.json'))), 6)
        self.assertEqual(json.loads((self.output / 'RETENTION.json').read_bytes()), report)

    def test_wrong_actual_binary_hash_preserves_partial_and_never_attests_it(self):
        self.rewrite_receipt('finite', lambda value: value.update(binary_sha256='0' * 64))
        before = self.snapshot()
        report = retain.retain(self.prepared, self.output)
        self.assertEqual(report['status'], 'INCOMPLETE_BRIDGE_RETENTION')
        self.assertEqual(len(report['retained_roles']), 5)
        self.assertNotIn('finite', report['retained_roles'])
        self.assertEqual(self.row(report, 'finite')['status'], 'NOT_RETAINED')
        self.assertTrue((self.output / 'finite/bridge.bin.partial').exists())
        self.assertFalse((self.output / 'finite/bridge.bin').exists())
        self.assertEqual(self.snapshot(), before)

    def test_missing_receipt_keeps_other_five_without_inventing_binary(self):
        self.receipts['recursive'].unlink()
        before = self.snapshot()
        report = retain.retain(self.prepared, self.output)
        self.assertEqual(report['status'], 'INCOMPLETE_BRIDGE_RETENTION')
        self.assertEqual(len(report['retained_roles']), 5)
        row = self.row(report, 'recursive')
        self.assertEqual(row['error']['type'], 'FileNotFoundError')
        self.assertNotIn('binary', row)
        self.assertFalse((self.output / 'recursive/bridge.bin').exists())
        self.assertEqual(self.snapshot(), before)

    def test_receipt_mutation_after_copy_is_preserved_as_unattested(self):
        original = self.receipts['raw'].read_bytes()
        copy = retain.copy_binary
        def changed(source, destination, expected):
            result = copy(source, destination, expected)
            if source == self.binaries['raw']:
                self.receipts['raw'].write_bytes(original + b' ')
            return result
        with patch.object(retain, 'copy_binary', side_effect=changed):
            report = retain.retain(self.prepared, self.output)
        self.assertEqual(report['status'], 'INCOMPLETE_BRIDGE_RETENTION')
        self.assertEqual(len(report['retained_roles']), 5)
        self.assertNotIn('raw', report['retained_roles'])
        self.assertIn('changed after actual binary copy', self.row(report, 'raw')['error']['message'])
        self.assertEqual((self.output / 'raw/build-receipt.json').read_bytes(), original)
        self.assertEqual((self.output / 'raw/bridge.bin').read_bytes(),
                         self.binaries['raw'].read_bytes())
        self.assertNotEqual(self.receipts['raw'].read_bytes(), original)

    def test_duplicate_identity_field_is_rejected_before_copy(self):
        path = self.receipts['dynamic']
        raw = path.read_bytes()
        malformed = raw.rstrip()[:-1] + b', "binary_sha256": "' + b'0' * 64 + b'"}\n'
        path.write_bytes(malformed)
        before = self.snapshot()
        report = retain.retain(self.prepared, self.output)
        self.assertEqual(report['status'], 'INCOMPLETE_BRIDGE_RETENTION')
        self.assertEqual(len(report['retained_roles']), 5)
        self.assertIn('duplicate receipt field',
                      self.row(report, 'dynamic')['error']['message'])
        self.assertEqual((self.output / 'dynamic/build-receipt.json').read_bytes(), malformed)
        self.assertFalse((self.output / 'dynamic/bridge.bin').exists())
        self.assertFalse((self.output / 'dynamic/bridge.bin.partial').exists())
        self.assertEqual(self.snapshot(), before)

    def test_outside_preparation_binary_is_not_copied(self):
        outside = self.root / 'foreign-control.bin'
        outside.write_bytes(b'foreign-controlled-input')
        outside.chmod(0o700)
        self.rewrite_receipt('ranking', lambda value: value.update(
            binary=str(outside), binary_sha256=sha256(outside.read_bytes()).hexdigest()))
        before = self.snapshot()
        report = retain.retain(self.prepared, self.output)
        self.assertEqual(report['status'], 'INCOMPLETE_BRIDGE_RETENTION')
        self.assertEqual(len(report['retained_roles']), 5)
        self.assertIn('outside this preparation',
                      self.row(report, 'ranking')['error']['message'])
        self.assertFalse((self.output / 'ranking/bridge.bin').exists())
        self.assertFalse((self.output / 'ranking/bridge.bin.partial').exists())
        self.assertEqual(outside.read_bytes(), b'foreign-controlled-input')
        self.assertEqual(self.snapshot(), before)

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir()
        marker = self.output / 'original'
        marker.write_bytes(b'original-output')
        before = self.snapshot()
        with self.assertRaises(FileExistsError):
            retain.retain(self.prepared, self.output)
        self.assertEqual(marker.read_bytes(), b'original-output')
        self.assertEqual(list(self.output.iterdir()), [marker])
        self.assertEqual(self.snapshot(), before)

    def test_changed_preparation_record_cannot_claim_complete_retention(self):
        original = (self.prepared / 'CI-PREPARATION.json').read_bytes()
        copy = retain.copy_binary
        def changed(source, destination, expected):
            result = copy(source, destination, expected)
            if source == self.binaries['stream']:
                (self.prepared / 'CI-PREPARATION.json').write_bytes(original + b' ')
            return result
        with patch.object(retain, 'copy_binary', side_effect=changed):
            report = retain.retain(self.prepared, self.output)
        self.assertEqual(len(report['retained_roles']), 6)
        self.assertFalse(report['preparation_observation_unchanged'])
        self.assertEqual(report['status'], 'INCOMPLETE_BRIDGE_RETENTION')
        self.assertEqual((self.output / 'CI-PREPARATION.original.json').read_bytes(), original)



    def test_fifo_receipt_and_binary_do_not_block_remaining_roles_or_terminal_evidence(self):
        import os
        import subprocess
        import sys
        before = self.snapshot()
        for kind in ('receipt', 'binary'):
            with self.subTest(kind=kind):
                path = self.receipts['finite'] if kind == 'receipt' else self.binaries['finite']
                original, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
                path.unlink()
                os.mkfifo(path, 0o600)
                output = self.root / ('fifo-' + kind)
                code = (
                    "import json,sys\n"
                    "sys.path.insert(0,sys.argv[1])\n"
                    "import retain_six_bridge_inputs as h\n"
                    "print(json.dumps(h.retain(sys.argv[2],sys.argv[3])))\n")
                result = subprocess.run(
                    [sys.executable, '-B', '-c', code, str(Path(retain.__file__).parent),
                     str(self.prepared), str(output)],
                    capture_output=True, timeout=2, check=False,
                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                report = json.loads(result.stdout)
                self.assertEqual(report['status'], 'INCOMPLETE_BRIDGE_RETENTION')
                self.assertEqual(len(report['retained_roles']), 5)
                self.assertNotIn('finite', report['retained_roles'])
                self.assertIn('stream', report['retained_roles'])
                row = self.row(report, 'finite')
                self.assertEqual(row['error']['type'], 'ValueError')
                self.assertIn('not a regular file', row['error']['message'])
                self.assertTrue(path.is_fifo())
                self.assertEqual(json.loads((output / 'RETENTION.json').read_bytes()), report)
                path.unlink()
                path.write_bytes(original)
                path.chmod(mode)
        self.assertEqual(self.snapshot(), before)

if __name__ == '__main__':
    unittest.main()
