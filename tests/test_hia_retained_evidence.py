"""Frozen archive identities survive explicit path migration, never rehashing."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.verify_hia_retained_evidence import verify, ROOT, INDEX, MIGRATIONS


class RetainedEvidenceTests(unittest.TestCase):
    def fixture(self, root):
        rows = []
        for name, data in [('BASE.json', b'program'), ('base.json', b'receipt')]:
            rows.append({'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        (root / 'BASE_PROGRAM.json').write_bytes(b'program')
        (root / 'base.json').write_bytes(b'receipt')
        manifest = {'schema': 'hepta.archive-path-migrations.v1',
                    'historical_snapshots_edited': False, 'new_native_execution_claimed': False,
                    'migrations': [{'original_path': 'BASE.json', 'current_path': 'BASE_PROGRAM.json',
                                    'bytes': rows[0]['bytes'], 'sha256': rows[0]['sha256'],
                                    'unchanged_receipt': rows[1].copy()}]}
        return {'files': rows}, manifest

    def test_real_frozen_archive(self):
        result = verify(ROOT, json.loads((ROOT / INDEX).read_text()),
                        json.loads((ROOT / MIGRATIONS).read_text()))
        self.assertTrue(result['passed'], result)
        self.assertEqual(result['files_checked'], 611)
        self.assertEqual(result['bytes_checked'], 26120286)
        self.assertEqual(len(result['applied_migrations']), 2)

    def test_migration_is_explicit_even_if_old_name_resolves_to_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            index, manifest = self.fixture(root)
            # Simulate the old name aliasing the lowercase receipt on Windows.
            (root / 'BASE.json').write_bytes(b'receipt')
            self.assertTrue(verify(root, index, manifest)['passed'])
            self.assertFalse(verify(root, index, {**manifest, 'migrations': []})['passed'])

    def test_corruption_missing_and_receipt_changes_fail(self):
        for name in ('BASE_PROGRAM.json', 'base.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                index, manifest = self.fixture(root)
                (root / name).write_bytes(b'changed')
                self.assertFalse(verify(root, index, manifest)['passed'])
                (root / name).unlink()
                self.assertFalse(verify(root, index, manifest)['passed'])

    def test_invalid_mappings_fail(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            index, manifest = self.fixture(root)
            for field, value in [('sha256', '0' * 64), ('bytes', 0),
                                 ('original_path', 'unknown'), ('current_path', '../escape'),
                                 ('current_path', '/absolute'), ('current_path', 'base.json')]:
                changed = copy.deepcopy(manifest)
                changed['migrations'][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    verify(root, index, changed)
            manifest['migrations'] *= 2
            with self.assertRaises(ValueError):
                verify(root, index, manifest)

    def test_symlink_target_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            index, manifest = self.fixture(root)
            (root / 'BASE_PROGRAM.json').unlink()
            try:
                (root / 'BASE_PROGRAM.json').symlink_to(root / 'base.json')
            except (OSError, NotImplementedError):
                self.skipTest('symlinks unavailable')
            with self.assertRaises(ValueError):
                verify(root, index, manifest)
