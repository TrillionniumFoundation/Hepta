"""Physical-source custody controls for the complete 61-method transaction gate."""
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_store_transaction as subject
from tools import hia_cold_caller_sources as cold
from tools.hia_frozen_component_sources import cold_caller_source
from tests import hia_installed_distribution_history as installed
from tests import hia_component_authoring_history as component
from tests import hia_journal_installed_preparation as journal

ROOT = Path(subject.__file__).resolve().parents[1]


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class StoreTransactionSourceCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory, cls.proof = subject.admit_separate_inventory(
            root=ROOT, with_source_admission=True)
        cls.data = {name: (ROOT / name).read_bytes()
                    for name in cls.proof['captured_files']}
        cls.records = {row['path']: row for row in cls.inventory['modules']}
        cls.original = {subject.FIXTURE: cls.data[subject.FIXTURE]}
        for name, record in cls.records.items():
            prior, _ = cold_caller_source(ROOT, name, cls.data[name])
            prior = installed.predecessor(name, prior, root=ROOT)
            if name == journal.PATH:
                prior = journal.restore_source(
                    prior, json.loads(cls.data[journal.FIXTURE]))
            expected = {key: record[key] for key in ('bytes', 'sha256')}
            if pin(prior) != expected:
                raise ValueError('the complete original caller was not reconstructed')
            cls.original[name] = prior

    def stage(self, files=None):
        directory = tempfile.TemporaryDirectory(prefix='hia-store-transaction-custody-')
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for name, raw in (self.data if files is None else files).items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        return root

    def admit(self, root):
        return subject.admit_separate_inventory(root=root, with_source_admission=True)

    def assert_original_inventory(self, value, proof):
        self.assertEqual(value, self.inventory)
        self.assertEqual(proof['original_ordered_ids'], self.inventory['ordered_ids'])
        self.assertEqual(len(proof['original_ordered_ids']), 61)
        self.assertEqual(proof['original_count'], 61)
        self.assertEqual(proof['original_module_counts'], [21, 25, 15])
        self.assertEqual(proof['original_outer_seconds'], 1800)
        self.assertEqual(proof['production_source_exceptions'], [])
        self.assertFalse(proof['whole_native'])
        self.assertTrue(proof['terminal_reread_identical'])

    def test_complete_physical_capture_is_independent_of_ambient_source_roots(self):
        root = self.stage()
        foreign = root / 'absent-ambient-root'
        original_read = Path.read_bytes
        loaded_helpers = {cold.SOURCE, journal.HELPER}

        def read(path):
            path = Path(path)
            if path.is_relative_to(ROOT):
                relative = path.relative_to(ROOT).as_posix()
                if relative not in loaded_helpers:
                    raise AssertionError('foreign source root was read: ' + relative)
            return original_read(path)

        with ExitStack() as scope:
            for module in (subject, installed, component):
                scope.enter_context(patch.object(module, 'ROOT', foreign))
            scope.enter_context(patch.object(Path, 'read_bytes', read))
            value, proof = self.admit(root)
        self.assert_original_inventory(value, proof)
        self.assertEqual(proof, self.proof)
        self.assertEqual(set(proof['reviewed_native_cold_caller_sources']),
                         set(self.records))
        self.assertEqual(proof['captured_files'],
                         {name: pin(raw) for name, raw in self.data.items()})

    def test_exact_original_callers_need_no_migration_authority(self):
        root = self.stage(self.original)
        foreign = root / 'absent-ambient-root'
        with ExitStack() as scope:
            for module in (subject, installed, component):
                scope.enter_context(patch.object(module, 'ROOT', foreign))
            value, proof = self.admit(root)
        self.assert_original_inventory(value, proof)
        self.assertEqual(proof['captured_files'],
                         {name: pin(raw) for name, raw in self.original.items()})
        self.assertEqual(proof['reviewed_native_cold_caller_sources'], {})
        self.assertEqual(proof['installed_distribution_predecessors'], {})
        self.assertEqual(proof['reviewed_journal_installed_preparation_source_adjustments'], {})

    def test_current_callers_reject_missing_each_and_combined_migration_authorities(self):
        authority_names = sorted(set(self.data) - set(self.records) - {subject.FIXTURE})
        missing_sets = [(name,) for name in authority_names]
        missing_sets.extend(((cold.FIXTURE, cold.PREVIOUS_FIXTURE),
                             (installed.FIXTURE, component.FIXTURE),
                             tuple(authority_names)))
        for missing in missing_sets:
            with self.subTest(missing=missing):
                root = self.stage({name: raw for name, raw in self.data.items()
                                   if name not in missing})
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.admit(root)

    def test_every_consumed_physical_source_and_authority_rejects_byte_mutation(self):
        root = self.stage()
        for name, raw in self.data.items():
            with self.subTest(path=name):
                path = root / name
                path.write_bytes(raw + b'\n# unreviewed physical mutation\n')
                try:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        self.admit(root)
                finally:
                    path.write_bytes(raw)

    def test_every_physical_capture_has_an_effective_terminal_reread(self):
        root = self.stage()
        original_read = Path.read_bytes
        baseline = Counter()

        def measured(path):
            raw = original_read(path)
            path = Path(path)
            if path.is_relative_to(root):
                baseline[path.relative_to(root).as_posix()] += 1
            return raw

        with patch.object(Path, 'read_bytes', measured):
            self.admit(root)
        self.assertEqual(set(baseline), set(self.data))
        self.assertTrue(all(count >= 2 for count in baseline.values()))
        for name in sorted(self.data):
            with self.subTest(path=name):
                calls = Counter()

                def drift(path):
                    raw = original_read(path)
                    path = Path(path)
                    if path.is_relative_to(root):
                        relative = path.relative_to(root).as_posix()
                        calls[relative] += 1
                        if relative == name and calls[relative] == baseline[name]:
                            return raw + b'\n# terminal-only physical drift\n'
                    return raw

                with patch.object(Path, 'read_bytes', drift):
                    with self.assertRaisesRegex(
                            ValueError, 'transaction caller captured source changed'):
                        self.admit(root)
                self.assertEqual(calls[name], baseline[name])

    def test_physical_source_map_binding_requires_every_captured_dependency(self):
        digests = {name: value['sha256']
                   for name, value in self.proof['captured_files'].items()}
        subject._bind_source_admission(self.proof, digests)
        for name in sorted(digests):
            with self.subTest(path=name):
                missing = dict(digests)
                del missing[name]
                with self.assertRaises(ValueError):
                    subject._bind_source_admission(self.proof, missing)
                changed = {**digests, name: '0' * 64}
                with self.assertRaises(ValueError):
                    subject._bind_source_admission(self.proof, changed)


if __name__ == '__main__':
    unittest.main()
