"""Additional custody controls for the exact native-cold bootstrap caller.

These controls read source bytes only. They do not execute the retained caller,
build a component, or change its original IDs, assertions, inputs, or budgets.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tests import hia_installed_distribution_history as installed
from tools import hia_cold_caller_sources as cold
from tools import qualify_hia_service_bootstrap_callers as producer
from tools import read_hia_service_bootstrap as reader

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = 'tests/test_hia_service_context_native.py'


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class BootstrapColdSourceCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = (producer.FIXTURE, CONTEXT, cold.FIXTURE,
                 cold.PREVIOUS_FIXTURE, cold.SOURCE, installed.FIXTURE)
        cls.sources = {name: (ROOT / name).read_bytes() for name in names}
        cls.scope = json.loads(cls.sources[producer.FIXTURE])['scopes']['context']
        cls.physical = cls.sources[CONTEXT]
        relations = cold.read_relations(
            cls.sources[cold.FIXTURE],
            previous_raw=cls.sources[cold.PREVIOUS_FIXTURE])
        cls.pre_cold = cold.restore_caller_source(CONTEXT, cls.physical, relations)
        cls.original = installed._restore(
            cls.pre_cold, installed._parse_records(cls.sources[installed.FIXTURE])[CONTEXT])
        if (pin(cls.original) != cls.scope['files'][CONTEXT]
                or cls.physical == cls.pre_cold or cls.pre_cold == cls.original):
            raise AssertionError('the three complete context source generations differ')
        if len(cls.scope['ordered_ids']) != 15 or cls.scope['outer_seconds'] != 1800:
            raise AssertionError('the immutable original context domain differs')

    @classmethod
    def tearDownClass(cls):
        if cls.sources != {name: (ROOT / name).read_bytes() for name in cls.sources}:
            raise AssertionError('bootstrap cold controls changed their actual source inputs')

    def setUp(self):
        temporary = TemporaryDirectory(prefix='hia-bootstrap-cold-source-controls-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.sequence = 0

    def stage(self, mode='current'):
        self.sequence += 1
        root = self.base / str(self.sequence)
        root.mkdir()
        if mode == 'current':
            sources = self.sources
        elif mode == 'pre-cold':
            sources = {producer.FIXTURE: self.sources[producer.FIXTURE],
                       CONTEXT: self.pre_cold,
                       installed.FIXTURE: self.sources[installed.FIXTURE]}
        elif mode == 'original':
            sources = {producer.FIXTURE: self.sources[producer.FIXTURE],
                       CONTEXT: self.original}
        else:
            raise AssertionError('unknown test fixture generation')
        for name, raw in sources.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        return root

    def inner(self, proof, *, include_proof=True):
        before = {name: item['sha256'] for name, item in proof['captured_files'].items()}
        inner = {'source_before': before, 'source_after': dict(before)}
        if include_proof:
            inner['caller_source_admission'] = deepcopy(proof)
        return inner

    def independent(self, root, proof, *, inner=None):
        captures = []
        if inner is None:
            inner = self.inner(proof)
        with patch.object(reader, 'ROOT', root):
            actual = reader._read_caller_source_admission(
                'context', self.scope, inner, captures)
            reader.unchanged(captures)
        return actual, captures

    def reject_both(self, root, proof, *, inner=None):
        with self.assertRaises((ValueError, FileNotFoundError)):
            producer.admit_original_scope(root, 'context')
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.independent(root, proof, inner=inner)

    def test_original_and_pre_cold_use_only_their_own_exact_authority(self):
        for mode in ('original', 'pre-cold'):
            with self.subTest(generation=mode):
                root = self.stage(mode)
                scope, proof = producer.admit_original_scope(root, 'context')
                self.assertEqual(scope, self.scope)
                self.assertEqual(proof['original_files'], self.scope['files'])
                self.assertEqual(proof['original_ordered_ids'], self.scope['ordered_ids'])
                self.assertEqual(proof['original_outer_seconds'], 1800)
                expected = {producer.FIXTURE, CONTEXT}
                if mode == 'pre-cold':
                    expected.add(installed.FIXTURE)
                    self.assertEqual(proof['reviewed_scope_predecessors'][CONTEXT],
                                     {'physical': pin(self.pre_cold), 'predecessor': pin(self.original)})
                else:
                    self.assertNotIn('reviewed_scope_predecessors', proof)
                self.assertEqual(set(proof['captured_files']), expected)
                self.assertNotIn('reviewed_native_cold_caller_adjustments', proof)
                self.assertEqual(self.independent(root, proof)[0], proof)
                legacy = self.inner(proof, include_proof=False)
                if mode == 'original':
                    self.assertEqual(self.independent(root, proof, inner=legacy)[0], proof)
                else:
                    with self.assertRaises(ValueError):
                        self.independent(root, proof, inner=legacy)

    def test_current_has_complete_physical_captures_and_independent_readback(self):
        root = self.stage()
        scope, proof = producer.admit_original_scope(root, 'context')
        actual, captures = self.independent(root, proof)
        self.assertEqual(actual, proof)
        self.assertEqual(scope, self.scope)
        self.assertEqual(set(proof['captured_files']), set(self.sources))
        self.assertEqual(proof['captured_files'],
                         {name: pin(raw) for name, raw in self.sources.items()})
        self.assertEqual(proof['reviewed_native_cold_caller_adjustments'][CONTEXT],
                         {'physical': pin(self.physical), 'predecessor': pin(self.pre_cold)})
        self.assertEqual(proof['reviewed_scope_predecessors'][CONTEXT],
                         {'physical': pin(self.physical), 'predecessor': pin(self.original)})
        self.assertEqual(proof['original_files'], self.scope['files'])
        self.assertEqual(proof['original_ordered_ids'], self.scope['ordered_ids'])
        self.assertEqual(proof['original_outer_seconds'], 1800)
        self.assertEqual(proof['production_source_exceptions'], [])
        self.assertTrue(proof['terminal_reread_identical'])
        self.assertFalse(proof['whole_native'])
        self.assertGreaterEqual(len(captures), len(self.sources))

    def test_every_current_input_is_required_and_byte_exact(self):
        root = self.stage()
        _, proof = producer.admit_original_scope(root, 'context')
        for name, raw in self.sources.items():
            for action in ('missing', 'changed'):
                with self.subTest(path=name, action=action):
                    path = root / name
                    if action == 'missing':
                        path.unlink()
                    else:
                        path.write_bytes(raw + b'\n')
                    try:
                        self.reject_both(root, proof)
                    finally:
                        path.write_bytes(raw)

    def test_current_without_both_generations_cannot_obtain_legacy_admission(self):
        root = self.stage()
        _, proof = producer.admit_original_scope(root, 'context')
        for name in (cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE):
            (root / name).unlink()
        legacy = self.inner(proof, include_proof=False)
        for name in (cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE):
            legacy['source_before'].pop(name)
            legacy['source_after'].pop(name)
        self.reject_both(root, proof, inner=legacy)

    def test_changed_current_bytes_reject_resigned_capture_claims(self):
        root = self.stage()
        _, proof = producer.admit_original_scope(root, 'context')
        changes = [self.physical + b'\n']
        for offset in (0, len(self.physical) // 2, len(self.physical) - 1):
            changed = bytearray(self.physical)
            changed[offset] ^= 1
            changes.append(bytes(changed))
        for index, raw in enumerate(changes):
            with self.subTest(change=index):
                (root / CONTEXT).write_bytes(raw)
                claimed = deepcopy(proof)
                claimed['captured_files'][CONTEXT] = pin(raw)
                claimed['reviewed_native_cold_caller_adjustments'][CONTEXT]['physical'] = pin(raw)
                claimed['reviewed_scope_predecessors'][CONTEXT]['physical'] = pin(raw)
                self.reject_both(root, claimed)
        (root / CONTEXT).write_bytes(self.physical)

    def test_late_drift_of_every_capture_is_rejected_by_both_consumers(self):
        root = self.stage()
        _, proof = producer.admit_original_scope(root, 'context')
        real_read = Path.read_bytes
        for name in self.sources:
            for consumer in ('producer', 'independent'):
                with self.subTest(path=name, consumer=consumer):
                    target = root / name
                    counts = []
                    def changed(path):
                        raw = real_read(path)
                        if path == target:
                            counts.append(True)
                            if len(counts) > 1:
                                return raw + b'\n'
                        return raw
                    with patch.object(Path, 'read_bytes', changed):
                        with self.assertRaises(ValueError):
                            if consumer == 'producer':
                                producer.admit_original_scope(root, 'context')
                            else:
                                self.independent(root, proof)
                    self.assertGreaterEqual(len(counts), 2)

    def test_claims_and_capture_omissions_cannot_replace_independent_source_proof(self):
        root = self.stage()
        _, proof = producer.admit_original_scope(root, 'context')
        variants = []
        for field in ('reviewed_native_cold_caller_adjustments', 'reviewed_scope_predecessors'):
            inner = self.inner(proof)
            inner['caller_source_admission'].pop(field)
            variants.append((field + '-missing', inner))
            inner = self.inner(proof)
            inner['caller_source_admission'][field][CONTEXT]['predecessor']['sha256'] = '0' * 64
            variants.append((field + '-resigned', inner))
        inner = self.inner(proof)
        inner['caller_source_admission']['original_ordered_ids'].reverse()
        variants.append(('reordered-original-ids', inner))
        inner = self.inner(proof, include_proof=False)
        variants.append(('missing-current-proof', inner))
        for name in proof['captured_files']:
            inner = self.inner(proof)
            inner['caller_source_admission']['captured_files'].pop(name)
            inner['source_before'].pop(name)
            inner['source_after'].pop(name)
            variants.append(('capture-omitted:' + name, inner))
            inner = self.inner(proof)
            inner['source_after'][name] = '0' * 64
            variants.append(('source-after-changed:' + name, inner))
        for label, inner in variants:
            with self.subTest(change=label), self.assertRaises(ValueError):
                self.independent(root, proof, inner=inner)


if __name__ == '__main__':
    unittest.main()
