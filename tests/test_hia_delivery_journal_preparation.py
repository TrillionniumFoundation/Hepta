"""New Journal source proof through the unchanged full Delivery outer guards.

These source controls retain the 64/89-file authorities and the previous
terminal/qualifier/diagnostic domains. They execute no HIA or native product.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import hia_native_transport_worker_successor as subject
from tests import hia_store_delivery_successor as composition
from tests import hia_journal_installed_preparation as journal
from tests import test_hia_native_delivery as native
from tests import test_hia_store_native_delivery as store

ROOT = Path(__file__).resolve().parents[1]
OUTERS = {'native': native, 'store': store}
OUTER_PINS = {
    'tests/test_hia_native_delivery.py': {'bytes': 13263, 'sha256': '09692f4ce91da30ad3aac0b009e15e520058022cd01af8fdf1a7dd8811aab64b'},
    'tests/test_hia_store_native_delivery.py': {'bytes': 16697, 'sha256': 'f1d6605a2dfaba8b949f81e213d19a187779fe251258e73fa58b26fe6fecfb1c'},
}


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class DeliveryJournalPreparationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = set(OUTER_PINS) | set(journal.SOURCE_PATHS) | {
            'tests/test_hia_delivery_journal_preparation.py',
            'tests/hia_native_transport_worker_successor.py',
            'tests/hia_store_delivery_successor.py', 'hepta/hia_native_helpers.py',
            subject.FIXTURE, subject.EVALUATION_FIXTURE, subject.QUALIFIER_FIXTURE,
            subject.QUALIFIER_DEPENDENCY_FIXTURE, subject.DIAGNOSTIC_FIXTURE,
            str(composition.FIXTURE.relative_to(ROOT)),
            *subject.PATHS, subject.EVALUATION, *subject.QUALIFIER_PATHS,
            *subject.QUALIFIER_DEPENDENCIES, *subject.QUALIFIER_DIAGNOSTIC_DEPENDENCIES,
            *subject.DIAGNOSTIC_PATHS, *subject.DIAGNOSTIC_DEPENDENCIES, *composition.PATHS,
        }
        cls.originals = {}
        for kind, (name, expected) in subject.ORIGINALS.items():
            raw = (ROOT / name).read_bytes()
            if pin(raw) != expected:
                raise AssertionError('Delivery original whole authority changed')
            cls.originals[kind] = json.loads(raw)
            names.add(name)
            names.update(cls.originals[kind]['unchanged_files'])
            names.update(cls.originals[kind].get('shared_dependency_review', {}))
        names.update((subject.SQL_SOURCE_FIXTURE, subject.SQL_EFFECT_TEST))
        from tools import hia_cold_caller_sources as cold
        names.update((cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE))
        cls.sources = {name: (ROOT / name).read_bytes() for name in sorted(names)}
        from tests.hia_installed_distribution_history import predecessor
        from tests.hia_historical_diagnostic_controls import cold_control_source
        cls.cold_adjustments = {}
        for name, expected in OUTER_PINS.items():
            raw = cold_control_source(
                ROOT, name, cls.sources[name], cls.sources, cls.cold_adjustments)
            raw = predecessor(name, raw)
            if name == subject.DELIVERY and pin(raw) != expected:
                raw = subject.restore_sql_source(name, raw, cls.sources.__getitem__, expected)
            if pin(raw) != expected:
                raise AssertionError('complete original Delivery test was changed')
        if pin(cls.sources[journal.ARCHIVE]) != journal.ORIGINAL:
            raise AssertionError('complete retained Journal original changed')

    @classmethod
    def tearDownClass(cls):
        if cls.sources != {name: (ROOT / name).read_bytes() for name in cls.sources}:
            raise AssertionError('Delivery Journal Source inputs changed')

    @contextmanager
    def view(self, *, old=False, overrides=None, missing=()):
        values = {ROOT / name: raw for name, raw in (overrides or {}).items()}
        if old: values[ROOT / journal.PATH] = self.sources[journal.ARCHIVE]
        absent, real_read = {ROOT / name for name in missing}, Path.read_bytes
        def read(path):
            if path in absent: raise FileNotFoundError(str(path))
            return values[path] if path in values else real_read(path)
        with patch.object(Path, 'read_bytes', read):
            yield

    def test_01_complete_original_guards_consume_exact_current_proof_and_keep_literal_authority(self):
        for kind, outer in OUTERS.items():
            for old in (False, True):
                with self.subTest(kind=kind, old=old), self.view(old=old):
                    value = outer.admit_originals()
                    self.assertEqual(value['unchanged_files'], self.originals[kind]['unchanged_files'])
                    self.assertEqual(len(value['unchanged_files']), 64 if kind == 'native' else 89)
                    proof = value['transport_terminal_successor']
                    self.assertEqual(proof['production_composition_source_count'], 13)
                    if old:
                        self.assertNotIn(journal.PATH, proof['source_adjustments'])
                        self.assertNotIn('journal_installed_preparation_source_admission', proof)
                    else:
                        current = proof['journal_installed_preparation_source_admission']
                        self.assertEqual(current['source_adjustment_count'], 1)
                        self.assertEqual(set(current['source_adjustments']), {journal.PATH})
                        self.assertEqual(current['reviewed_journal_installed_preparation']['original'], journal.ORIGINAL)
                        self.assertEqual(current['reviewed_journal_installed_preparation']['current'], journal.CURRENT)
                        self.assertTrue(current['prior_captures_consumed_without_refresh'])
                        self.assertTrue(current['terminal_reread_identical'])
                        self.assertEqual(current['production_source_exceptions'], [])
                        self.assertEqual(current['reviewed_journal_installed_preparation']['original_method_count'], 21)
                        self.assertEqual(proof['source_adjustments'][journal.PATH], current['source_adjustments'][journal.PATH])
                        if kind == 'store':
                            consumed = {row['path']: row for row in value['successor_source_adjustments']}
                            self.assertEqual(consumed[journal.PATH], proof['source_adjustments'][journal.PATH])
            with self.subTest(kind=kind, authority='absent-old'), self.view(old=True, missing=(journal.FIXTURE,)):
                self.assertEqual(outer.admit_originals()['unchanged_files'], self.originals[kind]['unchanged_files'])
            with self.subTest(kind=kind, authority='absent-current'), self.view(missing=(journal.FIXTURE,)), \
                    self.assertRaises(AssertionError):
                outer.admit_originals()
            changed = deepcopy(self.originals[kind])
            changed['unchanged_files'][journal.PATH] = journal.CURRENT
            with self.subTest(kind=kind, source='forged-new-original'), self.assertRaises(ValueError):
                subject.admit_terminal_sources(changed, original_kind=kind)

    def test_02_all_new_captures_prior_gap_and_actual_outer_map_fail_closed(self):
        for kind, outer in OUTERS.items():
            for name in journal.SOURCE_PATHS:
                for action in ('missing', 'tamper', 'no-cache', 'reread'):
                    with self.subTest(kind=kind, path=name, action=action):
                        if action == 'no-cache': outer.admit_originals()
                        if action == 'missing':
                            with self.view(missing=(name,)), self.assertRaises((AssertionError, ValueError, FileNotFoundError)):
                                outer.admit_originals()
                        elif action == 'reread':
                            target, real_read, seen = ROOT / name, Path.read_bytes, []
                            def changed(path):
                                raw = real_read(path)
                                if path == target:
                                    seen.append(True)
                                    if len(seen) > 1: return raw + b'\n'
                                return raw
                            with patch.object(Path, 'read_bytes', changed), self.assertRaises(ValueError):
                                outer.admit_originals()
                            self.assertGreaterEqual(len(seen), 2)
                        else:
                            with self.view(overrides={name: self.sources[name] + b'\n'}), self.assertRaises(ValueError):
                                outer.admit_originals()
            real_admit = subject.admit_terminal_sources
            for variant in ('missing-map', 'old-current-pin', 'foreign-current-pin', 'late-current-source'):
                completed = []
                def altered(*args, **kwargs):
                    proof = deepcopy(real_admit(*args, **kwargs))
                    completed.append(True)
                    if variant == 'missing-map': del proof['source_adjustments'][journal.PATH]
                    elif variant == 'old-current-pin':
                        proof['source_adjustments'][journal.PATH]['current_bytes'] = journal.ORIGINAL['bytes']
                        proof['source_adjustments'][journal.PATH]['current_sha256'] = journal.ORIGINAL['sha256']
                    elif variant == 'foreign-current-pin':
                        proof['source_adjustments'][journal.PATH]['current_sha256'] = '0' * 64
                    return proof
                real_read = Path.read_bytes
                def late(path):
                    raw = real_read(path)
                    return raw + b'\n' if (variant == 'late-current-source' and completed
                                            and path == ROOT / journal.PATH) else raw
                with self.subTest(kind=kind, map=variant), patch.object(subject, 'admit_terminal_sources', altered), \
                        patch.object(Path, 'read_bytes', late), self.assertRaises(AssertionError):
                    outer.admit_originals()
        real_prior, real_read, completed = subject._admit_terminal_sources_before_journal, Path.read_bytes, []
        def prior(*args, **kwargs):
            value = real_prior(*args, **kwargs)
            completed.append(True)
            return value
        target = ROOT / subject.DIAGNOSTIC_PATHS[0]
        def prior_changed(path):
            raw = real_read(path)
            return raw + b'\n' if completed and path == target else raw
        with patch.object(subject, '_admit_terminal_sources_before_journal', prior), \
                patch.object(Path, 'read_bytes', prior_changed), self.assertRaisesRegex(ValueError, 'prior source changed'):
            OUTERS['store'].admit_originals()
        self.assertTrue(completed)


if __name__ == '__main__':
    unittest.main()
