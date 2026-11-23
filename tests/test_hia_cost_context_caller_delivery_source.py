"""Exact Cost and Context caller source relations through both unchanged Delivery guards.

These controls only read and compare source. They do not run either caller
suite, compile HIA, enter a native image, touch a database or deliver a result.
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


def independent_inverse(raw, record):
    result = raw
    for item in reversed(record['splices']):
        at = item['new_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if result[at:at + len(after)] != after:
            raise AssertionError('independent Cost whole-source inverse splice differs')
        result = result[:at] + before + result[at + len(after):]
    if pin(result) != record['old']:
        raise AssertionError('independent inverse did not restore the full original Cost source')
    replay = result
    for item in reversed(record['splices']):
        at = item['old_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if replay[at:at + len(before)] != before:
            raise AssertionError('independent Cost forward splice differs')
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != raw:
        raise AssertionError('independent whole current Cost replay differs')
    return result


class CostContextCallerDeliverySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = set(OUTER_PINS) | set(subject.ORDINARY_CALLER_CAPTURE_PATHS) | {
            'tests/test_hia_cost_context_caller_delivery_source.py',
            'tests/hia_native_transport_worker_successor.py',
            'tests/hia_store_delivery_successor.py', 'hepta/hia_native_helpers.py',
            subject.FIXTURE, subject.EVALUATION_FIXTURE, subject.QUALIFIER_FIXTURE,
            subject.QUALIFIER_DEPENDENCY_FIXTURE, subject.DIAGNOSTIC_FIXTURE,
            subject.SQLITE_BOUNDARY_FIXTURE,
            str(composition.FIXTURE.relative_to(ROOT)),
            *subject.PATHS, subject.EVALUATION, *subject.QUALIFIER_PATHS,
            *subject.QUALIFIER_DEPENDENCIES, *subject.QUALIFIER_DIAGNOSTIC_DEPENDENCIES,
            *subject.DIAGNOSTIC_PATHS, *subject.DIAGNOSTIC_DEPENDENCIES,
            *subject.JOURNAL_PREPARATION_PATHS, *composition.PATHS,
        }
        cls.originals = {}
        for kind, (name, expected) in subject.ORIGINALS.items():
            raw = (ROOT / name).read_bytes()
            if pin(raw) != expected:
                raise AssertionError('complete original Delivery authority changed')
            cls.originals[kind] = json.loads(raw)
            names.add(name)
            names.update(cls.originals[kind]['unchanged_files'])
            names.update(cls.originals[kind].get('shared_dependency_review', {}))
        names.update((subject.SQL_SOURCE_FIXTURE, subject.SQL_EFFECT_TEST))
        cls.sources = {name: (ROOT / name).read_bytes() for name in sorted(names)}
        for name, expected in OUTER_PINS.items():
            raw = cls.sources[name]
            if name == subject.DELIVERY and pin(raw) != expected:
                raw = subject.restore_sql_source(name, raw, cls.sources.__getitem__, expected)
            if pin(raw) != expected:
                raise AssertionError('an unchanged complete Delivery outer test changed')
        frozen = cls.sources[subject.ORDINARY_CALLER_FIXTURE]
        if pin(frozen) != subject.ORDINARY_CALLER_FIXTURE_PIN:
            raise AssertionError('fixed Cost/Context caller source authority changed')
        cls.authority = json.loads(frozen)
        cls.records = cls.authority['files']
        cls.old_sources = {path: independent_inverse(cls.sources[path], cls.records[path])
                           for path in subject.ORDINARY_CALLER_PATHS}
        for path, old in cls.old_sources.items():
            if any(pin(old) != value['unchanged_files'][path] for value in cls.originals.values()):
                raise AssertionError('caller inverse does not recover both complete original inventories')
        cls.original_counts = {
            'tools/qualify_hia_cost_ledger_callers.py': 81,
            'tools/qualify_hia_service_context_callers.py': 50,
        }

    @classmethod
    def tearDownClass(cls):
        if cls.sources != {name: (ROOT / name).read_bytes() for name in cls.sources}:
            raise AssertionError('ordinary caller Delivery Source inputs changed')

    @contextmanager
    def view(self, mask=3, *, old_journal=False, overrides=None, missing=()):
        values = {ROOT / path: (self.sources[path] if mask & (1 << bit) else self.old_sources[path])
                  for bit, path in enumerate(subject.ORDINARY_CALLER_PATHS)}
        values.update({ROOT / name: raw for name, raw in (overrides or {}).items()})
        if old_journal:
            values[ROOT / subject.JOURNAL_PREPARATION_PATH] = self.sources[subject.JOURNAL_PREPARATION_ARCHIVE]
        absent, real_read = {ROOT / name for name in missing}, Path.read_bytes
        def read(path):
            if path in absent:
                raise FileNotFoundError(str(path))
            return values[path] if path in values else real_read(path)
        with patch.object(Path, 'read_bytes', read):
            yield

    def test_01_both_complete_inventories_keep_all_cost_context_and_journal_combinations(self):
        for kind, outer in OUTERS.items():
            for mask in range(4):
                for old_journal in (False, True):
                    with self.subTest(kind=kind, mask=mask, old_journal=old_journal), \
                            self.view(mask, old_journal=old_journal):
                        value = outer.admit_originals()
                        self.assertEqual(value['unchanged_files'], self.originals[kind]['unchanged_files'])
                        self.assertEqual(len(value['unchanged_files']), 64 if kind == 'native' else 89)
                        actual = value['transport_terminal_successor']
                        prior = subject._admit_terminal_sources_before_ordinary_callers(
                            deepcopy(self.originals[kind]), original_kind=kind)
                        self.assertEqual(actual['production_composition_source_count'], 13)
                        expected_paths = {path for bit, path in enumerate(subject.ORDINARY_CALLER_PATHS)
                                          if mask & (1 << bit)}
                        if not expected_paths:
                            self.assertEqual(actual, prior)
                        else:
                            current = actual['ordinary_caller_source_admission']
                            self.assertEqual(current['source_adjustment_count'], len(expected_paths))
                            self.assertEqual(current['original_ordinary_method_counts'], self.original_counts)
                            self.assertEqual(current['complete_old_sources'], {
                                path: pin(raw) for path, raw in self.old_sources.items()})
                            self.assertTrue(current['terminal_reread_identical'])
                            self.assertTrue(current['prior_captures_consumed_without_refresh'])
                            self.assertEqual(current['production_source_exceptions'], [])
                            self.assertFalse(current['whole_native'])
                            for name, item in prior.items():
                                if name != 'source_adjustments':
                                    self.assertEqual(actual[name], item)
                            self.assertEqual(actual['source_adjustments'], {
                                **prior['source_adjustments'], **current['source_adjustments']})
                            self.assertEqual(set(current['source_adjustments']), expected_paths)
                            for path in subject.ORDINARY_CALLER_PATHS:
                                self.assertEqual(current['actual_source_states'][path],
                                    'EXACT_REVIEWED_SUCCESSOR' if path in expected_paths else 'EXACT_ORIGINAL')
                            for name, expected in current['actual_captured_files'].items():
                                self.assertEqual(pin((ROOT / name).read_bytes()), expected)
                            if kind == 'store':
                                consumed = {row['path']: row for row in value['successor_source_adjustments']}
                                for path in expected_paths:
                                    self.assertEqual(consumed[path], current['source_adjustments'][path])
            with self.view(0, missing=(subject.ORDINARY_CALLER_FIXTURE,)):
                self.assertEqual(outer.admit_originals()['unchanged_files'], self.originals[kind]['unchanged_files'])
            for mask in (1, 2, 3):
                with self.subTest(kind=kind, missing_authority_mask=mask), \
                        self.view(mask, missing=(subject.ORDINARY_CALLER_FIXTURE,)), self.assertRaises(AssertionError):
                    outer.admit_originals()
            for path in subject.ORDINARY_CALLER_PATHS:
                forged = deepcopy(self.originals[kind])
                forged['unchanged_files'][path] = subject.ORDINARY_CALLER_RECORDS[path]['new']
                with self.assertRaises(ValueError):
                    subject.admit_terminal_sources(forged, original_kind=kind)

    def test_02_all_fixed_captures_refuse_missing_drift_cache_and_terminal_mutation(self):
        for kind, outer in OUTERS.items():
            for name in subject.ORDINARY_CALLER_CAPTURE_PATHS:
                for mode in ('missing', 'tamper', 'no-cache', 'reread'):
                    with self.subTest(kind=kind, path=name, mode=mode):
                        if mode == 'no-cache':
                            outer.admit_originals()
                        if mode == 'missing':
                            with self.view(missing=(name,)), self.assertRaises((AssertionError, ValueError, FileNotFoundError)):
                                outer.admit_originals()
                        elif mode == 'reread':
                            target, real_read, calls = ROOT / name, Path.read_bytes, []
                            def changed(path):
                                raw = real_read(path)
                                if path == target:
                                    calls.append(True)
                                    if len(calls) > 1:
                                        return raw + b'\n'
                                return raw
                            with patch.object(Path, 'read_bytes', changed), self.assertRaises(ValueError):
                                outer.admit_originals()
                            self.assertGreaterEqual(len(calls), 2)
                        else:
                            with self.view(overrides={name: self.sources[name] + b'\n'}), self.assertRaises(ValueError):
                                outer.admit_originals()

    def test_03_actual_outer_maps_and_prior_valid_source_swaps_remain_bound(self):
        for kind, outer in OUTERS.items():
            for target_name in subject.ORDINARY_CALLER_PATHS:
                real_admit = subject.admit_terminal_sources
                for variant in ('missing-map', 'old-pin', 'foreign-pin', 'source-after-admission'):
                    completed = []
                    def altered(*args, **kwargs):
                        value = deepcopy(real_admit(*args, **kwargs))
                        completed.append(True)
                        if variant == 'missing-map':
                            del value['source_adjustments'][target_name]
                        elif variant == 'old-pin':
                            old = subject.ORDINARY_CALLER_RECORDS[target_name]['old']
                            value['source_adjustments'][target_name].update(
                                current_bytes=old['bytes'], current_sha256=old['sha256'])
                        elif variant == 'foreign-pin':
                            value['source_adjustments'][target_name]['current_sha256'] = '0' * 64
                        return value
                    real_read = Path.read_bytes
                    def late(path):
                        raw = real_read(path)
                        return self.old_sources[target_name] if (variant == 'source-after-admission' and completed
                                                                and path == ROOT / target_name) else raw
                    with self.subTest(kind=kind, path=target_name, map=variant), \
                            patch.object(subject, 'admit_terminal_sources', altered), \
                            patch.object(Path, 'read_bytes', late), self.assertRaises(AssertionError):
                        outer.admit_originals()
        target_name = subject.DIAGNOSTIC_PATHS[0]
        diagnostic = json.loads(self.sources[subject.DIAGNOSTIC_FIXTURE])
        sqlite_fixture = self.sources[subject.SQLITE_BOUNDARY_FIXTURE]
        self.assertEqual(pin(sqlite_fixture), subject.SQLITE_BOUNDARY_FIXTURE_PIN)
        sqlite_record = json.loads(sqlite_fixture)['files'][target_name]
        self.assertEqual(sqlite_record['predecessor_fixture'],
                         {'path': subject.DIAGNOSTIC_FIXTURE, **pin(self.sources[subject.DIAGNOSTIC_FIXTURE])})
        predecessor = composition.reverse_exact(
            self.sources[target_name], sqlite_record['record'], diagnostic['files'][target_name]['new'])
        old_native_tools = independent_inverse(predecessor, diagnostic['files'][target_name])
        for changed_raw in (self.sources[target_name] + b'\n', old_native_tools):
            real_prior, real_read, completed = subject._admit_terminal_sources_before_ordinary_callers, Path.read_bytes, []
            def prior(*args, **kwargs):
                value = real_prior(*args, **kwargs)
                completed.append(True)
                return value
            def changed(path):
                raw = real_read(path)
                return changed_raw if completed and path == ROOT / target_name else raw
            with patch.object(subject, '_admit_terminal_sources_before_ordinary_callers', prior), \
                    patch.object(Path, 'read_bytes', changed), self.assertRaisesRegex(ValueError, 'prior source changed'):
                OUTERS['store'].admit_originals()
            self.assertTrue(completed)

    def test_04_whole_inverse_and_forward_require_exact_paths_and_typed_splices(self):
        variants = ('scope', 'old-pin', 'new-pin', 'tuple-splices', 'missing-splice', 'wrong-id',
                    'overlap', 'uppercase-hex', 'old-byte', 'new-byte', 'extra-field',
                    'raw-bytearray', 'raw-unlisted-byte')
        for path in subject.ORDINARY_CALLER_PATHS:
            current, original_record = self.sources[path], self.records[path]
            self.assertEqual(subject.reverse_ordinary_caller(current, original_record, path), self.old_sources[path])
            self.assertEqual(subject._ordinary_caller_transform(self.old_sources[path], original_record, path, reverse=False), current)
            for variant in variants:
                record, raw = deepcopy(original_record), current
                if variant == 'scope': record['scope'] += ' changed'
                elif variant == 'old-pin': record['old']['sha256'] = '0' * 64
                elif variant == 'new-pin': record['new']['sha256'] = '0' * 64
                elif variant == 'tuple-splices': record['splices'] = tuple(record['splices'])
                elif variant == 'missing-splice': record['splices'].pop()
                elif variant == 'wrong-id': record['splices'][0]['id'] += '-changed'
                elif variant == 'overlap': record['splices'][1]['old_offset'] = record['splices'][0]['old_offset']
                elif variant == 'uppercase-hex': record['splices'][0]['old_hex'] = record['splices'][0]['old_hex'].upper()
                elif variant == 'old-byte': record['splices'][0]['old_hex'] = '00' + record['splices'][0]['old_hex'][2:]
                elif variant == 'new-byte': record['splices'][0]['new_hex'] = '00' + record['splices'][0]['new_hex'][2:]
                elif variant == 'extra-field': record['extra'] = True
                elif variant == 'raw-bytearray': raw = bytearray(raw)
                elif variant == 'raw-unlisted-byte': raw += b'\n'
                with self.subTest(path=path, variant=variant), self.assertRaises(ValueError):
                    subject.reverse_ordinary_caller(raw, record, path)
            for index in range(len(original_record['splices'])):
                for coordinate in ('old_offset', 'new_offset'):
                    record = deepcopy(original_record)
                    record['splices'][index][coordinate] = True
                    with self.subTest(path=path, splice=index, coordinate=coordinate), self.assertRaises(ValueError):
                        subject.reverse_ordinary_caller(current, record, path)
            for reverse in (0, 1, None):
                with self.subTest(path=path, reverse=reverse), self.assertRaises(ValueError):
                    subject._ordinary_caller_transform(current, original_record, path, reverse=reverse)
            for other_path in (None, True, 'tools/unlisted.py',
                               next(name for name in subject.ORDINARY_CALLER_PATHS if name != path)):
                with self.subTest(path=path, other_path=other_path), self.assertRaises(ValueError):
                    subject.reverse_ordinary_caller(current, original_record, other_path)


if __name__ == '__main__':
    unittest.main()
