"""Exact source successors through the unchanged complete Delivery file guards.

Only source reads/admission are exercised. No caller qualifier main, HIA VM,
compiler, native helper, database or delivery action is run by these controls.
The complete original Delivery Source and Native suites remain independent.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from tests import hia_native_transport_worker_successor as subject
from tests import hia_store_delivery_successor as composition
from tests import test_hia_native_delivery as native
from tests import test_hia_store_native_delivery as store

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = 'HEPTA_HIA_DELIVERY_DIAGNOSTIC_SOURCE_EVIDENCE'
AUTHORITY = 'tests/fixtures/delivery_diagnostic_source_successors_v1.json'
AUTHORITY_PIN = {'bytes': 29000, 'sha256': '725f18e0ff6a8f598176bac85383f19234938a0efce73259779357bf6a853778'}
TARGETS = ('tests/test_hia_agent_native_tools.py',
           'tools/qualify_hia_evaluation_callers.py',
           'tools/qualify_hia_store_lifecycle_callers.py')
DEPENDENCIES = ('tests/hia_caller_diagnostics_admission.py',
                'tests/fixtures/caller_deadline_diagnostics_v1.json',
                'tests/fixtures/evaluation_callers_19065.json',
                'tests/fixtures/store_lifecycle_callers_ad352ee.json')
CHECK_PATHS = (AUTHORITY, *TARGETS, *DEPENDENCIES)
OUTERS = {'native': native, 'store': store}
OUTER_PINS = {
    'tests/test_hia_native_delivery.py': {'bytes': 13263, 'sha256': '09692f4ce91da30ad3aac0b009e15e520058022cd01af8fdf1a7dd8811aab64b'},
    'tests/test_hia_store_native_delivery.py': {'bytes': 16697, 'sha256': 'f1d6605a2dfaba8b949f81e213d19a187779fe251258e73fa58b26fe6fecfb1c'},
}
ALLOWED = {'native': TARGETS[:2], 'store': TARGETS}
REVERSE_BAD = ('scope', 'old-pin', 'new-pin', 'tuple-splices', 'missing-splice',
               'wrong-id', 'bool-offset', 'shifted-offset', 'overlap',
               'noncanonical-hex', 'old-byte', 'new-byte', 'extra-field',
               'raw-bytearray', 'raw-unlisted-byte')


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                       separators=(',', ':')) + '\n').encode()


def write(path, value):
    with path.open('xb') as stream:
        stream.write(encoded(value))


def independent_inverse(raw, record):
    result = raw
    for item in reversed(record['splices']):
        at = item['new_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if result[at:at + len(after)] != after:
            raise AssertionError('independent original source splice differs')
        result = result[:at] + before + result[at + len(after):]
    if pin(result) != record['old']:
        raise AssertionError('independent inverse did not restore the whole original source')
    replay = result
    for item in reversed(record['splices']):
        at = item['old_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if replay[at:at + len(before)] != before:
            raise AssertionError('independent original source forward splice differs')
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != raw:
        raise AssertionError('independent complete current replay differs')
    return result


def planned_ids():
    first = ['DDS-ACTUAL-' + kind for kind in OUTERS]
    first += ['DDS-MATRIX-' + kind + '-' + str(mask) for kind in OUTERS for mask in range(8)]
    first += ['DDS-ABSENT-' + kind + '-' + str(mask) for kind in OUTERS for mask in (0, 7)]
    second = ['DDS-' + action + '-' + name
              for action in ('TAMPER', 'MISSING', 'REREAD', 'NO-CACHE') for name in CHECK_PATHS]
    second += ['DDS-WRONG-ORIGINAL-' + kind for kind in OUTERS]
    second += ['DDS-BAD-KIND-' + name for name in ('none', 'bool', 'unlisted')]
    second += ['DDS-PRIOR-CAPTURE-GAP']
    third = ['DDS-MAP-' + kind + '-' + name + '-' + variant
             for kind in OUTERS for name in ALLOWED[kind]
             for variant in ('missing', 'old-pin', 'foreign-pin', 'source-after-admission')]
    third += ['DDS-REVERSE-' + name + '-' + variant for name in TARGETS for variant in REVERSE_BAD]
    third += ['DDS-REVERSE-UNLISTED-PATH']
    return first, second, third


class DeliveryDiagnosticSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = os.environ.get(EVIDENCE)
        if selected == '':
            raise ValueError('empty explicit Delivery diagnostic source evidence path')
        parent = None if selected is None else Path(selected).absolute()
        if parent is not None:
            parent.mkdir(parents=True, exist_ok=True)
        cls.output = Path(tempfile.mkdtemp(prefix='delivery-diagnostic-source-', dir=parent))
        cls.values = {}
        names = set(CHECK_PATHS) | set(OUTER_PINS) | {
            'hepta/hia_native_helpers.py',
            'tests/hia_native_transport_worker_successor.py',
            'tests/hia_store_delivery_successor.py',
            'tests/test_hia_delivery_diagnostic_sources.py', 'tests/__init__.py',
            subject.FIXTURE, subject.EVALUATION_FIXTURE, subject.QUALIFIER_FIXTURE,
            subject.SQLITE_BOUNDARY_FIXTURE,
            subject.QUALIFIER_DEPENDENCY_FIXTURE, composition.EVALUATE_FIXTURE,
            str(composition.FIXTURE.relative_to(ROOT)),
            *subject.PATHS, subject.EVALUATION,
            *subject.QUALIFIER_PATHS, *subject.QUALIFIER_DEPENDENCIES,
            *subject.QUALIFIER_DIAGNOSTIC_DEPENDENCIES, *composition.PATHS,
            *subject.JOURNAL_PREPARATION_PATHS,
        }
        for kind, (name, expected) in subject.ORIGINALS.items():
            raw = (ROOT / name).read_bytes()
            if pin(raw) != expected:
                raise AssertionError('unchanged complete Delivery original authority differs')
            cls.values[kind] = json.loads(raw)
            names.add(name)
            names.update(cls.values[kind]['unchanged_files'])
            names.update(cls.values[kind].get('shared_dependency_review', {}))
        names.update((subject.SQL_SOURCE_FIXTURE, subject.SQL_EFFECT_TEST))
        cls.source_raw = {name: (ROOT / name).read_bytes() for name in sorted(names)}
        cls.source_names = tuple(sorted(names))
        for name, expected in OUTER_PINS.items():
            raw = cls.source_raw[name]
            if name == subject.DELIVERY and pin(raw) != expected:
                raw = subject.restore_sql_source(name, raw, cls.source_raw.__getitem__, expected)
            if pin(raw) != expected:
                raise AssertionError('original outer Delivery test file was changed')
        if pin(cls.source_raw[AUTHORITY]) != AUTHORITY_PIN:
            raise AssertionError('fixed Delivery diagnostic source authority changed')
        cls.authority = json.loads(cls.source_raw[AUTHORITY])
        cls.old_sources = {}
        cls.reviewed_sources = {}
        for name in TARGETS:
            record = cls.authority['files'][name]
            current = cls.source_raw[name]
            if name == TARGETS[1] and pin(current) != record['new']:
                update = composition.evaluate_records(
                    cls.source_raw[composition.EVALUATE_FIXTURE])['evaluation_qualifier']
                current = composition.reverse_exact(current, update, record['new'])
            elif pin(current) != record['new']:
                boundary = cls.source_raw[subject.SQLITE_BOUNDARY_FIXTURE]
                current = subject._reverse_sqlite_boundary(
                    name, current, boundary, AUTHORITY, cls.source_raw[AUTHORITY], record['new'])
            cls.reviewed_sources[name] = current
            cls.old_sources[name] = independent_inverse(current, record)
            for kind in OUTERS:
                if name in ALLOWED[kind]:
                    if pin(cls.old_sources[name]) != cls.values[kind]['unchanged_files'][name]:
                        raise AssertionError('old source is not the independently frozen original')
        cls.planned_by_method = planned_ids()
        cls.planned = sum((list(ids) for ids in cls.planned_by_method), [])
        if len(cls.planned) != 126 or len(set(cls.planned)) != 126:
            raise AssertionError('complete new source-control plan differs')
        cls.results = []
        write(cls.output / 'plan.json', {
            'schema': 'hepta.hia.delivery-diagnostic-source-plan.v1',
            'planned_ids': cls.planned, 'method_count': 3,
            'source_before': {name: pin(raw) for name, raw in cls.source_raw.items()},
            'original_file_counts': {'native': 64, 'store': 89},
            'original_outer_test_files_unchanged': OUTER_PINS,
            'original_gates_replaced': False, 'production_source_exceptions': []})

    @classmethod
    def tearDownClass(cls):
        after = {name: (ROOT / name).read_bytes() for name in cls.source_names}
        stable = after == cls.source_raw
        complete = [row['id'] for row in cls.results] == cls.planned
        passed = complete and stable and all(row['status'] == 'PASS_SOURCE_CONTROL' for row in cls.results)
        write(cls.output / 'report.json', {
            'schema': 'hepta.hia.delivery-diagnostic-source-controls.v1',
            'status': 'PASS_SOURCE_CONTROLS' if passed else 'HOLD',
            'planned_ids': cls.planned, 'results': cls.results,
            'complete_ordered_ids': complete,
            'source_before': {name: pin(raw) for name, raw in cls.source_raw.items()},
            'source_after': {name: pin(raw) for name, raw in after.items()},
            'raw_terminal_reread_identical': stable,
            'original_file_counts': {'native': 64, 'store': 89},
            'original_outer_test_files_unchanged': OUTER_PINS,
            'original_gates_replaced': False, 'production_source_exceptions': [],
            'qualifier_main_HIA_VM_Native_compiler_database_executions': 0,
            'whole_stack_qualified': False})
        if not passed:
            raise AssertionError('complete Delivery diagnostic source evidence is HOLD')

    @contextmanager
    def observe(self, identity):
        row = {'id': identity, 'status': 'HOLD', 'started_monotonic_ns': time.monotonic_ns()}
        try:
            self.assertEqual(identity, self.planned[len(type(self).results)])
            yield row
            row['status'] = 'PASS_SOURCE_CONTROL'
        except BaseException as error:
            row['error'] = {'type': type(error).__module__ + '.' + type(error).__qualname__,
                            'text': str(error)}
            raise
        finally:
            row['ended_monotonic_ns'] = time.monotonic_ns()
            type(self).results.append(row)
            write(self.output / ('control-' + str(len(type(self).results)).zfill(3) + '.json'), row)

    @contextmanager
    def view(self, mask=7, *, overrides=None, missing=()):
        # Only exact reconstructed target bytes are supplied for old-version
        # controls. Every other file read is the actual unchanged current file.
        selected = {ROOT / name: (self.source_raw[name] if mask & (1 << bit)
                                  else self.old_sources[name])
                    for bit, name in enumerate(TARGETS)}
        selected.update({ROOT / name: raw for name, raw in (overrides or {}).items()})
        absent = {ROOT / name for name in missing}
        original_read = Path.read_bytes

        def read(path):
            if path in absent:
                raise FileNotFoundError(str(path))
            return selected[path] if path in selected else original_read(path)

        with patch.object(Path, 'read_bytes', read):
            yield

    def admit(self, kind):
        return subject.admit_terminal_sources(deepcopy(self.values[kind]), original_kind=kind)

    def check_outer(self, kind, mask):
        # Invoke the original outer implementation: these are the exact methods
        # that failed on current bytes, not a copied normalization/file loop.
        value = OUTERS[kind].admit_originals()
        proof = value['transport_terminal_successor']['caller_diagnostic_source_admission']
        expected = {name for bit, name in enumerate(TARGETS)
                    if mask & (1 << bit) and name in ALLOWED[kind]}
        self.assertEqual(set(proof['source_adjustments']), expected)
        self.assertEqual(proof['source_adjustment_count'], len(expected))
        self.assertEqual(proof['original_source_count'], 64 if kind == 'native' else 89)
        self.assertEqual(len(value['unchanged_files']), proof['original_source_count'])
        self.assertEqual(value['unchanged_files'], self.values[kind]['unchanged_files'])
        self.assertEqual(proof['complete_old_source_pins'],
                         {name: pin(raw) for name, raw in self.old_sources.items()})
        self.assertEqual(proof['production_source_exceptions'], [])
        self.assertTrue(proof['terminal_reread_identical'])
        self.assertTrue(proof['prior_captures_consumed_without_refresh'])
        propagated = value['transport_terminal_successor']['source_adjustments']
        for name in expected:
            self.assertEqual(propagated[name], proof['source_adjustments'][name])
            reviewed = self.authority['files'][name]['new']
            active = pin(self.source_raw[name])
            if name == TARGETS[1] and active != reviewed:
                update = composition.evaluate_records(
                    self.source_raw[composition.EVALUATE_FIXTURE])['evaluation_qualifier']
                self.assertEqual(active, {'bytes': update['new_bytes'], 'sha256': update['new_sha256']})
                self.assertEqual(propagated[name]['original_evaluation_callers_verified'], 183)
            elif active != reviewed:
                self.assertEqual(active, subject.SQLITE_BOUNDARY_SOURCES[name])
                self.assertEqual(propagated[name]['sqlite_boundary_successor'], {
                    'authority': {'path': subject.SQLITE_BOUNDARY_FIXTURE, **subject.SQLITE_BOUNDARY_FIXTURE_PIN},
                    'restores_reviewed_diagnostic_source_exactly': True,
                })
            else:
                self.assertNotIn('sqlite_boundary_successor', propagated[name])
            self.assertEqual(propagated[name]['current_sha256'], active['sha256'])
            self.assertEqual(propagated[name]['current_bytes'], active['bytes'])
        if kind == 'native':
            self.assertNotIn(TARGETS[2], propagated)
        else:
            consumed = {item['path']: item for item in value['successor_source_adjustments']}
            for name in expected:
                self.assertEqual(consumed[name], proof['source_adjustments'][name])
        return {'original_kind': kind, 'selected_mask': mask,
                'original_file_count': len(value['unchanged_files']),
                'new_adjustment_paths': sorted(expected),
                'admission_sha256': sha256(encoded(proof)).hexdigest(),
                'unchanged_original_outer_guard_consumed_map': True}

    def test_01_actual_and_every_exact_old_current_map_reach_original_outer_guards(self):
        for kind in OUTERS:
            with self.subTest(kind=kind), self.observe('DDS-ACTUAL-' + kind) as row:
                row['actual'] = self.check_outer(kind, 7)
        for kind in OUTERS:
            for mask in range(8):
                identity = 'DDS-MATRIX-' + kind + '-' + str(mask)
                with self.subTest(id=identity), self.observe(identity) as row, self.view(mask):
                    row['outer'] = self.check_outer(kind, mask)
        for kind in OUTERS:
            for mask in (0, 7):
                identity = 'DDS-ABSENT-' + kind + '-' + str(mask)
                with self.subTest(id=identity), self.observe(identity), self.view(mask, missing=(AUTHORITY,)):
                    prior = self.admit(kind)
                    self.assertNotIn('caller_diagnostic_source_admission', prior)
                    self.assertFalse(set(ALLOWED[kind]) & set(prior['source_adjustments']))
                    if mask:
                        with self.assertRaises(AssertionError):
                            OUTERS[kind].admit_originals()
                    else:
                        actual = OUTERS[kind].admit_originals()
                        self.assertEqual(actual['unchanged_files'], self.values[kind]['unchanged_files'])

    def test_02_fixed_sources_missing_authorities_rereads_and_no_cache_reject_drift(self):
        for action in ('TAMPER', 'MISSING', 'REREAD', 'NO-CACHE'):
            for name in CHECK_PATHS:
                identity = 'DDS-' + action + '-' + name
                with self.subTest(id=identity), self.observe(identity):
                    if action == 'NO-CACHE':
                        self.check_outer('store', 7)
                    if action == 'MISSING':
                        with self.view(missing=(name,)):
                            with self.assertRaises((AssertionError, ValueError, FileNotFoundError)):
                                OUTERS['store'].admit_originals()
                    elif action == 'REREAD':
                        target, calls = ROOT / name, []
                        original_read = Path.read_bytes

                        def read_then_change(path):
                            raw = original_read(path)
                            if path == target:
                                calls.append(len(raw))
                                if len(calls) > 1:
                                    return raw + b'\n'
                            return raw

                        with patch.object(Path, 'read_bytes', read_then_change):
                            with self.assertRaises(ValueError):
                                self.admit('store')
                        self.assertGreaterEqual(len(calls), 2)
                    else:
                        with self.view(overrides={name: self.source_raw[name] + b'\n'}):
                            with self.assertRaises(ValueError):
                                self.admit('store')
        for kind in OUTERS:
            with self.observe('DDS-WRONG-ORIGINAL-' + kind):
                changed = deepcopy(self.values[kind])
                changed['unchanged_files'][TARGETS[0]] = self.authority['files'][TARGETS[0]]['new']
                with self.assertRaises(ValueError):
                    subject.admit_terminal_sources(changed, original_kind=kind)
        for label, kind in (('none', None), ('bool', True), ('unlisted', 'unlisted')):
            with self.observe('DDS-BAD-KIND-' + label):
                with self.assertRaises(ValueError):
                    subject.admit_terminal_sources(self.values['store'], original_kind=kind)
        with self.observe('DDS-PRIOR-CAPTURE-GAP'):
            target = subject.QUALIFIER_PATHS[0]
            old = independent_inverse(self.source_raw[target],
                                      json.loads(self.source_raw[subject.QUALIFIER_FIXTURE])['files'][target])
            prior_call, original_read = subject._admit_qualifier_sources, Path.read_bytes
            completed = []

            def prior_then_change(*args):
                result = prior_call(*args)
                completed.append(True)
                return result

            def changed_prior(path):
                if completed and path == ROOT / target:
                    return old
                return original_read(path)

            with patch.object(subject, '_admit_qualifier_sources', prior_then_change), \
                    patch.object(Path, 'read_bytes', changed_prior):
                with self.assertRaisesRegex(ValueError, 'prior source changed after admission'):
                    self.admit('store')
            self.assertEqual(completed, [True])

    def test_03_original_outer_map_checks_and_typed_inverse_negative_controls(self):
        actual_admit = subject.admit_terminal_sources
        original_read = Path.read_bytes
        for kind in OUTERS:
            for name in ALLOWED[kind]:
                for variant in ('missing', 'old-pin', 'foreign-pin', 'source-after-admission'):
                    identity = 'DDS-MAP-' + kind + '-' + name + '-' + variant
                    with self.subTest(id=identity), self.observe(identity):
                        completed = []

                        def altered(*args, **kwargs):
                            result = deepcopy(actual_admit(*args, **kwargs))
                            if variant == 'missing':
                                del result['source_adjustments'][name]
                            elif variant == 'old-pin':
                                old = self.authority['files'][name]['old']
                                result['source_adjustments'][name]['current_bytes'] = old['bytes']
                                result['source_adjustments'][name]['current_sha256'] = old['sha256']
                            elif variant == 'foreign-pin':
                                result['source_adjustments'][name]['current_sha256'] = '0' * 64
                            completed.append(True)
                            return result

                        def changed_after_admission(path):
                            raw = original_read(path)
                            if (variant == 'source-after-admission' and completed
                                    and path == ROOT / name):
                                return raw + b'\n'
                            return raw

                        with patch.object(subject, 'admit_terminal_sources', altered), \
                                patch.object(Path, 'read_bytes', changed_after_admission):
                            with self.assertRaises(AssertionError):
                                OUTERS[kind].admit_originals()
                        self.assertEqual(completed, [True])
        for name in TARGETS:
            for variant in REVERSE_BAD:
                identity = 'DDS-REVERSE-' + name + '-' + variant
                with self.subTest(id=identity), self.observe(identity):
                    record, raw = deepcopy(self.authority['files'][name]), self.reviewed_sources[name]
                    if variant == 'scope':
                        record['scope'] = 'unlisted'
                    elif variant == 'old-pin':
                        record['old']['bytes'] = True
                    elif variant == 'new-pin':
                        record['new']['sha256'] = '0' * 64
                    elif variant == 'tuple-splices':
                        record['splices'] = tuple(record['splices'])
                    elif variant == 'missing-splice':
                        record['splices'].pop()
                    elif variant == 'wrong-id':
                        record['splices'][0]['id'] = 'unlisted'
                    elif variant == 'bool-offset':
                        record['splices'][0]['old_offset'] = True
                    elif variant == 'shifted-offset':
                        record['splices'][0]['new_offset'] += 1
                    elif variant == 'overlap':
                        record['splices'][1] = deepcopy(record['splices'][0])
                    elif variant == 'noncanonical-hex':
                        record['splices'][0]['new_hex'] = ' ' + record['splices'][0]['new_hex']
                    elif variant in ('old-byte', 'new-byte'):
                        key = 'old_hex' if variant == 'old-byte' else 'new_hex'
                        value = record['splices'][0][key]
                        record['splices'][0][key] = ('00' if value[:2] != '00' else '01') + value[2:]
                    elif variant == 'extra-field':
                        record['splices'][0]['unlisted'] = True
                    elif variant == 'raw-bytearray':
                        raw = bytearray(raw)
                    elif variant == 'raw-unlisted-byte':
                        raw = b'\0' + raw[1:]
                    else:
                        raise AssertionError('unplanned typed inverse control')
                    with self.assertRaises(ValueError):
                        subject.reverse_diagnostic_source(raw, record, name)
        with self.observe('DDS-REVERSE-UNLISTED-PATH'):
            with self.assertRaises(ValueError):
                subject.reverse_diagnostic_source(self.source_raw[TARGETS[0]],
                    self.authority['files'][TARGETS[0]], 'tests/unlisted_source.py')


if __name__ == '__main__':
    unittest.main()
