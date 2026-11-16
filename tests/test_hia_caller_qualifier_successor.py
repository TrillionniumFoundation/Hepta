"""Complete pure-source controls for one fixed qualifier-successor authority.

No qualifier main, product, compiler, VM or Native call is executed here.
The complete original Delivery and Evaluation-worker Source gates remain
separate requirements; no test body, old fixture or budget is replaced.
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

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = 'HEPTA_HIA_CALLER_QUALIFIER_SOURCE_EVIDENCE'
AUTHORITY = 'tests/fixtures/caller_qualifier_successor_provenance_v1.json'
AUTHORITY_PIN = {"bytes":29822,"sha256":"36ad92a954cb3244bc31a6e95f1bcd8cbaf7b215856e6624b54fee3e66f686f4"}
QUALIFIERS = ('tools/qualify_hia_native_build_admission_callers.py',
              'tools/qualify_hia_emission_callers.py',
              'tools/qualify_hia_store_artifact_profile_callers.py')
ORIGINALS = {'native': 'tests/fixtures/native_delivery_original_9c46166.json',
             'store': 'tests/fixtures/store_native_delivery_original_c019.json'}
PRIOR_NAMES = ('tests/test_hia_native_transport_failures.py',
               'tests/test_hia_native_delivery.py', 'tests/test_hia_evaluation_native.py')
PAIR = 'tests/fixtures/native_transport_worker_terminal_v2_provenance.json'
EVALUATION = 'tests/fixtures/evaluation_worker_terminal_v2_provenance.json'
DEPENDENCIES = ('tests/hia_caller_terminal_admission.py',
                'tests/fixtures/hia_native_build_admission_callers_aac7550.json',
                'tests/fixtures/hia_emission_original_73f1634/original-freeze.json',
                'tests/fixtures/hia_store_artifact_profile_callers_73f1634.json')
CAPTURE_PATHS = (AUTHORITY, *ORIGINALS.values(), *DEPENDENCIES, PAIR, EVALUATION,
                 *PRIOR_NAMES, *QUALIFIERS)
SOURCE_INPUTS = (*CAPTURE_PATHS, 'tests/hia_native_transport_worker_successor.py',
                 'tests/test_hia_caller_qualifier_successor.py',
                 'tests/test_hia_evaluation_worker_successor.py',
                 'tests/test_hia_store_native_delivery.py',
                 'tests/__init__.py')
VALID_PRIOR = (0, 3, 7)
REVERSE_BAD = ('scope', 'old-pin', 'new-pin', 'tuple-splices', 'missing-splice',
               'wrong-id', 'bool-offset', 'shifted-offset', 'overlap',
               'noncanonical-hex', 'old-byte', 'new-byte', 'extra-field',
               'raw-bytearray', 'raw-unlisted-byte')


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


def write(path, value):
    with path.open('xb') as stream:
        stream.write(canonical(value))


def planned_ids():
    first = ['CQ-MATRIX-' + kind + '-' + str(prior) + '-' + str(mask)
             for kind in ('native', 'store') for prior in VALID_PRIOR for mask in range(8)]
    first += ['CQ-ABSENT-' + kind + '-' + str(prior)
              for kind in ('native', 'store') for prior in VALID_PRIOR]
    second = ['CQ-TAMPER-' + name for name in CAPTURE_PATHS]
    second += ['CQ-MISSING-' + name for name in CAPTURE_PATHS if name != AUTHORITY]
    second += ['CQ-REREAD-' + name for name in CAPTURE_PATHS]
    second += ['CQ-NO-CACHE-' + name for name in QUALIFIERS]
    second += ['CQ-WRONG-ORIGINAL-' + kind for kind in ('native', 'store')]
    second += ['CQ-BAD-KIND-' + name for name in ('none', 'bool', 'unlisted')]
    second += ['CQ-REVERSE-' + name + '-' + variant
               for name in QUALIFIERS for variant in REVERSE_BAD]
    second += ['CQ-REVERSE-UNLISTED-PATH']
    return first, second


def independent_inverse(raw, record):
    result = raw
    for item in reversed(record['splices']):
        at = item['new_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if result[at:at + len(after)] != after:
            raise AssertionError('independent full old-source inverse splice differs')
        result = result[:at] + before + result[at + len(after):]
    if pin(result) != record['old']:
        raise AssertionError('independent inverse does not recover the full original fixture pin')
    return result


class CallerQualifierSuccessorSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = os.environ.get(EVIDENCE)
        if selected == '':
            raise ValueError('empty explicit caller qualifier evidence path')
        parent = None if selected is None else Path(selected).absolute()
        if parent is not None:
            parent.mkdir(parents=True, exist_ok=True)
        cls.output = Path(tempfile.mkdtemp(prefix='caller-qualifier-source-', dir=parent))
        cls.source_raw = {name: (ROOT / name).read_bytes() for name in SOURCE_INPUTS}
        cls.corpus = {name: cls.source_raw[name] for name in CAPTURE_PATHS}
        if pin(cls.corpus[AUTHORITY]) != AUTHORITY_PIN:
            raise AssertionError('new fixed qualifier authority changed')
        cls.authority = json.loads(cls.corpus[AUTHORITY])
        cls.values = {kind: json.loads(cls.corpus[name]) for kind, name in ORIGINALS.items()}
        cls.old_qualifiers = {}
        for name in QUALIFIERS:
            record = cls.authority['files'][name]
            if pin(cls.corpus[name]) != record['new']:
                raise AssertionError('control needs the exact reviewed current qualifier sources')
            cls.old_qualifiers[name] = independent_inverse(cls.corpus[name], record)
            for kind in ('native', 'store'):
                if name in cls.values[kind]['unchanged_files']:
                    if pin(cls.old_qualifiers[name]) != cls.values[kind]['unchanged_files'][name]:
                        raise AssertionError('old qualifier oracle is not a fixed original inventory')
        cls.old_prior = {}
        pair = json.loads(cls.corpus[PAIR])
        for name in PRIOR_NAMES[:2]:
            record = pair['files'][name]
            raw = cls.corpus[name]
            if pin(raw) != record['new']:
                raise AssertionError('control needs the unchanged complete current Transport pair')
            at = record['offset']
            before, after = bytes.fromhex(record['old_hex']), bytes.fromhex(record['new_hex'])
            if raw[at:at + len(after)] != after:
                raise AssertionError('independent prior pair inverse differs')
            old = raw[:at] + before + raw[at + len(after):]
            if pin(old) != record['old']:
                raise AssertionError('independent prior pair original pin differs')
            cls.old_prior[name] = old
        evaluation = json.loads(cls.corpus[EVALUATION])['record']
        if pin(cls.corpus[PRIOR_NAMES[2]]) != evaluation['new']:
            raise AssertionError('control needs the exact current Evaluation successor')
        cls.old_prior[PRIOR_NAMES[2]] = independent_inverse(cls.corpus[PRIOR_NAMES[2]], evaluation)
        cls.first_ids, cls.second_ids = planned_ids()
        cls.planned = cls.first_ids + cls.second_ids
        if len(cls.planned) != 152 or len(set(cls.planned)) != 152:
            raise AssertionError('complete new source control inventory differs')
        cls.results = []
        write(cls.output / 'plan.json', {
            'schema': 'hepta.hia.caller-qualifier-source-plan.v1', 'planned_ids': cls.planned,
            'method_count': 2, 'source_before': {name: pin(raw) for name, raw in cls.source_raw.items()},
            'original_gates_replaced': False, 'production_source_exceptions': []})

    @classmethod
    def tearDownClass(cls):
        after = {name: (ROOT / name).read_bytes() for name in SOURCE_INPUTS}
        stable = after == cls.source_raw
        complete = [row['id'] for row in cls.results] == cls.planned
        passed = complete and stable and all(row['status'] == 'PASS_SOURCE_CONTROL' for row in cls.results)
        write(cls.output / 'report.json', {
            'schema': 'hepta.hia.caller-qualifier-source-controls.v1',
            'status': 'PASS_SOURCE_CONTROLS' if passed else 'HOLD',
            'planned_ids': cls.planned, 'results': cls.results, 'complete_ordered_ids': complete,
            'source_before': {name: pin(raw) for name, raw in cls.source_raw.items()},
            'source_after': {name: pin(raw) for name, raw in after.items()},
            'raw_terminal_reread_identical': stable, 'original_gates_replaced': False,
            'qualifier_main_product_VM_Native_compiler_executions': 0,
            'production_composition_source_count': 13, 'production_source_exceptions': [],
            'whole_stack_qualified': False})
        if not passed:
            raise AssertionError('complete qualifier Source2 evidence is HOLD')

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
    def tree(self, mask=7, *, prior=7, authority=True):
        with tempfile.TemporaryDirectory(prefix='caller-qualifier-admission-') as directory:
            root = Path(directory)
            files = dict(self.corpus)
            for bit, name in enumerate(QUALIFIERS):
                files[name] = self.corpus[name] if mask & (1 << bit) else self.old_qualifiers[name]
            for bit, name in enumerate(PRIOR_NAMES):
                files[name] = self.corpus[name] if prior & (1 << bit) else self.old_prior[name]
            if not authority:
                del files[AUTHORITY]
            for name, raw in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('xb') as stream:
                    stream.write(raw)
            with patch.object(subject, 'ROOT', root):
                yield root

    def admit(self, kind):
        return subject.admit_terminal_sources(deepcopy(self.values[kind]), original_kind=kind)

    def test_01_complete_qualifier_matrix_and_absent_authority_preserve_old_boundary(self):
        for kind in ('native', 'store'):
            for prior in VALID_PRIOR:
                for mask in range(8):
                    identity = 'CQ-MATRIX-' + kind + '-' + str(prior) + '-' + str(mask)
                    with self.subTest(id=identity), self.observe(identity) as row, self.tree(mask, prior=prior):
                        if mask not in (0, 7):
                            with self.assertRaises(ValueError) as refused:
                                self.admit(kind)
                            row['refusal'] = {'type': type(refused.exception).__name__,
                                              'args': list(refused.exception.args)}
                            continue
                        base = subject._admit_terminal_sources_before_qualifiers(
                            deepcopy(self.values[kind]), original_kind=kind)
                        result = self.admit(kind)
                        proof = result['caller_qualifier_source_admission']
                        expected = set(QUALIFIERS[:2] if kind == 'native' else QUALIFIERS) if mask else set()
                        self.assertEqual(set(proof['source_adjustments']), expected)
                        self.assertEqual(set(result['source_adjustments']),
                                         set(base['source_adjustments']) | expected)
                        self.assertEqual({key: result[key] for key in base if key != 'source_adjustments'},
                                         {key: base[key] for key in base if key != 'source_adjustments'})
                        self.assertEqual(proof['state'], 'EXACT_REVIEWED_QUALIFIER_TRIPLE' if mask
                                         else 'EXACT_ORIGINAL_QUALIFIER_TRIPLE')
                        self.assertEqual(proof['source_adjustment_count'], 2 if kind == 'native' and mask
                                         else 3 if mask else 0)
                        self.assertEqual(set(proof['actual_captured_files']), set(CAPTURE_PATHS))
                        self.assertEqual(proof['complete_old_source_pins'],
                                         {name: pin(raw) for name, raw in self.old_qualifiers.items()})
                        self.assertTrue(proof['terminal_reread_identical'])
                        self.assertEqual(proof['production_source_exceptions'], [])
                        self.assertEqual(proof['production_composition_source_count'], 13)
                        row['admission'] = result
        for kind in ('native', 'store'):
            for prior in VALID_PRIOR:
                identity = 'CQ-ABSENT-' + kind + '-' + str(prior)
                with self.subTest(id=identity), self.observe(identity) as row, self.tree(prior=prior, authority=False) as root:
                    expected = subject._admit_terminal_sources_before_qualifiers(
                        deepcopy(self.values[kind]), original_kind=kind)
                    actual = self.admit(kind)
                    self.assertEqual(actual, expected)
                    self.assertNotIn('caller_qualifier_source_admission', actual)
                    for name in (QUALIFIERS[:2] if kind == 'native' else QUALIFIERS):
                        self.assertNotIn(name, actual['source_adjustments'])
                        self.assertNotEqual(pin((root / name).read_bytes()),
                                            self.values[kind]['unchanged_files'][name])
                    row['result'] = actual
                    row['new_qualifier_exception_granted'] = False

    def test_02_whole_source_authorities_exact_splices_and_actual_terminal_rereads(self):
        for name in CAPTURE_PATHS:
            identity = 'CQ-TAMPER-' + name
            with self.subTest(id=identity), self.observe(identity), self.tree() as root:
                path = root / name
                path.write_bytes(path.read_bytes() + b'\n')
                with self.assertRaises(ValueError):
                    self.admit('store')
        for name in CAPTURE_PATHS:
            if name == AUTHORITY:
                continue
            identity = 'CQ-MISSING-' + name
            with self.subTest(id=identity), self.observe(identity), self.tree() as root:
                (root / name).unlink()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.admit('store')
        original_read = Path.read_bytes
        for name in CAPTURE_PATHS:
            identity = 'CQ-REREAD-' + name
            with self.subTest(id=identity), self.observe(identity) as row, self.tree() as root:
                target = root / name
                fired = []
                def read_then_change(path):
                    raw = original_read(path)
                    if path == target and not fired:
                        path.write_bytes(raw + b'\n')
                        fired.append(str(path))
                    return raw
                with patch.object(Path, 'read_bytes', read_then_change):
                    with self.assertRaises(ValueError):
                        self.admit('store')
                self.assertEqual(fired, [str(target)])
                row['actual_read_then_mutated'] = fired
        for name in QUALIFIERS:
            identity = 'CQ-NO-CACHE-' + name
            with self.subTest(id=identity), self.observe(identity), self.tree() as root:
                self.admit('store')
                path = root / name
                path.write_bytes(path.read_bytes() + b'\n')
                with self.assertRaises(ValueError):
                    self.admit('store')
        for kind in ('native', 'store'):
            identity = 'CQ-WRONG-ORIGINAL-' + kind
            with self.subTest(id=identity), self.observe(identity), self.tree():
                changed = deepcopy(self.values[kind])
                changed['unlisted'] = True
                with self.assertRaises(ValueError):
                    subject.admit_terminal_sources(changed, original_kind=kind)
        for label, kind in (('none', None), ('bool', True), ('unlisted', 'unlisted')):
            identity = 'CQ-BAD-KIND-' + label
            with self.subTest(id=identity), self.observe(identity), self.tree():
                with self.assertRaises(ValueError):
                    subject.admit_terminal_sources(self.values['store'], original_kind=kind)
        for name in QUALIFIERS:
            for variant in REVERSE_BAD:
                identity = 'CQ-REVERSE-' + name + '-' + variant
                with self.subTest(id=identity), self.observe(identity):
                    record = deepcopy(self.authority['files'][name])
                    raw = self.corpus[name]
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
                    elif variant == 'old-byte':
                        value = record['splices'][0]['old_hex']
                        record['splices'][0]['old_hex'] = ('00' if value[:2] != '00' else '01') + value[2:]
                    elif variant == 'new-byte':
                        value = record['splices'][0]['new_hex']
                        record['splices'][0]['new_hex'] = ('00' if value[:2] != '00' else '01') + value[2:]
                    elif variant == 'extra-field':
                        record['splices'][0]['unlisted'] = True
                    elif variant == 'raw-bytearray':
                        raw = bytearray(raw)
                    elif variant == 'raw-unlisted-byte':
                        raw = b'\0' + raw[1:]
                    else:
                        raise AssertionError('unplanned reverse control')
                    with self.assertRaises(ValueError):
                        subject.reverse_qualifier(raw, record, name)
        identity = 'CQ-REVERSE-UNLISTED-PATH'
        with self.subTest(id=identity), self.observe(identity):
            name = QUALIFIERS[0]
            with self.assertRaises(ValueError):
                subject.reverse_qualifier(self.corpus[name], self.authority['files'][name],
                                          'tools/unlisted-qualifier.py')


if __name__ == '__main__':
    unittest.main()
