"""Independent exact-source admission controls; no Native/VM/SQL is invoked."""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_native_transport_worker_successor as subject

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_HELPER = 'tests/fixtures/evaluation_worker_terminal_original_r21.py.txt'
ORIGINAL_HELPER_PIN = {
    'bytes': 7551,
    'sha256': '7c6e205b35f0b49571f1fac53b78a9f5ca8f95d77bd7946deacc923c9123947e',
}
ORIGINAL_EVALUATION_PIN = {
    'bytes': 43338,
    'sha256': '22433d0de525210953c8ab23559b1cc7b3bd3575cfaa80fe2618415f03623ede',
}
REVIEWED_EVALUATION_PIN = {
    'bytes': 49105,
    'sha256': '673b1e330b48df5915a4a544188397e33055ac023986cb136e8b067e4574b9d3',
}
TRIPLE_RESULTS = (
    (0, 'EXACT_LEGACY_PAIR'),
    (1, None),
    (2, None),
    (3, 'EXACT_TERMINAL_V2_PAIR'),
    (4, None),
    (5, None),
    (6, None),
    (7, 'EXACT_TERMINAL_V2_PAIR_WITH_EVALUATION_V2'),
)


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def restore_pair(raw, record):
    at = record['offset']
    old, new = bytes.fromhex(record['old_hex']), bytes.fromhex(record['new_hex'])
    if raw[at:at + len(new)] != new:
        raise AssertionError('fixed prior source patch does not match')
    restored = raw[:at] + old + raw[at + len(new):]
    if pin(restored) != record['old']:
        raise AssertionError('fixed prior source does not restore its original')
    return restored


def transform_evaluation(raw, record, *, reverse):
    result = raw
    for item in reversed(record['splices']):
        at = item['new_offset' if reverse else 'old_offset']
        old = bytes.fromhex(item['old_hex'])
        new = bytes.fromhex(item['new_hex'])
        expected, replacement = (new, old) if reverse else (old, new)
        if result[at:at + len(expected)] != expected:
            raise AssertionError('fixed evaluation splice does not match')
        result = result[:at] + replacement + result[at + len(expected):]
    return result


class EvaluationWorkerSuccessorSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        helper_raw = (ROOT / ORIGINAL_HELPER).read_bytes()
        if pin(helper_raw) != ORIGINAL_HELPER_PIN:
            raise AssertionError('immutable original two-source admission helper changed')
        cls.legacy = {'__file__': str(ROOT / 'tests/hia_native_transport_worker_successor.py'),
                      '__name__': 'fixed_original_transport_admission'}
        exec(compile(helper_raw, str(ROOT / ORIGINAL_HELPER), 'exec'), cls.legacy)
        cls.authorities = {
            kind: (ROOT / item[0]).read_bytes()
            for kind, item in subject.ORIGINALS.items()
        }
        for kind, (_, expected) in subject.ORIGINALS.items():
            if pin(cls.authorities[kind]) != expected:
                raise AssertionError('an immutable original inventory changed')
        cls.authority_values = {
            kind: json.loads(raw) for kind, raw in cls.authorities.items()
        }
        cls.pair_raw = (ROOT / subject.FIXTURE).read_bytes()
        if sha256(cls.pair_raw).hexdigest() != subject.FIXTURE_SHA256:
            raise AssertionError('fixed prior pair authority changed')
        cls.pair = json.loads(cls.pair_raw)
        cls.evaluation_raw = (ROOT / subject.EVALUATION_FIXTURE).read_bytes()
        if sha256(cls.evaluation_raw).hexdigest() != subject.EVALUATION_FIXTURE_SHA256:
            raise AssertionError('fixed evaluation authority changed')
        cls.evaluation = json.loads(cls.evaluation_raw)
        cls.new_sources = {}
        cls.old_sources = {}
        for name in subject.PATHS:
            current = (ROOT / name).read_bytes()
            record = cls.pair['files'][name]
            if pin(current) != record['new']:
                raise AssertionError('control needs the exact reviewed current pair')
            cls.new_sources[name] = current
            cls.old_sources[name] = restore_pair(current, record)
        raw = (ROOT / subject.EVALUATION).read_bytes()
        record = cls.evaluation['record']
        if pin(raw) == REVIEWED_EVALUATION_PIN:
            new = raw
            old = transform_evaluation(raw, record, reverse=True)
        elif pin(raw) == ORIGINAL_EVALUATION_PIN:
            old = raw
            new = transform_evaluation(raw, record, reverse=False)
        else:
            raise AssertionError('control evaluation source is not either fixed version')
        if pin(old) != ORIGINAL_EVALUATION_PIN or pin(new) != REVIEWED_EVALUATION_PIN:
            raise AssertionError('control cannot reconstruct both fixed evaluation sources')
        cls.old_sources[subject.EVALUATION] = old
        cls.new_sources[subject.EVALUATION] = new

    @contextmanager
    def tree(self, mask):
        with tempfile.TemporaryDirectory(prefix='evaluation-terminal-admission-') as directory:
            root = Path(directory)
            files = {subject.ORIGINALS[kind][0]: raw
                     for kind, raw in self.authorities.items()}
            files[subject.FIXTURE] = self.pair_raw
            files[subject.EVALUATION_FIXTURE] = self.evaluation_raw
            names = (*subject.PATHS, subject.EVALUATION)
            for bit, name in enumerate(names):
                files[name] = (self.new_sources if mask & (1 << bit)
                               else self.old_sources)[name]
            for name, raw in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            with patch.object(subject, 'ROOT', root):
                self.legacy['ROOT'] = root
                yield root

    def admit(self, kind):
        return subject.admit_terminal_sources(
            deepcopy(self.authority_values[kind]), original_kind=kind)

    def test_01_original_pair_behavior_and_all_eight_combinations(self):
        for kind in ('native', 'store'):
            for mask in range(4):
                with self.subTest(kind=kind, previous_pair=mask), self.tree(mask):
                    try:
                        expected = self.legacy['admit_terminal_sources'](
                            deepcopy(self.authority_values[kind]), original_kind=kind)
                    except ValueError as original_error:
                        with self.assertRaises(ValueError) as actual:
                            self.admit(kind)
                        self.assertEqual(actual.exception.args, original_error.args)
                    else:
                        self.assertEqual(self.admit(kind), expected)
            for mask, state in TRIPLE_RESULTS:
                with self.subTest(kind=kind, complete_triplet=mask), self.tree(mask):
                    if state is None:
                        with self.assertRaises(ValueError):
                            self.admit(kind)
                        continue
                    result = self.admit(kind)
                    self.assertEqual(result['state'], state)
                    self.assertEqual(result['production_composition_source_count'], 13)
                    if mask == 7:
                        self.assertEqual(result['separate_test_successor_count'], 3)
                        self.assertEqual(set(result['source_adjustments']),
                                         {subject.TRANSPORT, subject.EVALUATION})
                        record = result['source_adjustments'][subject.EVALUATION]
                        self.assertEqual(record['original_bytes'], ORIGINAL_EVALUATION_PIN['bytes'])
                        self.assertEqual(record['original_sha256'], ORIGINAL_EVALUATION_PIN['sha256'])
                        self.assertEqual(record['current_bytes'], REVIEWED_EVALUATION_PIN['bytes'])
                        self.assertEqual(record['current_sha256'], REVIEWED_EVALUATION_PIN['sha256'])
                        self.assertEqual(record['reversible_patch_fixture_sha256'],
                                         subject.EVALUATION_FIXTURE_SHA256)
                        self.assertNotIn('all_original_test_methods_unchanged', record)
                    else:
                        self.assertNotIn(subject.EVALUATION, result['source_adjustments'])

    def test_02_fixed_authorities_sources_and_exact_splices_reject_tampering(self):
        names = (*subject.PATHS, subject.EVALUATION, subject.FIXTURE,
                 subject.EVALUATION_FIXTURE,
                 *(item[0] for item in subject.ORIGINALS.values()))
        for kind in ('native', 'store'):
            for name in names:
                with self.subTest(kind=kind, changed_file=name), self.tree(7) as root:
                    path = root / name
                    path.write_bytes(path.read_bytes() + b'\n')
                    with self.assertRaises(ValueError):
                        self.admit(kind)
            with self.tree(7):
                for bad_kind in (None, True, 'unlisted'):
                    with self.subTest(kind=kind, original_kind=bad_kind):
                        with self.assertRaises(ValueError):
                            subject.admit_terminal_sources(self.authority_values[kind],
                                                           original_kind=bad_kind)
                changed = deepcopy(self.authority_values[kind])
                changed['unlisted'] = True
                with self.assertRaises(ValueError):
                    subject.admit_terminal_sources(changed, original_kind=kind)
        raw = self.new_sources[subject.EVALUATION]
        good = self.evaluation['record']
        self.assertEqual(subject.reverse_evaluation(raw, deepcopy(good)),
                         self.old_sources[subject.EVALUATION])
        variants = []
        def variant(label, update):
            value = deepcopy(good)
            update(value)
            variants.append((label, value))
        variant('wrong-definition', lambda x: x.update(definition='other'))
        variant('extra-record-field', lambda x: x.update(extra=True))
        variant('missing-splice', lambda x: x['splices'].pop())
        variant('tuple-splices', lambda x: x.update(splices=tuple(x['splices'])))
        variant('bool-offset', lambda x: x['splices'][0].update(old_offset=True))
        variant('negative-offset', lambda x: x['splices'][0].update(new_offset=-1))
        variant('changed-offset', lambda x: x['splices'][0].update(new_offset=x['splices'][0]['new_offset']+1))
        variant('changed-old-bytes', lambda x: x['splices'][0].update(old_hex='00'+x['splices'][0]['old_hex'][2:]))
        variant('changed-new-bytes', lambda x: x['splices'][0].update(new_hex='00'+x['splices'][0]['new_hex'][2:]))
        variant('noncanonical-hex', lambda x: x['splices'][0].update(new_hex=' '+x['splices'][0]['new_hex']))
        variant('overlap', lambda x: x['splices'].__setitem__(1, deepcopy(x['splices'][0])))
        variant('wrong-whole-new-pin', lambda x: x['new'].update(sha256='0'*64))
        variant('wrong-whole-old-pin', lambda x: x['old'].update(bytes=True))
        for label, record in variants:
            with self.subTest(splice=label):
                with self.assertRaises(ValueError):
                    subject.reverse_evaluation(raw, record)
        for label, changed in (('non-bytes', bytearray(raw)),
                               ('unlisted-source-byte', b'X'+raw[1:])):
            with self.subTest(raw=label):
                with self.assertRaises(ValueError):
                    subject.reverse_evaluation(changed, deepcopy(good))

    def test_03_actual_post_capture_file_drift_and_no_admission_cache(self):
        original_read = Path.read_bytes
        for kind in ('native', 'store'):
            for mask in (0, 3, 7):
                names = [*(item[0] for item in subject.ORIGINALS.values()),
                         *subject.PATHS, subject.EVALUATION]
                if mask:
                    names.append(subject.FIXTURE)
                if mask == 7:
                    names.append(subject.EVALUATION_FIXTURE)
                for name in names:
                    with self.subTest(kind=kind, mask=mask, changed_after_capture=name), self.tree(mask) as root:
                        target = root / name
                        fired = []
                        def read_then_change(path):
                            raw = original_read(path)
                            if path == target and not fired:
                                path.write_bytes(raw + b'\n')
                                fired.append(True)
                            return raw
                        with patch.object(Path, 'read_bytes', read_then_change):
                            with self.assertRaises(ValueError):
                                self.admit(kind)
                        self.assertEqual(fired, [True])
                with self.tree(mask) as root:
                    self.admit(kind)
                    target = root / subject.EVALUATION
                    target.write_bytes(target.read_bytes() + b'\n')
                    with self.assertRaises(ValueError):
                        self.admit(kind)


if __name__ == '__main__':
    unittest.main()
