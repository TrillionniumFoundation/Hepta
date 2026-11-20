"""Exact v6 Store composition; all original Delivery controls stay independent."""
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import itertools
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import hia_store_delivery_successor as subject
from tests import test_hia_store_native_delivery as outer

ROOT = Path(__file__).resolve().parents[1]
OUTER_PIN = {'bytes': 16697, 'sha256': 'f1d6605a2dfaba8b949f81e213d19a187779fe251258e73fa58b26fe6fecfb1c'}


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def independent_inverse(raw, record):
    restored = raw
    for item in reversed(record['splices']):
        at = item['new_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if restored[at:at + len(after)] != after:
            raise AssertionError('independent carrier inverse fragment differs')
        restored = restored[:at] + before + restored[at + len(after):]
    if pin(restored) != record['old']:
        raise AssertionError('independent carrier inverse complete file differs')
    replay = restored
    for item in reversed(record['splices']):
        at = item['old_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if replay[at:at + len(before)] != before:
            raise AssertionError('independent carrier forward fragment differs')
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != raw:
        raise AssertionError('independent carrier forward whole file differs')
    return restored


class StoreDeliveryCarrierSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = {*subject.PATHS, subject.CARRIER_CONTEXT, subject.CARRIER_FIXTURE,
                 str(subject.FIXTURE.relative_to(ROOT)), str(subject.ORIGINAL.relative_to(ROOT)),
                 'tests/hia_store_delivery_successor.py',
                 'tests/test_hia_store_native_delivery.py',
                 'tests/test_hia_store_delivery_carrier_source.py'}
        cls.captured = {name: (ROOT / name).read_bytes() for name in sorted(names)}
        if pin(cls.captured['tests/test_hia_store_native_delivery.py']) != OUTER_PIN:
            raise AssertionError('complete original Store outer changed')
        cls.authority = subject.carrier_authority(cls.captured[subject.CARRIER_FIXTURE])
        cls.original = json.loads(cls.captured[str(subject.ORIGINAL.relative_to(ROOT))])
        cls.prior = json.loads(cls.captured[str(subject.FIXTURE.relative_to(ROOT))])
        cls.old = {name: independent_inverse(cls.captured[name], record)
                   for name, record in cls.authority['source_relations'].items()}
        cls.prior_sources = {name: cls.old.get(name, cls.captured[name]) for name in subject.PATHS}
        cls.original_sources = {}
        originals = dict(cls.original['unchanged_files'])
        originals.update(cls.original['shared_dependency_review'])
        originals[subject.ADAPTER_PATH] = subject.ADAPTER_ORIGINAL
        originals.update(subject.COMPANION_ORIGINALS)
        for name in subject.PATHS:
            cls.original_sources[name] = subject.reverse_exact(
                cls.prior_sources[name], cls.prior['files'][name], originals[name])

    @classmethod
    def tearDownClass(cls):
        if cls.captured != {name: (ROOT / name).read_bytes() for name in cls.captured}:
            raise AssertionError('carrier source control inputs changed')

    @contextmanager
    def view(self, overrides=None, missing=(), later=None):
        values = {ROOT / name: raw for name, raw in (overrides or {}).items()}
        absent = {ROOT / name for name in missing}
        reads, real = {}, Path.read_bytes
        def read(path):
            reads[path] = reads.get(path, 0) + 1
            if path in absent:
                raise FileNotFoundError(str(path))
            if later is not None and path == ROOT / later[0] and reads[path] > 1:
                return later[1]
            return values[path] if path in values else real(path)
        with patch.object(Path, 'read_bytes', read):
            yield reads

    def admit(self):
        return subject.admit_composition(deepcopy(self.original))

    def test_complete_original_prior_and_current_domains_keep_thirteen_and_twenty_one(self):
        for profile, sources in (('original', self.original_sources), ('prior', self.prior_sources)):
            values = {**sources, subject.CARRIER_CONTEXT: self.old[subject.CARRIER_CONTEXT]}
            with self.subTest(profile=profile), self.view(values, (subject.CARRIER_FIXTURE,)):
                admitted = self.admit()
                self.assertNotIn('carrier_source_admission', admitted)
                self.assertEqual(len(admitted['adapter_definition_review']), 21)
                if profile == 'original':
                    self.assertEqual(admitted['source_adjustments'], {})
                    self.assertEqual(admitted['shared_adjustments'], {})
                else:
                    self.assertEqual(len(admitted['source_adjustments']), 4)
                    self.assertEqual(len(admitted['shared_adjustments']), 7)
        admitted = self.admit()
        proof = admitted['carrier_source_admission']
        self.assertEqual(proof['composition_source_count'], 13)
        self.assertEqual(len(subject.PATHS), 13)
        self.assertNotIn(subject.CARRIER_CONTEXT, subject.PATHS)
        self.assertEqual(proof['complete_prior_composition'], self.authority['prior_composition'])
        self.assertEqual(proof['complete_current_composition'], self.authority['current_composition'])
        self.assertEqual(set(admitted['source_adjustments']), set(subject.SOURCE_PATHS))
        self.assertEqual(set(admitted['shared_adjustments']), set(subject.SHARED_PATHS))
        self.assertEqual(set(admitted['adapter_definition_adjustments']),
                         {'_context_special', 'StoreArtifactProfileFrame._global'})
        self.assertEqual(admitted['adapter_definition_review'],
                         outer.definition_pins(self.captured[subject.ADAPTER_PATH]))
        self.assertEqual(len(admitted['adapter_definition_review']), 21)
        self.assertTrue(proof['terminal_reread_identical'])
        self.assertFalse(proof['prior_qualification_transferred'])
        self.assertEqual(proof['captured_files'], {
            name: pin(self.captured[name])
            for name in (*subject.PATHS, subject.CARRIER_CONTEXT, subject.CARRIER_FIXTURE)})
        actual = outer.admit_originals()
        self.assertEqual(actual['unchanged_files'], self.original['unchanged_files'])
        self.assertEqual(len(actual['unchanged_files']), 89)
        self.assertEqual(actual['unchanged_adapter_definitions'], admitted['adapter_definition_review'])
        for name, expected in actual['shared_dependency_review'].items():
            self.assertEqual(pin((ROOT / name).read_bytes()), expected, name)

    def test_each_real_capture_is_fresh_and_terminal_changes_are_rejected(self):
        names = (*subject.PATHS, subject.CARRIER_CONTEXT, subject.CARRIER_FIXTURE,
                 str(subject.FIXTURE.relative_to(ROOT)), str(subject.ORIGINAL.relative_to(ROOT)))
        self.admit()
        for name in names:
            raw = self.captured[name]
            for action in ('missing', 'changed', 'after-read'):
                with self.subTest(name=name, action=action):
                    arguments = {'missing': (name,)} if action == 'missing' else (
                        {'overrides': {name: raw + b' '}} if action == 'changed'
                        else {'later': (name, raw + b' ')})
                    with self.view(**arguments), self.assertRaises((ValueError, FileNotFoundError)):
                        self.admit()
            self.admit()
        for name, old in self.old.items():
            with self.subTest(late_legal_predecessor=name), self.view(later=(name, old)), \
                    self.assertRaises(ValueError):
                self.admit()
        altered = deepcopy(self.original)
        altered['runtime_execution_before_freeze'] = True
        with self.assertRaises(ValueError):
            subject.admit_composition(altered)

    def test_partial_compositions_and_typed_inverse_changes_do_not_borrow_authority(self):
        changed = (*subject.CARRIER_PATHS, subject.CARRIER_CONTEXT)
        for flags in itertools.product((False, True), repeat=4):
            if all(flags) or not any(flags):
                continue
            values = {name: self.captured[name] if current else self.old[name]
                      for name, current in zip(changed, flags)}
            with self.subTest(partial=flags), self.view(values):
                # The unchanged outer also checks Context, which is deliberately
                # not a fourteenth production composition bit.
                with self.assertRaises((ValueError, AssertionError)):
                    result = outer.admit_originals()
                    for name, expected in result['shared_dependency_review'].items():
                        self.assertEqual(pin((ROOT / name).read_bytes()), expected, name)
        for name, record in self.authority['source_relations'].items():
            raw = self.captured[name]
            self.assertEqual(subject.restore_carrier_source(raw, name, record), self.old[name])
            for field in ('old_offset', 'new_offset'):
                for value in (True, -1, 0.0, '0'):
                    bad = deepcopy(record);bad['splices'][0][field] = value
                    with self.subTest(path=name, field=field, value=value), self.assertRaises(ValueError):
                        subject.restore_carrier_source(raw, name, bad)
            for field in ('old', 'new'):
                bad = deepcopy(record);bad[field]['sha256'] = '0' * 64
                with self.subTest(path=name, field=field), self.assertRaises(ValueError):
                    subject.restore_carrier_source(raw, name, bad)
            for badraw, badpath in ((raw + b' ', name), (bytearray(raw), name), (raw, 'other.py')):
                with self.subTest(path=name, badpath=badpath), self.assertRaises(ValueError):
                    subject.restore_carrier_source(badraw, badpath, record)
        changed_authority = deepcopy(self.authority)
        changed_authority['composition_source_count'] = 14
        with self.assertRaises(ValueError):
            subject.carrier_authority(json.dumps(changed_authority).encode())


if __name__ == '__main__':
    unittest.main()
