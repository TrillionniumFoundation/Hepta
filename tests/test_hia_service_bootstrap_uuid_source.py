"""Versioned UUID source preparation; the five original Bootstrap definitions remain fixed."""
import ast
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import hia_store_delivery_successor as relation

ROOT = Path(__file__).resolve().parents[1]
SERVICE = 'hepta/hia_agent_service.py'
HELPER = 'tests/hia_store_delivery_successor.py'
AUTHORITY = 'tests/fixtures/store_delivery_carrier_source_v1.json'
IDENTITY = 'tests/fixtures/hia_service_bootstrap_original_r12/source-identity.json'
PINS = {'hepta/hia_agent_service.py': {'bytes': 162342, 'sha256': '13ec7ac895c90bee39c8b1cab7dd70ba8630aaf833c1591e8ad8db558cf6dac8'}, 'tests/hia_store_delivery_successor.py': {'bytes': 20696, 'sha256': '4360dfeef6da522053f2f13fd3be8570ca766ce058e4630d62dc9e6914ff05bc'}, 'tests/fixtures/store_delivery_carrier_source_v1.json': {'bytes': 11408, 'sha256': '8e3a784605cf9b78f7e1bbaba155f1cdcdfac7ad692edfc8234a93344f29513c'}, 'tests/fixtures/hia_service_bootstrap_original_r12/source-identity.json': {'bytes': 6470, 'sha256': '15d199b528392f3837ca05cb592fd1d5c13ee7bdea2fbdf8b8b0ebbd0f19f091'}, 'tests/fixtures/hia_service_bootstrap_original_r12/__init__.py.txt': {'bytes': 1729, 'sha256': '03570fc017e76dd35f4bbd12b45672a21b735a7cb52933c715ce33f9271f3f0f'}, 'tests/fixtures/hia_service_bootstrap_original_r12/close.py.txt': {'bytes': 180, 'sha256': '60f1d4eaf32534640d3f4a17db901705b48ae6fc6982d3b4ea6cda19b4065ef6'}, 'tests/fixtures/hia_service_bootstrap_original_r12/_profiles.py.txt': {'bytes': 9744, 'sha256': '0faed3cf3fdb0642867c4b4430ffa965b9dba1f560b3ae65f1f1e89fa65c8b7d'}, 'tests/fixtures/hia_service_bootstrap_original_r12/_profile.py.txt': {'bytes': 101, 'sha256': '0adeac9e1bf6164386db92d0a24fef3a8e083b39e027fe3063926ba1e14aeb3c'}, 'tests/fixtures/hia_service_bootstrap_original_r12/_program.py.txt': {'bytes': 116, 'sha256': '7de11c0755047bab19cb7625741bfb2aa6c79dc64d7fd99b4b57fbd2c340402a'}}
OLD_SERVICE = {'bytes': 161343, 'sha256': 'f73d14d6271044ef7d2232d926d18741d05ed199527337219ec3171f95adb328'}
NAMES = ('__init__', 'close', '_profiles', '_profile', '_program')
CURRENT_DEFINITIONS = {'__init__': {'bytes': 1756, 'sha256': '3cf30ccc165600d125a3c3b666337622dd6db13e83bdf0086e18f0d21a105707'}, 'close': {'bytes': 180, 'sha256': '60f1d4eaf32534640d3f4a17db901705b48ae6fc6982d3b4ea6cda19b4065ef6'}, '_profiles': {'bytes': 9744, 'sha256': '0faed3cf3fdb0642867c4b4430ffa965b9dba1f560b3ae65f1f1e89fa65c8b7d'}, '_profile': {'bytes': 101, 'sha256': '0adeac9e1bf6164386db92d0a24fef3a8e083b39e027fe3063926ba1e14aeb3c'}, '_program': {'bytes': 116, 'sha256': '7de11c0755047bab19cb7625741bfb2aa6c79dc64d7fd99b4b57fbd2c340402a'}}
ORIGINAL_ASSERTIONS_SHA256 = '1c2be35d0f0e74b68d220f8db8b94adffe7cc64ebdfbedd64b786d9f74456520'


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    cls = next(node for node in ast.parse(raw).body
               if isinstance(node, ast.ClassDef) and node.name == 'HIAAgentService')
    result = {}
    for node in cls.body:
        if isinstance(node, ast.FunctionDef) and node.name in NAMES:
            start = min([node.lineno] + [item.lineno for item in node.decorator_list]) - 1
            result[node.name] = b''.join(lines[start:node.end_lineno])
    return result


class RetainedBootstrapService:
    def __init__(self, root):
        self.root, self.captured = Path(root), {}
        actual = self.read(SERVICE)
        observed = pin(actual)
        if observed == OLD_SERVICE:
            # The complete published literal keeps the old preparation path;
            # neither new authority nor new helper is necessary for its bytes.
            self.original = actual
            self.successor = False
        elif observed == PINS[SERVICE]:
            helper = self.read(HELPER)
            if pin(helper) != PINS[HELPER] or Path(relation.__file__).read_bytes() != helper:
                raise ValueError('loaded Bootstrap UUID relation source differs')
            frozen = self.read(AUTHORITY)
            if pin(frozen) != PINS[AUTHORITY]:
                raise ValueError('fixed Bootstrap UUID relation authority differs')
            value = relation.carrier_authority(frozen)
            self.original = relation.restore_carrier_source(actual, SERVICE, value['source_relations'][SERVICE])
            if pin(self.original) != OLD_SERVICE:
                raise ValueError('complete published Bootstrap source was not restored')
            if {name: pin(raw) for name, raw in definitions(actual).items()} != CURRENT_DEFINITIONS:
                raise ValueError('actual current Bootstrap definitions differ')
            self.successor = True
        else:
            raise ValueError('unreviewed complete Bootstrap service source')
        frozen = self.read(IDENTITY)
        if pin(frozen) != PINS[IDENTITY]:
            raise ValueError('original Bootstrap source identity changed')
        value = json.loads(frozen)
        prefix = self.original[:value['service']['bytes']]
        if pin(prefix) != value['service']:
            raise ValueError('original Bootstrap complete retained prefix changed')
        previous = definitions(self.original)
        for expected in value['methods']:
            name = expected['name']
            path = 'tests/fixtures/hia_service_bootstrap_original_r12/' + name + '.py.txt'
            raw = self.read(path)
            if (pin(raw) != PINS[path] or pin(raw) != {key: expected[key] for key in ('bytes', 'sha256')}
                    or previous[name] != raw):
                raise ValueError('original Bootstrap definition changed')
        self.finish()

    def read(self, name):
        raw = (self.root / name).read_bytes()
        if name in self.captured and self.captured[name] != raw:
            raise ValueError('Bootstrap UUID source changed while capturing')
        self.captured[name] = raw
        return raw

    def finish(self):
        if any((self.root / name).read_bytes() != raw for name, raw in self.captured.items()):
            raise ValueError('Bootstrap UUID source changed before terminal readback')


class ServiceBootstrapUUIDSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.captured = {name: (ROOT / name).read_bytes() for name in PINS}
        cls.actual = RetainedBootstrapService(ROOT)
        cls.old = cls.actual.original

    @classmethod
    def tearDownClass(cls):
        cls.actual.finish()
        if cls.captured != {name: (ROOT / name).read_bytes() for name in cls.captured}:
            raise AssertionError('Bootstrap UUID source control inputs changed')

    @contextmanager
    def view(self, overrides=None, missing=(), later=None):
        values = {ROOT / name: raw for name, raw in (overrides or {}).items()}
        absent, counts, real = {ROOT / name for name in missing}, {}, Path.read_bytes
        def read(path):
            counts[path] = counts.get(path, 0) + 1
            if path in absent:
                raise FileNotFoundError(str(path))
            if later is not None and path == ROOT / later[0] and counts[path] > 1:
                return later[1]
            return values[path] if path in values else real(path)
        with patch.object(Path, 'read_bytes', read):
            yield

    def test_original_prefix_five_definitions_and_current_exact_initialization_are_independent(self):
        self.assertTrue(self.actual.successor)
        self.assertEqual(pin(self.old), OLD_SERVICE)
        with self.view({SERVICE: self.old}, (AUTHORITY, HELPER)):
            old = RetainedBootstrapService(ROOT)
            self.assertFalse(old.successor)
            self.assertEqual(old.original, self.old)
            old.finish()
        olddefs, newdefs = definitions(self.old), definitions(self.captured[SERVICE])
        self.assertEqual(set(olddefs), set(NAMES))
        self.assertEqual(set(newdefs), set(NAMES))
        for name in NAMES[1:]:
            self.assertEqual(newdefs[name], olddefs[name])
        inserted = b'            _ensure_uuid()\n'
        self.assertEqual(newdefs['__init__'].count(inserted), 1)
        self.assertEqual(newdefs['__init__'].replace(inserted, b'', 1), olddefs['__init__'])
        from tests import test_hia_service_bootstrap_sources as retained
        case = retained.ServiceBootstrapStaticSourceTests(
            'test_five_original_definitions_signatures_and_retained_prefix')
        case.test_five_original_definitions_signatures_and_retained_prefix()
        self.assertTrue(case.doCleanups())

    def test_every_actual_dependency_is_required_fresh_and_terminally_bound(self):
        for name, raw in self.captured.items():
            for action in ('missing', 'changed', 'after-read'):
                arguments = {'missing': (name,)} if action == 'missing' else (
                    {'overrides': {name: raw + b' '}} if action == 'changed'
                    else {'later': (name, raw + b' ')})
                with self.subTest(name=name, action=action), self.view(**arguments), \
                        self.assertRaises((ValueError, FileNotFoundError)):
                    RetainedBootstrapService(ROOT)
            RetainedBootstrapService(ROOT).finish()
        with self.view(later=(SERVICE, self.old)), self.assertRaises(ValueError):
            RetainedBootstrapService(ROOT)
        captured = RetainedBootstrapService(ROOT)
        with self.view({SERVICE: self.old}), self.assertRaises(ValueError):
            captured.finish()

    def test_original_source_assertions_and_original_ids_are_retained(self):
        raw = (ROOT / 'tests/test_hia_service_bootstrap_sources.py').read_bytes()
        source = raw.decode()
        current = ("        from tests.test_hia_service_bootstrap_uuid_source import RetainedBootstrapService\n"
                   "        prepared=RetainedBootstrapService(ROOT)\n"
                   "        self.addCleanup(prepared.finish)\n"
                   "        raw=prepared.original\n")
        previous = "        raw=(ROOT/'hepta/hia_agent_service.py').read_bytes()\n"
        self.assertEqual(source.count(current), 1)
        restored = source.replace(current, previous, 1).encode()
        self.assertEqual(sha256(restored).hexdigest(), ORIGINAL_ASSERTIONS_SHA256)
        tree = ast.parse(raw)
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == 'ServiceBootstrapStaticSourceTests')
        self.assertEqual([node.name for node in cls.body if isinstance(node, ast.FunctionDef)], [
            'test_five_original_definitions_signatures_and_retained_prefix',
            'test_complete_protocol_graph_and_effect_set',
            'test_packaged_source_and_complete_original_caller_scope'])


if __name__ == '__main__':
    unittest.main()
