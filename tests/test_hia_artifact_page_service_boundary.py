"""Current public Service boundaries mapped to the retained AgentRead corpus.

The Page continuation deliberately retains foreign reference/SQL-binding semantics.
Only the public call's original complete-argument snapshot is claimed here.
"""
from __future__ import annotations

import ast
import base64
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

from hepta import hia_agent_service as service_module
from hepta import hia_agent_store as store_module
from hepta import hia_artifact_page_native as page

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/hia_artifact_page_service_admission_v1.json'
FIXTURE_SHA256 = 'e883b986b86e83ce027edd10fb83bd6e5ce61e429b349a1a3df0988ecffd34ca'
SELECTOR = page.SELECTOR
ORIGINAL = service_module.HIAAgentService._reference_hia_read
COLD = 'HEPTA_HIA_ARTIFACT_PAGE_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_ARTIFACT_PAGE_DEVELOPMENT_MANIFEST'
EVIDENCE = 'HEPTA_HIA_ARTIFACT_PAGE_BOUNDARY_EVIDENCE'


def _fixture():
    raw = (ROOT / FIXTURE).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('Page service boundary fixture differs')
    return json.loads(raw)


def _pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _function(raw, name):
    return next(n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == name)


def _rows(store):
    return [tuple(row) for row in store.db.execute('SELECT * FROM cursors ORDER BY id')]


def _restore_rows(store, rows):
    store.db.execute('DELETE FROM cursors')
    for row in rows:
        store.db.execute('INSERT INTO cursors VALUES (?,?,?,?)', row)


class ArtifactPageServiceSourceTests(unittest.TestCase):
    def test_full_historical_splice_and_current_dispatch_preserve_original_bootstrap(self):
        fixture = _fixture()
        before = zlib.decompress(base64.b64decode(fixture['before_zlib_base64'], validate=True))
        record = fixture['service_relation']
        self.assertEqual(_pin(before), record['before'])
        edit = record['edits'][0]
        inserted = base64.b64decode(edit['after'], validate=True)
        self.assertEqual(base64.b64decode(edit['before'], validate=True), b'')
        position = edit['before_offset']
        after = before[:position] + inserted + before[position:]
        self.assertEqual(_pin(after), record['after'])
        self.assertEqual(after[edit['after_offset']:edit['after_offset'] + len(inserted)], inserted)
        self.assertEqual(after[:position] + after[position + len(inserted):], before)
        name = '_service_bootstrap_dispatch___init__'
        old = _function(before, name)
        new = _function(after, name)
        actual = _function((ROOT / 'hepta/hia_agent_service.py').read_bytes(), name)
        self.assertEqual(ast.dump(actual, include_attributes=False), ast.dump(new, include_attributes=False))
        self.assertEqual(ast.dump(old, include_attributes=False),
                         ast.dump(_function(after[:position] + after[position + len(inserted):], name),
                                  include_attributes=False))
        self.assertEqual(len(fixture['original_methods']), 18)
        self.assertEqual(len(fixture['retained_ten_cases']), 10)
        # This test never treats its prepared historical bytes as physical current source.
        self.assertEqual(fixture['old_direct_adapter_snapshot_is_current_page_semantics'], False)

    def test_empty_missing_or_conflicting_selection_refuses_before_Store(self):
        with tempfile.TemporaryDirectory(prefix='hia-page-admission-') as temporary:
            root = Path(temporary)
            selections = [
                {SELECTOR: ''},
                {SELECTOR: str(root / 'missing')},
                {SELECTOR: str(root / 'missing'), 'HEPTA_HIA_SERVICE_READ_MANIFEST': ''},
            ]
            for env in selections:
                with self.subTest(env=env), patch.dict(os.environ, env, clear=True), \
                     patch.object(service_module, 'AgentStore', side_effect=AssertionError('Store opened')) as store:
                    with self.assertRaises((ValueError, OSError)):
                        service_module.HIAAgentService(root / 'must-not-exist')
                    self.assertEqual(store.call_count, 0)
                    self.assertFalse((root / 'must-not-exist').exists())


class ArtifactPageServiceNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise ValueError('Page boundary development and cold modes cannot be combined')
        if not cold and not development:
            raise unittest.SkipTest('explicit matching cold or development Page bundle required')
        cls.temporary = None
        if os.environ.get(EVIDENCE):
            cls.folder = Path(os.environ[EVIDENCE]).absolute()
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-page-service-boundary-')
            cls.folder = Path(cls.temporary.name)
        cls.cold = None
        if cold:
            from tools.hia_cold_compiler import read_cold_build_inputs
            from tools.build_hia_artifact_page import build
            cls.cold = read_cold_build_inputs(Path(cold))
            cls.manifest = build(cls.folder / 'bundle', cls.cold.compiler, Path(cold))
            cls.cold.unchanged()
            cls.scope = 'MATCHING_SOURCE_COLD_COMPONENT'
        else:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        cls.manifest_bytes = cls.manifest.read_bytes()
        cls.owner = page.installed_artifact_page(cls.manifest)
        cls.sources = {name: (ROOT / name).read_bytes() for name in (
            'hepta/hia_agent_service.py', 'hepta/hia_agent_journal_native.py',
            'hepta/hia_artifact_page_native.py', 'examples/hia_bootstrap/artifact_page.hepta',
            'examples/hia_bootstrap/json_wire.hepta', FIXTURE,
            'tests/test_hia_artifact_page_service_boundary.py')}
        cls.observations = {}
        cls.case_number = 0

    @classmethod
    def tearDownClass(cls):
        report = {'scope': cls.scope, 'whole_native_closure': False,
                  'source_before': {n: _pin(raw) for n, raw in cls.sources.items()},
                  'source_after': {n: _pin((ROOT / n).read_bytes()) for n in cls.sources},
                  'manifest': str(cls.manifest), 'manifest_sha256': sha256(cls.manifest_bytes).hexdigest(),
                  'policy_image_sha256': cls.owner.policy.image_sha256,
                  'wire_image_sha256': cls.owner.wire.image_sha256,
                  'observations': cls.observations}
        (cls.folder / 'observations.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        assert report['source_before'] == report['source_after']
        assert cls.manifest.read_bytes() == cls.manifest_bytes
        page.installed_artifact_page(cls.manifest)
        if cls.cold is not None: cls.cold.unchanged()
        if cls.temporary is not None: cls.temporary.cleanup()

    @contextmanager
    def _selected(self, manifest=None):
        with patch.dict(os.environ, {SELECTOR: str(manifest or self.manifest)}, clear=True), \
             patch.object(service_module.HIAAgentService, '_reference_hia_read',
                          side_effect=AssertionError('retained policy entered')):
            yield

    def _service(self, name, manifest=None):
        with self._selected(manifest):
            return service_module.HIAAgentService(self.folder / name)

    def _observed_page(self, data, reference, maximum, cursor, native):
        connection = sqlite3.connect(':memory:', isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute('CREATE TABLE cursors(id TEXT PRIMARY KEY,artifact_id TEXT,sha256 TEXT,offset INTEGER)')
        store = SimpleNamespace(db=connection, get=lambda ref: (data, {}))
        receiver = SimpleNamespace(store=store)
        arguments = {'artifact': deepcopy(reference), 'max_bytes': maximum}
        if cursor is not None:
            arguments['cursor'] = 'retained-oracle-cursor'
            row = {'artifact_id': reference['id'], 'sha256': reference['sha256'], 'offset': 0} | cursor
            connection.execute('INSERT INTO cursors VALUES (?,?,?,?)',
                               (arguments['cursor'], row['artifact_id'], row['sha256'], row['offset']))
        try:
            if native:
                with self._selected():
                    result = self.owner.read(receiver, arguments)
            else:
                with patch.dict(os.environ, {}, clear=True):
                    result = ORIGINAL(receiver, arguments)
            return result, _rows(store)
        finally:
            connection.close()

    def test_retained_ten_complete_page_cases_keep_results_and_SQL(self):
        records = []
        for case in _fixture()['retained_ten_cases']:
            data = bytes.fromhex(case['data_hex'])
            reference = case['reference']
            pair = [self._observed_page(data, reference, case['maximum'], case['cursor'], native)
                    for native in (False, True)]
            self.assertEqual(*pair, case['name'])
            records.append({'name': case['name'], 'reference': pair[0], 'native': pair[1]})
        self.observations['retained_ten_complete_values_and_SQL'] = records

    def test_ordinary_and_alias_snapshot_full_arguments_before_actual_file_read(self):
        records = []
        real_stable_read = store_module.stable_read
        real_step = page.PageSession.step
        for route in ('ordinary-tool', 'resource-alias'):
            service = self._service('capture-' + route)
            try:
                data = b'frozen-input/' * 300
                ref = service.store.put(data, 'input')
                arguments = ({'catalog_sha256': service.catalog_sha256, 'artifact': ref,
                              'max_bytes': 512.0, 'cursor': 'frozen-cursor'}
                             if route == 'ordinary-tool' else {'uri': ref['uri'], 'max_bytes': 512})
                service.store.db.execute('INSERT INTO cursors VALUES (?,?,?,?)',
                    ('frozen-cursor', ref['id'], ref['sha256'], 123))
                captured = deepcopy(arguments)
                page_arguments = (deepcopy(arguments) if route == 'ordinary-tool'
                                  else {'artifact': deepcopy(ref), 'max_bytes': 512})
                initial_rows = _rows(service.store)
                with patch.dict(os.environ, {}, clear=True):
                    expected = ORIGINAL(service, page_arguments)
                expected_rows = _rows(service.store)
                _restore_rows(service.store, initial_rows)
                target = service.store.artifacts / ref['sha256']
                calls, frames = [], []
                def mutate(path, limit, **kwargs):
                    if Path(path) == target:
                        calls.append({'path': str(path), 'limit': limit})
                        ref.clear()
                        ref.update({'id': 'changed-id', 'sha256': '0' * 64,
                                    'uri': 'hia://artifacts/changed', 'unexpected': True})
                        arguments.clear()
                        arguments.update({'artifact': {'another': 'mutable producer'}, 'cursor': 'different',
                                          'max_bytes': 65536, 'catalog_sha256': '0' * 64,
                                          'uri': 'hia://wrong', 'extra': True})
                    return real_stable_read(path, limit, **kwargs)
                def traced(session, packet=None):
                    before = session.packet if packet is None else packet
                    self.assertIs(type(before), bytes)
                    result = real_step(session, packet)
                    if packet is None: self.assertEqual(session.packet, before)
                    frames.append({'bytes': len(before), 'sha256': sha256(before).hexdigest(), 'result': result})
                    return result
                with self._selected(), patch.object(store_module, 'stable_read', mutate), \
                     patch.object(page.PageSession, 'step', traced):
                    response = service.call('hia_read' if route == 'ordinary-tool' else 'hia_resource_read', arguments)
                self.assertEqual(response['status'], 'completed', response)
                self.assertEqual(response['result'], expected)
                self.assertEqual(_rows(service.store), expected_rows)
                self.assertEqual(len(calls), 1)
                self.assertGreater(len(frames), 1)
                self.assertEqual(frames[-1]['result'], 2)
                self.assertNotEqual(arguments, captured)
                records.append({'route': route, 'captured_arguments': captured, 'producer_after': arguments,
                                'result': response['result'], 'actual_read_calls': calls,
                                'immutable_actual_native_packets': frames})
            finally:
                service.close()
        self.observations['public_full_argument_capture'] = records

    def test_exact_double_wire_boundary_and_two_halvings_are_native(self):
        from hepta.hia_agent_contract import wire
        records = []
        for name, data, exact in (
                ('exact-230000', b'\0' * 17690 + b'a' * 11, 230000),
                ('over-230000', b'\0' * 17690 + b'a' * 12, 230002),
                ('two-halvings', b'\0' * 65536, None)):
            ref = {'id': 'artifact-boundary', 'sha256': sha256(data).hexdigest(), 'uri': 'hia://boundary'}
            before = len(wire(wire(data.decode()).decode()))
            if exact is not None: self.assertEqual(before, exact)
            pair = [self._observed_page(data, ref, 65536, None, native) for native in (False, True)]
            self.assertEqual(*pair)
            content = pair[1][0]['content']
            self.assertLessEqual(len(wire(wire(content).decode())), 230000)
            expected_length = len(data) if name == 'exact-230000' else len(data) // 2 if name == 'over-230000' else 16384
            self.assertEqual(len(content), expected_length)
            records.append({'case': name, 'initial_double_wire_bytes': before,
                            'consumed': len(content), 'result': pair[1][0], 'rows': pair[1][1]})
        self.observations['exact_wire_thresholds'] = records

    def test_signed_SQL_offsets_and_insert_or_ignore_collision_keep_exact_rows(self):
        records = []
        data = b'x' * 700
        ref = {'id': 'artifact-signed', 'sha256': sha256(data).hexdigest(), 'uri': 'hia://signed'}
        for offset in (-(1 << 63), -515, -1, 0, 511, (1 << 63) - 1):
            pair = [self._observed_page(data, ref, 512.0, {'offset': offset}, native) for native in (False, True)]
            self.assertEqual(*pair)
            records.append({'offset': offset, 'reference': pair[0], 'native': pair[1]})
        service = self._service('collision')
        try:
            actual_ref = service.store.put(b'x' * 700, 'input')
            arguments = {'artifact': actual_ref, 'max_bytes': 512}
            with patch.dict(os.environ, {}, clear=True): expected = ORIGINAL(service, arguments)
            identifier = expected['next_cursor']
            service.store.db.execute('DELETE FROM cursors')
            collision = (identifier, 'different-artifact', 'f' * 64, -777)
            service.store.db.execute('INSERT INTO cursors VALUES (?,?,?,?)', collision)
            with self._selected(): actual = service._hia_read(arguments)
            self.assertEqual(actual, expected)
            self.assertEqual(_rows(service.store), [collision])
            records.append({'collision_row': collision, 'result': actual, 'rows': _rows(service.store)})
        finally:
            service.close()
        self.observations['signed_offsets_and_cursor_collision'] = records

    def test_invalid_bundle_and_late_image_change_refuse_before_Store_effects(self):
        records = []
        for kind in ('schema', 'policy_source', 'policy_image', 'wire_source', 'wire_image'):
            copied = self.folder / ('bad-' + kind)
            shutil.copytree(self.manifest.parent, copied)
            manifest = copied / self.manifest.name
            bundle = json.loads(manifest.read_bytes())
            if kind == 'schema':
                bundle['schema'] = 'unknown.page'
            else:
                role, field = kind.split('_')
                child = copied / bundle[role + '_manifest']
                value = json.loads(child.read_bytes()); value[field + '_sha256'] = '0' * 64
                child.write_text(json.dumps(value, sort_keys=True) + '\n')
                bundle[role + '_manifest_sha256'] = sha256(child.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(bundle, sort_keys=True) + '\n')
            state = self.folder / ('must-not-create-' + kind)
            with self._selected(manifest), patch.object(service_module, 'AgentStore',
                    side_effect=AssertionError('Store opened before child custody')) as store:
                with self.assertRaises((ValueError, OSError)):
                    service_module.HIAAgentService(state)
                self.assertEqual(store.call_count, 0); self.assertFalse(state.exists())
            records.append({'kind': kind, 'Store_calls': 0, 'state_created': False})
        copied = self.folder / 'late-private-bundle'
        shutil.copytree(self.manifest.parent, copied)
        manifest = copied / self.manifest.name
        service = self._service('late-private-state', manifest)
        try:
            ref = service.store.put(b'hello', 'input')
            bundle = json.loads(manifest.read_bytes())
            child = copied / bundle['policy_manifest']; record = json.loads(child.read_bytes())
            image = child.parent / record['image_path']; before = image.read_bytes()
            image.write_bytes(before + b'\0')
            try:
                with self._selected(manifest), patch.object(service.store, 'get',
                        side_effect=AssertionError('artifact read before fresh Page custody')) as get:
                    with self.assertRaises((ValueError, OSError)):
                        service._hia_read({'artifact': ref, 'max_bytes': 512})
                    self.assertEqual(get.call_count, 0)
            finally:
                self.assertEqual(image.read_bytes(), before + b'\0'); image.write_bytes(before)
            page.installed_artifact_page(manifest)
            records.append({'kind': 'late_private_image', 'artifact_get_calls': 0, 'restored_private_copy': True})
        finally:
            service.close()
        self.observations['current_selection_refusals'] = records
