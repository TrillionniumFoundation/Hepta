"""Independent retained/native AgentStore bytes, SQLite state and effect order."""
from __future__ import annotations

import ast
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import itertools
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid
import zipfile

from hepta import hia_agent_store as store_module
from hepta.hia_agent_store_authority_native import (
    SOURCE, SCHEMA, SELECTOR, MAGIC, NativeAgentStoreAuthority,
    StoreAuthoritySession, installed_agent_store_authority,
)

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_AGENT_STORE_AUTHORITY_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_AGENT_STORE_AUTHORITY_DEVELOPMENT_MANIFEST'
EVIDENCE = 'HEPTA_HIA_AGENT_STORE_AUTHORITY_FIXTURE_EVIDENCE'
METHODS = ('put', 'ref', 'get', 'resolve_uri', 'profile', 'check_profile')


def observation(operation):
    try:
        result = operation()
        return {'return': result}
    except BaseException as exc:
        return {'exception': {'type': type(exc).__module__ + '.' + type(exc).__qualname__,
                              'message': str(exc),
                              'code': getattr(exc, 'code', None), 'phase': getattr(exc, 'phase', None),
                              'retry_action': getattr(exc, 'retry_action', None)}}


def serializable(value):
    if type(value) is bytes:
        return {'exact_bytes_hex': value.hex()}
    if type(value) is tuple:
        return {'exact_tuple': [serializable(v) for v in value]}
    if type(value) is list:
        return [serializable(v) for v in value]
    if type(value) is dict:
        return {k: serializable(v) for k, v in value.items()}
    return value


class StoreAuthoritySourceTests(unittest.TestCase):
    def test_six_retained_methods_are_complete_independent_oracles(self):
        frozen = (ROOT / 'tests/fixtures/hia_agent_store_f689.py.txt').read_bytes()
        self.assertEqual(sha256(frozen).hexdigest(), '043250991c58bedceb670e88e51339323f21f45b725b3df455706fc37d6585e9')
        def owner(raw):
            return next(n for n in ast.parse(raw).body if isinstance(n, ast.ClassDef) and n.name == 'AgentStore')
        before, after = owner(frozen), owner((ROOT / 'hepta/hia_agent_store.py').read_bytes())
        for name in METHODS:
            original_name = '_ref' if name == 'ref' else name
            original = next(n for n in before.body if isinstance(n, ast.FunctionDef) and n.name == original_name)
            current = next(n for n in after.body if isinstance(n, ast.FunctionDef) and n.name == '_reference_' + name)
            current.name = original_name
            self.assertEqual(ast.dump(current, include_attributes=False), ast.dump(original, include_attributes=False), name)

    def test_generated_source_and_independent_Core_projection_and_refusal(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tools.generate_hia_agent_store_authority import document
        self.assertEqual(render_assembly(document()).encode(), SOURCE.read_bytes())
        program = assemble_program(SOURCE.read_bytes())
        function = program.as_dict()['functions'][0]
        resources = []
        def entry(s, ns, o, no, w, nw):
            packet = ctypes.string_at(s, ns)
            owners = [_Owner(-1, bytearray(packet)), _Owner(-2, bytearray(ctypes.string_at(o, no))),
                      _Owner(-3, bytearray(ctypes.string_at(w, nw)))]
            machine = _Machine(program, 25_000_000, 64 << 20, None, 128)
            result = machine.invoke(function, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
            self.assertEqual(bytes(owners[0].data), packet)
            ctypes.memmove(o, bytes(owners[1].data), no)
            ctypes.memmove(w, bytes(owners[2].data), nw)
            resources.append(machine.resources())
            return result
        owner = NativeAgentStoreAuthority.__new__(NativeAgentStoreAuthority)
        owner._entry = entry
        events = []
        class Row:
            def __getitem__(self, key):
                events.append(key)
                return {'id': 'a-1', 'sha256': '雪', 'uri': 'opaque://uri'}[key]
        self.assertEqual(owner.run(None, 0, Row()), {'id': 'a-1', 'sha256': '雪', 'uri': 'opaque://uri'})
        self.assertEqual(events, ['id', 'sha256', 'uri'])
        refusal = observation(lambda: owner.run(None, 4, {'id': 'old'}, {'id': 'new'}))
        self.assertEqual(refusal['exception']['code'], 'E_HIA_PROFILE_STALE')
        self.assertGreater(len(resources), 4)

    def test_bad_cold_cannot_create_candidate_or_invoke_compiler(self):
        from tools.build_hia_agent_store_authority import build
        with tempfile.TemporaryDirectory(prefix='hia-store-authority-bad-cold-') as temporary:
            folder = Path(temporary)
            compiler, report, output = folder / 'compiler', folder / 'cold.json', folder / 'output'
            compiler.write_bytes(b'not a qualified compiler'); report.write_text('{}')
            with patch('tools.build_hia_agent_store_authority.compile_stage', side_effect=AssertionError('compiler entered')):
                with self.assertRaises(ValueError):
                    build(output, compiler, report)
            self.assertFalse(output.exists())


class StoreAuthorityNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise AssertionError('development cannot override matching-source cold')
        if not cold and not development:
            raise unittest.SkipTest('requires explicit matching cold or development AgentStore manifest')
        selected = os.environ.get(EVIDENCE)
        if selected:
            cls.folder = Path(selected).absolute(); cls.folder.mkdir(mode=0o700, parents=True)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-store-authority-tests-')
            cls.folder = Path(temporary.name); cls.addClassCleanup(temporary.cleanup)
        if cold:
            from tools.build_hia_agent_store_authority import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        cls.owner = installed_agent_store_authority(str(cls.manifest))
        cls.manifest_bytes = cls.manifest.read_bytes()
        cls.source_bytes = SOURCE.read_bytes()
        cls.entries = Counter(); cls.records = []

    @classmethod
    def tearDownClass(cls):
        report = {'schema': 'hepta.hia.agent-store-authority-observations.v1',
                  'scope': cls.scope, 'source_sha256': sha256(cls.source_bytes).hexdigest(),
                  'manifest_sha256': sha256(cls.manifest_bytes).hexdigest(),
                  'actual_native_modes': dict(cls.entries), 'comparisons': cls.records,
                  'source_unchanged': SOURCE.read_bytes() == cls.source_bytes,
                  'manifest_unchanged': cls.manifest.read_bytes() == cls.manifest_bytes}
        (cls.folder / 'observations.json').write_text(json.dumps(serializable(report), indent=2, sort_keys=True) + '\n')

    def same(self, operation, *, store_class=None):
        rows = []
        directory = self.folder / ('case-' + str(len(self.records)))
        directory.mkdir()
        original_run = NativeAgentStoreAuthority.run
        def entered(owner, store, mode, *arguments):
            self.entries[mode] += 1
            return original_run(owner, store, mode, *arguments)
        for native in (False, True):
            state = directory / ('native' if native else 'reference')
            store = (store_class or store_module.AgentStore)(state)
            events, sql = [], []
            store.db.set_trace_callback(sql.append)
            counter = itertools.count(1)
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, {SELECTOR: str(self.manifest) if native else ''}))
                stack.enter_context(patch.object(store_module.uuid, 'uuid4', side_effect=lambda: uuid.UUID(int=next(counter))))
                if native:
                    for name in METHODS:
                        stack.enter_context(patch.object(store_module.AgentStore, '_reference_' + name,
                            side_effect=AssertionError('retained AgentStore authority entered: ' + name)))
                    stack.enter_context(patch.object(NativeAgentStoreAuthority, 'run', entered))
                result = observation(lambda: operation(store, events))
                store.db.set_trace_callback(None)
                tables = {name: [tuple(row) for row in store.db.execute('SELECT * FROM ' + name + ' ORDER BY rowid')]
                          for name in ('artifacts', 'profiles')}
            store.close()
            reopened = store_module.AgentStore(state)
            durable = {name: [tuple(row) for row in reopened.db.execute('SELECT * FROM ' + name + ' ORDER BY rowid')]
                       for name in ('artifacts', 'profiles')}
            reopened.close()
            self.assertEqual(tables, durable)
            files = {p.name: {'sha256': sha256(p.read_bytes()).hexdigest(), 'size': p.stat().st_size,
                             'mode': p.stat().st_mode & 0o777, 'bytes': p.read_bytes()}
                     for p in sorted((state / 'artifacts').iterdir())}
            rows.append({'result': result, 'events': events, 'sql': sql, 'tables': tables, 'files': files})
        record = {'test': self.id(), 'reference': rows[0], 'native': rows[1], 'equal': rows[0] == rows[1]}
        self.records.append(record)
        (directory / 'comparison.json').write_text(json.dumps(serializable(record), indent=2, sort_keys=True) + '\n')
        self.assertEqual(rows[1], rows[0])
        return rows[1]

    def test_real_issuance_dedup_profile_uri_and_restart_preserve_all_state(self):
        def operation(store, events):
            output = []
            for data, kind, metadata in [(b'', 'data', None), ('雪\0'.encode(), 'data', {'z': -0.0, 'a': [True, 1, None]}),
                                         (b'same', 'one', {}), (b'same', 'two', {'x': 0})]:
                ref = store.put(data, kind, metadata)
                output.append((ref, list(ref), store.get(ref, kind=kind), store.resolve_uri(ref['uri']),
                               store.put(data, kind, metadata)))
            for identifier in ('p', 42, False):
                profile, artifact = store.profile(identifier, {'x': '雪', 'n': 1})
                output.append((profile, artifact, store.check_profile(profile, dict(profile))))
            return output
        row = self.same(operation)
        self.assertIn('return', row['result'])
        self.assertEqual(set(self.entries), set(range(6)))

    def test_reference_schema_identity_kind_and_SQL_binding_error_order(self):
        def operation(store, events):
            ref = store.put(b'bytes', 'data')
            values = [None, [], tuple(ref), {}, {**ref, 'extra': 1}, {k: v for k, v in ref.items() if k != 'uri'},
                      {**ref, 'id': []}, {**ref, 'id': 'unknown'}, {**ref, 'sha256': 'wrong'}, {**ref, 'uri': 'wrong'}]
            output = [observation(lambda candidate=candidate: store.get(candidate, kind='wrong')) for candidate in values]
            output += [observation(lambda kind=kind: store.get(ref, kind=kind)) for kind in ('wrong', 1, True, [], None)]
            output += [observation(lambda uri=uri: store.resolve_uri(uri)) for uri in ('missing', None, [], b'bad', 42)]
            # Existing URI semantics are retained issuance, without a new
            # prefix parser. The database's exact old opaque value resolves.
            store.db.execute('UPDATE artifacts SET uri=? WHERE id=?', ('not-a-uri\0雪', ref['id']))
            output.append(store.resolve_uri('not-a-uri\0雪'))
            return output
        self.same(operation)

    def test_profile_comparison_numeric_bool_subclass_and_foreign_truth_order(self):
        def operation(store, events):
            output = []
            pairs = [(False, 0), (1, 1.0), (-0.0, 0), ({'id': True, 'sha256': 1}, {'id': 1.0, 'sha256': True}),
                     ({'id': 'p'}, {'id': 'q'}), (None, None), ([], []),
                     ({'id': 'missing', 'sha256': 'x'}, {'sha256': 'x', 'id': 'missing'}),
                     ({'id': '\ud800', 'sha256': 'x'}, {'id': '\ud800', 'sha256': 'x'})]
            for left, right in pairs:
                output.append(observation(lambda left=left, right=right: store.check_profile(left, right)))
            class Truth:
                def __bool__(self): events.append(['truth']); return False
            class Ref:
                def __ne__(self, other): events.append(['foreign-ne']); return Truth()
                def __getitem__(self, key): events.append(['foreign-item', key]); return 'absent'
            output.append(observation(lambda: store.check_profile(Ref(), object())))
            class Text(str):
                def __ne__(self, other): events.append(['text-ne', str(other)]); return False
                def __eq__(self, other): events.append(['text-eq', str(other)]); return True
            ref = store.put(b'text', 'data')
            output.append(store.get({**ref, 'sha256': Text('foreign')}, kind=Text('different')))
            return output
        self.same(operation)

    def test_bytes_verification_precedes_metadata_and_preserves_exact_decode_errors(self):
        for metadata in ('{', '1e400', b'\xff', '"\\ud800"', '[]'):
            for corrupt in (False, True):
                with self.subTest(metadata=metadata, corrupt=corrupt):
                    def operation(store, events, metadata=metadata, corrupt=corrupt):
                        ref = store.put(b'original', 'data')
                        store.db.execute('UPDATE artifacts SET metadata=? WHERE id=?', (metadata, ref['id']))
                        if corrupt:
                            path = store.artifacts / ref['sha256']; path.chmod(0o600); path.write_bytes(b'changed')
                        return observation(lambda: store.get(ref))
                    self.same(operation)

    def test_row_getitem_reobservations_and_subclass_dispatch_are_preserved(self):
        def operation(store, events):
            ref = store.put(b'original', 'data')
            database = store.db
            class Row:
                def __init__(self, row): self.row = row
                def __getitem__(self, key): events.append(['field', key]); return self.row[key]
            class Cursor:
                def __init__(self, cursor): self.cursor = cursor
                def fetchone(self):
                    events.append(['fetchone']); row = self.cursor.fetchone()
                    return Row(row) if row is not None else None
            class Database:
                def execute(self, query, parameters):
                    events.append(['execute', query]); return Cursor(database.execute(query, parameters))
            store.db = Database()
            try:
                return store.get(ref, kind='data')
            finally:
                store.db = database
        row = self.same(operation)
        self.assertEqual([x[1] for x in row['events'] if x[0] == 'field'],
                         ['id', 'sha256', 'uri', 'kind', 'sha256', 'sha256', 'sha256', 'metadata'])
        class Derived(store_module.AgentStore):
            @staticmethod
            def _ref(row):
                return {'id': row['id'], 'sha256': row['sha256'], 'uri': row['uri']}
            def get(self, ref, *, kind=None):
                return b'OVERRIDE', {'kind': kind}
        row = self.same(lambda store, events: (store.put(b'a', 'data'), store.resolve_uri('missing')), store_class=Derived)
        self.assertEqual(row['result']['exception']['code'], 'E_HIA_ARTIFACT_IDENTITY')

    def test_actual_SQL_failure_boundaries_and_transaction_rollback_keep_original_rows(self):
        for exception_type in (sqlite3.OperationalError, KeyboardInterrupt, MemoryError, RuntimeError):
            for inside_transaction in (False, True):
                with self.subTest(exception=exception_type.__name__, transaction=inside_transaction):
                    def operation(store, events, exception_type=exception_type, inside_transaction=inside_transaction):
                        database = store.db
                        class Database:
                            def execute(self, query, params=()):
                                result = database.execute(query, params)
                                if query == 'INSERT OR IGNORE INTO artifacts VALUES (?,?,?,?,?,?)':
                                    events.append(['after-insert-fault', exception_type.__name__])
                                    raise exception_type('after real INSERT')
                                return result
                        store.db = Database()
                        try:
                            def action():
                                if inside_transaction:
                                    with store.transaction(): return store.put(b'committed-or-rolled-back', 'data')
                                return store.put(b'committed-or-rolled-back', 'data')
                            return observation(action)
                        finally:
                            store.db = database
                    self.same(operation)

    def test_existing_native_publication_route_and_receipt_comparison_order(self):
        def operation(store, events):
            receipt = {'sha256': sha256(b'native').hexdigest(), 'size': 6}
            admission = object()
            def file_op(operation, root, data=b'', content_hash='-', _admission=None):
                events.append(['native-file', operation, content_hash, _admission is admission])
                if operation == 'store-hash': return dict(receipt)
                if operation == 'store-put': return dict(receipt)
                return b'native'
            with patch.object(store_module, '_native_artifact_admission', return_value=admission), \
                 patch.object(store_module, '_native_artifact_file', side_effect=file_op):
                ref = store.put(b'native', 'data')
                return ref, store.get(ref), store.put(b'native', 'data')
        self.same(operation)
        def mismatch(store, events):
            receipt = {'sha256': sha256(b'x').hexdigest()}
            with patch.object(store_module, '_native_artifact_admission', return_value=object()), \
                 patch.object(store_module, '_native_artifact_file', side_effect=[receipt, {'sha256': 'different'}]):
                return store.put(b'x', 'data')
        row = self.same(mismatch)
        self.assertEqual(row['result']['exception']['code'], 'E_HIA_ARTIFACT_CORRUPT')
        self.assertEqual(row['tables']['artifacts'], [])

    def test_original_64MiB_admission_boundary_and_no_length_hook_for_wrong_type(self):
        class WrongType:
            def __len__(self): raise AssertionError('wrong-type length observed')
        for candidate in (WrongType(), bytearray(b'a'), 'data', b'x' * (64 << 20), b'x' * ((64 << 20) + 1)):
            with self.subTest(type=type(candidate).__name__, size=len(candidate) if type(candidate) is bytes else None):
                def operation(store, events, candidate=candidate):
                    def admitted():
                        events.append(['file-owner-admission'])
                        raise RuntimeError('boundary control stops before hashing or publication')
                    with patch.object(store_module, '_native_artifact_admission', side_effect=admitted):
                        return store.put(candidate, 'data')
                row = self.same(operation)
                if type(candidate) is bytes and len(candidate) == 64 << 20:
                    self.assertEqual(row['events'], [['file-owner-admission']])
                    self.assertEqual(row['result']['exception']['type'], 'builtins.RuntimeError')
                else:
                    self.assertEqual(row['events'], [])
                    self.assertEqual(row['result']['exception']['code'], 'E_HIA_ARTIFACT_LIMIT')

    def test_foreign_callables_and_path_attributes_are_bound_before_argument_effects(self):
        class TrackedStore(store_module.AgentStore):
            watching = None
            @property
            def artifacts(self):
                if self.watching is not None: self.watching.append(['artifacts-attribute'])
                return self._artifacts
            @artifacts.setter
            def artifacts(self, value): self._artifacts = value
            @property
            def db(self):
                if self.watching is not None: self.watching.append(['db-attribute'])
                return self._db
            @db.setter
            def db(self, value): self._db = value
        def operation(store, events):
            reference = store.put(b'original', 'data')
            database = store.db
            original_wire = store_module.wire
            class Row:
                def __init__(self, row): self.row = row
                def __getitem__(self, key): events.append(['row-item', key]); return self.row[key]
            class Cursor:
                def __init__(self, cursor): self.cursor = cursor
                def fetchone(self):
                    events.append(['fetchone']); row = self.cursor.fetchone()
                    return Row(row) if row is not None else None
            class Database:
                def __getattribute__(self, name):
                    if name == 'execute': events.append(['execute-attribute'])
                    return object.__getattribute__(self, name)
                def execute(self, query, parameters=()):
                    events.append(['execute-call', query]); return Cursor(database.execute(query, parameters))
            def wire(value):
                events.append(['wire-call'])
                return original_wire(value)
            store.db = Database(); store.watching = events
            try:
                with patch.object(store_module, 'wire', wire):
                    result = [store.get(reference, kind='data')]
                    profile, artifact = store.profile('bound-profile', {'x': 1})
                    result.append(store.check_profile(profile, dict(profile)))
                    return result
            finally:
                store.watching = None; store.db = database
        self.same(operation, store_class=TrackedStore)

    def test_protocol_refusal_canaries_terminal_and_effect_one_shot(self):
        for mode in (0, 1, 5, 6, (1 << 64) - 1):
            raw = struct.pack('<11Q', MAGIC, 0, 0, mode, 1, 2, 3, 4, 5, 0, 0)
            for malformed in (raw[:15], b'\0' * len(raw), raw + b'X'):
                source = ctypes.create_string_buffer(malformed + b'SOURCE!!', len(malformed) + 8)
                output = ctypes.create_string_buffer(b'O' * 16, 16)
                workspace = ctypes.create_string_buffer(262144 + 8)
                ctypes.memmove(ctypes.addressof(workspace) + 262144, b'CANARY!!', 8)
                status = self.owner._entry(source, len(malformed), output, 8, workspace, 262144)
                self.assertEqual(status, 199)
                self.assertEqual(output.raw, b'O' * 16)
                self.assertEqual(source.raw, malformed + b'SOURCE!!')
                self.assertEqual(workspace.raw[-8:], b'CANARY!!')
        events = []
        class Row:
            def __getitem__(self, name): events.append(name); return name
        session = StoreAuthoritySession(self.owner, None, 0, Row())
        self.assertEqual(session.step(), 1)
        session.observe()
        with self.assertRaises(RuntimeError): session.observe()
        self.assertEqual(session.step(), 1)
        session.observe()
        self.assertEqual(events, ['id'])
        with self.assertRaises(RuntimeError): session.observe()
        self.assertEqual(events, ['id'])
        bad = bytearray(session.packet); struct.pack_into('<Q', bad, 8, 0)
        self.assertEqual(session.step(bytes(bad)), 199)
        with self.assertRaises(RuntimeError): session.observe()
        with self.assertRaises(RuntimeError): session.step()
        class FailedRow:
            def __getitem__(self, name): events.append('failure'); raise KeyboardInterrupt('row effect')
        failed = StoreAuthoritySession(self.owner, None, 0, FailedRow())
        self.assertEqual(failed.step(), 1); failed.observe(); self.assertEqual(failed.step(), 1)
        with self.assertRaises(KeyboardInterrupt): failed.observe()
        for action in (failed.observe, failed.step):
            with self.assertRaises(RuntimeError): action()
        self.assertEqual(events.count('failure'), 1)
        ended = StoreAuthoritySession(self.owner, None, 0, {'id': 1, 'sha256': 2, 'uri': 3})
        self.assertEqual(ended.run(), {'id': 1, 'sha256': 2, 'uri': 3})
        with self.assertRaises(RuntimeError): ended.observe()

    def test_selected_missing_and_drifted_source_or_image_never_enter_retained_owner(self):
        manifest = json.loads(self.manifest_bytes)
        directory = self.folder / 'selection-refusals'; directory.mkdir()
        for name in METHODS:
            with patch.object(store_module.AgentStore, '_reference_' + name, side_effect=AssertionError('fallback')):
                with patch.dict(os.environ, {SELECTOR: str(directory / 'missing.json')}):
                    with self.assertRaises(OSError): store_module.AgentStore._ref({})
        image = (self.manifest.parent / manifest['image_path']).read_bytes()
        (directory / 'wrong.bin').write_bytes(image + b'changed')
        bad = {**manifest, 'image_path': 'wrong.bin'}
        path = directory / 'bad.json'; path.write_text(json.dumps(bad))
        with patch.dict(os.environ, {SELECTOR: str(path)}), \
             patch.object(store_module.AgentStore, '_reference_ref', side_effect=AssertionError('fallback')):
            with self.assertRaises(ValueError): store_module.AgentStore._ref({})
        original = SOURCE.read_bytes()
        try:
            SOURCE.write_bytes(original + b'\n')
            with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), \
                 patch.object(store_module.AgentStore, '_reference_ref', side_effect=AssertionError('fallback')):
                with self.assertRaises(ValueError): store_module.AgentStore._ref({})
        finally:
            SOURCE.write_bytes(original)

    def test_installed_wheel_ordinary_API_resources_and_identity_without_checkout(self):
        folder = self.folder / 'installed'; folder.mkdir()
        build = folder / 'build-source'
        shutil.copytree(ROOT, build, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.git', 'build', '*.egg-info'))
        wheel_dir = folder / 'wheel'; wheel_dir.mkdir()
        command = [sys.executable, '-B', 'setup.py', 'bdist_wheel', '--dist-dir', str(wheel_dir), '--bdist-dir', str(folder / 'bdist')]
        result = subprocess.run(command, cwd=build, capture_output=True, timeout=120,
                                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        (folder / 'build.stdout').write_bytes(result.stdout); (folder / 'build.stderr').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        wheels = list(wheel_dir.glob('*.whl')); self.assertEqual(len(wheels), 1)
        site = folder / 'site'; site.mkdir()
        with zipfile.ZipFile(wheels[0]) as archive: archive.extractall(site)
        self.assertEqual((site / 'hepta/_data/examples/hia_bootstrap/agent_store_authority.hiaasm').read_bytes(), self.source_bytes)
        for source in (ROOT / 'hepta').rglob('*.py'):
            self.assertEqual((site / source.relative_to(ROOT)).read_bytes(), source.read_bytes())
        image_manifest = json.loads(self.manifest_bytes)
        native = folder / 'native'; native.mkdir()
        shutil.copyfile(self.manifest.parent / image_manifest['image_path'], native / image_manifest['image_path'])
        selected = native / 'manifest.json'; selected.write_bytes(self.manifest_bytes)
        child = r'''
import sys, os, json
from pathlib import Path
from unittest.mock import patch
from contextlib import ExitStack
sys.path.insert(0, sys.argv[1])
from hepta.hia_agent_store import AgentStore
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_store_authority_native import SOURCE, SELECTOR
assert 'tools' not in sys.modules and 'tests' not in sys.modules
before = installation_manifest()
with ExitStack() as stack:
 for name in ('put','ref','get','resolve_uri','profile','check_profile'):
  stack.enter_context(patch.object(AgentStore,'_reference_'+name,side_effect=AssertionError('retained owner')))
 store = AgentStore(sys.argv[2])
 ref = store.put('雪'.encode(),'data',{'installed': True})
 assert store.get(ref)==('雪'.encode(),{'installed': True})
 assert store.resolve_uri(ref['uri'])==ref
 profile, artifact = store.profile('installed-profile',{'answer':42})
 assert store.check_profile(profile,dict(profile))=={'answer':42}
 store.close()
 assert installation_manifest()==before
 for name,module in list(sys.modules.items()):
  if name=='hepta' or name.startswith('hepta.'):
   path=getattr(module,'__file__',None)
   assert path is None or Path(path).resolve().is_relative_to(Path(sys.argv[1]).resolve())
print(json.dumps({'status':'PASS','source':str(SOURCE),'installed_manifest':before,'reference':ref,'profile':profile},sort_keys=True))
'''
        (folder / 'installed-control.py').write_text(child)
        command = [sys.executable, '-I', '-S', '-B', '-c', child, str(site), str(folder / 'state')]
        result = subprocess.run(command, cwd=folder, env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(selected)},
                                capture_output=True, timeout=30)
        (folder / 'child.stdout').write_bytes(result.stdout); (folder / 'child.stderr').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        report = json.loads(result.stdout); self.assertEqual(report['status'], 'PASS')
        self.assertTrue(Path(report['source']).is_relative_to(site))


if __name__ == '__main__':
    unittest.main()
