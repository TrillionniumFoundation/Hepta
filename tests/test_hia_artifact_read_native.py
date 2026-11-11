"""Independent ordinary artifact-read semantics, SQL state and installed custody."""
from __future__ import annotations

import ast
from collections import Counter
from contextlib import ExitStack
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from hepta import hia_agent_service as service_module
from hepta import hia_agent_store as store_module
from hepta import hia_artifact_page_native as page

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_ARTIFACT_PAGE_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_ARTIFACT_PAGE_DEVELOPMENT_MANIFEST'
EVIDENCE = 'HEPTA_HIA_ARTIFACT_PAGE_FIXTURE_EVIDENCE'
SELECTOR = page.SELECTOR
ORIGINAL = service_module.HIAAgentService._reference_hia_read


def observed(operation):
    try:
        return {'return': operation()}
    except BaseException as exc:
        return {'exception': {'type': type(exc).__module__ + '.' + type(exc).__qualname__,
                             'message': str(exc), 'code': getattr(exc, 'code', None),
                             'phase': getattr(exc, 'phase', None), 'retry_action': getattr(exc, 'retry_action', None)}}


def serial(value):
    if type(value) is bytes:
        return {'bytes_hex': value.hex()}
    if type(value) in (tuple, list):
        return [serial(v) for v in value]
    if type(value) is dict:
        return {k: serial(v) for k, v in value.items()}
    return value


def sql_case(folder, manifest, *, native, binding=None, offset=0, fault=None, transaction=False):
    folder.mkdir(mode=0o700)
    data = b'A' * 600
    ref = {'id': 'artifact-old', 'sha256': sha256(data).hexdigest(), 'uri': 'hia://old'}
    args = {'artifact': ref, 'max_bytes': 512}
    if binding != 'insert':
        args['cursor'] = 'missing' if binding == 'select' else 'cursor-good'
    path = folder / 'state.sqlite3'
    connection = sqlite3.connect(path, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute('CREATE TABLE cursors(id TEXT PRIMARY KEY,artifact_id TEXT,sha256 TEXT,offset INTEGER)')
    connection.execute('INSERT INTO cursors VALUES (?,?,?,?)', ('cursor-good', ref['id'], ref['sha256'], offset))
    events, sql = [], []
    connection.set_trace_callback(sql.append)
    class Database:
        @property
        def execute(self):
            events.append('execute.lookup')
            if binding == 'select': args['cursor'] = 'cursor-good'
            if binding == 'insert': ref.update(id='artifact-mutated', sha256='f' * 64)
            def bound(query, parameters):
                events.append({'execute': query, 'parameters': serial(parameters)})
                hit = fault is not None and query.startswith(fault[0])
                if hit and fault[1] == 'before': raise fault[2]('injected SQL boundary')
                cursor = connection.execute(query, parameters)
                if hit and fault[1] == 'after': raise fault[2]('injected SQL boundary')
                return cursor
            return bound
    def get(reference):
        events.append('store.get'); return data, {}
    service = SimpleNamespace(store=SimpleNamespace(get=get, db=Database()))
    before = [list(row) for row in connection.execute('SELECT * FROM cursors ORDER BY id')]
    if transaction: connection.execute('BEGIN IMMEDIATE')
    if native:
        with patch.dict(os.environ, {SELECTOR: str(manifest)}), \
             patch.object(service_module.HIAAgentService, '_reference_hia_read', side_effect=AssertionError('retained page')):
            result = observed(lambda: service_module.HIAAgentService._hia_read(service, args))
    else:
        result = observed(lambda: ORIGINAL(service, args))
    if transaction: connection.execute('ROLLBACK' if 'exception' in result else 'COMMIT')
    rows = [list(row) for row in connection.execute('SELECT * FROM cursors ORDER BY id')]
    connection.close()
    restarted = sqlite3.connect(path)
    try:
        reopened = [list(row) for row in restarted.execute('SELECT * FROM cursors ORDER BY id')]
    finally:
        restarted.close()
    assert rows == reopened
    record = serial({'result': result, 'events': events, 'sql': sql, 'before': before,
                     'rows': rows, 'reopened': reopened})
    (folder / 'observations.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    return record


class ArtifactReadSourceTests(unittest.TestCase):
    def test_complete_retained_business_method_is_unchanged(self):
        fixture = ROOT / 'tests/fixtures/hia_agent_service_5810.py.txt'
        self.assertEqual(sha256(fixture.read_bytes()).hexdigest(), '684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330')
        def method(raw, name):
            cls = next(n for n in ast.parse(raw).body if isinstance(n, ast.ClassDef) and n.name == 'HIAAgentService')
            return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
        original = method(fixture.read_bytes(), '_hia_read')
        retained = method((ROOT / 'hepta/hia_agent_service.py').read_bytes(), '_reference_hia_read')
        retained.name = '_hia_read'
        self.assertEqual(ast.dump(original, include_attributes=False), ast.dump(retained, include_attributes=False))
        self.assertIn('230000', ast.unparse(original))

    def test_generated_source_and_independent_Core_execution(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tools.generate_hia_artifact_page import document
        self.assertEqual(render_assembly(document()).encode(), page.SOURCE.read_bytes())
        program = assemble_program(page.SOURCE.read_bytes())
        function = program.as_dict()['functions'][0]
        entries = []
        def entry(s, ns, o, no, w, nw):
            packet = ctypes.string_at(s, ns)
            owners = [_Owner(-1, bytearray(packet)), _Owner(-2, bytearray(ctypes.string_at(o, no))),
                      _Owner(-3, bytearray(ctypes.string_at(w, nw)))]
            machine = _Machine(program, 25_000_000, 64 << 20, None, 128)
            result = machine.invoke(function, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
            self.assertEqual(bytes(owners[0].data), packet)
            ctypes.memmove(o, bytes(owners[1].data), no); ctypes.memmove(w, bytes(owners[2].data), nw)
            entries.append(result)
            return result
        class IndependentWire:
            def encode_observed(self, observer, handle, maximum, **options):
                from hepta.hia_program_tools import _reference_bounded_json_wire
                return _reference_bounded_json_wire(observer.value(handle), maximum, **options)
        owner = page.NativeArtifactPage(SimpleNamespace(_entry=entry), IndependentWire())
        ref = {'id': 'a', 'sha256': '0' * 64, 'uri': 'hia://a'}
        service = SimpleNamespace(store=SimpleNamespace(get=lambda ref: (b'', {})))
        with patch.dict(os.environ, {}, clear=True):
            result = owner.read(service, {'artifact': ref})
        self.assertEqual(result, {'artifact': ref, 'encoding': 'utf8', 'content': '', 'next_cursor': None})
        self.assertEqual(list(result), ['artifact', 'encoding', 'content', 'next_cursor'])
        self.assertGreater(len(entries), 10); self.assertEqual(entries[-1], 2)

    def test_invalid_cold_refuses_before_output_or_compilation(self):
        from tools.build_hia_artifact_page import build
        with tempfile.TemporaryDirectory(prefix='hia-page-bad-cold-') as temporary:
            root = Path(temporary)
            compiler, cold, output = root / 'compiler', root / 'cold.json', root / 'output'
            compiler.write_bytes(b'not a compiler'); cold.write_text('{}')
            with patch('tools.build_hia_artifact_page.compile_stage', side_effect=AssertionError('compiler entered')):
                with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                    build(output, compiler, cold)
            self.assertFalse(output.exists())


class ArtifactReadNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if cold and development: raise AssertionError('development cannot override cold')
        if not cold and not development: raise unittest.SkipTest('requires explicit matching-source cold or development bundle')
        evidence = os.environ.get(EVIDENCE)
        cls.temporary = None
        if evidence:
            cls.folder = Path(evidence).absolute(); cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-artifact-read-native-')
            cls.folder = Path(cls.temporary.name)
        if cold:
            from tools.build_hia_artifact_page import build
            outer = json.loads(Path(cold).read_bytes()); nested = json.loads(Path(outer['nested_report']).read_bytes())
            cls.manifest = build(cls.folder / 'bundle', Path(nested['generations'][-1]['produced_image']), Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_NATIVE_TESTS'
        else:
            cls.manifest = Path(development).resolve(strict=True); cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        cls.manifest_bytes = cls.manifest.read_bytes()
        cls.owner = page.installed_artifact_page(cls.manifest)
        cls.source_before = {n: sha256((ROOT / n).read_bytes()).hexdigest() for n in (
            'hepta/hia_agent_service.py', 'hepta/hia_artifact_page_native.py', 'tools/generate_hia_artifact_page.py',
            'examples/hia_bootstrap/artifact_page.hiaasm', 'examples/hia_bootstrap/json_wire.hiaasm')}
        cls.observations = {}

    @classmethod
    def tearDownClass(cls):
        after = {n: sha256((ROOT / n).read_bytes()).hexdigest() for n in cls.source_before}
        record = {'scope': cls.scope, 'source_before': cls.source_before, 'source_after': after,
                  'manifest_path': str(cls.manifest), 'policy_image': cls.owner.policy.image_sha256,
                  'wire_image': cls.owner.wire.image_sha256, 'observations': cls.observations}
        (cls.folder / 'observations.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        assert cls.source_before == after and cls.manifest.read_bytes() == cls.manifest_bytes
        if cls.temporary is not None: cls.temporary.cleanup()

    def selected(self):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(self.manifest)}))
        stack.enter_context(patch.object(service_module.HIAAgentService, '_reference_hia_read', side_effect=AssertionError('retained page')))
        return stack

    def test_all_42_original_page_boundaries_execute_fresh(self):
        from tests.hia_artifact_read_cases import run_boundaries
        result = run_boundaries(self.owner, self.folder / 'full-boundaries')
        self.observations['full_boundaries'] = result
        self.assertEqual(result['expected_case_count'], 42)
        self.assertEqual(result['failures'], [])
        self.assertEqual(len(result['observations']), 42)
        self.assertEqual(result['status'], 'DEVELOPMENT_BOUNDARIES_PASS')
        self.assertTrue(result['source_preserved'])

    def test_real_store_ordinary_paging_and_reopen_preserve_bytes_and_cursors(self):
        records = []
        for label, data, limit in [('utf8', ('x' * 511 + '雪🧪' * 150 + 'end').encode(), 512),
                                   ('binary', b'abc\xff' * 300, 512), ('nul', b'\0' * 65536, 65536)]:
            pair = []
            for native in (False, True):
                folder = self.folder / (label + ('-native' if native else '-reference'))
                store = store_module.AgentStore(folder)
                ref = store.put(data, 'input')
                service = service_module.HIAAgentService.__new__(service_module.HIAAgentService); service.store = store
                args = {'artifact': ref, 'max_bytes': limit}; pages = []; assembled = bytearray()
                with patch.dict(os.environ, {SELECTOR: ''}):
                    while True:
                        if native:
                            with self.selected(): value = service._hia_read(args)
                        else: value = ORIGINAL(service, args)
                        pages.append(value)
                        assembled.extend(value['content'].encode() if value['encoding'] == 'utf8' else service_module.base64.b64decode(value['content']))
                        if value['next_cursor'] is None: break
                        args['cursor'] = value['next_cursor']
                        self.assertLess(len(pages), 100)
                self.assertEqual(bytes(assembled), data)
                rows = [tuple(row) for row in store.db.execute('SELECT artifact_id,sha256,offset FROM cursors ORDER BY offset')]
                store.close(); store = store_module.AgentStore(folder)
                self.assertEqual(rows, [tuple(row) for row in store.db.execute('SELECT artifact_id,sha256,offset FROM cursors ORDER BY offset')])
                store.close()
                # Issued IDs are intentionally different across independent stores;
                # compare the policy's exact content/offset sequence, while each
                # side separately checks its own retained identity and restart rows.
                pair.append({'encoding_content': [(p['encoding'], p['content']) for p in pages],
                             'offsets': [r[2] for r in rows], 'sha256': ref['sha256'],
                             'pages': len(pages), 'reconstructed_sha256': sha256(assembled).hexdigest()})
            self.assertEqual(*pair); records.append({'case': label, 'reference': pair[0], 'native': pair[1]})
        self.observations['real_store_pages'] = records

    def test_SQL_callable_binding_and_all_builtin_corrupt_offset_errors(self):
        cases = [('select', 'select', 0), ('insert', 'insert', 0), ('none', None, None),
                 ('real', None, 0.5), ('text', None, 'bad'), ('blob', None, b'bad'),
                 ('zero', None, 0), ('negative', None, -1)]
        records = []
        for name, binding, offset in cases:
            with self.subTest(case=name):
                pair = [sql_case(self.folder / ('binding-' + name + '-' + str(native)), self.manifest,
                                 native=native, binding=binding, offset=offset) for native in (False, True)]
                self.assertEqual(*pair); records.append({'case': name, 'reference': pair[0], 'native': pair[1]})
        self.observations['binding_and_offset'] = records

    def test_real_SQL_exceptions_and_transaction_boundaries_keep_exact_state(self):
        records = []
        for query in ('SELECT', 'INSERT'):
            for point in ('before', 'after'):
                for error in (sqlite3.OperationalError, RuntimeError, KeyboardInterrupt, MemoryError):
                    for transaction in (False, True):
                        name = '-'.join((query, point, error.__name__, str(transaction)))
                        with self.subTest(case=name):
                            pair = [sql_case(self.folder / ('fault-' + name + '-' + str(native)), self.manifest,
                                             native=native, fault=(query, point, error), transaction=transaction)
                                    for native in (False, True)]
                            self.assertEqual(*pair); self.assertIn('exception', pair[0]['result'])
                            records.append({'case': name, 'reference': pair[0], 'native': pair[1]})
        self.observations['sql_failures'] = records

    def test_protocol_canaries_and_effect_permissions_are_one_shot(self):
        for raw, output_size, workspace_size in [(b'', 131072, 131072), (b'\0' * 32, 131072, 131072),
                                                (b'\0' * 32, 131071, 131072), (b'\0' * 32, 131072, 131071)]:
            source = ctypes.create_string_buffer(raw or b'X')
            output = ctypes.create_string_buffer(b'O' * (131072 + 16)); workspace = ctypes.create_string_buffer(131072 + 16)
            before_source, before_output, before_workspace = source.raw, output.raw, workspace.raw
            code = self.owner.policy._entry(source, len(raw), output, output_size, workspace, workspace_size)
            self.assertEqual(code, 199)
            self.assertEqual((source.raw, output.raw, workspace.raw), (before_source, before_output, before_workspace))
        effects = []
        class Arguments(dict):
            def __getitem__(self, name): effects.append(name); return super().__getitem__(name)
        session = page.PageSession(self.owner, None, Arguments(artifact={}))
        self.assertEqual(session.step(), 1); session.observe(); self.assertEqual(effects, ['artifact'])
        with self.assertRaisesRegex(RuntimeError, 'consumed'): session.observe()
        self.assertEqual(effects, ['artifact'])
        session = page.PageSession(self.owner, None, {})
        self.assertEqual(session.step(), 1)
        with self.assertRaises(KeyError): session.observe()
        self.assertTrue(session.finished)
        with self.assertRaises(RuntimeError): session.observe()
        with self.assertRaises(RuntimeError): session.step()
        for exception in (KeyboardInterrupt, MemoryError, RuntimeError):
            session = page.PageSession(self.owner, None, {'artifact': {}})
            real_entry = self.owner.policy._entry
            def failing(*arguments):
                real_entry(*arguments)
                raise exception('after real native return')
            with patch.object(self.owner.policy, '_entry', side_effect=failing):
                with self.assertRaises(exception): session.step()
            self.assertTrue(session.finished); self.assertFalse(session._observation_pending)
            with self.assertRaises(RuntimeError): session.observe()

    def test_wire_selection_order_errors_preserve_SQL_and_no_legacy_codecs(self):
        data = b'\0' * 1000; ref = {'id': 'a', 'sha256': sha256(data).hexdigest(), 'uri': 'hia://a'}
        service = SimpleNamespace(store=SimpleNamespace(get=lambda value: (data, {})))
        # No cursor is needed after the whole content fits. In this interval
        # the page's policy, base64, cursor digest and wire cannot use Python.
        with self.selected(), patch.object(service_module, 'wire', side_effect=AssertionError('legacy page wire')), \
             patch.object(service_module, 'digest', side_effect=AssertionError('legacy cursor digest')), \
             patch.object(service_module.base64, 'b64encode', side_effect=AssertionError('legacy base64')), \
             patch('hepta.hia_program_tools._reference_bounded_json_wire', side_effect=AssertionError('legacy encoder')):
            value = service_module.HIAAgentService._hia_read(service, {'artifact': ref})
        self.assertEqual(value['content'], '\0' * 1000)
        records = []
        for variables in ({'HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST': str(self.folder / 'missing-formatter')},
                          {'HEPTA_HIA_JSON_WIRE_MANIFEST': str(self.folder / 'missing-wire')},
                          {'HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST': str(self.folder / 'missing-first'),
                           'HEPTA_HIA_JSON_WIRE_MANIFEST': str(self.folder / 'missing-second')}):
            with patch.dict(os.environ, variables):
                expected = observed(lambda: ORIGINAL(service, {'artifact': ref}))
                with self.selected(): actual = observed(lambda: service_module.HIAAgentService._hia_read(service, {'artifact': ref}))
            self.assertEqual(actual, expected); records.append({'environment': variables, 'reference': expected, 'native': actual})
        self.observations['wire_selection'] = records

    def test_selected_missing_source_and_cold_image_key_never_fall_back(self):
        service = SimpleNamespace(store=SimpleNamespace(get=lambda ref: (b'', {})))
        with patch.object(service_module.HIAAgentService, '_reference_hia_read', side_effect=AssertionError('retained page')):
            with patch.dict(os.environ, {SELECTOR: str(self.folder / 'absent')}):
                with self.assertRaises(OSError): service_module.HIAAgentService._hia_read(service, {'artifact': {}})
            bundle = self.folder / 'broken-bundle'; shutil.copytree(self.manifest.parent, bundle)
            selected = bundle / self.manifest.name; raw = json.loads(selected.read_bytes())
            policy_path = bundle / raw['policy_manifest']; policy = json.loads(policy_path.read_bytes())
            policy['image_path'] = 'fresh-broken-image.bin'; (policy_path.parent / policy['image_path']).write_bytes(b'wrong image')
            policy_path.write_text(json.dumps(policy, sort_keys=True)); raw['policy_manifest_sha256'] = sha256(policy_path.read_bytes()).hexdigest()
            selected.write_text(json.dumps(raw, sort_keys=True))
            with patch.dict(os.environ, {SELECTOR: str(selected)}):
                with self.assertRaises(ValueError): service_module.HIAAgentService._hia_read(service, {'artifact': {}})
            original = page.SOURCE.read_bytes()
            try:
                page.SOURCE.write_bytes(original + b'\n')
                with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
                    with self.assertRaises(ValueError): service_module.HIAAgentService._hia_read(service, {'artifact': {}})
            finally:
                page.SOURCE.write_bytes(original)

    def test_installed_wheel_ordinary_entry_and_packaged_bundle(self):
        folder = self.folder / 'installed'; folder.mkdir()
        build = folder / 'build-source'
        build.mkdir()
        shutil.copytree(ROOT / 'hepta', build / 'hepta', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        packaging_inputs = ('setup.py', 'pyproject.toml', 'MANIFEST.in') + tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
        for name in packaging_inputs:
            target = build / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        wheel_dir = folder / 'wheel'; wheel_dir.mkdir()
        command = [sys.executable, '-B', 'setup.py', 'bdist_wheel', '--dist-dir', str(wheel_dir), '--bdist-dir', str(folder / 'bdist')]
        result = subprocess.run(command, cwd=build, capture_output=True, timeout=120,
                                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        (folder / 'build.stdout').write_bytes(result.stdout); (folder / 'build.stderr').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        wheels = list(wheel_dir.glob('*.whl')); self.assertEqual(len(wheels), 1)
        site = folder / 'site'; site.mkdir()
        with zipfile.ZipFile(wheels[0]) as archive: archive.extractall(site)
        for name in ('artifact_page.hiaasm', 'json_wire.hiaasm'):
            self.assertEqual((site / 'hepta/_data/examples/hia_bootstrap' / name).read_bytes(),
                             (ROOT / 'examples/hia_bootstrap' / name).read_bytes())
        for source in (ROOT / 'hepta').rglob('*.py'):
            self.assertEqual((site / source.relative_to(ROOT)).read_bytes(), source.read_bytes())
        native = folder / 'native'; shutil.copytree(self.manifest.parent, native)
        child = r'''
import sys, os, json
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from hepta.hia_agent_store import AgentStore
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_artifact_page_native import SOURCE
assert 'tools' not in sys.modules and 'tests' not in sys.modules
before=installation_manifest()
store=AgentStore(sys.argv[2]); service=HIAAgentService.__new__(HIAAgentService); service.store=store
ref=store.put(('x'*511+'雪🧪'*150).encode(),'input')
arguments={'artifact':ref,'max_bytes':512}; content=bytearray(); calls=0
with patch.object(HIAAgentService,'_reference_hia_read',side_effect=AssertionError('retained page')):
 while True:
  result=service._hia_read(arguments); calls+=1; content.extend(result['content'].encode())
  if result['next_cursor'] is None: break
  arguments['cursor']=result['next_cursor']
assert bytes(content)==('x'*511+'雪🧪'*150).encode() and calls>1
store.close(); store=AgentStore(sys.argv[2]); service.store=store
with patch.object(HIAAgentService,'_reference_hia_read',side_effect=AssertionError('retained page')):
 again=service._hia_read(arguments)
assert again==result
store.close(); assert installation_manifest()==before
for name,module in list(sys.modules.items()):
 if name=='hepta' or name.startswith('hepta.'):
  path=getattr(module,'__file__',None)
  assert path is None or Path(path).resolve().is_relative_to(Path(sys.argv[1]).resolve())
print(json.dumps({'status':'PASS','calls':calls+1,'source':str(SOURCE),'installed_manifest':before},sort_keys=True))
'''
        (folder / 'installed-control.py').write_text(child)
        command = [sys.executable, '-I', '-S', '-B', '-c', child, str(site), str(folder / 'state')]
        result = subprocess.run(command, cwd=folder, env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(native / self.manifest.name)},
                                capture_output=True, timeout=30)
        (folder / 'child.stdout').write_bytes(result.stdout); (folder / 'child.stderr').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stderr, b'')
        report = json.loads(result.stdout); self.assertEqual(report['status'], 'PASS')
        self.assertTrue(Path(report['source']).is_relative_to(site))
        self.observations['installed'] = report


if __name__ == '__main__':
    unittest.main()
