"""Real Page image/Worker custody and failure-acknowledgement controls."""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
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

from hepta import hia_artifact_page_native as page
from hepta import hia_native_helpers as authority
from hepta.hia_artifact_page_worker_bundle import SCHEMA as WORKER_SCHEMA
from hepta.hia_json_preflight_native import NativeHiaJsonImage

ROOT = Path(__file__).resolve().parents[1]
INPUTS = 'HEPTA_HIA_ARTIFACT_PAGE_COMPONENT_INPUTS'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pinned(path):
    raw = Path(path).read_bytes()
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


@contextmanager
def clean_selection():
    with patch.dict(os.environ, {k: v for k, v in os.environ.items()
                                if not k.startswith('HEPTA_HIA_')}, clear=True):
        yield


def _loss_case(manifest, output):
    """One real SQL insert is followed by a malformed native acknowledgement."""
    owner = page.installed_artifact_page(manifest)
    db = sqlite3.connect(':memory:', isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute('CREATE TABLE cursors(id TEXT PRIMARY KEY,artifact_id TEXT,sha256 TEXT,offset INTEGER)')
    calls = []
    class Database:
        def execute(self, query, values):
            calls.append(query)
            return db.execute(query, values)
    ref = {'id': 'real-insert', 'sha256': sha256(b'A' * 600).hexdigest(), 'uri': 'hia://real'}
    service = SimpleNamespace(store=SimpleNamespace(get=lambda _: (b'A' * 600, {}),
                                                   db=Database()))
    session = page.PageSession(owner, service, {'artifact': ref, 'max_bytes': 512})
    for _ in range(10000):
        assert session.step() == 1
        opcode = struct.unpack_from('<Q', session.workspace, 8)[0]
        session.observe()
        if opcode == 13:
            break
    else:
        raise AssertionError('actual Page never issued its cursor insertion')
    assert len(calls) == 1 and calls[0].startswith('INSERT OR IGNORE')
    assert db.execute('SELECT count(*) FROM cursors').fetchone()[0] == 1
    malformed = bytearray(session.packet)
    sequence = struct.unpack_from('<Q', malformed, 8)[0]
    struct.pack_into('<Q', malformed, 8, sequence + 1)
    refused = False
    try:
        session.step(bytes(malformed))
    except page.ArtifactPageUnknown:
        refused = True
    assert refused and session.finished and session._delivery.loss is not None
    repeated = False
    try:
        session.step()
    except BaseException:
        repeated = True
    assert repeated and len(calls) == 1
    rows = [dict(row) for row in db.execute('SELECT * FROM cursors')]
    assert len(rows) == 1 and rows[0]['offset'] == 512
    record = {'actual_insert_calls': len(calls), 'rows': rows,
              'malformed_ack_refused': refused, 'reentry_refused': repeated,
              'unknown_preserved': session._delivery.loss is not None}
    Path(output).write_bytes(encoded(record))
    db.close()
    return record


class ArtifactPageWorkerSourceTests(unittest.TestCase):
    def test_native_manifest_author_and_closed_tables(self):
        from tools.generate_hia_artifact_page_manifest import render, SOURCE_PATH, TABLE_PATH, MODEL_PATH
        source, table, spec = render()
        self.assertEqual((ROOT / SOURCE_PATH).read_bytes(), source)
        self.assertEqual((ROOT / TABLE_PATH).read_bytes(), table)
        self.assertEqual((ROOT / MODEL_PATH).read_bytes(), encoded(spec))
        self.assertEqual([(r['mode'], r['role']) for r in spec['records']],
                         [(1, 1), (1, 2), (2, 0), (3, 0)])
        self.assertIn('opaque exact bytes', spec['scheduler_admission'])

    def test_public_page_factory_is_its_exact_five_field_contract(self):
        from hepta.hia_artifact_page_policy_native import NativeArtifactPagePolicy, SOURCE, SCHEMA
        self.assertIs(page.SOURCE, SOURCE)
        self.assertEqual(page.POLICY_SCHEMA, SCHEMA)
        self.assertEqual(SCHEMA, 'hepta.hia.artifact-page-native.v2')
        self.assertTrue(issubclass(NativeArtifactPagePolicy, NativeHiaJsonImage))


class ArtifactPageWorkerNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get(INPUTS)
        if configured is None:
            raise unittest.SkipTest('requires explicit actual Page component inputs')
        cls.input_path = Path(configured).resolve(strict=True)
        cls.input_raw = cls.input_path.read_bytes()
        cls.input = json.loads(cls.input_raw)
        cls.compiler = Path(cls.input['compiler']).resolve(strict=True)
        cls.compiler_raw = cls.compiler.read_bytes()
        if pinned(cls.compiler) != cls.input['compiler_identity']:
            raise AssertionError('component compiler input differs')
        cls.manifest = Path(cls.input['page_bundle']).resolve(strict=True)
        cls.output = Path(cls.input['output']).absolute()
        cls.output.mkdir(mode=0o700)
        cls.source_before = {p: (ROOT / p).read_bytes() for p in (
            'hepta/hia_artifact_page_native.py', 'hepta/hia_artifact_page_policy_native.py',
            'hepta/hia_artifact_page_worker_bundle.py', 'hepta/hia_worker_bundle.py',
            'hepta/hia_native_helpers.py', 'tools/generate_hia_artifact_page_manifest.py',
            'tools/build_hia_artifact_page_worker.py',
            'examples/hia_bootstrap/artifact_page.hepta',
            'examples/hia_bootstrap/json_wire.hepta',
            'examples/hia_bootstrap/source_artifact_page_manifest.hepta',
            'examples/hia_bootstrap/artifact_page_manifest_tables.hiastd',
        )}
        cls.products = {}
        from hepta import hia_worker_request_native as request
        cls.request_manifest = cls._compile('request', request.SOURCE, request.SCHEMA,
                                            'worker-request.image.bin')
        from hepta import hia_worker_report_native as report
        policy = cls._compile('report-policy', report.SOURCE, report.POLICY_SCHEMA,
                              'worker-report.image.bin')
        cls.report_root = cls.output / 'report'
        cls.report_root.mkdir()
        for name, child in (('policy', policy), ('wire', cls.manifest.parent / 'wire/manifest.json')):
            dest = cls.report_root / name
            dest.mkdir()
            item = json.loads(child.read_bytes())
            (dest / 'manifest.json').write_bytes(child.read_bytes())
            (dest / item['image_path']).write_bytes((child.parent / item['image_path']).read_bytes())
        report_value = {'schema': report.SCHEMA}
        for name in ('policy', 'wire'):
            report_value[name + '_manifest'] = name + '/manifest.json'
            report_value[name + '_manifest_sha256'] = sha256(
                (cls.report_root / name / 'manifest.json').read_bytes()).hexdigest()
        (cls.report_root / 'manifest.json').write_bytes(encoded(report_value))
        cls.base = cls.output / 'helpers.json'
        cls.base.write_bytes(encoded({
            'schema': authority.SCHEMA, 'target': authority.TARGET, 'abi': authority.ABI,
            'helpers': [{'selector': request.SELECTOR,
                         'manifest_path': str(cls.request_manifest),
                         'manifest_sha256': sha256(cls.request_manifest.read_bytes()).hexdigest()}],
        }))
        cls.report_wrapper = cls.output / 'report.json'
        cls.report_wrapper.write_bytes(encoded({
            'schema': 'hepta.hia.native-helpers.v2', 'target': authority.TARGET, 'abi': authority.ABI,
            'helpers_bundle': str(cls.base), 'helpers_bundle_sha256': sha256(cls.base.read_bytes()).hexdigest(),
            'report_bundle': str(cls.report_root / 'manifest.json'),
            'report_bundle_sha256': sha256((cls.report_root / 'manifest.json').read_bytes()).hexdigest(),
        }))
        cls.native_manifest = cls._compile(
            'native-manifest', ROOT / 'examples/hia_bootstrap/source_artifact_page_manifest.hepta',
            'hepta.hia.artifact-page-manifest-component.v1', 'manifest.flat')
        value = json.loads(cls.native_manifest.read_bytes())
        cls.framer = NativeHiaJsonImage(
            (cls.native_manifest.parent / value['image_path']).read_bytes(), value['image_sha256'])
        cls.serial = 0

    @classmethod
    def _compile(cls, name, source, schema, image_name):
        from tools.qualify_hia_selfhost import compile_stage
        from tools.build_hia_source_build import _check_pack_output
        folder = cls.output / name
        folder.mkdir()
        raw = source.read_bytes()
        image, receipt = compile_stage(folder, name, cls.compiler, raw)
        result = image.read_bytes()
        full = (folder / (name + '.output.bin')).read_bytes()
        if _check_pack_output(receipt, full, artifact=cls.compiler_raw, source=raw) != result:
            raise AssertionError('actual component compile output differs')
        target = folder / image_name
        target.write_bytes(result)
        manifest = folder / 'manifest.json'
        manifest.write_bytes(encoded({
            'schema': schema, 'source_sha256': sha256(raw).hexdigest(),
            'image_path': image_name, 'image_sha256': sha256(result).hexdigest(),
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
        }))
        cls.products[name] = {'source': str(source), 'source_identity': pinned(source),
                              'image': str(target), 'image_identity': pinned(target),
                              'compile_receipt': receipt}
        return manifest

    @classmethod
    def tearDownClass(cls):
        if cls.input_path.read_bytes() != cls.input_raw or cls.compiler.read_bytes() != cls.compiler_raw:
            raise AssertionError('component input changed')
        if any((ROOT / p).read_bytes() != raw for p, raw in cls.source_before.items()):
            raise AssertionError('actual Page component sources changed')
        (cls.output / 'actual-native-products.json').write_bytes(encoded(cls.products))

    def _workspace(self, label, *, report=False):
        type(self).serial += 1
        target = self.output / (str(type(self).serial) + '-' + label)
        target.mkdir()
        shutil.copytree(self.manifest.parent, target / 'page')
        base = self.report_wrapper if report else self.base
        from tools.build_hia_artifact_page_worker import build
        wrapper = build(target / 'page-worker.json', base_bundle=base,
                        base_sha256=sha256(base.read_bytes()).hexdigest(),
                        page_bundle=target / 'page/manifest.json')
        return target, wrapper

    def _rebind(self, wrapper):
        value = json.loads(wrapper.read_bytes())
        target = Path(value['page_bundle'])
        record = json.loads(target.read_bytes())
        for name in ('policy', 'wire'):
            child = target.parent / record[name + '_manifest']
            record[name + '_manifest_sha256'] = sha256(child.read_bytes()).hexdigest()
        target.write_bytes(encoded(record))
        value['page_bundle_sha256'] = sha256(target.read_bytes()).hexdigest()
        wrapper.write_bytes(encoded(value))

    def _scope(self, wrapper):
        return authority.native_helpers_scope(str(wrapper), sha256(wrapper.read_bytes()).hexdigest())

    def test_scope_owns_same_page_and_wire_instances(self):
        folder, wrapper = self._workspace('owned')
        ref = {'id': 'empty', 'sha256': sha256(b'').hexdigest(), 'uri': 'hia://empty'}
        service = SimpleNamespace(store=SimpleNamespace(get=lambda _: (b'', {})))
        with clean_selection(), self._scope(wrapper) as binding:
            first = page.installed_artifact_page(folder / 'page/manifest.json')
            second = page.installed_artifact_page(folder / 'page/manifest.json')
            self.assertIs(first, second)
            self.assertEqual(first.read(service, {'artifact': ref}), {
                'artifact': ref, 'encoding': 'utf8', 'content': '', 'next_cursor': None})
            self.assertEqual(binding.check_scheduling_companion(),
                             {page.SELECTOR: str(folder / 'page/manifest.json')})
            binding.check()

    def test_report_and_page_share_only_exact_wire_identity(self):
        folder, wrapper = self._workspace('report-shared', report=True)
        with clean_selection(), self._scope(wrapper) as binding:
            native = page.installed_artifact_page(folder / 'page/manifest.json')
            selected = Path(os.environ['HEPTA_HIA_JSON_WIRE_MANIFEST'])
            self.assertEqual(selected, self.report_root / 'wire/manifest.json')
            self.assertEqual(native.wire.image_sha256,
                             json.loads(selected.read_bytes())['image_sha256'])
            binding.check()
        folder, wrapper = self._workspace('report-compiler-refusal', report=True)
        for name in ('policy', 'wire'):
            path = folder / 'page' / name / 'manifest.json'
            item = json.loads(path.read_bytes())
            item['compiler_sha256'] = '0' * 64
            path.write_bytes(encoded(item))
        self._rebind(wrapper)
        with clean_selection(), self.assertRaisesRegex(ValueError, 'wire identities differ'):
            with self._scope(wrapper):
                self.fail('different compiler identity entered Page Worker scope')

    def test_changed_inputs_fail_even_after_mapping(self):
        for relative in ('page-worker.json', 'page/manifest.json',
                         'page/policy/manifest.json', 'page/policy/artifact-page-policy.image.bin',
                         'page/wire/manifest.json', 'page/wire/json-wire.image.bin'):
            with self.subTest(path=relative):
                folder, wrapper = self._workspace('late')
                with clean_selection(), self._scope(wrapper) as binding:
                    selected = folder / relative
                    old = selected.read_bytes()
                    selected.write_bytes(old + b'x')
                    with self.assertRaises(ValueError):
                        binding.check()
                    with self.assertRaises(ValueError):
                        binding.check_scheduling_companion()

    def test_bad_pins_paths_and_compiler_disagreement_fail_before_selection(self):
        for failure in ('bundle-pin', 'child-pin', 'parent-path', 'mixed-compilers',
                        'missing-wire', 'recursive-base'):
            with self.subTest(case=failure):
                folder, wrapper = self._workspace(failure)
                page_path = folder / 'page/manifest.json'
                value = json.loads(page_path.read_bytes())
                wrapper_value = json.loads(wrapper.read_bytes())
                if failure == 'bundle-pin':
                    wrapper_value['page_bundle_sha256'] = '0' * 64
                elif failure == 'child-pin':
                    value['wire_manifest_sha256'] = '0' * 64
                elif failure == 'parent-path':
                    value['wire_manifest'] = '../wire/manifest.json'
                elif failure == 'mixed-compilers':
                    path = folder / 'page/wire/manifest.json'
                    item = json.loads(path.read_bytes())
                    item['compiler_sha256'] = '0' * 64
                    path.write_bytes(encoded(item))
                    value['wire_manifest_sha256'] = sha256(path.read_bytes()).hexdigest()
                elif failure == 'missing-wire':
                    (folder / 'page/wire/manifest.json').unlink()
                elif failure == 'recursive-base':
                    recursive = folder / 'recursive.json'
                    recursive.write_bytes(wrapper.read_bytes())
                    wrapper_value['base_bundle'] = str(recursive)
                    wrapper_value['base_bundle_sha256'] = sha256(recursive.read_bytes()).hexdigest()
                page_path.write_bytes(encoded(value))
                if failure != 'bundle-pin':
                    wrapper_value['page_bundle_sha256'] = sha256(page_path.read_bytes()).hexdigest()
                wrapper.write_bytes(encoded(wrapper_value))
                with clean_selection(), self.assertRaises((ValueError, OSError)):
                    with self._scope(wrapper):
                        self.fail('invalid Page Worker entered scope')
                self.assertIsNone(authority._ACTIVE)

    def test_native_exception_ack_preserves_the_original_exception(self):
        owner = page.installed_artifact_page(self.manifest)
        error = RuntimeError('actual foreign failure')
        calls = []
        def get(_):
            calls.append('get')
            raise error
        service = SimpleNamespace(store=SimpleNamespace(get=get))
        session = page.PageSession(owner, service, {'artifact': {'id': 'x'}})
        with clean_selection(), self.assertRaises(RuntimeError) as caught:
            session.run()
        self.assertIs(caught.exception, error)
        self.assertEqual(calls, ['get'])
        self.assertTrue(session.finished)
        self.assertIsNone(session._pending_foreign)
        self.assertIsNone(session._delivery.loss)
        self.assertEqual(struct.unpack_from('<Q', session.workspace, 24)[0], 4294967295)

    def test_real_insert_with_lost_ack_stays_unknown_and_never_replays(self):
        output = self.output / 'actual-lost-insert-ack.json'
        code = ('from tests.test_hia_artifact_page_worker_custody import _loss_case;'
                'import sys;_loss_case(sys.argv[1],sys.argv[2])')
        env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_')}
        result = subprocess.run([sys.executable, '-B', '-c', code, str(self.manifest), str(output)],
                                cwd=ROOT, env=env, capture_output=True, timeout=30)
        (self.output / 'actual-lost-insert-ack.stdout').write_bytes(result.stdout)
        (self.output / 'actual-lost-insert-ack.stderr').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        record = json.loads(output.read_bytes())
        self.assertEqual(record['actual_insert_calls'], 1)
        self.assertTrue(record['unknown_preserved'])

    def _frame_call(self, request):
        output = ctypes.create_string_buffer(1048576)
        workspace = ctypes.create_string_buffer(1114112)
        argv = struct.pack('<2Q', 1, 5) + b'build'
        self.assertEqual(self.framer._entry(argv, len(argv), output, len(output),
                                            workspace, len(workspace)), 0)
        struct.pack_into('<Q', workspace, 0, 1)
        result = self.framer._entry(request, len(request), output, len(output),
                                    workspace, len(workspace))
        length = struct.unpack_from('<Q', workspace, 88)[0]
        self.assertLessEqual(length, len(output))
        raw = ctypes.string_at(output, length)
        if result == 0:
            struct.pack_into('<Q', workspace, 0, 2)
            self.assertEqual(self.framer._entry(b'', 0, output, len(output),
                                                workspace, len(workspace)), 3)
        else:
            self.assertEqual(length, 0)
        return result, raw

    def test_actual_native_manifest_framing_and_refusals(self):
        from tools.generate_hia_artifact_page_manifest import TABLE_PATH, REQUEST_MAGIC
        table = (ROOT / TABLE_PATH).read_bytes()
        def frame(mode, role, pieces, *, supplied_table=table):
            return REQUEST_MAGIC + struct.pack('<3Q', mode, role, len(pieces) + 1) + b''.join(
                struct.pack('<Q', len(raw)) + raw for raw in (*pieces, supplied_table))
        leaves = []
        rows = []
        for role, name, source in ((1, 'policy', page.SOURCE),
                                   (2, 'wire', ROOT / 'examples/hia_bootstrap/json_wire.hepta')):
            child = self.manifest.parent / name / 'manifest.json'
            record = json.loads(child.read_bytes())
            pieces = [source.read_bytes(), (child.parent / record['image_path']).read_bytes(),
                      self.compiler_raw]
            request = frame(1, role, pieces)
            rc, raw = self._frame_call(request)
            self.assertEqual((rc, raw), (0, child.read_bytes()))
            leaves.append(raw)
            rows.append({'mode': 1, 'role': role, 'request': pinned_bytes(request),
                         'output': pinned_bytes(raw), 'returncode': rc})
        rc, bundle = self._frame_call(frame(2, 0, leaves))
        self.assertEqual((rc, bundle), (0, self.manifest.read_bytes()))
        rc, wrapper = self._frame_call(frame(3, 0, [self.base.read_bytes(), bundle]))
        self.assertEqual(rc, 0)
        wrapped = json.loads(wrapper)
        self.assertEqual(wrapped['base_bundle_sha256'], sha256(self.base.read_bytes()).hexdigest())
        self.assertEqual(wrapped['page_bundle_sha256'], sha256(bundle).hexdigest())
        sample = frame(2, 0, leaves)
        bad = [('magic', b'X' + sample[1:]), ('empty', b''), ('short', sample[:31]),
               ('truncated', sample[:-1]), ('trailing', sample + b'x'),
               ('unknown-mode', frame(4, 0, leaves)), ('unknown-role', frame(2, 1, leaves)),
               ('missing-child', frame(2, 0, leaves[:1])),
               ('extra-child', frame(2, 0, [*leaves, b'x'])),
               ('table-pin', frame(2, 0, leaves, supplied_table=table[:-1] + bytes([table[-1] ^ 1])))]
        for index in range(2):
            altered = json.loads(leaves[index])
            altered['compiler_sha256'] = '0' * 64
            pieces = list(leaves); pieces[index] = encoded(altered)
            bad.append(('compiler-' + str(index), frame(2, 0, pieces)))
            pieces = list(leaves); pieces[index] = pieces[index].replace(b'  "', b'   "', 1)
            bad.append(('canonical-' + str(index), frame(2, 0, pieces)))
        for label, request in bad:
            with self.subTest(case=label):
                rc, raw = self._frame_call(request)
                self.assertEqual((rc, raw), (16, b''))
                rows.append({'case': label, 'request': pinned_bytes(request), 'returncode': rc})
        (self.output / 'native-manifest-controls.json').write_bytes(encoded({
            'actual_native': True, 'positive': 4, 'negative': len(bad), 'records': rows}))

    def test_native_store_cursor_interface_and_reopen(self):
        from hepta.hia_agent_store import AgentStore, uses_native_store
        configuration = self.input['native_store']
        release = Path(configuration['release']).resolve(strict=True)
        pins = configuration['images']
        names = ('hia-agent-store', 'hia-artifact', 'hia-agent-artifact-capture')
        initializer = release / 'hia-agent-store-init'
        self.assertEqual(pinned(initializer), pins[initializer.name])
        for name in names:
            self.assertEqual(pinned(release / name), pins[name])
        selection = (release, *(pins[name]['sha256'] for name in names))
        directory = self.output / 'native-store'
        owner = page.installed_artifact_page(self.manifest)
        from hepta.hia_agent_store_native import NativeStoreConnection
        directory.mkdir(mode=0o700)
        initialized = subprocess.run([str(initializer), str(directory), 'store'], input=b'',
                                     capture_output=True, timeout=10, env={'PATH': ''})
        (self.output / 'native-store-init.stdout').write_bytes(initialized.stdout)
        (self.output / 'native-store-init.stderr').write_bytes(initialized.stderr)
        self.assertEqual(initialized.returncode, 0, initialized.stderr.decode(errors='replace'))
        with clean_selection(), patch.object(NativeStoreConnection, '_execute',
                side_effect=AssertionError('Page used native Store SQL compatibility')):
            store = AgentStore(directory, native_store=selection)
            self.assertTrue(uses_native_store(store))
            data = ('原生Page边界' * 100).encode()
            reference = store.put(data, 'bytes')
            service = SimpleNamespace(store=store)
            first = owner.read(service, {'artifact': reference, 'max_bytes': 512})
            cursor = first['next_cursor']
            self.assertIsNotNone(cursor)
            row = store.cursor_lookup(cursor)
            self.assertEqual(row['artifact_id'], reference['id'])
            first_offset = row['offset']
            self.assertGreater(first_offset, 0)
            store.close()
            reopened = AgentStore(directory, native_store=selection)
            try:
                self.assertEqual(reopened.cursor_lookup(cursor)['offset'], first_offset)
                second = owner.read(SimpleNamespace(store=reopened),
                                    {'artifact': reference, 'cursor': cursor, 'max_bytes': 512})
                self.assertEqual(first['content'].encode() + second['content'].encode(),
                                 data[:len(first['content'].encode()) + len(second['content'].encode())])
                record = {'first': first, 'second': second, 'cursor_offset': first_offset,
                          'native_store_sql_dispatch_forbidden': True,
                          'release_images': pins}
                (self.output / 'native-store-page-reopen.json').write_bytes(encoded(record))
            finally:
                reopened.close()
        for name in (*names, initializer.name):
            self.assertEqual(pinned(release / name), pins[name])


def pinned_bytes(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


if __name__ == '__main__':
    unittest.main()
