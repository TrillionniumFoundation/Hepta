"""Native worker admission with the ordinary service, replay and installation."""
from __future__ import annotations

from contextlib import ExitStack
from hashlib import sha256
import io
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

from hepta.hia_agent_store import wire, digest
from hepta.hia_worker_request_native import (SOURCE, SCHEMA, SELECTOR,
    NativeWorkerRequest, installed_worker_request, buffer_sizes)

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_WORKER_REQUEST_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_WORKER_REQUEST_COLD_REPORT'


def request(arguments=None, *, tool='hia_describe', catalog='2' * 64):
    value = {'schema': 'hia-agent-worker-request-v1', 'tool': tool,
             'arguments': {'section': 'manifest'} if arguments is None else arguments,
             'profile_sha256': '1' * 64, 'catalog_sha256': catalog}
    value['request_sha256'] = sha256(wire(value)).hexdigest()
    return value


def interpreted(raw, catalog=None):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(SOURCE.read_bytes())
    _output, scratch = buffer_sizes(len(raw))
    state = bytearray(scratch)
    struct.pack_into('<2Q', state, 0, int(catalog is not None), sys.get_int_max_str_digits())
    if catalog is not None:
        state[scratch - 16384 + 64:scratch - 16384 + 128] = catalog.encode()
    owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(b'\xa5' * 8192)), _Owner(-3, state)]
    machine = _Machine(checked, 50_000_000, 64 << 20, None, 128)
    code = machine.invoke(checked.as_dict()['functions'][0],
                          [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
    return code, bytes(owners[1].data)


class WorkerRequestSourceTests(unittest.TestCase):
    def test_generated_source_and_independent_VM(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_worker_request import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        raw = b'{"z":1e15,"a":[-0,-0.0,1.25]}'
        expected = b'{"a":[0,-0.0,1.25],"z":1000000000000000.0}'
        code, output = interpreted(raw)
        self.assertEqual((code, output[:code]), (len(expected), expected))
        value = request({'z': 0, 'a': 1.25})
        code, output = interpreted(json.dumps(value).encode(), '2' * 64)
        expected = wire({key: item for key, item in value.items() if key != 'request_sha256'})
        self.assertEqual((code, output[:code]), (len(expected), expected))
        value['request_sha256'] = '0' * 64
        self.assertEqual(interpreted(wire(value), '2' * 64)[0], 0xffffffe9)

    def test_unqualified_build_creates_no_output(self):
        from tools.build_hia_json_preflight import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'compiler').write_bytes(b'unqualified')
            (root / 'cold').write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(root / 'out', root / 'compiler', root / 'cold', candidate='worker-request')
            self.assertFalse((root / 'out').exists())


class WorkerRequestNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development manifest cannot override requested cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-worker-request-')
        cls.folder = Path(cls.temporary.name)
        cls.serial = 0
        if development:
            cls.manifest = Path(development)
        elif cold:
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='worker-request')
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, _ = compile_stage(cls.folder, 'request', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_text(json.dumps({'schema': SCHEMA, 'source_sha256': sha256(SOURCE.read_bytes()).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(compiler.read_bytes()).hexdigest()}))
        cls.native = installed_worker_request(str(cls.manifest))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        type(self).serial += 1
        self.case = self.folder / ('case-' + str(self.serial))
        self.case.mkdir()

    def call_worker(self, raw, state, *, selected=True, block_old=True, manifest=None):
        from hepta import hia_agent_worker as worker
        from hepta.hia_native_helpers import ABI, SCHEMA as BUNDLE_SCHEMA, TARGET
        stdout, stderr = io.BytesIO(), io.StringIO()
        arguments = ['--state-root', str(state), '--request-json-stdin']
        helpers = []
        if selected:
            # The worker now admits only an explicit operator-pinned bundle.
            # This changes fixture selection, not any request/replay assertion.
            path = Path(manifest or self.manifest).absolute()
            expected = sha256(path.read_bytes()).hexdigest() if path.is_file() else '0' * 64
            helpers.append({'selector': SELECTOR, 'manifest_path': str(path),
                            'manifest_sha256': expected})
        # The existing selected-journal caller qualification also runs this
        # ordinary worker fixture. Preserve that explicit selection inside the
        # same bundle; production workers still reject every ambient selector.
        journal_selector = 'HEPTA_HIA_AGENT_JOURNAL_MANIFEST'
        if os.environ.get(journal_selector):
            journal = Path(os.environ[journal_selector]).resolve(strict=True)
            helpers.append({'selector': journal_selector, 'manifest_path': str(journal),
                            'manifest_sha256': sha256(journal.read_bytes()).hexdigest()})
        if helpers:
            bundle = self.folder / 'worker-helpers.json'
            encoded = wire({'schema': BUNDLE_SCHEMA, 'target': TARGET, 'abi': ABI,
                            'helpers': helpers})
            bundle.write_bytes(encoded)
            arguments += ['--native-helpers-manifest', str(bundle),
                          '--expected-native-helpers-sha256', sha256(encoded).hexdigest()]
        environment = {key: value for key, value in os.environ.items()
                       if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        with ExitStack() as stack:
            stack.enter_context(patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(raw))))
            stack.enter_context(patch.object(sys, 'stdout', SimpleNamespace(buffer=stdout)))
            stack.enter_context(patch.object(sys, 'stderr', stderr))
            stack.enter_context(patch.dict(os.environ, environment, clear=True))
            if selected and block_old:
                for name in ('decode_data', 'keys', 'canonical_digest', 'sha256'):
                    stack.enter_context(patch.object(worker, name,
                        side_effect=AssertionError('old worker request owner called: ' + name)))
            code = worker.main(arguments)
        output = stdout.getvalue()
        return code, json.loads(output) if output else None, stderr.getvalue()

    def test_ordinary_worker_native_admission_retained_replay_conflict_and_unknown(self):
        from hepta.hia_agent_service import HIAAgentService
        state = self.case / 'state'
        service = HIAAgentService(state)
        catalog, profile = service.catalog_sha256, service.profiles['artifact']
        service.close()
        arguments = {'catalog_sha256': catalog, 'request_key': 'native-request-replay',
            'artifact_profile': profile, 'source': {'kind': 'utf8', 'text': 'native request bytes'}}
        raw = json.dumps(request(arguments, tool='hia_artifact', catalog=catalog)).encode()
        first = self.call_worker(raw, state)
        second = self.call_worker(raw, state)
        self.assertEqual(first[0], 0, first)
        self.assertEqual(first[1]['response']['status'], 'completed', first)
        self.assertEqual(first, second)
        db = sqlite3.connect(state / 'state.sqlite3')
        self.addCleanup(db.close)
        self.assertEqual(db.execute('SELECT count(*) FROM requests').fetchone()[0], 1)
        changed = {**arguments, 'source': {'kind': 'utf8', 'text': 'different'}}
        conflict = self.call_worker(wire(request(changed, tool='hia_artifact', catalog=catalog)), state)
        self.assertEqual(conflict[1]['response']['error']['code'], 'E_HIA_REQUEST_CONFLICT')
        held = {**arguments, 'request_key': 'held-native-intent'}
        key = digest({'tool': 'hia_artifact', 'key': held['request_key']})
        body = digest({'tool': 'hia_artifact', 'arguments': held})
        db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)', (key, body, 'hia_artifact', 'running', None, '0'))
        db.commit()
        unknown = self.call_worker(wire(request(held, tool='hia_artifact', catalog=catalog)), state)
        self.assertEqual(unknown[1]['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
        self.assertEqual(unknown[1]['response']['error']['retry_action'], 'observe_original')
        self.assertEqual(db.execute('SELECT state,response FROM requests WHERE key=?', (key,)).fetchone(), ('running', None))

    def test_errors_keep_original_report_correlation_and_never_create_store(self):
        value = request({'z': 1, 'a': {'request_sha256': 'keep'}})
        value['request_sha256'] = '0' * 64
        raw = json.dumps(value, ensure_ascii=False).encode()
        native = self.call_worker(raw, self.case / 'native-state')
        hosted = self.call_worker(raw, self.case / 'hosted-state', selected=False)
        for result in (native, hosted):
            self.assertEqual(result[0], 0, result)
            self.assertEqual(result[1]['request_sha256'], '0' * 64)
            self.assertEqual(result[1]['response']['error']['code'], 'E_HIA_WORKER_IDENTITY')
        self.assertFalse((self.case / 'native-state').exists())
        self.assertFalse((self.case / 'hosted-state').exists())
        for raw in (b'{', b'{"a":1,"a":2}', b'1e9999', b'"\\ud800"'):
            code, report, _ = self.call_worker(raw, self.case / 'syntax-state')
            self.assertEqual((code, report), (2, None))
            self.assertFalse((self.case / 'syntax-state').exists())

    def test_selected_missing_manifest_never_falls_back(self):
        code, report, _ = self.call_worker(wire(request()), self.case / 'state', manifest=self.case / 'missing')
        self.assertEqual((code, report), (2, None))
        self.assertFalse((self.case / 'state').exists())

    def test_installed_wheel_resource_and_request_without_authoring_modules(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
        source = self.case / 'wheel-source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = (tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        packaging_python = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = self.case / 'wheels', self.case / 'installed'
        for command in ([packaging_python, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-index',
                         '--no-build-isolation', '--wheel-dir', str(wheels), str(source)],):
            result = subprocess.run(command, cwd=self.case, capture_output=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        wheel, = wheels.glob('*.whl')
        result = subprocess.run([packaging_python, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
                                 '--target', str(installed), str(wheel)], cwd=self.case, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        child = r'''import importlib.abc,sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed worker imported development authoring tools')
sys.meta_path.insert(0,NoTools())
from hepta.hia_worker_request_native import SOURCE,installed_worker_request
assert Path(sys.argv[1]) in SOURCE.parents
native=installed_worker_request(sys.argv[2])
assert native.canonicalize(b'{"z":1e15,"a":-0.0}')==b'{"a":-0.0,"z":1000000000000000.0}'
SOURCE.write_bytes(SOURCE.read_bytes()+b'\n')
try:installed_worker_request(sys.argv[2])
except ValueError:pass
else:raise AssertionError('warm loaded image hid installed source drift')
print('INSTALLED_NATIVE_REQUEST_PASS')
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', child, str(installed), str(self.manifest)],
                                cwd=self.case, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b'INSTALLED_NATIVE_REQUEST_PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
