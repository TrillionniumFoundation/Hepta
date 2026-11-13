"""Real five-family worker custody; hosted objects and persistence remain open."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from hashlib import sha256
import ast
import importlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from hepta import hia_native_helpers as authority
from hepta.hia_worker_scheduling_bundle import FAMILIES

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_WORKER_SCHEDULING_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_WORKER_SCHEDULING_DEVELOPMENT_BUNDLES'
EVIDENCE = 'HEPTA_HIA_WORKER_SCHEDULING_FIXTURE_EVIDENCE'


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


class WorkerSchedulingSourceTests(unittest.TestCase):
    def test_invalid_capsule_refuses_before_mapping_or_output_creation(self):
        from tools.build_hia_worker_scheduling_bundle import bind_scheduling_bundle
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'must-not-exist'
            for names in ({}, {'unknown': '/unused'}, {'core-lowering': '/unused', 'unknown': '/unused'}):
                with self.subTest(names=names), self.assertRaises(ValueError):
                    bind_scheduling_bundle(output, '/must-not-read', names)
                self.assertFalse(output.exists())


class WorkerSchedulingNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD), os.environ.get(DEVELOPMENT)
        if cold and development:
            raise AssertionError('development cannot override matching-source cold')
        if not cold and not development:
            raise unittest.SkipTest('requires explicit scheduling cold or development bundles')
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).absolute()
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-worker-scheduling-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.folder = Path(cls.temporary.name)
        if cold:
            from tools.build_hia_native_continuation import build
            from tools.build_hia_worker_report import build as report_build, bind_worker_bundle
            from tools.build_hia_json_preflight import build as request_build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifests = {kind: str(build(cls.folder / kind, compiler, Path(cold),
                                             in_process=True, kind=kind)) for kind in FAMILIES}
            request = request_build(cls.folder / 'request', compiler, Path(cold), candidate='worker-request')
            base = cls.folder / 'v1.json'
            base.write_text(json.dumps({'schema': authority.SCHEMA, 'target': authority.TARGET,
                'abi': authority.ABI, 'helpers': [{'selector': 'HEPTA_HIA_WORKER_REQUEST_MANIFEST',
                'manifest_path': str(request), 'manifest_sha256': digest(request)}]}))
            base.chmod(0o600)
            report_bundle = report_build(cls.folder / 'report', compiler, Path(cold))
            cls.base, _ = bind_worker_bundle(cls.folder / 'v2.json', base, report_bundle)
        else:
            value = json.loads(Path(development).read_bytes())
            if type(value) is not dict or set(value) != {'base_bundle', 'schedulers'}:
                raise ValueError('explicit complete development fixture map required')
            cls.base = Path(value['base_bundle'])
            if set(value['schedulers']) != set(FAMILIES):
                raise ValueError('all five real development families required')
            cls.manifests = {}
            for kind, original in value['schedulers'].items():
                original = Path(original)
                directory = cls.folder / kind
                shutil.copytree(original.parent, directory)
                cls.manifests[kind] = str(directory / original.name)
        cls.serial = 0

    def setUp(self):
        self.env = patch.dict(os.environ, {k: v for k, v in os.environ.items()
            if not (k.startswith('HEPTA_HIA_') and k.endswith('_MANIFEST'))}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def capsule(self, manifests=None):
        from tools.build_hia_worker_scheduling_bundle import bind_scheduling_bundle
        type(self).serial += 1
        return bind_scheduling_bundle(self.folder / ('v3-' + str(self.serial) + '.json'),
                                       self.base, self.manifests if manifests is None else manifests)

    def selection(self, kind):
        module = importlib.import_module('hepta.hia_' + FAMILIES[kind][0] + '_selection')
        namespace = vars(importlib.import_module('hepta.' + FAMILIES[kind][1]))
        return module, namespace, getattr(module, 'installed_' + FAMILIES[kind][0])

    def test_all_five_original_callers_without_host_scheduler_or_control(self):
        from hepta import hia_program_native as backend, hia_native_byte_abi as byte, hia_machine_elf as elf
        from hepta import hia_opcodes
        from hepta.hia_program import verify_program
        from hepta.hia_core_lowering_native import LoweringSession
        from hepta.hia_native_continuation_inprocess import InProcessContinuation
        from tests.test_hia_native_byte_abi import byte_program
        program = verify_program(byte_program())
        expected = backend.emit_program_machine(program, foreign_buffer_exports=(('copy_bytes', 4096),))
        path, pin = self.capsule()
        counts = {kind: [0, 0, 0] for kind in FAMILIES}
        actual_run = InProcessContinuation.run
        def forbidden(*args, **kwargs):
            raise AssertionError('retained scheduler/control/process entered')
        with authority.native_helpers_scope(str(path), pin) as binding:
            owners = {id(owner): kind for (_path, kind), owner in binding.schedulers.items()}
            def observed(engine, session):
                value = actual_run(engine, session)
                row = counts[owners[id(session.owner)]]
                row[0] += 1
                row[1] += session.native_observation[3]
                row[2] += session.native_observation[4]
                return value
            with ExitStack() as stack:
                stack.enter_context(patch.object(InProcessContinuation, 'run', observed))
                stack.enter_context(patch.object(subprocess, 'Popen', forbidden))
                for name in ('run', 'step', 'handoff'):
                    stack.enter_context(patch.object(LoweringSession, name, forbidden))
                for base in (backend._Function, backend._Emitter):
                    for name, method in tuple(vars(base).items()):
                        if inspect.isfunction(method) and name != '__new__':
                            stack.enter_context(patch.object(base, name, forbidden))
                for module, names in [(byte, ('_reference_normalize_exports', '_reference_emit_wrapper')),
                        (elf, ('_reference_name', '_reference_exact_int', '_reference_write_elf_object'))]:
                    for name in names:
                        stack.enter_context(patch.object(module, name, forbidden))
                actual = backend.emit_program_machine(program, foreign_buffer_exports=(('copy_bytes', 4096),))
                hia_opcodes.validate_execution_observation('returned',
                    dict.fromkeys(hia_opcodes.EXECUTION_RESOURCE_FIELDS, 0),
                    steps=1, max_steps=10, max_heap_bytes=64)
            for field in expected.__dataclass_fields__:
                if field != 'implementation_sha256':
                    self.assertEqual(getattr(actual, field), getattr(expected, field), field)
            self.assertNotEqual(actual.implementation_sha256, expected.implementation_sha256)
            self.assertTrue(all(all(value > 0 for value in row) for row in counts.values()), counts)
            self.assertEqual(authority.native_helpers_identity(), {'native_helpers_sha256': pin})
        print('WORKER_NATIVE_FIVE_FAMILY_COUNTS', json.dumps(counts, sort_keys=True))

    def test_only_registered_path_kind_and_original_namespace_are_selected(self):
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        path, pin = self.capsule({'execution-observation': self.manifests['execution-observation']})
        with authority.native_helpers_scope(str(path), pin):
            with patch.object(NativeHiaJsonImage, '__init__', side_effect=AssertionError('general image loader')):
                for kind in FAMILIES:
                    module, namespace, installed = self.selection(kind)
                    if kind == 'execution-observation':
                        owner = installed(self.manifests[kind], namespace)
                        self.assertIs(installed(self.manifests[kind], namespace), owner)
                    else:
                        with self.subTest(kind=kind), self.assertRaises(ValueError):
                            installed(self.manifests[kind], namespace)
                    with self.assertRaises(ValueError):
                        installed(self.manifests[kind], dict(namespace))
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        installed('/must-not-open', namespace)

    def test_held_old_owner_and_engine_refuse_before_any_native_entry(self):
        from hepta.hia_core_lowering_native import LoweringSession
        from hepta.hia_execution_observation_selection import _OWNER
        from hepta import hia_opcodes
        _module, namespace, installed = self.selection('execution-observation')
        old = installed(self.manifests['execution-observation'], namespace)
        held = LoweringSession(old, old.modes['need']['number'], (True, 'unused'))
        path, pin = self.capsule()
        with authority.native_helpers_scope(str(path), pin), \
                patch.object(old._continuation, '_entry', side_effect=AssertionError('unregistered native entry')):
            with self.assertRaises(ValueError):
                old._continuation.run(held)
            self.assertTrue(held.finished)
            token = _OWNER.set(old)
            try:
                with self.assertRaises(ValueError):
                    hia_opcodes.validate_execution_observation('returned',
                        dict.fromkeys(hia_opcodes.EXECUTION_RESOURCE_FIELDS, 0),
                        steps=1, max_steps=10, max_heap_bytes=64)
            finally:
                _OWNER.reset(token)

    def test_host_scheduler_cannot_drive_registered_or_fake_observation_sessions(self):
        from hepta.hia_core_lowering_native import LoweringSession
        path, pin = self.capsule()
        with authority.native_helpers_scope(str(path), pin):
            _, namespace, installed = self.selection('execution-observation')
            owner = installed(self.manifests['execution-observation'], namespace)
            for action in ('run', 'step', 'handoff', 'observe'):
                session = LoweringSession(owner, owner.modes['need']['number'], (True, 'unused'))
                with self.subTest(action=action), self.assertRaises(ValueError):
                    getattr(session, action)(bytes(128)) if action == 'step' else getattr(session, action)()
                self.assertTrue(session.finished)

    def test_registered_owner_peer_and_namespace_cannot_be_rebound(self):
        from hepta.hia_core_lowering_native import LoweringSession
        path, pin = self.capsule()
        with authority.native_helpers_scope(str(path), pin):
            _, namespace, installed = self.selection('execution-observation')
            owner = installed(self.manifests['execution-observation'], namespace)
            _, other_namespace, other_installed = self.selection('core-lowering')
            other = other_installed(self.manifests['core-lowering'], other_namespace)
            session = LoweringSession(owner, owner.modes['need']['number'], (True, 'unused'))
            with patch.object(other._continuation, '_entry', side_effect=AssertionError('wrong peer entered')):
                with self.assertRaises(ValueError):
                    other._continuation.run(session)
            self.assertTrue(session.finished)
            for attribute, replacement in [('_continuation', other._continuation),
                                            ('namespace', dict(namespace))]:
                original = getattr(owner, attribute)
                try:
                    setattr(owner, attribute, replacement)
                    with self.subTest(attribute=attribute), self.assertRaises(ValueError):
                        owner.invoke('need', (True, 'unused'))
                    with self.assertRaises(ValueError):
                        installed(self.manifests['execution-observation'], namespace)
                finally:
                    setattr(owner, attribute, original)
            self.assertIs(installed(self.manifests['execution-observation'], namespace), owner)

    def test_scope_owner_process_thread_and_expired_owner_cannot_be_reused(self):
        path, pin = self.capsule()
        _, namespace, installed = self.selection('execution-observation')
        with authority.native_helpers_scope(str(path), pin):
            owner = installed(self.manifests['execution-observation'], namespace)
            def foreign():
                with self.assertRaisesRegex(ValueError, 'original process and thread'):
                    owner.invoke('need', (True, 'unused'))
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(foreign).result(timeout=10)
            child = os.fork()
            if child == 0:
                try:
                    owner.invoke('need', (True, 'unused'))
                except ValueError:
                    os._exit(0)
                os._exit(1)
            _, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        with self.assertRaisesRegex(ValueError, 'original worker scope'):
            owner.invoke('need', (True, 'unused'))
        with authority.native_helpers_scope(str(path), pin):
            with self.assertRaisesRegex(ValueError, 'original worker scope'):
                owner.invoke('need', (True, 'unused'))

    def test_last_image_drift_and_runtime_pin_refuse_before_first_mapping(self):
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        path, pin = self.capsule()
        outer = Path(self.manifests['execution-observation'])
        record = json.loads(outer.read_bytes())
        image = outer.parent / record['image_path']
        raw, mode = image.read_bytes(), image.stat().st_mode & 0o777
        image.chmod(0o600)
        try:
            image.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            with patch.object(NativeHiaJsonImage, '__init__', side_effect=AssertionError('premature mapping')):
                with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                    with authority.native_helpers_scope(str(path), pin):
                        self.fail('changed last image admitted')
        finally:
            image.write_bytes(raw)
            image.chmod(mode)
        value = json.loads(path.read_bytes())
        value['runtime_sha256']['hepta/hia_worker_scheduling_bundle.py'] = '0' * 64
        other = self.folder / ('wrong-runtime-' + str(self.serial) + '.json')
        other.write_text(json.dumps(value))
        other.chmod(0o600)
        with patch.object(NativeHiaJsonImage, '__init__', side_effect=AssertionError('premature mapping')):
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                with authority.native_helpers_scope(str(other), digest(other)):
                    self.fail('changed runtime admitted')

    def test_selector_drift_and_capsule_file_drift_cannot_attest_success(self):
        path, pin = self.capsule()
        before = dict(os.environ)
        with authority.native_helpers_scope(str(path), pin):
            _, namespace, installed = self.selection('execution-observation')
            owner = installed(self.manifests['execution-observation'], namespace)
            os.environ['HEPTA_HIA_UNKNOWN_MANIFEST'] = '/must-not-use'
            with self.assertRaisesRegex(ValueError, 'selection changed'):
                owner.invoke('need', (True, 'unused'))
            os.environ.pop('HEPTA_HIA_UNKNOWN_MANIFEST')
            raw = path.read_bytes()
            try:
                path.write_bytes(raw + b' ')
                with self.assertRaisesRegex(ValueError, 'inputs changed'):
                    authority.native_helpers_identity()
            finally:
                path.write_bytes(raw)
        self.assertEqual(dict(os.environ), before)

    def test_original_ordinary_worker_sqlite_reopen_replay_conflict_and_unknown(self):
        # Execute the complete original test body, with only the administrator
        # capsule changed. This is hosted SQLite parity, not its replacement.
        from tests.test_hia_worker_report_native import WorkerReportNativeTests
        path, pin = self.capsule()
        case = WorkerReportNativeTests('test_ordinary_sqlite_reopen_replay_conflict_and_unknown')
        type(self).serial += 1
        case.folder = self.folder / ('original-sqlite-' + str(self.serial))
        case.folder.mkdir(mode=0o700)
        case.worker_bundle, case.worker_pin = path, pin
        case.test_ordinary_sqlite_reopen_replay_conflict_and_unknown()

    def test_two_original_no_child_compiler_scripts_inside_real_worker_scope(self):
        from tools.qualify_hia_continuation_no_child import PREFIX, FAMILIES as FOUR
        from tests.test_hia_program_native import minimal_document
        from tests.test_hia_native_byte_abi import byte_program
        path, pin = self.capsule()
        combined = {family: dict(invocations=0, calls=0, handoffs=0) for family in FOUR}
        for module, method, document in (
                ('test_hia_program_native', 'test_object_build_in_fresh_process_prohibits_llvm_import_and_process_launch', minimal_document()),
                ('test_hia_native_byte_abi', 'test_direct_byte_object_emission_needs_no_llvm_or_subprocess', byte_program())):
            tree = ast.parse((ROOT / 'tests' / (module + '.py')).read_bytes())
            node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == method)
            assignment = next(n for n in node.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'script' for t in n.targets))
            original = ast.literal_eval(assignment.value)
            folder = self.folder / ('worker-no-child-' + module)
            folder.mkdir(mode=0o700)
            (folder / 'original-script.py').write_text(original)
            prefix = PREFIX.replace('SITE_PATH', repr(str(ROOT))).replace('MANIFESTS',
                repr({kind: self.manifests[kind] for kind in FOUR}))
            suffix = '\nassert all(v["invocations"]>0 and v["calls"]>0 for v in counts.values()),counts\n'
            suffix += 'assert not any(n.startswith("tools.") and n!="tools.hia_core_reference" for n in sys.modules)\n'
            suffix += 'assert native_helpers_identity()==' + repr({'native_helpers_sha256': pin}) + '\n'
            suffix += 'print("WORKER_NO_CHILD_COUNTS",json.dumps(counts,sort_keys=True))\n'
            prologue = 'import sys\nsys.path.insert(0,' + repr(str(ROOT)) + ')\n'
            prologue += 'from hepta.hia_native_helpers import native_helpers_scope,native_helpers_identity\n'
            prologue += 'with native_helpers_scope(' + repr(str(path)) + ',' + repr(pin) + '):\n'
            script = folder / 'captured-caller.py'
            script.write_text(prologue + textwrap.indent(prefix + '\n' + original + suffix, ' '))
            env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_')
                   and k not in ('PYTHONPATH', 'PYTHONHOME')}
            env.update(PATH='', PYTHONDONTWRITEBYTECODE='1')
            result = subprocess.run([__import__('sys').executable, '-B', '-I', '-S', str(script),
                json.dumps(document), str(folder / 'output.o')], cwd=folder, env=env,
                capture_output=True, timeout=20, start_new_session=True)
            (folder / 'stdout.log').write_bytes(result.stdout)
            (folder / 'stderr.log').write_bytes(result.stderr)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            lines = [line for line in result.stdout.decode().splitlines()
                     if line.startswith('WORKER_NO_CHILD_COUNTS ')]
            self.assertEqual(len(lines), 1)
            counts = json.loads(lines[0].split(' ', 1)[1])
            self.assertEqual(set(counts), set(FOUR))
            for family in FOUR:
                self.assertGreater(counts[family]['invocations'], 0)
                self.assertGreater(counts[family]['calls'], 0)
                for field in combined[family]:
                    combined[family][field] += counts[family][field]
        self.assertTrue(all(all(v > 0 for v in counts.values()) for counts in combined.values()), combined)
        print('WORKER_ORIGINAL_NO_CHILD_COMBINED_COUNTS', json.dumps(combined, sort_keys=True))
