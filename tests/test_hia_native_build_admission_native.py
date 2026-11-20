"""Four complete frozen admission methods, independent VM, and real selected installation.

All original caller modules remain separate controls. These new fixtures
exercise finite observations, not an all-input equivalence theorem.
"""
from __future__ import annotations

import ast
import builtins
from collections import Counter
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
import sqlite3
from contextlib import ExitStack
import threading
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_native_build_admission_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.hia_native_build_admission_oracle import Fixture as OriginalFixture, observe_case, METHOD_SHA256
from tests.hia_native_build_admission_scenarios import scenarios
from tools import generate_hia_native_build_admission as generator

ROOT = Path(__file__).resolve().parents[1]
CALLERS = ROOT / 'tests/fixtures/hia_native_build_admission_callers_aac7550.json'
CALLERS_SHA256 = '262c3df1e051fe52797c91dd053f2d79c0704fe5b20a85f799d6d40c1c4bb2a9'
CASE_COUNT = 303
COLD = 'HEPTA_HIA_NATIVE_BUILD_ADMISSION_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_NATIVE_BUILD_ADMISSION_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_NATIVE_BUILD_ADMISSION_EVIDENCE'
VM_CASES = ('signatures_export_overrides_bad_scalar', 'signatures_params_once',
            'native_context_none', 'inputs_ordinary', 'inputs_build_reject_kind',
            'receipt_subject_reject_context')
FIXTURE_NAMES = {'_signatures': 'hia_native_build_signatures_aac7550.py.txt',
    '_native': 'hia_native_build_native_aac7550.py.txt',
    '_build_inputs': 'hia_native_build_inputs_aac7550.py.txt',
    '_build_receipt': 'hia_native_build_receipt_aac7550.py.txt'}


def vm_call(program, raw, output, state):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    owners = [_Owner(index + 1, bytearray(value))
              for index, value in enumerate((raw, output, state))]
    machine = _Machine(program, 2_000_000, 16 << 20, None, 128)
    code = machine.invoke(machine.functions['f0'],
                          [_View(owner, index != 0) for index, owner in enumerate(owners)])[0]
    if bytes(owners[0].data) != raw:
        raise AssertionError('independent VM changed immutable input')
    return code, bytes(owners[1].data), bytes(owners[2].data)


def vm_image(program):
    """Use the reference VM as the image boundary; never map native bytes here."""
    image = object.__new__(native.NativeBuildAdmission)
    image.image_sha256 = 'independent-vm-no-executable-mapping'
    image.entry_count = 0

    def entry(source, size, output, capacity, state, extent):
        image.entry_count += 1
        code, result, retained = vm_call(program, ctypes.string_at(source, size),
            ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
        ctypes.memmove(output, result, capacity)
        ctypes.memmove(state, retained, extent)
        return code

    image._entry = entry
    return image


def fixture_by_name():
    return {case["name"]: case for case in scenarios()}


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def bind_canonical_defaults(service, namespace):
    """Bind the original default-only matrix to actual selected public bridges.

Frozen originals and observations stay unchanged. Explicit replacement cases
use their separate fixture and never pass through this default-only helper.
    """
    if service is not None:
        service._native = api._NATIVE_BUILD_NATIVE_BRIDGE.__get__(service)
        service._build_inputs = api._NATIVE_BUILD_INPUTS_BRIDGE.__get__(service)
    namespace['_signatures'] = api._NATIVE_BUILD_SIGNATURES_BRIDGE


def Fixture(case):
    fixture = OriginalFixture(case)
    bind_canonical_defaults(fixture.service, fixture.namespace)
    original_providers = fixture.providers
    def providers():
        scope = original_providers()
        scope.enter_context(patch.object(api, 'sha256', fixture.namespace['sha256']))
        scope.enter_context(patch.object(api, 'reject', fixture.namespace['reject']))
        return scope
    fixture.providers = providers
    return fixture


def invoke(image):
    def owner(mode, service, arguments, namespace):
        bind_canonical_defaults(service, namespace)
        # This explicit-image fixture also serves the pre-mapping Core VM.
        # Public child bridges use that same supplied image boundary. Separate
        # public/installed controls still exercise the real pinned loader.
        with patch.dict(os.environ, {native.SELECTOR: 'explicit-fixture-image'}), \
                patch.object(native, 'installed_native_build_admission', return_value=image), \
                patch.object(api, 'sha256', namespace['sha256']), \
                patch.object(api, 'reject', namespace['reject']):
            return native.NativeBuildAdmissionFrame(image, mode, service, arguments, namespace=namespace).finish()
    return owner


def public_owner(mode, service, arguments, namespace):
    if service is not None:
        for name in ('_native', '_build_inputs', '_build_receipt',
                     '_native_reference', '_build_inputs_reference', '_build_receipt_reference'):
            setattr(service, name, getattr(api.HIAAgentService, name).__get__(service))
    with patch.object(api, 'sha256', namespace['sha256']), patch.object(api, 'reject', namespace['reject']):
        if mode == 1:
            return api._signatures(*arguments)
        return getattr(service, {2: '_native', 3: '_build_inputs', 4: '_build_receipt'}[mode])(*arguments)


class NativeBuildAdmissionSourceTests(unittest.TestCase):
    def test_source_four_complete_bodies_and_original_callers_are_exact(self):
        self.assertEqual(native.SOURCE.read_text(), render_assembly(generator.document()))
        document = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(document['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for fn in document['functions'] for b in fn['blocks']), 8192)
        self.assertLessEqual(max(len(b['params']) for fn in document['functions'] for b in fn['blocks']), 16)
        module = ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes())
        service = next(n for n in module.body if isinstance(n, ast.ClassDef) and n.name == 'HIAAgentService')
        for name, fixture_name in FIXTURE_NAMES.items():
            raw = (ROOT / 'tests/fixtures' / fixture_name).read_bytes()
            self.assertEqual(sha256(raw).hexdigest(), METHOD_SHA256[name])
            nodes = module.body if name == '_signatures' else service.body
            retained = next(n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == name + '_reference')
            retained.name = name
            self.assertEqual(ast.dump(retained), ast.dump(ast.parse(textwrap.dedent(raw.decode())).body[0]))
        self.assertEqual(sha256(CALLERS.read_bytes()).hexdigest(), CALLERS_SHA256)
        inventory = json.loads(CALLERS.read_bytes())
        self.assertEqual((inventory['ordinary_count'], inventory['separate_scope_count'], inventory['all_original_tests']), (112, 128, 240))
        from tools.qualify_hia_native_build_admission_callers import admit_original_sources
        from tools.run_hia_unittest_gate import load_declared_suite
        admit_original_sources(ROOT, {r['path']: r['sha256'] for r in inventory['modules'].values()})
        for name, record in inventory['modules'].items():
            with self.subTest(module=name):
                _suite, planned = load_declared_suite([name])
                self.assertEqual(list(planned), record['ordered_ids'])
        self.assertEqual(len(scenarios()), CASE_COUNT)

    def test_independent_VM_precedes_mapping_and_matches_original_effects(self):
        program, cases = assemble_program(native.SOURCE.read_bytes()), fixture_by_name()
        with patch.object(native.NativeBuildAdmission, '__init__', side_effect=AssertionError('native image before VM')):
            image = vm_image(program)
            for name in VM_CASES:
                with self.subTest(case=name):
                    self.assertEqual(encoded(observe_case(cases[name], invoke(image))), encoded(observe_case(cases[name])))
            self.assertGreater(image.entry_count, 0)

    def test_unselected_four_routes_are_lazy_and_unqualified_build_refuses(self):
        real_import = builtins.__import__
        def guarded(name, *arguments, **keywords):
            if name.endswith('hia_native_build_admission_native'):
                raise AssertionError('unselected admission imported optional image')
            return real_import(name, *arguments, **keywords)
        cases = fixture_by_name()
        with patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            with patch('builtins.__import__', guarded):
                for name in ('signatures_scalar', 'native_ordinary', 'inputs_ordinary', 'receipt_ordinary'):
                    self.assertEqual(encoded(observe_case(cases[name], public_owner)), encoded(observe_case(cases[name])))
        from tools.build_hia_native_build_admission import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'compiler').write_bytes(b'not a qualified compiler')
            (root / 'cold').write_text('{}')
            with self.assertRaises(ValueError):
                build(root / 'refused', root / 'compiler', root / 'cold')
            self.assertFalse((root / 'refused').exists())


class NativeBuildAdmissionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_native_build_admission import build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-native-build-admission-')
            cls.root = Path(cls.temporary.name)
        else:
            cls.root = Path(evidence).absolute()
            cls.root.mkdir(mode=0o700, exist_ok=False)
        if cold is not None:
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        else:
            compiler = Path(development)
        cls.compiler, cls.cold = compiler, cold
        cls.compiler_raw, cls.sources = compiler.read_bytes(), current_sources()
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_native_build_admission(str(cls.manifest))
        cls.program = assemble_program(native.SOURCE.read_bytes())

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = cls.compiler.read_bytes() == cls.compiler_raw and after == cls.sources
        record = {'schema': 'hepta.hia.native-build-admission-test-custody.v1',
            'manifest': str(cls.manifest), 'matching_cold_report': cls.cold,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'compiler_unchanged': cls.compiler.read_bytes() == cls.compiler_raw,
            'source_manifest_before': cls.sources, 'source_manifest_after': after,
            'source_and_compiler_unchanged': stable, 'test_result_owned_by_outer_runner': True,
            'foreign_object_protocols_and_Core_ABI_Store_hash_providers_hosted': True,
            'all_input_equivalence_proved': False, 'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('native build admission inputs changed during native tests')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()
        self.maxDiff = 8000
        selection = patch.dict(os.environ, {native.SELECTOR: str(self.manifest)})
        selection.start()
        self.addCleanup(selection.stop)

    def test_complete_original_foreign_effect_traces_and_first_errors(self):
        records = []
        inputs = scenarios()
        self.assertEqual(len(inputs), CASE_COUNT)
        for case in inputs:
            expected, actual = observe_case(case), observe_case(case, invoke(self.image))
            records.append({'case': case['name'], 'expected': expected, 'actual': actual})
            with self.subTest(case=case['name']):
                self.assertEqual(encoded(actual), encoded(expected))
        (self.case / 'complete-observations.json').write_bytes(encoded(records) + b'\n')

    def test_actual_native_full_buffers_match_independent_VM(self):
        cases, entry, counts = fixture_by_name(), self.image._entry, Counter()
        def compared(source, size, output, capacity, state, extent):
            raw = ctypes.string_at(source, size)
            expected = vm_call(self.program, raw, ctypes.string_at(output, capacity), ctypes.string_at(state, extent))
            code = entry(source, size, output, capacity, state, extent)
            self.assertEqual((code, ctypes.string_at(output, capacity), ctypes.string_at(state, extent)), expected)
            self.assertEqual(ctypes.string_at(source, size), raw)
            counts['continuation'] += 1
            return code
        with patch.object(self.image, '_entry', compared):
            for name in VM_CASES:
                with self.subTest(case=name):
                    self.assertEqual(encoded(observe_case(cases[name], invoke(self.image))), encoded(observe_case(cases[name])))
        self.assertGreater(counts['continuation'], 0)
        (self.case / 'vm-native-entry-counts.json').write_bytes(encoded(counts) + b'\n')

    def test_four_public_routes_poisoned_reference_manifest_and_scope_pinning(self):
        cases = fixture_by_name()
        with ExitStack() as stack:
            forbidden = lambda *a, **k: (_ for _ in ()).throw(AssertionError('retained admission body'))
            stack.enter_context(patch.object(api, '_signatures_reference', forbidden))
            for name in ('_native_reference', '_build_inputs_reference', '_build_receipt_reference'):
                stack.enter_context(patch.object(api.HIAAgentService, name, forbidden))
            for name in ('signatures_scalar', 'native_ordinary', 'inputs_ordinary', 'receipt_ordinary'):
                expected = observe_case(cases[name])
                with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}):
                    self.assertEqual(encoded(observe_case(cases[name], public_owner)), encoded(expected))
                for value in ('', '/no/such/admission-manifest'):
                    with self.subTest(case=name, selector=value), patch.dict(os.environ, {native.SELECTOR: value}):
                        refused = observe_case(cases[name], public_owner)
                        self.assertIn('exception', refused['outcome'])
                        self.assertEqual(refused['trace'], [])
        manifest = self.case / 'manifest.json'
        manifest.write_bytes(self.manifest.read_bytes())
        value = json.loads(manifest.read_bytes())
        image = self.case / value['image_path']
        image.write_bytes((self.manifest.parent / value['image_path']).read_bytes())
        held = native.installed_native_build_admission(str(manifest))
        image.write_bytes(image.read_bytes() + b'\0')
        with self.assertRaises(ValueError):
            native.installed_native_build_admission(str(manifest))
        self.assertEqual(held.image_sha256, value['image_sha256'])
        from hepta.hia_native_helpers import native_helpers_scope
        with patch.dict(os.environ, clean_environment(), clear=True), native_helpers_scope():
            with self.assertRaisesRegex(ValueError, 'outside the pinned'):
                native.installed_native_build_admission(str(self.manifest))

    def test_lost_ACK_native_errors_retain_unknown_and_foreign_errors_confirm(self):
        from tests.test_hia_native_transport_failures import errors, observe_error, check_transport
        cases, records = fixture_by_name(), []
        for case_name, port_name in (('signatures_scalar', 'signature_scalar_publish'),
                                     ('native_ordinary', 'native_get'),
                                     ('inputs_ordinary', 'build_object_get')):
            expected = observe_case(cases[case_name])
            for label, injected in errors():
                with self.subTest(case=case_name, error=label):
                    fixture, events = Fixture(cases[case_name]), []
                    entry = self.image._entry
                    def lost(source, size, output, capacity, state, extent):
                        words = struct.unpack('<10Q', ctypes.string_at(source, size))
                        code = entry(source, size, output, capacity, state, extent)
                        events.append(words[1])
                        if words[1] == 2 and words[3] == native.PORT[port_name]:
                            raise injected
                        return code
                    with fixture.providers(), patch.object(self.image, '_entry', lost):
                        frame = native.NativeBuildAdmissionFrame(self.image, fixture.case['mode'],
                            fixture.service, fixture.arguments(), namespace=fixture.namespace)
                        error = observe_error(frame.finish)
                    check_transport(error, injected, native.NativeBuildAdmissionUnknown)
                    self.assertTrue(frame.fenced and frame.native_failed and frame.unconfirmed)
                    self.assertFalse(frame.finished)
                    self.assertIs(native._FRAME_CUSTODY[id(frame)], frame)
                    self.assertNotIn(3, events)
                    trace = list(fixture.trace.events)
                    self.assertTrue(trace)
                    self.assertEqual(encoded(trace), encoded(expected['trace'][:len(trace)]))
                    with self.assertRaises(native.NativeBuildAdmissionUnknown):
                        frame.finish()
                    self.assertEqual(fixture.trace.events, trace)
                    records.append({'case': case_name, 'port': port_name, 'injected': label,
                        'raised': type(error).__name__, 'original_exception_or_cause_identity_retained': True,
                        'unknown_custody_retained': True, 'events': events, 'trace': trace})
        for label, injected in errors():
            fixture = Fixture(cases['inputs_ordinary'])
            get, events, entry = fixture.service.store.get, [], self.image._entry
            def observed(source, size, output, capacity, state, extent):
                events.append(struct.unpack('<10Q', ctypes.string_at(source, size))[1])
                return entry(source, size, output, capacity, state, extent)
            def foreign(reference, *, kind):
                value = get(reference, kind=kind)
                if kind == 'build-object':
                    raise injected
                return value
            with fixture.providers(), patch.object(fixture.service.store, 'get', foreign), patch.object(self.image, '_entry', observed):
                frame = native.NativeBuildAdmissionFrame(self.image, 3, fixture.service, fixture.arguments(), namespace=fixture.namespace)
                error = observe_error(frame.finish)
            self.assertIs(error, injected)
            self.assertTrue(frame.finished)
            self.assertFalse(frame.fenced or frame.native_failed or frame.unconfirmed)
            self.assertNotIn(id(frame), native._FRAME_CUSTODY)
            self.assertEqual(events[-1], 3)
            records.append({'foreign': label, 'same_exception_object': True,
                'confirmed_phase': frame.receipt.phase, 'events': events})
        (self.case / 'native-and-foreign-exceptions.json').write_bytes(encoded(records) + b'\n')

    def test_foreign_thread_finished_replay_and_forged_ACK_do_not_repeat(self):
        case, errors = fixture_by_name()['inputs_ordinary'], []
        fixture = Fixture(case)
        with fixture.providers():
            frame = native.NativeBuildAdmissionFrame(self.image, 3, fixture.service, fixture.arguments(), namespace=fixture.namespace)
            def foreign():
                try:
                    frame.finish()
                except BaseException as error:
                    errors.append(type(error))
            thread = threading.Thread(target=foreign)
            thread.start(); thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [native.NativeBuildAdmissionUnknown])
            self.assertEqual(fixture.trace.events, [])
            frame.finish()
            before = list(fixture.trace.events)
            with self.assertRaises(native.NativeBuildAdmissionUnknown):
                frame.finish()
            self.assertEqual(fixture.trace.events, before)
        fixture = Fixture(case)
        with fixture.providers():
            forged = native.NativeBuildAdmissionFrame(self.image, 3, fixture.service, fixture.arguments(), namespace=fixture.namespace)
            with self.assertRaises(native.NativeBuildAdmissionUnknown):
                forged.call(2)
            self.assertEqual(fixture.trace.events, [])

    def test_actual_installed_worker_unknown_replay_and_source_pinning(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from tests.test_hia_agent_native_tools import AgentToolCase
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_scope
        staging = self.case / 'source'
        staging.mkdir()
        shutil.copytree(ROOT / 'hepta', staging / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        environment = clean_environment()
        environment['PYTHONDONTWRITEBYTECODE'] = '1'

        def run(label, arguments, *, body=None, expected_code=0):
            result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=self.case,
                env=environment, input=body, capture_output=True, timeout=60)
            (self.case / (label + '.stdout')).write_bytes(result.stdout)
            (self.case / (label + '.stderr')).write_bytes(result.stderr)
            if expected_code is not None:
                self.assertEqual(result.returncode, expected_code,
                                 result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
            return result

        run('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                      '--wheel-dir', self.case / 'wheels', staging])
        wheel, = (self.case / 'wheels').glob('*.whl')
        installed = self.case / 'installed'
        run('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--no-compile',
                        '--target', installed, wheel])
        bundle = self.case / 'bundle.json'
        bundle.write_bytes(encoded({'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [{
            'selector': native.SELECTOR, 'manifest_path': str(self.manifest),
            'manifest_sha256': sha256(self.manifest.read_bytes()).hexdigest()}]}))
        bundle_sha = sha256(bundle.read_bytes()).hexdigest()
        script = r'''import ctypes,importlib.abc,json,os,struct,sys
from pathlib import Path
installed=sys.argv.pop(1);mode=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name=='tools' or name.startswith('tools.'):raise AssertionError('installed runtime imported authoring')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_native_build_admission_native as native
from hepta import hia_agent_service as api
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'frames':0,'entries':0,'modes':{},'object_observations':0}
def forbidden(*a,**k):raise AssertionError('installed retained admission entered')
api._signatures_reference=forbidden
for name in ('_native_reference','_build_inputs_reference','_build_receipt_reference'):
    setattr(api.HIAAgentService,name,forbidden)
initialize=native.NativeBuildAdmission.__init__
def image_init(self,*a,**k):
    initialize(self,*a,**k);entry=self._entry
    def counted(source,size,output,capacity,state,extent):
        words=struct.unpack('<10Q',ctypes.string_at(source,size))
        result=entry(source,size,output,capacity,state,extent)
        assert words[0]==native.REQUEST_MAGIC and result==native.OUTPUT_BYTES
        counts['entries']+=1
        if mode=='lost_ack_valueerror' and words[1]==2 and words[3]==native.PORT['build_object_get']:
            raise ValueError('controlled lost object observation acknowledgement')
        return result
    self._entry=counted
native.NativeBuildAdmission.__init__=image_init
frame_init=native.NativeBuildAdmissionFrame.__init__
def frame_count(self,*a,**k):
    frame_init(self,*a,**k);counts['frames']+=1
    name=str(self.mode);counts['modes'][name]=counts['modes'].get(name,0)+1
native.NativeBuildAdmissionFrame.__init__=frame_count
effect=native.NativeBuildAdmissionFrame.effect
def observed(self,port):
    result=effect(self,port)
    if port==native.PORT['build_object_get']:
        counts['object_observations']+=1
        if mode=='exit_after_object':
            counts['unknown_frames']=len(native._FRAME_CUSTODY)
            os.write(2,('NATIVE_BUILD_COUNTS='+json.dumps(counts,sort_keys=True)+'\n').encode())
            os._exit(73)
    return result
native.NativeBuildAdmissionFrame.effect=observed
assert mode in ('normal','lost_ack_valueerror','exit_after_object')
try:status=main(sys.argv[1:])
finally:
    counts['unknown_frames']=len(native._FRAME_CUSTODY)
    print('NATIVE_BUILD_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)
raise SystemExit(status)
'''

        def counts(result):
            prefix = b'NATIVE_BUILD_COUNTS='
            found = [line[len(prefix):] for line in result.stderr.splitlines() if line.startswith(prefix)]
            self.assertEqual(len(found), 1, result.stderr.decode(errors='replace'))
            return json.loads(found[0])

        def prepare():
            case = AgentToolCase('runTest')
            workload = {'schema': 'hepta.hia.agent.workload.v1', 'cases': [{
                'function': 'transform', 'arguments': [0], 'expected': {'status': 'returned', 'values': [7]}}],
                'warmup_iterations': 0, 'repetitions': 1}
            with patch.dict(os.environ, environment, clear=True), native_helpers_scope(str(bundle), bundle_sha):
                case.setUp()
                _, candidate, _, build, _ = case.build_pair(workload=workload)
            arguments = case.session.arguments(candidate=candidate, base_program=None,
                validation_profile=case.session.profiles['validation'], claims=['encoding_check'],
                subject={'kind': 'native_artifact', 'backend_profile': case.session.backend,
                         'native_artifact': build['native_artifact'], 'build_receipt': build['build_receipt']})
            envelope = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_verify',
                'arguments': arguments, 'profile_sha256': 'a' * 64,
                'catalog_sha256': case.service.catalog_sha256}
            envelope['request_sha256'] = sha256(encoded(envelope)).hexdigest()
            case.service.close()
            return case, envelope

        def worker(label, case, envelope, mode='normal', expected_code=0):
            flags = ['-I', '-c', script, installed, mode, '--state-root', case.state_root,
                     '--request-json-stdin', '--native-helpers-manifest', bundle,
                     '--expected-native-helpers-sha256', bundle_sha]
            return run(label, flags, body=encoded(envelope), expected_code=expected_code)

        def retained_state(case, envelope):
            from hepta.hia_agent_store import digest
            key = digest({'tool': envelope['tool'], 'key': envelope['arguments']['request_key']})
            with sqlite3.connect(case.state_root / 'state.sqlite3') as db:
                db.row_factory = sqlite3.Row
                return {'request': dict(db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone()),
                    'artifacts': db.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0],
                    'costs': db.execute('SELECT COUNT(*) FROM costs').fetchone()[0]}

        observations = {}
        zero = {'frames': 0, 'entries': 0, 'modes': {}, 'object_observations': 0, 'unknown_frames': 0}
        case, envelope = prepare()
        try:
            first = worker('first', case, envelope)
            retained_before = retained_state(case, envelope)
            replay = worker('replay', case, envelope)
            retained_after = retained_state(case, envelope)
            first_report, replay_report = json.loads(first.stdout), json.loads(replay.stdout)
            first_counts, replay_counts = counts(first), counts(replay)
            self.assertEqual(first_report['response']['status'], 'completed', first_report)
            self.assertEqual(replay_report['response'], first_report['response'])
            self.assertEqual(first_report['native_helpers_sha256'], bundle_sha)
            self.assertEqual(first_counts['modes'], {'2': 2, '3': 2, '4': 2})
            self.assertEqual(first_counts['frames'], 6)
            self.assertEqual(first_counts['object_observations'], 2)
            self.assertEqual(first_counts['unknown_frames'], 0)
            self.assertGreater(first_counts['entries'], 0)
            # The frozen original hia_verify replay calls _verification,
            # whose _subject must revalidate the complete retained build.
            self.assertEqual(replay_counts, {'frames': 3, 'modes': {'2': 1, '3': 1, '4': 1},
                'entries': first_counts['entries'] // 2, 'object_observations': 1, 'unknown_frames': 0})
            self.assertEqual(first_counts['entries'] % 2, 0)
            self.assertEqual(retained_after, retained_before)
            self.assertEqual([(r['claim'], r['status']) for r in first_report['response']['result']['checks']],
                             [('encoding_check', 'proved')])
            observations['first'] = {'report': first_report, 'counts': first_counts}
            observations['replay'] = {'report': replay_report, 'counts': replay_counts,
                'read_only_original_verification_revalidation': True,
                'retained_before': retained_before, 'retained_after': retained_after}
        finally:
            case.tearDown()

        from hepta.hia_agent_store import digest
        for label, mode, exit_code in (('native_ack', 'lost_ack_valueerror', 1),
                                       ('process_loss', 'exit_after_object', 73)):
            case, envelope = prepare()
            try:
                lost = worker(label, case, envelope, mode, exit_code)
                lost_counts = counts(lost)
                self.assertEqual(lost_counts['frames'], 3)
                self.assertEqual(lost_counts['object_observations'], 1)
                self.assertEqual(lost_counts['unknown_frames'], 2)
                if mode == 'lost_ack_valueerror':
                    self.assertIn(b'NativeBuildAdmissionUnknown', lost.stderr)
                key = digest({'tool': envelope['tool'], 'key': envelope['arguments']['request_key']})
                def journal():
                    with sqlite3.connect(case.state_root / 'state.sqlite3') as db:
                        db.row_factory = sqlite3.Row
                        return dict(db.execute('SELECT * FROM requests WHERE key=?', (key,)).fetchone())
                before = journal()
                self.assertEqual(before['state'], 'running')
                self.assertIsNone(before['response'])
                replay = worker(label + '-replay', case, envelope)
                report, replay_counts = json.loads(replay.stdout), counts(replay)
                self.assertEqual(report['response']['status'], 'rejected', report)
                self.assertEqual(report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
                self.assertEqual(replay_counts, zero)
                self.assertEqual(journal(), before)
                observations[label] = {'native_counts': lost_counts, 'request_before': before,
                    'request_after': journal(), 'replay': report, 'replay_counts': replay_counts,
                    'lost_worker_exit_code': lost.returncode}
                if mode == 'exit_after_object':
                    source = installed / 'hepta/_data/examples/hia_bootstrap/native_build_admission.hepta'
                    original_source = source.read_bytes()
                    self.assertEqual(original_source, native.SOURCE.read_bytes())
                    source.write_bytes(original_source + b'\n')
                    drift = worker('changed-installed-source', case, envelope, expected_code=None)
                    self.assertNotEqual(drift.returncode, 0)
                    self.assertEqual(counts(drift), zero)
                    observations['installed_source_drift'] = {'worker_exit_code': drift.returncode,
                        'before_sha256': sha256(original_source).hexdigest(),
                        'after_sha256': sha256(source.read_bytes()).hexdigest(), 'native_counts': counts(drift)}
            finally:
                case.tearDown()
        observations.update({'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
            'bundle_sha256': bundle_sha, 'all_four_references_forbidden_in_actual_child': True,
            'authoring_imports_forbidden_in_actual_child': True, 'original_worker_used': True,
            'whole_native_delivery_qualified': False})
        (self.case / 'installed-observations.json').write_bytes(encoded(observations) + b'\n')


    def test_seven_owner_public_evaluation_and_exact_replay_forbid_all_retained_policies(self):
        from contextlib import ExitStack
        from hepta import hia_native_helpers as helpers
        from hepta import hia_agent_store as store_module
        from hepta import hia_execution_budget as budget_module
        from hepta import hia_execution_budget_native as execution
        from hepta import hia_candidate_budget_native as candidate
        from hepta import hia_service_context_native as context
        from hepta import hia_cost_ledger_native as ledger
        from hepta import hia_evaluation_native as evaluation
        from tools.build_hia_evaluation import build as build_evaluation
        from tests.test_hia_agent_native_tools import AgentToolCase
        from tests.test_hia_service_context_native import poison as poison_context
        from tools.build_hia_store_lifecycle import build as build_store
        from tools.build_hia_service_context import build as build_context
        from tools.build_hia_cost_ledger import build as build_ledger
        from tools.build_hia_execution_budget import build as build_execution
        from tools.build_hia_candidate_budget import build as build_candidate
        from tools.qualify_hia_selfhost import compile_stage

        root = self.case / 'seven-owner-composition'
        root.mkdir()
        manifests = {native.SELECTOR: self.manifest}
        for selector, builder, label in (
                ('HEPTA_HIA_STORE_LIFECYCLE_MANIFEST', build_store, 'store-lifecycle'),
                (context.SELECTOR, build_context, 'service-context'),
                (ledger.SELECTOR, build_ledger, 'cost-ledger'),
                (evaluation.SELECTOR, build_evaluation, 'evaluation')):
            manifests[selector] = builder(root / label, self.compiler, self.cold,
                                           development=self.cold is None)
        for module, builder, label in ((execution, build_execution, 'execution-budget'),
                                       (candidate, build_candidate, 'candidate-budget')):
            directory = root / label
            if self.cold is not None:
                manifest = builder(directory, self.compiler, Path(self.cold))
            else:
                directory.mkdir()
                source = module.SOURCE.read_bytes()
                image, receipt = compile_stage(directory, label, self.compiler, source)
                self.assertEqual(module.SOURCE.read_bytes(), source)
                value = {'schema': module.SCHEMA, 'source_sha256': sha256(source).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(self.compiler_raw).hexdigest()}
                manifest = directory / 'manifest.json'
                manifest.write_text(json.dumps(value, sort_keys=True) + '\n')
                (directory / 'development-build.json').write_text(json.dumps({
                    'scope': 'DEVELOPMENT_COMPONENT', 'manifest': value,
                    'native_compile_receipt': receipt}, sort_keys=True) + '\n')
            manifests[module.SELECTOR] = manifest
        bundle = root / 'bundle.json'
        bundle.write_bytes(encoded({'schema': helpers.SCHEMA, 'target': helpers.TARGET,
            'abi': helpers.ABI, 'helpers': [{'selector': selector,
                'manifest_path': str(path.resolve()),
                'manifest_sha256': sha256(path.read_bytes()).hexdigest()}
                for selector, path in sorted(manifests.items())]}))
        bundle_sha = sha256(bundle.read_bytes()).hexdigest()
        reference_calls = []

        def forbidden(*arguments, **keywords):
            reference_calls.append('retained policy')
            raise AssertionError('seven-owner evaluation entered a retained policy')

        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, clean_environment(), clear=True))
            binding = stack.enter_context(helpers.native_helpers_scope(str(bundle), bundle_sha))
            poison_context(stack)
            for name in ('_NATIVE_STORE_INITIALIZE_REFERENCE', '_NATIVE_STORE_CLOSE_REFERENCE'):
                stack.enter_context(patch.object(store_module, name, forbidden))
            for name in ('_initialize_reference', '_close_reference'):
                stack.enter_context(patch.object(store_module.AgentStore, name, forbidden))
            stack.enter_context(patch.object(budget_module, '_ReferenceExecutionBudgetStore', forbidden))
            for name in ('_reference_consume_attempt', '_cost_ledger_reference', '_hia_evaluate_reference'):
                stack.enter_context(patch.object(api.HIAAgentService, name, forbidden))
            stack.enter_context(patch.object(api, '_signatures_reference', forbidden))
            for method in ('_native_reference', '_build_inputs_reference', '_build_receipt_reference'):
                stack.enter_context(patch.object(api.HIAAgentService, method, forbidden))
            self.assertEqual(len(binding.images), 7)
            images = {key[0]: image for key, image in binding.images.items()}
            spies = {selector: stack.enter_context(patch.object(images[str(path.resolve())], '_entry',
                wraps=images[str(path.resolve())]._entry)) for selector, path in manifests.items()}
            self.assertEqual(set(spies), set(manifests))
            case = AgentToolCase('runTest')
            case.setUp()
            try:
                workload = {'schema': 'hepta.hia.agent.workload.v1', 'cases': [{
                    'function': 'transform', 'arguments': [0],
                    'expected': {'status': 'returned', 'values': [7]}}],
                    'warmup_iterations': 0, 'repetitions': 1}
                _, _, baseline, build, receipts = case.build_pair(workload=workload,
                    budget={'max_total_wall_ms': 3000, 'max_native_wall_ms': 1000})
                arguments = case.session.arguments(baseline_artifact=baseline['native_artifact'],
                    candidate_artifact=build['native_artifact'], build_receipt=build['build_receipt'],
                    verification_receipts=receipts)
                first = case.client.call('hia_evaluate', arguments)
                self.assertEqual(first['status'], 'completed', first)
                result = first['result']
                for flag in ('report_complete', 'planned_workload_complete', 'termination_confirmed'):
                    self.assertTrue(result[flag])
                self.assertFalse(result['adopted'])
                measurements, _ = case.service.store.get_json(result['measurements'])
                costs, _ = case.service.store.get_json(result['full_cost_ledger'])
                receipt, _ = case.service.store.get_json(result['evaluation_receipt'])
                self.assertEqual(measurements['planned_cases'], 1)
                self.assertEqual(len(measurements['observations']), 1)
                self.assertTrue(measurements['planned_workload_complete'])
                self.assertFalse(measurements['universal_equivalence_or_native_refinement_proved'])
                for arm in ('baseline', 'candidate'):
                    run = measurements['native_runs'][arm]['normal']
                    self.assertTrue(run['started'])
                    self.assertTrue(run['termination_confirmed'])
                self.assertEqual(costs['context'], arguments['context'])
                self.assertFalse(costs['full_search_cost_complete'])
                self.assertFalse(costs['net_optimization_benefit_proved'])
                self.assertEqual(receipt['measurements'], result['measurements'])
                self.assertEqual(receipt['full_cost_ledger'], result['full_cost_ledger'])
                context_id = arguments['context']['id']
                budget_before = dict(case.service.store.db.execute(
                    'SELECT * FROM execution_budgets WHERE context_id=?', (context_id,)).fetchone())
                self.assertIsNone(budget_before['owner'])
                self.assertEqual(budget_before['used_native_ns'], costs['native_child_wall_ns'])
                before = {selector: spy.call_count for selector, spy in spies.items()}
                changes_before = case.service.store.db.total_changes
                replay = case.client.call('hia_evaluate', arguments)
                after = {selector: spy.call_count for selector, spy in spies.items()}
                self.assertEqual(replay, first)
                self.assertEqual(after, before)
                self.assertEqual(case.service.store.db.total_changes, changes_before)
                budget_after = dict(case.service.store.db.execute(
                    'SELECT * FROM execution_budgets WHERE context_id=?', (context_id,)).fetchone())
                self.assertEqual(budget_after, budget_before)
                adoption_arguments = case.session.arguments(target_slot='native-build-composition',
                    expected_current={'generation': '0', 'epoch': '0'},
                    candidate_artifact=build['native_artifact'],
                    evaluation_receipt=result['evaluation_receipt'], verification_receipts=receipts)
                adoption = case.client.call('hia_adopt', adoption_arguments)
                self.assertEqual(adoption['status'], 'completed', adoption)
                self.assertEqual(adoption['result']['active_artifact'], build['native_artifact'])
                adoption_before = {selector: spy.call_count for selector, spy in spies.items()}
                adoption_changes = case.service.store.db.total_changes
                adoption_replay = case.client.call('hia_adopt', adoption_arguments)
                self.assertEqual(adoption_replay, adoption)
                self.assertEqual(case.service.store.db.total_changes, adoption_changes)
                self.assertEqual({selector: spy.call_count for selector, spy in spies.items()}, adoption_before)
            finally:
                case.tearDown()
            counts = {selector: spy.call_count for selector, spy in spies.items()}
            self.assertTrue(all(count > 0 for count in counts.values()), counts)
        self.assertEqual(reference_calls, [])
        (root / 'composition.json').write_text(json.dumps({
            'schema': 'hepta.hia.native-build-admission-seven-owner-composition.v1',
            'scope': 'DEVELOPMENT_COMPONENT' if self.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'bundle': str(bundle), 'bundle_sha256': bundle_sha,
            'manifests': {selector: str(path) for selector, path in manifests.items()},
            'actual_native_entries': counts, 'entries_before_replay': before,
            'entries_after_replay': after, 'replay_additional_entries': {
                selector: after[selector] - before[selector] for selector in before},
            'first_response': first, 'replayed_response': replay,
            'adoption_response': adoption, 'adoption_replay': adoption_replay,
            'all_four_admission_retained_bodies_forbidden': True,
            'measurements': measurements, 'ledger': costs, 'evaluation_receipt': receipt,
            'budget_before_replay': budget_before, 'budget_after_replay': budget_after,
            'original_context_wall_ms': 3000, 'original_native_wall_ms': 1000,
            'durable_changes_on_replay': 0, 'reference_calls': reference_calls,
            'all_seven_retained_policy_references_forbidden': True,
            'hosted_request_journal_sqlite_runner_and_object_protocols_retained': True,
            'source_and_compiler_custody_owned_by_outer_component': True,
            'whole_native_delivery_qualified': False}, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    unittest.main()
