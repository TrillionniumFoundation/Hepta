"""Current Agent context policy, actual native execution and installed routing."""
from __future__ import annotations

import ast
import builtins
from contextlib import ExitStack
from copy import deepcopy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
from random import Random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_service_context_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.hia_service_context_fixtures import Fixture, FIXTURE, METHODS, documents, frozen
from tools import generate_hia_service_context as generator

ROOT = Path(__file__).resolve().parents[1]
REFERENCES = ('_NATIVE_SERVICE_CONTEXT_FREEZE_REFERENCE', '_NATIVE_SERVICE_CONTEXT_LOOKUP_REFERENCE',
              '_NATIVE_SERVICE_CONTEXT_BUDGET_REFERENCE', '_NATIVE_SERVICE_CONTEXT_REMAINING_REFERENCE')


def context_arguments(service):
    workload, objective, cost = documents()
    return {'catalog_sha256': service.catalog_sha256, 'request_key': 'context-native-fixture',
        'compiler_profile': service.profiles['compiler'], 'target_profile': service.profiles['target'],
        'baseline_program': None, 'workload': service.store.json(workload, 'input'),
        'objective': service.store.json(objective, 'input'), 'budget': {
            'cost_policy': service.store.json(cost, 'input'), 'max_candidates': 4,
            'max_model_tokens': 100, 'max_total_wall_ms': 3000,
            'max_native_wall_ms': 1000, 'max_memory_bytes': '536870912'}}


def poison(stack):
    def forbidden(*args, **keywords):
        raise AssertionError('selected context entered retained Python policy')
    for name in REFERENCES:
        stack.enter_context(patch.object(api, name, forbidden))
    for name in METHODS:
        stack.enter_context(patch.object(api.HIAAgentService, name + '_reference', forbidden))


class ServiceContextSourceTests(unittest.TestCase):
    def test_generated_source_and_four_published_bodies_are_exact(self):
        self.assertEqual(native.SOURCE.read_text(), render_assembly(generator.document()))
        original = ast.parse(FIXTURE.read_text()).body[0]
        actual = next(node for node in ast.parse((ROOT / 'hepta/hia_agent_service.py').read_text()).body
                      if isinstance(node, ast.ClassDef) and node.name == 'HIAAgentService')
        for name in METHODS:
            old = next(node for node in original.body if isinstance(node, ast.FunctionDef) and node.name == name)
            new = next(node for node in actual.body if isinstance(node, ast.FunctionDef) and node.name == name + '_reference')
            new.name = name
            self.assertEqual(ast.dump(old), ast.dump(new))
        frozen()

    def test_absent_selector_does_not_import_optional_owner(self):
        actual_import = builtins.__import__
        def guarded(name, *args, **kwargs):
            if name.endswith('hia_service_context_native'):
                raise AssertionError('unselected context imported native owner')
            return actual_import(name, *args, **kwargs)
        fixture = Fixture()
        try:
            with (patch.dict(os.environ), patch('builtins.__import__', guarded),
                  patch.object(api.time, 'time_ns', return_value=fixture.now)):
                os.environ.pop(native.SELECTOR, None)
                self.assertEqual(api.HIAAgentService._remaining_ms(fixture.service, fixture.context), 3000)
        finally:
            fixture.close()

    def test_fixed_buffer_provider_successes_are_exact_nonnegative_integers(self):
        from hepta.hia_agent_buffers import _buffer_size_reference
        for value in ({'bytes_hex': ''}, {'bytes_hex': 'aabb'}, {'byte_length': 0, 'fill_byte': 255},
                      {'byte_length': 1048576, 'fill_byte': 0}):
            answer = _buffer_size_reference(value)
            self.assertIs(type(answer), int)
            self.assertGreaterEqual(answer, 0)


class ServiceContextNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_service_context import build
        evidence = os.environ.get('HEPTA_HIA_SERVICE_CONTEXT_EVIDENCE')
        cls.temporary = None
        if evidence is not None:
            if not evidence:
                raise ValueError('context evidence selector must not be empty')
            cls.root = Path(evidence)
            cls.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-service-context-')
            cls.root = Path(cls.temporary.name)
        cold = os.environ.get('HEPTA_HIA_SERVICE_CONTEXT_COLD_REPORT')
        development = os.environ.get('HEPTA_HIA_SERVICE_CONTEXT_DEVELOPMENT_COMPILER')
        if cold is not None and development is not None:
            raise ValueError('choose matching cold custody or explicit development compiler')
        if cold is not None:
            if not cold:
                raise ValueError('context cold selector must not be empty')
            outer = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(outer['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
        elif development is not None:
            if not development:
                raise ValueError('context development compiler selector must not be empty')
            compiler = Path(development)
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage, SOURCE
            seed, _ = build_seed(cls.root)
            compiler, _ = compile_stage(cls.root, 'B1', seed, SOURCE.read_bytes(), image_format='seed-shared')
        cls.cold_report, cls.compiler = cold, compiler
        cls.compiler_bytes = compiler.read_bytes()
        cls.manifest = build(cls.root / 'built', compiler, cold, development=cold is None)
        cls.image = native.installed_service_context(str(cls.manifest))
        cls.program = assemble_program(native.SOURCE.read_bytes())

    @classmethod
    def tearDownClass(cls):
        same = cls.compiler.read_bytes() == cls.compiler_bytes
        (cls.root / 'component-custody.json').write_text(json.dumps({
            'schema': 'hepta.hia.service-context-test-custody.v1',
            'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(), 'compiler_unchanged': same,
            'image_sha256': cls.image.image_sha256,
            'scope': 'DEVELOPMENT_COMPONENT' if cls.cold_report is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'whole_native_delivery_qualified': False}, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not same:
            raise AssertionError('component compiler changed')

    def compare(self, mode, *, candidate=True, **options):
        observed = []
        for image in (None, self.image):
            fixture = Fixture(**options)
            try:
                value, error = fixture.observe(image, mode, candidate=candidate)
                if options.get('fail_at') is not None:
                    self.assertIs(error, fixture.primary)
                    self.assertIsNone(error.__cause__)
                    self.assertIsNone(error.__context__)
                observed.append(value)
            finally:
                fixture.close()
        self.assertEqual(*observed)
        return observed[0]

    def test_real_provider_order_and_every_foreign_failure_match_frozen_bodies(self):
        failures = 0
        before = native.unconfirmed_context_count()
        for mode in (1, 2, 3, 4):
            ordinary = self.compare(mode)
            self.assertIsNone(ordinary['error'])
            for point in range(1, len(ordinary['trace']) + 1):
                with self.subTest(mode=mode, point=point):
                    self.compare(mode, fail_at=point)
                failures += 1
        self.assertEqual(failures, 37)
        self.assertEqual(native.unconfirmed_context_count(), before)
        (self.root / 'original-effects.json').write_text(json.dumps({
            'modes': 4, 'foreign_failure_points': failures, 'actual_SQLite_rows_compared': True,
            'fixed_schema_and_buffer_providers': True, 'exception_identity_cause_context_notes_preserved': True,
            'original_effect_order_and_partial_mutations_preserved': True}, sort_keys=True) + '\n')

    def test_freeze_short_circuit_rejections_and_loop_branches_match(self):
        def budget(name, value):
            return lambda f: f.args['budget'].__setitem__(name, value)
        changes = [budget('max_memory_bytes', '1'), budget('max_memory_bytes', str(4*1024**3+1)),
            budget('max_native_wall_ms', 3001), budget('max_candidates', '7'),
            lambda f: f.cost['external_costs'].update(model_tokens=101),
            lambda f: f.cost.update(external_costs_complete=True),
            lambda f: f.cost['external_costs'].update(model_wall_ns='12', discovery_wall_ns='13', model_tokens=2),
            lambda f: f.args.update(baseline_program={'id': 'base'}),
            lambda f: f.workload['cases'][0].update(arguments=[0, 1, 2]),
            lambda f: f.workload['cases'][0].update(arguments=[{'byte_length': 1048576, 'fill_byte': 0}]*33)]
        for index, changed in enumerate(changes):
            with self.subTest(index=index):
                self.compare(1, changed=changed)

    def test_deadlines_keep_strict_boundary_floor_and_consume_route(self):
        created = 10**18
        for delta in (-10**30, -1, 0, 2_999_999_999, 3_000_000_000, 3_000_000_001, 10**30):
            for candidate in (False, True):
                with self.subTest(delta=delta, candidate=candidate):
                    result = self.compare(3, created=created, now=created+delta, candidate=candidate)
                    self.assertEqual(len(result['consumed']), int(candidate and delta <= 3_000_000_000))
            result = self.compare(4, created=created, now=created+delta)
            self.assertEqual(result['result'], max(0, (3_000_000_000-delta)//1_000_000))
        # Existing direct object/time operations remain physical foreign ports.
        class Clock(int):
            pass
        self.compare(3, created=created, now=Clock(created), candidate=False)
        self.compare(4, created=created, now=Clock(created))

    def test_integer_arithmetic_has_no_fixed_width_or_decimal_digit_cutoff(self):
        random = Random(1732)
        count = 0
        for bits in (0, 1, 7, 8, 15, 31, 32, 63, 64, 127, 128, 1023, 4096, 32768, 1048577):
            for sign in (1, -1):
                a, b = sign*random.getrandbits(bits), random.getrandbits(max(1, bits//2))
                for operation, left, right, expected in (
                    (1, a, b, a+b), (2, a, b, a-b), (3, a, 1000000, a*1000000),
                    (4, a, 1000000, a//1000000), (5, a, b, a>b), (6, a, b, a<=b),
                    (7, a, b, a!=b), (8, a, 0, max(0, a))):
                    answer = self.image.arithmetic(operation, left, right)
                    self.assertIs(type(answer), type(expected))
                    self.assertEqual(answer, expected)
                    count += 1
        self.assertEqual(count, 240)

    def test_all_four_actual_public_routes_use_native_with_references_poisoned(self):
        from hepta import hia_native_helpers as helpers
        from hepta import hia_agent_store as store_module
        from hepta import hia_execution_budget as budget_module
        from hepta import hia_execution_budget_native as execution
        from hepta import hia_candidate_budget_native as candidate
        from tools.build_hia_store_lifecycle import build as build_store
        from tools.build_hia_execution_budget import build as build_execution
        from tools.build_hia_candidate_budget import build as build_candidate
        from tools.qualify_hia_selfhost import compile_stage

        root = self.root / 'four-owner-composition'
        root.mkdir()
        store = build_store(root / 'store', self.compiler, self.cold_report,
                            development=self.cold_report is None)
        manifests = {native.SELECTOR: self.manifest,
                     'HEPTA_HIA_STORE_LIFECYCLE_MANIFEST': store}
        for module, builder, label in ((execution, build_execution, 'execution-budget'),
                                       (candidate, build_candidate, 'candidate-budget')):
            directory = root / label
            if self.cold_report is not None:
                manifest = builder(directory, self.compiler, Path(self.cold_report))
            else:
                # Explicit development execution only. The strict cold builders
                # are used unchanged whenever current cold evidence is supplied.
                directory.mkdir()
                source = module.SOURCE.read_bytes()
                image, receipt = compile_stage(directory, label, self.compiler, source)
                self.assertEqual(module.SOURCE.read_bytes(), source)
                manifest = directory / 'manifest.json'
                value = {'schema': module.SCHEMA, 'source_sha256': sha256(source).hexdigest(),
                    'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                    'compiler_sha256': sha256(self.compiler_bytes).hexdigest()}
                manifest.write_text(json.dumps(value, sort_keys=True) + '\n')
                (directory / 'development-build.json').write_text(json.dumps({
                    'scope': 'DEVELOPMENT_COMPONENT', 'manifest': value,
                    'native_compile_receipt': receipt}, sort_keys=True) + '\n')
            manifests[module.SELECTOR] = manifest
        bundle = root / 'bundle.json'
        bundle.write_text(json.dumps({'schema': helpers.SCHEMA, 'target': helpers.TARGET,
            'abi': helpers.ABI, 'helpers': [{'selector': selector,
                'manifest_path': str(path.resolve()),
                'manifest_sha256': sha256(path.read_bytes()).hexdigest()}
                for selector, path in sorted(manifests.items())]}, sort_keys=True) + '\n')
        counts = {}
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            binding = stack.enter_context(helpers.native_helpers_scope(
                str(bundle), sha256(bundle.read_bytes()).hexdigest()))
            poison(stack)
            def forbidden(*args, **keywords):
                raise AssertionError('composed native owner reached retained Python policy')
            for name in ('_NATIVE_STORE_INITIALIZE_REFERENCE', '_NATIVE_STORE_CLOSE_REFERENCE'):
                stack.enter_context(patch.object(store_module, name, forbidden))
            for name in ('_initialize_reference', '_close_reference'):
                stack.enter_context(patch.object(store_module.AgentStore, name, forbidden))
            stack.enter_context(patch.object(budget_module, '_ReferenceExecutionBudgetStore', forbidden))
            stack.enter_context(patch.object(api.HIAAgentService, '_reference_consume_attempt', forbidden))
            spies = {type(image).__name__: stack.enter_context(patch.object(image, '_entry', wraps=image._entry))
                     for image in binding.images.values()}
            self.assertEqual(len(spies), 4)
            service = api.HIAAgentService(directory)
            try:
                response = service.call('hia_context', context_arguments(service))
                self.assertEqual(response['status'], 'completed', response)
                context = service._context(response['result']['context'])
                service._budget(context, candidate=True)
                self.assertEqual(service.store.db.execute('SELECT attempts FROM contexts').fetchone()[0], 1)
                self.assertGreaterEqual(service._remaining_ms(context), 0)
                self.assertLessEqual(service._remaining_ms(context), 3000)
                with patch.object(service, '_consume_attempt', side_effect=RuntimeError('same current route')):
                    with self.assertRaisesRegex(RuntimeError, 'same current route'):
                        service._budget(context, candidate=True)
            finally:
                service.close()
            counts = {name: spy.call_count for name, spy in spies.items()}
            self.assertTrue(all(count > 0 for count in counts.values()), counts)
        (root / 'composition.json').write_text(json.dumps({
            'scope': 'DEVELOPMENT_COMPONENT' if self.cold_report is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'actual_native_entries': counts, 'original_context_wall_ms': 3000,
            'context_store_execution_and_candidate_budget_composed': True,
            'all_retained_policy_references_forbidden': True,
            'whole_native_delivery_qualified': False}, indent=2, sort_keys=True) + '\n')

    def test_empty_invalid_selector_refuses_before_context_effect(self):
        fixture = Fixture()
        try:
            for selector in ('', '/no-such-context-manifest'):
                with patch.dict(os.environ, {native.SELECTOR: selector}), ExitStack() as stack:
                    poison(stack)
                    with self.assertRaises((ValueError, OSError)):
                        api.HIAAgentService._hia_context(fixture.service, fixture.args)
                self.assertEqual(fixture.trace, [])
        finally:
            fixture.close()

    def test_real_budget_create_failure_keeps_context_row_and_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            outcomes = []
            for selected in (False, True):
                with patch.dict(os.environ):
                    os.environ.pop(native.SELECTOR, None)
                    if selected:
                        os.environ[native.SELECTOR] = str(self.manifest)
                    service = api.HIAAgentService(Path(directory) / str(selected))
                    try:
                        args = context_arguments(service)
                        failure = RuntimeError('execution budget creation failed after INSERT')
                        with patch.object(service.store.execution_budgets, 'create', side_effect=failure):
                            with self.assertRaises(RuntimeError) as raised:
                                service._hia_context(args)
                        self.assertIs(raised.exception, failure)
                        row = service.store.db.execute('SELECT * FROM contexts').fetchone()
                        self.assertIsNotNone(row)
                        manifest = api.decode_data(row['artifact'])
                        record, _ = service.store.get_json(manifest, kind='context')
                        outcomes.append((row['attempts'], record['budget'], record['context_is_execution_authority']))
                    finally:
                        service.close()
            # Artifact identities differ with each genuine installation/session.
            for item in outcomes:
                item[1].pop('cost_policy')
            self.assertEqual(*outcomes)

    def test_real_insert_lost_ack_retains_service_and_never_replays(self):
        # A disposable process owns the deliberately unknown resource until exit.
        # The test never discards the global custody entry to simulate cleanup.
        script = r'''import ctypes,gc,os,struct,sys,tempfile,weakref
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from unittest.mock import patch
from hepta import hia_agent_service as api
from hepta import hia_service_context_native as native
from tests.test_hia_service_context_native import context_arguments
directory=tempfile.TemporaryDirectory()
service=api.HIAAgentService(directory.name)
args=context_arguments(service)
image=native.installed_service_context(sys.argv[2])
frame=native.ContextFrame(image,1,service,args)
service_ref=weakref.ref(service)
actual=image._entry
lost=RuntimeError('context INSERT acknowledgement lost')
def entry(source,size,output,capacity,state,extent):
    result=actual(source,size,output,capacity,state,extent)
    if size==80:
        words=struct.unpack('<10Q',ctypes.string_at(source,size))
        if words[1]==2 and words[3]==44:raise lost
    return result
with patch.object(image,'_entry',entry):
    try:frame.finish()
    except RuntimeError as error:assert error is lost
    else:raise AssertionError('lost acknowledgement accepted')
assert frame.unconfirmed and frame.fenced
assert frame.receipt.port==44 and frame.receipt.phase==2
assert service.store.db.execute('SELECT COUNT(*) FROM contexts').fetchone()[0]==1
before=service.store.db.total_changes
for call in (lambda:frame.call(2),lambda:native.ContextFrame(image,1,service,args)):
    try:call()
    except native.ServiceContextUnknown:pass
    else:raise AssertionError('unknown effect replayed')
assert service.store.db.total_changes==before
del service,args,frame
gc.collect()
assert service_ref() is not None
assert native.unconfirmed_context_count()==1
assert service_ref().store.db.execute('SELECT COUNT(*) FROM contexts').fetchone()[0]==1
print('UNKNOWN_CONTEXT_RETAINED_UNTIL_PROCESS_EXIT',flush=True)
os._exit(0)
'''
        environment = {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_HIA_')}
        result = subprocess.run([sys.executable, '-I', '-c', script, str(ROOT), str(self.manifest)],
            env=environment, cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'UNKNOWN_CONTEXT_RETAINED_UNTIL_PROCESS_EXIT')

    def invoke(self, raw, state):
        source = ctypes.create_string_buffer(raw, len(raw))
        output = ctypes.create_string_buffer(b'\xa5'*(native.OUTPUT_BYTES+16), native.OUTPUT_BYTES+16)
        code = self.image._entry(source, len(raw), output, native.OUTPUT_BYTES, state, native.STATE_BYTES)
        self.assertEqual(source.raw, raw)
        self.assertEqual(output.raw[native.OUTPUT_BYTES:], b'\xa5'*16)
        return code, output.raw[:native.OUTPUT_BYTES]

    def test_fork_with_custody_lock_held_cannot_block_new_child_context(self):
        script = r'''import ctypes,os,select,signal,struct,sys,threading
sys.path.insert(0,sys.argv[1])
from unittest.mock import patch
from hepta import hia_service_context_native as native
from tests.hia_service_context_fixtures import Fixture
image=native.installed_service_context(sys.argv[2])
fixture=Fixture()
held=native.ContextFrame(image,1,fixture.service,fixture.args,namespace=fixture.namespace)
actual=image._entry
def lost(*arguments):
    actual(*arguments)
    raise RuntimeError('parent claim receipt lost')
with patch.object(image,'_entry',lost):
    try:held.call(1)
    except RuntimeError:pass
assert held.unconfirmed
entered,release=threading.Event(),threading.Event()
def holding():
    with native._custody_lock():entered.set();release.wait(15)
thread=threading.Thread(target=holding);thread.start()
assert entered.wait(5)
reader,writer=os.pipe()
child=os.fork()
if child==0:
    os.close(reader)
    try:
        assert native.unconfirmed_context_count()==1
        assert native._FRAME_CUSTODY[id(held)] is held
        try:held.call(2)
        except native.ServiceContextUnknown:pass
        else:raise AssertionError('inherited parent frame resumed')
        current=Fixture()
        result,error=current.observe(image,4)
        assert error is None and result['result']==3000
        current.close()
        assert native._FRAME_CUSTODY[id(held)] is held
        os.write(writer,b'FORK_CONTEXT_FINISHED_WITH_UNKNOWN_RETAINED')
    except BaseException as error:
        os.write(writer,(type(error).__name__+': '+str(error)).encode()[:4096]);os._exit(1)
    os._exit(0)
os.close(writer)
try:
    ready,_,_=select.select([reader],[],[],10)
    if not ready:
        os.kill(child,signal.SIGKILL);os.waitpid(child,0)
        raise AssertionError('child inherited locked context custody')
    output=os.read(reader,4096);_,status=os.waitpid(child,0)
    assert status==0,output
    assert output==b'FORK_CONTEXT_FINISHED_WITH_UNKNOWN_RETAINED',output
finally:
    os.close(reader);release.set();thread.join(5)
assert not thread.is_alive()
print(output.decode(),flush=True)
os._exit(0)
'''
        environment = {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_HIA_')}
        result = subprocess.run([sys.executable, '-I', '-c', script, str(ROOT), str(self.manifest)],
            env=environment, cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'FORK_CONTEXT_FINISHED_WITH_UNKNOWN_RETAINED')

    def test_control_transitions_match_independent_core_vm(self):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        paths = [(2, list(range(101,110))+[108,109,110,111], {}),
                 (3, list(range(201,210)), {208: 1}),
                 (4, list(range(301,310)), {})]
        for mode, ports, observations in paths:
            state = ctypes.create_string_buffer(native.STATE_BYTES)
            machine_state = _Owner(3, bytearray(native.STATE_BYTES))
            sequence = port = 0
            def compare(event, observation=0):
                nonlocal sequence, port
                raw = struct.pack('<10Q', native.REQUEST_MAGIC,event,sequence,port,observation,mode,17,23,0,0)
                owners = [_Owner(1,bytearray(raw)),_Owner(2,bytearray(b'\xa5'*80)),machine_state]
                machine = _Machine(self.program, 2_000_000, 16 << 20, None, 128)
                code = machine.invoke(machine.functions['f0'], [_View(owner,i!=0) for i,owner in enumerate(owners)])[0]
                result = self.invoke(raw,state)
                self.assertEqual(result,(code,bytes(owners[1].data)))
                self.assertEqual(state.raw,bytes(machine_state.data))
                words = struct.unpack('<10Q',result[1]);port,sequence=words[2:4]
                return words
            compare(0)
            for expected in ports:
                self.assertEqual(port,expected)
                compare(1)
                words=compare(2,observations.get(expected,0))
            self.assertEqual(words[4],4)

    def test_replay_cross_identity_mutated_state_and_pre_effect_capacity_refuse(self):
        for mode in (1,2,3,4):
            start=struct.pack('<10Q',native.REQUEST_MAGIC,0,0,0,0,mode,17,23,0,0)
            for change in ('replay','identity','state'):
                state=ctypes.create_string_buffer(native.STATE_BYTES)
                self.assertEqual(self.invoke(start,state)[0],80)
                request=struct.pack('<10Q',native.REQUEST_MAGIC,1,1,1+(mode-1)*100,0,mode,
                                    19 if change=='identity' else 17,23,0,0)
                if change=='state':
                    state[24]=b'\xff'
                    self.assertEqual(self.invoke(request,state)[0],4294967293)
                elif change=='identity':
                    self.assertEqual(struct.unpack('<10Q',self.invoke(request,state)[1])[1],1)
                else:
                    self.assertEqual(struct.unpack('<10Q',self.invoke(request,state)[1])[1],0)
                    self.assertEqual(struct.unpack('<10Q',self.invoke(request,state)[1])[1],1)
        class Unavailable(dict):
            def __setitem__(self,key,value):raise MemoryError('custody reservation failed')
        fixture=Fixture()
        try:
            with patch.object(native,'_FRAME_CUSTODY',Unavailable()):
                with self.assertRaises(MemoryError):
                    native.ContextFrame(self.image,1,fixture.service,fixture.args)
            self.assertEqual(fixture.trace,[])
        finally:fixture.close()

    def test_actual_installed_wheel_and_pinned_bundle_use_public_context_routes(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
        self.assertIn('examples/hia_bootstrap/service_context.hepta',RESOURCES)
        folder=self.root/'installation';folder.mkdir()
        source=folder/'source';source.mkdir()
        shutil.copytree(ROOT/'hepta',source/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES,*SDIST_SUPPORT_FILES,'setup.py','pyproject.toml','MANIFEST.in'):
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
        environment={key:value for key,value in os.environ.items()
                     if key not in ('PYTHONPATH','PYTHONHOME') and not key.startswith('HEPTA_HIA_')}
        environment['PYTHONDONTWRITEBYTECODE']='1'
        def run(arguments,cwd=source):
            result=subprocess.run([sys.executable,'-B',*map(str,arguments)],cwd=cwd,env=environment,
                                  capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            return result
        wheels=folder/'wheels'
        run(['-m','pip','wheel','--no-deps','--no-build-isolation','--wheel-dir',wheels,source])
        wheel,=wheels.glob('*.whl');installed=folder/'installed'
        run(['-m','pip','install','--no-deps','--no-index','--target',installed,wheel])
        child=folder/'context.json';child.write_bytes(self.manifest.read_bytes())
        record=json.loads(child.read_bytes())
        (folder/record['image_path']).write_bytes((self.manifest.parent/record['image_path']).read_bytes())
        bundle=folder/'helpers.json'
        bundle.write_text(json.dumps({'schema':SCHEMA,'target':TARGET,'abi':ABI,'helpers':[
            {'selector':native.SELECTOR,'manifest_path':child.name,
             'manifest_sha256':sha256(child.read_bytes()).hexdigest()}]},sort_keys=True))
        script=r'''import json,os,sys
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from hepta import hia_agent_service as api
from hepta import hia_service_context_native as native
from hepta.hia_native_helpers import native_helpers_scope,native_helpers_identity
assert Path(api.__file__).is_relative_to(Path(sys.argv[1]))
assert native.SOURCE.is_relative_to(Path(sys.argv[1]))
def forbidden(*args,**kwargs):raise AssertionError('installed reference fallback')
for name in ('FREEZE','LOOKUP','BUDGET','REMAINING'):
    setattr(api,'_NATIVE_SERVICE_CONTEXT_'+name+'_REFERENCE',forbidden)
for name in ('_hia_context','_context','_budget','_remaining_ms'):
    setattr(api.HIAAgentService,name+'_reference',forbidden)
bundle=Path(sys.argv[2]);expected=sha256(bundle.read_bytes()).hexdigest()
if sys.argv[4]=='refuse':
    try:
        with native_helpers_scope(str(bundle),expected):pass
    except ValueError:print('REFUSED_CHANGED_INSTALLED_INPUT')
    else:raise AssertionError('changed installed input accepted')
else:
    before=dict(os.environ)
    with native_helpers_scope(str(bundle),expected):
        with patch.object(native,'_mapped_context',forbidden):
            service=api.HIAAgentService(sys.argv[3])
            try:
                example=service._examples()
                workload={'schema':'hepta.hia.agent.workload.v1','cases':[{'function':'f','arguments':[1],
                    'expected':{'status':'returned','values':[1]}}],'warmup_iterations':0,'repetitions':1}
                args={'catalog_sha256':service.catalog_sha256,'request_key':'installed-context',
                    'compiler_profile':service.profiles['compiler'],'target_profile':service.profiles['target'],
                    'baseline_program':None,'workload':service.store.json(workload,'input'),
                    'objective':service.store.json(example['objective'],'input'),'budget':{
                        'cost_policy':service.store.json(example['cost_policy'],'input'),'max_candidates':4,
                        'max_model_tokens':0,'max_total_wall_ms':3000,'max_native_wall_ms':1000,
                        'max_memory_bytes':'536870912'}}
                response=service.call('hia_context',args)
                assert response['status']=='completed',response
                context=service._context(response['result']['context'])
                service._budget(context,candidate=True)
                assert service.store.db.execute('SELECT attempts FROM contexts').fetchone()[0]==1
                assert 0<=service._remaining_ms(context)<=3000
            finally:service.close()
        assert native_helpers_identity()=={'native_helpers_sha256':expected}
    assert dict(os.environ)==before and native_helpers_identity()=={}
    # Exercise the actual installed one-request worker, including JSON input,
    # helper-bundle admission, a newly constructed service and normal close.
    import io
    from contextlib import redirect_stdout
    from hepta.hia_agent_worker import main
    args['request_key']='installed-worker-context'
    envelope={'schema':'hia-agent-worker-request-v1','tool':'hia_context','arguments':args,
        'profile_sha256':'a'*64,'catalog_sha256':service.catalog_sha256}
    envelope['request_sha256']=sha256(api.wire(envelope)).hexdigest()
    sys.stdin=io.TextIOWrapper(io.BytesIO(api.wire(envelope)),encoding='utf-8')
    output_bytes=io.BytesIO()
    output=io.TextIOWrapper(output_bytes,encoding='utf-8')
    with redirect_stdout(output):
        code=main(['--state-root',sys.argv[3],'--request-json-stdin',
            '--native-helpers-manifest',str(bundle),'--expected-native-helpers-sha256',expected])
    output.flush()
    report=json.loads(output_bytes.getvalue())
    assert code==0 and report['response']['status']=='completed',(code,report)
    assert report['native_helpers_sha256']==expected
    assert dict(os.environ)==before and native_helpers_identity()=={}
    print('INSTALLED_FOUR_NATIVE_CONTEXT_ROUTES_BUNDLE_RESTORED')
'''
        result=run(['-I','-c',script,installed,bundle,folder/'accepted','accept'],cwd=folder)
        self.assertEqual(result.stdout.strip(),'INSTALLED_FOUR_NATIVE_CONTEXT_ROUTES_BUNDLE_RESTORED')
        for altered in (installed/'hepta/_data/examples/hia_bootstrap/service_context.hepta',child):
            raw=altered.read_bytes()
            try:
                altered.write_bytes(raw+b'\n')
                result=run(['-I','-c',script,installed,bundle,folder/'refused','refuse'],cwd=folder)
                self.assertEqual(result.stdout.strip(),'REFUSED_CHANGED_INSTALLED_INPUT')
            finally:altered.write_bytes(raw)
        (folder/'installed-custody.json').write_text(json.dumps({
            'wheel_sha256':sha256(wheel.read_bytes()).hexdigest(),'native_image_sha256':self.image.image_sha256,
            'real_public_context_lookup_budget_remaining':True,'references_poisoned':True,
            'actual_installed_JSON_worker_context_request':True,
            'administrator_bundle_scope_restored':True,'installed_source_and_child_manifest_drift_refused':True},
            sort_keys=True)+'\n')
