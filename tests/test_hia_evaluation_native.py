"""Frozen evaluation effects, independent VM, and real selected installation.

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
import threading
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_evaluation_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tests.hia_evaluation_oracle import World, reference_method
from tests.hia_evaluation_scenarios import scenarios
from tools import generate_hia_evaluation as generator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_evaluate_19065.py.txt'
VALUE_FIXTURE = ROOT / 'tests/fixtures/hia_evaluation_value_19065.py.txt'
CALLERS = ROOT / 'tests/fixtures/evaluation_callers_19065.json'
CALLERS_SHA256 = '256e6c83a79fc2f237b4c12dd4bc2ae00d61bee03332b6adc794086b7e081395'
COLD = 'HEPTA_HIA_EVALUATION_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_EVALUATION_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_EVALUATION_EVIDENCE'
VM_CASES = ('artifact_improved', 'mixed_normal_and_two_traps',
            'reference_candidate_budget_exceeded', 'buffer_trap_snapshots_empty',
            'output_kind_before_abi_and_baseline', 'matching_trap_latency')


def original():
    return reference_method(FIXTURE, api, VALUE_FIXTURE)


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
    image = object.__new__(native.NativeEvaluation)
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
    return {case.name: case for case in scenarios()}


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


class EvaluationSourceTests(unittest.TestCase):
    def test_source_retained_body_value_helper_and_original_inventory_are_exact(self):
        self.assertEqual(native.SOURCE.read_text(), render_assembly(generator.document()))
        document = assemble_program(native.SOURCE.read_bytes()).as_dict()
        self.assertLessEqual(len(document['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in document['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(max(len(block['params']) for fn in document['functions'] for block in fn['blocks']), 16)
        original()
        module = ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes())
        service = next(node for node in module.body
                       if isinstance(node, ast.ClassDef) and node.name == 'HIAAgentService')
        retained = next(node for node in service.body
                        if isinstance(node, ast.FunctionDef) and node.name == '_hia_evaluate_reference')
        retained.name = '_hia_evaluate'
        self.assertEqual(ast.dump(retained), ast.dump(ast.parse(FIXTURE.read_bytes()).body[0]))
        value = next(node for node in module.body
                     if isinstance(node, ast.FunctionDef) and node.name == '_value_observation')
        self.assertEqual(ast.dump(value), ast.dump(ast.parse(VALUE_FIXTURE.read_bytes()).body[0]))
        raw = CALLERS.read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), CALLERS_SHA256)
        inventory = json.loads(raw)
        self.assertEqual(inventory['all_original_tests'], 183)
        self.assertEqual(inventory['ordinary_count'], 81)
        from tools.qualify_hia_evaluation_callers import admit_original_sources
        from tools.run_hia_unittest_gate import load_declared_suite
        admit_original_sources(ROOT, {record['path']: record['sha256']
                                      for record in inventory['modules'].values()})
        for name, record in inventory['modules'].items():
            with self.subTest(module=name):
                _suite, planned = load_declared_suite([name])
                self.assertEqual(list(planned), record['ordered_ids'])

    def test_independent_VM_precedes_native_mapping_and_matches_original_effects(self):
        program = assemble_program(native.SOURCE.read_bytes())
        inputs, reference = fixture_by_name(), original()
        with patch.object(native.NativeEvaluation, '__init__',
                          side_effect=AssertionError('native bytes mapped before independent VM')):
            image = vm_image(program)
            for name in VM_CASES:
                with self.subTest(case=name):
                    expected = World(inputs[name], api).observe(reference)
                    actual = World(inputs[name], api).observe(
                        lambda service, args: native.EvaluationFrame(image, service, args).finish())
                    self.assertEqual(encoded(actual), encoded(expected))
            self.assertGreater(image.entry_count, 0)

    def test_unselected_route_is_lazy_and_unqualified_build_refuses(self):
        real_import = builtins.__import__

        def guarded(name, *arguments, **keywords):
            if name.endswith('hia_evaluation_native'):
                raise AssertionError('unselected evaluation imported optional native owner')
            return real_import(name, *arguments, **keywords)

        case = fixture_by_name()['artifact_improved']
        expected = World(case, api).observe(original())
        with patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            with patch('builtins.__import__', guarded):
                actual = World(case, api).observe(lambda service, args: service._hia_evaluate(args))
        self.assertEqual(encoded(actual), encoded(expected))
        from tools.build_hia_evaluation import build
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'compiler').write_bytes(b'not a qualified compiler')
            (root / 'cold').write_text('{}')
            with self.assertRaises(ValueError):
                build(root / 'refused', root / 'compiler', root / 'cold')
            self.assertFalse((root / 'refused').exists())


class EvaluationNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_evaluation import build
        from tools.build_hia_json_preflight import current_sources
        cold, development, evidence = (os.environ.get(name) for name in (COLD, DEVELOPMENT, EVIDENCE))
        if (cold is None) == (development is None) or cold == '' or development == '' or evidence == '':
            raise ValueError('choose one nonempty matching cold report or explicit development compiler')
        cls.temporary = None
        if evidence is None:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-evaluation-')
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
        cls.image = native.installed_evaluation(str(cls.manifest))
        cls.program = assemble_program(native.SOURCE.read_bytes())

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after = current_sources()
        stable = cls.compiler.read_bytes() == cls.compiler_raw and after == cls.sources
        record = {'schema': 'hepta.hia.evaluation-test-custody.v1',
            'manifest': str(cls.manifest), 'matching_cold_report': cls.cold,
            'compiler_sha256': sha256(cls.compiler_raw).hexdigest(),
            'compiler_unchanged': cls.compiler.read_bytes() == cls.compiler_raw,
            'source_manifest_before': cls.sources, 'source_manifest_after': after,
            'source_and_compiler_unchanged': stable, 'test_result_owned_by_outer_runner': True,
            'foreign_object_protocols_providers_and_binary64_hosted': True,
            'all_input_equivalence_proved': False, 'whole_native_delivery_qualified': False}
        (cls.root / 'component-custody.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not stable:
            raise AssertionError('evaluation inputs changed during native tests')

    def setUp(self):
        self.case = self.root / self._testMethodName
        self.case.mkdir()
        self.maxDiff = 8000

    def test_complete_111_original_foreign_effect_traces_and_first_errors(self):
        records = []
        inputs = scenarios()
        self.assertEqual(len(inputs), 111)
        reference = original()
        for scenario in inputs:
            expected = World(scenario, api).observe(reference)
            actual = World(scenario, api).observe(
                lambda service, args: native.EvaluationFrame(self.image, service, args).finish())
            records.append({'case': scenario.name, 'expected': expected, 'actual': actual})
            with self.subTest(case=scenario.name):
                self.assertEqual(encoded(actual), encoded(expected))
        (self.case / 'complete-observations.json').write_text(
            json.dumps(records, indent=2, sort_keys=True, ensure_ascii=False) + '\n')

    def test_actual_native_full_buffers_and_state_match_independent_VM(self):
        inputs, reference = fixture_by_name(), original()
        entry, counts = self.image._entry, Counter()

        def compared(source, size, output, capacity, state, extent):
            raw = ctypes.string_at(source, size)
            expected = vm_call(self.program, raw, ctypes.string_at(output, capacity),
                               ctypes.string_at(state, extent))
            code = entry(source, size, output, capacity, state, extent)
            actual = code, ctypes.string_at(output, capacity), ctypes.string_at(state, extent)
            self.assertEqual(actual, expected)
            self.assertEqual(ctypes.string_at(source, size), raw)
            counts['continuation' if struct.unpack_from('<Q', raw)[0] == native.REQUEST_MAGIC else 'integer'] += 1
            return code

        with patch.object(self.image, '_entry', compared):
            for name in VM_CASES:
                with self.subTest(case=name):
                    expected = World(inputs[name], api).observe(reference)
                    actual = World(inputs[name], api).observe(
                        lambda service, args: native.EvaluationFrame(self.image, service, args).finish())
                    self.assertEqual(encoded(actual), encoded(expected))
        self.assertGreater(counts['continuation'], 0)
        self.assertGreater(counts['integer'], 0)
        (self.case / 'vm-native-entry-counts.json').write_text(json.dumps(counts, sort_keys=True) + '\n')

    def test_public_selection_poisoned_reference_and_manifest_drift(self):
        case = fixture_by_name()['artifact_improved']
        expected = World(case, api).observe(original())
        with patch.object(api.HIAAgentService, '_hia_evaluate_reference',
                          side_effect=AssertionError('retained evaluation entered')):
            with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}):
                actual = World(case, api).observe(lambda service, args: service._hia_evaluate(args))
            self.assertEqual(encoded(actual), encoded(expected))
            for value in ('', '/no/such/evaluation-manifest'):
                with self.subTest(value=value), patch.dict(os.environ, {native.SELECTOR: value}):
                    refused = World(case, api).observe(lambda service, args: service._hia_evaluate(args))
                    self.assertEqual(refused['outcome']['status'], 'raised')
                    self.assertEqual(refused['trace'], [])
        manifest = self.case / 'manifest.json'
        manifest.write_bytes(self.manifest.read_bytes())
        value = json.loads(manifest.read_bytes())
        image = self.case / value['image_path']
        image.write_bytes((self.manifest.parent / value['image_path']).read_bytes())
        held = native.installed_evaluation(str(manifest))
        image.write_bytes(image.read_bytes() + b'\0')
        with self.assertRaises(ValueError):
            native.installed_evaluation(str(manifest))
        self.assertEqual(held.image_sha256, value['image_sha256'])
        from hepta.hia_native_helpers import native_helpers_scope
        with patch.dict(os.environ, clean_environment(), clear=True), native_helpers_scope():
            with self.assertRaisesRegex(ValueError, 'outside the pinned'):
                native.installed_evaluation(str(self.manifest))

    def test_lost_native_run_and_publication_ACK_never_repeat_or_complete(self):
        inputs, reference = fixture_by_name(), original()
        expected = World(inputs['artifact_improved'], api).observe(reference)
        cases = (
            ('normal_run', 'budget_run', 1, False, 0),
            ('normal_report_arithmetic', 'budget_run', 1, False, 0),
            ('measurements', 'json', 2, True, 1),
        )
        failures = (KeyboardInterrupt, ValueError, OSError, OverflowError)
        for (port_name, effect, native_calls, completed, publications), failure in (
                (case, failure) for case in cases for failure in failures):
            with self.subTest(port=port_name, failure=failure.__name__):
                world = World(inputs['artifact_improved'], api)
                frames = []
                entry = self.image._entry

                def lost(source, size, output, capacity, state, extent):
                    raw = ctypes.string_at(source, size)
                    magic, event = struct.unpack_from('<2Q', raw)
                    words = struct.unpack('<10Q', raw) if magic == native.REQUEST_MAGIC else None
                    result = entry(source, size, output, capacity, state, extent)
                    lost_ack = (words is not None and event == 2
                                and words[3] == native.PORT.get(port_name))
                    lost_math = (port_name == 'normal_report_arithmetic'
                                 and magic == native.MATH_MAGIC and event == 7)
                    if lost_ack or lost_math:
                        raise failure('lost original effect acknowledgement')
                    return result

                def invoke(service, args):
                    frame = native.EvaluationFrame(self.image, service, args)
                    frames.append(frame)
                    return frame.finish()

                with patch.object(self.image, '_entry', lost):
                    observed = world.observe(invoke)
                expected_type = (KeyboardInterrupt if failure is KeyboardInterrupt
                                 else native.EvaluationUnknown)
                self.assertEqual(observed['outcome']['type'],
                                 expected_type.__module__ + '.' + expected_type.__qualname__)
                index = next(index for index, row in enumerate(expected['trace']) if row['effect'] == effect)
                self.assertEqual(observed['trace'], expected['trace'][:index + 1])
                self.assertEqual(observed['native_calls'], native_calls)
                self.assertEqual(observed['claim_completed'], completed)
                self.assertEqual(len(observed['published']), publications)
                frame, = frames
                self.assertTrue(frame.fenced)
                self.assertTrue(frame.unconfirmed)
                before = list(world.trace)
                with self.assertRaises(native.EvaluationUnknown):
                    frame.finish()
                self.assertEqual(world.trace, before)
                (self.case / (port_name + '-' + failure.__name__ + '.json')).write_text(
                    json.dumps(observed, indent=2, sort_keys=True) + '\n')

    def test_foreign_thread_replay_and_forged_ACK_cannot_repeat_an_effect(self):
        scenario = fixture_by_name()['artifact_improved']
        world, errors = World(scenario, api), []
        with world.providers():
            frame = native.EvaluationFrame(self.image, world.service, world.args)

            def foreign():
                try:
                    frame.finish()
                except BaseException as error:
                    errors.append(type(error))

            thread = threading.Thread(target=foreign)
            thread.start()
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [native.EvaluationUnknown])
            self.assertEqual(world.trace, [])
            frame.finish()
            before = list(world.trace)
            with self.assertRaises(native.EvaluationUnknown):
                frame.finish()
            self.assertEqual(world.trace, before)
        world = World(scenario, api)
        with world.providers():
            forged = native.EvaluationFrame(self.image, world.service, world.args)
            with self.assertRaises(native.EvaluationUnknown):
                forged.call(2)
            self.assertEqual(world.trace, [])

    def test_actual_installed_worker_replay_process_loss_and_source_pinning(self):
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
from hepta import hia_evaluation_native as native
from hepta import hia_agent_runner
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_worker import main
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta'/'_data')
counts={'frames':0,'continuations':0,'integers':0,'native_results':[]}
def forbidden(*a,**k):raise AssertionError('installed retained evaluation entered')
HIAAgentService._hia_evaluate_reference=forbidden
initialize=native.NativeEvaluation.__init__
def image_init(self,*a,**k):
    initialize(self,*a,**k);entry=self._entry
    def counted(source,size,output,capacity,state,extent):
        magic=struct.unpack('<Q',ctypes.string_at(source,8))[0]
        result=entry(source,size,output,capacity,state,extent)
        if magic==native.REQUEST_MAGIC:
            assert result==native.OUTPUT_BYTES;counts['continuations']+=1
            event,_,port=struct.unpack_from('<3Q',ctypes.string_at(source,size),8)
            if mode=='lost_ack_valueerror' and event==2 and port==native.PORT['normal_run']:
                raise ValueError('controlled lost native acknowledgement')
        elif magic==native.MATH_MAGIC:
            assert result==32;counts['integers']+=1
        else:raise AssertionError('unexpected installed evaluation request')
        return result
    self._entry=counted
native.NativeEvaluation.__init__=image_init
frame_init=native.EvaluationFrame.__init__
def frame_count(self,*a,**k):
    frame_init(self,*a,**k);counts['frames']+=1
native.EvaluationFrame.__init__=frame_count
runner=hia_agent_runner.run_native_batch
def observed(*a,**k):
    value=runner(*a,**k)
    if k.get('_mode')!='reference':counts['native_results'].append(value)
    return value
hia_agent_runner.run_native_batch=observed
if mode=='exit_after_native':
    effect=native.EvaluationFrame.effect
    def lost(self,port):
        result=effect(self,port)
        if port==native.PORT['normal_run']:
            os.write(2,('EVALUATION_NATIVE_COUNTS='+json.dumps(counts,sort_keys=True)+'\n').encode())
            os._exit(73)
        return result
    native.EvaluationFrame.effect=lost
elif mode not in ('normal','lost_ack_valueerror'):raise AssertionError('unknown installed fixture mode')
try:
    status=main(sys.argv[1:])
finally:
    print('EVALUATION_NATIVE_COUNTS='+json.dumps(counts,sort_keys=True),file=sys.stderr)
raise SystemExit(status)
'''

        def counts(result):
            prefix = b'EVALUATION_NATIVE_COUNTS='
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
                _, _, baseline, build, receipts = case.build_pair(workload=workload)
            arguments = case.session.arguments(baseline_artifact=baseline['native_artifact'],
                candidate_artifact=build['native_artifact'], build_receipt=build['build_receipt'],
                verification_receipts=receipts)
            envelope = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_evaluate',
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

        observations = {}
        case, envelope = prepare()
        try:
            first = worker('first', case, envelope)
            replay = worker('replay', case, envelope)
            first_report, replay_report = json.loads(first.stdout), json.loads(replay.stdout)
            first_counts, replay_counts = counts(first), counts(replay)
            self.assertEqual(first_report['response']['status'], 'completed', first_report)
            self.assertEqual(replay_report['response'], first_report['response'])
            self.assertEqual(first_report['native_helpers_sha256'], bundle_sha)
            self.assertEqual(first_counts['frames'], 1)
            self.assertGreater(first_counts['continuations'], 0)
            self.assertGreater(first_counts['integers'], 0)
            self.assertEqual(len(first_counts['native_results']), 2)
            self.assertTrue(all(row['started'] and row['termination_confirmed']
                                for row in first_counts['native_results']))
            self.assertEqual(replay_counts, {'frames': 0, 'continuations': 0, 'integers': 0, 'native_results': []})
            case.service = api.HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
            measurement, _ = case.service.store.get_json(first_report['response']['result']['measurements'])
            self.assertTrue(measurement['planned_workload_complete'])
            self.assertFalse(measurement['universal_equivalence_or_native_refinement_proved'])
            observations['first'] = {'report': first_report, 'counts': first_counts, 'measurement': measurement}
            observations['replay'] = {'report': replay_report, 'counts': replay_counts}
        finally:
            case.tearDown()

        case, envelope = prepare()
        try:
            lost = worker('lost-ack-valueerror', case, envelope, 'lost_ack_valueerror', 1)
            lost_counts = counts(lost)
            self.assertEqual(lost_counts['frames'], 1)
            self.assertEqual(len(lost_counts['native_results']), 1)
            self.assertTrue(lost_counts['native_results'][0]['termination_confirmed'])
            self.assertIn(b'EvaluationUnknown', lost.stderr)
            case.service = api.HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
            context_id = envelope['arguments']['context']['id']
            retained = dict(case.service.store.db.execute(
                'SELECT * FROM execution_budgets WHERE context_id=?', (context_id,)).fetchone())
            self.assertIsNotNone(retained['owner'])
            self.assertEqual(retained['used_native_ns'], '0')
            case.service.close()
            replay = worker('lost-ack-replay', case, envelope)
            replay_report, replay_counts = json.loads(replay.stdout), counts(replay)
            self.assertEqual(replay_report['response']['status'], 'rejected', replay_report)
            self.assertEqual(replay_report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
            self.assertEqual(replay_counts, {'frames': 0, 'continuations': 0, 'integers': 0, 'native_results': []})
            case.service = api.HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
            after = dict(case.service.store.db.execute(
                'SELECT * FROM execution_budgets WHERE context_id=?', (context_id,)).fetchone())
            self.assertEqual(after, retained)
            observations['native_ack_exception'] = {'actual_native_counts': lost_counts,
                'retained_budget': retained, 'replay': replay_report, 'replay_counts': replay_counts}
        finally:
            case.tearDown()

        case, envelope = prepare()
        try:
            lost = worker('process-lost-after-native', case, envelope, 'exit_after_native', 73)
            lost_counts = counts(lost)
            self.assertEqual(lost_counts['frames'], 1)
            self.assertEqual(len(lost_counts['native_results']), 1)
            self.assertTrue(lost_counts['native_results'][0]['started'])
            self.assertTrue(lost_counts['native_results'][0]['termination_confirmed'])
            self.assertGreater(int(lost_counts['native_results'][0]['wall_ns']), 0)
            case.service = api.HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
            context_id = envelope['arguments']['context']['id']
            retained = dict(case.service.store.db.execute(
                'SELECT * FROM execution_budgets WHERE context_id=?', (context_id,)).fetchone())
            self.assertIsNotNone(retained['owner'])
            # The original budget commits its aggregate only at complete().
            # Unknown real cost remains fenced by owner, never retried/refunded.
            self.assertEqual(retained['used_native_ns'], '0')
            case.service.close()
            replay = worker('unknown-replay', case, envelope)
            replay_report, replay_counts = json.loads(replay.stdout), counts(replay)
            self.assertEqual(replay_report['response']['status'], 'rejected', replay_report)
            self.assertEqual(replay_report['response']['error']['code'], 'E_HIA_REQUEST_UNKNOWN')
            self.assertEqual(replay_counts, {'frames': 0, 'continuations': 0, 'integers': 0, 'native_results': []})
            case.service = api.HIAAgentService(case.state_root, artifact_roots=(case.files_root,))
            after = dict(case.service.store.db.execute(
                'SELECT * FROM execution_budgets WHERE context_id=?', (context_id,)).fetchone())
            self.assertEqual(after, retained)
            observations['process_loss'] = {'actual_native_counts': lost_counts,
                'retained_budget': retained, 'replay': replay_report, 'replay_counts': replay_counts}

            source = installed / 'hepta/_data/examples/hia_bootstrap/evaluation.hepta'
            original_source = source.read_bytes()
            self.assertEqual(sha256(original_source).hexdigest(), sha256(native.SOURCE.read_bytes()).hexdigest())
            source.write_bytes(original_source + b'\n')
            case.service.close()
            drift = worker('changed-installed-source', case, envelope, expected_code=None)
            self.assertNotEqual(drift.returncode, 0)
            self.assertEqual(counts(drift), {'frames': 0, 'continuations': 0, 'integers': 0, 'native_results': []})
            observations['installed_source_drift'] = {
                'before_sha256': sha256(original_source).hexdigest(),
                'after_sha256': sha256(source.read_bytes()).hexdigest(),
                'worker_exit_code': drift.returncode, 'native_counts': counts(drift)}
        finally:
            case.tearDown()
        observations.update({'wheel': str(wheel), 'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(),
            'bundle_sha256': bundle_sha, 'retained_body_forbidden_in_actual_child': True,
            'authoring_imports_forbidden_in_actual_child': True, 'original_worker_used': True,
            'whole_native_delivery_qualified': False})
        (self.case / 'installed-observations.json').write_text(json.dumps(observations, indent=2, sort_keys=True) + '\n')


    def test_six_owner_public_evaluation_and_exact_replay_forbid_all_retained_policies(self):
        from contextlib import ExitStack
        from hepta import hia_native_helpers as helpers
        from hepta import hia_agent_store as store_module
        from hepta import hia_execution_budget as budget_module
        from hepta import hia_execution_budget_native as execution
        from hepta import hia_candidate_budget_native as candidate
        from hepta import hia_service_context_native as context
        from hepta import hia_cost_ledger_native as ledger
        from tests.test_hia_agent_native_tools import AgentToolCase
        from tests.test_hia_service_context_native import poison as poison_context
        from tools.build_hia_store_lifecycle import build as build_store
        from tools.build_hia_service_context import build as build_context
        from tools.build_hia_cost_ledger import build as build_ledger
        from tools.build_hia_execution_budget import build as build_execution
        from tools.build_hia_candidate_budget import build as build_candidate
        from tools.qualify_hia_selfhost import compile_stage

        root = self.case / 'six-owner-composition'
        root.mkdir()
        manifests = {native.SELECTOR: self.manifest}
        for selector, builder, label in (
                ('HEPTA_HIA_STORE_LIFECYCLE_MANIFEST', build_store, 'store-lifecycle'),
                (context.SELECTOR, build_context, 'service-context'),
                (ledger.SELECTOR, build_ledger, 'cost-ledger')):
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
            raise AssertionError('six-owner evaluation entered a retained policy')

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
            self.assertEqual(len(binding.images), 6)
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
            finally:
                case.tearDown()
            counts = {selector: spy.call_count for selector, spy in spies.items()}
            self.assertTrue(all(count > 0 for count in counts.values()), counts)
        self.assertEqual(reference_calls, [])
        (root / 'composition.json').write_text(json.dumps({
            'schema': 'hepta.hia.evaluation-six-owner-composition.v1',
            'scope': 'DEVELOPMENT_COMPONENT' if self.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'bundle': str(bundle), 'bundle_sha256': bundle_sha,
            'manifests': {selector: str(path) for selector, path in manifests.items()},
            'actual_native_entries': counts, 'entries_before_replay': before,
            'entries_after_replay': after, 'replay_additional_entries': {
                selector: after[selector] - before[selector] for selector in before},
            'first_response': first, 'replayed_response': replay,
            'measurements': measurements, 'ledger': costs, 'evaluation_receipt': receipt,
            'budget_before_replay': budget_before, 'budget_after_replay': budget_after,
            'original_context_wall_ms': 3000, 'original_native_wall_ms': 1000,
            'durable_changes_on_replay': 0, 'reference_calls': reference_calls,
            'all_six_retained_policy_references_forbidden': True,
            'hosted_request_journal_sqlite_runner_and_object_protocols_retained': True,
            'source_and_compiler_custody_owned_by_outer_component': True,
            'whole_native_delivery_qualified': False}, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    unittest.main()
