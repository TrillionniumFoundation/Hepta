"""Independent HIA plan interpretation, selected callers and source custody."""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import ctypes
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_machine_plan as plans
from hepta.hia_machine_plan_native import (
    SOURCE, SCHEMA, SELECTOR, NativeMachinePlan, installed_machine_plan)
from hepta.hia_program import verify_program
from tools.qualify_hia_machine_registers import fixture, explicit_plan

DEVELOPMENT = 'HEPTA_HIA_MACHINE_PLAN_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_MACHINE_PLAN_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_MACHINE_PLAN_FIXTURE_EVIDENCE'


def observed(call):
    try:
        return {'value': call()}
    except Exception as exc:
        return {'exception': type(exc).__name__, 'message': str(exc)}


class MachinePlanSourceTests(unittest.TestCase):
    def test_caller_gate_requires_every_loaded_test_without_anomalies(self):
        from tools.qualify_hia_machine_plan_native_callers import strict_pass
        result = unittest.TestResult()
        self.assertFalse(strict_pass(result, [], [], 1))
        result.testsRun = 1
        self.assertTrue(strict_pass(result, ['one'], ['one'], 1))
        self.assertFalse(strict_pass(result, ['one', 'missing'], ['one'], 1))
        self.assertFalse(strict_pass(result, ['one'], ['different'], 1))
        self.assertFalse(strict_pass(result, ['one'], ['one'], 0))
        result.expectedFailures.append((unittest.FunctionTestCase(lambda: None), 'expected'))
        self.assertFalse(strict_pass(result, ['one'], ['one'], 1))
        result.expectedFailures.clear()
        result.unexpectedSuccesses.append(unittest.FunctionTestCase(lambda: None))
        self.assertFalse(strict_pass(result, ['one'], ['one'], 1))

    def test_generated_source_and_retained_oracles(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_machine_plan import document
        self.assertEqual(render_assembly(document()).encode(), SOURCE.read_bytes())
        for name, expected in (
            ('validate_plan', 'ff1bb1d5728ada31db2b71ed33d74173e7637c5016e7077901ce1e03f2eae1b7'),
            ('register_assignment_witness', 'dee21ee89241cf783e56bea3ede51f7e399576e9421d3c237df8fac0e47075f0'),
        ):
            original = inspect.getsource(getattr(plans, '_reference_' + name)).replace(
                'def _reference_' + name + '(', 'def ' + name + '(', 1)
            self.assertEqual(sha256(original.encode()).hexdigest(), expected, name)

    def test_current_cold_admission_precedes_artifacts(self):
        from tools.build_hia_machine_plan import build
        with tempfile.TemporaryDirectory(prefix='hia-machine-plan-gate-') as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold'
            compiler.write_bytes(b'development-only bytes')
            cold.write_text('{"status":"DEVELOPMENT_ONLY"}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(root / 'new-parent' / 'out', compiler, cold)
            self.assertFalse((root / 'new-parent').exists())

    def test_independent_vm_runs_complete_witness_and_refusal(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tests.test_hia_machine_plan import call_document
        interpreted = assemble_program(SOURCE.read_bytes())
        code = interpreted.as_dict()['functions'][0]
        entries, resources = [], []

        def entry(source, source_size, output, output_size, workspace, workspace_size):
            original = ctypes.string_at(source, source_size)
            owners = [_Owner(-1, bytearray(original)),
                      _Owner(-2, bytearray(ctypes.string_at(output, output_size))),
                      _Owner(-3, bytearray(ctypes.string_at(workspace, workspace_size)))]
            machine = _Machine(interpreted, 12_000_000, 64 << 20, None, 128)
            command = struct.unpack_from('<Q', owners[2].data)[0]
            result = machine.invoke(code, [_View(owners[0], False),
                _View(owners[1], True), _View(owners[2], True)])[0]
            self.assertEqual(bytes(owners[0].data), original)
            for destination, owner in ((output, owners[1]), (workspace, owners[2])):
                ctypes.memmove(destination, bytes(owner.data), len(owner.data))
            entries.append(command)
            resources.append(machine.resources())
            return result

        owner = NativeMachinePlan.__new__(NativeMachinePlan)
        owner._entry = entry  # Ordinary Core VM; no native image is mapped.
        checked = verify_program(call_document())
        assignments = {'answer': {'x': 'r12'}}
        expected = plans._reference_register_assignment_witness(checked, assignments)
        self.assertEqual(owner.witness(checked, assignments), expected)
        self.assertIn(13, entries)
        self.assertEqual(entries[-1], 14)
        with self.assertRaisesRegex(plans.MachinePlanRejected, 'unreviewed function alignment'):
            owner.validate(checked, {**explicit_plan(checked), 'function_alignment': 7}, owner.witness)
        self.assertEqual(observed(lambda: owner.witness(checked, {'unknown': {'x': 'rax'}})),
                         observed(lambda: plans._reference_register_assignment_witness(
                             checked, {'unknown': {'x': 'rax'}})))
        self.assertTrue(all(row['live_owners'] == row['live_local_loans'] == 0 for row in resources))


class MachinePlanNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development image cannot override a requested cold report')
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-machine-plan-native-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.folder = Path(cls.temporary.name)
        if cold:
            from tools.build_hia_machine_plan import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        elif development:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        else:
            raise unittest.SkipTest('requires explicit machine-plan cold report or development manifest')
        cls.native = installed_machine_plan(str(cls.manifest))
        document, cls.placements = fixture()
        cls.program = verify_program(document)

    def selected(self):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, {SELECTOR: str(self.manifest)}))
        for name in ('_reference_validate_plan', '_reference_register_assignment_witness'):
            stack.enter_context(patch.object(plans, name,
                side_effect=AssertionError('retained machine-plan owner entered: ' + name)))
        return stack

    def test_differential_schema_and_first_refusal_priority(self):
        base = explicit_plan(self.program, self.placements)
        mutations = [
            {'schema': 'unknown', 'core_sha256': '0' * 64},
            {'core_sha256': '0' * 64, 'block_order': []},
            {'block_order': {'missing': []}, 'function_order': []},
            {'function_order': [], 'scratch_registers': {}},
            {'scratch_registers': {}, 'instruction_selection': {}},
            {'instruction_selection': {'move_immediate': 'bad', 'alu_immediate': 'bad', 'scalar_select': 'bad'}},
            {'instruction_selection': {'move_immediate': 'movabs', 'alu_immediate': 'bad', 'scalar_select': 'bad'},
             'function_alignment': 7},
            {'function_alignment': True, 'value_registers': {'missing': {}}},
            {'function_alignment': 7, 'instruction_selection': {
                'move_immediate': 'movabs', 'alu_immediate': 'imm32', 'scalar_select': 'bad'}},
            {'value_registers': {'plus7': {'x': 'r12', 'seven': 'r12'}}},
        ]
        for item in [None, [], {}, base, *({**base, **m} for m in mutations)]:
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = observed(lambda: plans.validate_plan(self.program, deepcopy(item)))
            with self.selected():
                self.assertEqual(observed(lambda: plans.validate_plan(self.program, deepcopy(item))), expected)

    def test_seeded_register_lifetimes_and_opaque_foreign_refusals(self):
        rng = random.Random(20261111)
        document = self.program.as_dict()
        definitions = {fn['name']: [p['name'] for b in fn['blocks']
            for p in b['params'] + [p for op in b['ops'] for p in op['out']]]
            for fn in document['functions']}
        registers = ('rbx', 'r12', 'r13', 'r14', 'r15', 'r8', 'r9', 'rax', None, [], {})
        for case in range(500):
            names = rng.sample(list(definitions), rng.randrange(1, 4))
            mapping = {name: {value: deepcopy(rng.choice(registers)) for value in
                rng.sample(definitions[name] + ['missing'], min(4, len(definitions[name])))} for name in names}
            leaf = bool(case % 2)
            expected = observed(lambda: plans._reference_register_assignment_witness(
                self.program, mapping, allow_leaf_registers=leaf))
            with self.selected():
                actual = observed(lambda: plans.register_assignment_witness(
                    self.program, mapping, allow_leaf_registers=leaf))
            self.assertEqual(actual, expected, (case, mapping))
        cycle = {}; cycle['x'] = cycle
        for mapping in (cycle, {'missing': cycle}, {'plus7': cycle},
                        {'plus7': {'x': 1 << 40000}}, {'plus7': {'x' * 1000000: 'r8'}},
                        {'plus7': {'x': 'r8' + '\ud800' * 129}}):
            expected = observed(lambda: plans._reference_register_assignment_witness(self.program, mapping))
            with self.selected():
                self.assertEqual(observed(lambda: plans.register_assignment_witness(self.program, mapping)), expected)

    def test_public_witness_hook_observes_frozen_plan_and_captured_owner(self):
        plan = explicit_plan(self.program, self.placements)
        saved = deepcopy(plan)
        original = plans.register_assignment_witness
        calls = []

        def hook(checked, assignments, **kwargs):
            calls.append(deepcopy(assignments))
            plan['value_registers']['plus7']['x'] = 'rax'
            os.environ[SELECTOR] = str(self.folder / 'missing-after-selection')
            return original(checked, assignments, **kwargs)

        with self.selected(), patch.object(plans, 'register_assignment_witness', side_effect=hook):
            frozen = plans.validate_plan(self.program, plan)
        self.assertEqual(frozen, saved)
        self.assertEqual(calls, [saved['value_registers']])
        self.assertIsNone(plans._NATIVE_OWNER.get())
        with patch.dict(os.environ, {SELECTOR: str(self.folder / 'still-missing')}):
            with self.assertRaises(FileNotFoundError):
                plans.register_assignment_witness(self.program, {})

    def test_foreign_truthiness_key_equality_and_mutation_order(self):
        cases = ('normal', 'first-unknown', 'first-unknown-bad-register',
                 'first-equivalent-key', 'lookup-changes-register',
                 'lookup-invalid-register', 'second-changes-register',
                 'second-clears-functions', 'second-replaces-mapping')

        def run(case, call):
            mapping = {'x': 'r12'}
            assignments = {'plus7': mapping}
            events, booleans, hashes = [], [0], [0]

            class Name(str):
                def __hash__(self):
                    hashes[0] += 1
                    events.append(('hash', hashes[0]))
                    if hashes[0] == 2 and case.startswith('lookup-'):
                        mapping['x'] = 'rax' if case == 'lookup-invalid-register' else 'r15'
                    return str.__hash__(self)

                def __eq__(self, other):
                    events.append(('equal', str(other)))
                    return str.__eq__(self, other)

            class Flag:
                def __bool__(self):
                    booleans[0] += 1
                    events.append(('bool', booleans[0]))
                    if booleans[0] == 1:
                        if case.startswith('first-unknown'):
                            assignments.clear()
                            assignments['missing'] = {'x': 'rax'} if case.endswith('bad-register') else {}
                        if case == 'first-equivalent-key' or case.startswith('lookup-'):
                            assignments.clear()
                            assignments[Name('plus7')] = mapping
                    if booleans[0] == 2:
                        if case == 'second-changes-register':
                            mapping['x'] = 'r15'
                        if case == 'second-clears-functions':
                            assignments.clear()
                        if case == 'second-replaces-mapping':
                            assignments['plus7'] = {'x': 'r15'}
                    return True

            result = observed(lambda: call(self.program, assignments, allow_leaf_registers=Flag()))
            # Normalize only after execution, preserving the actual event tape.
            return json.loads(json.dumps(result, sort_keys=True)), list(events)

        for case in cases:
            expected = run(case, plans._reference_register_assignment_witness)
            with self.selected():
                self.assertEqual(run(case, plans.register_assignment_witness), expected, case)

    def test_selected_failure_has_no_fallback_and_context_is_released(self):
        with self.selected():
            with self.assertRaisesRegex(plans.MachinePlanRejected, 'unknown plan schema'):
                plans.validate_plan(self.program, {})
            self.assertIsNone(plans._NATIVE_OWNER.get())
            with patch.dict(os.environ, {SELECTOR: str(self.folder / 'missing')}):
                with self.assertRaises(FileNotFoundError):
                    plans.validate_plan(self.program, explicit_plan(self.program))

    def test_warm_code_still_rechecks_manifest_and_source(self):
        from hepta import hia_machine_plan_native as bridge
        self.assertIs(installed_machine_plan(str(self.manifest)), self.native)
        source = self.folder / 'changed-source.hepta'
        source.write_bytes(SOURCE.read_bytes() + b'\n')
        with patch.object(bridge, 'SOURCE', source):
            with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                installed_machine_plan(str(self.manifest))
        value = json.loads(self.manifest.read_bytes())
        value['source_sha256'] = '0' * 64
        manifest = self.folder / 'bad-source-manifest.json'
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
            installed_machine_plan(str(manifest))

    def test_backend_custody_binds_selected_native_owner(self):
        from hepta.hia_program_native import _implementation_hash
        with patch.dict(os.environ, {SELECTOR: ''}):
            retained = _implementation_hash()
        with self.selected():
            selected = _implementation_hash()
            self.assertNotEqual(selected, retained)
            self.assertIn(self.native.image_sha256.encode(), plans.native_implementation_identity())
            with patch.object(self.native, 'image_sha256', '0' * 64):
                self.assertNotEqual(_implementation_hash(), selected)

    def test_actual_wheel_native_calls_without_authoring_or_checkout_fallback(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES
        root = Path(__file__).resolve().parents[1]
        case = self.folder / 'installed-control'
        case.mkdir()
        source = case / 'source'
        source.mkdir()
        shutil.copytree(root / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, target)
        packaging_python = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = case / 'wheels', case / 'installed'
        commands = [[packaging_python, '-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps',
                     '--no-index', '--no-build-isolation', '--wheel-dir', str(wheels), str(source)]]
        records = []

        def command(arguments, label, *, env=None):
            result = subprocess.run(arguments, cwd=case, env=env, capture_output=True, timeout=120)
            (case / (label + '.stdout')).write_bytes(result.stdout)
            (case / (label + '.stderr')).write_bytes(result.stderr)
            records.append({'argv': arguments, 'returncode': result.returncode,
                'stdout_sha256': sha256(result.stdout).hexdigest(),
                'stderr_sha256': sha256(result.stderr).hexdigest()})
            (case / 'processes.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result

        command(commands[0], 'wheel-build')
        wheel, = wheels.glob('*.whl')
        command([packaging_python, '-B', '-m', 'pip', 'install', '--no-cache-dir', '--no-deps',
                 '--no-index', '--target', str(installed), str(wheel)], 'wheel-install')
        inputs = case / 'inputs.json'
        inputs.write_text(json.dumps({'core': self.program.as_dict(),
            'plan': explicit_plan(self.program, self.placements),
            'witness': plans._reference_register_assignment_witness(self.program, self.placements)}))
        child = r'''import importlib.abc,json,os,sys
from hashlib import sha256
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed machine plan imported authoring tools')
sys.meta_path.insert(0,NoTools())
from hepta import hia_machine_plan as plans
from hepta.hia_machine_plan_native import SOURCE,SELECTOR,installed_machine_plan
from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine
assert Path(sys.argv[1]) in SOURCE.parents
def forbidden(*args,**kwargs):
    raise AssertionError('retained machine-plan owner entered installed execution')
plans._reference_validate_plan=plans._reference_register_assignment_witness=forbidden
os.environ[SELECTOR]=sys.argv[2]
inputs=json.loads(Path(sys.argv[3]).read_bytes())
core=verify_program(inputs['core'])
plan=plans.validate_plan(core,inputs['plan'])
assert plan==inputs['plan']
assert plans.register_assignment_witness(core,plan['value_registers'])==inputs['witness']
machine=emit_program_machine(core,machine_plan=plan)
assert machine.object_bytes[:4]==b'\x7fELF' and machine.machine_plan_sha256
native=installed_machine_plan(sys.argv[2])
original=SOURCE.read_bytes()
SOURCE.write_bytes(original+b'\n')
try:installed_machine_plan(sys.argv[2])
except ValueError:pass
else:raise AssertionError('warm image hid changed installed source')
SOURCE.write_bytes(original)
SOURCE.unlink()
try:installed_machine_plan(sys.argv[2])
except FileNotFoundError:pass
else:raise AssertionError('missing installed source used checkout fallback')
SOURCE.write_bytes(original)
print(json.dumps({'status':'INSTALLED_NATIVE_MACHINE_PLAN_PASS',
 'image_sha256':native.image_sha256,'source_sha256':sha256(original).hexdigest(),
 'object_sha256':sha256(machine.object_bytes).hexdigest(),
 'isolated_without_site':sys.flags.isolated and sys.flags.no_site,
 'empty_PATH':os.environ['PATH']=='','authoring_forbidden':True,'retained_owners_forbidden':True}))
'''
        script = case / 'installed-control.py'
        script.write_text(child)
        env = {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_HIA_')}
        env.update(PATH='', PYTHONPATH='')
        observed_child = command([sys.executable, '-I', '-S', '-B', str(script), str(installed),
                                  str(self.manifest), str(inputs)], 'installed-execution', env=env)
        observed_result = json.loads(observed_child.stdout)
        self.assertEqual(observed_result['status'], 'INSTALLED_NATIVE_MACHINE_PLAN_PASS')
        self.assertTrue(observed_result['isolated_without_site'])
        self.assertTrue(observed_result['empty_PATH'])


if __name__ == '__main__':
    unittest.main()
