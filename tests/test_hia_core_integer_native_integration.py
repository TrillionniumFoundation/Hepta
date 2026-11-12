"""Source and synthetic controls for matching-cold integer qualification.

These fifteen methods never compile, map or invoke native code, execute the
original Core116/UNPACK18, build an installed distribution, or grant a gate.
Synthetic receipts and IntegerSession doubles exercise the independent readers
and the real outer primitive. A simulated step return is not a native result.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256
import json
import operator
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import hia_core_companion_arguments as arguments
from tools import hia_core_integer_qualification as reader

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_core_integer_native_integration'
POPULATION = ROOT / 'tests/fixtures/hia_core_compare_integration_baseline.json'
IMAGE = 'a' * 64
OPERATIONS = ((11, 1, 1), (11, 2, 2), (12, 2, 3), (12, 3, 4))
COUNTER_FIELDS = (
    'outer_integer_attempts', 'outer_integer_eligible', 'outer_integer_normal_returns',
    'outer_integer_exceptions', 'eligible_normal_returns', 'eligible_exceptions',
    'eligible_exception_terminal_returns', 'eligible_exception_finish_returns',
    'actual_integer_finish_returns')


def tree(path):
    return ast.parse(Path(path).read_bytes())


def assignment(path, name):
    node = next(node for node in tree(path).body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
    return ast.literal_eval(node.value)


def functions(module):
    return {node.name: node for node in module.body if isinstance(node, ast.FunctionDef)}


def methods(path):
    return {cls.name + '.' + node.name: node for cls in tree(path).body
            if isinstance(cls, ast.ClassDef) for node in cls.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}


def groups():
    population = json.loads(POPULATION.read_bytes())['original116']
    return {name: group for group, names in population.items() for name in names}


def synthetic_returns():
    """Invented positive reader input only; no entry or test was executed."""
    population = groups()
    effects = [dict(group=group,
                    test=next(name for name, label in population.items() if label == group),
                    opcode=opcode, operation=operation, image_sha256=IMAGE, count=1)
               for group in ('component', 'original-machine', 'original-core')
               for opcode, operation, _ in OPERATIONS]
    value = {field: [] for field in COUNTER_FIELDS}
    for field in ('outer_integer_attempts', 'outer_integer_eligible',
                  'outer_integer_normal_returns', 'eligible_normal_returns',
                  'actual_integer_finish_returns'):
        value[field] = deepcopy(effects)
    value.update(native_step_semantics=reader.STEP_MEANING,
                 finish_return_semantics=reader.FINISH_MEANING,
                 fixture_step_rows_are_not_test_pass=True,
                 retained_builtin_target_entries=[], unbound_native_returns=[],
                 independent_Core_VM_effects_not_native_proof=[])
    value['actual_integer_step_returns'] = [
        dict(row, native_operation=row['operation'] if row['opcode'] == 11 else row['operation'] + 1,
             status=status, count=1 if status == 0 else 2)
        for row in effects for status in (1, 2, 0)]
    return value, population


def add_synthetic_exception(value, done, finished):
    """Add one failed eligible effect to the first existing aggregate key."""
    row = deepcopy(value['outer_integer_attempts'][0])
    for field in ('outer_integer_attempts', 'outer_integer_eligible'):
        value[field][0]['count'] += 1
    value['outer_integer_exceptions'] = [deepcopy(row)]
    value['eligible_exceptions'] = [deepcopy(row)]
    if done:
        value['eligible_exception_terminal_returns'] = [deepcopy(row)]
        value['actual_integer_step_returns'][2]['count'] += 1
    if finished:
        value['eligible_exception_finish_returns'] = [deepcopy(row)]
        value['actual_integer_finish_returns'][0]['count'] += 1


def synthetic_compile(folder):
    """Complete six-file fixture, explicitly not an executable compiler/image."""
    from hepta import hia_core_integer_selection as selection
    source = (ROOT / selection.HIA_SOURCE).read_bytes()
    compiler = b'synthetic compiler identity; never executable'
    image = b'synthetic integer image; never executable'
    compiler_path = folder / 'compiler.bin'
    compiler_path.write_bytes(compiler)
    image_path = folder / 'core-integer.image.bin'
    image_path.write_bytes(image)
    output = image + bytes(1048576 - len(image))
    source_hash, image_hash, compiler_hash = (sha256(body).hexdigest() for body in (source, image, compiler))
    manifest = {'source_sha256': source_hash, 'image_sha256': image_hash}
    context = {'compiler_sha256': compiler_hash, 'identities': [{}, {}, {'path': str(compiler_path)}],
               'source_manifest': {'tools/hia_selfhost_child.py':
                   sha256((ROOT / 'tools/hia_selfhost_child.py').read_bytes()).hexdigest()}}
    receipt = {'status': 'returned', 'abi_status': 0, 'case': 'core-integer', 'format': 'flat-x86-64',
        'source_sha256': source_hash, 'input_sha256': source_hash, 'input_bytes': len(source),
        'image_sha256': compiler_hash, 'artifact_sha256': compiler_hash,
        'produced_sha256': image_hash, 'produced_image': str(image_path),
        'produced_bytes': len(image), 'core_u32': len(image), 'output_sha256': sha256(output).hexdigest(),
        'source_unchanged': True, 'forbidden_compiler_modules_loaded': [],
        'runner_sha256': context['source_manifest']['tools/hia_selfhost_child.py'], 'wall_elapsed_ns': 1,
        'limits': {'address_bytes': 268435456, 'core_dumpable': False, 'cpu_seconds': 10,
                   'output_capacity': 1048576, 'stack_bytes': 8388608, 'workspace_bytes': 1048576}}
    added = {'case', 'input_sha256', 'input_bytes', 'artifact_sha256', 'format',
             'runner_sha256', 'wall_elapsed_ns', 'produced_image', 'produced_bytes', 'produced_sha256'}
    request = {'format': 'flat-x86-64', 'image': str(compiler_path), 'image_sha256': compiler_hash,
        'source': str(folder / 'core-integer.input.bin'), 'source_sha256': source_hash,
        'capacity': 1048576, 'workspace_size': 1048576, 'workspace_fill': 0,
        'output': str(folder / 'core-integer.output.bin')}
    originals = {'.receipt.json': json.dumps(receipt).encode(),
        '.stdout.log': json.dumps({key: item for key, item in receipt.items() if key not in added}).encode(),
        '.stderr.log': b'', '.request.json': json.dumps(request).encode(),
        '.input.bin': source, '.output.bin': output}
    for suffix, body in originals.items():
        (folder / ('core-integer' + suffix)).write_bytes(body)
    return manifest, receipt, context, originals, added


def observed_fixture():
    """Use the real Core primitive with an explicitly synthetic IntegerSession."""
    from hepta import hia_core_lowering_native as outer
    from tools.qualify_hia_core_integer_callers import IntegerCallObservation
    events = []
    image = SimpleNamespace(image_sha256=IMAGE)

    class SyntheticSession:
        def __init__(self, operation, companion):
            self.operation = operation
            self.image = companion.image
            self.companion = companion

        def step(self, status):
            events.append(('synthetic-raw-entry', status))
            if self.companion.failure_stage == 'step':
                raise self.companion.failure
            events.append(('synthetic-step-return', status))
            return status

        def finish(self):
            events.append(('synthetic-finish-enter', self.operation))
            if self.companion.failure_stage == 'finish':
                raise self.companion.failure
            return self.companion.result

    class Companion:
        _admitted_integer = object()

        def __init__(self):
            self.image = image
            self.result = int('123456789012345678901234567890')
            self.statuses = (1, 2, 0)
            self.failure_stage = None
            self.failure = KeyboardInterrupt('synthetic original failure')
            self.call_retained = False
            self.finish_twice = False
            self.operation_offset = 0
            self.image_override = None

        def run(self, operation):
            session = SyntheticSession(operation + self.operation_offset, self)
            if self.image_override is not None:
                session.image = self.image_override
            for status in self.statuses:
                session.step(status)
            result = session.finish()
            if self.finish_twice:
                session.finish()
            return result

        def binary(self, operation, left, right):
            events.append(('synthetic-binary', operation, left, right))
            if self.call_retained:
                return (operator.add if operation == 1 else operator.sub)(left, right)
            return self.run(operation)

        def unary(self, operation, value):
            events.append(('synthetic-unary', operation, value))
            if self.call_retained:
                return (operator.neg if operation == 2 else operator.invert)(value)
            return self.run(operation + 1)

    companion = Companion()
    session = object.__new__(outer.LoweringSession)
    session.owner = SimpleNamespace(integer=companion)
    session.pending = False
    session.value = lambda handle: (5, 3)[handle - 1]
    name = 'tests.synthetic.CoreLoweringSourceTests.test_integer'
    observation = IntegerCallObservation(outer, SimpleNamespace(IntegerSession=SyntheticSession), {name: 'component'})
    observation.current_test[:] = [name, 'component']
    return SimpleNamespace(outer=outer, events=events, image=image, companion=companion,
                           session=session, observation=observation, Session=SyntheticSession, name=name)


def installed_fixture():
    """Reader-only installed example. All images and results are synthetic."""
    from hepta import hia_core_integer_selection as selection
    sources = dict(zip((selection.HIA_SOURCE, selection.ABI_SOURCE,
                        selection.BRIDGE_SOURCE, selection.SELECTION_SOURCE),
                       ('b' * 64, 'c' * 64, 'd' * 64, 'e' * 64)))
    manifest = {'schema': selection.SCHEMA, 'image_path': 'core-integer.image.bin',
        'image_sha256': IMAGE, 'compiler_sha256': 'f' * 64,
        **{field: sources[name] for field, name in (
            ('source_sha256', selection.HIA_SOURCE), ('abi_sha256', selection.ABI_SOURCE),
            ('bridge_sha256', selection.BRIDGE_SOURCE), ('selection_sha256', selection.SELECTION_SOURCE))}}
    binding = {'manifest': manifest, 'files': [{'sha256': '1' * 64}], 'sources': sources}
    value = {'schema': 'hepta.hia.core-integer-installed-observation.v1',
        **reader.admitted_companion(binding), 'actual_step_semantics': reader.STEP_MEANING,
        'finish_return_semantics': reader.FINISH_MEANING,
        'retained_builtin_target_forbidden': True, 'retained_builtin_target_entries': [],
        'CPython_object_primitives_still_hosted': True,
        'ordinary_eligible_effects': [dict(opcode=opcode, operation=operation, native_operation=native,
            returned=True, done_returns=1, finish_returns=1) for opcode, operation, native in OPERATIONS],
        'step_returns': [dict(phase=phase, native_operation=operation, image_sha256=IMAGE,
            status=status, count=1 if status == 0 else 2)
            for phase in ('ordinary', 'window-probe') for operation in (1, 2, 3, 4) for status in (1, 2, 0)],
        'finish_returns': [dict(phase=phase, native_operation=operation, image_sha256=IMAGE, count=1)
            for phase in ('ordinary', 'window-probe') for operation in (1, 2, 3, 4)],
        'window_probes': [
            {'operation': 1, 'left': '(1<<1025)-1', 'right': '1', 'result': '1<<1025'},
            {'operation': 2, 'left': '1<<1025', 'right': '1', 'result': '(1<<1025)-1'},
            {'operation': 3, 'left': '1<<1025', 'right': None, 'result': '-(1<<1025)'},
            {'operation': 4, 'left': '(1<<1025)-1', 'right': None, 'result': '-(1<<1025)'}],
        'refusals': [name + suffix for name in (selection.ABI_SOURCE, selection.HIA_SOURCE,
            selection.BRIDGE_SOURCE, selection.SELECTION_SOURCE) for suffix in (':changed', ':missing')],
        'restored_identity_sha256': reader.implementation_digest(binding)}
    return value, binding


class IntegerNativeIntegrationSourceTests(unittest.TestCase):
    def test_v1_returns_and_v2_exact_three_manifest_arguments(self):
        legacy = [([], {'schema': 'hepta.hia.core-lowering-installed-companions.v1',
                         'unpack_manifest': None, 'numeric_compare_manifest': None}),
                  (['relative-legacy-manifest'], {'schema': 'hepta.hia.core-lowering-installed-companions.v1',
                         'unpack_manifest': 'relative-legacy-manifest', 'numeric_compare_manifest': None})]
        for argv, wanted in legacy:
            self.assertEqual(arguments.parse_installed_companions(argv), wanted)
        self.assertEqual(arguments.installed_companion_arguments(), [])
        self.assertEqual(arguments.installed_companion_arguments('/unpack'), ['/unpack'])
        two = arguments.installed_companion_arguments('/unpack', '/numeric')
        self.assertEqual(arguments.parse_installed_companions(two), {
            'schema': 'hepta.hia.core-lowering-installed-companions.v1',
            'unpack_manifest': '/unpack', 'numeric_compare_manifest': '/numeric'})
        three = arguments.installed_companion_arguments('/unpack', '/numeric', '/integer')
        expected = {'schema': 'hepta.hia.core-lowering-installed-companions.v2',
                    'unpack_manifest': '/unpack', 'numeric_compare_manifest': '/numeric',
                    'integer_manifest': '/integer'}
        self.assertEqual(arguments.parse_installed_companions(three), expected)
        invalid = [None, ('/unpack',), [True], ['--companions-json'], ['/u', '/n', '/i'],
                   ['--other', three[1]], three + ['extra']]
        for field in expected:
            missing = dict(expected); del missing[field]
            invalid.append(['--companions-json', json.dumps(missing)])
            invalid.append(['--companions-json', three[1][:-1] + ',' + json.dumps(field) + ':"/duplicate"}'])
        for field in ('unpack_manifest', 'numeric_compare_manifest', 'integer_manifest'):
            for item in (None, False, '', 'relative', '/nul\0path'):
                invalid.append(['--companions-json', json.dumps({**expected, field: item})])
        invalid.extend([['--companions-json', json.dumps({**expected, 'extra': '/extra'})],
                        ['--companions-json', json.dumps({**expected, 'schema': 'unknown'})],
                        ['--companions-json', '{"schema":"hepta.hia.core-lowering-installed-companions.v1",'
                         '"unpack_manifest":"/u","numeric_compare_manifest":"/n","integer_manifest":"/i"}']])
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises((ValueError, TypeError)):
                arguments.parse_installed_companions(argv)
        with self.assertRaises(ValueError):
            arguments.installed_companion_arguments('/unpack', None, '/integer')

    def test_installed_literal_parser_and_original_companion_blocks_are_preserved(self):
        current = ROOT / 'tests/test_hia_core_lowering_native.py'
        previous = FIXTURE / 'installed_core_before_integer.py.txt'
        baseline = json.loads((FIXTURE / 'BASELINE.json').read_bytes())
        raw = previous.read_bytes()
        self.assertEqual((len(raw), sha256(raw).hexdigest()),
                         (baseline['installed_test']['bytes'], baseline['installed_test']['sha256']))
        before, after = methods(previous), methods(current)
        self.assertEqual(set(before), set(after))
        self.assertEqual(len(before), 15)
        for name in before.keys() - {baseline['only_installed_method_may_change']}:
            self.assertEqual(ast.dump(before[name]), ast.dump(after[name]), name)
        old_child, new_child = (ast.parse(assignment(path, 'INSTALLED_CHILD')) for path in (previous, current))
        central = functions(tree(ROOT / 'tools/hia_core_companion_arguments.py'))
        self.assertEqual(ast.dump(functions(new_child)['parse_installed_companions']),
                         ast.dump(central['parse_installed_companions']))
        for field in ('unpack_manifest', 'numeric_compare_manifest'):
            condition = "companions[" + repr(field) + "] is not None"
            select = lambda module: [node for node in module.body if isinstance(node, ast.If)
                                     and ast.unparse(node.test) == condition]
            old_blocks, new_blocks = select(old_child), select(new_child)
            self.assertEqual((len(old_blocks), len(new_blocks)), (2, 2))
            self.assertEqual([ast.dump(node) for node in old_blocks],
                             [ast.dump(node) for node in new_blocks], field)
        installed = after[baseline['only_installed_method_may_change']]
        named = [node for node in ast.walk(installed) if isinstance(node, ast.Call)
                 and ast.unparse(node.func) == 'installed_companion_arguments']
        self.assertEqual(len(named), 1)
        self.assertEqual(len(named[0].args), 3)
        child_text = assignment(current, 'INSTALLED_CHILD')
        self.assertNotIn('len(sys.argv)==5', child_text)
        self.assertIn("companions.get('integer_manifest') is not None", child_text)
        for field in ('unpack_observations', 'numeric_compare_observations', 'integer_observations'):
            self.assertIn(field, child_text)

    def test_original32_Core39_116_18_kernel_and_bridge_are_unchanged(self):
        from tools import hia_core_unpack_gates as unpack
        from tools import hia_compiler_owner_gates as core
        baseline = json.loads(POPULATION.read_bytes())
        self.assertEqual(list(unpack.SUCCESSOR_GATES), baseline['original32'])
        self.assertEqual(len(core.SUCCESSOR_GATES), 30)
        self.assertEqual(len(unpack.SUCCESSOR_GATES), 32)
        for missing in unpack.SUCCESSOR_GATES:
            gates = dict.fromkeys(unpack.SUCCESSOR_GATES, True); del gates[missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                unpack.require_successor_gates(gates)
        original = ROOT / 'tools/qualify_hia_core_lowering_callers.py'
        actual = {label: assignment(original, field) for label, field in (
            ('component', 'COMPONENT_IDS'), ('original-machine', 'ORIGINAL_IDS'), ('original-core', 'CORE_IDS'))}
        self.assertEqual(actual, baseline['original116'])
        self.assertEqual([len(actual[label]) for label in ('component', 'original-machine', 'original-core')], [15, 51, 50])
        self.assertEqual(unpack.FINITE_IDS['shim'], baseline['original18']['shim'])
        self.assertEqual(unpack.FINITE_IDS['finite-native'], baseline['original18']['finite-native'])
        self.assertEqual(unpack.expected_component_ids(), baseline['original18']['ordinary'])
        self.assertEqual([len(baseline['original18'][label]) for label in ('shim', 'finite-native', 'ordinary')], [4, 6, 8])
        for name, wanted in unpack.FINITE_PINS.items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), wanted, name)
        pins = json.loads((FIXTURE / 'BASELINE.json').read_bytes())['protected_files']
        for name, pin in pins.items():
            body = (ROOT / name).read_bytes()
            self.assertEqual((len(body), sha256(body).hexdigest()), (pin['bytes'], pin['sha256']), name)
        rows = json.loads((ROOT / 'tests/fixtures/hia_core_compare_core39.json').read_bytes())['files']
        self.assertEqual(len(rows), 40)  # 39 unchanged HIA sources plus ABI.
        for row in rows:
            body = (ROOT / row['path']).read_bytes()
            self.assertEqual((len(body), sha256(body).hexdigest()), (row['size'], row['sha256']), row['path'])

    def test_each_wrapper_calls_the_next_complete_main_once(self):
        chain = (
            ('qualify_hia_core_integer_callers.py', 'numeric.main'),
            ('qualify_hia_core_compare_callers.py', 'unpack.main'),
            ('qualify_hia_core_unpack_callers.py', 'original.main'))
        for name, target in chain:
            main = functions(tree(ROOT / 'tools' / name))['main']
            calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)
                     and ast.unparse(node.func).endswith('.main')]
            self.assertEqual([ast.unparse(node.func) for node in calls], [target], name)
            self.assertEqual(calls[0].args, [])
            self.assertEqual(calls[0].keywords, [])
        integer = (ROOT / 'tools/qualify_hia_core_integer_callers.py').read_text()
        self.assertIn("'complete_numeric_wrapper_calls_required': 1", integer)
        self.assertIn("report['complete_numeric_wrapper_calls'] += 1", integer)
        self.assertIn("'--integer-manifest', str(manifest)", integer)
        self.assertIn("'raw_entry_returns_counted_as_step_returns': False", integer)
        installed = (ROOT / 'tools/hia_core_integer_qualification.py').read_text()
        for field in ('matching_integer_build', 'installed_integer_observation',
                      'installed_numeric_observation', 'installed_UNPACK_observation'):
            self.assertIn(field, installed)
        # Readback joins all nested reports; no additional owner or native execution here.
        self.assertIn('unpack_reader.inspect_callers', installed)
        self.assertIn('numeric_value.get(\'independent_current_cold_readback\') == original', installed)

        # Real unittest callbacks through all three observation layers. These
        # inert fixtures never invoke a primitive, native entry or original116.
        from tools.qualify_hia_core_integer_callers import IntegerCallObservation
        from tools.qualify_hia_core_compare_callers import NumericCallObservation
        from tools import hia_core_unpack_progress as progress
        from tests.test_hia_core_unpack_progress import (
            fixture_modules, run_original_group, original_report)

        def forbidden(*args, **kwargs):
            raise AssertionError('nested source-only observer control entered a primitive')

        class InertOuterSession:
            _primitive = forbidden

        class InertIntegerSession:
            step = forbidden
            finish = forbidden

        class InertNumericSession:
            step = forbidden

        outer = SimpleNamespace(LoweringSession=InertOuterSession,
            _integer_binary_eligible=forbidden, _integer_unary_eligible=forbidden,
            _numeric_comparison_eligible=forbidden)

        def observers(specifications):
            population = {name: group['label'] for group in specifications for name in group['ids']}
            integer = IntegerCallObservation(outer,
                SimpleNamespace(IntegerSession=InertIntegerSession), population)
            numeric = NumericCallObservation(outer,
                SimpleNamespace(NumericCompareSession=InertNumericSession), population)
            return integer, numeric

        missing = object()
        original_callbacks = (unittest.TextTestResult.startTest,
            unittest.TextTestResult.__dict__.get('stopTest', missing),
            unittest.TestResult.startTest, unittest.TestResult.stopTest,
            unittest.TextTestRunner.run)
        with tempfile.TemporaryDirectory(prefix='integer-numeric-progress-source-') as temporary:
            with fixture_modules(unrelated=True) as (specifications, trace):
                integer, numeric = observers(specifications)
                folder = Path(temporary)
                recorder = progress.ProgressRecorder(folder, specifications, lambda: 0)
                with integer.observe(), numeric.observe(), recorder.observe():
                    loaded, result = run_original_group(specifications[0])
                self.assertEqual(loaded, specifications[0]['ids'])
                self.assertEqual(result.testsRun, 4)
                self.assertTrue(result.wasSuccessful())
                for field in ('errors', 'failures', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
                    self.assertEqual(getattr(result, field), [])
                original_pin = original_report(folder)
                binding = recorder.finish(complete=True, original_report=original_pin)
                self.assertTrue(binding['complete'])
                self.assertEqual(binding['status'], 'COMPLETE')
                self.assertEqual(progress.inspect_progress(folder, specifications, original_pin), binding)
                rows = [json.loads(line) for line in (folder / progress.LOG_NAME).read_bytes().splitlines()]
                self.assertEqual([row['subject'] for row in rows if row['event'] == 'test_start'], loaded)
                self.assertEqual([row['subject'] for row in rows if row['event'] == 'test_stop'], loaded)
                self.assertEqual({row['detail']['kind'] for row in rows if row['event'] == 'fixture_begin'},
                                 progress.FIXTURES)
                self.assertTrue(all(row['detail']['outcome'] == 'normal_return'
                                    for row in rows if row['event'] == 'fixture_end'))
                self.assertFalse(any('auxiliary' in row['subject'] for row in rows))
                self.assertEqual(sum(row[0] == 'unrelated_method' for row in trace), 4)
                self.assertTrue(all(row['native_returns'] == 0 for row in rows))
                self.assertFalse(integer.attempts or numeric.attempts)

        # The original stop exception must retain identity even when the
        # inner recorder's secondary diagnostic also raises BaseException.
        for logging_failure in (False, True):
            with self.subTest(progress_logging_failure=logging_failure), \
                    tempfile.TemporaryDirectory(prefix='integer-numeric-progress-error-') as temporary, \
                    fixture_modules() as (specifications, trace):
                integer, numeric = observers(specifications)
                folder = Path(temporary)
                recorder = progress.ProgressRecorder(folder, specifications, lambda: 0)
                original_error = KeyboardInterrupt('original inert stop callback')
                recording_error = SystemExit('secondary inert progress callback')
                called = []
                base_stop = unittest.TestResult.stopTest
                event = recorder.event

                def fail_stop(result, test):
                    called.append(test.id())
                    base_stop(result, test)
                    raise original_error

                def record(kind, *args, **kwargs):
                    if logging_failure and kind == 'test_stop':
                        raise recording_error
                    return event(kind, *args, **kwargs)

                with patch.object(unittest.TestResult, 'stopTest', fail_stop), \
                        integer.observe(), numeric.observe(), recorder.observe(), \
                        patch.object(recorder, 'event', record):
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        run_original_group(specifications[0])
                self.assertIs(caught.exception, original_error)
                self.assertEqual(called, specifications[0]['ids'][:1])
                original_pin = original_report(folder)
                binding = recorder.finish(complete=False, original_report=original_pin)
                self.assertFalse(binding['complete'])
                self.assertEqual(binding['status'], 'HOLD')
                rows = [json.loads(line) for line in (folder / progress.LOG_NAME).read_bytes().splitlines()]
                stops = [row for row in rows if row['event'] == 'test_stop']
                self.assertEqual(len(stops), 0 if logging_failure else 1)
                if stops:
                    self.assertEqual(stops[0]['detail']['exception_type'], 'builtins.KeyboardInterrupt')
                semantic = progress.validate_events((folder / progress.LOG_NAME).read_bytes(),
                    specifications, False, original_pin) if not logging_failure else None
                if semantic is not None:
                    self.assertTrue(semantic['fixture_error_or_exception_seen'])
                    self.assertEqual((semantic['test_start_count'], semantic['test_stop_count']), (1, 1))
                else:
                    with self.assertRaises(ValueError):
                        progress.validate_events((folder / progress.LOG_NAME).read_bytes(),
                            specifications, False, original_pin)
                self.assertFalse(integer.attempts or numeric.attempts)
        restored_callbacks = (unittest.TextTestResult.startTest,
            unittest.TextTestResult.__dict__.get('stopTest', missing),
            unittest.TestResult.startTest, unittest.TestResult.stopTest,
            unittest.TextTestRunner.run)
        for before, after in zip(original_callbacks, restored_callbacks):
            self.assertIs(before, after)

    def test_two_original_owners_and_ambient_selector_cleanup_are_retained(self):
        from tools import qualify_hia_core_unpack_ci as adapter
        from tools import hia_core_unpack_gates as gates
        owned = functions(tree(ROOT / 'tools/qualify_hia_core_unpack_ci.py'))['execute_owned']
        calls = [node for node in ast.walk(owned) if isinstance(node, ast.Call)
                 and ast.unparse(node.func) == 'hia_selfhost_process_owner.run_owned']
        self.assertEqual(len(calls), 1)
        keywords = {item.arg: item.value for item in calls[0].keywords}
        self.assertEqual(ast.literal_eval(keywords['qualification_seconds']), 180)
        self.assertEqual(ast.literal_eval(keywords['cleanup_seconds']), 3)
        with tempfile.TemporaryDirectory(prefix='integer-owned-source-control-') as temporary:
            root = Path(temporary); cold = root / 'cold.json'; cold.write_text('{}')
            base = root / 'evidence'
            env = {'HOME': '/unchanged-home', 'PATH': '/unchanged-path', 'GITHUB_TOKEN': 'synthetic-never-inherited',
                   'HEPTA_KEEP_VALUE': 'ordinary', 'HEPTA_HIA_CORE_INTEGER_MANIFEST': '/ambient/integer',
                   'HEPTA_HIA_CORE_COMPARE_MANIFEST': '/ambient/compare',
                   'HEPTA_HIA_CORE_UNPACK_MANIFEST': '/ambient/unpack',
                   'HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST': '/ambient/development',
                   'HEPTA_OTHER_BUNDLE': '/ambient/bundle'}
            cleaned = adapter.owned_environment(env, cold)
            self.assertEqual((cleaned['HOME'], cleaned['PATH']), (env['HOME'], env['PATH']))
            self.assertEqual(cleaned['HEPTA_KEEP_VALUE'], 'ordinary')
            self.assertNotIn('GITHUB_TOKEN', cleaned)
            self.assertFalse(any(key.startswith('HEPTA_') and ('DEVELOPMENT' in key
                            or key.endswith(('_MANIFEST', '_BUNDLE'))) for key in cleaned))
            self.assertEqual(cleaned['HEPTA_HIA_CORE_UNPACK_COLD_REPORT'], str(cold.resolve()))
            command = gates.owned_command('callers', cold, base)
            self.assertEqual(command, [sys.executable, '-B', '-m', 'tools.qualify_hia_core_integer_callers',
                                      '--cold-report', str(cold.resolve()), '--evidence', str(base / 'callers')])
            context, runtime, final = object(), object(), object()
            seen = []
            with patch.object(gates, 'cold_inputs', return_value=context), \
                 patch.object(gates, 'runtime_identity', return_value=runtime), \
                 patch.object(gates, 'admit_dependencies'), \
                 patch.object(gates, 'inspect_all', return_value=final), \
                 patch.object(adapter, 'execute_owned', side_effect=lambda *args: seen.append(args)):
                self.assertIs(adapter.qualify_all(cold, base), final)
            self.assertEqual(seen, [('callers', cold, base, context), ('component', cold, base, context)])

    def test_compile_reader_binds_six_originals_and_the_full_one_MiB_output(self):
        with tempfile.TemporaryDirectory(prefix='integer-compile-reader-') as temporary:
            folder = Path(temporary)
            manifest, receipt, context, originals, added = synthetic_compile(folder)
            before = reader.compile_originals(folder, manifest, receipt, context)
            self.assertEqual([Path(row['path']).name for row in before],
                             ['core-integer' + suffix for suffix in reader.COMPILE_SUFFIXES])
            self.assertEqual([row['bytes'] for row in before], [len(originals[suffix]) for suffix in reader.COMPILE_SUFFIXES])
            self.assertEqual(before[-1]['bytes'], 1048576)
            for suffix in reader.COMPILE_SUFFIXES:
                path = folder / ('core-integer' + suffix)
                saved = path.read_bytes()
                path.unlink()
                with self.subTest(missing=suffix), self.assertRaises((FileNotFoundError, ValueError)):
                    reader.compile_originals(folder, manifest, receipt, context)
                path.write_bytes(saved)
            for suffix in ('.receipt.json', '.stdout.log', '.request.json', '.input.bin', '.output.bin'):
                path = folder / ('core-integer' + suffix)
                saved = path.read_bytes()
                mutations = [b'changed'] if suffix != '.output.bin' else [saved[:-1], saved + b'X', saved[:-1] + b'X']
                for changed in mutations:
                    path.write_bytes(changed)
                    with self.subTest(suffix=suffix, bytes=len(changed)), self.assertRaises((ValueError, KeyError)):
                        reader.compile_originals(folder, manifest, receipt, context)
                path.write_bytes(saved)
            # stderr is retained verbatim, not arbitrarily required to be empty.
            stderr = folder / 'core-integer.stderr.log'
            stderr.write_bytes(b'synthetic diagnostic\x00\xff')
            changed = reader.compile_originals(folder, manifest, receipt, context)
            self.assertNotEqual(changed, before)
            self.assertEqual(changed[2]['sha256'], sha256(stderr.read_bytes()).hexdigest())
            stderr.write_bytes(originals['.stderr.log'])
            for name, replacement in (('cpu_seconds', 11), ('output_capacity', 1048577), ('workspace_bytes', 1048575)):
                widened = deepcopy(receipt); widened['limits'][name] = replacement
                (folder / 'core-integer.receipt.json').write_text(json.dumps(widened))
                (folder / 'core-integer.stdout.log').write_text(json.dumps({key: value for key, value in widened.items() if key not in added}))
                with self.subTest(limit=name), self.assertRaises(ValueError):
                    reader.compile_originals(folder, manifest, widened, context)
            for suffix in ('.receipt.json', '.stdout.log'):
                (folder / ('core-integer' + suffix)).write_bytes(originals[suffix])
            for key, replacement in (('compiler_sha256', '0' * 64),):
                with self.assertRaises(ValueError):
                    reader.compile_originals(folder, manifest, receipt, {**context, key: replacement})

    def test_return_reader_maps_original_operations_and_requires_DONE_and_finish(self):
        value, population = synthetic_returns()
        observed = reader.validate_returns(value, population, IMAGE)
        self.assertTrue(observed['all116_methods_required_separately'])
        self.assertTrue(observed['fixture_steps_are_not_method_success'])
        actual = {(row['opcode'], row['operation'], row['native_operation']) for row in value['actual_integer_step_returns']}
        self.assertEqual(actual, set(OPERATIONS))
        for label in ('component', 'original-machine', 'original-core'):
            for opcode, operation, native in OPERATIONS:
                with self.subTest(label=label, opcode=opcode, operation=operation):
                    changed = deepcopy(value)
                    row = next(row for row in changed['actual_integer_step_returns']
                               if (row['group'], row['opcode'], row['operation'], row['status']) == (label, opcode, operation, 0))
                    row['native_operation'] = operation if opcode == 12 else 4
                    with self.assertRaises(ValueError):
                        reader.validate_returns(changed, population, IMAGE)
        for field in ('actual_integer_finish_returns', 'actual_integer_step_returns'):
            changed = deepcopy(value); changed[field] = []
            with self.subTest(missing=field), self.assertRaises(ValueError):
                reader.validate_returns(changed, population, IMAGE)

    def test_exception_rows_allow_zero_or_one_DONE_and_finish_without_inventing_success(self):
        for done, finished in ((0, 0), (1, 0), (1, 1)):
            value, population = synthetic_returns()
            add_synthetic_exception(value, done, finished)
            with self.subTest(done=done, finished=finished):
                reader.validate_returns(value, population, IMAGE)
                self.assertEqual(value['eligible_normal_returns'][0]['count'], 1)
                self.assertEqual(value['eligible_exceptions'][0]['count'], 1)
            if done:
                changed = deepcopy(value); changed['eligible_exception_terminal_returns'][0]['count'] = 2
                with self.assertRaises(ValueError):
                    reader.validate_returns(changed, population, IMAGE)
            if finished:
                changed = deepcopy(value); changed['eligible_exception_finish_returns'][0]['count'] = 2
                with self.assertRaises(ValueError):
                    reader.validate_returns(changed, population, IMAGE)
        value, population = synthetic_returns()
        add_synthetic_exception(value, 0, 1)
        with self.assertRaises(ValueError):
            reader.validate_returns(value, population, IMAGE)

    def test_return_reader_refuses_attempt_only_boolean_duplicate_and_unbound_rows(self):
        value, population = synthetic_returns()
        mutations = []
        for field in ('actual_integer_step_returns', 'actual_integer_finish_returns', 'outer_integer_eligible'):
            changed = deepcopy(value); changed[field] = []; mutations.append(changed)
        for field in ('outer_integer_attempts', 'actual_integer_finish_returns', 'actual_integer_step_returns'):
            changed = deepcopy(value); changed[field].append(deepcopy(changed[field][0])); mutations.append(changed)
        for field in ('opcode', 'operation', 'native_operation', 'status', 'count'):
            changed = deepcopy(value); changed['actual_integer_step_returns'][0][field] = True; mutations.append(changed)
        for field, replacement in (('test', 'unbound-test'), ('group', 'unknown-group'), ('image_sha256', 'b' * 64)):
            changed = deepcopy(value); changed['actual_integer_step_returns'][0][field] = replacement; mutations.append(changed)
        for field in ('retained_builtin_target_entries', 'unbound_native_returns'):
            changed = deepcopy(value); changed[field] = ['actual-forbidden-observation']; mutations.append(changed)
        changed = deepcopy(value); changed['actual_integer_step_returns'][0]['operation'] = 3; mutations.append(changed)
        changed = deepcopy(value); changed['outer_integer_normal_returns'][0]['count'] = 2; mutations.append(changed)
        changed = deepcopy(value); changed['native_step_semantics'] = 'entry attempted'; mutations.append(changed)
        changed = deepcopy(value); changed['finish_return_semantics'] = 'DONE is finish'; mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.validate_returns(changed, population, IMAGE)

    def test_observer_binds_target_before_each_operand_once_for_binary_and_unary(self):
        for opcode, operation, native_operation in OPERATIONS:
            fixture = observed_fixture()
            outer, events = fixture.outer, fixture.events
            registry_name = '_BINARY' if opcode == 11 else '_UNARY'
            class Registry(dict):
                def __getitem__(self, key):
                    events.append(('target', key))
                    return super().__getitem__(key)
            registry = Registry(getattr(outer, registry_name))
            def get(handle):
                events.append(('get', handle))
                if handle == 1:
                    registry[operation] = lambda *args: (_ for _ in ()).throw(AssertionError('rebound target used'))
                return (5, 3)[handle - 1]
            fixture.session.value = get
            old_profile = sys.getprofile()
            with patch.object(outer, registry_name, registry), fixture.observation.observe():
                operands = (operation, 1, 2) if opcode == 11 else (operation, 1)
                result = fixture.session._primitive(opcode, operands, ())
            self.assertIs(result[1][0], fixture.companion.result)
            self.assertEqual(events[:3] if opcode == 11 else events[:2],
                             [('target', operation), ('get', 1), ('get', 2)] if opcode == 11
                             else [('target', operation), ('get', 1)])
            self.assertEqual([row for row in events if row[0] == 'get'],
                             [('get', 1), ('get', 2)] if opcode == 11 else [('get', 1)])
            self.assertEqual({key[5] for key in fixture.observation.returns}, {native_operation})
            self.assertEqual(sum(fixture.observation.finishes.values()), 1)
            self.assertIs(sys.getprofile(), old_profile)

    def test_observer_preserves_boolean_foreign_mutated_targets_and_separate_VM_scope(self):
        fixture = observed_fixture()
        class Foreign(int):
            def __add__(self, other):
                return 'foreign binary result'
            def __neg__(self):
                return 'foreign unary result'
        with fixture.observation.observe():
            for opcode, operation, values, wanted in (
                (11, 1, (True, 3), 4), (12, 2, (True,), -1),
                (11, 1, (Foreign(5), 3), 'foreign binary result'),
                (12, 2, (Foreign(5),), 'foreign unary result')):
                fixture.session.value = lambda handle, values=values: values[handle - 1]
                args = (operation, 1, 2) if opcode == 11 else (operation, 1)
                self.assertEqual(fixture.session._primitive(opcode, args, ()), (0, (wanted,)))
            marker = object()
            fixture.session.value = lambda handle: (5, 3)[handle - 1]
            with patch.dict(fixture.outer._BINARY, {1: lambda left, right: marker}):
                self.assertIs(fixture.session._primitive(11, (1, 1, 2), ())[1][0], marker)
            self.assertFalse(fixture.observation.eligible)
            self.assertFalse(fixture.observation.returns)
            self.assertFalse(fixture.observation.finishes)
            fixture.session.owner = SimpleNamespace(integer=None)
            self.assertEqual(fixture.session._primitive(11, (1, 1, 2), ()), (0, (8,)))
            self.assertEqual(sum(fixture.observation.unadmitted_VM.values()), 1)
            fixture.session.owner._admitted_bundle = object()
            with self.assertRaisesRegex(AssertionError, 'lost its integer companion'):
                fixture.session._primitive(11, (1, 1, 2), ())
            fixture.session.owner = SimpleNamespace(integer=None)
            fixture.observation.current_test[:] = ['tests.synthetic.NativeTests.test_case', 'component']
            with self.assertRaisesRegex(AssertionError, 'lost its integer companion'):
                fixture.session._primitive(11, (1, 1, 2), ())
        self.assertEqual(fixture.observation.report()['independent_Core_VM_effects_not_native_proof'][0]['count'], 1)

    def test_original_exceptions_raw_entry_and_finish_failures_remain_distinct(self):
        for stage in ('left-get', 'right-get', 'step', 'finish'):
            fixture = observed_fixture()
            failure = KeyboardInterrupt('the original exception object')
            old_profile = sys.getprofile()
            def get(handle):
                fixture.events.append(('get', handle))
                if (stage == 'left-get' and handle == 1) or (stage == 'right-get' and handle == 2):
                    raise failure
                return (5, 3)[handle - 1]
            fixture.session.value = get
            if stage in ('step', 'finish'):
                fixture.companion.failure_stage = stage
                fixture.companion.failure = failure
                fixture.companion.statuses = (0,)
            with fixture.observation.observe(), self.assertRaises(KeyboardInterrupt) as caught:
                fixture.session._primitive(11, (1, 1, 2), ())
            self.assertIs(caught.exception, failure)
            self.assertIs(sys.getprofile(), old_profile)
            self.assertEqual(sum(fixture.observation.failed.values()), 1)
            self.assertEqual(sum(fixture.observation.normal.values()), 0)
            self.assertEqual(sum(fixture.observation.finishes.values()), 0)
            self.assertEqual(sum(fixture.observation.failed_finish.values()), 0)
            self.assertEqual(sum(fixture.observation.failed_done.values()), int(stage == 'finish'))
            if stage == 'step':
                self.assertIn(('synthetic-raw-entry', 0), fixture.events)
                self.assertFalse(fixture.observation.returns)
            if stage == 'finish':
                self.assertEqual(sum(fixture.observation.returns.values()), 1)
            self.assertEqual([row for row in fixture.events if row[0] == 'get'],
                             [('get', 1)] if stage == 'left-get' else [('get', 1), ('get', 2)])

    def test_observer_refuses_unbound_duplicate_wrong_image_and_retained_builtin_returns(self):
        for mode in ('unbound-step', 'unbound-finish', 'repeat-DONE', 'repeat-finish',
                     'wrong-image', 'wrong-operation', 'retained-target', 'pending', 'unadmitted'):
            fixture = observed_fixture()
            if mode == 'repeat-DONE':
                fixture.companion.statuses = (0, 0)
            elif mode == 'repeat-finish':
                fixture.companion.finish_twice = True
            elif mode == 'wrong-image':
                fixture.companion.image_override = SimpleNamespace(image_sha256='b' * 64)
            elif mode == 'wrong-operation':
                fixture.companion.operation_offset = 1
            elif mode == 'retained-target':
                fixture.companion.call_retained = True
            elif mode == 'pending':
                fixture.session.pending = True
            elif mode == 'unadmitted':
                fixture.session.owner.integer = SimpleNamespace(image=fixture.image)
            with self.subTest(mode=mode), fixture.observation.observe(), self.assertRaises(AssertionError):
                if mode == 'unbound-step':
                    fixture.Session(1, fixture.companion).step(0)
                elif mode == 'unbound-finish':
                    fixture.Session(1, fixture.companion).finish()
                else:
                    fixture.session._primitive(11, (1, 1, 2), ())
            self.assertFalse(fixture.observation.normal)
            if mode.startswith('unbound'):
                self.assertEqual(len(fixture.observation.unbound), 1)
            if mode == 'retained-target':
                self.assertEqual(len(fixture.observation.retained), 1)

    def test_installed_reader_requires_four_cross_window_operations_and_eight_refusals(self):
        value, binding = installed_fixture()
        self.assertIs(reader.validate_installed(value, binding), value)
        self.assertEqual(len(value['refusals']), 8)
        self.assertEqual(len(set(value['refusals'])), 8)
        self.assertEqual({row['operation'] for row in value['window_probes']}, {1, 2, 3, 4})
        for operation in (1, 2, 3, 4):
            rows = [row for row in value['step_returns']
                    if row['phase'] == 'window-probe' and row['native_operation'] == operation]
            self.assertEqual({row['status']: row['count'] for row in rows}, {0: 1, 1: 2, 2: 2})
        # The producer's literal four-source loop and restoration remain inspectable.
        child = ast.parse(assignment(ROOT / 'tests/test_hia_core_lowering_native.py', 'INSTALLED_CHILD'))
        integer_blocks = [node for node in child.body if isinstance(node, ast.If)
                          and ast.unparse(node.test) == "companions.get('integer_manifest') is not None"]
        self.assertEqual(len(integer_blocks), 2)
        report_block = ast.unparse(integer_blocks[-1])
        self.assertIn('(INTEGER_ABI, INTEGER_SOURCE, INTEGER_BRIDGE, INTEGER_SELECTION)', report_block)
        self.assertIn('finally:', report_block)
        self.assertIn('path.write_bytes(original)', report_block)
        self.assertIn('integer_identity(owner.integer) == integer_identity_before', report_block)
        self.assertIn('for operation in (1, 2, 3, 4)', report_block)

    def test_installed_reader_rejects_short_windows_missing_origins_and_changed_image_bindings(self):
        value, binding = installed_fixture()
        mutations = []
        for operation in (1, 2, 3, 4):
            for status in (1, 2):
                changed = deepcopy(value)
                row = next(row for row in changed['step_returns'] if
                           (row['phase'], row['native_operation'], row['status']) == ('window-probe', operation, status))
                row['count'] = 1
                mutations.append(changed)
        for field in ('step_returns', 'finish_returns'):
            changed = deepcopy(value); changed[field].append(deepcopy(changed[field][0])); mutations.append(changed)
            changed = deepcopy(value); changed[field][0]['image_sha256'] = '0' * 64; mutations.append(changed)
            changed = deepcopy(value); changed[field][0]['count'] = True; mutations.append(changed)
            changed = deepcopy(value); changed[field][0]['phase'] = 'unbound'; mutations.append(changed)
        for field in ('opcode', 'operation', 'native_operation', 'done_returns', 'finish_returns'):
            changed = deepcopy(value); changed['ordinary_eligible_effects'][0][field] = True; mutations.append(changed)
        for field in reader.admitted_companion(binding):
            changed = deepcopy(value); changed[field] = '0' * 64; mutations.append(changed)
        for index in range(8):
            changed = deepcopy(value); del changed['refusals'][index]; mutations.append(changed)
        for field in ('ordinary_eligible_effects', 'step_returns', 'finish_returns', 'window_probes'):
            changed = deepcopy(value); changed[field] = []; mutations.append(changed)
        changed = deepcopy(value); changed['refusals'].append(value['refusals'][0]); mutations.append(changed)
        changed = deepcopy(value); changed['restored_identity_sha256'] = '0' * 64; mutations.append(changed)
        changed = deepcopy(value); changed['retained_builtin_target_entries'] = ['entered']; mutations.append(changed)
        changed = deepcopy(value); changed['ordinary_eligible_effects'][0]['returned'] = False; mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                reader.validate_installed(changed, binding)


if __name__ == '__main__':
    unittest.main()
