"""Ordinary task instruction ownership, ordered effects and native custody."""
from __future__ import annotations

from copy import deepcopy
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
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program
from hepta.hia_task_operations_native import (SOURCE, SCHEMA, SELECTOR, MAGIC,
    INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, TaskPacket, TaskResult,
    NativeTaskOperations, installed_task_operations, selected_task_operations)
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests import test_hia_composite_returned_loans as loans
from tests import test_hia_task_helpers_native as helpers
from tests.test_hia_program import b, f

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_TASK_OPERATIONS_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_TASK_OPERATIONS_DEVELOPMENT_MANIFEST'


def wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode()


def outcome(call):
    try:
        return call(), None
    except HIAProgramRejected as exc:
        return None, (exc.code, str(exc))


def empty_program():
    types = [fixtures.record('Empty', []),
        fixtures.enum('Step', [('pending', [('state', 'Empty')]), ('ready', [('result', 'Empty')])]),
        dict(name='Work', params=[], kind='task', state='Empty', result='Empty', poll='poll', cancel='cancel')]
    return fixtures.module(types,
        f('poll', [('state', 'Empty')], ['Step'], [], [b('entry', [('state', 'Empty')], [
            fixtures.i('enum.make', ['state'], [('step', 'Step')], variant='ready')], fixtures.ret('step'))]),
        f('cancel', [('state', 'Empty')], [], [], [b('entry', [('state', 'Empty')], [], fixtures.ret())]),
        f('empty_task', [], ['u8'], ['alloc', 'trap'], [b('entry', [], [
            fixtures.i('record.make', [], [('state', 'Empty')]),
            fixtures.i('task.create', ['state'], [('created', 'Work')]),
            fixtures.i('task.start', ['created'], [('started', 'Work')]),
            fixtures.i('task.poll', ['started'], [('completed', 'Work')]),
            fixtures.i('task.state', ['completed'], [('status', 'u8')]),
            fixtures.i('task.join', ['completed'], [('result', 'Empty')]),
        ], fixtures.ret('status'))]))


class TaskOperationsSourceTests(unittest.TestCase):
    def test_exact_generator_and_unchanged_compiler_profile(self):
        from tools import generate_hia_task_operations as generator
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        from hepta.hia_agent_assembly import render_assembly
        document = generator.document()
        self.assertEqual(render_assembly(document).encode(), SOURCE.read_bytes())
        self.assertLessEqual(len(document['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in document['functions']
                                 for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for fn in document['functions']
                                 for block in fn['blocks']), 16)
        self.assertEqual((generator.MAGIC, generator.INPUT_BYTES, generator.OUTPUT_BYTES,
                          generator.WORKSPACE_BYTES), (MAGIC, INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES))
        verify_core(document)

    def test_selected_missing_image_cannot_enter_reference(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_task_operations())
        with patch.dict(os.environ, {SELECTOR: '/missing-task-operations'}), patch.object(
                composite._Elaborator, '_reference_task_operation', side_effect=AssertionError('host task called')):
            with self.assertRaises(HIAProgramRejected):
                verify_core(empty_program())

    def test_packet_copies_identity_without_semantic_key_expansion(self):
        class ForbiddenKey:
            def __str__(self):
                raise AssertionError('display key expanded')
            def __hash__(self):
                raise AssertionError('semantic identity hashed')
            def __eq__(self, other):
                raise AssertionError('semantic identity compared')
        empty = composite._Type(ForbiddenKey(), 'record', ())
        task = composite._Type(ForbiddenKey(), 'task', ('u8', 'buffer'), state=empty, result=empty, linear=True)
        value = composite._Value(task, ('tag', 'token'))
        context = TaskPacket('task.start', ['input', 'input'], {}, [value, value], [('out', task)], 0)
        self.assertIs(type(context.data()), bytes)
        self.assertEqual((len(context.values), len(context.types)), (1, 2))
        self.assertEqual(context.arguments, [['input', 0], ['input', 0]])


class TaskOperationsAdapterTests(unittest.TestCase):
    def context(self, operation='task.create', phase=0):
        owner = composite._Elaborator(empty_program())
        task = owner.types.resolve('Work'); state = task.state
        actual = composite._Value(state if operation == 'task.create' else task,
                                  () if operation == 'task.create' else ('tag', 'token'))
        context = TaskPacket(operation, ['input'], {}, [actual], [('out', task)], 7)
        context.data(); context.phase = phase
        return context

    def frame(self, context, *, request=0, error=0, final=None, query=None, ops=None, values=None, flags=None):
        if values is None:
            values = [] if request in (1, 2, 3) or error or context.operation == 'task.close' or context.phase == 2 else [['out', 0, ['token'], False, False]]
        if query is None and request:
            query = ({'type': 0} if request == 1 else {'type': 'u8'} if request == 2 else
                     {} if request == 3 else {'type': 0, 'operation': context.operation[5:]})
        raw = wire({'ops': [] if ops is None else ops,
                    'consumed': [False] if flags is None else flags, 'values': values, 'query': query})
        return struct.pack('<8Q', MAGIC, error, context.serial if final is None else final,
                           request, len(raw), 0, 0, 0) + raw

    def image(self, data, *, mutate=False):
        image = object.__new__(NativeTaskOperations)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate:
                ctypes.memmove(source, b'x', 1)
            if type(data) is int:
                return data
            ctypes.memmove(output, data, len(data))
            return len(data)
        image._entry = entry
        return image

    def test_strict_frames_queries_and_effect_prefixes(self):
        context = self.context(phase=1)
        for data in (0, 0xfffffff1, self.frame(context, final=6), self.frame(context, final=8193),
                     self.frame(context, error=99), self.frame(context, error=1),
                     self.frame(context, query={}), self.frame(context, values=[])):
            with self.subTest(data=repr(data)[:70]), self.assertRaises(HIAProgramRejected):
                self.image(data).step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'input bytes changed'):
            self.image(self.frame(context), mutate=True).step(context)
        context = self.context()
        for query in ({}, {'type': -1}, {'type': False}, {'type': 0, 'plan': []}):
            with self.assertRaises(HIAProgramRejected):
                self.image(self.frame(context, request=1, query=query)).step(context)
        for altered in ({'ops': [{}]}, {'flags': [True]}, {'final': 8}):
            with self.assertRaises(HIAProgramRejected):
                self.image(self.frame(context, request=1, **altered)).step(context)
        context = self.context('task.start', 1)
        for query in ({}, {'type': -1, 'operation': 'start'}, {'type': 0, 'operation': 'close'}):
            with self.assertRaises(HIAProgramRejected):
                self.image(self.frame(context, request=4, query=query)).step(context)

    def test_cannot_skip_repeat_or_reorder_owner_continuations(self):
        phases = {'task.create': (1, 0), 'task.state': (2, 3, 2, 0),
                  'task.start': (3, 4, 0), 'task.close': (3, 4, 0), 'task.unknown': (0,)}
        for operation, expected in phases.items():
            for phase in range(4):
                for request in range(5):
                    if phase < len(expected) and request == expected[phase]:
                        continue
                    context = self.context(operation, phase)
                    with self.subTest(operation=operation, phase=phase, request=request), self.assertRaises(HIAProgramRejected):
                        self.image(self.frame(context, request=request)).step(context)


class TaskOperationsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development tasks cannot override cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-task-operations-')
        cls.addClassCleanup(cls.temporary.cleanup); cls.folder = Path(cls.temporary.name)
        if development:
            supplied = Path(development); value = json.loads(supplied.read_bytes()); name = value['image_path']
            assert type(name) is str and Path(name).name == name
            shutil.copyfile(supplied.parent / name, cls.folder / name)
            cls.manifest = cls.folder / 'manifest.json'; cls.manifest.write_bytes(supplied.read_bytes())
            cls.fixture_scope = 'DEVELOPMENT_ONLY'
        elif cold:
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes()); nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='task-operations')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder); source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'task-operations', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_task_operations(str(cls.manifest))

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def supporting(self, tests, implementation):
        fixture = type('SupportingFixture', (unittest.TestCase,), {})
        self.addCleanup(fixture.doClassCleanups)
        extra = {}
        if os.environ.get(COLD_REPORT) and not os.environ.get(tests.COLD_REPORT):
            extra[tests.COLD_REPORT] = os.environ[COLD_REPORT]
        with patch.dict(os.environ, extra):
            implementation.setUpClass.__func__(fixture)
        return fixture

    def compare_at_tasks(self, document, *, variations=None, serials=(0, 8187, 8188, 8190, 8191, 8192), prepare=None, native_helpers=None):
        """Compare the retained branch and full owner including failed helper cache.

        Existing closures observe the real env/ops objects, restored in place.
        Every run records owner callbacks, helper functions/names, type caches,
        flags, bindings, counter and instruction prefix, including exceptions.
        """
        case, observations = self, []
        reference = composite._Elaborator._reference_task_operation
        selected = composite._Elaborator.lower_task_operation
        def freeze(value):
            if isinstance(value, composite._Type):
                return ('type', value.key)
            if isinstance(value, dict):
                return tuple((key, freeze(item)) for key, item in sorted(value.items()))
            if isinstance(value, (tuple, list)):
                return tuple(freeze(item) for item in value)
            return value
        def compare(owner, ins, actual, declared, env, ops, consume, outputs):
            initial_serial, initial_env, initial_ops = owner.serial, dict(env), deepcopy(ops)
            held = {id(item): (item, item.consumed) for item in [*env.values(), *actual]}
            choices = [(deepcopy(ins), actual, declared)]
            if variations:
                choices.extend(variations(owner, ins, actual, declared))
            saved_cache, saved_active = dict(owner.types.cache), set(owner.types.active)
            saved_loans, saved_steps = dict(owner.types.known_loan_cache), owner.types.partial_declaration_steps
            saved_helpers, saved_names = deepcopy(owner.helpers), dict(owner.helper_names)
            saved_functions, saved_signatures = dict(owner.functions), dict(owner.signatures)
            def restore():
                env.clear(); env.update(initial_env); ops[:] = deepcopy(initial_ops)
                for item, consumed in held.values():
                    item.consumed = consumed
                owner.types.cache.clear(); owner.types.cache.update(saved_cache)
                owner.types.active.clear(); owner.types.active.update(saved_active)
                owner.types.known_loan_cache.clear(); owner.types.known_loan_cache.update(saved_loans)
                owner.types.partial_declaration_steps = saved_steps
                owner.helper_names.clear(); owner.helper_names.update(saved_names)
                owner.helpers[:] = deepcopy(saved_helpers)
                owner.functions.clear(); owner.functions.update(saved_functions)
                owner.signatures.clear(); owner.signatures.update(saved_signatures)
            def observed(call):
                trace = []
                methods = {name: getattr(owner, name) for name in ('parameters', 'check_task', 'helper')}
                resolve = owner.types.resolve
                def tracked(name):
                    def invoke(*args, **kwargs):
                        trace.append((name, freeze(args), owner.serial,
                            tuple((key, value.consumed) for key, value in env.items()), len(ops)))
                        return methods[name](*args, **kwargs)
                    return invoke
                def tracked_resolve(*args, **kwargs):
                    trace.append(('resolve', freeze(args), owner.serial))
                    return resolve(*args, **kwargs)
                with patch.object(owner.types, 'resolve', side_effect=tracked_resolve), patch.object(
                        owner, 'parameters', side_effect=tracked('parameters')), patch.object(
                        owner, 'check_task', side_effect=tracked('check_task')), patch.object(
                        owner, 'helper', side_effect=tracked('helper')):
                    _, error = outcome(call)
                snapshot = {name: (freeze(item.typ), item.names, item.external, item.consumed)
                            for name, item in env.items()}
                return (error, owner.serial, deepcopy(ops), snapshot, trace, freeze(owner.types.cache),
                        owner.types.partial_declaration_steps, freeze(owner.types.known_loan_cache),
                        dict(owner.helper_names), deepcopy(owner.helpers))
            for changed, values, declarations in choices:
                for serial in serials:
                    # Counter injection is a test boundary. Clear existing
                    # helpers so their generated names cannot lie in its future.
                    restore(); owner.serial = serial; owner.helpers.clear(); owner.helper_names.clear()
                    if prepare:
                        prepare(owner, changed, actual, env)
                    expected = observed(lambda: reference(owner, changed, values, declarations,
                        env, ops, consume, outputs))
                    restore(); owner.serial = serial; owner.helpers.clear(); owner.helper_names.clear()
                    if prepare:
                        prepare(owner, changed, actual, env)
                    with patch('hepta.hia_task_operations_native.selected_task_operations', return_value=case.native), patch(
                            'hepta.hia_task_helpers_native.selected_task_helpers', return_value=native_helpers):
                        native = observed(lambda: selected(owner, changed, values, declarations,
                            env, ops, consume, outputs))
                    case.assertEqual(native, expected, (changed, serial))
                    observations.append((changed['op'], expected[0], serial, expected[1],
                        len(expected[2]) - len(initial_ops), expected[3], expected[4], expected[8], expected[9]))
            restore(); owner.serial = initial_serial
            return reference(owner, ins, actual, declared, env, ops, consume, outputs)
        with patch.object(composite._Elaborator, 'lower_task_operation', compare):
            _, original_error = outcome(lambda: verify_core(document))
        self.assertTrue(observations, 'fixture must reach real task lowering')
        return observations, original_error

    def test_exact_core_all_profiles_and_runtime_ownership(self):
        cases = [(fixtures.task_program, 'task_case', [[0], [1], [2]], [33, 13, 28]),
                 (fixtures.scalar_task_program, 'scalar_task', [[]], [3]),
                 (fixtures.owned_result_task_program, 'owned_result', [[0], [19]], [0, 19]),
                 (empty_program, 'empty_task', [[]], [2])]
        for version in range(1, 5):
            for factory, name, arguments, answers in cases:
                document = factory(); document['schema'] = 'hepta.hia.composite.v' + str(version)
                with patch.dict(os.environ, {SELECTOR: ''}):
                    expected = verify_core(document)
                with self.selected(), patch.object(composite._Elaborator, '_reference_task_operation',
                        side_effect=AssertionError('host task called')):
                    actual = verify_core(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))
                for inputs, answer in zip(arguments, answers):
                    report = execute_program(actual, name, inputs)
                    self.assertEqual(report['result'], answer)
                    self.assertEqual((report['resources']['live_owners'], report['resources']['live_local_loans']), (0, 0))
        for factory in helpers.FACTORIES:
            document = factory()
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_task_operation',
                    side_effect=AssertionError('host task called')):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))

    def test_exact_errors_counter_instruction_prefix_and_helper_cache_order(self):
        def variations(owner, ins, actual, declared):
            choices = []
            for attrs in ({'extra': 1}, None):
                changed = deepcopy(ins); changed['attrs'] = attrs; choices.append((changed, actual, declared))
            changed = deepcopy(ins); changed['args'] = []; choices.append((changed, [], declared))
            changed = deepcopy(ins); changed['args'] *= 2; choices.append((changed, actual * 2, declared))
            changed = deepcopy(ins); changed['op'] = 'task.unknown'; choices.append((changed, actual, declared))
            if ins['op'] == 'task.create':
                choices += [(deepcopy(ins), actual, []),
                    (deepcopy(ins), actual, [('wrong', owner.types.resolve('u32'))])]
            else:
                for outputs in [[], [{'name': 'wrong', 'type': 'bool'}],
                                [{'name': 'wrong', 'type': 'Unknown'}]]:
                    changed = deepcopy(ins); changed['out'] = outputs; choices.append((changed, actual, declared))
            return choices
        rows = []
        for document in (empty_program(), fixtures.owned_result_task_program(), fixtures.scalar_task_program()):
            observations, error = self.compare_at_tasks(document, variations=variations)
            self.assertIsNone(error); rows += observations
        self.assertEqual({row[0] for row in rows}, {'task.create', 'task.state', 'task.start',
            'task.poll', 'task.cancel', 'task.join', 'task.close', 'task.unknown'})
        self.assertTrue({'E_HIA_TYPE', 'E_HIA_FORMAT', 'E_HIA_OPCODE', 'E_HIA_LIMIT'} <=
                        {row[1][0] for row in rows if row[1]})
        self.assertTrue(any(row[0] == 'task.create' and row[1] and row[4] > 0 for row in rows))
        self.assertTrue(any(row[1] and row[7] and not row[8] for row in rows), 'failed helpers retain their allocated cache names')
        self.assertTrue(any(row[1] and any(call[0] == 'helper' and any(consumed for _, consumed in call[3])
            for call in row[6]) for row in rows), 'helper failures observe consumed prefix state')

    def test_protocol_refusals_and_consumed_state_keep_original_order(self):
        def missing(owner, ins, actual, env):
            owner.functions.pop('cancel', None)
        rows, error = self.compare_at_tasks(empty_program(), serials=(0, 8192), prepare=missing)
        self.assertIsNone(error)
        self.assertTrue(any(row[0] == 'task.create' and row[1][0] == 'E_HIA_CALL' and row[2] == 8192 for row in rows))
        self.assertTrue(any(row[0] == 'task.join' and row[1][0] == 'E_HIA_CALL' and row[7] == {} for row in rows))
        def consumed(owner, ins, actual, env):
            for value in actual:
                value.consumed = True
        rows, error = self.compare_at_tasks(empty_program(), serials=(0,), prepare=consumed)
        self.assertIsNone(error)
        self.assertTrue(all(row[1][0] == 'E_HIA_RESOURCE' for row in rows if row[0] != 'task.state'))
        self.assertTrue(all(row[1] is None for row in rows if row[0] == 'task.state'))

    def test_selected_native_helpers_preserve_failed_cache_and_repeated_use(self):
        support = self.supporting(helpers, helpers.TaskHelpersNativeTests)
        rows, error = self.compare_at_tasks(empty_program(), serials=(0, 8150, 8187, 8190, 8191, 8192),
                                            native_helpers=support.native)
        self.assertIsNone(error)
        self.assertTrue(any(row[1] and row[7] and not row[8] for row in rows))
        # close has no output-name allocation. An earlier helper failure can
        # leave its name cached; a repeat must call that same absent helper in
        # the raw lowering state, just as the unchanged original branch does.
        snapshots = []
        for native in (False, True):
            owner = composite._Elaborator(empty_program()); task = owner.types.resolve('Work')
            owner.serial = 8191
            env = {'input': composite._Value(task, ('tag', 'token'))}; ops = []
            ins = fixtures.i('task.close', ['input'])
            def consume(name):
                if env[name].consumed:
                    raise HIAProgramRejected('use of consumed nominal value', 'E_HIA_RESOURCE')
                if env[name].typ.linear:
                    env[name].consumed = True
            def outputs(instruction, expected):
                result = owner.parameters(instruction['out'])
                if tuple(typ for _, typ in result) != tuple(expected):
                    raise HIAProgramRejected('nominal output type/arity mismatch', 'E_HIA_TYPE')
                return [name for name, _ in result]
            implementation = owner.lower_task_operation if native else owner._reference_task_operation
            with patch('hepta.hia_task_operations_native.selected_task_operations', return_value=self.native), patch(
                    'hepta.hia_task_helpers_native.selected_task_helpers', return_value=support.native if native else None):
                _, first = outcome(lambda: implementation(ins, [env['input']], (), env, ops, consume, outputs))
                state = (first, owner.serial, dict(owner.helper_names), deepcopy(owner.helpers), deepcopy(ops), env['input'].consumed)
                env['input'] = composite._Value(task, ('again_tag', 'again_token'))
                _, second = outcome(lambda: implementation(ins, [env['input']], (), env, ops, consume, outputs))
                snapshots.append((state, second, owner.serial, dict(owner.helper_names),
                                  deepcopy(owner.helpers), deepcopy(ops), env['input'].consumed))
        self.assertEqual(snapshots[0], snapshots[1])
        self.assertEqual(snapshots[0][0][0][0], 'E_HIA_LIMIT')
        self.assertIsNone(snapshots[0][1])
        self.assertEqual(snapshots[0][5][0]['attrs']['function'], 'h2internal_8192')

    def test_maximum_task_layout_zero_result_and_inactive_loan_refusal_prefix(self):
        document = helpers.maximum_program()
        document['functions'].append(f('make_task', [('state', 'Empty')], ['Task'], ['alloc'], [
            b('entry', [('state', 'Empty')], [fixtures.i('task.create', ['state'], [('task', 'Task')])], fixtures.ret('task'))]))
        rows, error = self.compare_at_tasks(document, serials=(0, 6658, 6659, 8190, 8192))
        self.assertIsNone(error)
        self.assertTrue(any(row[2] == 6658 and row[1] is None and row[3] == 8192 for row in rows))
        self.assertTrue(any(row[2] == 6659 and row[1][0] == 'E_HIA_LIMIT' and row[4] == 1022 for row in rows))
        # Direct-owner controls retain the old unreachable loan-padding refusal.
        # Public task declarations still reject loans at the separate type owner.
        for result_types in (['readbuf'], ['buffer', 'mutbuf'], ['chain', 'buffer', 'readbuf']):
            for serial in (0, 8189, 8192):
                results = []
                for native in (False, True):
                    owner, task = helpers.helper_owner([], result_types, serial=serial)
                    owner.types = composite._Types([])
                    state = composite._Value(task.state, ())
                    env, ops = {'state': state}, []
                    ins = fixtures.i('task.create', ['state'], [('task', 'Task')])
                    def consume(name):
                        if env[name].consumed:
                            raise HIAProgramRejected('use of consumed nominal value', 'E_HIA_RESOURCE')
                        if env[name].typ.linear:
                            env[name].consumed = True
                    implementation = owner.lower_task_operation if native else owner._reference_task_operation
                    with patch('hepta.hia_task_operations_native.selected_task_operations', return_value=self.native):
                        _, error = outcome(lambda: implementation(ins, [state], [('task', task)], env, ops,
                            consume, lambda *_: (_ for _ in ()).throw(AssertionError('unexpected output reparse'))))
                    results.append((error, owner.serial, ops, tuple(env), state.consumed))
                self.assertEqual(results[0], results[1], (result_types, serial))
                self.assertEqual(results[0][0][0], 'E_HIA_LOAN' if serial == 0 else 'E_HIA_LIMIT')

    def test_independent_hia_vm_matches_native_query_and_effect_bytes(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        owner = composite._Elaborator(empty_program()); task = owner.types.resolve('Work')
        u8 = owner.types.resolve('u8'); contexts = []
        for serial in (0, 8190, 8192):
            for phase in (0, 1):
                context = TaskPacket('task.create', ['state'], {}, [composite._Value(task.state, ())], [('task', task)], serial)
                context.data(); context.phase = phase
                if phase:
                    context.receipts = [context.type_ref(task)]
                contexts.append(context)
        for phase in range(4):
            context = TaskPacket('task.state', ['task'], {}, [composite._Value(task, ('tag', 'token'))], [('status', u8)], 7)
            context.data(); context.phase = phase
            if phase:
                context.receipts = [context.type_ref(u8)]
            if phase >= 2:
                context.outputs = [['status', context.type_ref(u8)]]
            if phase == 3:
                context.receipts.append(context.type_ref(owner.types.resolve('u8')))
            contexts.append(context)
        for phase in range(3):
            value = composite._Value(task, ('tag', 'token'), consumed=phase == 2)
            context = TaskPacket('task.start', ['task'], {}, [value], [('started', task)], 7)
            context.data(); context.phase = phase
            if phase:
                context.outputs = [['started', context.type_ref(task)]]
            if phase == 2:
                context.prefix = [9, [['started', context.type_ref(task), ['h2internal_8', 'h2internal_9'], False, False]]]
                owner.serial = 9
                context.helper_name = owner._reference_helper(task, 'start'); context.serial = owner.serial
            contexts.append(context)
        output, workspace = _Owner(-2, bytearray(OUTPUT_BYTES)), _Owner(-3, bytearray(WORKSPACE_BYTES))
        for context in contexts:
            data = context.data(); source = _Owner(-1, bytearray(data))
            machine = _Machine(checked, 20_000_000, 128 << 20, None, 256)
            extent = machine.invoke(checked.as_dict()['functions'][0],
                [_View(source, False), _View(output, True), _View(workspace, True)])[0]
            self.assertTrue(64 <= extent <= OUTPUT_BYTES)
            native_source = ctypes.create_string_buffer(data)
            native_output, native_workspace = ctypes.create_string_buffer(OUTPUT_BYTES), ctypes.create_string_buffer(WORKSPACE_BYTES)
            native_extent = self.native._entry(native_source, len(data), native_output, OUTPUT_BYTES,
                                               native_workspace, WORKSPACE_BYTES)
            self.assertEqual(native_extent, extent)
            self.assertEqual(ctypes.string_at(native_output, extent), bytes(output.data[:extent]))
            self.assertEqual(bytes(source.data), data)

    def test_retained_execution_rejection_and_runtime_transition_controls(self):
        names = ['test_cooperative_task_pending_running_complete_and_refusal',
                 'test_scalar_task_has_primitive_linear_token_without_allocator_calls',
                 'test_completed_owned_result_survives_cancel_and_moves_out_once']
        negative = ['test_tasks_are_linear_even_if_all_fields_are_scalars',
                    'test_task_protocol_signature_and_loan_captures_rejected',
                    'test_invalid_runtime_task_transitions_trap']
        result = unittest.TestResult()
        with self.selected(), patch.object(composite._Elaborator, '_reference_task_operation',
                side_effect=AssertionError('host task called')):
            unittest.TestSuite([*[fixtures.CompositeExecutionTests(name) for name in names],
                *[fixtures.CompositeRejectionTests(name) for name in negative],
                partials.PartialRecordExecutionTests('test_partial_states_compose_with_cooperative_tasks')]).run(result)
        self.assertEqual(result.testsRun, len(names) + len(negative) + 1)
        self.assertEqual((result.errors, result.failures, result.skipped), ([], [], []))

    def test_all_seven_native_nominal_owners_compose_without_references(self):
        from tests import test_hia_composite_types_native as types
        from tests import test_hia_enum_operations_native as enums
        from tests import test_hia_enum_match_native as matches
        from tests import test_hia_record_operations_native as records
        from tests import test_hia_record_transitions_native as transitions
        from hepta.hia_composite_types_native import SELECTOR as TYPE_SELECTOR
        from hepta.hia_enum_operations_native import SELECTOR as ENUM_SELECTOR
        from hepta.hia_enum_match_native import SELECTOR as MATCH_SELECTOR
        from hepta.hia_record_operations_native import SELECTOR as RECORD_SELECTOR
        from hepta.hia_record_transitions_native import SELECTOR as TRANSITION_SELECTOR
        from hepta.hia_task_helpers_native import SELECTOR as HELPER_SELECTOR
        prepared = {SELECTOR: str(self.manifest)}
        for tests, implementation, selector in [(types, types.CompositeTypesNativeTests, TYPE_SELECTOR),
                (enums, enums.EnumOperationsNativeTests, ENUM_SELECTOR), (matches, matches.EnumMatchNativeTests, MATCH_SELECTOR),
                (records, records.RecordOperationsNativeTests, RECORD_SELECTOR),
                (transitions, transitions.RecordTransitionsNativeTests, TRANSITION_SELECTOR),
                (helpers, helpers.TaskHelpersNativeTests, HELPER_SELECTOR)]:
            prepared[selector] = str(self.supporting(tests, implementation).manifest)
        for document, name, arguments, answer in [
                (fixtures.task_program(), 'task_case', [2], 28),
                (partials.task_partial_program(), 'partial_task', [13, 2], 33),
                (loans.task_program(), 'task_probe', [7, 2], 27)]:
            with patch.dict(os.environ, {key: '' for key in prepared}):
                expected = verify_core(document)
            with patch.dict(os.environ, prepared), patch.object(composite, '_Types',
                    side_effect=AssertionError('host type owner called')), patch.object(
                    composite._Elaborator, '_reference_record_transition', side_effect=AssertionError('host transition called')), patch.object(
                    composite._Elaborator, '_reference_record_operation', side_effect=AssertionError('host record called')), patch.object(
                    composite._Elaborator, '_reference_enum_operation', side_effect=AssertionError('host enum called')), patch.object(
                    composite._Elaborator, '_reference_match', side_effect=AssertionError('host match called')), patch.object(
                    composite._Elaborator, '_reference_helper', side_effect=AssertionError('host helper called')), patch.object(
                    composite._Elaborator, '_reference_task_operation', side_effect=AssertionError('host task called')):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))
            self.assertEqual(execute_program(actual, name, arguments)['result'], answer)

    def test_actual_machine_task_allocator_failure_and_cleanup(self):
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        from hepta.hia_task_helpers_native import SELECTOR as HELPER_SELECTOR
        support = self.supporting(helpers, helpers.TaskHelpersNativeTests)
        cc = shutil.which('cc'); self.assertIsNotNone(cc)
        driver = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live[16]; static size_t allocations,frees,refusals,attempt,fail_at;
void *__wrap_calloc(size_t n,size_t w){
  attempt++;if(fail_at && attempt==fail_at){refusals++;return NULL;}
  void *p=__real_calloc(n,w);if(p){for(size_t i=0;i<16;i++)if(!live[i]){live[i]=p;allocations++;return p;}exit(80);}return p;
}
void __wrap_free(void *p){if(p){size_t i;for(i=0;i<16 && live[i]!=p;i++);if(i==16)exit(81);live[i]=NULL;frees++;}__real_free(p);}
size_t task_case(uint8_t);
int main(void){
  if(task_case(0)!=33 || task_case(1)!=13 || task_case(2)!=28)return 82;
  attempt=0;fail_at=1;if(task_case(2)!=250)return 83;
  for(size_t i=0;i<16;i++)if(live[i])return 84;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=3 || frees!=3 || refusals!=1;
}
'''
        with self.selected(), patch.dict(os.environ, {HELPER_SELECTOR: str(support.manifest)}), patch.object(
                composite._Elaborator, '_reference_task_operation', side_effect=AssertionError('host task called')), patch.object(
                composite._Elaborator, '_reference_helper', side_effect=AssertionError('host helper called')):
            checked = verify_core(fixtures.task_program())
        obj = self.folder / 'task-effects.o'
        compile_program_machine(emit_program_machine(checked), program=checked, output=obj, kind='object', linker=cc)
        source, executable = self.folder / 'task-effects.c', self.folder / 'task-effects'
        source.write_text(driver)
        built = subprocess.run([cc, '-std=c11', '-O2', str(source), str(obj),
            '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(executable)], capture_output=True, timeout=30)
        self.assertEqual((ran.returncode, ran.stdout, ran.stderr), (0, b'3 3 1\n', b''))

    def test_private_regions_continuation_corruption_and_concurrency(self):
        from concurrent.futures import ThreadPoolExecutor
        from hepta.hia_instruction_policy_native import transport
        owner = composite._Elaborator(empty_program()); task = owner.types.resolve('Work')
        context = TaskPacket('task.create', ['state'], {}, [composite._Value(task.state, ())], [('task', task)], 0)
        data = context.data(); source = ctypes.create_string_buffer(data)
        output, workspace = ctypes.create_string_buffer(OUTPUT_BYTES + 32), ctypes.create_string_buffer(WORKSPACE_BYTES + 32)
        ctypes.memset(ctypes.addressof(output) + OUTPUT_BYTES, 0xA7, 32)
        ctypes.memset(ctypes.addressof(workspace) + WORKSPACE_BYTES, 0xB9, 32)
        for oc, wc in [(OUTPUT_BYTES-1, WORKSPACE_BYTES), (OUTPUT_BYTES, WORKSPACE_BYTES-1)]:
            self.assertEqual(self.native._entry(source, len(data), output, oc, workspace, wc), 0xfffffff1)
        extent = self.native._entry(source, len(data), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        self.assertGreater(extent, 64)
        self.assertEqual(ctypes.string_at(ctypes.addressof(output) + OUTPUT_BYTES, 32), b'\xa7'*32)
        self.assertEqual(ctypes.string_at(ctypes.addressof(workspace) + WORKSPACE_BYTES, 32), b'\xb9'*32)
        self.assertEqual(ctypes.string_at(source, len(data)), data)
        nested = None
        for _ in range(129):
            nested = [nested]
        for malformed in (b'', data[:-1], transport(nested)):
            bad = ctypes.create_string_buffer(malformed, max(1, len(malformed)))
            self.assertEqual(self.native._entry(bad, len(malformed), output, OUTPUT_BYTES,
                                               workspace, WORKSPACE_BYTES), 0xfffffff1)
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: self.native.step(context), range(6)))
        self.assertTrue(all(result == results[0] for result in results))
        value = composite._Value(task, ('tag', 'token'), consumed=True)
        resumed = TaskPacket('task.start', ['task'], {}, [value], [('out', task)], 20)
        resumed.data(); resumed.phase = 2; resumed.outputs = [['out', resumed.type_ref(task)]]
        resumed.prefix = [9, [['out', resumed.type_ref(task), ['h2internal_8', 'h2internal_9'], False, False]]]
        resumed.helper_name = 'h2internal_10'
        self.assertEqual(self.native.step(resumed).ops[0]['op'], 'call')
        for change in ('prefix_counter', 'prefix_name', 'prefix_type', 'prefix_consumed', 'value_consumed', 'helper', 'receipt'):
            changed = TaskPacket('task.start', ['task'], {},
                [composite._Value(task, ('tag', 'token'), consumed=True)], [('out', task)], 20)
            changed.data(); changed.phase = 2
            changed.outputs, changed.prefix = deepcopy(resumed.outputs), deepcopy(resumed.prefix)
            changed.helper_name = resumed.helper_name
            self.assertEqual(self.native.step(changed).ops[0]['op'], 'call')
            if change == 'prefix_counter': changed.prefix[0] = 21
            elif change == 'prefix_name': changed.prefix[1][0][2][0] = 'h2internal_7'
            elif change == 'prefix_type': changed.prefix[1][0][1] = 1
            elif change == 'prefix_consumed': changed.prefix[1][0][4] = True
            elif change == 'value_consumed': changed.values[0].consumed = False
            elif change == 'helper': changed.helper_name = 'ordinary_function'
            else: changed.receipts = [0]
            with self.subTest(change=change), self.assertRaises(HIAProgramRejected):
                self.native.step(changed)

    def test_repeated_zero_width_arguments_and_global_value_slot_boundary(self):
        document = empty_program(); document['functions'] = document['functions'][:2]
        document['functions'].append(f('bad', [('state', 'Empty')], [], ['alloc'], [
            b('entry', [('state', 'Empty')], [fixtures.i('task.create', ['state'] * 15000, [('task', 'Work')])],
              fixtures.ret())]))
        candidates = [(document, 'E_HIA_TYPE')]
        # The poll function's one-slot Step precedes the two-slot task input.
        for count, code in [(32765, 'E_HIA_TYPE'), (32766, 'E_HIA_LIMIT')]:
            document = empty_program(); document['functions'] = document['functions'][:2]
            document['functions'].append(f('bad', [('task', 'Work')], [], ['alloc'], [
                b('entry', [('task', 'Work')], [fixtures.i('task.state', ['task'],
                    [('out' + str(i), 'u32') for i in range(count)])], fixtures.ret())]))
            candidates.append((document, code))
        for document, code in candidates:
            with patch.dict(os.environ, {SELECTOR: ''}):
                _, expected = outcome(lambda: verify_core(document))
            with self.selected(), patch.object(composite._Elaborator, '_reference_task_operation',
                    side_effect=AssertionError('host task called')):
                _, actual = outcome(lambda: verify_core(document))
            self.assertEqual(actual, expected)
            self.assertEqual(actual[0], code)

    def test_state_preserves_three_resolves_final_identity_and_callback_refusals(self):
        for failed_call in (0, 1, 2, 3):
            observed = []
            for native in (False, True):
                owner = composite._Elaborator(empty_program()); task = owner.types.resolve('Work')
                declared = [('status', owner.types.resolve('u8'))]
                env = {'task': composite._Value(task, ('tag', 'token'))}; ops = []
                ins = fixtures.i('task.state', ['task'], [('status', 'u8')])
                resolves = []; real = owner.types.resolve
                def resolve(name):
                    resolves.append(name)
                    if len(resolves) == failed_call:
                        raise HIAProgramRejected('injected original type-owner refusal', 'E_HIA_TYPE')
                    typ = real(name); last[0] = typ
                    return typ
                def outputs(instruction, expected):
                    values = owner.parameters(instruction['out'])
                    if tuple(typ for _, typ in values) != tuple(expected):
                        raise HIAProgramRejected('nominal output type/arity mismatch', 'E_HIA_TYPE')
                    return [name for name, _ in values]
                last = [None]
                implementation = owner.lower_task_operation if native else owner._reference_task_operation
                with patch.object(owner.types, 'resolve', side_effect=resolve), patch(
                        'hepta.hia_task_operations_native.selected_task_operations', return_value=self.native):
                    _, error = outcome(lambda: implementation(ins, [env['task']], declared, env, ops,
                        lambda *_: (_ for _ in ()).throw(AssertionError('task.state consumed input')), outputs))
                if not failed_call:
                    self.assertIs(env['status'].typ, last[0])
                    self.assertEqual(env['status'].names, ('tag',))
                observed.append((error, resolves, owner.serial, ops, tuple(env), env['task'].consumed))
            self.assertEqual(observed[0], observed[1])
            self.assertEqual(len(observed[0][1]), failed_call or 3)

    def test_installed_wheel_source_custody_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
        from hepta.hia_task_helpers_native import SELECTOR as HELPER_SELECTOR
        support = self.supporting(helpers, helpers.TaskHelpersNativeTests)
        self.assertIn('examples/hia_bootstrap/task_operations.hepta', NATIVE_SOURCE_FILES)
        source = self.folder / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        names = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES
        for name in (*names, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        wheels, installed = self.folder / 'wheels', self.folder / 'installed'
        built = subprocess.run([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
            '--wheel-dir', str(wheels), str(source)], cwd=source, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=self.folder, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(copied.returncode, 0, copied.stdout + copied.stderr)
        child = '''import sys,importlib.abc
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed task operations imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_task_operations_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host task called')
composite._Elaborator._reference_task_operation=absent
composite._Elaborator._reference_helper=absent
try: result=verify_core(Path(sys.argv[2]).read_bytes())
except HIAProgramRejected:
    if sys.argv[3]=='refuse':print('REFUSED')
    else:raise
else:
    assert sys.argv[3]=='accept','invalid installed code custody accepted'
    sys.stdout.buffer.write(result.canonical_bytes)
'''
        data = self.folder / 'installed-input.json'
        def run(mode, manifest=self.manifest):
            return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
                str(installed), str(data), mode], cwd=self.folder, capture_output=True, timeout=30,
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(manifest),
                     HELPER_SELECTOR: str(support.manifest)})
        for document in (fixtures.task_program(), fixtures.owned_result_task_program(), empty_program()):
            data.write_bytes(wire(document))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/task_operations.hepta'
        original = resource.read_bytes()
        for missing in (False, True):
            try:
                resource.unlink() if missing else resource.write_bytes(original + b'\n')
                result = run('refuse')
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
            finally:
                resource.write_bytes(original)
        bad = self.folder / 'bad-manifest.json'; bad.write_bytes(b'{}')
        result = run('refuse', bad)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))


if __name__ == '__main__':
    unittest.main()
