"""Reconstructed controls for the maintained native HIA function source.

The HIA and bridge recovery hashes are authenticated separately. This test
file is new source; it is not represented as the lost author's original file.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
from copy import deepcopy
import ctypes
from dataclasses import replace
from hashlib import sha256
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_instruction_policy_native import transport
from hepta.hia_native_value_graph import decode_native_graph
from hepta.hia_nominal_function_native import (SOURCE, SCHEMA, SELECTOR, MAGIC,
    INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, FunctionContext, NativeNominalFunction,
    installed_nominal_function, selected_nominal_function)
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests import test_hia_composite_returned_loans as loans
from tests.test_hia_program import b, f

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_NOMINAL_FUNCTION_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_NOMINAL_FUNCTION_DEVELOPMENT_MANIFEST'
REFERENCE_AST_SHA256 = 'c4725d8619bcb0ad80b34878ed64d327c58a054f90a088e9cfa9357ebb006075'
HOST_REFERENCES = ('_reference_function', '_reference_main_function', '_reference_parameters', '_reference_record_transition',
    '_reference_record_operation', '_reference_enum_operation', '_reference_task_operation',
    '_reference_call_primitive', '_reference_nominal_terminator', '_reference_match',
    '_reference_helper', '_reference_helper_cache')


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def outcome(action):
    try:
        return action(), None
    except HIAProgramRejected as exc:
        return None, (exc.code, str(exc))


def constant_program():
    return fixtures.module([], f('constant', [], ['u32'], [], [
        b('entry', [], [fixtures.c('answer', 'u32', 37)], fixtures.ret('answer'))]))


def call_program():
    pair = fixtures.record('Pair', [('left', 'u32'), ('right', 'u32')])
    caller = f('call_entry', [], ['u32'], [], [b('entry', [], [
        fixtures.c('a', 'u32', 37), fixtures.c('b', 'u32', 11),
        fixtures.i('record.make', ['a', 'b'], [('pair', 'Pair')]),
        fixtures.i('call', ['pair'], [('answer', 'u32')], function='first'),
    ], fixtures.ret('answer'))])
    callee = f('first', [('pair', 'Pair')], ['u32'], [], [b('entry', [('pair', 'Pair')], [
        fixtures.i('record.get', ['pair'], [('answer', 'u32')], field='left'),
    ], fixtures.ret('answer'))])
    return fixtures.module([pair], caller, callee)


def borrowed_function():
    function = f('borrowed', [('loan', 'readbuf')], ['readbuf'], [], [
        b('entry', [('loan', 'readbuf')], [fixtures.c('unused', 'u32', 37)], fixtures.ret('loan'))])
    function['return_loans'] = [{'param': 'loan', 'fields': []}]
    document = fixtures.module([], function)
    document['schema'] = 'hepta.hia.composite.v4'
    return document


def choice_program():
    return fixtures.module([fixtures.enum('Pick', [('left', []), ('right', [])])],
        f('pick', [('item', 'Pick')], ['u32'], ['trap'], [
            b('entry', [('item', 'Pick')], [], {'op': 'match', 'value': 'item', 'cases': [
                {'variant': 'left', 'target': 'left', 'args': []},
                {'variant': 'right', 'target': 'right', 'args': []}]}),
            b('left', [], [fixtures.c('a', 'u32', 3)], fixtures.ret('a')),
            b('right', [], [fixtures.c('b', 'u32', 7)], fixtures.ret('b'))]))


def wide_types():
    return [fixtures.record('Chunk', [('x'+str(i), 'u32') for i in range(64)]),
            fixtures.record('Wide', [('part'+str(i), 'Chunk') for i in range(8)])]


class NominalFunctionSourceTests(unittest.TestCase):
    def test_maintained_hia_source_complete_ir_and_unchanged_compiler_profile(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        raw = SOURCE.read_bytes()
        document = assemble_program(raw).as_dict()
        self.assertEqual(render_assembly(document).encode(), raw)
        self.assertEqual(document['schema'], 'hepta.hia.program.v8')
        self.assertEqual([p['type'] for p in document['functions'][0]['params']],
                         ['readbuf', 'mutbuf', 'mutbuf'])
        self.assertEqual(document['functions'][0]['returns'], ['u32'])
        self.assertLessEqual(len(document['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in document['functions'] for block in fn['blocks']),
                             MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for fn in document['functions'] for block in fn['blocks']), 16)
        verify_core(document)

    def test_original_function_ast_and_transport_identity(self):
        body = ast.parse(textwrap.dedent(inspect.getsource(composite._Elaborator._reference_function))).body[0].body
        from tests.hia_reference_ast import reference_ast_dump
        self.assertEqual(sha256(reference_ast_dump(ast.Module(body=body, type_ignores=[])).encode()).hexdigest(),
                         REFERENCE_AST_SHA256)
        class ForbiddenKey:
            def __str__(self): raise AssertionError('semantic display key expanded')
            def __eq__(self, other): raise AssertionError('semantic type compared')
            def __hash__(self): raise AssertionError('semantic key hashed')
        owner = composite._Elaborator(constant_program())
        context = FunctionContext(owner, owner.document['functions'][0])
        try:
            typ = composite._Type(ForbiddenKey(), 'record', ())
            self.assertEqual((context.type_ref(typ), context.type_ref(typ)), (0, 0))
            value = composite._Value(typ, ())
            context.environment = {'a': value, 'z': value}
            raw = context.data()
            self.assertEqual(decode_native_graph(raw, raw)[8], [['a', 0, False], ['z', 0, False]])
            context.environment_snapshot = context.pending_environment
            value.consumed = True
            raw = context.data()
            self.assertEqual(decode_native_graph(raw, raw)[8], [['a', 0, True], ['z', 0, True]])
            context.environment_snapshot = context.pending_environment
            raw = context.data()
            self.assertEqual(decode_native_graph(raw, raw)[8], [])
            self.assertEqual((len(context.types), len(context.values)), (1, 1))
        finally:
            context.close()
            if owner.native_types is not None: owner.native_types.close()

    def test_selected_missing_image_cannot_use_reference(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_nominal_function())
        with patch.dict(os.environ, {SELECTOR: '/missing-native-function'}), patch.object(
                composite._Elaborator, '_reference_function', side_effect=AssertionError('host function used')):
            with self.assertRaises(HIAProgramRejected): verify_core(constant_program())


class NominalFunctionAdapterTests(unittest.TestCase):
    def test_exact_frame_permission_precedes_counter_prefix_and_terminal_return(self):
        context = self.context()
        result = self.image(self.frame(serial=7, slots=9, request=3, value={})).step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'unconsumed'):
            context.accept(replace(result, serial=8))
        self.assertEqual((context.owner.serial, context.owner.value_slots), (0, 0))
        context.accept(result)
        self.assertEqual((context.owner.serial, context.owner.value_slots), (7, 9))
        with self.assertRaisesRegex(HIAProgramRejected, 'unconsumed'):
            context.accept(result)
        context.service(result.request, result.value)
        context = self.context()
        result = self.image(self.frame(serial=7, slots=9, request=0,
                                      value={'name': 'issued'})).step(context)
        result.value['name'] = 'changed'
        with self.assertRaisesRegex(HIAProgramRejected, 'issued graph changed'):
            context.accept(result)
        self.assertEqual((context.owner.serial, context.owner.value_slots), (0, 0))
        self.assertTrue(context.closed)
        self.assertIsNone(context._binding)
        context = self.context()
        result = self.image(self.frame(error=1, serial=8192, slots=9, request=0)).step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'expansion budget'):
            context.accept(result)
        self.assertEqual((context.owner.serial, context.owner.value_slots), (8192, 9))

    def context(self):
        owner = composite._Elaborator(constant_program())
        context = FunctionContext(owner, owner.document['functions'][0])
        self.addCleanup(context.close)
        if owner.native_types is not None: self.addCleanup(owner.native_types.close)
        return context

    def image(self, data, mutate=False):
        image = object.__new__(NativeNominalFunction)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate: ctypes.memmove(source, b'x', 1)
            if type(data) is int: return data
            ctypes.memmove(output, data, len(data))
            return len(data)
        image._entry = entry
        return image

    def frame(self, *, error=0, serial=0, slots=0, request=1, sequence=1, value=None):
        if value is None and not error: value = {'path': ['blocks', 0, 'params']}
        data = transport(value)
        return struct.pack('<8Q', MAGIC, error, serial, slots, request, len(data), sequence, 0) + data

    def test_bad_frames_and_input_mutation_fail_closed(self):
        for data in (0, 0xfffffff1, self.frame(error=99), self.frame(error=1, request=0),
                     self.frame(error=13, request=0), self.frame(serial=8193), self.frame(request=13),
                     self.frame(sequence=0), self.frame(value=[])):
            context = self.context()
            with self.subTest(data=repr(data)[:70]):
                with self.assertRaises(HIAProgramRejected): self.image(data).step(context)
                self.assertTrue(context.closed)
                context.close()
        context = self.context()
        with self.assertRaisesRegex(HIAProgramRejected, 'input bytes changed'):
            self.image(self.frame(), mutate=True).step(context)
        context.close()
        context = self.context()
        context.function['entry'] = 'changed'
        with self.assertRaisesRegex(HIAProgramRejected, 'held function changed'): context.data()

    def test_invalid_storage_locations_and_descriptor_ids_refuse_before_callbacks(self):
        for request, query in ((99, {}), (1, {'path': ['blocks', -1, 'params']}),
                (2, {'index': True, 'name': 'entry', 'params': [], 'bindings': [], 'flat': []}),
                (4, {'index': 0}), (5, {'index': 0, 'ops': []}),
                (6, {'owner': 5, 'path': [], 'actual': [0], 'declared': []}),
                (8, {'current': {'ops': []}}), (12, {'values': [None]})):
            context = self.context()
            with self.subTest(request=request), self.assertRaises(HIAProgramRejected):
                result = self.image(self.frame(request=request, value=query)).step(context)
                context.service(result.request, result.value)
            context.close()
        context = self.context()
        context.environment = {'a': composite._Value(composite._Types([]).resolve('u32'), ('a',))}
        context.data()
        context.environment_snapshot = context.pending_environment
        context.environment.clear()
        raw = context.data()
        self.assertEqual(decode_native_graph(raw, raw)[8], [['a', None, None]])

    def test_callback_permission_is_exact_once_only_and_requires_a_reply(self):
        context = self.context()
        image = self.image(self.frame(request=3, value={}))
        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted'): context.service(3, {})
        first = image.step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'not completed'): image.step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted'):
            context.service(first.request, dict(first.value))
        context.service(first.request, first.value)
        self.assertEqual((context.executed, context.completed, context.sequence), (1, 1, 1))
        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted'):
            context.service(first.request, first.value)
        second = self.image(self.frame(request=11, sequence=2, value={})).step(context)
        context.service(second.request, second.value)
        context.close()
        with self.assertRaisesRegex(HIAProgramRejected, 'closed'): image.step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'closed'): context.data()
        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted'):
            context.service(second.request, second.value)
        self.assertIsNone(context.workspace)
        self.assertIsNone(context.output)

    def test_constructor_allocation_refusal_releases_partial_arenas_with_traceback_held(self):
        # This is actual ctypes allocation with a controlled allocation fault,
        # before any native entry. Keeping the original traceback exercises the
        # partial constructor; detaching it or invoking GC is not the fix.
        real_allocate = ctypes.create_string_buffer
        for ordinal in (1, 2):
            for exception_type in (MemoryError, KeyboardInterrupt):
                with self.subTest(ordinal=ordinal, exception_type=exception_type.__name__):
                    fault = exception_type('controlled context allocation refusal')
                    requests, allocated, entered = [], [], []
                    def allocate(size, *args):
                        requests.append(size)
                        if len(requests) == ordinal:
                            raise fault
                        value = real_allocate(size, *args)
                        allocated.append((ctypes.sizeof(value), weakref.ref(value)))
                        return value
                    image = object.__new__(NativeNominalFunction)
                    image._entry = lambda *args: entered.append(args)
                    held_error = None
                    with patch('hepta.hia_nominal_function_native.ctypes.create_string_buffer', allocate):
                        try:
                            image.lower(object(), {'name': 'allocation_probe'})
                        except BaseException as error:
                            held_error = error
                    self.assertIs(held_error, fault)
                    self.assertEqual(requests, [OUTPUT_BYTES, WORKSPACE_BYTES][:ordinal])
                    self.assertEqual(entered, [])
                    traceback = held_error.__traceback__
                    while traceback is not None and traceback.tb_frame.f_code is not FunctionContext.__init__.__code__:
                        traceback = traceback.tb_next
                    self.assertIsNotNone(traceback)
                    context = traceback.tb_frame.f_locals['self']
                    self.assertTrue(context.closed)
                    self.assertIsNone(context.output)
                    self.assertIsNone(context.workspace)
                    self.assertEqual([size for size, _ in allocated], [OUTPUT_BYTES] * (ordinal - 1))
                    self.assertTrue(all(reference() is None for _, reference in allocated))
                    self.assertIsNotNone(held_error.__traceback__)
                    with self.assertRaisesRegex(HIAProgramRejected, 'closed'):
                        context.data()


class NominalFunctionNativeTests(unittest.TestCase):
    def test_actual_issued_payload_and_result_replacement_refuse_before_effects(self):
        with self.selected():
            owner = composite._Elaborator(constant_program())
            context = FunctionContext(owner, owner.document['functions'][0])
            try:
                result = self.native.step(context)
                self.assertEqual((result.request, result.value), (1, {'path': ['blocks', 0, 'params']}))
                result.value['path'][:] = ['blocks', 0, 'ops', 0, 'out']
                with patch.object(owner, 'parameters',
                        side_effect=AssertionError('changed path reached native parameter parsing')):
                    with self.assertRaisesRegex(HIAProgramRejected, 'issued graph changed'):
                        context.service(result.request, result.value)
                self.assertEqual((owner.serial, owner.value_slots), (0, 0))
                self.assertTrue(context.closed)
                self.assertIsNone(context._binding)
            finally:
                context.close()
                owner.native_types.close()
            document = fixtures.module([], f('return_guard', [('x', 'u32')], [], [], [
                b('entry', [('x', 'u32')], [], fixtures.ret())]))
            reference = composite._Elaborator(deepcopy(document))
            try:
                expected = reference._reference_function(reference.document['functions'][0])
            finally:
                reference.native_types.close()
            owner = composite._Elaborator(deepcopy(document))
            try:
                self.assertEqual(self.native.lower(owner, owner.document['functions'][0]), expected)
            finally:
                owner.native_types.close()
            for mode in ('terminal_graph', 'copied_counter_frame'):
                owner = composite._Elaborator(deepcopy(document))
                real_step, captured, prefixes = self.native.step, [], []
                def changed(context):
                    result = real_step(context)
                    captured.append(context)
                    if mode == 'copied_counter_frame':
                        prefixes.append((owner.serial, owner.value_slots))
                        return replace(result, serial=result.serial + 1)
                    if not result.request:
                        prefixes.append((owner.serial, owner.value_slots))
                        result.value['name'] = 'unissued_name'
                    return result
                try:
                    with patch.object(self.native, 'step', side_effect=changed):
                        with self.assertRaises(HIAProgramRejected):
                            self.native.lower(owner, owner.document['functions'][0])
                    self.assertEqual(len(prefixes), 1)
                    self.assertEqual((owner.serial, owner.value_slots), prefixes[0])
                    self.assertTrue(captured[-1].closed)
                    self.assertIsNone(captured[-1]._binding)
                    self.assertIsNone(captured[-1].output)
                    self.assertIsNone(captured[-1].workspace)
                finally:
                    owner.native_types.close()

    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development nominal function cannot override cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-nominal-function-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        if development:
            supplied = Path(development)
            value = json.loads(supplied.read_bytes())
            name = value['image_path']
            assert type(name) is str and Path(name).name == name
            shutil.copyfile(supplied.parent / name, cls.folder / name)
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(supplied.read_bytes())
            cls.fixture_scope = 'DEVELOPMENT_ONLY'
        elif cold:
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='nominal-function')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'nominal-function', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_nominal_function(str(cls.manifest))

        from tests import test_hia_composite_types_native as types
        from tests import test_hia_enum_match_native as matches
        from tests import test_hia_enum_operations_native as enums
        from tests import test_hia_record_operations_native as records
        from tests import test_hia_record_transitions_native as transitions
        from tests import test_hia_task_operations_native as tasks
        from tests import test_hia_task_helpers_native as helpers
        from tests import test_hia_task_helper_cache_native as helper_cache
        from tests import test_hia_call_primitive_native as calls
        from tests import test_hia_nominal_terminators_native as terms
        cls.support = {}
        for module, implementation in ((types, types.CompositeTypesNativeTests),
                (matches, matches.EnumMatchNativeTests), (enums, enums.EnumOperationsNativeTests),
                (records, records.RecordOperationsNativeTests), (transitions, transitions.RecordTransitionsNativeTests),
                (tasks, tasks.TaskOperationsNativeTests), (helpers, helpers.TaskHelpersNativeTests),
                (helper_cache, helper_cache.TaskHelperCacheNativeTests),
                (calls, calls.CallPrimitiveNativeTests), (terms, terms.NominalTerminatorsNativeTests)):
            fixture = type('SupportingFixture', (unittest.TestCase,), {})
            cls.addClassCleanup(fixture.doClassCleanups)
            extra = {}
            if os.environ.get(COLD_REPORT) and not os.environ.get(module.COLD_REPORT):
                extra[module.COLD_REPORT] = os.environ[COLD_REPORT]
            with patch.dict(os.environ, extra): implementation.setUpClass.__func__(fixture)
            cls.support[module.SELECTOR] = str(fixture.manifest)

    def selected(self):
        return patch.dict(os.environ, {**self.support, SELECTOR: str(self.manifest)})

    def compare_function(self, document, index=0, *, serial=0, slots=0, prepare=None):
        observations = []
        for native in (False, True):
            with self.selected():
                owner = composite._Elaborator(deepcopy(document))
                try:
                    owner.serial, owner.value_slots = serial, slots
                    function = owner.document['functions'][index]
                    if prepare: prepare(owner, function)
                    trace = []
                    real = owner.parameters
                    def parameters(value):
                        trace.append(deepcopy(value))
                        return real(value)
                    with patch.object(owner, 'parameters', side_effect=parameters):
                        result, error = outcome(lambda: self.native.lower(owner, function)
                            if native else owner._reference_function(function))
                    observations.append((result, error, owner.serial, owner.value_slots,
                        owner.types.observations, deepcopy(owner.helpers), tuple(owner.helper_names.values()), trace))
                finally:
                    owner.types.close()
        self.assertEqual(observations[0], observations[1])
        return observations[1]

    def test_exact_core_all_profiles_runtime_and_selected_owners_without_references(self):
        for version in range(1, 5):
            for source in (constant_program(), call_program()):
                source['schema'] = 'hepta.hia.composite.v' + str(version)
                for index in range(len(source['functions'])):
                    with self.subTest(version=version, function=index):
                        self.assertIsNone(self.compare_function(source, index)[1])
            source = constant_program()
            source['schema'] = 'hepta.hia.composite.v' + str(version)
            with self.selected(), ExitStack() as stack:
                stack.enter_context(patch.object(composite, '_Types', side_effect=AssertionError('host types used')))
                for name in HOST_REFERENCES:
                    stack.enter_context(patch.object(composite._Elaborator, name,
                        side_effect=AssertionError('host owner used: ' + name)))
                checked = verify_core(source)
                self.assertEqual(execute_program(checked, source['functions'][0]['name'], [])['result'], 37)
        for source in (fixtures.task_program(), fixtures.enum_owner_program(), partials.roundtrip_program()):
            with patch.dict(os.environ, {key: '' for key in (*self.support, SELECTOR)}):
                expected = verify_core(source).canonical_bytes
            with self.selected(), ExitStack() as stack:
                stack.enter_context(patch.object(composite, '_Types', side_effect=AssertionError('host types used')))
                for name in HOST_REFERENCES:
                    stack.enter_context(patch.object(composite._Elaborator, name,
                        side_effect=AssertionError('host owner used: ' + name)))
                self.assertEqual(verify_core(source).canonical_bytes, expected)

    def test_original_prepass_errors_callbacks_and_budget_prefixes(self):
        mutations = [
            lambda fn: fn.update(blocks=None), lambda fn: fn.update(blocks=[]),
            lambda fn: fn['blocks'][0].update(extra=0),
            lambda fn: fn['blocks'][0].update(id='h2internal_bad'),
            lambda fn: fn['blocks'].append(deepcopy(fn['blocks'][0])),
            lambda fn: fn['blocks'][0].update(ops={}),
            lambda fn: fn['blocks'][0]['ops'][0].update(extra=0),
            lambda fn: fn['blocks'][0]['ops'][0].update(op=None),
            lambda fn: fn['blocks'][0]['ops'][0].update(attrs=[]),
            lambda fn: fn['blocks'][0]['ops'][0].update(op='record.begin'),
            lambda fn: fn['blocks'][0]['ops'][0].update(args=None),
            lambda fn: fn['blocks'][0]['ops'][0].update(args=['invalid value']),
            lambda fn: fn['blocks'][0]['ops'][0].update(out=[{'name': 'x', 'type': 'Missing'}]),
            lambda fn: fn['blocks'][0]['ops'].append(deepcopy(fn['blocks'][0]['ops'][0])),
            lambda fn: fn.update(entry='absent'), lambda fn: fn.update(entry='h2internal_bad'),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                result = self.compare_function(constant_program(), prepare=lambda owner, fn: mutate(fn))
                self.assertIsNotNone(result[1])
        source = fixtures.module([], f('entry_mismatch', [], [], ['trap'], [
            b('entry', [('x', 'u32')], [], {'op': 'trap', 'code': 'user'})]))
        self.assertEqual(self.compare_function(source)[1][0], 'E_HIA_CFG')
        source = fixtures.module([fixtures.record('Pair', [('a', 'u32'), ('b', 'u32')])],
            f('fresh_boundary', [('value', 'Pair')], [], ['trap'], [
                b('entry', [('value', 'Pair')], [], {'op': 'trap', 'code': 'user'})]))
        result = self.compare_function(source, serial=8191)
        self.assertEqual((result[1][0], result[2], result[3]), ('E_HIA_LIMIT', 8192, 2))
        result = self.compare_function(constant_program(), slots=32768)
        self.assertEqual((result[1][0], result[3]), ('E_HIA_LIMIT', 32769))

    def test_actual_lookup_output_reparse_resource_and_callback_failures(self):
        for argument in ('missing', 'h2internal_missing'):
            source = constant_program()
            source['functions'][0]['blocks'][0]['ops'][0]['args'] = [argument]
            result = self.compare_function(source)
            self.assertIsNotNone(result[1])
            self.assertEqual(len(result[-1]), 2)
        source = fixtures.module([], f('consume_twice', [('owner', 'buffer')], [], ['alloc'], [
            b('entry', [('owner', 'buffer')], [fixtures.i('owner.drop', ['owner']),
                fixtures.i('owner.drop', ['owner'])], fixtures.ret())]))
        result = self.compare_function(source)
        self.assertEqual(result[1][0], 'E_HIA_RESOURCE')
        for failing_call in (1, 2, 3):
            def prepare(owner, function):
                original = owner.parameters
                count = 0
                def parameters(value):
                    nonlocal count
                    count += 1
                    result = original(value)
                    if count == failing_call: raise HIAProgramRejected('injected parameter refusal', 'E_HIA_TYPE')
                    return result
                owner.parameters = parameters
            result = self.compare_function(constant_program(), prepare=prepare)
            self.assertEqual(result[1], ('E_HIA_TYPE', 'E_HIA_TYPE: injected parameter refusal'))
            self.assertEqual(len(result[-1]), failing_call)
        self.assertIsNone(self.compare_function(borrowed_function())[1])

    def test_retained_helper_partial_and_returned_loan_families(self):
        for source in (fixtures.task_program(), fixtures.enum_owner_program(),
                       partials.roundtrip_program(), loans.pair_program()):
            for index in range(len(source['functions'])):
                with self.subTest(module=source['module'], function=index):
                    self.assertIsNone(self.compare_function(source, index)[1])

    def test_independent_vm_native_frames_workspace_and_all_continuations(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        requests = set()
        for document in (borrowed_function(), choice_program()):
            with self.selected():
                owner = composite._Elaborator(document)
                context = FunctionContext(owner, owner.document['functions'][0])
                vm_output = _Owner(-2, bytearray(OUTPUT_BYTES))
                vm_workspace = _Owner(-3, bytearray(WORKSPACE_BYTES))
                try:
                    for _ in range(128):
                        wire_bytes = context.data()
                        snapshot = dict(context.pending_environment)
                        vm_source = _Owner(-1, bytearray(wire_bytes))
                        machine = _Machine(checked, 200_000_000, 256 << 20, None, 256)
                        extent = machine.invoke(checked.as_dict()['functions'][0],
                            [_View(vm_source, False), _View(vm_output, True), _View(vm_workspace, True)])[0]
                        result = self.native.step(context)
                        native_extent = 64 + struct.unpack_from('<Q', context.output, 40)[0]
                        self.assertEqual(extent, native_extent)
                        self.assertEqual(bytes(vm_output.data[:extent]), ctypes.string_at(context.output, extent))
                        self.assertEqual(sha256(vm_workspace.data).digest(), sha256(context.workspace).digest())
                        self.assertEqual(bytes(vm_source.data), wire_bytes)
                        self.assertEqual(context.environment_snapshot, snapshot)
                        owner.serial, owner.value_slots = result.serial, result.value_slots
                        result.admit()
                        if not result.request:
                            self.assertEqual(result.value['name'], document['functions'][0]['name'])
                            break
                        requests.add(result.request)
                        context.service(result.request, result.value)
                    else:
                        self.fail('controller did not finish')
                finally:
                    context.close()
                    owner.types.close()
        self.assertEqual(requests, set(range(1, 13)))

    def test_many_zero_width_parameters_and_exact_nonzero_slot_boundary(self):
        document = fixtures.module([fixtures.record('Empty', [])],
            f('empty', [('p'+str(i), 'Empty') for i in range(15000)], [], ['trap'], [
                b('entry', [('p'+str(i), 'Empty') for i in range(15000)], [], {'op': 'trap', 'code': 'user'})]))
        result = self.compare_function(document, serial=8192)
        self.assertIsNone(result[1])
        self.assertEqual((result[2], result[3]), (8192, 0))
        self.assertEqual((result[0]['params'], result[0]['blocks'][0]['params']), ([], []))
        for count, code in ((32768, 'E_HIA_CFG'), (32769, 'E_HIA_LIMIT')):
            document = fixtures.module([], f('bound', [], [], ['trap'], [
                b('entry', [('p'+str(i), 'u32') for i in range(count)], [], {'op': 'trap', 'code': 'user'})]))
            result = self.compare_function(document)
            self.assertEqual((result[1][0], result[3]), (code, count))

    def test_wide_returns_and_original_null_origin_arrays_cross_wire_capacity(self):
        count = 8193
        function = f('wide', [], ['Wide'] * count, ['trap'], [b('entry', [], [], {'op': 'trap', 'code': 'user'})])
        function['return_loans'] = [None] * count
        document = fixtures.module(wide_types(), function)
        document['schema'] = 'hepta.hia.composite.v4'
        frames = []
        original = self.native.step
        def step(context):
            result = original(context)
            frames.append(64 + struct.unpack_from('<Q', context.output, 40)[0])
            return result
        with patch.object(self.native, 'step', side_effect=step): result = self.compare_function(document)
        self.assertIsNone(result[1])
        actual = result[0]
        self.assertEqual(len(actual['returns']), count * 512)
        self.assertEqual(len(actual['return_loans']), count * 512)
        self.assertEqual(actual['returns'][:512], ['u32'] * 512)
        self.assertEqual(actual['returns'][-512:], ['u32'] * 512)
        self.assertTrue(all(value is None for value in actual['return_loans']))
        self.assertGreater(len(actual['returns']) * 6 + len(actual['return_loans']) * 5, 32 << 20)
        self.assertLess(max(frames), 256 << 10)

    def test_private_regions_exact_function_custody_and_independent_contexts(self):
        from concurrent.futures import ThreadPoolExecutor
        with self.selected():
            owner = composite._Elaborator(constant_program())
            context = FunctionContext(owner, owner.document['functions'][0])
            try:
                data = context.data()
                source = ctypes.create_string_buffer(data)
                for oc, wc in ((OUTPUT_BYTES-1, WORKSPACE_BYTES), (OUTPUT_BYTES, WORKSPACE_BYTES-1)):
                    self.assertEqual(self.native._entry(source, len(data), context.output, oc,
                        context.workspace, wc), 0xfffffff1)
                first = self.native.step(context)
                context.service(first.request, first.value)
                data = context.data()
                altered = bytearray(data)
                position = data.index(transport(37)) + 16
                altered[position:position+2] = b'38'
                bad = ctypes.create_string_buffer(bytes(altered))
                before = sha256(memoryview(context.workspace).cast('B')[4096:]).digest()
                self.assertEqual(self.native._entry(bad, len(altered), context.output, OUTPUT_BYTES,
                    context.workspace, WORKSPACE_BYTES), 0xfffffff1)
                self.assertEqual(sha256(memoryview(context.workspace).cast('B')[4096:]).digest(), before)
                self.assertEqual(self.native.step(context).request, 2)
            finally:
                context.close()
                owner.types.close()
            def run(index):
                document = constant_program()
                document['functions'][0]['blocks'][0]['ops'][0]['attrs']['value'] = 37 + index
                owner = composite._Elaborator(document)
                try: return self.native.lower(owner, document['functions'][0])['blocks'][0]['ops'][0]['attrs']['value']
                finally: owner.types.close()
            with ThreadPoolExecutor(max_workers=2) as pool: actual = list(pool.map(run, range(4)))
            self.assertEqual(actual, [37, 38, 39, 40])

    def test_actual_callback_interrupt_and_reply_assignment_loss_cannot_replay(self):
        for mode in ('parameters_return', 'reply_assignment', 'helper_return'):
            with self.subTest(mode=mode), self.selected():
                document = fixtures.task_program() if mode == 'helper_return' else borrowed_function()
                owner = composite._Elaborator(document)
                function = next(fn for fn in document['functions'] if fn['name'] ==
                                ('task_case' if mode == 'helper_return' else 'borrowed'))
                interrupted = KeyboardInterrupt('injected actual ' + mode)
                captured, callbacks, tripped = [], [], []
                real_step, real_parameters, real_helper = self.native.step, owner.parameters, owner.helper
                real_assignment = FunctionContext.__setattr__
                def step(context):
                    result = real_step(context)
                    captured.append((context, result))
                    return result
                def parameters(value):
                    result = real_parameters(value)
                    callbacks.append(('parameters', deepcopy(value)))
                    if mode == 'parameters_return' and not tripped:
                        tripped.append(True)
                        raise interrupted
                    return result
                def helper(typ, operation, **kwargs):
                    result = real_helper(typ, operation, **kwargs)
                    callbacks.append(('helper', operation))
                    if mode == 'helper_return' and not tripped:
                        tripped.append(True)
                        raise interrupted
                    return result
                def assignment(context, name, value):
                    if (mode == 'reply_assignment' and name == 'reply'
                            and getattr(context, 'sequence', 0) == 1 and not tripped):
                        tripped.append(True)
                        raise interrupted
                    return real_assignment(context, name, value)
                try:
                    with patch.object(self.native, 'step', side_effect=step), \
                            patch.object(owner, 'parameters', side_effect=parameters), \
                            patch.object(owner, 'helper', side_effect=helper), \
                            patch.object(FunctionContext, '__setattr__', assignment), \
                            patch.object(composite._Elaborator, '_reference_helper',
                                         side_effect=AssertionError('host helper called')):
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            self.native.lower(owner, function)
                        self.assertIs(caught.exception, interrupted)
                        self.assertEqual(len(tripped), 1)
                        context, result = captured[-1]
                        self.assertEqual(result.request, 6 if mode == 'helper_return' else 1)
                        self.assertEqual(context.executed, context.sequence)
                        self.assertLess(context.completed, context.executed)
                        self.assertTrue(context.closed)
                        self.assertIsNone(context.output)
                        self.assertIsNone(context.workspace)
                        def state():
                            return (owner.serial, owner.value_slots, deepcopy(owner.helpers),
                                tuple(owner.helper_names.values()), deepcopy(owner.types.observations),
                                deepcopy(callbacks), deepcopy(context.ops),
                                tuple((name, value.names, value.consumed)
                                      for name, value in context.environment.items()))
                        snapshot = state()
                        for resume in (lambda: context.service(result.request, result.value),
                                       lambda: self.native.step(context), context.data):
                            with self.assertRaises(HIAProgramRejected): resume()
                        self.assertEqual(snapshot, state())
                        if mode == 'helper_return':
                            self.assertEqual(sum(kind == 'helper' for kind, _ in callbacks), 1)
                            self.assertEqual((len(owner.helpers), len(owner.helper_names)), (1, 1))
                        else:
                            self.assertEqual(len(callbacks), 1)
                finally:
                    owner.types.close()

    def test_selected_dependencies_refuse_only_at_original_continuation(self):
        from hepta.hia_call_primitive_native import SELECTOR as CALL_SELECTOR
        from hepta.hia_task_helpers_native import SELECTOR as HELPER_SELECTOR
        from hepta.hia_task_helper_cache_native import SELECTOR as CACHE_SELECTOR
        with self.selected():
            owner = composite._Elaborator(constant_program())
            try:
                with patch.dict(os.environ, {CALL_SELECTOR: ''}), patch.object(composite._Elaborator,
                        '_reference_call_primitive', side_effect=AssertionError('host call used')):
                    _, error = outcome(lambda: self.native.lower(owner, owner.document['functions'][0]))
                self.assertEqual(error[0], 'E_HIA_TYPE')
                self.assertIn('requires native continuation', error[1])
                self.assertEqual((owner.serial, owner.value_slots), (0, 1))
            finally:
                owner.types.close()
            owner = composite._Elaborator(fixtures.task_program())
            try:
                typ = owner.types.resolve('Work')
                name = owner.helper(typ, 'start', require_native=True)
                prefix = (owner.serial, deepcopy(owner.helpers), tuple(owner.helper_names.values()))
                with patch.dict(os.environ, {CACHE_SELECTOR: ''}), patch.object(owner, '_reference_helper_cache',
                        side_effect=AssertionError('native function used hosted cache lookup')):
                    with self.assertRaisesRegex(HIAProgramRejected, 'requires native task helper cache'):
                        owner.helper(typ, 'start', require_native=True)
                self.assertEqual(prefix, (owner.serial, owner.helpers, tuple(owner.helper_names.values())))
                with patch.dict(os.environ, {HELPER_SELECTOR: '/invalid-generator'}), \
                        patch.object(owner, 'check_task', side_effect=AssertionError('cached helper checked task')):
                    self.assertEqual(owner.helper(typ, 'start', require_native=True), name)
                self.assertEqual(prefix, (owner.serial, owner.helpers, tuple(owner.helper_names.values())))
                with patch.dict(os.environ, {HELPER_SELECTOR: ''}), \
                        patch.object(owner, 'check_task', side_effect=AssertionError('missing generator checked task')), \
                        patch.object(owner, '_reference_helper', side_effect=AssertionError('host helper used')):
                    with self.assertRaisesRegex(HIAProgramRejected, 'requires native task helper generation'):
                        owner.helper(typ, 'cancel', require_native=True)
                self.assertEqual(prefix, (owner.serial, owner.helpers, tuple(owner.helper_names.values())))
            finally:
                owner.types.close()

    def test_eight_downstream_images_are_pinned_after_actual_admission(self):
        from hepta import hia_record_transitions_native as transitions
        from hepta import hia_record_operations_native as records
        from hepta import hia_enum_operations_native as enums
        from hepta import hia_task_operations_native as tasks
        from hepta import hia_call_primitive_native as calls
        from hepta import hia_enum_match_native as matches
        from hepta import hia_nominal_terminators_native as terms
        from hepta import hia_task_helper_cache_native as cache
        cases = (
            (transitions, 'selected_record_transitions', partials.roundtrip_program(), 0),
            (records, 'selected_record_operations', fixtures.task_program(), 0),
            (enums, 'selected_enum_operations', fixtures.enum_owner_program(), 0),
            (tasks, 'selected_task_operations', fixtures.task_program(), 2),
            (calls, 'selected_call_primitive', constant_program(), 0),
            (matches, 'selected_enum_match', choice_program(), 0),
            (terms, 'selected_nominal_terminators', constant_program(), 0),
            (cache, 'selected_task_helper_cache', fixtures.task_program(), 2),
        )
        observations = []
        for module, selector_name, document, index in cases:
            with self.subTest(owner=selector_name), self.selected():
                old = composite._Elaborator(deepcopy(document))
                try:
                    expected = old._reference_function(old.document['functions'][index])
                    expected_state = (old.serial, old.value_slots, deepcopy(old.helpers),
                                      tuple(old.helper_names.values()), old.types.observations)
                finally:
                    old.types.close()
                owner = composite._Elaborator(deepcopy(document))
                original_selector = getattr(module, selector_name)
                image = original_selector()
                self.assertIsNotNone(image)
                original_lower = type(image).lower
                manifest = self.support[module.SELECTOR]
                counts = {'selector_reads': 0, 'native_invocations': 0}
                def select():
                    counts['selector_reads'] += 1
                    admitted = original_selector()
                    self.assertIsNotNone(admitted, 'admitted dependency was selected a second time')
                    os.environ[module.SELECTOR] = ''
                    return admitted
                def invoke(selected_image, *args, **kwargs):
                    self.assertEqual(os.environ[module.SELECTOR], '')
                    counts['native_invocations'] += 1
                    try:
                        return original_lower(selected_image, *args, **kwargs)
                    finally:
                        os.environ[module.SELECTOR] = manifest
                try:
                    with ExitStack() as stack:
                        stack.enter_context(patch.object(module, selector_name, side_effect=select))
                        stack.enter_context(patch.object(type(image), 'lower', invoke))
                        for name in HOST_REFERENCES:
                            stack.enter_context(patch.object(composite._Elaborator, name,
                                side_effect=AssertionError('host owner used after native admission: ' + name)))
                        actual = self.native.lower(owner, owner.document['functions'][index])
                    self.assertEqual(actual, expected)
                    self.assertEqual((owner.serial, owner.value_slots, owner.helpers,
                        tuple(owner.helper_names.values()), owner.types.observations), expected_state)
                    self.assertGreater(counts['native_invocations'], 0)
                    self.assertEqual(counts['selector_reads'], counts['native_invocations'])
                    observations.append({'owner': selector_name, **counts})
                finally:
                    os.environ[module.SELECTOR] = manifest
                    owner.types.close()
        self.assertEqual(len(observations), 8)
        self.pinning_observations = observations

    def test_existing_large_call_core_is_reused_and_later_callee_limit_is_unchanged(self):
        count = 8193
        parameters = [('p'+str(index), 'Wide') for index in range(count)]
        caller = f('caller', [('value', 'Wide')], [], ['trap'], [
            b('entry', [('value', 'Wide')],
              [fixtures.i('call', ['value'] * count, [], function='callee')], fixtures.ret())])
        callee = f('callee', parameters, [], ['trap'], [b('entry', parameters, [], {'op': 'trap', 'code': 'user'})])
        document = fixtures.module(wide_types(), caller, callee)
        observations = []
        for native in (False, True):
            with self.selected():
                owner = composite._Elaborator(deepcopy(document))
                held_arguments = []
                hold = FunctionContext.hold
                def observe(context, value):
                    if type(value) is list and value and type(value[0]) is dict and value[0].get('op') == 'call':
                        held_arguments.append(value[0]['args'])
                    return hold(context, value)
                try:
                    with patch.object(FunctionContext, 'hold', observe):
                        first = (self.native.lower(owner, owner.document['functions'][0]) if native
                                 else owner._reference_function(owner.document['functions'][0]))
                    args = first['blocks'][0]['ops'][0]['args']
                    self.assertEqual(len(args), count * 512)
                    if native:
                        self.assertTrue(held_arguments)
                        self.assertIs(args, held_arguments[-1])
                    _, error = outcome(lambda: self.native.lower(owner, owner.document['functions'][1])
                        if native else owner._reference_function(owner.document['functions'][1]))
                    observations.append((first, error, owner.serial, owner.value_slots))
                finally:
                    owner.types.close()
        self.assertEqual(observations[0], observations[1])
        self.assertEqual(observations[1][1],
                         ('E_HIA_LIMIT', 'E_HIA_LIMIT: nominal elaborated value-slot budget exceeded'))

    def test_original_nominal_resource_and_loan_suites_without_host_function(self):
        names = ('tests.test_hia_program_composite', 'tests.test_hia_partial_record',
                 'tests.test_hia_composite_returned_loans.CompositeReturnedLoans')
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(names)
        self.assertEqual(loader.errors, [])
        log = io.StringIO()
        with self.selected(), patch.object(composite._Elaborator, '_reference_function',
                side_effect=AssertionError('host function called')):
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        self.assertTrue(result.wasSuccessful(), log.getvalue())
        self.assertEqual((result.testsRun, len(result.skipped), len(result.expectedFailures),
                          len(result.unexpectedSuccesses)), (75, 0, 0, 0), log.getvalue())

    def test_actual_machine_allocator_failure_and_cleanup_with_native_function(self):
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        cc = shutil.which('cc')
        self.assertIsNotNone(cc)
        driver = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live[16]; static size_t allocations,frees,refusals,attempt,fail_at;
static void *remember(void *p){
  if(p){for(size_t i=0;i<16;i++)if(!live[i]){live[i]=p;allocations++;return p;}exit(80);}return p;
}
void *__wrap_malloc(size_t n){
  attempt++;if(fail_at && attempt==fail_at){refusals++;return NULL;}return remember(__real_malloc(n));
}
void *__wrap_calloc(size_t n,size_t w){
  attempt++;if(fail_at && attempt==fail_at){refusals++;return NULL;}
  return remember(__real_calloc(n,w));
}
void __wrap_free(void *p){if(p){size_t i;for(i=0;i<16 && live[i]!=p;i++);if(i==16)exit(81);live[i]=NULL;frees++;}__real_free(p);}
size_t task_case(uint8_t);
int main(void){
  if(task_case(2)!=28)return 10;
  if(task_case(0)!=33)return 11;
  if(task_case(1)!=13)return 12;
  fail_at=attempt+1;if(task_case(2)!=250)return 13;
  for(size_t i=0;i<16;i++)if(live[i])return 14;
  printf("%zu %zu %zu\n",allocations,frees,refusals);return 0;
}
'''
        folder = self.folder / 'machine'
        folder.mkdir()
        obj = folder / 'program.o'
        with self.selected(), patch.object(composite._Elaborator, '_reference_function',
                side_effect=AssertionError('host function used')):
            program = verify_core(fixtures.task_program())
            image = emit_program_machine(program)
            compile_program_machine(image, program=program, output=obj, kind='object', linker=cc)
        cfile = folder / 'driver.c'
        cfile.write_text(driver)
        executable = folder / 'run'
        built = subprocess.run([cc, str(cfile), str(obj), '-Wl,--wrap=malloc', '-Wl,--wrap=calloc', '-Wl,--wrap=free',
                                '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        executed = subprocess.run([str(executable)], capture_output=True, timeout=10)
        self.assertEqual((executed.returncode, executed.stdout, executed.stderr), (0, b'3 3 1\n', b''))

    def test_installed_wheel_source_custody_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/nominal_function.hiaasm', NATIVE_SOURCE_FILES)
        source = self.folder / 'wheel-source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        names = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES
        for name in (*names, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
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
            raise AssertionError('installed function imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_nominal_function_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host function called')
composite._Types=absent
for name in ('_reference_function','_reference_main_function','_reference_parameters','_reference_record_transition','_reference_record_operation',
             '_reference_enum_operation','_reference_task_operation','_reference_call_primitive',
             '_reference_nominal_terminator','_reference_match','_reference_helper','_reference_helper_cache'):
    setattr(composite._Elaborator,name,absent)
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
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(manifest), **self.support})
        for document in (constant_program(), call_program(), fixtures.task_program(), borrowed_function()):
            data.write_bytes(wire(document))
            with patch.dict(os.environ, {key: '' for key in (*self.support, SELECTOR)}):
                expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/nominal_function.hiaasm'
        original = resource.read_bytes()
        for missing in (False, True):
            try:
                resource.unlink() if missing else resource.write_bytes(original + b'\n')
                result = run('refuse')
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
            finally:
                resource.write_bytes(original)
        bad = self.folder / 'bad-manifest.json'
        bad.write_bytes(b'{}')
        result = run('refuse', bad)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))


if __name__ == '__main__':
    unittest.main()
