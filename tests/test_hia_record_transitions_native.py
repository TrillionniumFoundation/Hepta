"""Complete native record transitions: independent state, type-cache and effects."""
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
from hepta.hia_record_transitions_native import (SOURCE, SCHEMA, SELECTOR, MAGIC,
    ERRORS, INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, TransitionPacket,
    NativeRecordTransitions, installed_record_transitions, selected_record_transitions)
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests.test_hia_program import b, f
from tests.test_hia_enum_operations_native import wire, outcome

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_RECORD_TRANSITIONS_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_RECORD_TRANSITIONS_DEVELOPMENT_MANIFEST'


def borrow_program(mode='read'):
    types = [fixtures.record('Box', [('owner', 'buffer')])]
    loan = 'readbuf' if mode == 'read' else 'mutbuf'
    return fixtures.module(types, f('borrow_case', [], ['usize'], ['alloc', 'trap'], [
        b('entry', [], [fixtures.c('size', 'usize', 7), fixtures.i('buffer.new', ['size'], [('owner', 'buffer')]),
            fixtures.i('record.make', ['owner'], [('box', 'Box')]),
            fixtures.i('record.borrow', ['box'], [('view', loan)], field='owner', mode=mode),
            fixtures.i('buffer.len', ['view'], [('answer', 'usize')]), fixtures.i('loan.end', ['view']),
            fixtures.i('record.unpack', ['box'], [('restored', 'buffer')]), fixtures.i('owner.drop', ['restored'])],
          fixtures.ret('answer'))]))


def empty_program():
    empty = partials.partial('Empty')
    return partials.v3([fixtures.record('Empty', [])], f('empty_case', [], [], ['alloc'], [
        b('entry', [], [fixtures.i('record.begin', [], [('first', empty)]),
            fixtures.i('record.finish', ['first'], [('whole', 'Empty')]),
            fixtures.i('record.begin', [], [('second', empty)]), fixtures.i('record.abandon', ['second'])],
          fixtures.ret())]))


def cache_refusal_program():
    # The incorrect primitive output is admitted before lowering. The first
    # actual remainder descriptor is therefore created by record.take itself.
    return partials.v3([fixtures.record('Pair', [('left', 'buffer'), ('right', 'u32')])],
        f('bad', [('pair', 'Pair')], [], ['alloc'], [b('entry', [('pair', 'Pair')], [
            fixtures.i('record.take', ['pair'], [('out', 'buffer'), ('wrong', 'u32')], field='left')],
          fixtures.ret())]))


class RecordTransitionsSourceTests(unittest.TestCase):
    def test_generator_source_and_unchanged_compiler_limits(self):
        from tools import generate_hia_record_transitions as generator
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

    def test_selected_missing_image_never_reaches_reference(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_record_transitions())
        with patch.dict(os.environ, {SELECTOR: '/missing-record-transitions'}), patch.object(
                composite._Elaborator, '_reference_record_transition', side_effect=AssertionError('host transition called')):
            with self.assertRaises(HIAProgramRejected):
                verify_core(empty_program())

    def test_transport_preserves_interned_partial_base_and_argument_aliases(self):
        class ForbiddenKey:
            def __str__(self):
                raise AssertionError('display key expanded')
            def __hash__(self):
                raise AssertionError('semantic identity hashed')
            def __eq__(self, other):
                raise AssertionError('semantic identity compared')
        base = composite._Type(ForbiddenKey(), 'record', ())
        partial = composite._Type(ForbiddenKey(), 'partial_record', ('buffer',), record=base, linear=True)
        value = composite._Value(partial, ('token',))
        context = TransitionPacket('record.take', ['value', 'value'], {}, [value, value], [], 0)
        context.resolved = context.type_ref(partial)
        self.assertIs(type(context.data()), bytes)
        self.assertEqual((len(context.values), len(context.types)), (1, 2))


class RecordTransitionsAdapterTests(unittest.TestCase):
    def context(self, operation='record.begin', phase=0):
        base = composite._Type('Empty<>', 'record', ())
        partial = composite._Type('partial<Empty<>;>', 'partial_record', ('buffer',), record=base, linear=True)
        context = TransitionPacket(operation, [], {}, [], [('out', partial)], 7)
        context.data(); context.phase = phase
        return context

    def frame(self, context, *, request=0, error=0, final=None, query=None, ops=None, values=None):
        if values is None:
            values = [] if request or error or context.operation == 'record.abandon' else [['out', 0, ['token'], False, False]]
        if query is None and request:
            query = {'base': 1, 'fields': []} if request == 1 else {'type': 'readbuf'} if request == 2 else {}
        raw = wire({'ops': [] if ops is None else ops, 'consumed': [], 'values': values, 'query': query})
        return struct.pack('<8Q', MAGIC, error, context.serial if final is None else final,
                           request, len(raw), 0, 0, 0) + raw

    def image(self, data, *, mutate=False):
        image = object.__new__(NativeRecordTransitions)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate:
                ctypes.memmove(source, b'x', 1)
            if type(data) is int:
                return data
            ctypes.memmove(output, data, len(data))
            return len(data)
        image._entry = entry
        return image

    def test_bad_frames_effects_and_queries_fail_closed(self):
        context = self.context()
        for data in (0, 0xfffffff1, self.frame(context, final=6), self.frame(context, final=8193),
                     self.frame(context, error=99), self.frame(context, error=1),
                     self.frame(context, query={}), self.frame(context, values=[])):
            with self.subTest(data=repr(data)[:70]), self.assertRaises(HIAProgramRejected):
                self.image(data).step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'input bytes changed'):
            self.image(self.frame(context), mutate=True).step(context)
        context = self.context('record.take')
        for query in ({}, {'base': -1, 'fields': []}, {'base': 1, 'fields': [False]},
                      {'base': 1, 'fields': [], 'plan': []}):
            with self.assertRaises(HIAProgramRejected):
                self.image(self.frame(context, request=1, query=query)).step(context)
        with self.assertRaises(HIAProgramRejected):
            self.image(self.frame(context, request=1, ops=[{}])).step(context)

    def test_cannot_skip_repeat_or_reorder_type_owner_queries(self):
        phases = {'record.begin': {0: 0}, 'record.take': {0: 1, 1: 3, 2: 0},
                  'record.insert': {0: 1, 1: 3, 2: 0}, 'record.finish': {0: 3, 2: 0},
                  'record.abandon': {0: 3, 2: 0}, 'record.borrow': {0: 2, 1: 3, 2: 0}}
        for operation, steps in phases.items():
            for phase in range(3):
                for request in range(4):
                    if steps.get(phase) == request:
                        continue
                    context = self.context(operation, phase)
                    with self.subTest(operation=operation, phase=phase, request=request), self.assertRaises(HIAProgramRejected):
                        self.image(self.frame(context, request=request)).step(context)


class RecordTransitionsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development transitions cannot override cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-record-transitions-')
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
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='record-transitions')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder); source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'record-transitions', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_record_transitions(str(cls.manifest))

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def compare_at_transitions(self, document, *, variations=None, serials=(0, 8188, 8189, 8190, 8191, 8192), prepare=None):
        """Use unchanged closures and restore the original type cache per run.

        move_field closes over the actual operation list, so both implementations
        must use that exact list. New partial descriptors may be created before
        refusal; their semantic cache contents and call traces are compared.
        """
        case, observations = self, []
        reference = composite._Elaborator._reference_record_transition
        selected = composite._Elaborator.lower_record_transition

        def freeze(value):
            if isinstance(value, composite._Type):
                return ('type', value.key)
            if isinstance(value, dict):
                return tuple((key, freeze(item)) for key, item in sorted(value.items()))
            if isinstance(value, (tuple, list)):
                return tuple(freeze(item) for item in value)
            return value

        def compare(owner, ins, actual, declared, env, ops, consume, outputs, record_field, move_field):
            initial_serial, initial_env, initial_ops = owner.serial, dict(env), deepcopy(ops)
            held = {id(item): (item, item.consumed) for item in [*env.values(), *actual]}
            choices = [(deepcopy(ins), actual, declared)]
            if variations:
                choices.extend(variations(owner, ins, actual, declared))
            saved_cache = dict(owner.types.cache)
            saved_active = set(owner.types.active)
            saved_loans = dict(owner.types.known_loan_cache)
            saved_steps = owner.types.partial_declaration_steps
            def restore():
                env.clear(); env.update(initial_env); ops[:] = deepcopy(initial_ops)
                for item, consumed in held.values():
                    item.consumed = consumed
                owner.types.cache.clear(); owner.types.cache.update(saved_cache)
                owner.types.active.clear(); owner.types.active.update(saved_active)
                owner.types.known_loan_cache.clear(); owner.types.known_loan_cache.update(saved_loans)
                owner.types.partial_declaration_steps = saved_steps
            def observed(call):
                trace = []
                methods = {name: getattr(owner.types, name) for name in ('resolve', 'partial_record')}
                parameters = owner.parameters
                def tracked(name):
                    def invoke(*args, **kwargs):
                        trace.append((name, freeze(args), freeze(kwargs)))
                        return methods[name](*args, **kwargs)
                    return invoke
                def tracked_parameters(value):
                    trace.append(('parameters', freeze(value)))
                    return parameters(value)
                with patch.object(owner.types, 'resolve', side_effect=tracked('resolve')), patch.object(
                        owner.types, 'partial_record', side_effect=tracked('partial_record')), patch.object(
                        owner, 'parameters', side_effect=tracked_parameters):
                    _, error = outcome(call)
                snapshot = {name: (freeze(item.typ), item.names, item.external, item.consumed)
                            for name, item in env.items()}
                cache = tuple(sorted((key, typ.kind, typ.flat,
                    tuple((name, field.key) for name, field in typ.fields),
                    typ.record.key if typ.record is not None else None) for key, typ in owner.types.cache.items()))
                return (error, owner.serial, deepcopy(ops), snapshot, trace, cache,
                        owner.types.partial_declaration_steps, freeze(owner.types.known_loan_cache))
            for changed, values, declarations in choices:
                for serial in serials:
                    restore(); owner.serial = serial
                    if prepare:
                        prepare(owner, changed)
                    expected = observed(lambda: reference(owner, changed, values, declarations,
                        env, ops, consume, outputs, record_field, move_field))
                    restore(); owner.serial = serial
                    if prepare:
                        prepare(owner, changed)
                    with patch('hepta.hia_record_transitions_native.selected_record_transitions', return_value=case.native):
                        native = observed(lambda: selected(owner, changed, values, declarations,
                            env, ops, consume, outputs, record_field, move_field))
                    case.assertEqual(native, expected, (changed, serial))
                    observations.append((changed['op'], expected[0], serial, expected[1],
                        len(expected[2]) - len(initial_ops), expected[3], expected[4],
                        len(expected[5]) - len(saved_cache)))
            restore(); owner.serial = initial_serial
            return reference(owner, ins, actual, declared, env, ops, consume, outputs, record_field, move_field)
        with patch.object(composite._Elaborator, 'lower_record_transition', compare):
            _, original_error = outcome(lambda: verify_core(document))
        self.assertTrue(observations, 'fixture must reach a real record transition')
        return observations, original_error

    def test_exact_core_profiles_runtime_resource_and_return_origins(self):
        from tests import test_hia_composite_returned_loans as loans
        cases = [(partials.roundtrip_program, 'roundtrip', [7, False], 31),
                 (partials.task_partial_program, 'partial_task', [13, 2], 33),
                 (partials.nested_record_program, 'nested', [13], 27),
                 (partials.chain_partial_program, 'chain_case', [], False),
                 (empty_program, 'empty_case', [], [])]
        for version in (3, 4):
            for factory, name, arguments, answer in cases:
                document = factory(); document['schema'] = 'hepta.hia.composite.v' + str(version)
                with patch.dict(os.environ, {SELECTOR: ''}):
                    expected = verify_core(document)
                with self.selected(), patch.object(composite._Elaborator, '_reference_record_transition',
                        side_effect=AssertionError('host transition called')):
                    actual = verify_core(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))
                report = execute_program(actual, name, arguments)
                self.assertEqual(report['result'], answer)
                self.assertEqual((report['resources']['live_owners'], report['resources']['live_local_loans']), (0, 0))
        for version in range(1, 5):
            document = borrow_program(); document['schema'] = 'hepta.hia.composite.v' + str(version)
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected, expected_error = outcome(lambda: verify_core(document))
            with self.selected(), patch.object(composite._Elaborator, '_reference_record_transition',
                    side_effect=AssertionError('host transition called')):
                actual, actual_error = outcome(lambda: verify_core(document))
            self.assertEqual(actual_error, expected_error)
            if expected_error is None:
                self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
                self.assertEqual(execute_program(actual, 'borrow_case', [])['result'], 7)
        for mode in ('read', 'mut'):
            document = loans.pair_program(mode)
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_record_transition',
                    side_effect=AssertionError('host transition called')):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))
            self.assertEqual(execute_program(actual, 'probe', [1, 37, True])['result'], loans.expected(mode, 37))

    def test_original_errors_partial_ops_consumption_and_type_owner_order(self):
        def variations(owner, ins, actual, declared):
            choices = []
            for attrs in [{}, {'extra': 1}, {'field': False}, {'field': 'h2internal_7'},
                          {'field': '__hia_reserved'}, {'field': 'unknown'},
                          {'field': ins['attrs'].get('field', 'first'), 'mode': False}]:
                changed = deepcopy(ins); changed['attrs'] = attrs
                choices.append((changed, actual, declared))
            if ins['op'] == 'record.begin':
                choices += [(deepcopy(ins), actual, []),
                    (deepcopy(ins), actual, [('wrong', owner.types.resolve('u32'))])]
            else:
                for outputs in [[], [{'name': 'wrong', 'type': 'bool'}],
                                [{'name': 'wrong', 'type': 'unknown'}]]:
                    changed = deepcopy(ins); changed['out'] = outputs
                    choices.append((changed, actual, declared))
            return choices
        rows = []
        for document in [partials.roundtrip_program(), partials.nested_record_program(),
                         partials.chain_partial_program(), empty_program()]:
            observations, error = self.compare_at_transitions(document, variations=variations)
            self.assertIsNone(error)
            rows += observations
        document = borrow_program('mut'); document['schema'] = 'hepta.hia.composite.v4'
        observations, error = self.compare_at_transitions(document, variations=variations)
        self.assertIsNone(error); rows += observations
        self.assertTrue({'E_HIA_FORMAT', 'E_HIA_NAME', 'E_HIA_TYPE', 'E_HIA_LIMIT', 'E_HIA_LOAN'} <=
                        {row[1][0] for row in rows if row[1]})
        self.assertTrue(any(row[1] and row[1][0] == 'E_HIA_LIMIT' and row[4] > 0 for row in rows))
        self.assertTrue(any(row[0] == 'record.take' and row[1] and any(state[3] for state in row[5].values()) for row in rows))

    def test_type_cache_effects_survive_output_refusal_and_budget_refusal_order(self):
        rows, error = self.compare_at_transitions(cache_refusal_program(), serials=(0, 8192))
        self.assertEqual(error[0], 'E_HIA_TYPE')
        self.assertTrue(all(row[7] == 1 for row in rows), 'take must create its missing remainder before output refusal')
        self.assertTrue(all(row[6][0][0] == 'partial_record' for row in rows))
        def full_cache(owner, ins):
            if ins['op'] == 'record.take':
                for index in range(128 - len(owner.types.cache)):
                    key = 'Held' + str(index)
                    owner.types.cache[key] = composite._Type(key, 'record', ())
        rows, error = self.compare_at_transitions(cache_refusal_program(), serials=(0, 8192), prepare=full_cache)
        self.assertTrue(all(row[1][0] == 'E_HIA_LIMIT' and row[6][0][0] == 'partial_record'
                            and not any(call[0] == 'parameters' for call in row[6]) for row in rows))
        loan_record = partials.v3([fixtures.record('Stored', [('view', 'readbuf')])],
            f('bad', [('stored', 'Stored')], [], [], [b('entry', [('stored', 'Stored')], [
                fixtures.i('record.take', ['stored'], [('view', 'readbuf'), ('wrong', 'u32')], field='view')],
              fixtures.ret())]))
        rows, error = self.compare_at_transitions(loan_record, serials=(0, 8192))
        self.assertEqual(error[0], 'E_HIA_LOAN')
        self.assertTrue(all(not any(call[0] == 'parameters' for call in row[6]) for row in rows))

    def test_retained_partial_execution_and_rejection_controls_on_selected_owner(self):
        names = ['test_roundtrip_cross_call_and_reinitialization', 'test_error_and_cancel_only_clean_initialized_fields',
                 'test_empty_tokens_do_not_consume_failure_index', 'test_step_stop_does_not_invent_partial_cleanup']
        negative = ['test_old_schemas_reject_partial_types', 'test_old_schemas_reject_new_operations_even_without_partial_types',
            'test_uninitialized_read_and_borrow_reject', 'test_duplicate_initialization_rejects',
            'test_finish_missing_field_rejects', 'test_abandon_live_field_rejects',
            'test_begin_cannot_assert_initialized_field', 'test_use_after_take_and_insert_rejects',
            'test_taking_borrowed_owner_rejects', 'test_transfer_partial_owner_with_live_loan_rejects',
            'test_nested_owner_move_rejects_live_borrow', 'test_partial_typestates_consume_instantiation_budget',
            'test_partial_token_counts_against_flattened_layout_budget', 'test_empty_token_still_requires_alloc_effect']
        result = unittest.TestResult()
        with self.selected(), patch.object(composite._Elaborator, '_reference_record_transition',
                side_effect=AssertionError('host transition called')):
            unittest.TestSuite([*[partials.PartialRecordExecutionTests(name) for name in names],
                *[partials.PartialRecordRejectionTests(name) for name in negative]]).run(result)
        self.assertEqual(result.testsRun, len(names) + len(negative))
        self.assertEqual((result.errors, result.failures, result.skipped), ([], [], []))

    def test_multiple_owner_move_prefixes_and_maximum_partial_layout(self):
        child = fixtures.record('Child', [('a', 'buffer'), ('b', 'buffer'), ('chain', 'chain')])
        outer = fixtures.record('Outer', [('child', 'Child'), ('count', 'u32')])
        rest, empty = partials.partial('Outer', 'count'), partials.partial('Outer')
        document = partials.v3([child, outer], f('take_many', [('value', 'Outer')], ['u32'], ['alloc'], [
            b('entry', [('value', 'Outer')], [
                fixtures.i('record.take', ['value'], [('child', 'Child'), ('rest', rest)], field='child'),
                fixtures.i('record.unpack', ['child'], [('a', 'buffer'), ('b', 'buffer'), ('nodes', 'chain')]),
                fixtures.i('owner.drop', ['a']), fixtures.i('owner.drop', ['b']), fixtures.i('owner.drop', ['nodes']),
                fixtures.i('record.take', ['rest'], [('count', 'u32'), ('empty', empty)], field='count'),
                fixtures.i('record.abandon', ['empty']),
            ], fixtures.ret('count'))]))
        rows, error = self.compare_at_transitions(document, serials=(0, 8186, 8187, 8188, 8190, 8192))
        self.assertIsNone(error)
        self.assertTrue(any(row[1] and row[1][0] == 'E_HIA_LIMIT' and row[4] >= 4 for row in rows))
        self.assertTrue(any(row[0] == 'record.take' and row[1] is None and row[2] == 8186 and row[3] == 8192 for row in rows))
        long = lambda prefix: prefix + 'x' * (128 - len(prefix))
        fields = [(long('field' + str(index)), 'Chunk' if index < 63 else 'Tail') for index in range(64)]
        target = fields[32][0]
        initialized = [name for name, _ in fields]
        remainder = partials.partial('Wide', *[name for name in initialized if name != target])
        complete = partials.partial('Wide', *initialized)
        types = [fixtures.record('Chunk', [('f' + str(i), 'u32') for i in range(8)]),
                 fixtures.record('Tail', [('f' + str(i), 'u32') for i in range(7)]),
                 fixtures.record('Wide', fields)]
        wide = partials.v3(types, f('wide', [('input', 'u32')], ['u32'], ['alloc'], [
            b('entry', [('input', 'u32')], [
                fixtures.i('record.make', ['input'] * 8, [('chunk', 'Chunk')]),
                fixtures.i('record.make', ['input'] * 7, [('tail', 'Tail')]),
                fixtures.i('record.make', ['chunk'] * 63 + ['tail'], [('wide', 'Wide')]),
                fixtures.i('record.take', ['wide'], [('taken', 'Chunk'), ('rest', remainder)], field=target),
                fixtures.i('record.insert', ['rest', 'taken'], [('full', complete)], field=target),
                fixtures.i('record.finish', ['full'], [('restored', 'Wide')]),
                fixtures.i('record.get', ['restored'], [('last', 'Tail')], field=fields[-1][0]),
                fixtures.i('record.get', ['last'], [('answer', 'u32')], field='f6'),
            ], fixtures.ret('answer'))]))
        with patch.dict(os.environ, {SELECTOR: ''}):
            expected = verify_core(wide)
        with self.selected(), patch.object(composite._Elaborator, '_reference_record_transition',
                side_effect=AssertionError('host transition called')):
            actual = verify_core(wide)
        self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
        self.assertEqual(execute_program(actual, 'wide', [37])['result'], 37)

    def test_public_arity_attributes_mode_and_field_type_refusals(self):
        candidates = []
        for operation in ('record.begin', 'record.take', 'record.insert', 'record.finish', 'record.abandon', 'record.borrow'):
            base = borrow_program() if operation == 'record.borrow' else partials.roundtrip_program()
            base['schema'] = 'hepta.hia.composite.v4'
            for change in ('attrs', 'args', 'out'):
                document = deepcopy(base)
                selected = next(ins for fn in document['functions'] for block in fn['blocks']
                                for ins in block['ops'] if ins['op'] == operation)
                if change == 'attrs':
                    selected['attrs'] = {'bad': 1}
                elif change == 'args':
                    if operation == 'record.begin':
                        continue
                    selected['args'] = []
                else:
                    if operation == 'record.abandon':
                        selected['out'] = [{'name': 'unexpected', 'type': 'u32'}]
                    else:
                        selected['out'] = []
                candidates.append(document)
        for mode in (False, 'invalid'):
            document = borrow_program(); document['schema'] = 'hepta.hia.composite.v4'
            operation = next(ins for ins in document['functions'][0]['blocks'][0]['ops'] if ins['op'] == 'record.borrow')
            operation['attrs'] = {'mode': mode, 'field': False}
            candidates.append(document)
        wrong_field = borrow_program(); wrong_field['schema'] = 'hepta.hia.composite.v4'
        wrong_field['types'][0]['fields'].append(fixtures.field('count', 'usize'))
        operations = wrong_field['functions'][0]['blocks'][0]['ops']
        make = next(ins for ins in operations if ins['op'] == 'record.make'); make['args'].append('size')
        borrow = next(ins for ins in operations if ins['op'] == 'record.borrow'); borrow['attrs']['field'] = 'count'
        candidates.append(wrong_field)
        for document in candidates:
            with patch.dict(os.environ, {SELECTOR: ''}):
                _, expected = outcome(lambda: verify_core(document))
            with self.selected(), patch.object(composite._Elaborator, '_reference_record_transition',
                    side_effect=AssertionError('host transition called')):
                _, actual = outcome(lambda: verify_core(document))
            self.assertIsNotNone(expected)
            self.assertEqual(actual, expected)

    def test_independent_hia_vm_matches_image_queries_results_and_partial_ops(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        owner = composite._Elaborator(cache_refusal_program())
        base, buffer_type = owner.types.resolve('Pair'), owner.types.resolve('buffer')
        empty = owner.types.partial_record(base, [])
        remainder = owner.types.partial_record(base, ['right'])
        actual = composite._Value(base, ('source_owner', 'source_number'))
        contexts = [TransitionPacket('record.begin', [], {}, [], [('empty', empty)], serial) for serial in (0, 8190, 8192)]
        for phase in (0, 1, 2):
            context = TransitionPacket('record.take', ['pair'], {'field': 'left'}, [actual],
                                       [('owner', buffer_type), ('rest', remainder)], 8189)
            if phase:
                context.resolved = context.type_ref(remainder); context.phase = phase
            if phase == 2:
                context.outputs = [['owner', context.type_ref(buffer_type)], ['rest', context.type_ref(remainder)]]
            contexts.append(context)
        loan = owner.types.resolve('readbuf')
        for phase in (0, 1, 2):
            context = TransitionPacket('record.borrow', ['pair'], {'mode': 'read', 'field': 'left'},
                                       [actual], [('loan', loan)], 8192)
            if phase:
                context.resolved = context.type_ref(loan); context.phase = phase
            if phase == 2:
                context.outputs = [['loan', context.type_ref(loan)]]
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

    def test_all_native_nominal_type_record_enum_match_owners_compose(self):
        from tests import test_hia_composite_types_native as types
        from tests import test_hia_enum_operations_native as enums
        from tests import test_hia_enum_match_native as matches
        from tests import test_hia_record_operations_native as records
        from hepta.hia_composite_types_native import SELECTOR as TYPE_SELECTOR
        from hepta.hia_enum_operations_native import SELECTOR as ENUM_SELECTOR
        from hepta.hia_enum_match_native import SELECTOR as MATCH_SELECTOR
        from hepta.hia_record_operations_native import SELECTOR as RECORD_SELECTOR
        prepared = {}
        for tests, implementation, selector in [(types, types.CompositeTypesNativeTests, TYPE_SELECTOR),
                (enums, enums.EnumOperationsNativeTests, ENUM_SELECTOR),
                (matches, matches.EnumMatchNativeTests, MATCH_SELECTOR),
                (records, records.RecordOperationsNativeTests, RECORD_SELECTOR)]:
            fixture = type('SupportingFixture', (unittest.TestCase,), {})
            self.addCleanup(fixture.doClassCleanups)
            extra = {}
            if os.environ.get(COLD_REPORT) and not os.environ.get(tests.COLD_REPORT):
                extra[tests.COLD_REPORT] = os.environ[COLD_REPORT]
            with patch.dict(os.environ, extra):
                implementation.setUpClass.__func__(fixture)
            prepared[selector] = str(fixture.manifest)
        prepared[SELECTOR] = str(self.manifest)
        from tests import test_hia_composite_returned_loans as loans
        for document, name, arguments, answer in [
            (partials.task_partial_program(), 'partial_task', [13, 2], 33),
            (partials.roundtrip_program(), 'roundtrip', [7, False], 31),
            (loans.pair_program('mut'), 'probe', [1, 37, True], loans.expected('mut', 37))]:
            with patch.dict(os.environ, {key: '' for key in prepared}):
                expected = verify_core(document)
            with patch.dict(os.environ, prepared), patch.object(composite, '_Types',
                    side_effect=AssertionError('host type owner called')), patch.object(
                    composite._Elaborator, '_reference_record_transition', side_effect=AssertionError('host transition called')), patch.object(
                    composite._Elaborator, '_reference_record_operation', side_effect=AssertionError('host record called')), patch.object(
                    composite._Elaborator, '_reference_enum_operation', side_effect=AssertionError('host enum called')), patch.object(
                    composite._Elaborator, '_reference_match', side_effect=AssertionError('host match called')):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))
            self.assertEqual(execute_program(actual, name, arguments)['result'], answer)

    def test_actual_machine_allocator_failures_moves_and_cleanup(self):
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
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
size_t roundtrip(size_t,uint8_t);
int main(void){
  if(roundtrip(7,0)!=31 || roundtrip(7,1)!=33 || roundtrip(0,0)!=17)return 82;
  attempt=0;fail_at=1;if(roundtrip(7,0)!=250)return 83;
  attempt=0;fail_at=2;if(roundtrip(7,0)!=24)return 84;
  for(size_t i=0;i<16;i++)if(live[i])return 85;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=4 || frees!=4 || refusals!=2;
}
'''
        with self.selected(), patch.object(composite._Elaborator, '_reference_record_transition',
                side_effect=AssertionError('host transition called')):
            checked = verify_core(partials.roundtrip_program())
        obj = self.folder / 'transition-effects.o'
        compile_program_machine(emit_program_machine(checked), program=checked, output=obj, kind='object', linker=cc)
        source, executable = self.folder / 'transition-effects.c', self.folder / 'transition-effects'
        source.write_text(driver)
        built = subprocess.run([cc, '-std=c11', '-O2', str(source), str(obj),
            '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(executable)], capture_output=True, timeout=30)
        self.assertEqual((ran.returncode, ran.stdout, ran.stderr), (0, b'4 4 2\n', b''))

    def test_private_region_depth_and_concurrent_results(self):
        from concurrent.futures import ThreadPoolExecutor
        from hepta.hia_instruction_policy_native import transport
        owner = composite._Elaborator(empty_program()); typ = owner.types.resolve(partials.partial('Empty'))
        context = TransitionPacket('record.begin', [], {}, [], [('empty', typ)], 0)
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

    def test_repeated_zero_width_arguments_and_exact_output_slot_boundary(self):
        empty = partials.partial('Empty')
        candidates = [partials.v3([fixtures.record('Empty', [])],
            f('bad', [('input', 'Empty')], [], ['alloc'], [b('entry', [('input', 'Empty')], [
                fixtures.i('record.begin', ['input'] * 15000, [('state', empty)])], fixtures.ret())]))]
        codes = ['E_HIA_TYPE']
        for count, code in [(32767, 'E_HIA_TYPE'), (32768, 'E_HIA_LIMIT')]:
            candidates.append(partials.v3([fixtures.record('Empty', [])],
                f('bad', [('state', empty)], [], ['alloc'], [b('entry', [('state', empty)], [
                    fixtures.i('record.finish', ['state'], [('out' + str(i), 'u32') for i in range(count)])],
                  fixtures.ret())])))
            codes.append(code)
        for document, code in zip(candidates, codes):
            with patch.dict(os.environ, {SELECTOR: ''}):
                _, expected = outcome(lambda: verify_core(document))
            with self.selected(), patch.object(composite._Elaborator, '_reference_record_transition',
                    side_effect=AssertionError('host transition called')):
                _, actual = outcome(lambda: verify_core(document))
            self.assertEqual(actual, expected)
            self.assertEqual(actual[0], code)

    def test_installed_wheel_source_custody_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/record_transitions.hepta', NATIVE_SOURCE_FILES)
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
            raise AssertionError('installed transitions imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_record_transitions_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host transition called')
composite._Elaborator._reference_record_transition=absent
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
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(manifest)})
        for document in (partials.roundtrip_program(), partials.chain_partial_program(), empty_program()):
            data.write_bytes(wire(document))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/record_transitions.hepta'
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
