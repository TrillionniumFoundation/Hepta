"""Native record field policy, independent reference state and real effects."""
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
from hepta.hia_record_operations_native import (SOURCE, SCHEMA, SELECTOR, MAGIC,
    ERRORS, INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, RecordPacket,
    NativeRecordOperations, installed_record_operations, selected_record_operations)
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests.test_hia_program import b, f
from tests.test_hia_enum_operations_native import wire, outcome

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_RECORD_OPERATIONS_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_RECORD_OPERATIONS_DEVELOPMENT_MANIFEST'


def scalar_program():
    types = [fixtures.record('Empty', []), fixtures.record('Pair', [('left', 'u32'), ('right', 'u32')]),
             fixtures.record('Nested', [('empty', 'Empty'), ('pair', 'Pair')])]
    return fixtures.module(types, f('scalar', [('input', 'u32')], ['u32'], [], [
        b('entry', [('input', 'u32')], [
            fixtures.i('record.make', [], [('empty', 'Empty')]),
            fixtures.i('record.make', ['input', 'input'], [('pair', 'Pair')]),
            fixtures.i('record.make', ['empty', 'pair'], [('nested', 'Nested')]),
            fixtures.i('record.get', ['nested'], [('alias', 'Pair')], field='pair'),
            fixtures.i('record.get', ['nested'], [('zero', 'Empty')], field='empty'),
            fixtures.i('record.get', ['alias'], [('answer', 'u32')], field='right'),
            fixtures.i('record.unpack', ['alias'], [('left', 'u32'), ('right', 'u32')]),
            fixtures.i('record.unpack', ['zero']),
        ], fixtures.ret('answer'))]))


def resource_program():
    types = [fixtures.record('Box', [('owner', 'buffer'), ('count', 'usize')])]
    return fixtures.module(types, f('record_case', [('size', 'usize')], ['usize'], ['alloc', 'trap'], [
        b('entry', [('size', 'usize')], [
            fixtures.i('buffer.try_new', ['size'], [('owner', 'buffer'), ('ok', 'bool')]),
            fixtures.c('count', 'usize', 17),
            fixtures.i('record.make', ['owner', 'count'], [('box', 'Box')]),
            fixtures.i('record.get', ['box'], [('constant', 'usize')], field='count'),
            fixtures.i('record.unpack', ['box'], [('owned', 'buffer'), ('marker', 'usize')]),
            fixtures.i('buffer.len', ['owned'], [('length', 'usize')]), fixtures.i('owner.drop', ['owned']),
            fixtures.i('int.add.checked', ['length', 'constant'], [('answer', 'usize')]),
        ], fixtures.ret('answer'))]))


def external_loan_program():
    types = [fixtures.record('Reader', [('view', 'readbuf')])]
    callee = f('length', [('reader', 'Reader')], ['usize'], [], [
        b('entry', [('reader', 'Reader')], [
            fixtures.i('record.unpack', ['reader'], [('external', 'readbuf')]),
            fixtures.i('record.make', ['external'], [('rebuilt', 'Reader')]),
            fixtures.i('record.unpack', ['rebuilt'], [('view', 'readbuf')]),
            fixtures.i('buffer.len', ['view'], [('size', 'usize')]),
        ], fixtures.ret('size'))])
    caller = f('borrowed_call', [], ['usize'], ['alloc', 'trap'], [
        b('entry', [], [fixtures.c('size', 'usize', 9), fixtures.i('buffer.new', ['size'], [('owner', 'buffer')]),
            fixtures.i('borrow.read', ['owner'], [('loan', 'readbuf')]),
            fixtures.i('record.make', ['loan'], [('stored', 'Reader')]),
            fixtures.i('call', ['stored'], [('answer', 'usize')], function='length'),
            fixtures.i('record.unpack', ['stored'], [('restored', 'readbuf')]),
            fixtures.i('loan.end', ['restored']), fixtures.i('owner.drop', ['owner'])], fixtures.ret('answer'))])
    return fixtures.module(types, callee, caller)


def partial_get_program(field='value'):
    base = 'Pair'
    empty, present = partials.partial(base), partials.partial(base, 'value')
    return partials.v3([fixtures.record(base, [('value', 'u32'), ('missing', 'u32')])],
        f('partial_get', [], ['u32'], ['alloc'], [b('entry', [], [
            fixtures.i('record.begin', [], [('empty', empty)]), fixtures.c('number', 'u32', 37),
            fixtures.i('record.insert', ['empty', 'number'], [('present', present)], field='value'),
            fixtures.i('record.get', ['present'], [('answer', 'u32')], field=field),
            fixtures.i('record.take', ['present'], [('removed', 'u32'), ('rest', empty)], field='value'),
            fixtures.i('record.abandon', ['rest']),
        ], fixtures.ret('answer'))]))


class RecordOperationsSourceTests(unittest.TestCase):
    def test_generator_matches_source_and_unchanged_native_profile(self):
        from tools import generate_hia_record_operations as generator
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

    def test_selected_missing_image_has_no_reference_fallback(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_record_operations())
        with patch.dict(os.environ, {SELECTOR: '/missing-record-manifest'}), patch.object(
                composite._Elaborator, '_reference_record_operation', side_effect=AssertionError('host record called')):
            with self.assertRaises(HIAProgramRejected):
                verify_core(scalar_program())

    def test_transport_holds_exact_descriptor_and_alias_identity(self):
        class ForbiddenKey:
            def __str__(self):
                raise AssertionError('transport expanded nominal display identity')
            def __hash__(self):
                raise AssertionError('transport hashed semantic identity')
            def __eq__(self, other):
                raise AssertionError('transport compared semantic identity')
        empty = composite._Type(ForbiddenKey(), 'record', ())
        record = composite._Type(ForbiddenKey(), 'record', (), fields=(('a', empty), ('b', empty)))
        partial = composite._Type(ForbiddenKey(), 'partial_record', ('buffer',),
                                  fields=(('b', empty),), record=record, linear=True)
        item = composite._Value(empty, (), external=True)
        context = RecordPacket('record.make', ['item', 'item'], {}, [item, item], [('out', record)], 8192)
        context.type_ref(partial)
        self.assertIs(type(context.data()), bytes)
        self.assertEqual((len(context.values), len(context.types)), (1, 3))
        self.assertEqual(context.arguments, [['item', 0], ['item', 0]])


class RecordOperationsAdapterTests(unittest.TestCase):
    def context(self, operation='record.make', phase=0):
        typ = composite._Type('Empty<>', 'record', ())
        actual = composite._Value(typ, (), external=True)
        context = RecordPacket(operation, ['value'] if operation != 'record.make' else [],
            {}, [actual] if operation != 'record.make' else [], [('out', typ)], 8192)
        context.data(); context.phase = phase
        if phase:
            context.outputs = []
        return context

    def frame(self, context, *, error=0, serial=None, request=0, payload=None, magic=MAGIC, reserved=0):
        if payload is None:
            payload = {'ops': [], 'consumed': [item.consumed for item in context.values],
                'values': [] if error or request or context.operation == 'record.unpack'
                          else [['out', 0, [], True, False]]}
        raw = wire(payload)
        return struct.pack('<8Q', magic, error, context.serial if serial is None else serial,
                           request, len(raw), reserved, 0, 0) + raw

    def image(self, data, *, mutate=False):
        image = object.__new__(NativeRecordOperations)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate:
                ctypes.memmove(source, b'x', 1)
            if type(data) is int:
                return data
            ctypes.memmove(output, data, len(data))
            return len(data)
        image._entry = entry
        return image

    def test_invalid_frames_and_invented_instructions_fail_closed(self):
        context = self.context()
        invalid = [0, 0xfffffff1, self.frame(context, magic=0), self.frame(context, reserved=1),
            self.frame(context, error=99), self.frame(context, serial=8191), self.frame(context, serial=8193),
            self.frame(context, request=1), self.frame(context, payload={'ops': [], 'consumed': [], 'values': []}),
            self.frame(context, payload={'ops': [{}], 'consumed': [], 'values': [['out', 0, [], False, False]]}),
            self.frame(context, payload={'ops': [], 'consumed': [False], 'values': []}),
            self.frame(context, payload={'ops': [], 'consumed': [], 'values': [], 'plan': []}),
            self.frame(context, error=2, payload={'ops': [], 'consumed': [], 'values': [['out', 0, [], False, False]]})]
        for frame in invalid:
            with self.subTest(frame=repr(frame)[:70]), self.assertRaises(HIAProgramRejected):
                self.image(frame).step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'input bytes changed'):
            self.image(self.frame(context), mutate=True).step(context)

    def test_output_reparse_cannot_be_skipped_repeated_or_effectful(self):
        for operation in ('record.unpack', 'record.get'):
            for phase in (0, 1):
                context = self.context(operation, phase)
                expected = 1 - phase
                with self.assertRaises(HIAProgramRejected):
                    self.image(self.frame(context, request=phase)).step(context)
                if expected:
                    payload = {'ops': [], 'consumed': [True], 'values': []}
                    with self.assertRaises(HIAProgramRejected):
                        self.image(self.frame(context, request=expected, payload=payload)).step(context)
        context = self.context('record.unpack', 1)
        self.assertEqual(self.image(self.frame(context)).step(context).bindings, [])


class RecordOperationsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development record operations cannot override cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-record-operations-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        if development:
            supplied = Path(development)
            value = json.loads(supplied.read_bytes()); name = value['image_path']
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
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='record-operations')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'record-operations', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_record_operations(str(cls.manifest))

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def compare_at_operations(self, document, *, variations=None, serials=(0, 8191, 8192)):
        """The unchanged branch runs with original admitted value/field closures."""
        case, observations = self, []
        reference = composite._Elaborator._reference_record_operation
        selected = composite._Elaborator.lower_record_operation

        def compare(owner, ins, actual, declared, env, ops, consume, outputs, record_field):
            initial_serial, initial_env = owner.serial, dict(env)
            held = {id(item): (item, item.consumed) for item in [*env.values(), *actual]}
            choices = [(deepcopy(ins), actual, declared)]
            if variations:
                choices.extend(variations(owner, ins, actual, declared))
            def restore():
                env.clear(); env.update(initial_env)
                for item, consumed in held.values():
                    item.consumed = consumed
            def observed(call, current_ops):
                trace = []
                resolve, parameters = owner.types.resolve, owner.parameters
                def tracked_resolve(*args, **kwargs):
                    trace.append(('resolve', deepcopy(args), deepcopy(kwargs)))
                    return resolve(*args, **kwargs)
                def tracked_parameters(value):
                    trace.append(('parameters', deepcopy(value)))
                    return parameters(value)
                with patch.object(owner.types, 'resolve', side_effect=tracked_resolve), patch.object(
                        owner, 'parameters', side_effect=tracked_parameters):
                    _, error = outcome(call)
                snapshot = {name: (id(item.typ), item.names, item.external, item.consumed)
                            for name, item in env.items()}
                return error, owner.serial, deepcopy(current_ops), snapshot, trace
            for changed, values, declarations in choices:
                for serial in serials:
                    restore(); owner.serial = serial
                    reference_ops = list(ops)
                    expected = observed(lambda: reference(owner, changed, values, declarations,
                        env, reference_ops, consume, outputs, record_field), reference_ops)
                    restore(); owner.serial = serial
                    native_ops = list(ops)
                    with patch('hepta.hia_record_operations_native.selected_record_operations', return_value=case.native):
                        native = observed(lambda: selected(owner, changed, values, declarations,
                            env, native_ops, consume, outputs, record_field), native_ops)
                    case.assertEqual(native, expected, (changed, serial))
                    case.assertEqual(owner.serial, serial)
                    case.assertEqual(native_ops, ops)
                    observations.append((changed['op'], expected[0], expected[3], expected[4]))
            restore(); owner.serial = initial_serial
            return reference(owner, ins, actual, declared, env, ops, consume, outputs, record_field)
        with patch.object(composite._Elaborator, 'lower_record_operation', compare):
            _, original_error = outcome(lambda: verify_core(document))
        self.assertTrue(observations, 'fixture must reach an actual record operation')
        return observations, original_error

    def test_all_versions_exact_core_and_independent_execution(self):
        for version in range(1, 5):
            for factory, name, args, answers in [
                (scalar_program, 'scalar', [(0,), (37,), (0xffffffff,)], [0, 37, 0xffffffff]),
                (resource_program, 'record_case', [(0,), (7,)], [17, 24]),
                (fixtures.stored_loan_program, 'stored', [(False,), (True,)], [91, 91]),
                (external_loan_program, 'borrowed_call', [()], [9])]:
                document = factory(); document['schema'] = 'hepta.hia.composite.v' + str(version)
                with patch.dict(os.environ, {SELECTOR: ''}):
                    expected = verify_core(document)
                with self.selected(), patch.object(composite._Elaborator, '_reference_record_operation',
                        side_effect=AssertionError('host record called')):
                    actual = verify_core(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))
                self.assertEqual(actual.as_dict()['schema'], 'hepta.hia.program.v' + str(6 if version == 1 else 8 if version == 4 else 7))
                for arguments, answer in zip(args, answers):
                    report = execute_program(actual, name, arguments)
                    self.assertEqual(report['result'], answer)
                    self.assertEqual((report['resources']['live_owners'], report['resources']['live_local_loans']), (0, 0))

    def test_first_errors_external_flags_aliases_and_type_owner_call_order(self):
        def variants(owner, ins, actual, declared):
            result = []
            bad_attrs = [{'extra': 1}]
            if ins['op'] == 'record.get':
                bad_attrs += [{}, {'field': True}, {'field': '__hia_reserved'},
                              {'field': 'h2internal_9'}, {'field': 'absent'}]
            for attrs in bad_attrs:
                changed = deepcopy(ins); changed['attrs'] = attrs
                result.append((changed, actual, declared))
            if ins['op'] == 'record.make':
                result += [(deepcopy(ins), actual, []),
                    (deepcopy(ins), actual, [('wrong', owner.types.resolve('u32'))]),
                    (deepcopy(ins), actual, [*declared, *declared])]
            else:
                for outputs in [[], [{'name': 'wrong', 'type': 'bool'}],
                                [{'name': 'wrong', 'type': 'unknown'}]]:
                    changed = deepcopy(ins); changed['out'] = outputs
                    result.append((changed, actual, declared))
            return result
        rows = []
        for document in [scalar_program(), fixtures.stored_loan_program(), external_loan_program(),
                         resource_program(), partial_get_program(), fixtures.task_program()]:
            observations, error = self.compare_at_operations(document, variations=variants)
            self.assertIsNone(error)
            rows += observations
        self.assertTrue({'E_HIA_FORMAT', 'E_HIA_NAME', 'E_HIA_TYPE'} <=
                        {row[1][0] for row in rows if row[1]})
        self.assertTrue(any(state[2] for row in rows for state in row[2].values()), 'external flags must be exercised')
        self.assertTrue(any(not state[2] for row in rows for state in row[2].values()), 'local flags must be exercised')

    def test_duplicate_linear_argument_keeps_consumed_prefix_and_no_bindings(self):
        document = fixtures.module([fixtures.record('Pair', [('a', 'buffer'), ('b', 'buffer')])],
            f('bad', [('owner', 'buffer')], [], [], [b('entry', [('owner', 'buffer')], [
                fixtures.i('record.make', ['owner', 'owner'], [('pair', 'Pair')])], fixtures.ret())]))
        rows, error = self.compare_at_operations(document)
        self.assertEqual(error, ('E_HIA_RESOURCE', 'E_HIA_RESOURCE: use of consumed nominal value'))
        for _, refusal, state, trace in rows:
            self.assertEqual(refusal, error)
            self.assertTrue(state['owner'][3])
            self.assertNotIn('pair', state)
            self.assertEqual(trace, [])

    def test_partial_projection_uninitialized_unknown_and_loan_field_refusals(self):
        for field, error in [('value', None), ('missing', 'E_HIA_INIT'), ('unknown', 'E_HIA_TYPE')]:
            rows, original = self.compare_at_operations(partial_get_program(field))
            self.assertEqual(original[0] if original else None, error)
            if original is None:
                with self.selected():
                    self.assertEqual(execute_program(partial_get_program(field), 'partial_get', [])['result'], 37)
        for source in (fixtures.stored_loan_program(), external_loan_program()):
            block = source['functions'][0]['blocks'][1 if len(source['functions']) == 1 else 0]
            input_name = block['params'][0]['name']
            output_type = 'buffer' if len(source['functions']) == 1 else 'readbuf'
            field = 'owner' if len(source['functions']) == 1 else 'view'
            block['ops'].insert(0, fixtures.i('record.get', [input_name], [('forbidden', output_type)], field=field))
            rows, error = self.compare_at_operations(source)
            self.assertEqual(error[0], 'E_HIA_RESOURCE')
            self.assertTrue(any(row[1] == error and row[3] == [] for row in rows))

    def test_public_malformed_inputs_and_same_flat_distinct_nominal_fields(self):
        cases = []
        base = resource_program()
        for index, key, value in [(2, 'attrs', {'bad': 1}), (2, 'out', []),
            (2, 'out', [{'name': 'box', 'type': 'u32'}]), (2, 'args', []),
            (2, 'args', ['owner', 'owner']), (2, 'args', ['undefined', 'count']),
            (3, 'attrs', {}), (3, 'args', []), (3, 'args', ['count']),
            (3, 'attrs', {'field': False}), (3, 'attrs', {'field': 'h2internal_1'}),
            (3, 'attrs', {'field': 'unknown'}), (3, 'attrs', {'field': 'owner'}),
            (3, 'out', [{'name': 'constant', 'type': 'bool'}]),
            (4, 'attrs', {'bad': 1}), (4, 'args', []), (4, 'args', ['count']),
            (4, 'out', []), (4, 'out', [{'name': 'new', 'type': 'missing'}])]:
            document = deepcopy(base); document['functions'][0]['blocks'][0]['ops'][index][key] = value
            cases.append(document)
        types = [fixtures.record('A', [('n', 'u32')]), fixtures.record('B', [('n', 'u32')]),
                 fixtures.record('Box', [('child', 'A')])]
        cases.append(fixtures.module(types, f('wrong', [('b', 'B')], [], [], [
            b('entry', [('b', 'B')], [fixtures.i('record.make', ['b'], [('value', 'Box')])], fixtures.ret())])))
        cases.append(partial_get_program('missing'))
        messages = set()
        for document in cases:
            with patch.dict(os.environ, {SELECTOR: ''}):
                _, expected = outcome(lambda: verify_core(document))
            with self.selected(), patch.object(composite._Elaborator, '_reference_record_operation',
                    side_effect=AssertionError('host record called')):
                _, actual = outcome(lambda: verify_core(document))
            self.assertIsNotNone(expected)
            self.assertEqual(actual, expected)
            messages.add(actual[1])
        for number in set(ERRORS) - {4}:
            code, message = ERRORS[number]
            self.assertIn(code + ': ' + message, messages)

    def test_returned_loan_origins_and_partial_task_composition(self):
        from tests import test_hia_composite_returned_loans as loans
        for mode in ('read', 'mut'):
            document = loans.pair_program(mode)
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_record_operation',
                    side_effect=AssertionError('host record called')):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))
            for flag in (False, True):
                report = execute_program(actual, 'probe', [1, 37, flag])
                self.assertEqual(report['result'], loans.expected(mode, 37))
                self.assertEqual((report['resources']['live_owners'], report['resources']['live_local_loans']), (0, 0))
        for factory, name, arguments, expected_value in [
            (partials.roundtrip_program, 'roundtrip', [13, False], 43),
            (partials.task_partial_program, 'partial_task', [13, 2], 33),
            (partials.nested_record_program, 'nested', [13], 27)]:
            document = factory()
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_record_operation',
                    side_effect=AssertionError('host record called')):
                actual = verify_core(document)
            self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
            self.assertEqual(execute_program(actual, name, arguments)['result'], expected_value)

    def test_wide_aliases_zero_width_fields_and_exact_slot_boundary(self):
        long = lambda prefix: prefix + 'x' * (128 - len(prefix))
        fields = [(long('f' + str(index)), 'u32') for index in range(64)]
        types = [fixtures.record('Chunk', fields), fixtures.record('Wide', [('c' + str(i), 'Chunk') for i in range(8)])]
        document = fixtures.module(types, f('wide', [('input', 'u32')], ['u32'], [], [
            b('entry', [('input', 'u32')], [
                fixtures.i('record.make', ['input'] * 64, [('chunk', 'Chunk')]),
                fixtures.i('record.make', ['chunk'] * 8, [('wide', 'Wide')]),
                fixtures.i('record.get', ['wide'], [('last', 'Chunk')], field='c7'),
                fixtures.i('record.unpack', ['last'], [('out' + str(i), 'u32') for i in range(64)]),
            ], fixtures.ret('out63'))]))
        with patch.dict(os.environ, {SELECTOR: ''}):
            expected = verify_core(document)
        with self.selected(), patch.object(composite._Elaborator, '_reference_record_operation',
                side_effect=AssertionError('host record called')):
            actual = verify_core(document)
        self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
        self.assertEqual(execute_program(actual, 'wide', [37])['result'], 37)
        for zero_width in (True, False):
            typ = 'Empty' if zero_width else 'u32'
            ops = ([fixtures.i('record.make', [], [('item', 'Empty')])] if zero_width else
                   [fixtures.c('item', 'u32', 37)])
            ops += [fixtures.i('record.make', ['item'] * 15000, [('result', 'Empty')])]
            wide = fixtures.module([fixtures.record('Empty', [])], f('bad', [], [], [], [b('entry', [], ops, fixtures.ret())]))
            with patch.dict(os.environ, {SELECTOR: ''}):
                _, expected = outcome(lambda: verify_core(wide))
            with self.selected():
                _, actual = outcome(lambda: verify_core(wide))
            self.assertEqual(actual, expected)
            self.assertEqual(actual[0], 'E_HIA_TYPE')
        for count, code in [(32765, 'E_HIA_TYPE'), (32766, 'E_HIA_LIMIT')]:
            wide = fixtures.module([fixtures.record('Box', [('value', 'u32')])],
                f('bad', [('input', 'u32')], ['u32'], [], [b('entry', [('input', 'u32')], [
                    fixtures.i('record.make', ['input'], [('box', 'Box')]),
                    fixtures.i('record.get', ['box'], [('extra', 'u32')], field='value'),
                    fixtures.i('record.unpack', ['box'], [('out' + str(i), 'u32') for i in range(count)]),
                ], fixtures.ret('extra'))]))
            with patch.dict(os.environ, {SELECTOR: ''}):
                _, expected = outcome(lambda: verify_core(wide))
            with self.selected():
                _, actual = outcome(lambda: verify_core(wide))
            self.assertEqual(actual, expected)
            self.assertEqual(actual[0], code)

    def test_independent_hia_vm_matches_actual_image_for_empty_and_continued_results(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        owner = composite._Elaborator(scalar_program())
        empty, pair = owner.types.resolve('Empty'), owner.types.resolve('Pair')
        scalar = owner.types.resolve('u32')
        value = composite._Value(scalar, ('input',))
        pair_value = composite._Value(pair, ('input', 'input'), external=True)
        contexts = [RecordPacket('record.make', [], {}, [], [('empty', empty)], 8192),
                    RecordPacket('record.make', ['input', 'input'], {}, [value, value], [('out', pair)], 8192),
                    RecordPacket('record.get', ['pair'], {'field': 'missing'}, [pair_value], [('out', scalar)], 17)]
        for operation in ('record.get', 'record.unpack'):
            attrs = {'field': 'right'} if operation == 'record.get' else {}
            outputs = [('right', scalar)] if operation == 'record.get' else [('left', scalar), ('right', scalar)]
            for phase in (0, 1):
                context = RecordPacket(operation, ['pair'], attrs, [pair_value], outputs, 8192)
                if phase:
                    context.outputs = [[name, context.type_ref(typ)] for name, typ in outputs]
                    context.phase = phase
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

    def test_native_types_enum_and_match_compose_without_selected_host_owners(self):
        from tests import test_hia_composite_types_native as type_tests
        from tests import test_hia_enum_operations_native as enum_tests
        from tests import test_hia_enum_match_native as match_tests
        from hepta.hia_composite_types_native import SELECTOR as TYPE_SELECTOR
        from hepta.hia_enum_operations_native import SELECTOR as ENUM_SELECTOR
        from hepta.hia_enum_match_native import SELECTOR as MATCH_SELECTOR
        prepared = {}
        for tests, implementation, selector in [(type_tests, type_tests.CompositeTypesNativeTests, TYPE_SELECTOR),
                (enum_tests, enum_tests.EnumOperationsNativeTests, ENUM_SELECTOR),
                (match_tests, match_tests.EnumMatchNativeTests, MATCH_SELECTOR)]:
            fixture = type('SupportingFixture', (unittest.TestCase,), {})
            self.addCleanup(fixture.doClassCleanups)
            extra = {}
            if os.environ.get(COLD_REPORT) and not os.environ.get(tests.COLD_REPORT):
                extra[tests.COLD_REPORT] = os.environ[COLD_REPORT]
            with patch.dict(os.environ, extra):
                implementation.setUpClass.__func__(fixture)
            prepared[selector] = str(fixture.manifest)
        prepared[SELECTOR] = str(self.manifest)
        for document in (scalar_program(), fixtures.stored_loan_program(), external_loan_program(),
                         fixtures.task_program(), partials.task_partial_program()):
            with patch.dict(os.environ, {key: '' for key in prepared}):
                expected = verify_core(document)
            with patch.dict(os.environ, prepared), patch.object(composite, '_Types',
                    side_effect=AssertionError('host type owner called')), patch.object(
                    composite._Elaborator, '_reference_record_operation', side_effect=AssertionError('host record called')), patch.object(
                    composite._Elaborator, '_reference_enum_operation', side_effect=AssertionError('host enum called')), patch.object(
                    composite._Elaborator, '_reference_match', side_effect=AssertionError('host match called')):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))

    def test_real_machine_allocator_failure_alias_and_cleanup(self):
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        cc = shutil.which('cc'); self.assertIsNotNone(cc)
        driver = r'''
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live; static size_t allocations, frees, refusals; static bool refuse;
void *__wrap_calloc(size_t n,size_t w){
  if(refuse){refuse=false;refusals++;return NULL;}
  void *p=__real_calloc(n,w);if(p){if(live)exit(80);live=p;allocations++;}return p;
}
void __wrap_free(void *p){if(p){if(live!=p)exit(81);live=NULL;frees++;}__real_free(p);}
size_t record_case(size_t);
int main(void){
  if(record_case(7)!=24 || record_case(0)!=17)return 82;
  refuse=true;if(record_case(7)!=17 || refuse || live)return 83;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=1 || frees!=1 || refusals!=1;
}
'''
        with self.selected(), patch.object(composite._Elaborator, '_reference_record_operation',
                side_effect=AssertionError('host record called')):
            checked = verify_core(resource_program())
        obj = self.folder / 'record-effects.o'
        compile_program_machine(emit_program_machine(checked), program=checked, output=obj, kind='object', linker=cc)
        source, executable = self.folder / 'record-effects.c', self.folder / 'record-effects'
        source.write_text(driver)
        built = subprocess.run([cc, '-std=c11', '-O2', str(source), str(obj),
            '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(executable)], capture_output=True, timeout=30)
        self.assertEqual((ran.returncode, ran.stdout, ran.stderr), (0, b'1 1 1\n', b''))

    def test_private_bounds_depth_canaries_and_concurrent_calls(self):
        from concurrent.futures import ThreadPoolExecutor
        from hepta.hia_instruction_policy_native import transport
        owner = composite._Elaborator(scalar_program()); typ = owner.types.resolve('Empty')
        context = RecordPacket('record.make', [], {}, [], [('empty', typ)], 8192)
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

    def test_installed_wheel_custody_without_authoring_or_reference_fallback(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/record_operations.hiaasm', NATIVE_SOURCE_FILES)
        source = self.folder / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        names = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES
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
            raise AssertionError('installed record operations imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_record_operations_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host record called')
composite._Elaborator._reference_record_operation=absent
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
        for factory in (scalar_program, resource_program, external_loan_program, partial_get_program):
            document = factory(); data.write_bytes(wire(document))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/record_operations.hiaasm'
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
