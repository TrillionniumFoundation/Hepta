"""Native enum construction/tag, exact partial effects and independent owners."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
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
from hepta.hia_enum_operations_native import (SOURCE, SCHEMA, SELECTOR, MAGIC,
    ERRORS, INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, EnumPacket,
    NativeEnumOperations, installed_enum_operations, selected_enum_operations)
from tests import test_hia_program_composite as fixtures
from tests.test_hia_program import b, f

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_ENUM_OPERATIONS_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_ENUM_OPERATIONS_DEVELOPMENT_MANIFEST'


def wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(',', ':')).encode()


def outcome(call):
    try:
        return call(), None
    except HIAProgramRejected as error:
        return None, (error.code, str(error))


def tag_program(variant='empty'):
    types = [fixtures.enum('Choice', [('empty', []), ('scalar', [('n', 'u32')])])]
    arguments = [] if variant == 'empty' else ['input']
    return fixtures.module(types, f('tagged', [('input', 'u32')], ['u32'], [], [
        b('entry', [('input', 'u32')], [
            fixtures.i('enum.make', arguments, [('value', 'Choice')], variant=variant),
            fixtures.i('enum.tag', ['value'], [('tag', 'u32')]),
        ], fixtures.ret('tag'))]))


def padding_program():
    fields = [('flag', 'bool'), ('nothing', 'unit'), ('integer', 'i64'),
              ('owner', 'buffer'), ('chain', 'chain')]
    types = [fixtures.enum('Choice', [('empty', []), ('full', fields)])]
    document = fixtures.module(types, f('padding', [], ['u32'], ['alloc', 'trap'], [
        b('entry', [], [fixtures.i('enum.make', [], [('value', 'Choice')], variant='empty'),
            fixtures.i('enum.tag', ['value'], [('tag', 'u32')])],
            fixtures.match('value', ('empty', 'empty', ['tag']), ('full', 'full', ['tag']))),
        b('empty', [('empty_tag', 'u32')], [], fixtures.ret('empty_tag')),
        b('full', fields + [('full_tag', 'u32')], [
            fixtures.i('owner.drop', ['owner']), fixtures.i('owner.drop', ['chain'])],
            fixtures.ret('full_tag'))]))
    document['schema'] = 'hepta.hia.composite.v4'
    return document


class EnumOperationsSourceTests(unittest.TestCase):
    def test_generator_matches_source_and_unchanged_native_profile(self):
        from tools import generate_hia_enum_operations as generator
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

    def test_selected_missing_image_never_calls_reference(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_enum_operations())
        with patch.dict(os.environ, {SELECTOR: '/missing-enum-operations-manifest'}), patch.object(
                composite._Elaborator, '_reference_enum_operation', side_effect=AssertionError('host enum called')):
            with self.assertRaises(HIAProgramRejected):
                verify_core(tag_program())

    def test_packet_preserves_nominal_identity_and_repeated_value_aliases(self):
        class ForbiddenKey:
            def __str__(self):
                raise AssertionError('transport expanded nominal display identity')
            def __hash__(self):
                raise AssertionError('transport hashed semantic identity')
            def __eq__(self, other):
                raise AssertionError('transport compared semantic identity')
        record = composite._Type(ForbiddenKey(), 'record', ())
        typ = composite._Type(ForbiddenKey(), 'enum', ('u32',),
            variants=(('pair', (('a', record), ('b', record))),))
        actual = composite._Value(record, ())
        context = EnumPacket('enum.make', ['source', 'source'], {'variant': 'pair'},
                             [actual, actual], [('out', typ)], 0)
        self.assertIs(type(context.data()), bytes)
        self.assertEqual(len(context.values), 1)
        self.assertEqual(len(context.types), 2)
        self.assertEqual(context.arguments, [['source', 0], ['source', 0]])


class EnumOperationsAdapterTests(unittest.TestCase):
    def context(self, operation='enum.make', phase=0):
        scalar = composite._Type('u32', 'primitive', ('u32',))
        typ = composite._Type('Choice<>', 'enum', ('u32',), variants=(('empty', ()),))
        value = composite._Value(typ, ('tag',))
        context = EnumPacket(operation, ['value'] if operation == 'enum.tag' else [],
            {} if operation == 'enum.tag' else {'variant': 'empty'},
            [value] if operation == 'enum.tag' else [], [('out', typ)], 3)
        context.data()
        if phase:
            context.expected = context.type_ref(scalar)
            context.tag_declared = [('out', context.type_ref(scalar))]
            if phase == 2:
                context.bound = context.type_ref(scalar)
        context.phase = phase
        return context

    def frame(self, context, *, error=0, serial=None, request=0, payload=None,
              magic=MAGIC, reserved=0):
        if payload is None:
            payload = {'ops': [], 'consumed': [item.consumed for item in context.values],
                       'values': [] if error or request else [['out', 0, ['tag'], False, False]]}
        raw = wire(payload)
        return struct.pack('<8Q', magic, error, context.serial if serial is None else serial,
                           request, len(raw), reserved, 0, 0) + raw

    def image(self, data, *, mutate=False):
        image = object.__new__(NativeEnumOperations)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate:
                ctypes.memmove(source, b'x', 1)
            if type(data) is int:
                return data
            ctypes.memmove(output, data, len(data))
            return len(data)
        image._entry = entry
        return image

    def test_invalid_frames_and_partial_state_envelopes_fail_closed(self):
        context = self.context()
        invalid = [0, 0xfffffff1, self.frame(context, magic=0),
            self.frame(context, reserved=1), self.frame(context, error=99),
            self.frame(context, serial=2), self.frame(context, serial=8193),
            self.frame(context, error=1), self.frame(context, request=1),
            self.frame(context, payload={'ops': [], 'consumed': [], 'values': []}),
            self.frame(context, payload={'ops': [], 'consumed': [0], 'values': []}),
            self.frame(context, payload={'ops': [], 'consumed': [], 'values': [], 'plan': []}),
            self.frame(context, error=4, payload={'ops': [], 'consumed': [],
                'values': [['out', 0, ['tag'], False, False]]})]
        for frame in invalid:
            with self.subTest(frame=repr(frame)[:80]), self.assertRaises(HIAProgramRejected):
                self.image(frame).step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'input bytes changed'):
            self.image(self.frame(context), mutate=True).step(context)

    def test_tag_cannot_skip_repeat_or_mutate_continuation(self):
        for phase in range(3):
            context = self.context('enum.tag', phase)
            valid_request = phase + 1 if phase < 2 else 0
            for request in set(range(3)) - {valid_request}:
                with self.subTest(phase=phase, request=request), self.assertRaises(HIAProgramRejected):
                    self.image(self.frame(context, request=request)).step(context)
            with self.assertRaises(HIAProgramRejected):
                self.image(self.frame(context, serial=4, request=valid_request)).step(context)
            if valid_request:
                payload = {'ops': [], 'consumed': [True], 'values': []}
                with self.assertRaises(HIAProgramRejected):
                    self.image(self.frame(context, request=valid_request, payload=payload)).step(context)


class EnumOperationsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development enum operations cannot override cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-enum-operations-')
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
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='enum-operations')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'enum-operations', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_enum_operations(str(cls.manifest))

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def compare_at_operations(self, document, *, variations=None,
                              serials=(0, 8188, 8189, 8190, 8191, 8192)):
        """Run the unchanged branch and image against real admitted closures.

        Compare first errors, partial Core, aliases/consumption, bound types,
        and calls to the preceding type owner, even after failing mid-padding.
        """
        case, observations = self, []
        reference = composite._Elaborator._reference_enum_operation
        selected = composite._Elaborator.lower_enum_operation

        def compare(owner, ins, actual, declared, env, ops, consume, outputs):
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
                trace, resolved = [], []
                resolve, parameters = owner.types.resolve, owner.parameters
                def tracked_resolve(*args, **kwargs):
                    trace.append(('resolve', deepcopy(args), deepcopy(kwargs)))
                    result = resolve(*args, **kwargs); resolved.append(result)
                    return result
                def tracked_parameters(value):
                    trace.append(('parameters', deepcopy(value)))
                    return parameters(value)
                with patch.object(owner.types, 'resolve', side_effect=tracked_resolve), patch.object(
                        owner, 'parameters', side_effect=tracked_parameters):
                    _, error = outcome(call)
                snapshot = {name: (item.typ, item.names, item.external, item.consumed)
                            for name, item in env.items()}
                if error is None and ins['op'] == 'enum.tag':
                    added = [value for name, value in env.items() if name not in initial_env]
                    if added:
                        case.assertIs(added[0].typ, resolved[-1])
                return error, owner.serial, deepcopy(current_ops), snapshot, trace

            for changed, values, declarations in choices:
                for serial in serials:
                    restore(); owner.serial = serial
                    reference_ops = list(ops)
                    expected = observed(lambda: reference(owner, changed, values, declarations,
                        env, reference_ops, consume, outputs), reference_ops)
                    restore(); owner.serial = serial
                    native_ops = list(ops)
                    with patch('hepta.hia_enum_operations_native.selected_enum_operations', return_value=case.native):
                        native = observed(lambda: selected(owner, changed, values, declarations,
                            env, native_ops, consume, outputs), native_ops)
                    case.assertEqual(native, expected, (changed, serial))
                    observations.append((changed['op'], expected[0], serial, expected[1],
                                         len(reference_ops) - len(ops)))
            restore(); owner.serial = initial_serial
            return reference(owner, ins, actual, declared, env, ops, consume, outputs)

        with patch.object(composite._Elaborator, 'lower_enum_operation', compare):
            _, original_error = outcome(lambda: verify_core(document))
        self.assertTrue(observations, 'fixture must reach an actual enum operation')
        return observations, original_error

    def test_all_versions_exact_core_and_independent_execution(self):
        for version in range(1, 5):
            for factory, name, args, answers in [
                (fixtures.enum_owner_program, 'choose', [(False, 0), (True, 7), (False, 7)], [10, 7, 17]),
                (tag_program, 'tagged', [(0,), (0xffffffff,)], [0, 0]),
                (lambda: tag_program('scalar'), 'tagged', [(37,), (0xffffffff,)], [1, 1])]:
                document = factory(); document['schema'] = 'hepta.hia.composite.v' + str(version)
                with patch.dict(os.environ, {SELECTOR: ''}):
                    expected = verify_core(document)
                with self.selected(), patch.object(composite._Elaborator, '_reference_enum_operation',
                        side_effect=AssertionError('host enum called')):
                    actual = verify_core(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))
                self.assertEqual(actual.as_dict()['schema'], 'hepta.hia.program.v' + str(6 if version == 1 else 8 if version == 4 else 7))
                for arguments, answer in zip(args, answers):
                    self.assertEqual(execute_program(actual, name, arguments)['result'], answer)

    def test_first_errors_partial_core_consumption_and_type_owner_call_order(self):
        def variations(owner, ins, actual, declared):
            result = []
            attrs = ([{}, {'variant': True}, {'variant': ''}, {'variant': '__hia_reserved'},
                      {'variant': 'h2internal_9'}, {'variant': 'unlisted'},
                      {'variant': ins['attrs']['variant'], 'extra': 1}]
                     if ins['op'] == 'enum.make' else [{'extra': 1}])
            for value in attrs:
                changed = deepcopy(ins); changed['attrs'] = value
                result.append((changed, actual, declared))
            if ins['op'] == 'enum.make':
                result += [(deepcopy(ins), actual, []),
                    (deepcopy(ins), actual, [('wrong', owner.types.resolve('u32'))]),
                    (deepcopy(ins), actual, [*declared, *declared])]
            else:
                for outputs in [[], [{'name': 'wrong', 'type': 'bool'}],
                                [{'name': 'wrong', 'type': 'missing'}]]:
                    changed = deepcopy(ins); changed['out'] = outputs
                    result.append((changed, actual, declared))
            return result
        observations = []
        for document in [fixtures.enum_owner_program(), tag_program(), padding_program(), fixtures.task_program()]:
            rows, error = self.compare_at_operations(document, variations=variations)
            self.assertIsNone(error)
            observations += rows
        self.assertTrue({'E_HIA_FORMAT', 'E_HIA_NAME', 'E_HIA_TYPE', 'E_HIA_LIMIT'} <=
                        {row[1][0] for row in observations if row[1]})
        self.assertTrue(any(row[1] and row[1][0] == 'E_HIA_LIMIT' and row[4] > 0 for row in observations))

    def test_duplicate_linear_argument_preserves_consumed_prefix(self):
        types = [fixtures.enum('Choice', [('pair', [('a', 'buffer'), ('b', 'buffer')])])]
        document = fixtures.module(types, f('bad', [('owner', 'buffer')], [], ['alloc'], [
            b('entry', [('owner', 'buffer')], [
                fixtures.i('enum.make', ['owner', 'owner'], [('value', 'Choice')], variant='pair')],
              fixtures.ret())]))
        rows, error = self.compare_at_operations(document)
        self.assertEqual(error, ('E_HIA_RESOURCE', 'E_HIA_RESOURCE: use of consumed nominal value'))
        self.assertTrue(all(row[1] == error and row[2] == row[3] and row[4] == 0 for row in rows))

    def test_public_bad_inputs_preserve_first_refusal_and_nominal_identity(self):
        cases = []
        for index, key, value in [
            (0, 'attrs', {}), (0, 'out', []),
            (0, 'out', [{'name': 'value', 'type': 'u32'}]),
            (0, 'attrs', {'variant': True}), (0, 'attrs', {'variant': 'h2internal_9'}),
            (0, 'attrs', {'variant': 'missing'}), (0, 'args', ['input']),
            (0, 'args', ['undefined']), (1, 'attrs', {'extra': 1}),
            (1, 'args', []), (1, 'args', ['input']), (1, 'args', ['value', 'value']),
            (1, 'out', [{'name': 'tag', 'type': 'bool'}]),
            (1, 'out', [{'name': 'tag', 'type': 'missing'}]),
        ]:
            document = tag_program()
            document['functions'][0]['blocks'][0]['ops'][index][key] = value
            cases.append(document)
        wrong_scalar = tag_program('scalar')
        wrong_scalar['functions'][0]['params'][0]['type'] = 'bool'
        wrong_scalar['functions'][0]['blocks'][0]['params'][0]['type'] = 'bool'
        cases.append(wrong_scalar)
        types = [fixtures.record('A', [('n', 'u32')]), fixtures.record('B', [('n', 'u32')]),
                 fixtures.enum('Choice', [('one', [('payload', 'A')])])]
        cases.append(fixtures.module(types, f('wrong', [('b', 'B')], [], [], [
            b('entry', [('b', 'B')], [fixtures.i('enum.make', ['b'], [('value', 'Choice')], variant='one')],
              fixtures.ret())])))
        messages = set()
        for document in cases:
            with patch.dict(os.environ, {SELECTOR: ''}):
                _, expected = outcome(lambda: verify_core(document))
            with self.selected(), patch.object(composite._Elaborator, '_reference_enum_operation',
                    side_effect=AssertionError('host enum called')):
                _, actual = outcome(lambda: verify_core(document))
            self.assertIsNotNone(expected)
            self.assertEqual(actual, expected)
            messages.add(actual[1])
        for code in (3, 4, 5, 6, 7, 9, 10, 11):
            error, message = ERRORS[code]
            self.assertIn(error + ': ' + message, messages)

    def test_private_inactive_loan_refusal_and_exact_mid_buffer_names(self):
        def variants(owner, ins, actual, declared):
            if ins['op'] != 'enum.make':
                return []
            original = declared[0][1]
            selected = ins['attrs']['variant']
            result = []
            for loan_name in ('readbuf', 'mutbuf'):
                loan = owner.types.resolve(loan_name)
                changed = tuple((name, fields if name == selected else (('loan', loan),))
                                for name, fields in original.variants)
                typ = replace(original, flat=('u32',) + tuple(p for _, fields in changed
                    for _, child in fields for p in child.flat), variants=changed)
                result.append((deepcopy(ins), actual, [(declared[0][0], typ)]))
            return result
        rows, error = self.compare_at_operations(fixtures.enum_owner_program(), variations=variants)
        self.assertIsNone(error)
        self.assertIn('E_HIA_LOAN', {row[1][0] for row in rows if row[1]})
        self.assertTrue(any(row[1] and row[1][0] == 'E_HIA_LOAN' and row[4] == 1 for row in rows))

    def test_large_repeated_zero_width_and_scalar_inputs_do_not_reduce_public_limits(self):
        for zero_width, count in [(True, 15000), (False, 15000)]:
            types = [fixtures.record('Empty', []), fixtures.enum('Choice', [('empty', [])])]
            ops = ([fixtures.i('record.make', [], [('item', 'Empty')])] if zero_width else
                   [fixtures.c('item', 'u32', 37)])
            ops += [fixtures.i('enum.make', ['item'] * count, [('value', 'Choice')], variant='empty')]
            document = fixtures.module(types, f('wide', [], [], [], [b('entry', [], ops, fixtures.ret())]))
            with patch.dict(os.environ, {SELECTOR: ''}):
                _, expected = outcome(lambda: verify_core(document))
            with self.selected(), patch.object(composite._Elaborator, '_reference_enum_operation',
                    side_effect=AssertionError('host enum called')):
                _, actual = outcome(lambda: verify_core(document))
            self.assertEqual(actual, expected)
            self.assertEqual(actual, ('E_HIA_TYPE', 'E_HIA_TYPE: enum payload differs from selected variant'))
        document = tag_program()
        document['types'].append(fixtures.record('Empty', []))
        document['functions'][0]['blocks'][0]['ops'][-1]['out'] = [
            {'name': 'out' + str(i), 'type': 'Empty'} for i in range(15000)]
        with patch.dict(os.environ, {SELECTOR: ''}):
            _, expected = outcome(lambda: verify_core(document))
        with self.selected(), patch.object(composite._Elaborator, '_reference_enum_operation',
                side_effect=AssertionError('host enum called')):
            _, actual = outcome(lambda: verify_core(document))
        self.assertEqual(actual, expected)
        self.assertEqual(actual, ('E_HIA_TYPE', 'E_HIA_TYPE: nominal output type/arity mismatch'))

    def test_independent_hia_vm_matches_native_bytes_for_make_and_tag_phases(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        owner = composite._Elaborator(tag_program())
        typ, scalar = owner.types.resolve('Choice'), owner.types.resolve('u32')
        value = composite._Value(typ, ('source_tag', 'source_payload'))
        contexts = [EnumPacket('enum.make', [], {'variant': 'empty'}, [], [('out', typ)], serial)
                    for serial in (0, 8191, 8192)]
        tag = EnumPacket('enum.tag', ['value'], {}, [value], [('tag', scalar)], 17)
        contexts.append(tag)
        phase1 = EnumPacket('enum.tag', ['value'], {}, [value], [('tag', scalar)], 17)
        phase1.expected = phase1.type_ref(scalar)
        phase1.tag_declared = [('tag', phase1.type_ref(scalar))]; phase1.phase = 1
        contexts.append(phase1)
        phase2 = EnumPacket('enum.tag', ['value'], {}, [value], [('tag', scalar)], 17)
        phase2.expected = phase2.type_ref(scalar)
        phase2.tag_declared = [('tag', phase2.type_ref(scalar))]
        phase2.bound = phase2.type_ref(scalar); phase2.phase = 2
        contexts.append(phase2)
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

    def test_maximum_layout_long_names_and_scalar_output_slot_boundary(self):
        def long_name(prefix):
            return prefix + 'x' * (128 - len(prefix))
        variants = [(long_name('v' + str(index)),
                     [(long_name('f' + str(field)), 'u32') for field in
                      range(0 if index == 0 else 31 if index == 31 else 16)])
                    for index in range(32)]
        self.assertEqual(1 + sum(len(fields) for _, fields in variants), 512)
        item, enum_value, tag = map(long_name, ('input', 'value', 'tag'))
        for selected in (0, 1, 15, 31):
            name, fields = variants[selected]
            document = fixtures.module([fixtures.enum('Choice', variants)],
                f('wide', [(item, 'u32')], ['u32'], [], [
                    b('entry', [(item, 'u32')], [
                        fixtures.i('enum.make', [item] * len(fields), [(enum_value, 'Choice')], variant=name),
                        fixtures.i('enum.tag', [enum_value], [(tag, 'u32')])], fixtures.ret(tag))]))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_enum_operation',
                    side_effect=AssertionError('host enum called')):
                actual = verify_core(document)
            self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
            self.assertEqual(execute_program(actual, 'wide', [37])['result'], selected)
        for count, code in [(32765, 'E_HIA_TYPE'), (32766, 'E_HIA_LIMIT')]:
            document = tag_program()
            document['functions'][0]['blocks'][0]['ops'][-1]['out'] = [
                {'name': 'out' + str(index), 'type': 'u32'} for index in range(count)]
            with patch.dict(os.environ, {SELECTOR: ''}):
                _, expected = outcome(lambda: verify_core(document))
            with self.selected(), patch.object(composite._Elaborator, '_reference_enum_operation',
                    side_effect=AssertionError('host enum called')):
                _, actual = outcome(lambda: verify_core(document))
            self.assertEqual(actual, expected)
            self.assertEqual(actual[0], code)

    def test_native_type_session_and_match_compose_without_reference_owners(self):
        from tests import test_hia_composite_types_native as type_tests
        from tests import test_hia_enum_match_native as match_tests
        from hepta.hia_composite_types_native import SELECTOR as TYPE_SELECTOR
        from hepta.hia_enum_match_native import SELECTOR as MATCH_SELECTOR
        class TypeFixture(unittest.TestCase):
            pass
        class MatchFixture(unittest.TestCase):
            pass
        for fixture, tests, implementation in [(TypeFixture, type_tests, type_tests.CompositeTypesNativeTests),
                                               (MatchFixture, match_tests, match_tests.EnumMatchNativeTests)]:
            self.addCleanup(fixture.doClassCleanups)
            extra = {}
            if os.environ.get(COLD_REPORT) and not os.environ.get(tests.COLD_REPORT):
                extra[tests.COLD_REPORT] = os.environ[COLD_REPORT]
            with patch.dict(os.environ, extra):
                implementation.setUpClass.__func__(fixture)
        for document in (fixtures.enum_owner_program(), tag_program('scalar'), padding_program(), fixtures.task_program()):
            with patch.dict(os.environ, {SELECTOR: '', TYPE_SELECTOR: '', MATCH_SELECTOR: ''}):
                expected = verify_core(document)
            with patch.dict(os.environ, {SELECTOR: str(self.manifest), TYPE_SELECTOR: str(TypeFixture.manifest),
                                         MATCH_SELECTOR: str(MatchFixture.manifest)}), patch.object(
                    composite, '_Types', side_effect=AssertionError('host type owner called')), patch.object(
                    composite._Elaborator, '_reference_enum_operation', side_effect=AssertionError('host enum called')), patch.object(
                    composite._Elaborator, '_reference_match', side_effect=AssertionError('host match called')):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))

    def test_native_effects_use_real_allocator_and_free(self):
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        cc = shutil.which('cc')
        self.assertIsNotNone(cc)
        driver = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live[16]; static size_t allocations, frees, refusals; static bool refuse;
void *__wrap_calloc(size_t n,size_t w){
  if(refuse){refuse=false;refusals++;return NULL;}
  void *p=__real_calloc(n,w);if(p){for(size_t i=0;i<16;i++)if(!live[i]){live[i]=p;allocations++;return p;}exit(80);}return p;
}
void __wrap_free(void *p){
  if(p){size_t i;for(i=0;i<16 && live[i]!=p;i++);if(i==16)exit(81);live[i]=NULL;frees++;}__real_free(p);
}
size_t choose(uint8_t,size_t);
int main(void){
  for(size_t flag=0;flag<2;flag++){
    if(choose(flag,7)!=7+(flag?0:10))return 82;
    refuse=true;if(choose(flag,7)!=(flag?0:10) || refuse)return 83;
    if(choose(flag,0)!=(flag?0:10))return 84;
  }
  for(size_t i=0;i<16;i++)if(live[i])return 85;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=frees || refusals!=2;
}
'''
        with self.selected(), patch.object(composite._Elaborator, '_reference_enum_operation',
                side_effect=AssertionError('host enum called')):
            checked = verify_core(fixtures.enum_owner_program())
        object_file = self.folder / 'enum-effects.o'
        compile_program_machine(emit_program_machine(checked), program=checked,
                                output=object_file, kind='object', linker=cc)
        source, executable = self.folder / 'enum-effects.c', self.folder / 'enum-effects'
        source.write_text(driver)
        built = subprocess.run([cc, '-std=c11', '-O2', str(source), str(object_file),
            '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(executable)], capture_output=True, timeout=30)
        self.assertEqual((ran.returncode, ran.stderr), (0, b''), ran.stdout)
        self.assertEqual([int(value) for value in ran.stdout.split()], [2, 2, 2])

    def test_private_validation_short_regions_canaries_depth_and_concurrency(self):
        from concurrent.futures import ThreadPoolExecutor
        from hepta.hia_instruction_policy_native import transport
        owner = composite._Elaborator(tag_program())
        typ = owner.types.resolve('Choice')
        context = EnumPacket('enum.make', [], {'variant': 'empty'}, [], [('value', typ)], 0)
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

    def test_installed_wheel_has_custodied_source_and_no_authoring_or_reference_fallback(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/enum_operations.hepta', NATIVE_SOURCE_FILES)
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
            raise AssertionError('installed enum operations imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_enum_operations_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host enum called')
composite._Elaborator._reference_enum_operation=absent
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
        for factory in (fixtures.enum_owner_program, tag_program, padding_program):
            document = factory(); data.write_bytes(wire(document))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/enum_operations.hepta'
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
