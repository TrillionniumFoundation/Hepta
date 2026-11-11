"""Stateful native nominal types, ordinary normalization and installed custody."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
import ctypes
from hashlib import sha256
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
import weakref
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_composite_types_native import (SOURCE, SCHEMA, SELECTOR, MAGIC, ORIGINS_MAGIC,
    HEADER_BYTES, MAX_COMMAND_BYTES, OUTPUT_BYTES, SESSION_BYTES, PRIMITIVES, ERRORS,
    NativeCompositeTypes, NativeCompositeTypeSession, _NativeTypeIdentity,
    installed_composite_types)
from hepta.hia_schema import (COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2,
    COMPOSITE_SCHEMA_V3, COMPOSITE_SCHEMA_V4, composite_core_schema)
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partial_fixtures
from tests import test_hia_composite_returned_loans as loan_fixtures
from tests import test_hia_composite_v6_resources as resource_fixtures
from tests.test_hia_program import b, f, ret

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_COMPOSITE_TYPES_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST'
ReferenceTypes = composite._Types
record, enum, ref = fixtures.record, fixtures.enum, fixtures.ref
partial = partial_fixtures.partial


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def descriptor(identifier, kind, name, *, args=(), flat=(), fields=(), variants=(),
               state=None, result=None, poll=None, cancel=None, linear=False, base=None):
    return dict(id=identifier, kind=kind, name=name, args=list(args), flat=list(flat),
        fields=[list(x) for x in fields], variants=list(variants), state=state,
        result=result, poll=poll, cancel=cancel, linear=linear, record=base)


def primitive_descriptors():
    return [descriptor(index, 'primitive', name, flat=[index], linear=index >= 13)
            for index, name in enumerate(PRIMITIVES, 1)]


def frame(types=(), *, result=0, error=0, cached=0, active=0, steps=0):
    payload = wire({'types': list(types)})
    return struct.pack('<8Q', MAGIC, error, result, len(payload), cached, active, steps, 0) + payload


def synthetic_image(frames, calls=None):
    """Only adapter negative controls; no claim that these are HIA programs."""
    image = object.__new__(NativeCompositeTypes)
    pending = iter(frames)
    def entry(source, size, output, capacity, workspace, workspace_size):
        if calls is not None:
            calls.append((json.loads(ctypes.string_at(source, size)), ctypes.addressof(workspace)))
        data = next(pending)
        if isinstance(data, int):
            return data
        ctypes.memmove(output, data, len(data))
        return len(data)
    image._entry = entry
    return image


def interpreted(commands):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    checked = assemble_program(SOURCE.read_bytes())
    output = _Owner(-2, bytearray(OUTPUT_BYTES))
    workspace = _Owner(-3, bytearray(SESSION_BYTES))
    results = []
    for command in commands:
        raw = wire(command)
        source = _Owner(-1, bytearray(raw))
        machine = _Machine(checked, 20_000_000, 256 << 20, None, 256)
        code = machine.invoke(checked.as_dict()['functions'][0],
            [_View(source, False), _View(output, True), _View(workspace, True)])[0]
        assert bytes(source.data) == raw
        results.append(bytes(output.data[:code]) if HEADER_BYTES <= code <= OUTPUT_BYTES else code)
    return results


def native_key(session, identifier, memo):
    """Bounded test-only display of a native identity for the old independent oracle."""
    if identifier in memo:
        return memo[identifier]
    item = session._descriptors[identifier]
    if item['kind'] == 'primitive':
        value = item['name']
    elif item['kind'] == 'partial_record':
        value = ('partial<' + native_key(session, item['record'], memo) + ';'
                 + ','.join(name for name, _ in item['fields']) + '>')
    else:
        value = item['name'] + '<' + ','.join(native_key(session, x, memo) for x in item['args']) + '>'
    if len(value) > 65536:
        raise AssertionError('this independent display oracle is only for bounded small keys')
    memo[identifier] = value
    return value


def snapshot(typ, session=None):
    nodes, keys = {}, {}
    def key(value):
        return value.key if session is None else native_key(session, session._ids[id(value)], keys)
    pending = [typ]
    while pending:
        value = pending.pop()
        name = key(value)
        if name in nodes:
            continue
        references = [child for _, child in value.fields]
        references += [child for _, fields in value.variants for _, child in fields]
        references += [child for child in (value.state, value.result, value.record) if child is not None]
        nodes[name] = {'kind': value.kind, 'flat': value.flat, 'linear': value.linear,
            'fields': tuple((field, key(child)) for field, child in value.fields),
            'variants': tuple((variant, tuple((field, key(child)) for field, child in fields))
                              for variant, fields in value.variants),
            'state': None if value.state is None else key(value.state),
            'result': None if value.result is None else key(value.result),
            'record': None if value.record is None else key(value.record),
            'poll': value.poll, 'cancel': value.cancel}
        pending.extend(references)
    return key(typ), nodes


def observation(reference):
    return {'cache_count': len(getattr(reference, 'cache', {})),
            'active_count': len(getattr(reference, 'active', set())),
            'partial_declaration_steps': getattr(reference, 'partial_declaration_steps', 0)}


class CompositeTypesAdapterTests(unittest.TestCase):
    def test_partial_arena_allocation_releases_the_first_buffer_and_keeps_error(self):
        allocate = ctypes.create_string_buffer
        allocated = []
        failure = MemoryError('second native type arena allocation refused')
        calls = 0
        def allocation(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise failure
            result = allocate(*args, **kwargs)
            allocated.append(weakref.ref(result))
            return result
        session = object.__new__(NativeCompositeTypeSession)
        with patch('hepta.hia_composite_types_native.ctypes.create_string_buffer', allocation):
            try:
                NativeCompositeTypeSession.__init__(session, synthetic_image([]), [])
            except MemoryError as error:
                self.assertIs(error, failure)
            else:
                self.fail('allocation failure was swallowed')
        self.assertEqual(calls, 2)
        self.assertTrue(session._closed)
        self.assertIsNone(session._output)
        self.assertIsNone(session._state)
        self.assertEqual([ref() for ref in allocated], [None])

    def test_development_fixture_cannot_override_requested_cold_qualification(self):
        with patch.dict(os.environ, {DEVELOPMENT_MANIFEST: '/unread-development-manifest',
                                     COLD_REPORT: '/unread-cold-report'}), patch(
                'tempfile.TemporaryDirectory', side_effect=AssertionError('fixture work began before gate')):
            with self.assertRaisesRegex(AssertionError, 'development manifest cannot override'):
                CompositeTypesNativeTests.setUpClass()

    def test_forward_DAG_materialization_repeated_identity_and_native_counters(self):
        calls = []
        child = descriptor(18, 'record', 'Child', flat=[13], fields=[('owner', 13)], linear=True)
        parent = descriptor(17, 'record', 'Parent', flat=[13, 13],
                            fields=[('first', 18), ('second', 18)], linear=True)
        image = synthetic_image([frame(primitive_descriptors()),
            frame([parent, child], result=17, cached=2),
            frame(result=17, cached=2), frame(error=25, cached=2, active=1, steps=32769),
            frame(result=17, cached=2, active=1, steps=32769)], calls)
        with image.session([]) as types:
            value = types.resolve('Parent')
            self.assertIs(value.fields[0][1], value.fields[1][1])
            self.assertEqual(value.flat, ('buffer', 'buffer'))
            self.assertIs(value, types.resolve('Parent'))
            with self.assertRaisesRegex(HIAProgramRejected, 'partial declaration analysis budget exceeded'):
                types.resolve('Bad')
            self.assertEqual(types.observations, dict(cache_count=2, active_count=1,
                                                     partial_declaration_steps=32769))
            self.assertIs(value, types.resolve('Parent'))
        self.assertEqual(len({address for _, address in calls}), 1)
        self.assertEqual([call['op'] for call, _ in calls], ['init', 'resolve', 'resolve', 'resolve', 'resolve'])

    def test_session_identity_cannot_alias_or_reinterpret_another_session_base(self):
        typ = descriptor(17, 'record', 'Empty')
        images = [synthetic_image([frame(primitive_descriptors()), frame([typ], result=17, cached=1)])
                  for _ in range(2)]
        with images[0].session([]) as left, images[1].session([]) as right:
            a, z = left.resolve('Empty'), right.resolve('Empty')
            self.assertNotEqual(a.key, z.key)
            self.assertIsInstance(a.key, _NativeTypeIdentity)
            with self.assertRaisesRegex(HIAProgramRejected, 'does not belong to this session'):
                right.partial_record(a, [])

    def test_malformed_native_frames_descriptors_and_fatal_statuses_never_fall_back(self):
        bad = [b'bad', 0xfffffff0, 0xfffffff1, 0xfffffff2,
               frame(result=99), frame(error=999), frame(error=25, result=1),
               frame([descriptor(17, 'record', 'Cycle', fields=[('self', 17)])], result=17),
               frame([descriptor(17, 'record', 'Unknown', fields=[('missing', 88)])], result=17),
               frame([descriptor(1, 'record', 'Wrong')], result=1)]
        for malformed in bad:
            with self.subTest(frame=repr(malformed)[:100]):
                image = synthetic_image([frame(primitive_descriptors()), malformed])
                with image.session([]) as types:
                    with self.assertRaises(HIAProgramRejected):
                        types.resolve('anything')
                    with self.assertRaisesRegex(HIAProgramRejected, 'failed transport'):
                        types.resolve('anything')


class CompositeTypesSourceTests(unittest.TestCase):
    def test_checked_in_source_reproduces_and_transport_error_table_matches(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools import generate_hia_composite_types as author
        self.assertEqual(SOURCE.read_text(), render_assembly(author.document()))
        self.assertEqual(ERRORS, author.ERRORS)
        self.assertEqual(ORIGINS_MAGIC, author.ORIGINS_MAGIC)
        self.assertEqual(PRIMITIVES, author.PRIMITIVES)
        self.assertEqual((OUTPUT_BYTES, SESSION_BYTES), (author.OUTPUT_BYTES, author.WORKSPACE_BYTES))
        self.assertEqual(MAX_COMMAND_BYTES, author.MAX_COMMAND_BYTES)
        checked = assemble_program(SOURCE.read_bytes())
        self.assertGreater(len(checked.as_dict()['functions']), 1)

    def test_independent_VM_persistent_resolution_partial_and_refusal(self):
        commands = [dict(op='init', definitions=[record('Pair', [('owner', 'buffer'), ('count', 'u8')])],
                         recursive_chain=True, partial_records=True),
                    dict(op='resolve', ref='Pair'),
                    dict(op='resolve', ref=partial('Pair', 'count')),
                    dict(op='resolve', ref=partial('Pair', 'absent'))]
        frames = interpreted(commands)
        self.assertTrue(all(type(value) is bytes for value in frames))
        image = synthetic_image(frames)
        with image.session(commands[0]['definitions'], recursive_chain=True, partial_records=True) as types:
            reference = ReferenceTypes(commands[0]['definitions'], recursive_chain=True, partial_records=True)
            for expression in ['Pair', partial('Pair', 'count')]:
                self.assertEqual(snapshot(reference.resolve(expression)), snapshot(types.resolve(expression), types))
                self.assertEqual(types.observations, observation(reference))
            with self.assertRaises(HIAProgramRejected) as caught:
                types.resolve(partial('Pair', 'absent'))
            self.assertEqual(caught.exception.code, 'E_HIA_INIT')


class CompositeTypesNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('a development manifest cannot override requested cold qualification')
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-composite-types-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
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
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='composite-types')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder)
            compiler_source = SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, compiler_source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, compiler_source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'composite-types', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_composite_types(str(cls.manifest))

    def test_public_elaboration_closes_owned_arenas_on_success_and_all_refusal_stages(self):
        original = NativeCompositeTypeSession.__init__
        sessions = []
        retained_errors = []
        def observe(session, *args, **kwargs):
            sessions.append(session)
            return original(session, *args, **kwargs)
        good = fixtures.enum_owner_program()
        lower = copy.deepcopy(good)
        lower['functions'][0]['blocks'] = []
        types = copy.deepcopy(good)
        types['types'] = None
        owner = copy.deepcopy(good)
        owner['functions'] = []
        for document in (good, lower, types, owner):
            with self.subTest(stage=('success' if document is good else
                                    'types' if document is types else
                                    'owner' if document is owner else 'lower')):
                with patch('hepta.hia_composite_types_native.selected_composite_types', return_value=None):
                    try:
                        expected = composite.elaborate_program(document)
                    except HIAProgramRejected as error:
                        expected = (error.code, str(error))
                before = len(sessions)
                with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                        NativeCompositeTypeSession, '__init__', observe):
                    try:
                        actual = composite.elaborate_program(document)
                    except HIAProgramRejected as error:
                        retained_errors.append(error)
                        actual = (error.code, str(error))
                self.assertEqual(actual, expected)
                self.assertEqual(len(sessions), before + 1)
                session = sessions[-1]
                self.assertTrue(session._closed)
                self.assertIsNone(session._output)
                self.assertIsNone(session._state)
        self.assertEqual(len(retained_errors), 3)
        self.assertTrue(all(error.__traceback__ is not None for error in retained_errors))
        # Private callers still own a usable session after construction/lower.
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            private = composite._Elaborator(good)
        try:
            self.assertFalse(private.native_types._closed)
            self.assertEqual(private.types.resolve('u8').flat, ('u8',))
        finally:
            private.native_types.close()

    def test_actual_native_init_interruption_releases_arenas_and_preserves_exception(self):
        original = self.native._entry
        failure = KeyboardInterrupt('after actual native type initialization')
        def interrupted(*args):
            original(*args)
            raise failure
        session = object.__new__(NativeCompositeTypeSession)
        with patch.object(self.native, '_entry', interrupted):
            try:
                NativeCompositeTypeSession.__init__(session, self.native, [])
            except KeyboardInterrupt as error:
                self.assertIs(error, failure)
            else:
                self.fail('native callback interruption was swallowed')
        self.assertTrue(session._closed)
        self.assertIsNone(session._output)
        self.assertIsNone(session._state)

    @contextmanager
    def paired(self, definitions, **flags):
        reference = object.__new__(ReferenceTypes)
        actual = object.__new__(NativeCompositeTypeSession)
        errors = []
        try:
            for owner, initialize in [(reference, lambda: ReferenceTypes.__init__(reference, definitions, **flags)),
                    (actual, lambda: NativeCompositeTypeSession.__init__(actual, self.native, definitions, **flags))]:
                try:
                    initialize()
                except HIAProgramRejected as error:
                    errors.append(error)
                else:
                    errors.append(None)
            self.assertEqual(None if errors[0] is None else errors[0].code,
                             None if errors[1] is None else errors[1].code)
            self.assertEqual(actual.observations, observation(reference))
            for text in ('partial declaration analysis budget exceeded',
                         'symbolic type argument nesting exceeds budget'):
                if errors[0] is not None and text in str(errors[0]):
                    self.assertIn(text, str(errors[1]))
            yield reference, actual, errors[0]
        finally:
            if hasattr(actual, '_lock'):
                actual.close()

    def compare(self, reference, actual, expected_call, actual_call):
        results, errors = [], []
        for call in (expected_call, actual_call):
            try:
                results.append(call())
            except HIAProgramRejected as error:
                results.append(None)
                errors.append(error.code)
            else:
                errors.append(None)
        self.assertEqual(errors[0], errors[1])
        self.assertEqual(actual.observations, observation(reference))
        if not errors[0]:
            self.assertEqual(snapshot(results[0]), snapshot(results[1], actual))
        return results, errors[0]

    def test_primitives_versions_and_nominal_chain_name_keep_original_meaning(self):
        for recursive, partials in [(False, False), (True, False), (True, True)]:
            with self.paired([], recursive_chain=recursive, partial_records=partials) as (old, new, error):
                self.assertIsNone(error)
                for name in PRIMITIVES:
                    self.compare(old, new, lambda name=name: old.resolve(name), lambda name=name: new.resolve(name))
                self.assertEqual(new.observations['cache_count'], 0)
        with self.paired([record('chain', [])]) as (old, new, error):
            self.assertIsNone(error)
            self.compare(old, new, lambda: old.resolve('chain'), lambda: new.resolve('chain'))
        with self.paired([record('chain', [])], recursive_chain=True) as (_, _, error):
            self.assertEqual(error.code, 'E_HIA_TYPE')

    def test_unused_invalid_declarations_error_order_and_lazy_loans(self):
        cases = [None, [None], [{'kind': False}], [{'kind': 'unknown'}],
            [record('Bad', [('x', 'missing')])], [record('Bad', [('x', 'u8'), ('x', 'u16')])],
            [record('same', []), record('same', [])], [record('__hia_bad', [])],
            [record('h2internal_bad', [])], [record('Self', [('x', 'Self')])],
            [record('A', [('b', 'B')]), record('B', [('a', 'A')])],
            [record('G', [], ['T', 'T'])], [record('G', [], ['u8'])],
            [enum('E', [])], [enum('E', [('same', []), ('same', [])])],
            [record('Base', [('read', 'readbuf')]), record('Unused', [('p', partial('Base'))])]]
        for definitions in cases:
            with self.subTest(definitions=repr(definitions)[:140]):
                with self.paired(definitions, recursive_chain=True, partial_records=True) as (_, _, error):
                    self.assertIsNotNone(error)
        definitions = [enum('LoanEnum', [('loan', [('view', 'readbuf')])]),
            {'name': 'LoanTask', 'params': [], 'kind': 'task', 'state': 'readbuf',
             'result': 'u8', 'poll': 'poller', 'cancel': 'cancel'}]
        with self.paired(definitions, partial_records=True) as (old, new, error):
            self.assertIsNone(error)  # The resolver alone does not eagerly instantiate every enum/task.
            for expression in ['LoanEnum', 'LoanEnum', 'LoanTask', 'LoanTask']:
                self.compare(old, new, lambda: old.resolve(expression), lambda: new.resolve(expression))

    def test_stateful_cache_exact_128_boundary_and_partial_transition(self):
        fields = [('f' + str(index), 'u8') for index in range(8)]
        with self.paired([record('Many', fields)], partial_records=True) as (old, new, _):
            bases, error = self.compare(old, new, lambda: old.resolve('Many'), lambda: new.resolve('Many'))
            self.assertIsNone(error)
            for mask in range(128):
                initialized = [name for index, (name, _) in enumerate(fields) if mask & (1 << index)]
                _, error = self.compare(old, new,
                    lambda: old.partial_record(bases[0], initialized),
                    lambda: new.partial_record(bases[1], initialized))
                self.assertEqual(error, 'E_HIA_LIMIT' if mask == 127 else None)
            self.assertEqual(new.observations['cache_count'], 128)
            self.compare(old, new, lambda: old.partial_record(bases[0], []),
                         lambda: new.partial_record(bases[1], []))
            self.compare(old, new, lambda: old.resolve('u8'), lambda: new.resolve('u8'))
        # Equal erased layouts with distinct generic arguments remain distinct identities.
        with self.paired([record('Phantom', [], ['A', 'B'])], recursive_chain=True) as (old, new, _):
            for index in range(129):
                expression = ref('Phantom', PRIMITIVES[index // 16], PRIMITIVES[index % 16])
                self.compare(old, new, lambda: old.resolve(expression), lambda: new.resolve(expression))
            self.assertEqual(new.observations['cache_count'], 128)

    def test_lexical_symbolic_bindings_and_stateful_known_loan_budget(self):
        definitions = [record('Id', [('value', 'T')], ['T']),
            record('Outer', [('value', ref('Id', 'T'))], ['T']),
            record('Constraint', [('state', partial(ref('Outer', 'U')))], ['U'])]
        with self.paired(definitions, partial_records=True) as (old, new, error):
            self.assertIsNone(error)
            for argument in ['u8', 'buffer', 'readbuf', 'mutbuf']:
                expression = ref('Constraint', argument)
                self.compare(old, new, lambda: old.resolve(expression), lambda: new.resolve(expression))
        known = definitions + [record('Unused', [('state', partial(ref('Outer', 'readbuf')))], ['U'])]
        with self.paired(known, partial_records=True) as (_, _, error):
            self.assertEqual(error.code, 'E_HIA_LOAN')
        nested = 'U'
        for _ in range(8):
            nested = ref('Repeated', nested)
        repeated = [record('Repeated', [('f' + str(i), 'T') for i in range(4)], ['T']),
                    record('Unused', [('state', partial(nested))], ['U'])]
        with self.paired(repeated, partial_records=True) as (old, new, error):
            self.assertIsNone(error)
            self.assertEqual(new.observations['partial_declaration_steps'], 272)
            self.compare(old, new, lambda: old.resolve(ref('Unused', 'u8')),
                         lambda: new.resolve(ref('Unused', 'u8')))
        distinct = [record('Wrap' + str(i), [('value', 'T')], ['T']) for i in range(4)]
        for level in range(6):
            distinct.append(record('Level' + str(level), [
                ('f' + str(i), ref('Level' + str(level + 1), ref('Wrap' + str(i), 'T')))
                for i in range(4)], ['T']))
        distinct += [record('Level6', [('value', 'T')], ['T']),
                     record('Unused', [('state', partial(ref('Level0', 'U')))], ['U'])]
        with self.paired(distinct, partial_records=True) as (_, new, error):
            self.assertEqual(error.code, 'E_HIA_LIMIT')
            self.assertIn('partial declaration analysis budget exceeded', str(error))
            self.assertEqual(new.observations, dict(cache_count=0, active_count=0,
                                                     partial_declaration_steps=32769))
        nested = 'T'
        for _ in range(25):
            nested = ref('Wrap', nested)
        lexical = [record('Wrap', [('value', 'T')], ['T'])]
        lexical += [record('Layer' + str(level), [('value', ref('Layer' + str(level + 1), nested))], ['T'])
                    for level in range(3)]
        lexical += [record('Layer3', [('value', 'T')], ['T']),
                    record('Unused', [('state', partial(ref('Layer0', 'U')))], ['U'])]
        with self.paired(lexical, partial_records=True) as (_, new, error):
            self.assertEqual(error.code, 'E_HIA_LIMIT')
            self.assertIn('symbolic type argument nesting exceeds budget', str(error))
            self.assertEqual(new.observations['partial_declaration_steps'], 157)
        concrete = [record('Pair', [('x', 'buffer'), ('y', 'u8')]),
                    record('Unused', [('state', partial('Pair'))])]
        with self.paired(concrete, partial_records=True) as (_, new, error):
            self.assertIsNone(error)
            self.assertEqual(new.observations, dict(cache_count=2, active_count=0,
                                                     partial_declaration_steps=2))

    def test_bounded_random_layouts_and_concurrent_private_sessions(self):
        def compare_case(seed):
            rng = random.Random(seed)
            definitions = [record('Empty', []), record('Pair', [('left', 'T'), ('right', 'U')], ['T', 'U'])]
            expressions = ['u8', 'usize', 'buffer', 'readbuf', 'Empty']
            for index in range(5):
                name = 'R' + str(index)
                definitions.append(record(name, [('f' + str(j), rng.choice(expressions))
                                                  for j in range(rng.randrange(4))]))
                expressions.append(name)
                expressions.append(ref('Pair', rng.choice(expressions), rng.choice(expressions)))
            with self.paired(definitions, recursive_chain=True, partial_records=True) as (old, new, error):
                self.assertIsNone(error)
                for expression in expressions:
                    self.compare(old, new, lambda: old.resolve(expression), lambda: new.resolve(expression))
        with ThreadPoolExecutor(max_workers=3) as executor:
            list(executor.map(compare_case, range(36)))

    def test_ordinary_four_versions_exact_normalized_bytes_without_host_type_owner(self):
        programs = []
        for factory in [fixtures.stored_loan_program, fixtures.enum_owner_program,
                        fixtures.task_program, fixtures.scalar_task_program, fixtures.owned_result_task_program]:
            for schema in [COMPOSITE_SCHEMA, COMPOSITE_SCHEMA_V2, COMPOSITE_SCHEMA_V3, COMPOSITE_SCHEMA_V4]:
                document = factory(); document['schema'] = schema; programs.append(document)
        programs.extend(factory() for factory in [partial_fixtures.roundtrip_program,
            partial_fixtures.nested_record_program, partial_fixtures.task_partial_program,
            partial_fixtures.chain_partial_program, resource_fixtures.composite_bulk_program,
            resource_fixtures.composite_range_task_program, loan_fixtures.pair_program,
            loan_fixtures.task_program, loan_fixtures.direct_downgrade_program])
        for index, document in enumerate(programs):
            with self.subTest(index=index, schema=document['schema']):
                with patch.dict(os.environ, {SELECTOR: ''}):
                    expected = verify_core(document)
                with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                        composite, '_Types', side_effect=AssertionError('host type resolver called')):
                    actual = verify_core(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))

    def test_existing_partial_rejections_symbolic_limits_and_frozen_fingerprints(self):
        suite = unittest.TestSuite()
        for test_class in [fixtures.CompositeRejectionTests, partial_fixtures.PartialRecordRejectionTests,
                           partial_fixtures.PartialRecordCompatibilityTests]:
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(test_class))
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                composite, '_Types', side_effect=AssertionError('host type resolver called')):
            result = unittest.TestResult()
            suite.run(result)
        self.assertFalse(result.errors + result.failures,
                         '\n'.join(str(test) + '\n' + message for test, message in result.errors + result.failures))
        self.assertFalse(result.skipped)
        self.assertGreater(result.testsRun, 30)

    def test_full_Core_byte_boundary_preserves_earlier_declaration_diagnostic(self):
        from hepta.hia_program import MAX_BYTES, MAX_NODES, MAX_DEPTH
        self.assertEqual((MAX_BYTES, MAX_NODES, MAX_DEPTH), (8 << 20, 262144, 64))
        entered = []
        native_entry = self.native._entry
        def observe_entry(source, size, *buffers):
            entered.append(size)
            return native_entry(source, size, *buffers)
        # The root shape/schema/module are admitted before nominal types. An
        # invalid functions value must not move a type-shape diagnostic behind
        # a private transport cap. The scalar case has the maximum +5 bytes.
        cases = [(version, []) for version in range(1, 5)] + [(1, 0)]
        for version, functions in cases:
            with self.subTest(version=version, functions=functions):
                definition = dict(kind='record', name='A', params=[], fields=[], extra='')
                document = dict(schema='hepta.hia.composite.v' + str(version),
                                module='m', types=[definition], functions=functions)
                definition['extra'] = 'x' * (MAX_BYTES - len(wire(document)))
                self.assertEqual(len(wire(document)), MAX_BYTES)
                with patch.dict(os.environ, {SELECTOR: ''}):
                    with self.assertRaises(HIAProgramRejected) as reference:
                        verify_core(document)
                self.assertEqual(reference.exception.code, 'E_HIA_FORMAT')
                before = len(entered)
                with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                        composite, '_Types', side_effect=AssertionError('host resolver called')), patch.object(
                        self.native, '_entry', side_effect=observe_entry):
                    with self.assertRaises(HIAProgramRejected) as actual:
                        verify_core(document)
                self.assertEqual(actual.exception.code, reference.exception.code)
                self.assertEqual(len(entered), before + 1)
                self.assertGreater(entered[-1], MAX_BYTES)
                self.assertLessEqual(entered[-1], MAX_COMMAND_BYTES)
                expected_extra = 5 if type(functions) is int else 4 - (version >= 2) - (version >= 3)
                self.assertEqual(entered[-1] - MAX_BYTES, expected_extra)
        # The allowance never changes public Core admission itself.
        definition['extra'] += 'x'
        before = len(entered)
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                composite, '_Types', side_effect=AssertionError('host resolver called')), patch.object(
                self.native, '_entry', side_effect=observe_entry):
            with self.assertRaises(HIAProgramRejected) as oversized:
                verify_core(document)
        self.assertEqual(oversized.exception.code, 'E_HIA_LIMIT')
        self.assertEqual(len(entered), before)

    def test_zero_width_generic_key_DAG_is_bounded_and_never_enters_public_JSON(self):
        definitions = [record('Empty', []), record('Join', [], ['A', 'B'])]
        for index in range(28):
            definitions.append(record('Layer' + str(index),
                [('next', ref('Layer' + str(index + 1), ref('Join', 'T', 'T')))], ['T']))
        definitions.append(record('Layer28', [], ['T']))
        expression = ref('Layer0', 'Empty')
        document = partial_fixtures.v3(definitions,
            f('identity', [('value', expression)], [expression], [],
              [b('entry', [('value', expression)], [], ret('value'))]))
        # Expanding the old display key would take gigabytes. The independent
        # expected primitive program has no value slots or instructions.
        expected = {'schema': composite_core_schema(COMPOSITE_SCHEMA_V3), 'module': document['module'],
            'exports': [], 'functions': [f('identity', [], [], [], [b('entry', [], [], ret())])]}
        expected = verify_core(expected).canonical_bytes
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                composite, '_Types', side_effect=AssertionError('host type resolver called')):
            self.assertEqual(verify_core(document).canonical_bytes, expected)
        with self.native.session(definitions, recursive_chain=True, partial_records=True) as types:
            value = types.resolve(expression)
            self.assertEqual(value.flat, ())
            self.assertIsInstance(value.key, _NativeTypeIdentity)
            self.assertLess(len(types._descriptors), 100)
            self.assertIs(value, types.resolve(expression))

    def test_native_ABI_bounds_duplicate_JSON_and_private_session_canaries(self):
        source = ctypes.create_string_buffer(wire(dict(op='init', definitions=[],
                    recursive_chain=True, partial_records=True)))
        output = ctypes.create_string_buffer(OUTPUT_BYTES + 16)
        state = ctypes.create_string_buffer(SESSION_BYTES + 16)
        for buffer in (output, state):
            ctypes.memmove(ctypes.addressof(buffer), b'BEFORE!!', 8)
            ctypes.memmove(ctypes.addressof(buffer) + len(buffer) - 8, b'!!AFTER!', 8)
        for output_size, state_size in [(OUTPUT_BYTES - 1, SESSION_BYTES), (OUTPUT_BYTES, SESSION_BYTES - 1)]:
            code = self.native._entry(source, len(source.value), ctypes.byref(output, 8), output_size,
                                      ctypes.byref(state, 8), state_size)
            self.assertEqual(code, 0xfffffff0)
        duplicate = b'{"op":"init","op":"resolve"}'
        raw = ctypes.create_string_buffer(duplicate)
        code = self.native._entry(raw, len(duplicate), ctypes.byref(output, 8), OUTPUT_BYTES,
                                  ctypes.byref(state, 8), SESSION_BYTES)
        self.assertEqual(code, 0xfffffffc)
        for buffer in (output, state):
            self.assertEqual(ctypes.string_at(ctypes.addressof(buffer), 8), b'BEFORE!!')
            self.assertEqual(ctypes.string_at(ctypes.addressof(buffer) + len(buffer) - 8, 8), b'!!AFTER!')

    def test_selected_source_and_manifest_fail_closed_even_after_warm_loading(self):
        document = fixtures.enum_owner_program()
        for selected in [self.folder / 'missing-manifest.json', self.folder / 'bad-manifest.json']:
            if selected.name.startswith('bad-'):
                selected.write_bytes(b'{}')
            with patch.dict(os.environ, {SELECTOR: str(selected)}), patch.object(
                    composite, '_Types', side_effect=AssertionError('fallback type resolver called')):
                with self.assertRaises(HIAProgramRejected):
                    verify_core(document)
        local_source = self.folder / 'changed-source.hiaasm'
        local_source.write_bytes(SOURCE.read_bytes())
        with patch('hepta.hia_composite_types_native.SOURCE', local_source):
            installed_composite_types(str(self.manifest))
            local_source.write_bytes(local_source.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
                installed_composite_types(str(self.manifest))

    def test_real_installed_wheel_ordinary_normalization_and_source_manifest_image_pins(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/composite_types.hiaasm', resources)
        source = self.folder / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        wheels = self.folder / 'wheels'
        result = subprocess.run([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
            '--wheel-dir', str(wheels), str(source)], cwd=source, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        wheel, = wheels.glob('*.whl')
        installed = self.folder / 'installed'
        result = subprocess.run([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=self.folder, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = loan_fixtures.task_program()
        with patch.dict(os.environ, {SELECTOR: ''}):
            expected = verify_core(document).canonical_bytes
        data = self.folder / 'installed-input.json'; data.write_bytes(wire(document))
        child = '''import sys,importlib.abc,json
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed nominal resolver imported checkout tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import HIAProgramRejected,verify_core
from hepta.hia_composite_types_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host nominal type owner called')
composite._Types=absent
composite._Elaborator.loan_origins=absent
composite._Elaborator._reference_parameters=absent
composite._Elaborator._reference_check_task=absent
try:result=verify_core(Path(sys.argv[2]).read_bytes())
except HIAProgramRejected:
    if sys.argv[3]=='refuse':print('REFUSED')
    else:raise
else:
    assert sys.argv[3]=='accept','bad installed native custody accepted'
    sys.stdout.buffer.write(result.canonical_bytes)
'''
        def run(mode, manifest=self.manifest):
            return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
                str(installed), str(data), mode], cwd=self.folder, capture_output=True, timeout=30,
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(manifest)})
        result = run('accept')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/composite_types.hiaasm'
        original = resource.read_bytes()
        for missing in (False, True):
            try:
                resource.unlink() if missing else resource.write_bytes(original + b'\n')
                result = run('refuse')
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
            finally:
                resource.write_bytes(original)
        bad = self.folder / 'installed-bad-manifest.json'; bad.write_bytes(b'{}')
        result = run('refuse', bad)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
        manifest_value = json.loads(self.manifest.read_bytes())
        image = self.manifest.parent / manifest_value['image_path']
        original_image = image.read_bytes()
        try:
            image.write_bytes(original_image[:-1] + bytes([original_image[-1] ^ 1]))
            result = run('refuse')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
        finally:
            image.write_bytes(original_image)


if __name__ == '__main__':
    unittest.main()
