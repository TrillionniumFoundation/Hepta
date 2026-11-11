"""Native parameter admission and complete nominal task-protocol relations.

The retained hosted methods are independent semantic oracles. Reusing an
existing compiler image is development evidence, never a fresh cold claim.
"""
from __future__ import annotations

from copy import deepcopy
import ctypes
import json
import os
import random
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_program import HIAProgramRejected, MAX_BYTES, verify_core
from hepta.hia_composite_types_native import (MAGIC, PARAMETERS_MAGIC, SOURCE, ERRORS,
    SELECTOR, OUTPUT_BYTES, SESSION_BYTES)
from tests import test_hia_composite_types_native as type_tests
from tests import test_hia_program_composite as fixtures
from tests import test_hia_composite_returned_loans as loans
from tests import test_hia_partial_record as partial_fixtures
from tests.test_hia_composite_types_native import (frame, descriptor, primitive_descriptors,
    synthetic_image, wire, snapshot, observation, record, enum, ref, partial)
from tests.test_hia_program import f, b, ret

REFERENCE_PARAMETERS = composite._Elaborator._reference_parameters
REFERENCE_TASK = composite._Elaborator._reference_check_task


def parameter_frame(params=(), types=(), *, error=0, count=None, cached=0, active=0,
                    steps=0, magic=PARAMETERS_MAGIC, envelope=None):
    payload = wire(dict(types=list(types), params=list(params)) if envelope is None else envelope)
    count = len(params) if count is None else count
    return struct.pack('<8Q', magic, error, count, len(payload), cached, active, steps, 0) + payload


def outcome(call):
    try:
        return call(), None
    except HIAProgramRejected as error:
        return None, error.code


def param(name, typ):
    return dict(name=name, type=typ)


def task_def(*, state='State', result='u8', poll='poller', cancel='cancel'):
    return dict(name='Job', params=[], kind='task', state=state, result=result,
                poll=poll, cancel=cancel)


class CompositeSignaturesAdapterTests(unittest.TestCase):
    def test_parameter_refusal_materializes_prior_native_types_and_keeps_state(self):
        item = descriptor(17, 'record', 'Empty')
        image = synthetic_image([frame(primitive_descriptors()),
            parameter_frame(types=[item], error=46, cached=1),
            parameter_frame([['x', 17], ['p', 14]], cached=1)])
        with image.session([]) as session:
            with self.assertRaisesRegex(HIAProgramRejected, 'duplicate nominal parameter'):
                session.parameters([param('x', 'Empty'), param('x', 'u8')])
            self.assertIn(17, session._types)
            self.assertEqual(session.observations, dict(cache_count=1, active_count=0,
                                                       partial_declaration_steps=0))
            result = session.parameters([param('x', 'Empty'), param('p', 'readbuf')])
            self.assertIs(result[0][1], session._types[17])

    def test_parameter_result_transport_refuses_bad_frames_and_unknown_types(self):
        bad = [parameter_frame([['x', 7]], magic=MAGIC), parameter_frame([['x', 7]], count=0),
            parameter_frame([['x', 7]], count=1, error=46), parameter_frame(error=37),
            parameter_frame([['x', 99]]), parameter_frame([['x', True]]),
            parameter_frame([['x', 7, 8]]), parameter_frame([[None, 7]]),
            parameter_frame(envelope={'types': [], 'params': [], 'extra': 1})]
        for data in bad:
            with self.subTest(frame=repr(data)[:100]):
                image = synthetic_image([frame(primitive_descriptors()), data])
                with image.session([]) as session:
                    with self.assertRaises(HIAProgramRejected):
                        session.parameters([param('x', 'u8')])
                    with self.assertRaisesRegex(HIAProgramRejected, 'failed transport'):
                        session.resolve('u8')

    def test_task_protocol_cannot_change_descriptors_counters_or_use_foreign_types(self):
        task = descriptor(17, 'task', 'Job', flat=[7, 13, 7, 7], state=7, result=7,
                          poll='poller', cancel='cancel', linear=True)
        step = descriptor(18, 'enum', 'Step', flat=[9, 7, 7], variants=[
            ['pending', [['state', 7]]], ['ready', [['value', 7]]]])
        initial = frame([*primitive_descriptors(), task, step], cached=2)
        for malformed in [frame(result=18, cached=3), frame(result=18, cached=2, active=1),
            frame(result=18, cached=2, steps=1), frame(error=46, cached=2),
            frame([descriptor(19, 'record', 'Extra')], result=18, cached=2)]:
            with synthetic_image([initial, malformed]).session([]) as session:
                with self.assertRaises(HIAProgramRejected):
                    session.check_task(session._types[17], {})
                with self.assertRaisesRegex(HIAProgramRejected, 'failed transport'):
                    session.resolve('u8')
        with synthetic_image([initial]).session([]) as first, synthetic_image([initial]).session([]) as second:
            with self.assertRaisesRegex(HIAProgramRejected, 'does not belong'):
                first.check_task(second._types[17], {})


class CompositeSignaturesNativeTests(unittest.TestCase):
    setUpClass = classmethod(type_tests.CompositeTypesNativeTests.setUpClass.__func__)
    paired = type_tests.CompositeTypesNativeTests.paired

    def compare_parameters(self, old, new, value):
        saved = deepcopy(value)
        expected, old_error = outcome(lambda: REFERENCE_PARAMETERS(SimpleNamespace(types=old), value))
        actual, new_error = outcome(lambda: new.parameters(value))
        self.assertEqual(new_error, old_error, value)
        self.assertEqual(new.observations, observation(old))
        self.assertEqual(value, saved)
        if old_error is None:
            self.assertEqual([name for name, _ in actual], [name for name, _ in expected])
            for (_, before), (_, after) in zip(expected, actual):
                self.assertEqual(snapshot(before), snapshot(after, new))
        return actual, old_error

    def test_parameter_shape_name_duplicate_resolution_order_and_partial_state(self):
        definitions = [record('Empty', []), record('Owned', [('owner', 'buffer'), ('value', 'u8')]),
            record('Pair', [('left', 'T'), ('right', 'U')], ['T', 'U']),
            record('Unused', [('saved', partial('Owned', 'value'))]),
            enum('Bad', [('borrowed', [('view', 'readbuf')])])]
        cases = [None, False, 0, '', {}, [], [None], [{}],
            [dict(name='x', type='u8', extra=0)], [dict(name='x')],
            [param('', 'missing')], [param('__hia_bad', 'u8')], [param('h2internal_bad', 'u8')],
            [param('bad-name', 'missing')], [param(False, 'missing')],
            [param('x', 'u8'), param('x', 'missing')],
            [param('x', 'missing'), param('x', 'u8')],
            [param('x', 'Empty'), param('x', 'u8')],
            [param('state', partial('Owned', 'value')), param('state', 'missing')],
            [param('state', partial('Owned', 'value')), param('new', 'u8')],
            [param('g', ref('Pair', 'readbuf', 'mutbuf')), param('plain', 'Empty')],
            [param('bad', 'Bad')], [param('reader', 'readbuf')], [param('bad', 'Bad')]]
        with self.paired(definitions, recursive_chain=True, partial_records=True) as (old, new, error):
            self.assertIsNone(error)
            for value in cases:
                with self.subTest(value=value):
                    self.compare_parameters(old, new, value)
            self.assertGreater(new.observations['cache_count'], 0)
            self.assertGreater(new.observations['partial_declaration_steps'], 0)
            self.assertGreater(new.observations['active_count'], 0)
            self.compare_parameters(old, new, [param('still', 'Empty')])

    def test_parameter_alias_snapshot_and_error_does_not_return_a_partial_inventory(self):
        with self.native.session([]) as session:
            raw = [param('first', 'u8'), param('second', 'readbuf')]
            entry = self.native._entry
            def mutate(source, size, *buffers):
                before = ctypes.string_at(source, size)
                raw[0]['name'] = 'changed'
                raw[1]['type'] = 'missing'
                result = entry(source, size, *buffers)
                self.assertEqual(ctypes.string_at(source, size), before)
                return result
            with patch.object(self.native, '_entry', side_effect=mutate):
                actual = session.parameters(raw)
            self.assertEqual([(name, typ.key) for name, typ in actual], [('first', 'u8'), ('second', 'readbuf')])
            with self.assertRaises(HIAProgramRejected):
                session.parameters(raw)
            self.assertEqual(session.parameters([]), ())

    def test_parameter_cache_boundary_and_deterministic_mixed_histories(self):
        with self.paired([record('Phantom', [], ['A', 'B'])], recursive_chain=True,
                         partial_records=True) as (old, new, error):
            self.assertIsNone(error)
            primitives = type_tests.PRIMITIVES
            for index in range(128):
                self.compare_parameters(old, new, [param('x', ref('Phantom',
                    primitives[index // 16], primitives[index % 16]))])
            self.assertEqual(new.observations['cache_count'], 128)
            self.assertEqual(self.compare_parameters(old, new,
                [param('known', ref('Phantom', 'u8', 'u8')),
                 param('new', ref('Phantom', 'u32', 'u8'))])[1], 'E_HIA_LIMIT')
            self.compare_parameters(old, new, [param('known', ref('Phantom', 'u8', 'u8'))])
        definitions = [record('Empty', []), record('Pair', [('a', 'T'), ('b', 'U')], ['T', 'U'])]
        rng = random.Random(441887)
        expressions = ['u8', 'buffer', 'readbuf', 'Empty', 'missing',
                       ref('Pair', 'Empty', 'mutbuf'), ref('Pair', 'u8', 'u16')]
        with self.paired(definitions, recursive_chain=True, partial_records=True) as (old, new, _):
            for _ in range(96):
                value = [param(rng.choice(['x', 'y', 'z', 'bad-name']), rng.choice(expressions))
                         for _ in range(rng.randrange(5))]
                self.compare_parameters(old, new, value)

    def compare_task(self, definitions, signatures, *, job='Job'):
        with self.paired(definitions, recursive_chain=True, partial_records=True) as (old, new, error):
            self.assertIsNone(error)
            registries = []
            for types in (old, new):
                registries.append({name: (tuple(('p' + str(i), types.resolve(typ))
                    for i, typ in enumerate(params)), tuple(types.resolve(typ) for typ in returns))
                    for name, (params, returns) in signatures.items()})
            old_job, new_job = old.resolve(job), new.resolve(job)
            before = new.observations
            def checked(call):
                try:
                    return call(), None
                except HIAProgramRejected as refusal:
                    return None, (refusal.code, str(refusal))
            expected, left_error = checked(lambda: REFERENCE_TASK(SimpleNamespace(
                functions=dict.fromkeys(registries[0]), signatures=registries[0]), old_job))
            actual, right_error = checked(lambda: new.check_task(new_job, registries[1]))
            self.assertEqual(right_error, left_error)
            self.assertEqual(new.observations, before)
            if left_error is None:
                self.assertEqual(snapshot(expected), snapshot(actual, new))
                self.assertIs(actual, new.check_task(new_job, registries[1]))
            return None if left_error is None else left_error[0]

    def test_complete_task_protocol_missing_lookup_exact_ids_and_error_order(self):
        definitions = [record('State', [('value', 'u8')]), record('Other', [('value', 'u8')]),
            enum('Step', [('pending', [('s', 'State')]), ('ready', [('v', 'u8')])]), task_def()]
        good = {'poller': (['State'], ['Step']), 'cancel': (['State'], [])}
        self.assertIsNone(self.compare_task(definitions, good))
        cases = [({}, 'E_HIA_CALL'), ({'poller': ([], [])}, 'E_HIA_CALL'),
            ({'cancel': ([], ['u8'])}, 'E_HIA_CALL'),
            ({'poller': (['State'], ['u8']), 'cancel': ([], ['u8'])}, 'E_HIA_TYPE')]
        for key, signature in [('poller', ([], ['Step'])), ('poller', (['State', 'State'], ['Step'])),
                ('poller', (['Other'], ['Step'])), ('poller', (['State'], [])),
                ('poller', (['State'], ['Step', 'Step'])), ('poller', (['State'], ['u8'])),
                ('cancel', ([], [])), ('cancel', (['Other'], [])),
                ('cancel', (['State', 'State'], [])), ('cancel', (['State'], ['u8']))]:
            registry = dict(good); registry[key] = signature
            cases.append((registry, 'E_HIA_TYPE'))
        for signatures, expected in cases:
            with self.subTest(signatures=signatures):
                self.assertEqual(self.compare_task(definitions, signatures), expected)
        # Poll/cancel may name the same original function; the contradictory
        # return obligations still reject in the original checking order.
        definitions[-1] = task_def(poll='same', cancel='same')
        self.assertEqual(self.compare_task(definitions, {'same': (['State'], ['Step'])}), 'E_HIA_TYPE')

    def test_task_step_variant_order_payload_arity_and_nominal_identity(self):
        variants = [[('ready', [('answer', 'u8')]), ('pending', [('renamed', 'State')])],
            [('pending', [('s', 'State')])], [('pending', []), ('ready', [('v', 'u8')])],
            [('pending', [('s', 'State'), ('t', 'State')]), ('ready', [('v', 'u8')])],
            [('pending', [('s', 'Other')]), ('ready', [('v', 'u8')])],
            [('pending', [('s', 'State')]), ('ready', [('v', 'u16')])],
            [('waiting', [('s', 'State')]), ('ready', [('v', 'u8')])],
            [('pending', [('s', 'State')]), ('ready', [('v', 'u8')]), ('extra', [])]]
        for index, choices in enumerate(variants):
            with self.subTest(variants=choices):
                definitions = [record('State', []), record('Other', []), enum('Step', choices), task_def()]
                self.assertEqual(self.compare_task(definitions,
                    {'poller': (['State'], ['Step']), 'cancel': (['State'], [])}),
                    None if index == 0 else 'E_HIA_TYPE')
        definitions = [record('Phantom', [], ['T']),
            enum('Step', [('pending', [('s', ref('Phantom', 'u8'))]), ('ready', [('v', 'u8')])]),
            task_def(state=ref('Phantom', 'u8'))]
        self.assertEqual(self.compare_task(definitions,
            {'poller': ([ref('Phantom', 'u16')], ['Step']),
             'cancel': ([ref('Phantom', 'u8')], [])}), 'E_HIA_TYPE')

    def test_task_registry_1024_functions_and_snapshot_remain_native(self):
        definitions = [record('State', []), enum('Step', [
            ('ready', [('v', 'u8')]), ('pending', [('s', 'State')])]), task_def()]
        with self.native.session(definitions) as session:
            job, state, step = (session.resolve(name) for name in ('Job', 'State', 'Step'))
            signatures = {'unused' + str(i): ((), ()) for i in range(1022)}
            signatures['cancel'] = ((('state', state),), ())
            signatures['poller'] = ((('state', state),), (step,))
            before = session.observations
            native_entry = self.native._entry
            def mutate(source, size, *buffers):
                wire_before = ctypes.string_at(source, size)
                self.assertEqual(len(json.loads(wire_before)['functions']), 1024)
                signatures.clear()
                result = native_entry(source, size, *buffers)
                self.assertEqual(ctypes.string_at(source, size), wire_before)
                return result
            with patch.object(self.native, '_entry', side_effect=mutate):
                self.assertIs(session.check_task(job, signatures), step)
            self.assertEqual(session.observations, before)
            with self.assertRaisesRegex(HIAProgramRejected, 'missing function'):
                session.check_task(job, signatures)
            self.assertEqual(session.observations, before)

    def test_ordinary_all_versions_disable_host_parameters_tasks_types_and_origins(self):
        programs = []
        for factory in (fixtures.task_program, fixtures.scalar_task_program, fixtures.owned_result_task_program,
                        fixtures.stored_loan_program, fixtures.enum_owner_program):
            for schema in type_tests.COMPOSITE_SCHEMA, type_tests.COMPOSITE_SCHEMA_V2, type_tests.COMPOSITE_SCHEMA_V3, type_tests.COMPOSITE_SCHEMA_V4:
                value = factory(); value['schema'] = schema; programs.append(value)
        programs += [partial_fixtures.task_partial_program(), loans.task_program(), loans.pair_program('mut')]
        for document in programs:
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                    composite, '_Types', side_effect=AssertionError('host types called')), patch.object(
                    composite._Elaborator, '_reference_parameters', side_effect=AssertionError('host parameters called')),
                    patch.object(composite._Elaborator, '_reference_check_task', side_effect=AssertionError('host task protocol called')),
                    patch.object(composite._Elaborator, 'loan_origins', side_effect=AssertionError('host origins called'))):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))

    def test_parameter_private_framing_preserves_exact_public_byte_boundary(self):
        raw_param = dict(name='p', type='u8', extra='')
        document = loans.v4([], f('probe', [], [], [], [b('entry', [], [], ret())]))
        document['functions'][0]['params'] = [raw_param]
        raw_param['extra'] = 'x' * (MAX_BYTES - len(wire(document)))
        self.assertEqual(len(wire(document)), MAX_BYTES)
        with patch.dict(os.environ, {SELECTOR: ''}):
            with self.assertRaises(HIAProgramRejected) as expected:
                verify_core(document)
        entered, entry = [], self.native._entry
        def observe(source, size, *buffers):
            if ctypes.string_at(source, min(size, 20)).startswith(b'{"op":"parameters"'):
                entered.append(size)
            return entry(source, size, *buffers)
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                composite._Elaborator, '_reference_parameters', side_effect=AssertionError('host parameters called')),
                patch.object(self.native, '_entry', side_effect=observe)):
            with self.assertRaises(HIAProgramRejected) as actual:
                verify_core(document)
        self.assertEqual(actual.exception.code, expected.exception.code)
        self.assertEqual(actual.exception.code, 'E_HIA_FORMAT')
        self.assertEqual(len(entered), 1)
        self.assertLess(entered[0], MAX_BYTES)
        self.assertGreater(entered[0], MAX_BYTES - 1024)

    def test_task_raw_forged_ids_inventory_and_cross_session_refuse(self):
        definitions = [record('State', []), enum('Step', [
            ('pending', [('s', 'State')]), ('ready', [('v', 'u8')])]), task_def()]
        with self.native.session(definitions) as session:
            job, state, step = (session.resolve(name) for name in ('Job', 'State', 'Step'))
            jid, sid, eid = (session._ids[id(value)] for value in (job, state, step))
            good = dict(op='task_protocol', task=jid, functions=[['poller', [sid], [eid]], ['cancel', [sid], []]])
            commands = [dict(good, extra=1), dict(good, task=0), dict(good, task=7),
                dict(good, task=145), dict(good, task=True), dict(good, functions=None),
                dict(good, functions=[['poller', [sid], [eid]], ['poller', [sid], [eid]]]),
                dict(good, functions=[['poller', [145], [eid]], ['cancel', [sid], []]]),
                dict(good, functions=[['poller', [sid], [False]], ['cancel', [sid], []]]),
                dict(good, functions=[['poller', [sid], [eid], []]])]
            for command in commands:
                raw = wire(command); source = ctypes.create_string_buffer(raw)
                status = self.native._entry(source, len(raw), session._output, OUTPUT_BYTES,
                                           session._state, SESSION_BYTES)
                self.assertEqual(status, 0xfffffff1)
                self.assertEqual(ctypes.string_at(source, len(raw)), raw)
            registry = {'poller': ((('state', state),), (step,)), 'cancel': ((('state', state),), ())}
            self.assertIs(session.check_task(job, registry), step)
            with self.native.session(definitions) as other:
                with self.assertRaisesRegex(HIAProgramRejected, 'does not belong'):
                    other.check_task(job, registry)

    def test_source_and_tables_are_reproducible(self):
        from tools import generate_hia_composite_types as author
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(), render_assembly(author.document()))
        self.assertEqual(ERRORS, author.ERRORS)
        self.assertEqual(PARAMETERS_MAGIC, author.PARAMETERS_MAGIC)
        self.assertEqual(PARAMETERS_MAGIC, int.from_bytes(b'HIAPRM01', 'little'))
        self.assertNotEqual(PARAMETERS_MAGIC, int.from_bytes(b'HIAPAR01', 'little'))
        document = author.document()
        self.assertLessEqual(len(document['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in document['functions']
                                 for block in fn['blocks']), 8192)


if __name__ == '__main__':
    unittest.main()
