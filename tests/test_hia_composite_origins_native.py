"""Returned-loan origin ownership in the actual HIA type-session image.

The old helper is an independent oracle only. Development images remain
development evidence; the shared fixture refuses to bypass a requested cold
qualification with a development manifest.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import ctypes
import json
import os
import random
import struct
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_composite_types_native import (HEADER_BYTES, MAGIC, ORIGINS_MAGIC,
    OUTPUT_BYTES, SESSION_BYTES, SELECTOR)
from hepta.hia_program import HIAProgramRejected, verify_core
from tests import test_hia_composite_returned_loans as loans
from tests import test_hia_composite_types_native as type_tests
from tests.test_hia_composite_types_native import (frame, primitive_descriptors, synthetic_image, wire,
    record, enum, ref, partial)
from tests.test_hia_program import b, f, ret


def origin_frame(origins=(), *, error=0, count=None, cached=0, active=0, steps=0,
                 magic=ORIGINS_MAGIC, reserved=0, envelope=None):
    payload = wire({'origins': list(origins)} if envelope is None else envelope)
    count = len(origins) if count is None else count
    return struct.pack('<8Q', magic, error, count, len(payload), cached, active, steps, reserved) + payload


def outcome(call):
    try:
        return call(), None
    except HIAProgramRejected as error:
        return None, error.code


class CompositeOriginsAdapterTests(unittest.TestCase):
    def test_strict_origins_frame_and_state_correlation_poison_bad_transport(self):
        bad = [origin_frame([['p', 0]], magic=MAGIC),
            origin_frame([['p', 0]], reserved=1), origin_frame([['p', 0]], count=0),
            origin_frame([['p', 0]], error=39), origin_frame([], error=25),
            origin_frame([['p', 0]], cached=1), origin_frame([['p', 0]], active=1),
            origin_frame([['p', 0]], steps=1), origin_frame([['unknown', 0]]),
            origin_frame([['p', True]]), origin_frame([['p', -1]]),
            origin_frame([['p', 512]]), origin_frame([['p', 0, 1]]),
            origin_frame([{'param': 'p', 'offset': 0}]),
            origin_frame([], count=1, envelope={'origins': [['p', 0]], 'types': []}),
            origin_frame([], count=1, envelope={'origins': []}),
            origin_frame([['p', 0]], count=0, error=39)]
        for malformed in bad:
            with self.subTest(frame=repr(malformed)[:100]):
                image = synthetic_image([frame(primitive_descriptors()), malformed])
                with image.session([]) as session:
                    params, returns = [('p', session._types[14])], [session._types[14]]
                    with self.assertRaises(HIAProgramRejected):
                        session.loan_origins({'return_loans': [loans.origin('p')]}, params, returns)
                    with self.assertRaisesRegex(HIAProgramRejected, 'failed transport'):
                        session.resolve('u8')

    def test_semantic_refusal_is_recoverable_and_absence_is_not_null(self):
        calls = []
        image = synthetic_image([frame(primitive_descriptors()),
            origin_frame([None]), origin_frame([], error=37), origin_frame([['p', 0]])], calls)
        with image.session([]) as session:
            params = [('p', session._types[14])]
            self.assertEqual(session.loan_origins({}, params, [session._types[3]]), (None,))
            with self.assertRaisesRegex(HIAProgramRejected, 'match return arity'):
                session.loan_origins({'return_loans': None}, params, [session._types[14]])
            self.assertEqual(session.loan_origins({'return_loans': [loans.origin('p')]},
                params, [session._types[14]]), (('p', 0),))
        self.assertNotIn('return_loans', calls[1][0])
        self.assertIsNone(calls[2][0]['return_loans'])

    def test_forged_and_other_session_types_do_not_enter_the_image(self):
        for location in ('param', 'return'):
            for forged_copy in (False, True):
                calls = []
                left_image = synthetic_image([frame(primitive_descriptors())], calls)
                right_image = synthetic_image([frame(primitive_descriptors())])
                with left_image.session([]) as left, right_image.session([]) as right:
                    forged = replace(left._types[14]) if forged_copy else right._types[14]
                    params = [('p', forged if location == 'param' else left._types[14])]
                    returns = [forged if location == 'return' else left._types[14]]
                    with self.assertRaisesRegex(HIAProgramRejected, 'does not belong to this session'):
                        left.loan_origins({'return_loans': [loans.origin('p')]}, params, returns)
                    self.assertEqual(len(calls), 1)
                    with self.assertRaisesRegex(HIAProgramRejected, 'failed transport'):
                        left.resolve('u8')


class CompositeOriginsNativeTests(unittest.TestCase):
    setUpClass = classmethod(type_tests.CompositeTypesNativeTests.setUpClass.__func__)
    paired = type_tests.CompositeTypesNativeTests.paired

    def compare_origins(self, old, new, function, params, returns):
        old_params = tuple((name, old.resolve(typ)) for name, typ in params)
        new_params = tuple((name, new.resolve(typ)) for name, typ in params)
        old_returns = tuple(old.resolve(typ) for typ in returns)
        new_returns = tuple(new.resolve(typ) for typ in returns)
        before = new.observations
        saved = deepcopy(function)
        expected = outcome(lambda: composite._Elaborator.loan_origins(function, old_params, old_returns))
        actual = outcome(lambda: new.loan_origins(function, new_params, new_returns))
        self.assertEqual(actual, expected, (function, params, returns))
        self.assertEqual(new.observations, before)
        self.assertEqual(function, saved)
        return actual

    def test_exact_absent_null_shapes_names_permissions_and_diagnostic_order(self):
        definitions = [record('Empty', []), record('Pair', [('pad', 'u16'),
            ('left', 'T'), ('right', 'U')], ['T', 'U']), record('Envelope', [
            ('zero', 'Empty'), ('prefix', 'u32'), ('inner', ref('Pair', 'readbuf', 'mutbuf')),
            ('tail', 'readbuf')]), record('Owned', [('view', 'readbuf'), ('owner', 'buffer')]),
            record('Plain', [('value', 'u8')]), enum('Choice', [('empty', []), ('value', [('x', 'u8')])]),
            dict(name='Task', params=[], kind='task', state='Plain', result='u8', poll='poller', cancel='cancel')]
        params = [('views', 'Envelope'), ('reader', 'readbuf'), ('writer', 'mutbuf'),
                  ('owned', 'Owned'), ('enumval', 'Choice'), ('taskval', 'Task'),
                  ('partialval', partial('Plain')), ('chainval', 'chain'), ('scalar', 'u8')]
        cases = [({}, [], ((), None)), ({'return_loans': []}, [], ((), None)),
            ({}, ['u8', 'Empty'], ((None, None), None)),
            ({'return_loans': [None, None]}, ['u8', 'Empty'], ((None, None), None)),
            ({'return_loans': None}, [], (None, 'E_HIA_LOAN')),
            ({'return_loans': False}, ['u8'], (None, 'E_HIA_LOAN')),
            ({'return_loans': []}, ['readbuf'], (None, 'E_HIA_LOAN')),
            ({}, ['readbuf'], (None, 'E_HIA_FORMAT')),
            ({'return_loans': [None]}, ['readbuf'], (None, 'E_HIA_FORMAT')),
            ({'return_loans': [loans.origin('missing')]}, ['u8'], (None, 'E_HIA_LOAN')),
            ({'return_loans': [loans.origin('views', 'inner', 'right'), None,
                               loans.origin('views', 'inner', 'left')]},
             ['mutbuf', 'u8', 'readbuf'], ((('views', 3), None, ('views', 2)), None)),
            ({'return_loans': [loans.origin('writer'), loans.origin('reader')]},
             ['readbuf', 'readbuf'], ((('writer', 0), ('reader', 0)), None)),
            ({'return_loans': [loans.origin('reader')]}, ['mutbuf'], (None, 'E_HIA_LOAN'))]
        malformed = [None, False, '', [], {'param': 'reader'},
            {'param': 'reader', 'fields': [], 'slot': 0},
            loans.origin(''), loans.origin('__hia_bad'), loans.origin('h2internal_bad'),
            loans.origin('bad-name'), loans.origin('é'), loans.origin('x' * 129),
            {'param': False, 'fields': []}, {'param': 'missing', 'fields': None},
            {'param': 'owned', 'fields': None}, {'param': 'reader', 'fields': None},
            {'param': 'views', 'fields': 'inner'}, loans.origin('views', *(['inner'] * 33)),
            loans.origin('reader', False), loans.origin('reader', 'missing'),
            loans.origin('views', 'missing'), loans.origin('views', 'inner'),
            loans.origin('views', 'prefix'), loans.origin('views', 'inner', False),
            loans.origin('views', 'inner', 'left', 'x'), loans.origin('owned', 'view'),
            loans.origin('enumval'), loans.origin('taskval'), loans.origin('partialval'),
            loans.origin('chainval'), loans.origin('scalar')]
        with self.paired(definitions, recursive_chain=True, partial_records=True) as (old, new, error):
            self.assertIsNone(error)
            for function, returns, wanted in cases:
                with self.subTest(function=function, returns=returns):
                    self.assertEqual(self.compare_origins(old, new, function, params, returns), wanted)
            for annotation in malformed:
                with self.subTest(annotation=annotation):
                    result, code = self.compare_origins(old, new, {'return_loans': [annotation]}, params, ['readbuf'])
                    self.assertIsNotNone(code)
            # Earlier return entries decide the diagnostic even when a later
            # origin is malformed. The reverse order must change that code.
            self.assertEqual(self.compare_origins(old, new,
                {'return_loans': [loans.origin('missing'), None]}, params, ['u8', 'readbuf'])[1], 'E_HIA_LOAN')
            self.assertEqual(self.compare_origins(old, new,
                {'return_loans': [None, loans.origin('missing')]}, params, ['readbuf', 'u8'])[1], 'E_HIA_FORMAT')

    def test_declared_field_offsets_zero_width_dag_depth_and_512_slot_boundary(self):
        definitions = [record('Empty', [])]
        for depth in range(16):
            previous = 'Empty' if depth == 0 else 'Empty' + str(depth - 1)
            definitions.append(record('Empty' + str(depth), [('z' + str(i), previous) for i in range(8)]))
        definitions += [record('Eight', [('n' + str(i), 'u8') for i in range(8)]),
            record('Seven', [('n' + str(i), 'u8') for i in range(7)]),
            record('Prefix', [('n' + str(i), 'Eight') for i in range(63)] + [('last', 'Seven')]),
            record('Boundary', [('zero', 'Empty15'), ('prefix', 'Prefix'), ('reader', 'readbuf')])]
        for depth in range(32):
            definitions.append(record('Deep' + str(depth), [('leaf', 'readbuf' if depth == 0 else 'Deep' + str(depth - 1))]))
        with self.paired(definitions, recursive_chain=True, partial_records=True) as (old, new, error):
            self.assertIsNone(error)
            result = self.compare_origins(old, new, {'return_loans': [loans.origin('p', 'reader')]},
                [('p', 'Boundary')], ['readbuf'])
            self.assertEqual(result, ((('p', 511),), None))
            result = self.compare_origins(old, new, {'return_loans': [loans.origin('p', *(['leaf'] * 32))]},
                [('p', 'Deep31')], ['readbuf'])
            self.assertEqual(result, ((('p', 0),), None))
            self.assertEqual(self.compare_origins(old, new,
                {'return_loans': [loans.origin('p', *(['leaf'] * 33))]},
                [('p', 'Deep31')], ['readbuf'])[1], 'E_HIA_LIMIT')

    def test_bounded_independent_random_paths_and_name_hash_collisions(self):
        definitions = [record('Empty', []), record('Leaf', [('pad', 'Empty'),
            ('left', 'T'), ('right', 'U')], ['T', 'U']),
            record('Root', [('count', 'u32'), ('a', ref('Leaf', 'readbuf', 'mutbuf')),
                ('b', ref('Leaf', 'mutbuf', 'readbuf'))])]
        # These collide under the HIA owner's 17-bit name-hash table. Equality,
        # not the bucket hash, must select the original formal.
        buckets, collision = {}, None
        for index in range(5000):
            name = 'p' + str(index)
            hashval = 1469598103934665603
            for byte in name.encode():
                hashval = ((hashval ^ byte) * 1099511628211) & ((1 << 64) - 1)
            bucket = hashval & 131071
            if bucket in buckets:
                collision = (buckets[bucket], name)
                break
            buckets[bucket] = name
        self.assertIsNotNone(collision)
        params = [(collision[0], 'readbuf'), (collision[1], 'Root'), ('other', 'mutbuf')]
        rng = random.Random(90173)
        with self.paired(definitions, recursive_chain=True, partial_records=True) as (old, new, error):
            self.assertIsNone(error)
            for _ in range(96):
                annotations, returns = [], []
                for _ in range(rng.randrange(1, 5)):
                    returns.append(rng.choice(['u8', 'readbuf', 'mutbuf']))
                    annotations.append(None if rng.randrange(7) == 0 else loans.origin(
                        rng.choice([*collision, 'other', 'missing']),
                        *rng.choice([[], ['a', 'left'], ['a', 'right'], ['b', 'left'],
                                     ['b', 'right'], ['a', 'pad'], ['count'], ['absent']])))
                self.compare_origins(old, new, {'return_loans': annotations}, params, returns)

    def test_original_input_snapshot_no_host_fallback_and_public_bytes(self):
        programs = [loans.pair_program('read'), loans.pair_program('mut'), loans.task_program(),
                    loans.direct_downgrade_program()]
        for document in programs:
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            before = deepcopy(document)
            with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                    composite, '_Types', side_effect=AssertionError('host type owner called')), patch.object(
                    composite._Elaborator, 'loan_origins', side_effect=AssertionError('host origins owner called')):
                actual = verify_core(document)
            self.assertEqual(document, before)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes))
        with self.native.session([], recursive_chain=True, partial_records=True) as session:
            typ = session.resolve('readbuf')
            function = {'return_loans': [loans.origin('p')]}
            entry = self.native._entry
            entered = []
            def mutate_after_snapshot(source, size, *buffers):
                raw = ctypes.string_at(source, size)
                entered.append(raw)
                function['return_loans'][0]['param'] = 'missing'
                function['return_loans'][0]['fields'].append('bad')
                result = entry(source, size, *buffers)
                self.assertEqual(ctypes.string_at(source, size), raw)
                return result
            with patch.object(self.native, '_entry', side_effect=mutate_after_snapshot):
                self.assertEqual(session.loan_origins(function, [('p', typ)], [typ]), (('p', 0),))
            self.assertEqual(json.loads(entered[0])['return_loans'], [loans.origin('p')])
            with self.assertRaises(HIAProgramRejected):
                session.loan_origins(function, [('p', typ)], [typ])
            function['return_loans'] = [loans.origin('p')]
            self.assertEqual(session.loan_origins(function, [('p', typ)], [typ]), (('p', 0),))

    def test_origins_preserve_public_byte_boundary_and_large_zero_width_formal_inventory(self):
        from hepta.hia_program import MAX_BYTES
        params = [('p' + str(i), 'Empty') for i in range(2048)] + [('reader', 'readbuf')]
        function = f('reader', params, ['readbuf'], [], [b('entry', params, [], ret('reader'))])
        function['return_loans'] = [loans.origin('reader')]
        document = loans.v4([record('Empty', [])], function)
        with patch.dict(os.environ, {SELECTOR: ''}):
            expected = verify_core(document)
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                composite, '_Types', side_effect=AssertionError('host type owner called')), patch.object(
                composite._Elaborator, 'loan_origins', side_effect=AssertionError('host origins owner called')):
            actual = verify_core(document)
        self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                         (expected.canonical_bytes, expected.structured_bytes))

        params = [('p', 'readbuf')]
        function = f('reader', params, ['readbuf'], [], [b('entry', params, [], ret('p'))])
        annotation = dict(param='p', fields=[], extra='')
        function['return_loans'] = [annotation]
        document = loans.v4([], function)
        annotation['extra'] = 'x' * (MAX_BYTES - len(wire(document)))
        self.assertEqual(len(wire(document)), MAX_BYTES)
        with patch.dict(os.environ, {SELECTOR: ''}):
            with self.assertRaises(HIAProgramRejected) as expected_error:
                verify_core(document)
        self.assertEqual(expected_error.exception.code, 'E_HIA_FORMAT')
        entry, entered = self.native._entry, []
        def observe(source, size, *buffers):
            if ctypes.string_at(source, min(size, 16)).startswith(b'{"op":"origins"'):
                entered.append(size)
            return entry(source, size, *buffers)
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}), patch.object(
                composite, '_Types', side_effect=AssertionError('host type owner called')), patch.object(
                composite._Elaborator, 'loan_origins', side_effect=AssertionError('host origins owner called')),
                patch.object(self.native, '_entry', side_effect=observe)):
            with self.assertRaises(HIAProgramRejected) as actual_error:
                verify_core(document)
        self.assertEqual(actual_error.exception.code, expected_error.exception.code)
        self.assertEqual(len(entered), 1)
        self.assertLess(entered[0], MAX_BYTES)
        self.assertGreater(entered[0], MAX_BYTES - 1024)

    def test_forged_interned_ids_and_incomplete_types_fail_closed(self):
        for where in ('param', 'return'):
            for bad in (0, -1, True, False, None, 14.0, '14', 17, 145, 1000, 2**64 + 14):
                with self.subTest(where=where, value=bad), self.native.session([]) as session:
                    command = dict(op='origins', params=[['p', bad if where == 'param' else 14]],
                        returns=[bad if where == 'return' else 14], return_loans=[loans.origin('p')])
                    # The common JSON preflight rejects decimals before the
                    # origins command's integer-ID admission is reached.
                    status = 0xffffffff if type(bad) is float else 0xfffffff1
                    with self.assertRaisesRegex(HIAProgramRejected, 'frame extent/status ' + str(status)):
                        session._command(command, origins=True)
                    with self.assertRaisesRegex(HIAProgramRejected, 'failed transport'):
                        session.resolve('u8')
        definitions = [enum('Bad', [('loan', [('v', 'readbuf')])])]
        with self.native.session(definitions) as session:
            with self.assertRaises(HIAProgramRejected):
                session.resolve('Bad')
            self.assertEqual(session.observations['active_count'], 1)
            before = session.observations
            self.assertEqual(session.loan_origins({'return_loans': [loans.origin('p')]},
                [('p', session._types[14])], [session._types[14]]), (('p', 0),))
            self.assertEqual(session.observations, before)
            with self.assertRaisesRegex(HIAProgramRejected, 'match return arity'):
                session.loan_origins({'return_loans': None}, [('p', session._types[14])], [session._types[14]])
            self.assertEqual(session.observations, before)
            with self.assertRaisesRegex(HIAProgramRejected, 'frame extent/status 4294967281'):
                session._command(dict(op='origins', params=[['p', 17]], returns=[14],
                    return_loans=[loans.origin('p')]), origins=True)

    def test_actual_raw_command_inventory_duplicate_names_and_input_custody(self):
        good = dict(op='origins', params=[['p', 14]], returns=[14], return_loans=[loans.origin('p')])
        malformed = [dict(good, extra=0), dict(good, params=None), dict(good, returns=None),
            dict(good, params=[['p', 14, 15]]), dict(good, params=[['p', 14], ['p', 15]]),
            dict(good, params=[['__hia_bad', 14]])]
        with self.native.session([]) as session:
            for command in malformed:
                raw = wire(command)
                source = ctypes.create_string_buffer(raw)
                status = self.native._entry(source, len(raw), session._output, OUTPUT_BYTES,
                                           session._state, SESSION_BYTES)
                self.assertEqual(status, 0xfffffff1)
                self.assertEqual(ctypes.string_at(source, len(raw)), raw)
            # A direct raw caller receives a fatal status, not a descriptor or
            # successful origin. The adapter additionally poisons its session.
            self.assertEqual(session.loan_origins({'return_loans': [loans.origin('p')]},
                [('p', session._types[14])], [session._types[14]]), (('p', 0),))


if __name__ == '__main__':
    unittest.main()
