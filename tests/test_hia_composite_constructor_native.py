"""Actual-image full constructor state/error/continuation comparisons.

Both paths use the same selected native type dependency; historical hosted
type wording or private initialization differences are not constructor results.
"""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import ctypes
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_composite_constructor_native import (
    NativeCompositeConstructor, NativeConstructorInvocation, installed_composite_constructor,
    SELECTOR, RESPONSE_MAGIC, WORKSPACE_BYTES, OUTPUT_BYTES)
from hepta.hia_composite_constructor_native import CTOR_MAGIC
from hepta.hia_composite_types_native import NativeCompositeTypeSession, SELECTOR as TYPE_SELECTOR
from hepta.hia_program import HIAProgramRejected
from tests.test_hia_program import b, c, f, ret
from tests import test_hia_program_composite as nominal
from tests import test_hia_composite_returned_loans as loans
from tests import test_hia_partial_record as partial

DEVELOPMENT = 'HEPTA_HIA_COMPOSITE_CONSTRUCTOR_DEVELOPMENT_MANIFEST'
TYPES = 'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST'
EVIDENCE = 'HEPTA_HIA_CONSTRUCTOR_EVIDENCE'


def simple(*, version=1):
    doc = nominal.module([], f('main', [], ['u32'], [], [b('entry', [], [c('answer', 'u32', 7)], ret('answer'))]))
    doc['schema'] = 'hepta.hia.composite.v' + str(version)
    return doc


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()


def forbidden(*args, **kwargs):
    raise AssertionError('retained constructor semantic owner invoked')


def state(owner, document):
    result = {'attributes': sorted(vars(owner))}
    for name in ('document', 'serial', 'value_slots', 'parameter_loan_returns', 'return_origins',
                 'helpers', 'helper_names'):
        if hasattr(owner, name):
            result[name] = deepcopy(getattr(owner, name))
    if hasattr(owner, 'document'):
        result['document_identity'] = owner.document is document
    if hasattr(owner, 'nominal_operations'):
        result['nominal_operations'] = sorted(owner.nominal_operations)
    if hasattr(owner, 'types'):
        types = owner.types
        result['types_native_identity'] = owner.native_types is types
        result['types_observations'] = types.observations
        result['types_descriptors'] = deepcopy(types._descriptors)
        result['issued_type_ids'] = sorted(types._types)
        if hasattr(owner, 'signatures'):
            result['signatures'] = [[name, [[p, types._ids[id(t)]] for p, t in params],
                                      [types._ids[id(t)] for t in returns]]
                                     for name, (params, returns) in owner.signatures.items()]
    if hasattr(owner, 'functions'):
        members = document['functions']
        result['functions'] = [[name, deepcopy(fn), any(fn is item for item in members)]
                               for name, fn in owner.functions.items()]
    if hasattr(owner, '_native_function_session'):
        result['function_session'] = owner._native_function_session is None
    return result


class ConstructorFrameTests(unittest.TestCase):
    def test_unknown_phases_and_crossed_continuations_refuse(self):
        valid = [CTOR_MAGIC, 2, 0, 10, 1, 4, 1, 1]
        bad = []
        for index, value in ((3, 123456), (3, 0), (3, 20), (7, 2), (4, 2), (6, 2)):
            row = valid.copy(); row[index] = value; bad.append(row)
        bad += [[CTOR_MAGIC, 2, 0, 41, 3, 4, 1, 2],
                [CTOR_MAGIC, 0, 0, 41, 3, 4, 1, 0],
                [CTOR_MAGIC, 2, 0, 2000, 3, 4, 1, 0]]
        for frame in bad:
            invocation = NativeConstructorInvocation.__new__(NativeConstructorInvocation)
            invocation._request = invocation._stage = 0
            invocation._profile = invocation._issued_phase = None
            invocation._waiting = invocation._completed = False
            invocation._broken = False
            invocation._output = ctypes.create_string_buffer(struct.pack('<8Q', *frame))
            with self.subTest(frame=frame), self.assertRaises(HIAProgramRejected):
                invocation._frame(64)
            self.assertTrue(invocation._broken)
        invocation = NativeConstructorInvocation.__new__(NativeConstructorInvocation)
        invocation._request = invocation._stage = 0
        invocation._profile = invocation._issued_phase = None
        invocation._waiting = invocation._completed = False
        invocation._broken = False
        invocation._output = ctypes.create_string_buffer(struct.pack('<8Q', *valid))
        self.assertEqual(invocation._frame(64), tuple(valid))

    def test_response_preserves_issued_phase_profile_and_single_use(self):
        for mode in ('phase', 'profile', 'replay', 'second_request', 'good'):
            invocation = NativeConstructorInvocation.__new__(NativeConstructorInvocation)
            invocation._request, invocation._stage, invocation._profile = 6, 3, 4
            invocation._issued_phase = None
            invocation._waiting = invocation._completed = invocation._broken = False
            request = [CTOR_MAGIC, 2, 0, 30, 3, 4, 7, 2]
            invocation._output = ctypes.create_string_buffer(struct.pack('<8Q', *request))
            invocation._frame(64)
            invocation._request = 7
            response = [CTOR_MAGIC, 0, 0, 30, 3, 4, 7, 0]
            if mode == 'phase': response[3] = 41
            if mode == 'profile': response[5] = 3
            if mode == 'second_request': response = [CTOR_MAGIC, 2, 0, 41, 3, 4, 8, 3]
            invocation._output = ctypes.create_string_buffer(struct.pack('<8Q', *response))
            if mode in ('replay', 'good'):
                self.assertEqual(invocation._frame(64), tuple(response))
            if mode != 'good':
                with self.subTest(mode=mode), self.assertRaises(HIAProgramRejected):
                    invocation._frame(64)


class NativeConstructorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_composite_function_fixture import composite_function_fixture
        fixture = composite_function_fixture()
        cls.fixture_scope = fixture.scope
        cls.bundle = fixture.constructor_bundle
        cls.env = fixture.constructor_environment
        cls.evidence = Path(os.environ[EVIDENCE]) if os.environ.get(EVIDENCE) else None
        if cls.evidence is not None:
            cls.evidence.mkdir(parents=True, exist_ok=True)
        cls.rows, cls.entries = [], {'owner': 0, 'render': 0}
        images = {}
        for kind, image in cls.bundle.images.items():
            proxy = type('EntryCounter', (), {})()
            delegate = image._entry
            def call(*args, kind=kind, delegate=delegate):
                cls.entries[kind] += 1
                return delegate(*args)
            proxy._entry = call
            images[kind] = proxy
        cls.measured = NativeCompositeConstructor(images, types_source_sha256=cls.bundle.types_source_sha256)

    @classmethod
    def tearDownClass(cls):
        if cls.evidence is not None:
            (cls.evidence/'summary.json').write_text(json.dumps({
                'comparisons': len(cls.rows), 'native_entries': cls.entries,
                'equal': sum(row['equal'] for row in cls.rows),
                'fixture_scope': cls.fixture_scope,
                'scope': 'ACTUAL_CONSTRUCTOR_COMPONENT_TEST_NOT_WHOLE_STACK_QUALIFICATION'}, indent=2)+'\n')

    def compare(self, label, source, *, legacy=False):
        before = canonical(source)
        outcomes = []
        original_command = NativeCompositeTypeSession._command
        for native in (False, True):
            document = deepcopy(source)
            owner = composite._Elaborator.__new__(composite._Elaborator)
            trace = []
            def command(session, packet, **kwargs):
                item = {'command': deepcopy(packet)}
                try:
                    result = original_command(session, packet, **kwargs)
                except HIAProgramRejected as error:
                    item['error'] = [error.code, str(error)]
                    item['observations'] = session.observations
                    trace.append(item)
                    raise
                item['observations'] = session.observations
                trace.append(item)
                return result
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.dict(os.environ, {**self.env, SELECTOR: ''}))
                    stack.enter_context(patch('hepta.hia_composite_functions_native.selected_composite_functions',
                                              new=lambda: None))
                    stack.enter_context(patch.object(NativeCompositeTypeSession, '_command', new=command))
                    stack.enter_context(patch('hepta.hia_composite_constructor_native.selected_composite_constructor',
                                              new=lambda: self.measured if native else None))
                    if native:
                        for name in ('_reference_initialize', '_reference_parameters', '_reference_check_task',
                                     'loan_origins', 'parameters', 'check_task'):
                            stack.enter_context(patch.object(composite._Elaborator, name, new=forbidden))
                    try:
                        owner.__init__(document, legacy=legacy)
                    except HIAProgramRejected as error:
                        result = {'status': 'rejected', 'error': [error.code, str(error)]}
                    else:
                        result = {'status': 'accepted'}
                result.update(state=state(owner, document), trace=trace)
                outcomes.append(result)
                self.assertEqual(canonical(document), before, 'caller source changed')
            finally:
                if hasattr(owner, 'types'):
                    owner.types.close()
                owner.__dict__.clear()
                gc.collect()
        equal = outcomes[0] == outcomes[1]
        row = {'label': label, 'legacy': legacy, 'source_sha256': sha256(before).hexdigest(),
               'source': source, 'expected': outcomes[0], 'actual': outcomes[1], 'equal': equal}
        self.rows.append(row)
        if self.evidence is not None:
            with (self.evidence/'outcomes.jsonl').open('ab') as output:
                output.write(canonical(row)+b'\n')
        self.assertEqual(outcomes[1], outcomes[0], label)
        return outcomes[1]

    def test_headers_inventory_and_missing_attributes(self):
        for value in (None, [], {}, {'schema': 'bad'}, simple() | {'extra': None}):
            with self.subTest(value=value):
                result = self.compare('header-' + str(len(self.rows)), value)
                self.assertEqual(result['state']['attributes'], [])
        for field, values in (('schema', (None, 4, 'hepta.hia.composite.v5')),
                              ('module', (None, '', 'x-y', '__hia_reserved', 'h2internal_reserved', 'x'*129))):
            for value in values:
                doc = simple(); doc[field] = value
                self.compare(field + '-' + repr(value), doc)
        for types in (None, {}, [None], [{'kind': 'unknown'}]):
            doc = simple(); doc['types'] = types
            result = self.compare('type-init-' + repr(types), doc)
            self.assertEqual(result['state']['attributes'], ['document', 'nominal_operations', 'serial', 'value_slots'])
        for functions in (None, {}, [], [None]*1025):
            doc = simple(); doc['functions'] = functions
            result = self.compare('function-inventory-' + str(type(functions)) + '-' + str(len(functions or [])), doc)
            self.assertNotIn('functions', result['state']['attributes'])
            self.assertIn('types', result['state']['attributes'])

    def test_profiles_names_shapes_and_effects(self):
        for version in range(1, 5):
            self.compare('profile-' + str(version), simple(version=version))
            self.compare('legacy-' + str(version), simple(version=version), legacy=True)
            for value in (None, '', '__hia_x', 'h2internal_x', 'x'*129):
                doc = simple(version=version); doc['functions'][0]['name'] = value
                self.compare('function-name-' + str(version) + repr(value), doc)
            for field in ('name', 'params', 'returns', 'effects', 'entry', 'blocks'):
                doc = simple(version=version); del doc['functions'][0][field]
                self.compare('missing-' + str(version) + field, doc)
            doc = simple(version=version); doc['functions'][0]['return_loans'] = None
            self.compare('return-loans-presence-' + str(version), doc)
        for effects in (None, {}, [None], ['unknown'], ['read', 'read'], ['read', 'read', None],
                        ['alloc', 'read', 'write', 'trap']):
            doc = simple(version=4); doc['functions'][0]['effects'] = effects
            result = self.compare('effects-' + repr(effects), doc)
            self.assertEqual(list(dict(result['state']['return_origins'])), ['main'])
            if result['status'] == 'rejected':
                self.assertEqual(result['state']['functions'], [])
        doc = simple(); duplicate = deepcopy(doc['functions'][0]); duplicate['params'] = None
        doc['functions'].append(duplicate)
        result = self.compare('duplicate-before-invalid-params', doc)
        self.assertEqual(result['error'][0], 'E_HIA_NAME')

    def test_parameter_and_return_order_with_partial_state(self):
        for params in (None, {}, [None], [{'name': 'x', 'type': 'u32'}, {'name': 'x', 'type': 'Missing'}],
                       [{'name': 'x', 'type': 'Missing'}], [{'name': '__hia_x', 'type': 'u32'}]):
            doc = simple(); doc['functions'][0]['params'] = params
            self.compare('params-' + repr(params), doc)
        for version in range(1, 5):
            for returns in (None, {}, ['readbuf'], ['readbuf', 'Missing'], ['u32', 'Missing'],
                            ['Stored'], ['Stored', 'Missing'], ['Missing', 'Stored']):
                doc = simple(version=version)
                doc['types'] = [nominal.record('Stored', [('view', 'readbuf')])]
                doc['functions'][0]['returns'] = returns
                result = self.compare('returns-order-' + str(version) + repr(returns), doc)
                if isinstance(returns, list) and 'Missing' in returns:
                    self.assertEqual(result['error'][0], 'E_HIA_TYPE')
        doc = simple(version=4)
        bad = deepcopy(doc['functions'][0]); bad['name'] = 'later'; bad['effects'] = ['unknown']
        doc['functions'].append(bad)
        result = self.compare('origin-commit-before-effects-after-prefix', doc)
        self.assertEqual(list(result['state']['return_origins']), ['main', 'later'])
        self.assertEqual([row[0] for row in result['state']['functions']], ['main'])

    def test_native_origins_and_ordinary_type_graphs(self):
        fixtures = [nominal.stored_loan_program, nominal.enum_owner_program, nominal.task_program,
                    nominal.scalar_task_program, nominal.owned_result_task_program,
                    partial.roundtrip_program, partial.task_partial_program, partial.nested_record_program,
                    partial.chain_partial_program, loans.pair_program, loans.task_program,
                    loans.direct_downgrade_program]
        for factory in fixtures:
            result = self.compare('ordinary-' + factory.__module__ + '.' + factory.__name__, factory())
            self.assertEqual(result['status'], 'accepted')
        for annotations in (None, [], [None], [loans.origin('unknown')], [loans.origin('input', 'absent')],
                            [loans.origin('input')]):
            doc = simple(version=4)
            doc['functions'][0].update(params=[{'name': 'input', 'type': 'readbuf'}],
                                      returns=['readbuf'], return_loans=annotations)
            self.compare('origin-' + repr(annotations), doc)

    def test_unused_tasks_original_declaration_order(self):
        valid = nominal.scalar_task_program()
        self.compare('unused-task-valid', valid)
        for definition in valid['types']:
            if definition['kind'] != 'task':
                continue
            doc = deepcopy(valid)
            index = valid['types'].index(definition)
            doc['types'][index]['poll'] = 'missing'
            result = self.compare('unused-task-missing-poll', doc)
            self.assertEqual(len(result['state']['functions']), len(doc['functions']))
            later = deepcopy(doc['types'][index]); later['name'] = 'LaterTask'; later['state'] = 'Missing'
            doc['types'].append(later)
            self.compare('unused-task-stops-before-later-resolution', doc)
            doc['types'].insert(0, doc['types'].pop())
            self.compare('unused-task-declaration-order-reversed', doc)

    def test_large_constructor_inventories_without_lowering(self):
        doc = simple(version=4)
        doc['functions'][0]['returns'] = ['u32'] * 4096
        doc['functions'][0]['entry'] = None
        doc['functions'][0]['blocks'] = None
        result = self.compare('4096-returns-deferred-blocks', doc)
        self.assertEqual(result['status'], 'accepted')
        doc = simple(version=4)
        doc['functions'][0]['params'] = [{'name': 'p' + str(i), 'type': 'u32'} for i in range(2048)]
        self.compare('2048-parameters-constructor-no-value-slot-reservation', doc)
        doc = simple(version=4)
        doc['functions'] = [dict(deepcopy(doc['functions'][0]), name='f' + str(i)) for i in range(1024)]
        self.compare('1024-functions-boundary', doc)

    def test_abi_poison_response_correlation_and_unissued_ids(self):
        def fresh():
            owner = composite._Elaborator.__new__(composite._Elaborator)
            return NativeConstructorInvocation(self.measured.images, owner, simple())
        with patch.dict(os.environ, self.env):
            for mode in ('request', 'kind', 'status', 'trailing', 'replay', 'unissued'):
                invocation = fresh()
                try:
                    frame = invocation._invoke(invocation._source_wire)
                    invocation._request = frame[6]
                    command = invocation._stream(1, frame[6])
                    good = struct.pack('<8Q', RESPONSE_MAGIC, frame[6], 1, 0, 0, 0, 0, 0)
                    if mode in ('replay', 'unissued'):
                        invocation._service(command, 1, frame[6])
                        if mode == 'replay':
                            wire = good
                        else:
                            # The example has zero parameters; let its genuine
                            # request complete, then forge the scalar return ID.
                            frame = invocation._run(); invocation._request = frame[6]
                            command = invocation._stream(frame[7], frame[6])
                            invocation._service(command, frame[7], frame[6])
                            frame = invocation._run(); invocation._request = frame[6]
                            invocation._stream(frame[7], frame[6])
                            wire = struct.pack('<8Q', RESPONSE_MAGIC, frame[6], 3, 0, 1, 8, 0, 0) + struct.pack('<Q', 144)
                    else:
                        fields = list(struct.unpack('<8Q', good))
                        if mode == 'request': fields[1] += 1
                        if mode == 'kind': fields[2] = 2
                        if mode == 'status': fields[3] = 2
                        wire = struct.pack('<8Q', *fields) + (b'x' if mode == 'trailing' else b'')
                    with self.assertRaises(HIAProgramRejected):
                        invocation._invoke(wire)
                        invocation._run()
                    with self.assertRaises(HIAProgramRejected):
                        invocation._invoke(good)
                finally:
                    if invocation.types is not None:
                        invocation.types.close()
                    invocation._workspace = invocation._output = None
            for kernel in ('owner', 'render'):
                invocation = fresh()
                try:
                    invocation._invoke(invocation._source_wire)
                    source = ctypes.create_string_buffer(b'')
                    status = invocation.images[kernel]._entry(source, 0, invocation._output, 63,
                                                               invocation._workspace, WORKSPACE_BYTES)
                    self.assertEqual(status, 0xfffffff1)
                    with self.assertRaises(HIAProgramRejected):
                        invocation._invoke(invocation._source_wire)
                finally:
                    invocation._workspace = invocation._output = None


if __name__ == '__main__':
    unittest.main()
