"""Independent actual-image CFG/terminator differential for the full bundle.

The retained complete function is the oracle, including its rejected-call
counter updates. These tests do not treat a development image as a qualified
compiler, and they do not invoke the hosted function on the native path.
"""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_composite_functions_native import (
    NativeFunctionSession, installed_composite_functions)
from hepta.hia_composite_types_native import installed_composite_types, SESSION_BYTES
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program
from hepta.hia_schema import SCHEMA_V8
from hepta.hia_task_helpers_native import installed_task_helpers
from tests.test_hia_composite_types_native import native_key
from tests.test_hia_composite_returned_loans import v4, origin
from tests.test_hia_program import b, branch, c, f, i, jump, ret
from tests.test_hia_program_composite import enum, match, record


BUNDLE = 'HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST'
TYPES = 'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST'
HELPERS = 'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST'
EVIDENCE = 'HEPTA_HIA_FUNCTION_TERMS_EVIDENCE'
ORACLE = getattr(composite._Elaborator, '_reference_function', composite._Elaborator.function)
HOST_METHODS = ('function', '_reference_function', 'flat_parameters', 'parameters',
                '_reference_parameters', 'fresh', 'reserve_values', 'zeros',
                'drop_padding', 'constant', 'helper', 'check_task')


def wire(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def state(owner):
    keys = {}
    native = owner.native_types
    lookup = {typ.key: ident for ident, typ in native._types.items()}
    cache = [[native_key(native, lookup[typ], keys), operation, name]
             for (typ, operation), name in owner.helper_names.items()]
    return dict(serial=owner.serial, value_slots=owner.value_slots,
                helpers=deepcopy(owner.helpers), helper_cache=cache,
                type_observations=dict(native.observations))


def outcome(owner, callback):
    try:
        result = callback()
    except HIAProgramRejected as error:
        result = dict(status='rejected', error=dict(code=error.code, message=str(error)))
    else:
        result = dict(status='accepted', core=result)
    result.update(state(owner))
    return result


def packed(types, functions):
    """Keep each author case intact while making constructor names unique."""
    functions = deepcopy(functions)
    for index, fn in enumerate(functions):
        fn['name'] = 'case_' + str(index)
    return v4(types, *functions)


class NativeFunctionTermsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_composite_function_fixture import composite_function_fixture
        fixture = composite_function_fixture()
        cls.bundle = fixture.bundle
        cls.types_image = fixture.types_image
        cls.helpers_image = fixture.helpers_image
        cls.evidence = Path(os.environ[EVIDENCE]) if os.environ.get(EVIDENCE) else None
        if cls.evidence is not None:
            cls.evidence.mkdir(parents=True, exist_ok=True)
        cls.entries = {kernel: 0 for kernel in cls.bundle.images}

    def compare(self, label, document, *, calls=None, serial=0, slots=0,
                custody=False, legacy=False):
        before = wire(document)
        source_identity = sha256(before).hexdigest()
        if self.evidence is not None:
            (self.evidence / (label + '.source.json')).write_bytes(before)
        owners = []
        session = None
        source_custody = []
        type_custody = []
        rows = []
        with ExitStack() as selectors:
            selectors.enter_context(patch(
                'hepta.hia_composite_functions_native.selected_composite_functions', return_value=None))
            selectors.enter_context(patch('hepta.hia_composite_types_native.selected_composite_types',
                side_effect=lambda definitions, **flags: self.types_image.session(definitions, **flags)))
            for _ in range(2):
                owner = composite._Elaborator(deepcopy(document), legacy=legacy)
                owner.serial, owner.value_slots = serial, slots
                owners.append(owner)
        reference, native = owners
        try:
            images = {}
            for kernel, image in self.bundle.images.items():
                delegate = image._entry
                proxy = type('EntryCustody', (), {})()
                def checked_entry(*args, kernel=kernel, delegate=delegate):
                    self.entries[kernel] += 1
                    if custody and kernel == 'terms' and args[1] == SESSION_BYTES:
                        previous = sha256(memoryview(args[0])).hexdigest()
                        result = delegate(*args)
                        final = sha256(memoryview(args[0])).hexdigest()
                        type_custody.append(dict(before=previous, after=final))
                        self.assertEqual(previous, final, 'terms modified the borrowed native type state')
                        return result
                    return delegate(*args)
                proxy._entry = checked_entry
                images[kernel] = proxy
            session = NativeFunctionSession(images, native, self.helpers_image, legacy=legacy)
            source_size = struct.unpack_from('<Q', session._workspace, 4096 + 16)[0]
            source_bytes = ctypes.string_at(ctypes.addressof(session._workspace) + 65536, source_size)
            indexes = list(range(len(document['functions']))) if calls is None else calls
            for ordinal, index in enumerate(indexes):
                expected = outcome(reference, lambda: ORACLE(reference, reference.document['functions'][index]))
                with ExitStack() as poisoned:
                    for name in HOST_METHODS:
                        if hasattr(composite._Elaborator, name):
                            poisoned.enter_context(patch.object(composite._Elaborator, name,
                                side_effect=AssertionError('hosted lowering invoked: ' + name)))
                    actual = outcome(native, lambda: session.function(native.document['functions'][index]))
                final_source = ctypes.string_at(ctypes.addressof(session._workspace) + 65536, source_size)
                self.assertEqual(final_source, source_bytes, 'native source snapshot changed')
                source_custody.append(sha256(final_source).hexdigest())
                row = dict(ordinal=ordinal, function=index, expected=expected, actual=actual)
                rows.append(row)
                if self.evidence is not None:
                    with (self.evidence / (label + '.outcomes.jsonl')).open('ab') as output:
                        output.write(wire(row) + b'\n')
                self.assertTrue(expected == actual,
                    (label, ordinal, expected.get('error'), actual.get('error'),
                     sha256(wire(expected)).hexdigest(), sha256(wire(actual)).hexdigest()))
                self.assertEqual(wire(expected), wire(actual), 'full serialized outcomes differ')
            self.assertEqual(wire(reference.document), before)
            self.assertEqual(wire(native.document), before)
            self.assertEqual(wire(document), before)
            if self.evidence is not None:
                summary = dict(source_sha256=source_identity, source_bytes=len(before),
                    calls=len(rows), accepted=sum(row['actual']['status'] == 'accepted' for row in rows),
                    native_entries=dict(self.entries), source_copy_bytes=source_size,
                    source_readbacks=source_custody, borrowed_type_readbacks=type_custody,
                    final_native_arena_cursor=struct.unpack_from('<Q', session._workspace, 4104)[0],
                    backend='retained direct x86 development images; not cold qualification')
                (self.evidence / (label + '.summary.json')).write_text(json.dumps(summary, indent=2) + '\n')
            return rows
        finally:
            if session is not None:
                session.close()
            for owner in owners:
                owner.types.close()

    def test_simple_terminators_shapes_names_and_diagnostic_order(self):
        params = [('x', 'u8'), ('condition', 'bool')]
        def one(term):
            return f('simple', params, ['u8'], [], [
                b('entry', params, [], term), b('tail', [('y', 'u8')], [], ret('y'))])
        terms = [ret('x'), jump('tail', 'x'),
            branch('condition', ('tail', 'x'), ('tail', 'x')),
            None, 0, [], {}, {'op': 0}, {'op': 'unknown'}, {'op': 'ret'},
            {'op': 'ret', 'values': [], 'extra': 0}, ret(), ret('x', 'missing'),
            ret('missing', 'x'), ret('condition'), {'op': 'ret', 'values': 1}]
        for name in ('', 'bad-name', '__hia_private', 'h2internal_private', 'missing', 0):
            terms.extend([ret(name), jump(name, 'missing'), jump('tail', name),
                          branch(name, ('missing',), ('tail', 'x'))])
        for raw in (None, [], {}, {'target': 'tail'}, {'target': 'tail', 'args': 0},
                    {'target': 'missing', 'args': ['bad-name']},
                    {'target': 'missing', 'args': ['missing']},
                    {'target': 'tail', 'args': ['condition']},
                    {'target': 'tail', 'args': ['x'], 'extra': None}):
            left = branch('condition', ('tail', 'x'), ('tail', 'x'))
            left['then'] = raw
            right = branch('condition', ('tail', 'x'), ('tail', 'x'))
            right['else'] = raw
            terms.extend([left, right])
        for code in ('user', 'other', 0, None, [], {'nested': [1, True]}):
            terms.append({'op': 'trap', 'code': code})
        terms.extend([{'op': 'trap'}, {'op': 'trap', 'code': 'user', 'extra': 0},
                      {'op': 'jump', 'target': 'tail', 'args': ['x'], 'extra': 0}])
        rows = self.compare('simple', packed([], [one(term) for term in terms]), custody=True)
        self.assertGreater(sum(row['actual']['status'] == 'rejected' for row in rows), 50)
        self.assertEqual(rows[0]['actual']['core']['blocks'][0]['term'], ret('x'))

    def test_resources_edge_liveness_alias_and_refusal_state(self):
        types = [record('Owned', [('owner', 'buffer'), ('n', 'u8')]),
                 record('Borrowed', [('view', 'readbuf')]), record('Empty', [])]
        cases = []
        def add(params, returns, term, *, ops=(), target=()):
            blocks = [b('entry', params, list(ops), term)]
            if target:
                blocks.append(b('tail', list(target), [], {'op': 'trap', 'code': 'user'}))
            function = f('resource', params, list(returns), [], blocks)
            if any(typ == 'readbuf' for typ in returns):
                function['return_loans'] = [origin('x') if typ == 'readbuf' else None for typ in returns]
            cases.append(function)
        for typ in ('buffer', 'chain', 'Owned', 'readbuf', 'Borrowed', 'Empty', 'u8'):
            add([('x', typ)], [] if typ == 'Borrowed' else [typ], ret('x'))
            add([('x', typ)], [], ret())
            if typ not in ('readbuf', 'Borrowed'):
                add([('x', typ)], [typ, typ], ret('x', 'x'))
            add([('x', typ)], [], jump('tail', 'x', 'x'), target=[('a', typ), ('z', typ)])
            add([('x', typ)], [], jump('tail'), target=[('a', typ)])
            add([('x', typ)], [], jump('tail', 'missing'), target=[('a', typ)])
        add([('x', 'buffer'), ('z', 'buffer')], [], jump('tail', 'x', 'x'),
            target=[('a', 'buffer'), ('other', 'u8')])
        add([('x', 'buffer'), ('z', 'buffer')], [], jump('tail', 'x', 'missing'),
            target=[('a', 'u8')])
        add([('x', 'buffer')], [], jump('tail', 'x'),
            ops=[i('owner.drop', ['x'])], target=[('a', 'buffer')])
        add([('x', 'buffer')], ['buffer', 'buffer'], ret('x', 'x'))
        add([('x', 'buffer')], [], ret('x', 'missing'))
        add([('x', 'readbuf')], [], ret(), ops=[i('loan.end', ['x'])])
        doc = packed(types, cases)
        indexes = list(range(len(cases))) + [len(cases) - 3, 0, len(cases) - 3, 1]
        rows = self.compare('resources', doc, calls=indexes)
        self.assertTrue(any(row['actual'].get('error', {}).get('message') ==
                            'E_HIA_RESOURCE: use of consumed nominal value' for row in rows))

    def test_match_exhaustiveness_declared_order_and_shared_scalar_carry(self):
        types = [record('Pair', [('a', 'u8'), ('z', 'u16')]), record('Empty', []),
                 enum('Choice', [('first', [('n', 'u8')]), ('second', [('n', 'u16')])])]
        params = [('choice', 'Choice'), ('pair', 'Pair'), ('empty', 'Empty')]
        ops = [i('record.get', ['pair'], [('left_alias', 'u8')], field='a'),
               i('record.get', ['pair'], [('right_alias', 'u16')], field='z'),
               i('enum.tag', ['choice'], [('tag_alias', 'u32')])]
        args = ['pair', 'empty', 'left_alias', 'right_alias', 'tag_alias']
        first = ('first', 'one', args)
        second = ('second', 'two', args)
        def one(term, operations=ops):
            return f('choice', params, ['u8'], [], [b('entry', params, deepcopy(operations), term),
                b('one', [('payload_a', 'u8'), ('pair_a', 'Pair'), ('empty_a', 'Empty'),
                          ('left_a', 'u8'), ('right_a', 'u16'), ('tag_a', 'u32')], [], ret('left_a')),
                b('two', [('payload_b', 'u16'), ('pair_b', 'Pair'), ('empty_b', 'Empty'),
                          ('left_b', 'u8'), ('right_b', 'u16'), ('tag_b', 'u32')], [], ret('left_b'))])
        base = match('choice', first, second)
        cases = [one(base), one(match('choice', second, first))]
        for value in ('pair', 'missing', 'bad-name', 'h2internal_bad', 0):
            term = deepcopy(base); term['value'] = value; cases.append(one(term))
        for variant_cases in (0, [], [{}], [None], base['cases'][:1],
                              base['cases'] + base['cases'][:1],
                              [dict(variant='other', target='one', args=[]), base['cases'][1]]):
            term = deepcopy(base); term['cases'] = deepcopy(variant_cases); cases.append(one(term))
        for index in (0, 1):
            for key, value in [('variant', ''), ('variant', '__hia_bad'), ('variant', 'h2internal_bad'),
                               ('args', 0), ('args', ['bad-name']), ('args', ['h2internal_bad']),
                               ('args', ['missing']), ('target', 'missing'), ('target', 'bad-name'),
                               ('args', []), ('args', ['pair'])]:
                term = deepcopy(base); term['cases'][index][key] = value; cases.append(one(term))
        term = deepcopy(base)
        term['cases'][0]['target'] = 'missing'
        term['cases'][1]['args'] = ['bad-name']
        cases.append(one(term))
        term = deepcopy(base)
        term['cases'][1]['variant'] = 'first'
        term['cases'][1]['args'] = ['bad-name']
        cases.append(one(term))
        # The original first-pass/global SSA namespace allows the same scalar
        # representation to be present under record fields and projection names.
        rows = self.compare('match-scalar', packed(types, cases), custody=True)
        a, z = deepcopy(rows[0]['actual']['core']), deepcopy(rows[1]['actual']['core'])
        # Fresh serials deliberately continue across calls. Compare each to its
        # complete oracle above; ordering is also directly visible in block ops.
        self.assertEqual([block['term']['op'] for block in a['blocks']],
                         [block['term']['op'] for block in z['blocks']])

    def test_owned_match_zero_width_and_large_legal_variant_inventory(self):
        owned = enum('OwnedChoice', [('buffer_case', [('item', 'buffer')]),
                                     ('chain_case', [('item', 'chain')])])
        empty = record('Empty', [])
        choices = enum('ZeroChoice', [('v' + str(n), [('empty', 'Empty')]) for n in range(32)])
        params = [('choice', 'OwnedChoice'), ('other', 'buffer')]
        base = match('choice', ('buffer_case', 'buffer_arm', ['other']),
                     ('chain_case', 'chain_arm', ['other']))
        def one(term):
            return f('owned', params, [], ['alloc'], [b('entry', params, [], term),
                b('buffer_arm', [('a', 'buffer'), ('b', 'buffer')],
                  [i('owner.drop', ['a']), i('owner.drop', ['b'])], ret()),
                b('chain_arm', [('c', 'chain'), ('d', 'buffer')],
                  [i('owner.drop', ['c']), i('owner.drop', ['d'])], ret())])
        cases = [one(base), one(dict(op='match', value='choice', cases=list(reversed(base['cases']))))]
        for args in ([], ['other', 'other'], ['choice'], ['missing'], ['h2internal_bad']):
            term = deepcopy(base); term['cases'][0]['args'] = args; cases.append(one(term))
        term = deepcopy(base); term['cases'][1] = deepcopy(term['cases'][0]); cases.append(one(term))
        zero_params = [('zero', 'ZeroChoice'), ('empty', 'Empty')]
        zero_cases = [('v' + str(n), 'arm_' + str(n), ['empty']) for n in range(32)]
        zero_blocks = [b('entry', zero_params, [], match('zero', *reversed(zero_cases)))]
        zero_blocks += [b('arm_' + str(n), [('payload_' + str(n), 'Empty'), ('keep_' + str(n), 'Empty')],
                         [], ret()) for n in range(32)]
        cases.append(f('zero', zero_params, [], [], zero_blocks))
        rows = self.compare('match-owned-zero', packed([owned, empty, choices], cases), custody=True)
        self.assertEqual(rows[-1]['actual']['status'], 'accepted')
        self.assertEqual(len(rows[-1]['actual']['core']['blocks']), 97)

    def test_exact_fresh_boundaries_and_nonfirst_entry_returned_origins(self):
        types = [record('Empty', []), enum('Tag', [('a', []), ('b', [])])]
        params = [('tag', 'Tag')]
        function = f('boundary', params, [], [], [
            b('entry', params, [], match('tag', ('a', 'left', []), ('b', 'right', []))),
            b('left', [], [], ret()), b('right', [], [], ret())])
        doc = v4(types, function)
        count = self.compare('fresh-baseline', doc)[0]['actual']['serial']
        for serial in (8192 - count, 8193 - count, 8191, 8192):
            rows = self.compare('fresh-' + str(serial), doc, serial=serial, calls=[0, 0])
            self.assertEqual(rows[0]['actual']['serial'], 8192)
        empty_fn = f('empty', [('input', 'Empty')], ['Empty'], [],
                     [b('entry', [('input', 'Empty')], [], ret('input'))])
        rows = self.compare('zero-at-max', v4(types, empty_fn), serial=8192, slots=32768, calls=[0, 0])
        self.assertEqual(rows[-1]['actual']['status'], 'accepted')
        loan_types = [record('Inner', [('left', 'readbuf'), ('right', 'mutbuf')]),
                      record('Outer', [('header', 'u16'), ('inner', 'Inner')]), record('Empty', [])]
        params = [('views', 'Outer'), ('zero', 'Empty')]
        fn = f('origins', params, ['readbuf', 'Empty', 'mutbuf'], [], [
            b('unused', [], [], {'op': 'trap', 'code': 'user'}),
            b('entry', params, [i('record.unpack', ['views'], [('header', 'u16'), ('inner', 'Inner')]),
                i('record.unpack', ['inner'], [('left', 'readbuf'), ('right', 'mutbuf')])],
                ret('left', 'zero', 'right'))])
        fn['entry'] = 'entry'
        fn['return_loans'] = [origin('views', 'inner', 'left'), None,
                              origin('views', 'inner', 'right')]
        rows = self.compare('origins-nonfirst-entry', v4(loan_types, fn), custody=True)
        core = rows[0]['actual']['core']
        self.assertEqual(core['return_loans'], ['h2internal_2', 'h2internal_3'])
        self.assertEqual(core['params'][0]['type'], 'u16')

    def test_large_output_is_completed_before_later_function_error(self):
        types = [record('A', [('p' + str(n), 'u8') for n in range(64)]),
                 record('Wide', [('part' + str(n), 'A') for n in range(8)])]
        params = [('input', 'Wide')]
        large = f('large', params, ['Wide'] * 1000, [],
                  [b('entry', params, [], ret(*(['input'] * 1000)))])
        later = f('later', [], [], [], [b('entry', [], [], ret())])
        later['blocks'] = 0
        document = v4(types, large, later)
        rows = self.compare('large-before-later-error', document, calls=[0, 1, 1])
        core = rows[0]['actual']['core']
        self.assertGreater(len(wire(core)), 8 << 20)
        self.assertEqual(len(core['returns']), 512000)
        self.assertEqual(len(core['blocks'][0]['term']['values']), 512000)
        self.assertEqual(rows[1]['actual']['error'],
                         dict(code='E_HIA_CFG', message='E_HIA_CFG: invalid nominal block inventory'))
        # The retained outer gate remains responsible for final expanded Core
        # inventory/structure. Do not add an early per-function output quota.
        core_module = dict(schema=SCHEMA_V8, module='large', exports=[], functions=[core])
        with self.assertRaises(HIAProgramRejected) as refused:
            verify_core(core_module)
        self.assertEqual(refused.exception.code, 'E_HIA_LIMIT')

    def test_widest_enum_repeated_wide_edges_and_many_zero_width_formals(self):
        atom = record('Atom', [('p' + str(n), 'u8') for n in range(64)])
        tail = record('Tail', [('p' + str(n), 'u8') for n in range(63)])
        wide = record('Wide', [('part' + str(n), 'Atom') for n in range(7)] + [('tail', 'Tail')])
        choice = enum('WideChoice', [('only', [('payload', 'Wide')])])
        types = [atom, tail, wide, choice]
        params = [('input', 'WideChoice')]
        function = f('wide', params, [], [], [
            b('entry', params, [], match('input', ('only', 'arm', []))),
            b('arm', [('payload', 'Wide')], [], ret())])
        rows = self.compare('match-maximum-flat-width', v4(types, function), custody=True)
        self.assertEqual(rows[0]['actual']['status'], 'accepted')
        self.assertEqual(len(rows[0]['actual']['core']['params']), 512)
        tag = enum('Tag', [('left', []), ('right', [])])
        empty = record('Empty', [])
        params = [('choice', 'Tag'), ('value', 'Atom')]
        repeated = ['value'] * 48
        function = f('repeated', params, [], [], [
            b('entry', params, [], match('choice', ('left', 'left', repeated), ('right', 'right', repeated))),
            b('left', [('a' + str(n), 'Atom') for n in range(48)], [], ret()),
            b('right', [('z' + str(n), 'Atom') for n in range(48)], [], ret())])
        rows = self.compare('match-repeated-wide-arguments', v4([atom, tag], function))
        self.assertEqual(rows[0]['actual']['status'], 'accepted')
        arms = [block for block in rows[0]['actual']['core']['blocks']
                if block['term']['op'] == 'jump']
        self.assertEqual([len(block['term']['args']) for block in arms], [3072, 3072])
        params = [('choice', 'Tag'), ('zero', 'Empty')]
        repeated = ['zero'] * 1024
        function = f('zero', params, [], [], [
            b('entry', params, [], match('choice', ('left', 'left', repeated), ('right', 'right', repeated))),
            b('left', [('a' + str(n), 'Empty') for n in range(1024)], [], ret()),
            b('right', [('z' + str(n), 'Empty') for n in range(1024)], [], ret())])
        rows = self.compare('match-many-zero-width-arguments', v4([empty, tag], function))
        self.assertEqual(rows[0]['actual']['status'], 'accepted')
        self.assertEqual(rows[0]['actual']['value_slots'], 1)

    def test_generated_match_cfg_executes_both_variants(self):
        choice = enum('Choice', [('left', [('n', 'u8')]), ('right', [('n', 'u8')])])
        params = [('value', 'u8'), ('condition', 'bool')]
        fn = f('select', params, ['u8'], ['trap'], [
            b('entry', params, [], branch('condition', ('make_left', 'value'), ('make_right', 'value'))),
            b('make_left', [('left_input', 'u8')], [
                i('enum.make', ['left_input'], [('left_choice', 'Choice')], variant='left')],
                jump('inspect', 'left_choice')),
            b('make_right', [('right_input', 'u8')], [
                i('enum.make', ['right_input'], [('right_choice', 'Choice')], variant='right')],
                jump('inspect', 'right_choice')),
            b('inspect', [('choice', 'Choice')], [],
                match('choice', ('right', 'right_arm', []), ('left', 'left_arm', []))),
            b('left_arm', [('left_payload', 'u8')], [], ret('left_payload')),
            b('right_arm', [('right_payload', 'u8')], [c('one', 'u8', 1),
                i('int.add.wrap', ['right_payload', 'one'], [('changed', 'u8')])], ret('changed'))])
        rows = self.compare('executed-match', v4([choice], fn))
        core = dict(schema=SCHEMA_V8, module='executed_match', exports=['select'],
                    functions=[rows[0]['actual']['core']])
        checked = verify_core(core)
        observations = []
        for value in (0, 1, 127, 255):
            for condition in (False, True):
                report = execute_program(checked, 'select', [value, condition])
                self.assertEqual(report['result'], value if condition else (value + 1) & 255)
                observations.append(dict(value=value, condition=condition, report=report))
        if self.evidence is not None:
            (self.evidence / 'executed-match.observations.json').write_bytes(wire(observations))


if __name__ == '__main__':
    unittest.main()
