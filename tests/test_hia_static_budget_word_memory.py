"""Additive v9 resource-profile controls; original v7/v8 fixtures stay frozen."""
from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from hepta import hia_static_budget as owner
from hepta import hia_static_budget_native as native
from hepta.hia_agent_assembly import assemble_program
from tests import test_hia_static_budget_native as controls
from tests.test_hia_static_budget_native import (
    frame, interpret, observed, poison)
from tools.hia_word_memory_cases import acyclic_program, foreign_program, owned_program

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/static_budget_word_memory_d998.py.txt'
FIXTURE_SHA = '827962b3c788c94c24f387b60798a666ec24cad8cdb1c3ea7ae9884366e8f907'
FIXTURE_COMMIT = 'd99855451c8140899c85cf264b330a81a1c00362'


def original_word_owner():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA:
        raise AssertionError('independent d998 word-memory resource fixture changed')
    scope = {'__name__': 'hepta._original_word_memory_static_budget', '__package__': 'hepta'}
    exec(compile(raw, str(FIXTURE), 'exec'), scope)
    return scope


def profile_documents():
    fn = {'name': 'z', 'params': [], 'returns': sorted(owner._V8_BYTE_TYPES),
          'blocks': [{'params': [], 'term': {'op': 'ret'},
                      'ops': [{'op': op, 'out': []}
                              for op in sorted(owner._V8_BYTE_OPS | owner._V9_WORD_OPS)]}]}
    doc = {'schema': owner._V9_SCHEMA, 'functions': [fn, deepcopy(fn)]}
    doc['functions'][1]['name'] = 'a'
    yield 'valid', doc
    for target in ('schema', 'term', 'op', 'type', 'chain'):
        bad = deepcopy(doc)
        if target == 'schema':
            bad['schema'] = 'hepta.hia.program.v8'
        elif target == 'term':
            bad['functions'][0]['blocks'][0]['term']['op'] = 'future'
        elif target == 'op':
            bad['functions'][0]['blocks'][0]['ops'][0]['op'] = 'future'
        else:
            bad['functions'][0]['returns'].append('chain' if target == 'chain' else 'future')
        yield target, bad
    # An opcode error in the first function precedes its type error; a first
    # function type error precedes a later function's terminator error.
    for earlier in ('op', 'type'):
        bad = deepcopy(doc)
        bad['functions'][0]['returns'].append('future')
        if earlier == 'op':
            bad['functions'][0]['blocks'][0]['ops'][0]['op'] = 'future'
        else:
            bad['functions'][1]['blocks'][0]['term']['op'] = 'future'
        yield 'ordered-' + earlier, bad


class StaticBudgetWordMemorySourceTests(unittest.TestCase):
    def test_all_original_profile_words_and_outside_extent_in_actual_hia(self):
        import ast
        from hepta.hia_program_runtime import _Machine
        from tools import generate_hia_static_budget as generator
        frozen = original_word_owner()
        groups = [('ret', 'trap', 'jump', 'branch'), sorted(frozen['_V8_BYTE_OPS']),
                  sorted(frozen['_V8_BYTE_TYPES']), sorted(frozen['_V8_CHAIN_OPS']),
                  ['chain'], sorted(frozen['_V9_WORD_OPS'])]
        words = []
        for group in groups:
            for token in group:
                raw = token.encode('ascii')
                words.append(len(raw))
                words.extend(int.from_bytes(raw[at:at + 8].ljust(8, b'\0'), 'little')
                             for at in range(0, len(raw), 8))
        self.assertEqual(len(words), 197)
        names = [node.name for node in ast.parse(generator.source()).body]
        entry = 'f' + str(names.index('profile_word'))
        program = assemble_program(native.SOURCE.read_bytes())
        machine = _Machine(program, 10_000_000, 8 << 20, None, 128)
        for index, expected in enumerate(words):
            with self.subTest(index=index):
                self.assertEqual(machine.invoke(machine.functions[entry], [index]), [expected])
        for index in (len(words), len(words) + 1, 1 << 32, 1 << 63, (1 << 64) - 1):
            with self.subTest(outside=index):
                self.assertEqual(machine.invoke(machine.functions[entry], [index]), [0])

    def test_v9_reports_match_independent_branch_original_without_selection(self):
        frozen = original_word_owner()
        with patch.dict(os.environ):
            os.environ.pop(native.SELECTOR, None)
            for doc in (acyclic_program(), foreign_program(), owned_program()):
                self.assertEqual(observed(owner.analyze_static_budget, doc),
                                 observed(frozen['analyze_static_budget'], doc))
                self.assertEqual(observed(owner.qualify_vm_call_depth, doc, max_call_depth=1),
                                 observed(frozen['qualify_vm_call_depth'], doc, max_call_depth=1))

    def test_original_packet_mode_rejects_word_operations_before_explicit_v9_mode(self):
        program = assemble_program(native.SOURCE.read_bytes())
        doc = acyclic_program()
        for allow in (False, True):
            legacy = native.profile_packet(doc, owner._V9_SCHEMA, allow)
            expanded = native.profile_packet(doc, owner._V9_SCHEMA, allow, word_memory=True)
            self.assertEqual(legacy[:8] + legacy[16:], expanded[:8] + expanded[16:])
            self.assertEqual(struct.unpack_from('<Q', legacy, 8)[0], 3)
            self.assertEqual(struct.unpack_from('<Q', expanded, 8)[0], 5)
            old = interpret(program, legacy, 3, len(doc['functions']))
            new = interpret(program, expanded, 5, len(doc['functions']))
            self.assertEqual((old[0], struct.unpack_from('<2Q', old[1], 16)), (0, (3, 0)))
            self.assertEqual((new[0], struct.unpack_from('<2Q', new[1], 16)), (0, (0, 0)))

    def test_word_profile_refusal_order_matches_independent_v9_original(self):
        frozen = original_word_owner()
        for label, doc in profile_documents():
            for allow in (False, True):
                with self.subTest(case=label, allow_chain=allow):
                    self.assertEqual(observed(owner._reference_audit_resource_profile, doc,
                                              schema=owner._V9_SCHEMA, allow_chain=allow, word_memory=True),
                                     observed(frozen['_audit_resource_profile'], doc,
                                              schema=owner._V9_SCHEMA, allow_chain=allow, word_memory=True))


class StaticBudgetWordMemoryNativeTests(unittest.TestCase):
    # Reuse the unchanged compiler/cold/manifest custody setup, without
    # inheriting or changing any of the original class's test method inventory.
    setUpClass = controls.StaticBudgetNativeTests.__dict__['setUpClass']
    tearDownClass = controls.StaticBudgetNativeTests.__dict__['tearDownClass']

    def test_explicit_word_profile_complete_buffers_and_ordered_refusals(self):
        frozen = original_word_owner()
        for label, doc in profile_documents():
            for allow in (False, True):
                with self.subTest(case=label, allow_chain=allow):
                    raw = native.profile_packet(doc, owner._V9_SCHEMA, allow, word_memory=True)
                    self.assertEqual(frame(self.image, raw, 5, len(doc['functions'])),
                                     interpret(self.program, raw, 5, len(doc['functions'])))
                    self.assertEqual(observed(self.image.audit_profile, doc, schema=owner._V9_SCHEMA,
                                              allow_chain=allow, word_memory=True),
                                     observed(frozen['_audit_resource_profile'], doc, schema=owner._V9_SCHEMA,
                                              allow_chain=allow, word_memory=True))
        doc = acyclic_program()
        with self.assertRaisesRegex(owner.HIAStaticBudgetRejected, 'opcode lacks this'):
            self.image.audit_profile(doc, schema=owner._V9_SCHEMA, allow_chain=False)

    def test_public_v9_reports_use_native_owner_with_all_host_owners_forbidden(self):
        frozen = original_word_owner()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}))
            poison(stack)
            for doc in (acyclic_program(), foreign_program(), owned_program()):
                for policy in ({}, {'max_vm_ticks': 0}, {'max_allocator_interactions': 1}):
                    self.assertEqual(observed(owner.analyze_static_budget, doc, **policy),
                                     observed(frozen['analyze_static_budget'], doc, **policy))
                for depth in (1, 2, 256):
                    self.assertEqual(observed(owner.qualify_vm_call_depth, doc, max_call_depth=depth),
                                     observed(frozen['qualify_vm_call_depth'], doc, max_call_depth=depth))
