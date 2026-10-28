"""Independent incremental-cache adversarial cases at call and edit boundaries."""
import copy
import json
import threading
import unittest
from unittest import mock

from hepta import hia_program as core
from hepta.hia_incremental import IncrementalVerifier
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected, apply_program_patch
from tests.test_hia_program import b, c, f, i, ret


def alias_module():
    caller = f('outer', [], ['u8'], ['alloc', 'read', 'write', 'trap'], [b('entry', [], [
        c('size', 'usize', 1), i('buffer.new', ['size'], [('owner', 'buffer')]),
        i('borrow.mut', ['owner'], [('view', 'mutbuf')]),
        i('call', ['view', 'view'], [('result', 'u8')], function='combine'),
        i('loan.end', ['view']), i('owner.drop', ['owner']),
    ], ret('result'))])
    params = [('left', 'readbuf'), ('right', 'readbuf')]
    callee = f('combine', params, ['u8'], ['read', 'trap'], [b('entry', params, [
        c('zero', 'usize', 0),
        i('buffer.load', ['left', 'zero'], [('a', 'u8')]),
        i('buffer.load', ['right', 'zero'], [('z', 'u8')]),
        i('int.add.wrap', ['a', 'z'], [('result', 'u8')]),
    ], ret('result'))])
    spare = f('spare', [], ['u8'], [], [b('entry', [], [c('value', 'u8', 19)], ret('value'))])
    return {'schema': 'hepta.hia.program.v7', 'module': 'independent_incremental',
            'exports': ['outer', 'spare'], 'functions': [caller, callee, spare]}


def outcome(check, candidate):
    try:
        value = check(candidate)
        if isinstance(value, tuple):
            value = value[0]
        return ('accepted', value.canonical_bytes, value.structured_bytes)
    except (core.HIAProgramRejected, HIAEditRejected) as exc:
        return ('rejected', type(exc).__name__, str(exc))


class IndependentIncrementalBoundaryTests(unittest.TestCase):
    def test_readonly_to_exclusive_formal_invalidates_unchanged_aliased_caller(self):
        original = alias_module()
        session = IncrementalVerifier(original)
        base = session.base_sha256
        candidate = copy.deepcopy(original)
        for params in (candidate['functions'][1]['params'],
                       candidate['functions'][1]['blocks'][0]['params']):
            params[1]['type'] = 'mutbuf'
        expected = outcome(core.verify_core, candidate)
        self.assertEqual(expected[0], 'rejected')
        self.assertIn('E_HIA_LOAN', expected[2])
        self.assertEqual(outcome(session.verify, candidate), expected)
        self.assertEqual(session.last_report['dependency_invalidations'], {'outer': ['combine']})
        self.assertEqual(session.last_report['functions_body_attempted'], ['outer'])
        self.assertEqual(session.base_sha256, base)
        _, report = session.verify(original)
        self.assertEqual(report['functions_body_completed'], [])
        self.assertEqual(execute_program(original, 'outer', [])['result'], 0)

    def test_new_resource_body_cannot_hide_behind_unchanged_signature(self):
        original = alias_module()
        session = IncrementalVerifier(original)
        candidate = copy.deepcopy(original)
        ops = candidate['functions'][0]['blocks'][0]['ops']
        ops[5] = c('pretend_drop', 'unit', None)
        expected = outcome(core.verify_core, candidate)
        self.assertEqual(expected[0], 'rejected')
        self.assertIn('E_HIA_RESOURCE', expected[2])
        self.assertEqual(outcome(session.verify, candidate), expected)
        self.assertEqual(session.base_sha256, core.verify_core(original).sha256)

    def test_callee_parameter_rename_invalidates_named_interface_and_caller(self):
        original = alias_module()
        seen = []
        original_check = core._verify_function

        def observed(schema, fn, blocks, interfaces):
            seen.append(fn['name'])
            return original_check(schema, fn, blocks, interfaces)

        with mock.patch.object(core, '_verify_function', observed):
            session = IncrementalVerifier(original)
            seen.clear()
            candidate = copy.deepcopy(original)
            callee = candidate['functions'][1]
            callee['params'][1]['name'] = 'renamed'
            callee['blocks'][0]['params'][1]['name'] = 'renamed'
            callee['blocks'][0]['ops'][2]['args'][0] = 'renamed'
            verified, report = session.verify(candidate)
            self.assertEqual(seen, ['outer', 'combine'])
            self.assertEqual(report['dependency_invalidations'], {'outer': ['combine']})
            self.assertEqual(report['functions_body_reused'], ['spare'])
            self.assertEqual(verified.canonical_bytes, core.verify_core(candidate).canonical_bytes)

    def test_removed_readded_callee_does_not_reuse_a_rejected_attempt(self):
        original = alias_module()
        session = IncrementalVerifier(original)
        missing = copy.deepcopy(original)
        missing['functions'].pop(1)
        self.assertEqual(outcome(session.verify, missing), outcome(core.verify_core, missing))
        self.assertEqual(session.base_sha256, core.verify_core(original).sha256)
        repaired = copy.deepcopy(original)
        repaired['functions'][1]['blocks'][0]['ops'][-1]['op'] = 'bit.xor'
        checked, report = session.verify(repaired)
        self.assertEqual(report['functions_body_completed'], ['combine'])
        self.assertEqual(report['functions_body_reused'], ['outer', 'spare'])
        self.assertEqual(checked.canonical_bytes, core.verify_core(repaired).canonical_bytes)

    def test_concurrent_snapshot_bound_patches_have_exactly_one_winner(self):
        original = alias_module()
        session = IncrementalVerifier(original)
        base = session.base_sha256
        barrier = threading.Barrier(3)
        successes, errors = [], []

        def worker(value):
            request = {'schema': 'hepta.hia.patch.v1', 'expected_sha256': base, 'edits': [
                {'action': 'replace_operation', 'function': 'spare', 'block': 'entry', 'index': 0,
                 'operation': c('value', 'u8', value)}]}
            try:
                barrier.wait(timeout=10)
                checked, receipt = session.apply_patch(request)
                successes.append((request, checked, receipt))
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(value,)) for value in (23, 71)]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], HIAEditRejected)
        self.assertIn('stale base snapshot', str(errors[0]))
        request, checked, receipt = successes[0]
        ordinary, _ = apply_program_patch(original, request)
        self.assertEqual(checked.canonical_bytes, ordinary.canonical_bytes)
        self.assertEqual(session.base_sha256, checked.sha256)
        self.assertEqual(receipt['verification']['functions_body_completed'], ['spare'])

    def test_partial_record_nominal_input_and_forged_binding_force_full_check(self):
        from tools.qualify_hia_partial_records import program
        nominal = program()
        session = IncrementalVerifier(nominal)
        bound, report = session.verify(nominal)
        self.assertEqual(report['mode'], 'full')
        self.assertEqual(report['functions_body_reused'], [])
        self.assertEqual(bound.structured_bytes, core.verify_core(nominal).structured_bytes)
        changed = copy.deepcopy(nominal)
        changed['module'] = 'different_nominal_identity'
        forged = core.VerifiedProgram(bound.canonical_bytes, json.dumps(changed).encode())
        expected = outcome(core.verify_core, forged)
        self.assertEqual(expected[0], 'rejected')
        self.assertEqual(outcome(session.verify, forged), expected)
        self.assertEqual(session.base_sha256, bound.sha256)

    def test_receipt_mutation_cannot_change_subsequent_interface_decisions(self):
        original = alias_module()
        session = IncrementalVerifier(original)
        _, receipt = session.verify(original)
        receipt['claims']['caller_digest_grants_admission'] = True
        receipt['functions_body_reused'] = ['invented']
        returned = session.last_report
        returned['dependency_invalidations']['outer'] = []
        changed = copy.deepcopy(original)
        changed['functions'][1]['effects'].append('alloc')
        # Caller already declares alloc: this is a valid interface edit that
        # still requires checking its cached loan call again.
        checked, report = session.verify(changed)
        self.assertEqual(report['functions_body_completed'], ['outer', 'combine'])
        self.assertEqual(report['dependency_invalidations'], {'outer': ['combine']})
        self.assertFalse(report['claims']['caller_digest_grants_admission'])
        self.assertEqual(checked.canonical_bytes, core.verify_core(changed).canonical_bytes)


if __name__ == '__main__':
    unittest.main()
