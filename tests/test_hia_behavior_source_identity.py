"""Current frozen behavior inputs, with real finite VM mutation controls."""
from __future__ import annotations

from hashlib import sha256
import os
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as service
from hepta import hia_program as program
from hepta import hia_program_runtime as runtime
from tools.hia_agent_native_qualification import add_program
from tests.test_hia_program import arithmetic


class BehaviorSourceIdentityTests(unittest.TestCase):
    def setUp(self):
        clean = {key: value for key, value in os.environ.items()
                 if not key.startswith('HEPTA_HIA_')}
        environment = patch.dict(os.environ, clean, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.owner = object.__new__(service.HIAAgentService)

    def routes(self):
        return (
            ('public-components', self.owner._behavior_equivalence),
            ('retained-reference', self.owner._behavior_equivalence_reference),
        )

    def inputs(self, *, different=False):
        left = program.verify_program(add_program(
            redundant_additions=2, increment=8 if different else 7))
        right = program.verify_program(add_program(optimized=True))
        wrong = program.verify_program(add_program(optimized=True, increment=8))
        return left, right, wrong

    def test_unchanged_snapshots_execute_every_original_vm_call(self):
        for name, call in self.routes():
            with self.subTest(route=name):
                left, right, _ = self.inputs()
                delegate, calls = runtime._execute_verified_program, []
                def execute(*args, **kwargs):
                    result = delegate(*args, **kwargs)
                    calls.append(result)
                    return result
                with patch.object(runtime, '_execute_verified_program', execute):
                    result = call(left, right, 10000)
                self.assertEqual(result[0], 'proved', result)
                self.assertEqual(len(calls), 512)
                self.assertEqual(result[2]['checked'], 256)
                self.assertEqual(result[2]['base_sha256'], left.sha256)
                self.assertEqual(result[2]['candidate_sha256'], right.sha256)
                self.assertTrue(result[2]['complete'])

    def test_observed_early_equivalent_change_cannot_regain_authority(self):
        for name, call in self.routes():
            with self.subTest(route=name):
                left, right, _ = self.inputs()
                initial = left.canonical_bytes
                delegate, calls = runtime._execute_verified_program, []
                def execute(*args, **kwargs):
                    result = delegate(*args, **kwargs)
                    calls.append(result)
                    if len(calls) == 1:
                        object.__setattr__(left, 'canonical_bytes', right.canonical_bytes)
                    elif len(calls) == 512:
                        object.__setattr__(left, 'canonical_bytes', initial)
                    return result
                with patch.object(runtime, '_execute_verified_program', execute):
                    result = call(left, right, 10000)
                self.assertEqual(len(calls), 512)
                self.assertEqual(left.canonical_bytes, initial)
                self.assertEqual(result[0], 'unknown', result)
                self.assertEqual(result[2]['checked'], 256)
                self.assertFalse(result[2]['complete'])
                self.assertFalse(result[2]['source_unchanged'])

    def test_last_actual_call_cannot_relabel_the_executed_program(self):
        for name, call in self.routes():
            with self.subTest(route=name):
                left, right, wrong = self.inputs()
                delegate, calls = runtime._execute_verified_program, []
                def execute(*args, **kwargs):
                    result = delegate(*args, **kwargs)
                    calls.append(result)
                    if len(calls) == 512:
                        object.__setattr__(left, 'canonical_bytes', wrong.canonical_bytes)
                    return result
                with patch.object(runtime, '_execute_verified_program', execute):
                    result = call(left, right, 10000)
                self.assertEqual(len(calls), 512)
                self.assertEqual(result[0], 'unknown', result)
                self.assertEqual(result[2]['checked'], 256)
                self.assertFalse(result[2]['complete'])
                self.assertFalse(result[2]['source_unchanged'])

    def test_between_checks_aba_executes_the_initial_inequivalent_graphs(self):
        for name, call in self.routes():
            with self.subTest(route=name):
                left, right, _ = self.inputs(different=True)
                initial = left.canonical_bytes
                delegate, calls = runtime._execute_verified_program, []
                def execute(*args, **kwargs):
                    object.__setattr__(left, 'canonical_bytes', right.canonical_bytes)
                    try:
                        result = delegate(*args, **kwargs)
                        calls.append(result)
                        return result
                    finally:
                        object.__setattr__(left, 'canonical_bytes', initial)
                with patch.object(runtime, '_execute_verified_program', execute):
                    result = call(left, right, 10000)
                self.assertEqual(left.canonical_bytes, initial)
                self.assertEqual(len(calls), 2)
                self.assertEqual(result[0], 'refuted', result)
                self.assertEqual(result[2]['counterexample'],
                                 {'function': 'transform', 'arguments': [0]})
                self.assertEqual(result[2]['before']['values'], [8])
                self.assertEqual(result[2]['after']['values'], [7])

    def test_between_checks_aba_cannot_replace_an_initial_equivalent_graph(self):
        for name, call in self.routes():
            with self.subTest(route=name):
                left, right, wrong = self.inputs()
                initial = left.canonical_bytes
                delegate, calls = runtime._execute_verified_program, []
                def execute(*args, **kwargs):
                    object.__setattr__(left, 'canonical_bytes', wrong.canonical_bytes)
                    try:
                        result = delegate(*args, **kwargs)
                        calls.append(result)
                        return result
                    finally:
                        object.__setattr__(left, 'canonical_bytes', initial)
                with patch.object(runtime, '_execute_verified_program', execute):
                    result = call(left, right, 10000)
                self.assertEqual(len(calls), 512)
                self.assertEqual(result[0], 'proved', result)
                self.assertEqual(result[2]['base_sha256'], sha256(initial).hexdigest())
                self.assertEqual(left.canonical_bytes, initial)

    def test_transcript_digest_is_followed_by_the_terminal_binding_check(self):
        for name, call in self.routes():
            with self.subTest(route=name):
                left, right, wrong = self.inputs()
                delegate, calls = runtime._execute_verified_program, []
                def execute(*args, **kwargs):
                    result = delegate(*args, **kwargs)
                    calls.append(result)
                    return result
                class Transcript:
                    def __init__(self):
                        self.inner = sha256()
                    def update(self, raw):
                        self.inner.update(raw)
                    def hexdigest(self):
                        object.__setattr__(left, 'canonical_bytes', wrong.canonical_bytes)
                        return self.inner.hexdigest()
                def checksum(*args, **kwargs):
                    return Transcript() if not args and not kwargs else sha256(*args, **kwargs)
                with patch.object(runtime, '_execute_verified_program', execute), \
                        patch.object(service, 'sha256', checksum):
                    result = call(left, right, 10000)
                self.assertEqual(len(calls), 512)
                self.assertEqual(result[0], 'unknown', result)
                self.assertFalse(result[2]['source_unchanged'])

    def test_structured_identity_is_bound_even_when_canonical_bytes_match(self):
        for name, call in self.routes():
            with self.subTest(route=name):
                left, right, _ = self.inputs()
                delegate, calls = runtime._execute_verified_program, []
                def execute(*args, **kwargs):
                    result = delegate(*args, **kwargs)
                    calls.append(result)
                    if len(calls) == 512:
                        object.__setattr__(left, 'structured_bytes', b'{}')
                    return result
                with patch.object(runtime, '_execute_verified_program', execute):
                    result = call(left, right, 10000)
                self.assertEqual(len(calls), 512)
                self.assertEqual(result[0], 'unknown', result)
                self.assertFalse(result[2]['source_unchanged'])

    def test_unbound_observer_aba_cannot_supply_a_complete_proof(self):
        for name, call in self.routes():
            with self.subTest(route=name):
                left, right, _ = self.inputs(different=True)
                delegate, calls = service._vm_observation, []
                def observe(subject, case, **kwargs):
                    captured = subject.canonical_bytes
                    object.__setattr__(subject, 'canonical_bytes', right.canonical_bytes)
                    try:
                        result = delegate(subject, case, **kwargs)
                        calls.append(result)
                        return result
                    finally:
                        object.__setattr__(subject, 'canonical_bytes', captured)
                with patch.object(service, '_vm_observation', observe):
                    result = call(left, right, 10000)
                self.assertEqual(len(calls), 512)
                self.assertEqual(result[0], 'unknown', result)
                self.assertFalse(result[2]['complete'])
                self.assertFalse(result[2]['source_unchanged'])

    def test_selected_admission_observes_original_snapshot_bytes_each_time(self):
        for name, call in self.routes():
            with self.subTest(route=name):
                left, right, _ = self.inputs()
                admitted = []
                def admission(raw):
                    admitted.append(raw)
                    return program._verify_program_reference(raw)
                with program.native_verified_program_scope(admission):
                    result = call(left, right, 10000)
                self.assertEqual(result[0], 'proved', result)
                self.assertEqual(result[2]['checked'], 256)
                self.assertEqual(len(admitted), 514)
                self.assertEqual(set(admitted), {left.canonical_bytes, right.canonical_bytes})

    def test_solver_effect_receives_captured_inputs_and_is_checked_after_return(self):
        # This controls the foreign result boundary; it does not qualify a solver.
        from hepta import hia_optimization
        for name, call in self.routes():
            with self.subTest(route=name):
                left = program.verify_program(arithmetic())
                right = program.verify_program(arithmetic('int.mul.checked'))
                captured = (left.canonical_bytes, right.canonical_bytes)
                seen = []
                def solver(first, second, policy):
                    self.assertIsNot(first, left)
                    self.assertIsNot(second, right)
                    self.assertEqual((first.canonical_bytes, second.canonical_bytes), captured)
                    seen.append(policy)
                    object.__setattr__(left, 'canonical_bytes', right.canonical_bytes)
                    return {'status': 'verified', 'scope': 'controlled-foreign-result'}
                with patch.object(hia_optimization, 'verify_optimization', solver):
                    result = call(left, right, 10000)
                self.assertEqual(len(seen), 1)
                self.assertEqual(result[0], 'unknown', result)
                self.assertFalse(result[2]['source_unchanged'])


if __name__ == '__main__':
    unittest.main()
