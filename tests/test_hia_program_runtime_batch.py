"""Reference proof preparation preserves full VM and admission semantics."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import os
import sys
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as service
from hepta import hia_program as program
from hepta import hia_program_runtime as runtime
from hepta.hia_agent_store import wire
from hepta.hia_static_budget import HIAStaticBudgetRejected
from hepta.hia_program_runtime_batch import prepare_reference_execution
from tests.test_hia_program import arithmetic, b, f, i, m, resource_program, ret
from tools.hia_agent_native_qualification import add_program


def observe(execute, function, arguments, **limits):
    try:
        return ('returned', execute(function, arguments, **limits))
    except (program.HIAProgramRejected, HIAStaticBudgetRejected, runtime.HIAProgramTrap,
            runtime.HIAProgramBudgetExceeded) as error:
        return (type(error), error.code, error.args, getattr(error, 'report', None))


class ReferenceExecutionTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {key: value for key, value in os.environ.items()
            if not key.startswith('HEPTA_HIA_')}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.service = object.__new__(service.HIAAgentService)

    def test_full_u8_domain_keeps_original_reports_ticks_and_transcript(self):
        left = program.verify_program(add_program(redundant_additions=128))
        right = program.verify_program(add_program(optimized=True))
        plans = [prepare_reference_execution(item) for item in (left, right)]
        self.assertTrue(all(plans))
        transcript = sha256()
        for value in range(256):
            rows = []
            for item, prepared in zip((left, right), plans):
                actual = prepared('transform', [value], max_steps=10000)
                expected = runtime.execute_program(item, 'transform', [value], max_steps=10000)
                self.assertEqual(actual, expected)
                self.assertEqual(actual['values'], [(value + 7) & 255])
                rows.append({'status': 'returned', 'values': expected['values'],
                             'first_trap': None, 'resources': expected['resources']})
            transcript.update(wire({'case': {'function': 'transform', 'arguments': [value]},
                                    'before': rows[0], 'after': rows[1]}))
        calls = Counter()
        def trace(frame, event, arg):
            if event == 'call':
                calls[frame.f_code] += 1
        before = sys.getprofile()
        sys.setprofile(trace)
        try:
            result = self.service._behavior_equivalence(left, right, 10000)
        finally:
            sys.setprofile(before)
        self.assertEqual(result[0], 'proved', result)
        self.assertEqual(result[2]['checked'], 256)
        self.assertEqual(result[2]['required'], 256)
        self.assertTrue(result[2]['complete'])
        self.assertTrue(result[2]['all_inputs_in_declared_widths'])
        self.assertEqual(result[2]['transcript_sha256'], transcript.hexdigest())
        self.assertEqual(calls[program._verify_program_reference.__code__], 2)
        self.assertEqual(calls[service.HIAAgentService._behavior_equivalence_with_components.__code__], 1)
        self.assertEqual(calls[runtime._execute_verified_program.__code__], 512)

    def test_traps_resources_budgets_and_argument_refusals_are_identical(self):
        cases = [(arithmetic(typ='u8'), 'calculate', [255, 1], {}),
                 (arithmetic('int.div.checked'), 'calculate', [1, 0], {}),
                 (arithmetic(), 'calculate', [1, 2], {'max_steps': 1}),
                 (arithmetic(), 'calculate', [True, 2], {}),
                 (arithmetic(), 'calculate', [1], {}),
                 (arithmetic(), 'missing', [], {}),
                 (arithmetic(), 'calculate', [1, 2], {'max_steps': True}),
                 (arithmetic(), 'calculate', [1, 2], {'max_heap_bytes': -1}),
                 (arithmetic(), 'calculate', [1, 2], {'bounded_resource_limits': {}}),
                 (resource_program(), 'owned', [4, 7], {}),
                 (resource_program(), 'owned', [4, 7], {'max_heap_bytes': 2}),
                 (resource_program(), 'owned', [4, 7], {'allocation_fail_at': 1})]
        recursive = m(f('again', [('x', 'i32')], ['i32'], [], [
            b('entry', [('x', 'i32')], [i('call', ['x'], [('y', 'i32')],
                                       function='again')], ret('y'))]))
        cases.append((recursive, 'again', [0], {'max_call_depth': 4}))
        for raw, name, arguments, limits in cases:
            with self.subTest(name=name, arguments=arguments, limits=limits):
                checked = program.verify_program(raw)
                prepared = prepare_reference_execution(checked)
                public = lambda name, args, **limits: runtime.execute_program(checked, name, args, **limits)
                expected = observe(public, name, arguments, **limits)
                self.assertEqual(observe(prepared, name, arguments, **limits), expected)
                self.assertEqual(observe(prepared, name, arguments, **limits), expected)

    def test_forged_and_changed_bytes_require_current_complete_admission(self):
        for forged in (program.VerifiedProgram(b'{}'),
                       program.VerifiedProgram(b'{}', b'{}')):
            with self.assertRaises(program.HIAProgramRejected):
                prepare_reference_execution(forged)
        checked = program.verify_program(arithmetic())
        prepared = prepare_reference_execution(checked)
        multiply = program.verify_program(arithmetic('int.mul.checked'))
        object.__setattr__(checked, 'canonical_bytes', multiply.canonical_bytes)
        self.assertFalse(prepared.current())
        self.assertEqual(prepared('calculate', [2, 3]), runtime.execute_program(checked, 'calculate', [2, 3]))
        self.assertEqual(prepared('calculate', [2, 3])['values'], [6])
        object.__setattr__(checked, 'structured_bytes', b'{}')
        with self.assertRaises(program.HIAProgramRejected):
            prepared('calculate', [2, 3])
        for field, value in (('_view', None), ('_program', multiply)):
            with self.assertRaises(AttributeError):
                setattr(prepared, field, value)
        with self.assertRaises(program.HIAProgramRejected):
            runtime.execute_program(prepared, 'calculate', [2, 3])

    def test_custom_providers_selectors_and_rebound_decoders_use_public_path(self):
        checked = program.verify_program(arithmetic())
        prepared = prepare_reference_execution(checked)
        class Derived(program.VerifiedProgram):
            pass
        class Custom:
            def __getattribute__(self, name):
                raise AssertionError('custom provider must not be consulted')
        self.assertIsNone(prepare_reference_execution(Derived(checked.canonical_bytes)))
        self.assertIsNone(prepare_reference_execution(Custom()))
        error = RuntimeError('selected decoder must still run')
        with patch.object(program, 'decode_internal_canonical', side_effect=error):
            self.assertIsNone(prepare_reference_execution(checked))
            self.assertFalse(prepared.current())
            with self.assertRaises(RuntimeError) as caught:
                prepared('calculate', [2, 3])
            self.assertIs(caught.exception, error)
        with patch.dict(os.environ, {'HEPTA_HIA_JSON_DECODE_MANIFEST': ''}):
            self.assertIsNone(prepare_reference_execution(checked))
            self.assertFalse(prepared.current())
            public = lambda name, args, **limits: runtime.execute_program(checked, name, args, **limits)
            # The original selected decoder exception, including its type and
            # message, must survive. It is not always a Core rejection.
            errors = []
            for execute in (public, prepared):
                try:
                    execute('calculate', [2, 3])
                except Exception as failure:
                    errors.append((type(failure), failure.args))
                else:
                    self.fail('empty selected decoder was accepted')
            self.assertEqual(errors[0], errors[1])
        authority_calls = []
        def authority(raw):
            authority_calls.append(raw)
            raise error
        token = program._VERIFIED_ADMISSION.set(authority)
        try:
            self.assertIsNone(prepare_reference_execution(checked))
            with self.assertRaises(RuntimeError) as caught:
                prepared('calculate', [2, 3])
            self.assertIs(caught.exception, error)
        finally:
            program._VERIFIED_ADMISSION.reset(token)
        self.assertEqual(authority_calls, [checked.canonical_bytes])
        with patch.object(runtime, 'execute_program', return_value={'custom': True}) as custom:
            self.assertIsNone(prepare_reference_execution(checked))
            self.assertEqual(prepared('calculate', [2, 3]), {'custom': True})
            custom.assert_called_once_with(checked, 'calculate', [2, 3])
        with patch.object(program.VerifiedProgram, 'scalar_entrypoints', property(lambda self: frozenset())):
            self.assertIsNone(prepare_reference_execution(checked))
            with self.assertRaises(program.HIAProgramRejected):
                prepared('calculate', [2, 3])

    def test_public_executor_revalidates_each_call_and_never_accepts_a_plan(self):
        checked = program.verify_program(arithmetic())
        with patch.object(runtime, 'verify_program', wraps=program.verify_program) as verifier:
            for _ in range(2):
                self.assertEqual(runtime.execute_program(checked, 'calculate', [2, 3])['values'], [5])
            self.assertEqual(verifier.call_count, 2)
        prepared = prepare_reference_execution(checked)
        with patch.object(runtime, 'execute_program', return_value={'qualified': True}) as public:
            result = prepared('calculate', [2, 3], bounded_resource_limits={'mode': 'custom'})
            self.assertEqual(result, {'qualified': True})
            public.assert_called_once_with(checked, 'calculate', [2, 3],
                                           bounded_resource_limits={'mode': 'custom'})

    def test_changed_source_during_enumeration_cannot_be_proved(self):
        left = program.verify_program(add_program(redundant_additions=128))
        right = program.verify_program(add_program(optimized=True))
        execute = runtime._execute_verified_program
        calls = []
        def mutate_after_execution(*args, **kwargs):
            result = execute(*args, **kwargs)
            if not calls:
                object.__setattr__(left, 'canonical_bytes', right.canonical_bytes)
            calls.append(True)
            return result
        with patch.object(runtime, '_execute_verified_program', mutate_after_execution):
            result = self.service._behavior_equivalence(left, right, 10000)
        self.assertEqual(result[0], 'unknown', result)
        self.assertEqual(result[2]['checked'], 256)
        self.assertFalse(result[2]['complete'])
        self.assertFalse(result[2]['source_unchanged'])

    def test_incomplete_and_expired_observations_remain_unknown(self):
        left = program.verify_program(add_program(redundant_additions=128))
        right = program.verify_program(add_program(optimized=True))
        with patch.object(service, '_vm_observation', return_value={'status': 'budget_exceeded'}) as custom:
            result = self.service._behavior_equivalence(left, right, 10000)
            self.assertEqual(result[0], 'unknown')
            self.assertEqual(result[2]['checked'], 0)
            self.assertFalse(result[2]['complete'])
            self.assertEqual(custom.call_count, 2)
            self.assertTrue(all('_execute' not in call.kwargs for call in custom.call_args_list))
        with patch.object(service.time, 'monotonic_ns', side_effect=[0, 10_000_000_001]):
            result = self.service._behavior_equivalence(left, right, 10000)
            self.assertEqual(result[0], 'unknown')
            self.assertEqual(result[2]['checked'], 0)
            self.assertFalse(result[2]['complete'])
        result = self.service._behavior_equivalence(left, right, 0)
        self.assertEqual(result[0], 'unknown')
        self.assertEqual(result[2]['method'], 'context_budget_exhausted')


if __name__ == '__main__':
    unittest.main()
