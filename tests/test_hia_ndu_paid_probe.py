from dataclasses import asdict, replace
from fractions import Fraction
import unittest
from experiments.hia_ndu_feedback_20261106.model import FeedbackError, Q32, scalar_backend
from experiments.hia_ndu_feedback_20261106.paid_probe import (
    State, belief, observe, plan, independent_policy_oracle, witness_problems,
)


class PaidInformationTests(unittest.TestCase):
    def test_information_changes_later_choice_and_is_paid(self):
        problem = witness_problems()[0]
        initial = State((), problem.budget)
        root = plan(problem, initial)
        self.assertEqual((root['selected_action'], root['value_q32']), ('read', 19*Q32))
        for signal in (0, 1):
            after = observe(problem, initial, 'read', signal)
            self.assertEqual(after.remaining_budget, 29)
            self.assertEqual(plan(problem, after)['selected_action'], f'select-{signal}')
            with self.assertRaises(FeedbackError):
                observe(problem, after, 'read', signal)

    def test_expensive_or_uninformative_read_preserves_incumbent(self):
        for problem in witness_problems()[1:3]:
            result = plan(problem, State((), problem.budget))
            self.assertEqual(result['selected_action'], 'abstain')
            self.assertEqual(result['value_q32'], 0)

    def test_two_step_information_beats_myopic_voi_but_not_exact_control(self):
        problem = witness_problems()[3]
        state = State((), problem.budget)
        full, myopic = plan(problem, state), plan(problem, state, depth=1)
        oracle = independent_policy_oracle(problem, state)
        self.assertEqual(myopic['selected_action'], 'abstain')
        self.assertEqual(myopic['value_q32'], 60*Q32)
        self.assertEqual(full['selected_action'], 'read-a')
        self.assertLessEqual(abs(full['value_q32']-round(Fraction(316, 5)*Q32)), 1)
        self.assertEqual(full['value_q32'], oracle['value_q32'])
        self.assertEqual(full['selected_action'], oracle['selected_action'])
        self.assertGreater(oracle['enumerated_policies'], 100)

    def test_information_competes_with_original_budget(self):
        problem = replace(witness_problems()[3], budget=1)
        self.assertEqual(plan(problem, State((), 1))['selected_action'], 'abstain')
        after = observe(problem, State((), 1), 'read-a', 0)
        with self.assertRaises(FeedbackError):
            observe(problem, after, 'read-b', 0)
        with self.assertRaises(FeedbackError):
            belief(problem, State((('read-a', 0),), 1))

    def test_separate_policy_tree_oracle_matches_full_controller(self):
        original = witness_problems()[3]
        for prior in (Fraction(0), Fraction(1, 4), Fraction(1, 2), Fraction(3, 4), Fraction(1)):
            for fee in (1, 3, 12):
                for budget in (0, fee, 2*fee):
                    problem = replace(original, prior0=prior, budget=budget,
                        probes=tuple(replace(p, cost=fee) for p in original.probes))
                    state = State((), budget)
                    actual, oracle = plan(problem, state), independent_policy_oracle(problem, state)
                    with self.subTest(prior=prior, fee=fee, budget=budget):
                        self.assertEqual(actual['value_q32'], oracle['value_q32'])
                        self.assertEqual(actual['selected_action'], oracle['selected_action'])

    def test_observation_contains_no_latent_or_future_channel(self):
        problem = witness_problems()[0]
        state = State((), problem.budget)
        self.assertEqual(set(asdict(state)), {'history', 'remaining_budget'})
        with self.assertRaises(TypeError):
            State((), 30, future_signal=0)
        self.assertEqual(plan(problem, state)['trace'], plan(problem, state)['trace'])
        with self.assertRaises(FeedbackError):
            belief(problem, State((('read', True),), 29))

    def test_reference_callback_never_qualifies_native_or_economic_evidence(self):
        problem = witness_problems()[0]
        state = State((), problem.budget)
        result = plan(problem, state, backend=scalar_backend)
        self.assertFalse(result['native_backend_used'])
        self.assertFalse(result['economic_benefit_established'])
        self.assertEqual(result['authority'], 'DENY_ALL')
        with self.assertRaises(FeedbackError):
            plan(problem, state, backend=scalar_backend, require_native=True)
        with self.assertRaises(FeedbackError):
            plan(problem, state, require_native=True)

    def test_failure_retains_timing_without_partial_advice(self):
        problem = witness_problems()[3]
        with self.assertRaises(FeedbackError) as caught:
            plan(problem, State((), 2), max_states=1)
        self.assertGreater(caught.exception.controller_wall_ns, 0)
        self.assertEqual(caught.exception.completed_backups, 0)
        def unavailable(*args, **kwargs):
            raise RuntimeError('unavailable measurement')
        with self.assertRaises(RuntimeError) as caught:
            plan(problem, State((), 2), backend=unavailable)
        self.assertGreater(caught.exception.controller_wall_ns, 0)

    def test_exact_model_admission_and_zero_likelihood(self):
        problem = witness_problems()[0]
        for change in ({'budget': True}, {'prior0': 0.5}, {'probes': problem.probes*3},
                       {'probes': (replace(problem.probes[0], cost=0),)}):
            with self.subTest(change=change), self.assertRaises(FeedbackError):
                replace(problem, **change)
        certain = replace(problem, prior0=Fraction(1))
        with self.assertRaises(FeedbackError):
            observe(certain, State((), 30), 'read', 1)


if __name__ == '__main__':
    unittest.main()
