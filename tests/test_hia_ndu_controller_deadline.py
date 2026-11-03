"""Deterministic controller deadline controls, not native timing observations."""
import unittest
from unittest.mock import patch

from hepta import hia_ndu_cost as cost
from test_hia_ndu_cost import fixture


class ControllerDeadlineTests(unittest.TestCase):
    def decide(self, *, elapsed, ready=False, projection_delay=False, baseline_cost=1000, existing_session=False):
        model = fixture(1)
        model['baseline']['latency_ns'] = [baseline_cost]
        model['session_ready'] = existing_session
        if ready:
            model['ready'] = ['b']
            model['variants'][1]['latency_ns'] = [900]
        bundle = cost.build_request(model)
        best_id = min(bundle['plans'], key=lambda key: bundle['plans'][key]['total_ns'])
        self.assertEqual(bundle['plans'][best_id]['actions'][0]['acquired'], ['a'])
        clock = [0]
        response = {'authority': 'DENY_ALL', 'safety_certificate': False,
                    'pareto_candidate_ids': [best_id]}

        class Session:
            def evaluate(self, request):
                if not projection_delay:
                    clock[0] = elapsed
                return response
            def close(self):
                pass

        original = cost.project_advice
        def project(*args):
            action = original(*args)
            if projection_delay:
                clock[0] = elapsed
            return action

        controller = cost.AdvisoryController(Session)
        if existing_session:
            controller.session = Session()
        with patch.object(cost.time, 'monotonic_ns', side_effect=lambda: clock[0]), \
                patch.object(cost, 'project_advice', side_effect=project):
            action, row = controller.decide(model)
        controller.close()
        self.assertTrue(row['native_invoked'])
        self.assertEqual(row['response'], response)
        return action, row

    def test_response_at_or_after_deadline_cannot_acquire_artifacts(self):
        for elapsed in (1_000_000, 1_000_001):
            with self.subTest(elapsed=elapsed):
                action, row = self.decide(elapsed=elapsed)
                self.assertEqual(action['mode'], 'skip')
                self.assertEqual(action['acquired'], [])
                self.assertEqual(action['dispatch'], 'baseline')
                self.assertIn('exhausted', row['reason'])

    def test_projection_time_is_also_charged_before_action_return(self):
        action, row = self.decide(elapsed=1_000_001, projection_delay=True)
        self.assertEqual(action['mode'], 'skip')
        self.assertEqual(row['response_projection_ns'], 1_000_001)

    def test_deadline_fallback_retains_valid_incumbent(self):
        action, _ = self.decide(elapsed=1_000_001, ready=True)
        self.assertEqual(action['mode'], 'skip')
        self.assertEqual(action['ready_after'], ['b'])
        self.assertEqual(action['acquired'], [])
        self.assertEqual(action['retired'], [])

    def test_no_model_feasible_incumbent_returns_refusal(self):
        action, row = self.decide(elapsed=1_000_001, baseline_cost=2_000_000)
        self.assertIsNone(action)
        self.assertTrue(row['optional_action_withheld'])
        self.assertIn('native unanimous', row['reason_before_budget_guard'])
        self.assertEqual(row['request_ns'], 1_000_001)

    def test_existing_session_also_rejects_late_projection(self):
        action, row = self.decide(elapsed=1_000_001, existing_session=True)
        self.assertEqual(action['mode'], 'skip')
        self.assertEqual(action['acquired'], [])
        self.assertEqual(row['startup_ns'], 0)

    def test_native_failure_keeps_error_and_incumbent_fallback(self):
        model = fixture(1)
        clock, closed = [0], []
        class FailedSession:
            def evaluate(self, request):
                clock[0] = model['budget_ns'] + 1
                raise cost.NduBridgeError('controlled refusal')
            def close(self):
                closed.append(True)
        controller = cost.AdvisoryController(FailedSession)
        with patch.object(cost.time, 'monotonic_ns', side_effect=lambda: clock[0]):
            action, row = controller.decide(model)
        self.assertEqual(action['mode'], 'skip')
        self.assertEqual(action['acquired'], [])
        self.assertEqual(row['native_error'], 'controlled refusal')
        self.assertNotIn('response', row)
        self.assertNotIn('optional_action_withheld', row)
        self.assertIsNone(controller.session)
        self.assertEqual(closed, [True])
        controller.close()

    def test_timely_response_preserves_native_projection(self):
        action, _ = self.decide(elapsed=999_999)
        self.assertEqual(action['mode'], 'invoke')
        self.assertEqual(action['acquired'], ['a'])


if __name__ == '__main__':
    unittest.main()
