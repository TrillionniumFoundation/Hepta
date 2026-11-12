"""Scalar advice relation regressions; authored replies do not prove native use.

Only NativeScalarSelectionTests invokes the source-bound native executable,
and it is visibly skipped when that executable and its receipt are absent.
"""
from copy import deepcopy
from itertools import product, permutations
import os
from pathlib import Path
import unittest

from hepta.hia_ndu_scalar_selection import (ScalarSelectionRejected,
    resolve_scalar_selection, TIE_POLICY)
from tests.hia_ndu_scalar_fixture import scalar_request, fixture_response


class ScalarSelectionTests(unittest.TestCase):
    def resolve(self, request):
        response = fixture_response(request)
        before = deepcopy((request, response))
        receipt = resolve_scalar_selection(request, response)
        self.assertEqual((request, response), before)
        self.assertFalse(receipt['proves_program_safety'])
        self.assertFalse(receipt['forecast_is_observed_benefit'])
        self.assertFalse(receipt['incremental_ndu_advantage_established'])
        self.assertFalse(receipt['native_identity_validated_here'])
        self.assertEqual(receipt['caller_tie_policy'], TIE_POLICY)
        return receipt

    def test_tied_cheaper_frontier_does_not_fall_back_to_dominated_incumbent(self):
        receipt = self.resolve(scalar_request((100, 50, 50)))
        self.assertEqual(receipt['validated_pareto_frontier'], ['alpha', 'beta'])
        self.assertEqual(receipt['selected_id'], 'alpha')
        self.assertIsNone(receipt['native_recommendation'])
        self.assertEqual(receipt['selection_source'], 'caller_pareto_tie_policy')

    def test_tie_with_incumbent_retains_it_without_claiming_native_abstention(self):
        receipt = self.resolve(scalar_request((50, 50, 100)))
        self.assertEqual(receipt['selected_id'], 'abstain')
        self.assertIsNone(receipt['native_recommendation'])
        self.assertTrue(receipt['caller_tie_policy_applied'])

    def test_unique_minimum_preserves_actual_native_recommendation(self):
        for costs, selected in [((10, 20, 30), 'abstain'), ((30, 10, 20), 'beta'), ((30, 20, 10), 'alpha')]:
            with self.subTest(costs=costs):
                receipt = self.resolve(scalar_request(costs))
                self.assertEqual(receipt['selected_id'], selected)
                self.assertEqual(receipt['native_recommendation'], selected)
                self.assertEqual(receipt['selection_source'], 'native_unique_pareto')
                self.assertFalse(receipt['caller_tie_policy_applied'])

    def test_hard_and_resource_rejections_cannot_enter_selection(self):
        receipt = self.resolve(scalar_request((100, 1, 1), resources=[0, 0, 1001], hard=[False, True, False]))
        self.assertEqual(receipt['selection_source'], 'native_explicit_abstain')
        self.assertEqual(receipt['native_recommendation'], 'abstain')

    def test_resource_cap_boundary_is_inclusive(self):
        receipt = self.resolve(scalar_request((100, 50, 50), resources=[0, 1000, 1001]))
        self.assertEqual(receipt['selected_id'], 'beta')

    def test_minimal_request_keeps_explicit_abstain(self):
        receipt = self.resolve(scalar_request((5,)))
        self.assertEqual(receipt['selection_source'], 'native_explicit_abstain')

    def test_request_order_does_not_change_tie_resolution(self):
        request = scalar_request((100, 50, 50))
        for rows in permutations(request['candidates']):
            value = {**request, 'candidates': list(rows)}
            self.assertEqual(self.resolve(value)['selected_id'], 'alpha')

    def test_bounded_cost_table_matches_full_enum_without_more_information(self):
        # 64 finite cost tables, not a universal proof or performance sample.
        for costs in product(range(4), repeat=3):
            request = scalar_request(costs)
            receipt = self.resolve(request)
            expected = min(request['candidates'], key=lambda r:(r['cost_q32'], r['id'] != 'abstain', r['id']))['id']
            self.assertEqual(receipt['selected_id'], expected)

    def test_wrong_frontiers_and_dispositions_are_rejected(self):
        request = scalar_request((100, 50, 50))
        base = fixture_response(request)
        faults = [
            {'pareto_frontier': ['abstain']}, {'pareto_frontier': ['alpha']},
            {'pareto_frontier': ['alpha', 'beta', 'abstain']},
            {'pareto_frontier': ['alpha', 'alpha']}, {'pareto_frontier': ['beta', 'alpha']},
            {'pareto_frontier': None}, {'pareto_frontier': [[], 'beta']},
            {'advisory_recommendation': 'abstain'}, {'advisory_recommendation': 'alpha'},
            {'advisory_recommendation': False}, {'advisory_recommendation': []},
            {'disposition': 'UniqueParetoRecommendation'}, {'disposition': 'future'},
            {'generation': True}, {'request_sha256': '0' * 64}, {'objective_sha256': '0' * 64},
            {'rejected': [{'id': 'beta', 'reasons': 'made up'}]}, {'rejected': None},
        ]
        for fault in faults:
            with self.subTest(fault=fault), self.assertRaises(ScalarSelectionRejected):
                resolve_scalar_selection(request, {**base, **fault})
        del base['advisory_recommendation']
        with self.assertRaises(ScalarSelectionRejected):
            resolve_scalar_selection(request, base)

    def test_null_unique_choice_is_not_silently_abstain(self):
        request = scalar_request((100, 20, 30))
        response = fixture_response(request)
        response['advisory_recommendation'] = None
        with self.assertRaises(ScalarSelectionRejected):
            resolve_scalar_selection(request, response)

    def test_feasibility_partition_cannot_omit_duplicate_or_invent_rejection(self):
        request = scalar_request((100, 1, 1), hard=[False, True, True])
        response = fixture_response(request)
        rejected = response['rejected']
        faults = [[], rejected[:1], rejected + rejected[:1],
            [{'id': 'unknown', 'reasons': 'x'}], [{'id': False, 'reasons': 'x'}],
            [{'id': 'alpha', 'reasons': ''}, rejected[1]],
            [{'id': 'alpha', 'reasons': [], 'extra': True}, rejected[1]]]
        for fault in faults:
            with self.subTest(fault=fault), self.assertRaises(ScalarSelectionRejected):
                resolve_scalar_selection(request, {**response, 'rejected': fault})

    def test_infeasible_incumbent_cannot_be_fabricated(self):
        for field, value in [('hard_violation', True), ('resource_q32', 1001)]:
            request = scalar_request()
            request['candidates'][0][field] = value
            with self.assertRaises(ScalarSelectionRejected):
                resolve_scalar_selection(request, fixture_response(request))

    def test_request_shape_and_exact_integer_boundaries_fail_closed(self):
        original = scalar_request()
        changes = [('resource_cap_q32', True), ('resource_cap_q32', -1),
            ('resource_cap_q32', 1 << 63), ('generation', True), ('generation', 0),
            ('generation', 1 << 64), ('schema', 'future'), ('candidates', [])]
        for key, value in changes:
            request = {**original, key: value}
            with self.subTest(key=key, value=value), self.assertRaises(ScalarSelectionRejected):
                resolve_scalar_selection(request, {})
        for key, value in [('id', []), ('id', 'abstain'), ('cost_q32', True),
            ('uncertainty_q32', -1), ('resource_q32', 1 << 63), ('hard_violation', 1), ('support_sha256', False)]:
            request = deepcopy(original)
            request['candidates'][1][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ScalarSelectionRejected):
                resolve_scalar_selection(request, {})

    def test_receipt_binds_exact_request_and_raw_reply_without_mutating_it(self):
        request = scalar_request()
        response = fixture_response(request)
        a = resolve_scalar_selection(request, response)
        response['additional_evidence'] = 'test label'
        b = resolve_scalar_selection(request, response)
        self.assertNotEqual(a['native_response_sha256'], b['native_response_sha256'])
        request['generation'] += 1
        c = self.resolve(request)
        self.assertNotEqual(a['request_sha256'], c['request_sha256'])


@unittest.skipUnless(os.environ.get('HEPTA_NDU_BRIDGE') and os.environ.get('HEPTA_NDU_BUILD'),
                     'actual source-bound native bridge and build receipt are required')
class NativeScalarSelectionTests(unittest.TestCase):
    def test_actual_native_tie_and_injected_wrong_frontier(self):
        from hepta.hia_ndu_optimizer import _native_rank
        bridge = {'binary': os.environ['HEPTA_NDU_BRIDGE'],
                  'build_receipt': str(Path(os.environ['HEPTA_NDU_BUILD']) / 'build-receipt.json')}
        request = scalar_request((100, 50, 50))
        response, identity = _native_rank(bridge, request, timeout_s=2)
        self.assertIsNone(response['advisory_recommendation'])
        self.assertEqual(response['disposition'], 'ParetoSetRequiresSlowPath')
        self.assertEqual(response['pareto_frontier'], ['alpha', 'beta'])
        self.assertEqual(len(identity['binary_sha256']), 64)
        receipt = resolve_scalar_selection(request, response)
        self.assertEqual(receipt['selected_id'], 'alpha')
        bad = {**response, 'pareto_frontier': ['abstain']}
        with self.assertRaises(ScalarSelectionRejected):
            resolve_scalar_selection(request, bad)


if __name__ == '__main__':
    unittest.main()
