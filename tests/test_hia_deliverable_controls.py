"""Adversarial controls for P4/P5; no model provider or native build required."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'experiments/hia_deliverable_controls_20261106'


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


controls = load_module('controls')
oracle = load_module('compute_oracle')


def fixture(study='ndu_increment', task_count=8):
    evidence = 'synthetic unit-test receipt; no external measurement'
    def costs(elapsed):
        return {name: {'value': elapsed if name == 'elapsed_ns' else 0,
                       'status': 'measured' if name == 'elapsed_ns' else 'not_applicable',
                       'evidence': evidence} for name in controls.METRICS}
    tasks = [{'id': 'task-%02d' % i, 'independent_unit': 'project-%02d' % i,
              'kind': 'synthetic-test-only', 'input_digest': 'a' * 64,
              'expected_output_digest': 'b' * 64} for i in range(task_count)]
    protocol = {'schema': 'hepta.hia.deliverable-controls.protocol.v1', 'study': study,
                'arms': list(controls.ARMS[study]), 'tasks': tasks,
                'information_digest': 'c' * 64, 'candidate_bank_digest': 'd' * 64,
                'model_identity_digest': 'e' * 64, 'hardware_digest': 'f' * 64,
                'setup_policy': 'full_charge_each_standalone_arm',
                'clock_policy': 'disjoint_cells_with_enclosing_phase_clocks',
                'minimum_independent_units': 8, 'minimum_gain_ns': 1, 'minimum_gain_ppm': 1,
                'maximum_peak_rss_bytes': 1_000_000, 'maximum_cell_elapsed_ns': 10_000}
    raw = controls.wire(protocol)
    cells = []
    for task in tasks:
        for arm in protocol['arms']:
            row = {'task': task['id'], 'arm': arm, 'status': 'success', 'attempts': 1,
                   'ndu_native_calls': 1 if arm == 'ndu' else 0,
                   'input_digest': task['input_digest'], 'output_digest': task['expected_output_digest'],
                   'costs': costs(100 if arm == 'ndu' or arm.startswith('hia_') else 200)}
            row.update({name: protocol[name] for name in ('information_digest', 'candidate_bank_digest',
                                                        'model_identity_digest', 'hardware_digest')})
            cells.append(row)
    results = {'schema': 'hepta.hia.deliverable-controls.results.v1', 'protocol_sha256': controls.digest(raw),
               'setup': {arm: costs(0) for arm in protocol['arms']}, 'cells': cells}
    return protocol, results


def assess(protocol, results):
    return controls.assess_campaign(controls.wire(protocol), controls.wire(results))


class DeliverableControlsTests(unittest.TestCase):
    def test_two_independent_studies_have_different_comparators(self):
        for study, expected in [('ndu_increment', 3), ('agent_factorial', 2)]:
            protocol, results = fixture(study)
            report = assess(protocol, results)
            self.assertEqual(len(report['contrasts']), expected)
            self.assertEqual(report['independent_units'], 8)
            self.assertEqual(report['planned_cells'], 32)
            self.assertTrue(report['conditional_observed_advantage'])
            self.assertFalse(report['population_advantage_established'])
            self.assertFalse(report['observer_authenticated'])
            self.assertFalse(report['production_activation_allowed'])

    def test_unknown_cost_is_preserved_and_never_imputed_as_zero(self):
        p, r = fixture()
        r['cells'][0]['costs']['billed_micro_usd'] = {'value': None, 'status': 'unknown', 'evidence': 'billing not returned'}
        report = assess(p, r)
        self.assertFalse(report['conditional_observed_advantage'])
        self.assertIsNone(report['arms']['ndu']['billed_micro_usd_including_setup'])
        self.assertIn('unknown_full_lifecycle_cost', report['reasons'])
        r['cells'][0]['costs']['billed_micro_usd']['value'] = 0
        with self.assertRaises(controls.ControlsRejected):
            assess(p, r)

    def test_failed_cell_retains_denominator_attempts_and_cost(self):
        p, r = fixture()
        row = r['cells'][0]
        row.update(status='failure', output_digest=None, attempts=3)
        row['costs']['failed_attempt_ns']['status'] = 'measured'
        row['costs']['failed_attempt_ns']['value'] = 90
        report = assess(p, r)
        self.assertEqual(report['arms']['ndu']['planned'], 8)
        self.assertEqual(report['arms']['ndu']['outcomes'], {'failure': 1, 'success': 7})
        self.assertEqual(report['arms']['ndu']['attempts_including_failed'], 10)
        self.assertEqual(report['arms']['ndu']['elapsed_ns_including_setup'], 800)
        self.assertEqual(report['contrasts'][0]['correctness_by_task']['losses'], 1)
        self.assertEqual(report['contrasts'][0]['elapsed_by_independent_unit']['unknown'], 1)
        self.assertFalse(report['conditional_observed_advantage'])

    def test_ties_never_expand_sign_test_sample(self):
        p, r = fixture()
        for row in r['cells']:
            row['costs']['elapsed_ns']['value'] = 200
        report = assess(p, r)
        for comparison in report['contrasts']:
            self.assertEqual(comparison['elapsed_by_independent_unit'], {'wins': 0, 'losses': 0, 'ties': 8, 'unknown': 0})
            self.assertEqual(comparison['one_sided_sign_p'], {'numerator': 1, 'denominator': 1})
        self.assertFalse(report['conditional_observed_advantage'])

    def test_shared_task_family_does_not_count_as_eight_independent_units(self):
        p, r = fixture()
        for task in p['tasks']:
            task['independent_unit'] = 'one-project'
        r['protocol_sha256'] = controls.digest(controls.wire(p))
        report = assess(p, r)
        self.assertEqual(report['independent_units'], 1)
        self.assertIn('too_few_independent_units', report['reasons'])

    def test_full_setup_can_reverse_per_task_win(self):
        p, r = fixture()
        r['setup']['ndu']['elapsed_ns']['value'] = 2000
        report = assess(p, r)
        self.assertEqual(report['contrasts'][0]['elapsed_by_independent_unit']['wins'], 8)
        self.assertFalse(report['conditional_observed_advantage'])

    def test_nested_phase_clocks_are_never_double_counted(self):
        p, r = fixture()
        for row in r['cells']:
            for phase in ('repair_ns', 'human_review_ns', 'failed_attempt_ns'):
                row['costs'][phase].update(value=90, status='measured')
        self.assertEqual(assess(p, r)['arms']['ndu']['elapsed_ns_including_setup'], 800)
        r['cells'][0]['costs']['repair_ns']['value'] = 101
        with self.assertRaises(controls.ControlsRejected):
            assess(p, r)

    def test_registered_effect_size_memory_and_deadline_are_required(self):
        p, r = fixture()
        p['minimum_gain_ns'] = 1000
        r['protocol_sha256'] = controls.digest(controls.wire(p))
        self.assertFalse(assess(p, r)['conditional_observed_advantage'])
        p, r = fixture()
        r['cells'][0]['costs']['peak_rss_bytes'].update(value=1_000_001, status='measured')
        self.assertIn('registered_memory_limit_exceeded', assess(p, r)['reasons'])
        p, r = fixture()
        r['cells'][0]['costs']['elapsed_ns']['value'] = 10_001
        self.assertIn('registered_cell_deadline_exceeded', assess(p, r)['reasons'])

    def test_native_skip_policy_cannot_claim_an_ndu_invocation(self):
        p, r = fixture()
        for row in r['cells']:
            row['ndu_native_calls'] = 0
        self.assertIn('no_actual_ndu_invocation', assess(p, r)['reasons'])

    def test_missing_cells_are_explicit_unknown_records(self):
        p, r = fixture()
        row = r['cells'][0]
        row.update(status='missing', attempts=0, ndu_native_calls=0, output_digest=None)
        for metric in row['costs'].values():
            metric.update(value=None, status='unknown', evidence='not executed')
        report = assess(p, r)
        self.assertEqual(report['arms']['ndu']['planned'], 8)
        self.assertIsNone(report['arms']['ndu']['elapsed_ns_including_setup'])
        self.assertFalse(report['conditional_observed_advantage'])

    def test_drift_omission_duplicates_and_boolean_cost_reject(self):
        mutations = [
            lambda p, r: r['cells'].pop(),
            lambda p, r: r['cells'].__setitem__(0, deepcopy(r['cells'][1])),
            lambda p, r: r['cells'][0].__setitem__('information_digest', '0' * 64),
            lambda p, r: r['cells'][0].__setitem__('output_digest', '0' * 64),
            lambda p, r: r['cells'][0]['costs']['elapsed_ns'].__setitem__('value', True),
            lambda p, r: r['cells'][0]['costs'].pop('human_review_ns'),
            lambda p, r: p.__setitem__('setup_policy', 'amortize_over_future_customers'),
            lambda p, r: r.__setitem__('protocol_sha256', '0' * 64),
        ]
        for mutation in mutations:
            p, r = fixture()
            mutation(p, r)
            with self.assertRaises(controls.ControlsRejected):
                assess(p, r)
        for raw in (b'{"a":0,"a":1}', b'{"a":NaN}', b'\xff'):
            with self.assertRaises(controls.ControlsRejected):
                controls.read_json(raw)

    def test_historical_negative_tie_and_unknown_results_stay_separate(self):
        history = controls.historical_summary()
        self.assertEqual(sum(c['observed_cells'] for c in history['agent_factorial_round6'].values()), 24)
        self.assertEqual(sum(c['underlying_tasks'] for c in history['agent_factorial_round6'].values()), 6)
        self.assertEqual(history['agent_prior_failures']['successful_main_cells'], 14)
        self.assertEqual(history['agent_prior_failures']['planned_main_cells'], 16)
        self.assertFalse(history['agent_prior_failures']['whole_service_lifecycle_usage_complete'])
        self.assertEqual(history['ndu_policy_closure']['states'], 10224)
        self.assertFalse(history['ndu_policy_closure']['full_lifecycle_cost_known'])
        for cohort in history['ndu_round6'].values():
            self.assertEqual(cohort['native_equal_rankings'], cohort['native_paired_cases'])
            self.assertGreater(cohort['ndu_increment_ns']['evaluation']['sum'], 0)
            self.assertIsNone(cohort['cost_ledger']['human_review_seconds'])
            self.assertIsNone(cohort['cost_ledger']['maintenance_seconds'])

    def test_immutable_history_corruption_rejects_before_interpretation(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / 'history').mkdir()
            manifest = json.loads((DIRECTORY / 'HISTORY.json').read_text())
            record = manifest['records'][0]
            manifest['records'] = [record]
            (base / 'HISTORY.json').write_text(json.dumps(manifest))
            (base / record['path']).write_bytes((DIRECTORY / record['path']).read_bytes() + b' ')
            with self.assertRaises(controls.ControlsRejected):
                controls.historical_summary(base)

    def test_proposed_model_types_effects_and_opcodes_are_not_current_core(self):
        from hepta.hia_opcodes import EFFECTS, TYPES, OpcodeRejected, opcode_spec
        for name in ('model.infer', 'model.train', 'model.update', 'model.replay'):
            with self.assertRaises(OpcodeRejected):
                opcode_spec(name)
        self.assertTrue({'model', 'tensor', 'model_state'}.isdisjoint(TYPES))
        self.assertTrue({'model_read', 'model_write', 'external_infer'}.isdisjoint(EFFECTS))

    def test_independent_budget_compute_and_whole_winner_set_audit(self):
        report = oracle.audit_compute_costs()
        self.assertEqual(report['status'], 'passed')
        self.assertGreaterEqual(len(report['cases']), 17)
        self.assertGreater(report['boundary_cases'], 0)
        self.assertGreater(report['future_compute_sensitive_cases'], 0)
        self.assertTrue(any(row['safe_skip_checked'] for row in report['gate_cases']))
        self.assertEqual(report['native_ndu_calls'], 0)
        self.assertEqual(report['model_calls'], 0)
        self.assertFalse(report['ndu_advantage_established'])


if __name__ == '__main__':
    unittest.main()
