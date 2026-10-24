"""Evaluator qualification using deterministic scripts, never AI model runs."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from experiments.agent_eval import harness
from experiments.agent_eval.__main__ import main
from experiments.agent_eval._private.oracles import expected, hidden_cases
from experiments.agent_eval._private.solutions import HEPTA, RUST
from experiments.agent_eval.fixtures.adapters import FIXTURE_MODEL, write_fixture
from experiments.agent_eval.harness import Budget, EvalError, compare, evaluate, make_plan, replay, sample_id, validate_usage, verify_plan
from experiments.agent_eval.sandbox import clean_environment, run_bounded
from experiments.agent_eval.scoring import score_candidate
from experiments.agent_eval.tasks import ROOT, TASK_IDS, LANGUAGES, balanced_body, canonical, digest, materialize, task_request, verify_manifest
from hepta.backend import find_rustc
from hepta.ast import HeptaError


# Synthetic identities below exercise validation only; they are not providers.
MODELS = [{'provider': 'unit-test-only', 'name': name, 'revision': 'synthetic-v1'} for name in ('alpha', 'beta')]


def metered(model=MODELS[0], inputs=4, outputs=2, tools=0, request_id='synthetic-request-1'):
    return {'input_tokens': inputs, 'output_tokens': outputs, 'total_tokens': inputs + outputs,
            'tool_calls': tools, 'provider_calls': [{'request_id': request_id, 'model': model,
                'input_tokens': inputs, 'output_tokens': outputs,
                'raw_usage': {'input_tokens': inputs, 'output_tokens': outputs, 'unit_test_only': True}}]}


def zero_usage(tools=0):
    return {'input_tokens': 0, 'output_tokens': 0, 'total_tokens': 0, 'tool_calls': tools, 'provider_calls': []}


class FrozenAgentTasksTests(unittest.TestCase):
    def test_manifest_and_paired_source_identity(self):
        manifest = verify_manifest()
        self.assertEqual(manifest['tasks'], list(TASK_IDS))
        for task in TASK_IDS:
            h, r = task_request(task, 'hepta'), task_request(task, 'rust')
            self.assertEqual(h['instructions'], r['instructions'])
            self.assertEqual(h['public_tests'], r['public_tests'])
            self.assertNotEqual(h['base_sha256'], r['base_sha256'])
            self.assertNotEqual(h['task_sha256'], r['task_sha256'])

    def test_changed_frozen_source_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / 'tasks'
            shutil.copytree(ROOT, clone, ignore=shutil.ignore_patterns('__pycache__', 'evidence'))
            path = clone / 'tasks' / 'lower_bound' / 'starter.rs'
            path.write_text(path.read_text() + '\n// changed\n')
            with self.assertRaisesRegex(ValueError, 'E_TASK_STALE'):
                verify_manifest(clone)

    def test_manifest_identity_cannot_be_edited_silently(self):
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / 'tasks'
            shutil.copytree(ROOT, clone, ignore=shutil.ignore_patterns('__pycache__', 'evidence'))
            path = clone / 'manifest.json'
            manifest = json.loads(path.read_text())
            manifest['seed'] += 1
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'E_TASK_STALE'):
                verify_manifest(clone)

    def test_body_scope_handles_literals_comments_and_rejects_escape(self):
        accepted = ['{ return 0; }', '{ /* } /* { */ */ return 0; }',
                    '{ let x = "}\\\"{"; return 0; }', '{ let x = r###"} {"###; return 0; }',
                    "{ let x = '}'; let y = '\\u{7b}'; return 0; }",
                    "{ fn f<'a>(x: &'a str) -> &'a str { x } return 0; }"]
        for body in accepted:
            self.assertTrue(balanced_body(body), body)
        for body in ['{} fn injected() {}', '{} {}', '{/* unterminated }', '{ // }', '{ "unterminated }',
                     '{ let x = r#" } "###; } fn injected() {}']:
            self.assertFalse(balanced_body(body), body)
        with self.assertRaisesRegex(ValueError, 'E_EDIT_SCOPE'):
            materialize(task_request('lower_bound', 'rust'), '{} fn injected() {}')
        with self.assertRaisesRegex(ValueError, 'E_EDIT_SCOPE'):
            materialize(task_request('lower_bound', 'rust'), '{' + ' ' * 65536 + '}')

    def test_request_contains_public_cases_only(self):
        for task in TASK_IDS:
            request = task_request(task, 'hepta')
            self.assertEqual(len(request['public_tests']), 2)
            self.assertNotIn('hidden_cases', request)
            self.assertNotIn('_private/', canonical(request).decode())
            self.assertNotIn(HEPTA[task], request['starter_source'])

    def test_independent_oracle_edges(self):
        self.assertEqual(expected('lower_bound', {'id': 0, 'input': [-2, 0, 0, 9], 'parameter': 0})['result'], 1)
        overflow = expected('parse_decimal', {'id': 0, 'input': list(b'18446744073709551616')})
        self.assertEqual((overflow['value'], overflow['status'], overflow['consumed']), (0, 2, 19))
        malformed = expected('parse_decimal', {'id': 0, 'input': list(b'1__2')})
        self.assertEqual((malformed['status'], malformed['consumed']), (1, 1))
        wrap = expected('rolling_sum', {'id': 0, 'input': [2**63 - 1, 1], 'parameter': 2, 'capacity': 1})
        self.assertEqual(wrap['output'], [-2**63])
        self.assertEqual([len(hidden_cases(t)) for t in TASK_IDS], [600, 194, 414, 220])


class AgentMeteringTests(unittest.TestCase):
    def test_budget_rejects_negative_boolean_nonfinite_and_wrong_types(self):
        for kwargs in ({'tool_calls': -1}, {'input_tokens': True}, {'wall_seconds': 0},
                       {'wall_seconds': float('nan')}, {'wall_seconds': float('inf')}, {'total_tokens': '2'}):
            with self.assertRaises(ValueError): Budget(**kwargs)

    def test_complete_exact_provider_usage_required(self):
        usage = metered()
        self.assertEqual(validate_usage(usage, MODELS[0], Budget(), 0, 'provider'), usage)
        for invalid in (None, {}, zero_usage()):
            with self.assertRaises(EvalError):
                validate_usage(invalid, MODELS[0], Budget(), 0, 'provider')

    def test_token_overrun_rejected_for_each_counter(self):
        for budget in (Budget(input_tokens=3), Budget(output_tokens=1), Budget(total_tokens=5)):
            with self.assertRaises(EvalError) as failure:
                validate_usage(metered(), MODELS[0], budget, 0, 'provider')
            self.assertEqual(failure.exception.code, 'E_TOKEN_BUDGET')

    def test_aggregate_and_observed_tool_accounting(self):
        usage = metered(); usage['total_tokens'] = 7
        with self.assertRaises(EvalError): validate_usage(usage, MODELS[0], Budget(), 0, 'provider')
        with self.assertRaises(EvalError) as failure:
            validate_usage(metered(), MODELS[0], Budget(), 1, 'provider')
        self.assertEqual(failure.exception.code, 'E_TOOL_ACCOUNTING')

    def test_model_revision_and_unique_receipts_required(self):
        usage = metered()
        with self.assertRaises(EvalError) as failure:
            validate_usage(usage, MODELS[1], Budget(), 0, 'provider')
        self.assertEqual(failure.exception.code, 'E_MODEL')
        usage['provider_calls'] *= 2
        with self.assertRaises(EvalError): validate_usage(usage, MODELS[0], Budget(), 0, 'provider')

    def test_cumulative_usage_cannot_reset_or_rewrite_receipts(self):
        previous = metered()
        for changed in (metered(request_id='replacement'), metered(inputs=3)):
            with self.assertRaises(EvalError) as failure:
                validate_usage(changed, MODELS[0], Budget(), 0, 'provider', previous)
            self.assertEqual(failure.exception.code, 'E_USAGE_RESET')

    def test_usage_metadata_rejects_credentials(self):
        usage = metered()
        usage['provider_calls'][0]['raw_usage']['nested'] = {'authorization': 'not-a-real-secret'}
        with self.assertRaises(EvalError): validate_usage(usage, MODELS[0], Budget(), 0, 'provider')

    def test_fixture_cannot_claim_ai_tokens(self):
        self.assertEqual(validate_usage(zero_usage(), FIXTURE_MODEL, Budget(), 0, 'fixture'), zero_usage())
        with self.assertRaises(EvalError) as failure:
            validate_usage(metered(model=FIXTURE_MODEL), FIXTURE_MODEL, Budget(), 0, 'fixture')
        self.assertEqual(failure.exception.code, 'E_FIXTURE_USAGE')

    def test_environment_is_empty_unless_explicitly_allowed(self):
        with patch.dict(os.environ, {'HEPTA_TEST_PRIVATE': 'do-not-forward'}):
            self.assertNotIn('HEPTA_TEST_PRIVATE', clean_environment())
            self.assertEqual(clean_environment(['HEPTA_TEST_PRIVATE'])['HEPTA_TEST_PRIVATE'], 'do-not-forward')


class AgentPlanTests(unittest.TestCase):
    def test_two_exact_models_and_full_reproducible_matrix(self):
        plan = make_plan(MODELS, Budget(tool_calls=3), replicates=2)
        self.assertEqual(plan, make_plan(MODELS, Budget(tool_calls=3), replicates=2))
        self.assertEqual(len(plan['schedule']), 32)
        self.assertEqual(verify_plan(plan), plan)
        for models in ([MODELS[0]], [MODELS[0], MODELS[0]], [{'provider': 'x', 'name': 'y'}]):
            with self.assertRaises(ValueError): make_plan(models)

    def test_modified_plan_and_missing_schedule_cell_rejected(self):
        plan = make_plan(MODELS)
        plan['budget']['tool_calls'] += 1
        with self.assertRaisesRegex(ValueError, 'E_PLAN_STALE'): verify_plan(plan)
        plan = make_plan(MODELS)
        plan['schedule'].pop()
        plan['plan_sha256'] = digest(canonical({key: value for key, value in plan.items() if key != 'plan_sha256'}))
        with self.assertRaisesRegex(ValueError, 'schedule'): verify_plan(plan)

    def test_empty_or_partial_comparison_never_claims_productivity(self):
        result = compare(make_plan(MODELS), [])
        self.assertEqual(result['status'], 'not_qualified')
        self.assertFalse(result['general_productivity_advantage_established'])
        self.assertEqual(result['rows'], [])

    def synthetic_reports(self, plan):
        # In-memory synthetic validation inputs only. Never persisted as evidence.
        reports = []
        for model in MODELS:
            for task in TASK_IDS:
                for language in LANGUAGES:
                    request = task_request(task, language)
                    body = (HEPTA if language == 'hepta' else RUST)[task]
                    source_hash = digest(materialize(request, body).encode())
                    reports.append(dict(schema='hepta.agent_run.v1', model=model, task_id=task,
                        language=language, replicate=0, sample_id=sample_id(plan, model, task, language, 0),
                        plan_sha256=plan['plan_sha256'], budget=plan['budget'], budget_sha256=Budget(**plan['budget']).sha256,
                        **{key: request[key] for key in ('taskset_sha256', 'task_sha256', 'base_sha256')},
                        evaluator_sha256='unit-test-synthetic', compiler={'unit_test_only': True},
                        status='provider_run_scored', run_kind='provider_adapter_run', ai_comparison_eligible=True,
                        usage=metered(model=model), observed_tool_calls=0, agent_wall_seconds=1.0,
                        sandbox={'available': True}, isolation='allowlisted_namespace_capsules',
                        submitted_body=body, final_body_sha256=digest(body.encode()), submitted_source_sha256=source_hash,
                        score={'ok': True, 'compiled': True, 'passed': len(hidden_cases(task)),
                               'total': len(hidden_cases(task)), 'native_status': 'exited', 'native_returncode': 0,
                               'protocol_error': None, 'source_sha256': source_hash}))
        return reports

    def test_comparison_coordinates_and_usage_cannot_be_relabelled(self):
        plan = make_plan(MODELS)
        reports = self.synthetic_reports(plan)
        self.assertEqual(compare(plan, reports)['status'], 'complete_adapter_attested_pilot')
        reports[0]['language'] = 'rust'
        self.assertEqual(compare(plan, reports)['status'], 'not_qualified')
        reports = self.synthetic_reports(plan)
        reports[0]['usage'] = None
        self.assertEqual(compare(plan, reports)['status'], 'not_qualified')
        reports = self.synthetic_reports(plan)
        reports[0]['submitted_body'] = '{ return 0; }'
        self.assertEqual(compare(plan, reports)['status'], 'not_qualified')
        reports = self.synthetic_reports(plan)
        reports[0]['score']['compiled'] = False
        self.assertEqual(compare(plan, reports)['status'], 'not_qualified')

    def test_fixture_and_duplicate_reports_cannot_qualify(self):
        plan = make_plan(MODELS)
        reports = self.synthetic_reports(plan)
        reports[0]['run_kind'] = 'trusted_fixture_qualification'
        self.assertEqual(compare(plan, reports)['status'], 'not_qualified')
        reports = self.synthetic_reports(plan)
        self.assertEqual(compare(plan, reports + reports[:1])['status'], 'not_qualified')

    def test_provider_fails_closed_before_adapter_when_sandbox_missing(self):
        with patch.object(harness, 'probe_sandbox', return_value={'available': False, 'reason': 'unit-test unavailable'}):
            report = evaluate('lower_bound', 'rust', '/does-not-exist', ['not-invoked'], MODELS[0], plan=make_plan(MODELS))
        self.assertEqual(report['status'], 'environment_blocked')
        self.assertFalse(report['adapter_invoked'])
        self.assertFalse(report['ai_comparison_eligible'])

    def test_cli_does_not_overwrite_an_existing_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'plan.json'
            output.write_text('preserve')
            self.assertEqual(main(['verify', '--output', str(output)]), 2)
            self.assertEqual(output.read_text(), 'preserve')


try:
    RUSTC = find_rustc()
except (ValueError, FileNotFoundError, HeptaError):
    RUSTC = None


@unittest.skipUnless(sys.platform.startswith('linux') and RUSTC and shutil.which('gcc'),
                     'native agent-evaluator qualification requires Linux, rustc, and gcc')
class AgentNativeQualificationTests(unittest.TestCase):
    def fixture(self, mode='oracle', body=None, budget=None, task='lower_bound', language='rust'):
        with tempfile.TemporaryDirectory(prefix='hepta-eval-test-adapter-') as temporary:
            directory = Path(temporary)
            command = write_fixture(directory, body if body is not None else (HEPTA if language == 'hepta' else RUST)[task], mode)
            return evaluate(task, language, directory, command, FIXTURE_MODEL, kind='fixture',
                            fixture_qualification=True, budget=budget or Budget(wall_seconds=10), rustc=RUSTC)

    def test_all_eight_oracle_solutions_compile_and_pass_independent_hidden_cases(self):
        for task in TASK_IDS:
            for language in LANGUAGES:
                with self.subTest(task=task, language=language):
                    result = score_candidate(task_request(task, language), (HEPTA if language == 'hepta' else RUST)[task], fixture=True, rustc=RUSTC)
                    self.assertTrue(result['ok'], result)
                    self.assertEqual(result['passed'], len(hidden_cases(task)))

    def test_wrong_native_solution_fails_hidden_score(self):
        report = self.fixture(body='{ return 0; }')
        self.assertEqual(report['status'], 'fixture_scored')
        self.assertFalse(report['score']['ok'])
        self.assertLess(report['score']['passed'], report['score']['total'])
        self.assertFalse(report['ai_comparison_eligible'])

    def test_repeated_frozen_candidate_has_stable_source_and_artifact_identity(self):
        request = task_request('lower_bound', 'rust')
        first = score_candidate(request, RUST['lower_bound'], fixture=True, rustc=RUSTC)
        second = score_candidate(request, RUST['lower_bound'], fixture=True, rustc=RUSTC)
        for key in ('source_sha256', 'rust_sha256', 'artifact_sha256'):
            self.assertEqual(first[key], second[key])

    def test_observed_public_tool_roundtrip_is_metered(self):
        report = self.fixture(mode='public_test')
        self.assertEqual(report['status'], 'fixture_scored', report)
        self.assertTrue(report['score']['ok'])
        self.assertEqual(report['observed_tool_calls'], 1)
        self.assertEqual(report['usage'], zero_usage(1))
        self.assertTrue(report['tools'][0]['ok'])
        self.assertEqual(report['run_kind'], 'trusted_fixture_qualification')
        self.assertFalse(report['ai_comparison_eligible'])
        self.assertEqual(report['provider_calls_attested'], 0)
        self.assertEqual(report['submitted_body'], RUST['lower_bound'])
        self.assertEqual(report['tools'][0]['body'], RUST['lower_bound'])

    def test_saved_candidate_replay_checks_identities_and_never_invokes_provider(self):
        report = self.fixture()
        replayed = replay(report, rustc=RUSTC, trusted_fixture=True)
        self.assertTrue(replayed['score']['ok'])
        self.assertFalse(replayed['adapter_invoked'])
        self.assertFalse(replayed['ai_comparison_eligible'])
        with self.assertRaisesRegex(ValueError, 'E_FIXTURE_MODE'):
            replay(report, rustc=RUSTC)
        report['submitted_body'] = '{ return 0; }'
        with self.assertRaisesRegex(ValueError, 'E_REPLAY_STALE'):
            replay(report, rustc=RUSTC, trusted_fixture=True)

    def test_stale_identity_missing_usage_and_wrong_model_rejected(self):
        for mode, code in [('stale', 'E_STALE_IDENTITY'), ('missing_usage', 'E_USAGE'),
                           ('wrong_model', 'E_MODEL'), ('fixture_tokens', 'E_FIXTURE_USAGE')]:
            with self.subTest(mode=mode):
                report = self.fixture(mode)
                self.assertEqual(report['status'], 'rejected')
                self.assertEqual(report['error']['code'], code)
                self.assertIsNone(report['score'])

    def test_tool_cap_rejected_before_any_compilation(self):
        with patch.object(harness, 'check_candidate', side_effect=AssertionError('must not run')):
            report = self.fixture('check', budget=Budget(tool_calls=0, wall_seconds=5))
        self.assertEqual(report['error']['code'], 'E_TOOL_BUDGET')
        self.assertEqual(report['observed_tool_calls'], 1)
        self.assertEqual(report['tools'], [])

    def test_second_tool_overrun_and_unknown_tool_rejected(self):
        report = self.fixture('extra_tool', budget=Budget(tool_calls=1, wall_seconds=10))
        self.assertEqual(report['error']['code'], 'E_TOOL_BUDGET')
        self.assertEqual(len(report['tools']), 1)
        report = self.fixture('unknown_tool')
        self.assertEqual(report['error']['code'], 'E_TOOL')

    def test_wall_timeout_kills_adapter_without_scoring(self):
        began = time.monotonic()
        report = self.fixture('sleep', budget=Budget(wall_seconds=0.2))
        self.assertEqual(report['error']['code'], 'E_WALL_BUDGET')
        self.assertIsNone(report['score'])
        self.assertLess(time.monotonic() - began, 3)

    def test_adapter_protocol_output_cap(self):
        report = self.fixture('flood', budget=Budget(protocol_bytes=1000, wall_seconds=5))
        self.assertEqual(report['error']['code'], 'E_PROTOCOL_BYTES')

    def test_scope_escape_and_compile_error_cannot_score_success(self):
        report = self.fixture(body='{} fn injected() {}')
        self.assertEqual(report['status'], 'rejected')
        report = self.fixture(body='{ return definitely_not_defined; }')
        self.assertEqual(report['status'], 'fixture_scored')
        self.assertFalse(report['score']['compiled'])
        self.assertFalse(report['score']['ok'])

    def test_candidate_subprocess_timeout_and_output_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            timed = run_bounded([sys.executable, '-c', 'import time; time.sleep(20)'], cwd=directory,
                                 timeout=0.1, fixture=True)
            self.assertEqual(timed['status'], 'timeout')
            flooded = run_bounded([sys.executable, '-c', 'print("x" * 100000)'], cwd=directory,
                                   timeout=3, max_output=100, fixture=True)
            self.assertEqual(flooded['status'], 'output_limit')

    def test_native_candidate_hang_is_bounded_after_compilation(self):
        began = time.monotonic()
        result = score_candidate(task_request('lower_bound', 'rust'), '{ loop {} }',
                                 timeout=0.5, fixture=True, rustc=RUSTC)
        self.assertFalse(result['ok'])
        self.assertEqual(result.get('native_status', result.get('build', {}).get('status')), 'timeout')
        self.assertLess(time.monotonic() - began, 3)


if __name__ == '__main__':
    unittest.main()
