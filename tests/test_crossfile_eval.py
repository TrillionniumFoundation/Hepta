"""Cross-file evaluator qualification. Scripts/synthetic receipts are never AI evidence."""
from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from hepta.backend import find_rustc
from experiments.agent_eval.harness import Budget
from experiments.crossfile_eval.__main__ import main
from experiments.crossfile_eval.adapter_binding import actual_config
from experiments.crossfile_eval._private.oracles import expected, hidden_cases
from experiments.crossfile_eval.fixtures.adapters import FIXTURE_MODEL, write_fixture
from experiments.crossfile_eval.plan import make_plan, sample_id, verify_plan
from experiments.crossfile_eval.qualification import qualify_fixtures
from experiments.crossfile_eval.records import cost_record, seal_record, verify_record, write_append_only
from experiments.crossfile_eval.reporting import compare
from experiments.crossfile_eval.runner import StudySession, evaluate, replay
from experiments.crossfile_eval.scoring import check_candidate, score_candidate
from experiments.crossfile_eval.semantic import nodes, replace_nodes, rust_tokens
from experiments.crossfile_eval.tasks import (ARMS, LANGUAGES, ROOT, TASK_IDS, apply_files, canonical,
                                             digest, snapshot_id, task_request, trusted_reference, verify_manifest)

# These labels and receipts are parser tests, never models invoked by this suite.
MODELS = [{'provider': 'unit-test-only', 'name': name, 'revision': 'synthetic-20261024'} for name in ('alpha', 'beta')]


def require_native():
    try: return find_rustc(os.environ.get('RUSTC'))
    except Exception as exc: raise unittest.SkipTest('native Rust toolchain unavailable: ' + str(exc)) from exc


def fake_usage(model, total=6):
    return {'input_tokens': total - 2, 'output_tokens': 2, 'total_tokens': total, 'tool_calls': 0,
            'provider_calls': [{'request_id': 'synthetic-unit-test-receipt', 'model': model,
                                'input_tokens': total - 2, 'output_tokens': 2,
                                'raw_usage': {'unit_test_only': True, 'input_tokens': total - 2, 'output_tokens': 2}}]}


class CrossfileFrozenTests(unittest.TestCase):
    def test_five_real_paired_multimodule_bundles_and_four_arms(self):
        self.assertEqual(len(TASK_IDS), 5)
        self.assertEqual(len(ARMS), 4)
        verify_manifest()
        for task in TASK_IDS:
            left, right = (task_request(task, lang) for lang in LANGUAGES)
            self.assertEqual(left['instructions'], right['instructions'])
            self.assertEqual(left['public_tests'], right['public_tests'])
            for request in (left, right):
                self.assertEqual(len(request['editable']), 2)
                self.assertNotIn(request['entry'], request['editable'])
                reference = trusted_reference(task, request['language'])
                self.assertTrue(all(reference[path] != request['files'][path] for path in request['editable']))
                public = canonical(request).decode()
                self.assertNotIn('_private/', public)
                self.assertNotIn('hidden_cases', public)
                self.assertEqual(snapshot_id(request['files']), request['base_sha256'])
        native = task_request('native_bridge', 'rust')
        self.assertIn('native/arith.c', native['files'])
        self.assertIn('native/meter.cpp', native['files'])

    def test_changed_frozen_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary) / 'study'
            shutil.copytree(ROOT, clone, ignore=shutil.ignore_patterns('__pycache__', 'evidence'))
            source = clone / 'tasks/owned_result/hepta/storage.hepta'
            source.write_text(source.read_text() + '\n// changed\n')
            with self.assertRaisesRegex(ValueError, 'E_TASK_STALE'): verify_manifest(clone)

    def test_file_mutation_scope_cannot_change_main_native_or_inventory(self):
        request = task_request('native_bridge', 'rust')
        for bad in ({'main.rs': ''}, {'native/meter.cpp': ''}, {'../leak': ''}, {'new.rs': ''}):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'E_EDIT_SCOPE'):
                apply_files(request, request['files'], bad)

    def test_oracle_has_boundary_and_actual_resource_expectations(self):
        self.assertEqual(sum(len(hidden_cases(task)) for task in TASK_IDS), 312)
        empty = {'id': 0, 'a': 0, 'b': 0, 'refuse': False}
        self.assertEqual(expected('owned_result', empty)['result'], -1)
        refused = expected('owned_result', {'id': 1, 'a': 257, 'b': 1, 'refuse': True})
        self.assertEqual((refused['result'], refused['allocations'], refused['frees'], refused['refusals']), (-3, 0, 0, 1))
        cancelled = expected('resource_cancel', {'id': 2, 'a': 17, 'b': 1, 'refuse': False})
        self.assertEqual((cancelled['threads'], cancelled['joins'], cancelled['allocations'], cancelled['frees']), (1, 1, 1, 1))
        self.assertEqual(expected('defect_repair', {'id': 0, 'a': 64, 'b': 100, 'refuse': False})['result'], 64)
        self.assertEqual(expected('defect_repair', {'id': 0, 'a': 8, 'b': -6, 'refuse': False})['result'], 3)


class CrossfileSemanticTests(unittest.TestCase):
    def test_rust_lexer_handles_nested_comments_raw_strings_characters_lifetimes(self):
        source = '''/* outer { /* nested } */ } */
pub fn f<'a>(x: &'a str) -> &'a str {
    let a = r###" } { fn injected() {} "###;
    let b = '\\u{7b}'; let c = '}'; let d = "escaped \\\" }";
    x
}
'''
        indexed = nodes('rust', source, 'm.rs')
        self.assertEqual([(n['kind'], n['symbol']) for n in indexed if n['kind'] == 'function'], [('function', 'f')])
        self.assertEqual(len([n for n in indexed if n['kind'] == 'body']), 1)

    def test_rust_index_rejects_unsupported_top_level_and_broken_delimiters(self):
        for source in ('impl S {}', 'mod m { fn f() {} }', 'macro_rules! x {()=>{}}',
                       'fn f() { r#"unterminated }', 'fn f() { /* no close', 'fn f() { ] }',
                       'pub(crate) fn f() {}', 'fn f<const N: usize>() {}'):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'E_RUST_INDEX'):
                nodes('rust', source, 'm.rs')

    def test_both_languages_offer_same_function_body_declaration_kinds(self):
        for lang in LANGUAGES:
            request = task_request('api_migration', lang)
            path = 'pricing.' + ('rs' if lang == 'rust' else 'hepta')
            kinds = {n['kind'] for n in nodes(lang, request['files'][path], path)}
            self.assertEqual(kinds, {'function', 'body', 'declaration'})

    def test_node_replacement_cannot_append_declarations_or_use_stale_ids(self):
        for lang in LANGUAGES:
            request = task_request('defect_repair', lang)
            path = 'search.' + ('rs' if lang == 'rust' else 'hepta')
            target = next(n for n in nodes(lang, request['files'][path], path) if n['kind'] == 'body')
            appended = '{} fn injected() -> usize ' + ('effects {} ' if lang == 'hepta' else '') + '{ return 0; }'
            edit = {'op': 'replace_body', 'target': path, 'node': target['id'], 'replacement': appended}
            with self.assertRaisesRegex(ValueError, 'E_PATCH_SCOPE'):
                replace_nodes(request, request['files'], [edit])
            edit['node'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'E_PATCH_NODE'):
                replace_nodes(request, request['files'], [edit])

    def test_overlapping_body_and_function_edits_reject(self):
        request = task_request('defect_repair', 'rust')
        path = 'search.rs'
        edits = [{'op': 'replace_' + n['kind'], 'target': path, 'node': n['id'], 'replacement': n['text']}
                 for n in nodes('rust', request['files'][path], path) if n['kind'] in {'body', 'function'}]
        with self.assertRaisesRegex(ValueError, 'E_PATCH_OVERLAP'):
            replace_nodes(request, request['files'], edits)

    def test_arm_capabilities_are_explicit(self):
        for arm, profile in ARMS.items():
            session = StudySession(task_request('defect_repair', profile['language']), arm, fixture=True, rustc=require_native())
            self.addCleanup(session.close)
            unauthorized = 'replace_files' if profile['semantic_tools'] else 'query_nodes'
            with self.assertRaisesRegex(ValueError, 'E_TOOL'):
                session.execute(unauthorized, {}, 1)


class CrossfileNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rustc = require_native()
        if not shutil.which('gcc') or not shutil.which('g++'): raise unittest.SkipTest('gcc/g++ unavailable')
        cls.qualification = qualify_fixtures(cls.rustc)

    def test_twenty_four_arm_reference_scripts_all_execute_native_hidden_tests(self):
        q = self.qualification
        self.assertEqual(q['status'], 'qualified_fixtures_only')
        self.assertEqual((q['fixture_runs'], q['hidden_native_cases_passed']), (20, 1248))
        self.assertEqual((q['actual_ai_model_runs'], q['provider_tokens']), (0, 0))
        self.assertEqual(q['production_workspace_v4_runs'],5)
        self.assertTrue(q['claims']['production_workspace_v4_exercised'])
        self.assertFalse(q['ai_comparison_eligible'])
        self.assertIsNone(q['human_seconds'])
        for run in q['runs']:
            verify_record(run)
            self.assertEqual(run['status'], 'fixture_scored')
            self.assertTrue(run['score']['ok'])
            self.assertEqual(run['usage']['provider_calls'], [])
            self.assertFalse(run['ai_comparison_eligible'])
            self.assertIsNotNone(run['initialization_seconds'])
            self.assertGreaterEqual(run['agent_wall_seconds'],run['initialization_seconds'])
            self.assertEqual(run['claims']['production_workspace_v4_exercised'],run['arm']=='hepta_protocol')
            expected_tools = ['query_nodes', 'replace_nodes', 'public_test'] if ARMS[run['arm']]['semantic_tools'] else ['replace_files', 'public_test']
            self.assertEqual([t['tool'] for t in run['tools']], expected_tools)

    def test_all_ten_starters_compile_and_fail_real_target_validation(self):
        for starter in self.qualification['starters']:
            self.assertTrue(starter['starter_compiles_without_new_contract']['ok'], starter)
            self.assertTrue(starter['starter_fails_target_oracle'], starter)
            score = starter['target_score']
            self.assertEqual(score['total'], len(hidden_cases(starter['task_id'])))
            if starter['task_id'] == 'resource_cancel':
                self.assertEqual(score['native_status'], 'timeout')
                self.assertEqual(score['passed'], 0)

    def test_atomic_crossfile_api_change_rejects_partial_then_accepts_complete(self):
        for lang in LANGUAGES:
            request = task_request('api_migration', lang)
            reference = trusted_reference('api_migration', lang)
            session = StudySession(request, lang + '_plain', rustc=self.rustc, fixture=True)
            path = 'pricing.' + ('rs' if lang == 'rust' else 'hepta')
            before = session.version
            rejected = session.execute('replace_files', {'expected_version': before, 'files': {path: reference[path]}}, 10)
            self.assertFalse(rejected['ok'])
            self.assertEqual(session.version, before)
            self.assertEqual(session.files, request['files'])
            accepted = session.execute('replace_files', {'expected_version': before,
                'files': {p: reference[p] for p in request['editable']}}, 10)
            self.assertTrue(accepted['ok'], accepted)
            self.assertNotEqual(session.version, before)
            with self.assertRaisesRegex(ValueError, 'E_STALE_SNAPSHOT'):
                session.execute('replace_files', {'expected_version': before, 'files': {path: reference[path]}}, 10)

    def test_balanced_semantic_edit_still_requires_real_compiler_acceptance(self):
        for lang, arm in (('rust', 'rust_semantic'), ('hepta', 'hepta_protocol')):
            request = task_request('defect_repair', lang)
            session = StudySession(request, arm, rustc=self.rustc, fixture=True)
            path = 'search.' + ('rs' if lang == 'rust' else 'hepta')
            self.addCleanup(session.close)
            node = next(n for n in session.execute('query_nodes', {}, 10)['nodes'][path] if n['kind'] == 'body')
            result = session.execute('replace_nodes', {'expected_version': session.version, 'edits': [
                {'op': 'replace_body', 'target': path, 'node': node['id'], 'replacement': '{ return missing_value; }'}]}, 10)
            self.assertFalse(result['ok'])
            self.assertFalse(result['applied'])
            self.assertEqual(session.files, request['files'])

    def test_native_allocator_detects_rust_leak_even_with_correct_return_values(self):
        request = task_request('owned_result', 'rust')
        files = trusted_reference('owned_result', 'rust')
        files['storage.rs'] = files['storage.rs'].replace('drop(packet);', 'std::mem::forget(packet);')
        score = score_candidate(request, files, public=True, rustc=self.rustc, fixture=True)
        self.assertTrue(score['compiled'])
        self.assertFalse(score['ok'])
        self.assertEqual(score['public_mismatches'][0]['actual']['result'], score['public_mismatches'][0]['expected']['result'])
        self.assertEqual(score['public_mismatches'][0]['actual']['frees'], 0)

    def test_real_allocator_refusal_does_not_accept_infallible_oom_abort(self):
        request = task_request('owned_result', 'rust')
        files = trusted_reference('owned_result', 'rust')
        files['storage.rs'] = files['storage.rs'].replace(
            'let mut bytes = Vec::new();\n    if bytes.try_reserve_exact(n).is_err() { return Err(3); }\n    bytes.resize(n, 0u8);',
            'let mut bytes = vec![0u8; n];')
        score = score_candidate(request, files, rustc=self.rustc, fixture=True)
        self.assertTrue(score['compiled'])
        self.assertFalse(score['ok'])
        self.assertNotEqual(score['native_returncode'], 0)
        self.assertEqual(score['passed'], 0)

    def test_candidate_cannot_mutate_trusted_driver_allocator_counters(self):
        request = task_request('owned_result', 'rust')
        files = trusted_reference('owned_result', 'rust')
        # Exact independently reproduced exploit against the earlier shared
        # crate layout. No Packet is allocated; only observation state is forged.
        files['service.rs'] = '''pub fn process(n:usize, abort_after_create:bool)->i64 {
 use std::sync::atomic::Ordering;
 if n==0{return -1;}
 if crate::REFUSE.load(Ordering::SeqCst){crate::REFUSALS.store(1,Ordering::SeqCst);return -3;}
 crate::ALLOCS.store(1,Ordering::SeqCst);crate::FREES.store(1,Ordering::SeqCst);
 if abort_after_create{return -2;}
 (0..n).map(|i|((i*7+3)%251)as i64).sum()
}\n'''
        score = score_candidate(request, files, rustc=self.rustc, fixture=True)
        self.assertFalse(score['compiled'])
        self.assertEqual(score['build']['stage'], 'candidate_rustc')
        self.assertIn('cannot find value', score['build']['diagnostics'])
        self.assertEqual(score['total'], 24)

    def test_hepta_missing_early_error_drop_is_rejected_before_native_execution(self):
        request = task_request('owned_result', 'hepta')
        files = trusted_reference('owned_result', 'hepta')
        files['service.hepta'] = files['service.hepta'].replace('if abort_after_create { storage::close(move packet); return -2; }',
                                                               'if abort_after_create { return -2; }')
        score = score_candidate(request, files, rustc=self.rustc, fixture=True)
        self.assertFalse(score['compiled'])
        self.assertEqual(score['total'], 24)
        self.assertEqual(score['build']['stage'], 'frontend')

    def test_native_calls_cannot_be_replaced_with_same_arithmetic(self):
        request = task_request('native_bridge', 'rust')
        files = trusted_reference('native_bridge', 'rust')
        files['foreign.rs'] = files['foreign.rs'].replace('unsafe { c_adjust(a, b) }', 'a * 3 + b').replace(
            'unsafe { cpp_scale(value, factor) }',
            'if factor < 0 || value < -10000 || value > 10000 { ForeignResult {value:0,status:1} } else { ForeignResult {value:(2*value+1)*factor,status:0} }')
        score = score_candidate(request, files, public=True, rustc=self.rustc, fixture=True)
        self.assertTrue(score['compiled'])
        self.assertFalse(score['ok'])
        for mismatch in score['public_mismatches']:
            self.assertEqual(mismatch['actual']['result'], mismatch['expected']['result'])
            self.assertEqual((mismatch['actual']['c_calls'], mismatch['actual']['cpp_calls']), (0, 0))

    def test_fake_cancellation_without_thread_does_not_pass(self):
        request = task_request('resource_cancel', 'rust')
        files = trusted_reference('resource_cancel', 'rust')
        files['service.rs'] = '''pub fn run(n:usize,cancel:bool)->i64 {
 if n<2{return -1;} let mut data=vec![0u8;n];
 for i in 1..n {data[i]=(i%251) as u8;}
 let value:i64=data[1..].iter().map(|x|*x as i64).sum();drop(data);
 value+if cancel{1000000}else{0}
}\n'''
        score = score_candidate(request, files, public=True, rustc=self.rustc, fixture=True)
        self.assertTrue(score['compiled'])
        self.assertFalse(score['ok'])
        self.assertEqual(score['public_mismatches'][0]['actual']['threads'], 0)

    def test_fixture_snapshot_replay_is_explicit_and_never_a_new_ai_run(self):
        run = self.qualification['runs'][0]
        with self.assertRaisesRegex(ValueError, 'E_FIXTURE_MODE'): replay(run, rustc=self.rustc)
        result = replay(run, rustc=self.rustc, trusted_fixture=True)
        self.assertTrue(result['score']['ok'])
        self.assertEqual(result['actual_ai_model_runs'], 0)
        self.assertFalse(result['ai_comparison_eligible'])


class CrossfilePlanAndAccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rustc = require_native()
        cls.adapter_temporary = tempfile.TemporaryDirectory(prefix='hepta-plan-unit-test-')
        cls.addClassCleanup(cls.adapter_temporary.cleanup)
        cls.adapter_dir = Path(cls.adapter_temporary.name)
        (cls.adapter_dir / 'test.py').write_text('# Explicit offline-only unit-test bundle.\n')
        cls.command = ['/usr/bin/python3', '{adapter}/test.py']
        cls.config, _ = actual_config(cls.adapter_dir, cls.command)
        cls.plan = make_plan(MODELS, Budget(input_tokens=100, output_tokens=100, total_tokens=200,
                                          wall_seconds=30, tool_calls=4), rustc=cls.rustc,
                             adapter_configs=[{'model': model, **cls.config} for model in MODELS])

    def blocked(self, task='defect_repair', arm='rust_plain'):
        with patch('experiments.crossfile_eval.runner.probe_sandbox', return_value={'available': False, 'reason': 'unit-test unavailable'}), \
             patch('experiments.crossfile_eval.runner.JsonAdapter', side_effect=AssertionError('must never spawn')), \
             patch('experiments.crossfile_eval.runner.StudySession', side_effect=AssertionError('must never initialize')):
            return evaluate(task, arm, self.adapter_dir, self.command, MODELS[0], plan=self.plan, rustc=self.rustc)

    def test_preregistered_full_matrix_and_exact_revision_and_compiler(self):
        self.assertEqual(len(self.plan['schedule']), 40)
        verify_plan(self.plan, rustc=self.rustc, current_environment=True)
        moving = copy.deepcopy(MODELS); moving[0]['revision'] = 'latest'
        with self.assertRaisesRegex(ValueError, 'E_MODEL_REVISION'): make_plan(moving, rustc=self.rustc)
        edited = copy.deepcopy(self.plan); edited['schedule'].pop()
        edited['plan_sha256'] = digest(canonical({k:v for k,v in edited.items() if k!='plan_sha256'}))
        with self.assertRaisesRegex(ValueError, 'E_PLAN'): verify_plan(edited)
        edited = copy.deepcopy(self.plan); edited['compiler']['python_version'] = 'different'
        edited['plan_sha256'] = digest(canonical({k:v for k,v in edited.items() if k!='plan_sha256'}))
        with self.assertRaisesRegex(ValueError, 'E_PLAN_STALE'):
            verify_plan(edited, rustc=self.rustc, current_environment=True)

    def test_namespace_failure_blocks_adapter_before_any_provider_invocation(self):
        report = self.blocked()
        self.assertEqual(report['status'], 'environment_blocked')
        self.assertFalse(report['adapter_invoked'])
        self.assertEqual(report['actual_ai_model_runs'], 0)
        self.assertIsNone(report['usage'])
        self.assertIsNone(report['human_seconds'])
        verify_record(report)

    def test_fixture_mode_cannot_be_silently_enabled_for_provider(self):
        with self.assertRaisesRegex(ValueError, 'E_FIXTURE_MODE'):
            evaluate('defect_repair','rust_plain','/absent',[],MODELS[0],kind='provider',fixture_qualification=True)

    def test_all_missing_and_blocked_cells_remain_in_denominators(self):
        result = compare(self.plan, [self.blocked()])
        self.assertEqual(result['planned_attempts'], 40)
        self.assertEqual(result['actual_ai_model_runs'], 0)
        self.assertEqual(result['contrasts'], [])
        self.assertTrue(all(row['planned_attempts'] == 5 and row['failures_including_missing'] == 5 for row in result['rows']))
        self.assertTrue(all(row['human_seconds_total'] is None and row['provider_tokens_total'] is None for row in result['rows']))
        self.assertEqual(sum(row['missing_or_invalid_records'] for row in result['rows']), 39)

    def test_duplicate_samples_cannot_select_a_best_retry(self):
        report = self.blocked()
        result = compare(self.plan, [report, report])
        self.assertTrue(any('duplicate' in issue for issue in result['issues']))
        self.assertEqual(sum(row['missing_or_invalid_records'] for row in result['rows']), 40)

    def test_timeout_and_incomplete_cost_receipts_are_failure_not_exclusion(self):
        report = self.blocked()
        report.update(status='attempt_failed', sandbox={'available':True}, isolation='allowlisted_namespace_capsules',
                      adapter_invoked=True, usage=fake_usage(MODELS[0]), observed_tool_calls=0,
                      usage_complete=False, agent_wall_seconds=30.01, error={'code':'E_WALL_BUDGET'})
        # Synthetic metering only: this record is never saved as experiment evidence.
        result = compare(self.plan, [seal_record(report)])
        row = next(r for r in result['rows'] if r['model']==MODELS[0] and r['arm']=='rust_plain')
        self.assertEqual((row['planned_attempts'], row['successful_tasks'], row['failures_including_missing']), (5,0,5))
        self.assertEqual(row['provider_tokens_known'], 6)
        self.assertIsNone(row['provider_tokens_total'])
        self.assertIsNone(row['provider_tokens_per_success'])

    def test_fixture_provenance_and_changed_reports_cannot_enter_ai_statistics(self):
        report = self.blocked()
        report['run_kind'] = 'trusted_fixture_qualification'
        result = compare(self.plan, [seal_record(report)])
        self.assertEqual(result['actual_ai_model_runs'], 0)
        self.assertTrue(result['issues'])
        report['human_seconds'] = 0
        with self.assertRaisesRegex(ValueError, 'E_RECORD_STALE'): verify_record(report)

    def test_rejected_later_tool_frame_preserves_last_validated_cost_prefix(self):
        report = self.blocked()
        usage = fake_usage(MODELS[0]); usage['tool_calls'] = 4
        report.update(status='attempt_failed', sandbox={'available':True}, isolation='allowlisted_namespace_capsules',
                      adapter_invoked=True, usage=usage, observed_tool_calls=5, validated_tool_calls=4,
                      usage_complete=False, agent_wall_seconds=0.2, error={'code':'E_TOOL_BUDGET'})
        result = compare(self.plan, [seal_record(report)])
        row = next(r for r in result['rows'] if r['model']==MODELS[0] and r['arm']=='rust_plain')
        self.assertEqual(row['provider_tokens_known'], 6)
        self.assertIsNone(row['provider_tokens_total'])
        self.assertEqual(row['failures_including_missing'], 5)

    def test_recycled_provider_receipt_invalidates_every_affected_sample(self):
        template = self.blocked()
        reports = []
        for scheduled in self.plan['schedule']:
            model = MODELS[scheduled['model_index']]
            task, arm, replica = scheduled['task'], scheduled['arm'], scheduled['replicate']
            request = task_request(task, ARMS[arm]['language'])
            report = copy.deepcopy(template)
            report.update(model=model, task_id=task, arm=arm, language=request['language'], replicate=replica,
                          sample_id=sample_id(self.plan,model,task,arm,replica),
                          task_sha256=request['task_sha256'], base_sha256=request['base_sha256'],
                          status='attempt_failed', sandbox={'available':True}, isolation='allowlisted_namespace_capsules',
                          adapter_invoked=True, usage=fake_usage(model), observed_tool_calls=0,
                          validated_tool_calls=0, usage_complete=False, agent_wall_seconds=0.1)
            reports.append(seal_record(report))
        result = compare(self.plan, reports)
        self.assertEqual(result['status'], 'not_qualified')
        self.assertFalse(result['outcome_comparison_eligible'])
        self.assertEqual(result['actual_ai_model_runs'], 0)
        self.assertEqual(sum(r['failures_including_missing'] for r in result['rows']), 40)
        self.assertTrue(any('reused across planned samples' in issue for issue in result['issues']))

    def test_claimed_success_without_matching_native_evidence_stays_failure(self):
        report = self.blocked()
        request = task_request('defect_repair', 'rust')
        report.update(status='provider_scored', sandbox={'available':True}, isolation='allowlisted_namespace_capsules',
                      adapter_invoked=True, usage=fake_usage(MODELS[0]), observed_tool_calls=0,
                      usage_complete=True, agent_wall_seconds=0.1,
                      submitted_files=request['files'], submitted_sha256=request['base_sha256'],
                      score={'ok':True,'compiled':True,'passed':1,'total':1,'native_status':'exited',
                             'native_returncode':0,'protocol_error':None,'source_sha256':request['base_sha256'],
                             'artifact_sha256':'0'*64})
        result = compare(self.plan, [seal_record(report)])
        self.assertEqual(sum(r['successful_tasks'] for r in result['rows']), 0)
        self.assertTrue(any('native evidence' in issue for issue in result['issues']))

    def test_mismatched_provider_revision_does_not_enter_cost_or_success_totals(self):
        report = self.blocked()
        report.update(status='attempt_failed', sandbox={'available':True}, adapter_invoked=True,
                      usage=fake_usage(MODELS[1]), observed_tool_calls=0, agent_wall_seconds=0.1)
        result = compare(self.plan, [seal_record(report)])
        self.assertEqual(result['actual_ai_model_runs'], 0)
        self.assertTrue(all(row['provider_tokens_known'] is None for row in result['rows']))

    def test_cost_observation_requires_sources_and_preserves_missing_as_null(self):
        run = self.blocked()
        missing = cost_record(run)
        self.assertIsNone(missing['human_seconds'])
        self.assertIsNone(missing['monetary_cost_usd'])
        with self.assertRaisesRegex(ValueError, 'observer'): cost_record(run, human_seconds=0)
        with self.assertRaisesRegex(ValueError, 'price source'): cost_record(run, monetary_cost_usd=0.2)
        with self.assertRaisesRegex(ValueError, 'finite'): cost_record(run, human_seconds=float('nan'), human_observer='clock')
        measured = cost_record(run, human_seconds=4.5, human_observer='unit-test timer', monetary_cost_usd=0.02, price_source='unit-test receipt')
        result = compare(self.plan, [run], [measured])
        row = next(r for r in result['rows'] if r['model']==MODELS[0] and r['arm']=='rust_plain')
        self.assertEqual(row['human_seconds_known'], 4.5)
        self.assertIsNone(row['human_seconds_total'])

    def test_record_output_and_cli_are_append_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'record.json'
            write_append_only(output, {'unchanged': True})
            before = output.read_bytes()
            with self.assertRaises(FileExistsError): write_append_only(output, {'changed': True})
            with redirect_stdout(io.StringIO()): code = main(['qualify-fixtures', '--output', str(output)])
            self.assertEqual(code, 2)
            self.assertEqual(output.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
