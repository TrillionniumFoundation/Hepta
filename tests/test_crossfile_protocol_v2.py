"""Production workspace paths and offline-only provider protocol regression tests.

Synthetic receipts below are never saved as experiment evidence and never count
as qualification of a provider, model, cost advantage, or language advantage.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta.backend import find_rustc
from experiments.agent_eval.harness import Budget, EvalError
from experiments.crossfile_eval.adapter_binding import actual_config
from experiments.crossfile_eval.plan import make_plan, verify_plan
from experiments.crossfile_eval.records import seal_record
from experiments.crossfile_eval.reporting import compare
from experiments.crossfile_eval.runner import StudySession, evaluate
from experiments.crossfile_eval.scoring import study_frontend
from experiments.crossfile_eval.semantic import nodes
from experiments.crossfile_eval.tasks import canonical, digest, snapshot_id, task_request, trusted_reference
from experiments.crossfile_eval.workspace_evidence import validate_workspace_record

MODELS = [{'provider': 'offline-unit-test-only', 'name': name, 'revision': 'synthetic-20261024'} for name in ('a', 'b')]


def native():
    try: return find_rustc(os.environ.get('RUSTC'))
    except Exception as exc: raise unittest.SkipTest('native compiler unavailable: ' + str(exc)) from exc


def receipts(model, tools=0, total=6):
    return {'input_tokens': total-2, 'output_tokens': 2, 'total_tokens': total, 'tool_calls': tools,
            'provider_calls': [{'request_id': 'offline-test-only-1', 'model': model,
                                'input_tokens': total-2, 'output_tokens': 2,
                                'raw_usage': {'offline_unit_test': True, 'input_tokens': total-2, 'output_tokens': 2}}]}


class AccountingOnlySession:
    """No compilation claim: used only in isolated parser/accounting unit tests."""
    def __init__(self, request, arm, **kwargs):
        self.request, self.files, self.version = request, request['files'], request['base_sha256']
        self.tools = ['read_file']
    def execute(self, operation, arguments, timeout):
        return {'ok': True, 'version': self.version, 'source': self.files[arguments['path']]}
    def evidence(self):
        return {'backend': 'offline_accounting_stub', 'production_workspace_v4_exercised': False, 'validation_seconds': 0.0}
    def finalize(self, timeout): return self.files
    def close(self): pass


class CrossfileProtocolV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rustc = native()
        cls.temp = tempfile.TemporaryDirectory(prefix='hepta-accounting-test-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        (cls.directory / 'adapter.py').write_text('# Offline unit-test bundle; no model invocation.\n')
        cls.command = ['/usr/bin/python3', '{adapter}/adapter.py']
        cls.config, _ = actual_config(cls.directory, cls.command)
        cls.plan = make_plan(MODELS, Budget(input_tokens=100, output_tokens=100, total_tokens=200,
                                          wall_seconds=20, tool_calls=4), rustc=cls.rustc,
                             adapter_configs=[{'model': m, **cls.config} for m in MODELS])

    def run_frames(self, frames):
        class OfflineAdapter:
            bytes_read, stderr = 0, b''
            def __init__(self, *args, **kwargs): self.frames = iter(frames)
            def send(self, value, deadline):
                if value['kind'] == 'start':
                    self.request = value
                    assert value['capabilities']['abort_frame']
                    assert 0 < value['remaining']['wall_seconds'] <= value['budget']['wall_seconds']
            def read(self, deadline):
                frame = next(self.frames)
                identity = {k: self.request[k] for k in ('request_id','task_sha256','base_sha256','model','adapter_kind')}
                return {**identity, **frame}
            def close(self): pass
        with patch('experiments.crossfile_eval.runner.probe_sandbox', return_value={'available': True}), \
             patch('experiments.crossfile_eval.runner.JsonAdapter', OfflineAdapter), \
             patch('experiments.crossfile_eval.runner.StudySession', AccountingOnlySession), \
             patch('experiments.crossfile_eval.runner.score_candidate', side_effect=AssertionError('abort may not score')):
            return evaluate('defect_repair', 'rust_plain', self.directory, self.command, MODELS[0],
                            plan=self.plan, rustc=self.rustc)

    def abort(self, usage, complete=False, **extra):
        return {'kind': 'abort', 'usage': usage, 'usage_complete': complete,
                'error': {'code': 'E_ADAPTER_TEST', 'message': 'Fixed offline test explanation.'}, **extra}

    def row(self, report):
        result = compare(self.plan, [report])
        self.assertEqual(result['planned_attempts'], 40)
        row = next(r for r in result['rows'] if r['model'] == MODELS[0] and r['arm'] == 'rust_plain')
        self.assertEqual(row['failures_including_missing'], 5)
        return row

    def test_abort_before_any_receipt_is_failure_with_unknown_cost(self):
        r = self.run_frames([self.abort(None)])
        self.assertEqual(r['status'], 'attempt_failed')
        self.assertTrue(r['adapter_aborted'])
        self.assertIsNone(r['usage'])
        self.assertFalse(r['usage_complete'])
        self.assertIsNone(r['score'])
        self.assertEqual(r['observed_tool_calls'], 0)
        self.assertIsNone(self.row(r)['provider_tokens_known'])

    def test_abort_after_paid_call_keeps_known_complete_cost_and_fails(self):
        r = self.run_frames([self.abort(receipts(MODELS[0]), True)])
        self.assertEqual(r['status'], 'attempt_failed')
        self.assertTrue(r['usage_complete'])
        self.assertEqual(r['usage']['total_tokens'], 6)
        self.assertIsNone(r['score'])
        self.assertEqual(self.row(r)['provider_tokens_known'], 6)
        from experiments.crossfile_eval.reporting import _facts
        facts = _facts(self.plan, r, (MODELS[0], 'defect_repair', 'rust_plain', 0))
        self.assertTrue(facts['tokens_complete'])
        self.assertFalse(facts['success'])

    def test_abort_over_cap_retains_complete_real_receipt_prefix(self):
        r = self.run_frames([self.abort(receipts(MODELS[0], total=250), True)])
        self.assertEqual(r['status'], 'attempt_failed')
        self.assertEqual(r['error']['code'], 'E_TOKEN_BUDGET')
        self.assertEqual(r['usage']['total_tokens'], 250)
        self.assertTrue(r['usage_complete'])
        self.assertEqual(self.row(r)['provider_tokens_known'], 250)

    def test_null_abort_after_tool_never_erases_validated_usage(self):
        usage = receipts(MODELS[0], tools=1)
        r = self.run_frames([{'kind':'tool_call','call_id':'1','tool':'read_file',
                              'arguments':{'path':'search.rs'},'usage':usage}, self.abort(None)])
        self.assertEqual(r['usage'], usage)
        self.assertEqual((r['observed_tool_calls'], r['validated_tool_calls']), (1, 1))
        self.assertFalse(r['usage_complete'])
        self.assertEqual(self.row(r)['provider_tokens_known'], 6)

    def test_pending_abort_retains_unknown_total_and_rejects_complete_claim(self):
        pending = {'client_request_id': 'offline-pending', 'request_id': None, 'receipt_verified': False}
        for complete in (False, True):
            with self.subTest(complete=complete):
                r = self.run_frames([self.abort(receipts(MODELS[0]), complete, pending_provider_request=pending)])
                self.assertEqual(r['status'], 'attempt_failed')
                self.assertFalse(r['usage_complete'])
                self.assertEqual(r['usage']['total_tokens'], 6)
                self.assertEqual(r['pending_provider_request'], pending)
                self.assertIsNone(r['score'])
        r = self.run_frames([self.abort(None, True)])
        self.assertEqual(r['error']['code'], 'E_PROTOCOL')
        self.assertIsNone(r['usage'])
        self.assertFalse(r['usage_complete'])

    def test_initialization_failure_precedes_adapter_and_hidden_scoring(self):
        with patch('experiments.crossfile_eval.runner.probe_sandbox', return_value={'available': True}), \
             patch('experiments.crossfile_eval.runner.StudySession', side_effect=EvalError('E_WALL_BUDGET', 'offline setup timeout')), \
             patch('experiments.crossfile_eval.runner.JsonAdapter', side_effect=AssertionError('must not spawn')):
            r = evaluate('defect_repair', 'hepta_protocol', self.directory, self.command, MODELS[0],
                         plan=self.plan, rustc=self.rustc)
        self.assertEqual(r['status'], 'attempt_failed')
        self.assertFalse(r['adapter_invoked'])
        self.assertIsNotNone(r['initialization_seconds'])
        self.assertGreaterEqual(r['agent_wall_seconds'], r['initialization_seconds'])
        self.assertIsNone(r['score'])

    def test_unconfigured_plan_cannot_start_any_provider(self):
        plan = make_plan(MODELS, rustc=self.rustc)
        self.assertFalse(plan['provider_ready'])
        with self.assertRaisesRegex(ValueError, 'E_ADAPTER_CONFIG'):
            evaluate('defect_repair','rust_plain',self.directory,self.command,MODELS[0],plan=plan,rustc=self.rustc)
        self.assertEqual(compare(plan, [])['planned_attempts'], 40)

    def test_changed_adapter_bundle_argv_environment_network_is_not_invoked(self):
        alternatives = [([*self.command, 'extra'], (), False),
                        (self.command, ('UNIT_TEST_SECRET_NAME_ONLY',), False),
                        (self.command, (), True)]
        for command, names, network in alternatives:
            with self.subTest(command=command,names=names,network=network), \
                 patch('experiments.crossfile_eval.runner.StudySession', side_effect=AssertionError('must not initialize')):
                r = evaluate('defect_repair','rust_plain',self.directory,command,MODELS[0],plan=self.plan,
                             rustc=self.rustc,pass_env=names,network=network)
            self.assertEqual(r['error']['code'], 'E_ADAPTER_CONFIG_MISMATCH')
            self.assertFalse(r['adapter_invoked'])
            self.assertIsNone(self.row(r)['provider_tokens_known'])
        with tempfile.TemporaryDirectory() as tmp:
            other=Path(tmp);(other/'adapter.py').write_text('# Different wrapper.\n')
            r=evaluate('defect_repair','rust_plain',other,self.command,MODELS[0],plan=self.plan,rustc=self.rustc)
            self.assertEqual(r['error']['code'], 'E_ADAPTER_CONFIG_MISMATCH')

    def test_comparison_rejects_one_arm_with_a_different_frozen_wrapper(self):
        r = self.run_frames([self.abort(receipts(MODELS[0]), True)])
        r['adapter']['command'] = [*r['adapter']['command'], 'different-prompt-wrapper']
        # Detached copy: mutating this fixture must not alter the class plan.
        r = seal_record(r)
        result = compare(self.plan, [r])
        self.assertFalse(result['outcome_comparison_eligible'])
        self.assertEqual(result['actual_ai_model_runs'], 0)
        self.assertTrue(result['issues'])

    def test_plan_mapping_must_cover_models_once_and_stays_immutable(self):
        verify_plan(self.plan)
        incomplete = [{'model': MODELS[0], **self.config}]
        with self.assertRaisesRegex(ValueError, 'E_ADAPTER_CONFIG'):
            make_plan(MODELS,rustc=self.rustc,adapter_configs=incomplete)
        changed = copy.deepcopy(self.plan)
        changed['adapter_configs'][0]['network_requested'] = True
        with self.assertRaisesRegex(ValueError, 'E_PLAN_STALE'): verify_plan(changed)


class CrossfileProductionSessionTests(unittest.TestCase):
    def session(self, task='api_migration', request=None):
        s=StudySession(request or task_request(task,'hepta'),'hepta_protocol',rustc=native(),fixture=True)
        self.addCleanup(s.close)
        return s

    def edits(self, session, task, only=None):
        indexed=session.execute('query_nodes',{},10)
        reference=trusted_reference(task,'hepta')
        edits=[]
        for path in session.request['editable']:
            if only and path != only: continue
            old=[n for n in indexed['nodes'][path] if n['kind']=='declaration']
            new=[n for n in nodes('hepta',reference[path],path) if n['kind']=='declaration']
            edits += [{'op':'replace_declaration','target':path,'node':a['id'],'replacement':b['text']}
                      for a,b in zip(old,new)]
        return edits

    def test_real_v4_prepare_commit_recover_pin_and_equal_public_scope(self):
        s=self.session()
        index=s.execute('query_nodes',{},10)
        self.assertEqual(index['operations'],['replace_function','replace_body','replace_declaration'])
        self.assertTrue(all(n['kind'] in {'function','body','declaration'} for v in index['nodes'].values() for n in v))
        before=s.version
        accepted=s.execute('replace_nodes',{'expected_version':before,'edits':self.edits(s,'api_migration')},20)
        self.assertTrue(accepted['ok'],accepted)
        self.assertTrue(accepted['interface_changed'])
        files=s.finalize(10)
        e=s.evidence()
        self.assertTrue(e['production_workspace_v4_exercised'])
        self.assertNotEqual(s.version,snapshot_id(files))
        self.assertNotEqual(before,s.version)
        self.assertEqual(accepted['workspace']['prepared'],accepted['workspace']['committed'])
        self.assertEqual(accepted['workspace']['publication']['journal']['state'],'committed')
        self.assertEqual(accepted['workspace']['publication']['journal']['after'],s.version)
        self.assertEqual(json.loads((s.directory/'store/CURRENT').read_text())['version'],s.version)
        events=e['events'];prepare=next(v for v in events if v['operation']=='prepare');commit=next(v for v in events if v['operation']=='commit')
        self.assertEqual(prepare['patch_sha256'],commit['patch_sha256'])
        self.assertEqual(prepare['current_snapshot']['version'],before)
        from experiments.crossfile_eval.scoring import compiler_identity
        record={'compiler':compiler_identity(native()),'session':e,'submitted_sha256':snapshot_id(files),
                'submitted_version':s.version,'claims':{'production_workspace_v4_exercised':True}}
        self.assertTrue(validate_workspace_record(record,require_committed=True))
        record['submitted_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'identities'):validate_workspace_record(record,require_committed=True)

    def test_partial_migration_and_failed_task_contract_never_publish(self):
        s=self.session();before=s.version;head=(s.directory/'store/CURRENT').read_bytes()
        partial=s.execute('replace_nodes',{'expected_version':before,'edits':self.edits(s,'api_migration',only='pricing.hepta')},15)
        self.assertFalse(partial['ok']);self.assertEqual((s.directory/'store/CURRENT').read_bytes(),head)
        # A syntactically valid no-op graph passes production validation, but
        # still lacks the target API contract and must not become a commit.
        indexed=s.execute('query_nodes',{},10);path='pricing.hepta'
        node=next(n for n in indexed['nodes'][path] if n['kind']=='declaration')
        same=s.execute('replace_nodes',{'expected_version':before,'edits':[
            {'op':'replace_declaration','target':path,'node':node['id'],'replacement':node['text']}]},15)
        self.assertFalse(same['ok']);self.assertFalse(same['applied'])
        self.assertEqual(s.version,before);self.assertEqual((s.directory/'store/CURRENT').read_bytes(),head)
        self.assertFalse(any(e['operation']=='commit' for e in s.events))

    def test_final_source_is_fresh_pin_not_mutable_parent_cache(self):
        s=self.session('defect_repair');original=dict(s.files)
        s.files={k:'// corrupt parent cache\n' for k in s.files}
        self.assertEqual(s.finalize(10),original)
        self.assertEqual(s.files,original)

    def test_transport_timeout_is_fatal_with_unverified_publication(self):
        s=self.session('defect_repair')
        with patch('experiments.crossfile_eval.workspace_session.run_bounded', return_value={
                'status':'timeout','returncode':-9,'stdout':'','stderr':''}):
            with self.assertRaisesRegex(EvalError,'publication state'):
                s.execute('read_file',{'path':'search.hepta'},1)
        self.assertEqual(s.publication_state,'unverified_after_pin')
        self.assertFalse(s.evidence()['production_workspace_v4_exercised'])

    def test_exact_crlf_sources_survive_child_profiles_and_workspace_pins(self):
        for language in ('rust','hepta'):
            request=task_request('defect_repair',language)
            request['files']={p:text.replace('\n','\r\n') for p,text in request['files'].items()}
            request['base_sha256']=snapshot_id(request['files'])
            result=study_frontend(request,request['files'],'query_nodes',fixture=True)
            self.assertTrue(result['ok'],result)
            for path, values in result['nodes'].items():
                self.assertTrue(all(n['source_sha256']==digest(request['files'][path].encode()) for n in values))
            if language=='hepta':
                s=self.session(request=request);self.assertEqual(s.finalize(10),request['files'])
                index=s.execute('query_nodes',{},10);path='search.hepta'
                node=next(n for n in index['nodes'][path] if n['kind']=='body')
                r=s.execute('replace_nodes',{'expected_version':s.version,'edits':[
                    {'op':'replace_body','target':path,'node':node['id'],'replacement':node['text']}]},15)
                self.assertTrue(r['ok'],r)
                self.assertEqual(s.finalize(10),request['files'])


if __name__=='__main__':unittest.main()
