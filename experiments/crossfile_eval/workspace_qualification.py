"""Trusted scripted v4 transactions under the real provider namespace policy.

This qualification creates no provider adapter and no provider receipt. Public
and trusted reference code are fixture inputs; hidden expectations remain in
the parent. No unavailable namespace or failed transaction has a fallback.
"""
from __future__ import annotations

import datetime
import time

from experiments.agent_eval.harness import EvalError
from experiments.agent_eval.sandbox import probe_sandbox

from .plan import evaluator_hash
from .records import seal_record
from .runner import StudySession
from .scoring import compiler_identity, score_candidate
from .semantic import nodes
from .tasks import TASK_IDS, snapshot_id, task_request, trusted_reference, verify_manifest
from .workspace_evidence import validate_workspace_record


def qualify_workspace(rustc=None, *, execution_context='unspecified_operator_environment'):
    sandbox = probe_sandbox()
    report = {'schema': 'hepta.crossfile_workspace_qualification.v1',
              'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'run_kind': 'trusted_namespace_workspace_qualification',
              'taskset_sha256': verify_manifest()['taskset_sha256'], 'evaluator_sha256': evaluator_hash(),
              'compiler': compiler_identity(rustc), 'environment': sandbox,
              'operator_execution_context': execution_context,
              'execution_context_verification': 'operator_annotation_not_automatic_host_attestation',
              'isolation': 'allowlisted_namespace_capsules', 'fixture_mode': False,
              'actual_ai_model_runs': 0, 'provider_tokens': 0, 'provider_receipts': [],
              'ai_comparison_eligible': False, 'human_seconds': None, 'monetary_cost_usd': None,
              'planned_workspace_fixtures': len(TASK_IDS), 'strict_workspace_v4_runs': 0,
              'hidden_native_cases_passed': 0, 'runs': [],
              'claims': {'production_workspace_v4_exercised': False,
                         'strict_hidden_test_namespace_isolation_exercised': False,
                         'measured_ai_productivity': False, 'hepta_advantage_established': False}}
    if not sandbox['available']:
        return seal_record({**report, 'status': 'environment_blocked', 'error': {
            'code': 'E_SANDBOX_UNAVAILABLE', 'message': sandbox['reason']}})
    for task in TASK_IDS:
        request = task_request(task, 'hepta')
        # These are frozen trusted reference sources, never provider-controlled
        # input to a parser in the parent and never sent to a provider process.
        reference = trusted_reference(task, 'hepta')
        replacements = {p: [n['text'] for n in nodes('hepta', reference[p], p) if n['kind'] == 'declaration']
                        for p in request['editable']}
        started, session = time.monotonic(), None
        deadline = started + 40.0
        def remaining():
            left = deadline - time.monotonic()
            if left <= 0: raise EvalError('E_WALL_BUDGET', 'workspace qualification deadline exhausted')
            return left
        run = {'task_id': task, 'arm': 'hepta_protocol', 'language': 'hepta',
               'run_kind': 'trusted_namespace_workspace_fixture', 'actual_ai_model_runs': 0,
               'isolation': 'allowlisted_namespace_capsules', 'fixture_mode': False,
               'provider_receipts': [], 'compiler': report['compiler'], 'score': None,
               'claims': {'production_workspace_v4_exercised': False}}
        try:
            init_started = time.monotonic()
            session = StudySession(request, 'hepta_protocol', rustc=rustc, fixture=False, timeout=remaining())
            run['initialization_seconds'] = time.monotonic() - init_started
            indexed = session.execute('query_nodes', {}, remaining())
            edits = []
            for path, texts in replacements.items():
                old = [n for n in indexed['nodes'][path] if n['kind'] == 'declaration']
                if len(old) != len(texts): raise ValueError('fixture declarations differ from frozen task')
                edits.extend({'op': 'replace_declaration', 'target': path, 'node': node['id'], 'replacement': text}
                             for node, text in zip(old, texts))
            changed = session.execute('replace_nodes', {'expected_version': session.version, 'edits': edits}, remaining())
            run['transaction'] = changed
            if not changed.get('ok') or not changed.get('applied'):
                raise ValueError('actual namespace transaction did not publish the prepared candidate')
            files = session.finalize(remaining())
            remaining()
            run.update(status='submitted', submitted_sha256=snapshot_id(files), submitted_version=session.version,
                       session=session.evidence())
            run['claims']['production_workspace_v4_exercised'] = run['session']['production_workspace_v4_exercised']
            validate_workspace_record(run, require_committed=True)
            session.close()
            run['agent_wall_seconds'] = time.monotonic() - started
            # Private inputs are used only after all workspace children exit.
            run['score'] = score_candidate(request, files, rustc=rustc, fixture=False)
            run['status'] = 'qualified' if run['score']['ok'] else 'native_failed'
        except (EvalError, OSError, ValueError, KeyError, TypeError) as exc:
            run.update(status='failed', error={'code': getattr(exc, 'code', 'E_WORKSPACE_QUALIFICATION'),
                                              'message': str(exc)})
        finally:
            if session:
                run['session'] = session.evidence()
                session.close()
            run.setdefault('agent_wall_seconds', time.monotonic() - started)
        report['runs'].append(run)
    qualified = [run for run in report['runs'] if run['status'] == 'qualified']
    report['strict_workspace_v4_runs'] = len(qualified)
    report['hidden_native_cases_passed'] = sum(r['score']['passed'] for r in qualified)
    complete = len(qualified) == len(TASK_IDS)
    report['status'] = 'qualified_workspace_fixtures_only' if complete else 'qualification_failed'
    report['claims']['production_workspace_v4_exercised'] = complete
    report['claims']['strict_hidden_test_namespace_isolation_exercised'] = complete
    return seal_record(report)
