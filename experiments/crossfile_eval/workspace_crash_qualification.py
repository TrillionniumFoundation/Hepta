"""Per-task process-death qualification of production workspace v4.

Only frozen trusted sources are used. There is no adapter and no provider
usage. Ordinary provider sessions still stop on any ambiguous transport result;
this operator qualification separately observes and recovers their store.
"""
from __future__ import annotations

import copy
import datetime
import json
from pathlib import Path
import shutil
import sys
import time

from experiments.agent_eval.harness import EvalError
from experiments.agent_eval.sandbox import probe_sandbox, run_bounded

from .plan import evaluator_hash
from .records import seal_record
from .scoring import compiler_identity, python_read_only, score_candidate
from .semantic import nodes
from .tasks import ROOT, TASK_IDS, canonical, digest, snapshot_id, task_request, trusted_reference, verify_manifest
from .workspace_session import ProductionWorkspaceSession

CHECKPOINTS = ('prepared', 'published')
CRASH_EXIT_CODE = 71
CASE_WALL_SECONDS = 90.0


def _metadata(value):
    return {key: item for key, item in value.items() if key != 'files'}


class _CrashQualificationSession(ProductionWorkspaceSession):
    """Trusted one-shot fault injector, never selected by StudySession."""

    def __init__(self, request, checkpoint, *, rustc=None, fixture=False, timeout=30.0):
        if checkpoint not in CHECKPOINTS:
            raise ValueError('E_CRASH_CHECKPOINT: exact production checkpoint required')
        self.checkpoint = checkpoint
        self.fault_attempted = self.fault_observed = False
        self.fault_patch = self.prepared_result = None
        super().__init__(request, rustc=rustc, fixture=fixture, timeout=timeout)
        shutil.copyfile(ROOT / '_workspace_crash_frontend.py', self.directory / 'workspace_crash_frontend.py')
        self.crash_worker_sha256 = digest((self.directory / 'workspace_crash_frontend.py').read_bytes())

    def _fault_worker(self, operation, timeout, **payload):
        started = time.monotonic()
        event = {'operation': operation, 'namespace_required': not self.fixture,
                 'qualification_worker_sha256': self.crash_worker_sha256}
        if operation == 'commit':
            event['fault_injection'] = {'checkpoint': self.checkpoint, 'exit_code': CRASH_EXIT_CODE,
                                       'mechanism': 'os._exit'}
            event['patch_sha256'] = digest(canonical(payload['patch']))
            event['patch_preconditions'] = {key: payload['patch'][key] for key in
                ('schema', 'expected_version', 'expected_interface_sha256', 'interface_policy')}
        try:
            process = run_bounded([sys.executable, str(self.directory / 'workspace_crash_frontend.py')],
                                  cwd=self.directory, input_bytes=canonical({'operation': operation, **payload}),
                                  timeout=timeout, fixture=self.fixture,
                                  read_only=[str(Path(self.rustc).parent.parent), *python_read_only()],
                                  max_output=2 * 1024 * 1024)
        except (ValueError, OSError) as exc:
            self.publication_state = 'unverified_after_' + operation
            event.update(process_status='transport_error', process_returncode=None,
                         elapsed_seconds=round(time.monotonic() - started, 6))
            self.events.append(event)
            raise EvalError('E_WORKSPACE_TRANSPORT', 'Crash qualification worker could not run') from exc
        elapsed = time.monotonic() - started
        if operation == 'commit':
            self.validation_seconds += elapsed
        event.update(elapsed_seconds=round(elapsed, 6), process_status=process['status'],
                     process_returncode=process['returncode'], response_sha256=digest(process['stdout'].encode()),
                     stderr_sha256=digest(process['stderr'].encode()))
        self.events.append(event)
        try:
            result = json.loads(process['stdout'])
        except ValueError:
            result = None
        return process, result, event

    def _rpc(self, operation, timeout, **payload):
        if operation == 'commit' and not self.fault_attempted:
            self.fault_attempted = True
            self.fault_patch = json.loads(canonical(payload['patch']))
            process, marker, event = self._fault_worker('commit', timeout, rustc=self.rustc,
                patch=self.fault_patch, qualification_checkpoint=self.checkpoint)
            self.publication_state = 'unverified_after_commit'
            if isinstance(marker, dict):
                event['crash_marker'] = marker
                event['crash_marker_sha256'] = digest(canonical(marker))
            if (process['status'] != 'exited' or process['returncode'] != CRASH_EXIT_CODE
                    or not isinstance(marker, dict) or marker.get('schema') != 'hepta.workspace_crash_marker.v1'
                    or marker.get('checkpoint') != self.checkpoint or marker.get('mechanism') != 'os._exit'
                    or marker.get('exit_code') != CRASH_EXIT_CODE
                    or marker.get('patch_sha256') != event['patch_sha256']):
                raise EvalError('E_WORKSPACE_CRASH_NOT_OBSERVED', 'Expected production checkpoint death was not observed')
            self.fault_observed = True
            raise EvalError('E_WORKSPACE_INJECTED_CRASH', 'Actual checkpoint child exited; publication remains unverified until recovery')
        result = super()._rpc(operation, timeout, **payload)
        if operation == 'prepare' and result.get('ok') is True:
            self.prepared_result = result
        if 'diagnostics' in result:
            self.events[-1]['diagnostics'] = result['diagnostics']
        return result

    def observe(self, timeout, phase):
        process, result, event = self._fault_worker('observe', timeout, old_version=self.initial_version)
        event['qualification_observation'] = phase
        if (process['status'] != 'exited' or process['returncode'] != 0
                or not isinstance(result, dict) or result.get('ok') is not True):
            raise EvalError('E_WORKSPACE_OBSERVATION', 'Independent post-crash pin observation failed')
        # Verify both sets of bytes before retaining just their bound metadata.
        self._verify_snapshot(result['current_snapshot'])
        self._verify_snapshot(result['old_pinned_snapshot'])
        if result['old_pinned_snapshot']['version'] != self.initial_version:
            raise EvalError('E_WORKSPACE_IDENTITY', 'Old pinned version changed')
        event.update(api=result['api'], ok=True, publication=result['publication'],
                     current_snapshot=_metadata(result['current_snapshot']),
                     old_pinned_snapshot=_metadata(result['old_pinned_snapshot']))
        return result

    def evidence(self):
        result = super().evidence()
        result['qualification_crash'] = {'checkpoint': self.checkpoint,
                                        'attempted': self.fault_attempted, 'observed': self.fault_observed}
        # The ordinary committed flag means an acknowledged successful commit.
        # Post-publication death has no such acknowledgement; CURRENT/recovery
        # are separate evidence and never retroactively fabricate that reply.
        result['commit_acknowledgement_scope'] = 'normal_success_response_only'
        if self.fault_observed:
            result['not_claimed'].remove('crash_injection_during_task_runs')
            result['capability_scope'].append('trusted_task_checkpoint_process_death')
        return result


def _reference_edits(session, task, timeout):
    indexed = session.execute('query_nodes', {}, timeout)
    reference = trusted_reference(task, 'hepta')
    edits = []
    for path in session.request['editable']:
        old = [n for n in indexed['nodes'][path] if n['kind'] == 'declaration']
        new = [n for n in nodes('hepta', reference[path], path) if n['kind'] == 'declaration']
        if len(old) != len(new):
            raise ValueError('E_CRASH_FIXTURE: frozen declarations differ')
        edits.extend({'op': 'replace_declaration', 'target': path, 'node': a['id'], 'replacement': b['text']}
                     for a, b in zip(old, new))
    return edits


def _qualify_case(task, checkpoint, compiler, *, rustc=None, fixture=False):
    """fixture=True exists only for native unit tests, not the public command."""
    started, session = time.monotonic(), None
    deadline = started + CASE_WALL_SECONDS
    request = task_request(task, 'hepta')
    run = {'schema': 'hepta.crossfile_workspace_crash_case.v1', 'task_id': task,
           'checkpoint': checkpoint, 'arm': 'hepta_protocol', 'language': 'hepta',
           'run_kind': 'offline_native_crash_unit_test' if fixture else 'trusted_namespace_workspace_crash_fixture',
           'fixture_mode': fixture,
           'isolation': 'trusted_fixture_process_separation_only' if fixture else 'allowlisted_namespace_capsules',
           'taskset_sha256': request['taskset_sha256'], 'task_sha256': request['task_sha256'],
           'base_sha256': request['base_sha256'], 'compiler': compiler,
           'wall_budget_seconds': CASE_WALL_SECONDS, 'score': None,
           'actual_ai_model_runs': 0, 'provider_tokens': 0, 'provider_receipts': [],
           'ai_comparison_eligible': False, 'human_seconds': None, 'monetary_cost_usd': None,
           'claims': {'workspace_crash_recovery_exercised': False, 'no_torn_snapshot_observed': False,
                      'measured_ai_productivity': False, 'hepta_advantage_established': False,
                      'power_failure_durability_proved': False}}

    def remaining():
        return ProductionWorkspaceSession._remaining(deadline)

    try:
        session = _CrashQualificationSession(request, checkpoint, rustc=rustc, fixture=fixture, timeout=remaining())
        initial = copy.deepcopy(session.pinned_metadata)
        run['initial_snapshot'] = initial
        edits = _reference_edits(session, task, remaining())
        try:
            session.execute('replace_nodes', {'expected_version': session.version, 'edits': edits}, remaining())
        except EvalError as exc:
            if exc.code != 'E_WORKSPACE_INJECTED_CRASH':
                raise
            run['injected_failure'] = {'code': exc.code, 'publication_state': session.publication_state}
        else:
            raise ValueError('E_WORKSPACE_CRASH_NOT_OBSERVED: transaction returned instead of dying')
        if not session.fault_observed or not session.prepared_result:
            raise ValueError('E_WORKSPACE_CRASH_NOT_OBSERVED: missing checkpoint or checked preparation')
        prepared = session.prepared_result
        prepared_version = prepared['after']
        if prepared_version == session.initial_version:
            raise ValueError('E_CRASH_FIXTURE: task must change the initial version')
        run['prepared_snapshot'] = _metadata(prepared['snapshot'])
        observed = session.observe(remaining(), 'after_crash')
        expected_version = session.initial_version if checkpoint == 'prepared' else prepared_version
        if observed['current_snapshot']['version'] != expected_version:
            raise ValueError('E_CRASH_PUBLICATION: CURRENT disagrees with the actual checkpoint')
        if observed['old_pinned_snapshot'] != {**initial, 'files': request['files']}:
            raise ValueError('E_CRASH_OLD_PIN: original source bytes or metadata changed')
        expected_recovery = 'aborted' if checkpoint == 'prepared' else 'committed'
        for _ in range(2):
            result = session._recover(remaining(), expected_version)
            if result['recovery'] != expected_recovery:
                raise ValueError('E_CRASH_RECOVERY: recovery is incorrect or not idempotent')
        # Replay exactly the same request, including the original expected head
        # and interface. Only pre-publication death permits this retry to commit.
        retry = session._rpc('commit', remaining(), patch=session.fault_patch)
        run['retry'] = {key: retry[key] for key in ('ok', 'applied', 'status', 'before', 'after', 'diagnostics') if key in retry}
        if checkpoint == 'prepared':
            if retry.get('ok') is not True or retry.get('applied') is not True or retry.get('after') != prepared_version:
                raise ValueError('E_CRASH_RETRY: exact pre-publication request did not commit')
            session._accept(retry['current_snapshot'], prepared_version)
            session.prepared_version = session.committed_version = prepared_version
            session.committed = True
        else:
            if (retry.get('ok') is not False or retry.get('applied') is not False
                    or [d.get('code') for d in retry.get('diagnostics', [])] != ['E_STALE_PROJECT']):
                raise ValueError('E_CRASH_RETRY: published request must reject its stale original precondition')
            session._accept(retry['current_snapshot'], prepared_version)
        final_recovery = session._recover(remaining(), prepared_version)
        if final_recovery['recovery'] != 'committed':
            raise ValueError('E_CRASH_RECOVERY: final committed journal missing')
        resolved = session.observe(remaining(), 'after_resolution')
        if resolved['old_pinned_snapshot'] != {**initial, 'files': request['files']}:
            raise ValueError('E_CRASH_OLD_PIN: final historical snapshot changed')
        files = session.finalize(remaining())
        if snapshot_id(files) != prepared['snapshot']['source_sha256']:
            raise ValueError('E_CRASH_IDENTITY: final source differs from checked preparation')
        run.update(submitted_sha256=snapshot_id(files), submitted_version=session.version,
                   session=session.evidence(), final_pin_before_score=True)
        # All workspace children are dead and their store is closed before
        # private native cases are materialized in a different capsule.
        session.close()
        run['score'] = score_candidate(request, files, rustc=rustc, fixture=fixture, timeout=remaining())
        remaining()
        run['status'] = 'qualified' if run['score']['ok'] else 'native_failed'
        if run['score']['ok']:
            run['claims'].update(workspace_crash_recovery_exercised=True, no_torn_snapshot_observed=True)
    except (EvalError, OSError, ValueError, KeyError, TypeError) as exc:
        run.update(status='failed', error={'code': getattr(exc, 'code', 'E_CRASH_QUALIFICATION'), 'message': str(exc)})
    finally:
        if session:
            run['session'] = session.evidence()
            session.close()
        run['wall_seconds'] = round(time.monotonic() - started, 6)
    return seal_record(run)


def qualify_workspace_crashes(rustc=None, *, execution_context='unspecified_operator_environment'):
    from .workspace_crash_evidence import adversarial_controls, validate_crash_matrix

    sandbox = probe_sandbox()
    report = {'schema': 'hepta.crossfile_workspace_crash_qualification.v1',
              'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'run_kind': 'trusted_namespace_workspace_crash_qualification',
              'taskset_sha256': verify_manifest()['taskset_sha256'], 'evaluator_sha256': evaluator_hash(),
              'compiler': compiler_identity(rustc), 'environment': sandbox,
              'operator_execution_context': execution_context,
              'execution_context_verification': 'operator_annotation_not_automatic_host_attestation',
              'qualification_worker_sha256': digest((ROOT / '_workspace_crash_frontend.py').read_bytes()),
              'isolation': 'allowlisted_namespace_capsules', 'fixture_mode': False,
              'actual_ai_model_runs': 0, 'provider_tokens': 0, 'provider_receipts': [],
              'ai_comparison_eligible': False, 'human_seconds': None, 'monetary_cost_usd': None,
              'planned_cases': [{'task_id': task, 'checkpoint': point} for task in TASK_IDS for point in CHECKPOINTS],
              'case_wall_budget_seconds': CASE_WALL_SECONDS, 'qualified_crash_cases': 0,
              'hidden_native_cases_passed': 0, 'runs': [], 'adversarial_controls': [],
              'claims': {'all_task_checkpoint_crashes_exercised': False,
                         'strict_hidden_test_namespace_isolation_exercised': False,
                         'measured_ai_productivity': False, 'hepta_advantage_established': False,
                         'power_failure_durability_proved': False},
              'scope': 'same_host_process_death_at_two_existing_fsync_checkpoints_not_power_loss_or_arbitrary_instruction_kill'}
    if not sandbox['available']:
        return seal_record({**report, 'status': 'environment_blocked', 'error': {
            'code': 'E_SANDBOX_UNAVAILABLE', 'message': sandbox['reason']}})
    for case in report['planned_cases']:
        report['runs'].append(_qualify_case(case['task_id'], case['checkpoint'], report['compiler'], rustc=rustc))
    qualified = [r for r in report['runs'] if r['status'] == 'qualified']
    report['qualified_crash_cases'] = len(qualified)
    report['hidden_native_cases_passed'] = sum(r['score']['passed'] for r in qualified)
    report['status'] = 'qualified_workspace_crash_fixtures_only' if len(qualified) == len(report['planned_cases']) else 'qualification_failed'
    if report['status'] != 'qualification_failed':
        report['claims'].update(all_task_checkpoint_crashes_exercised=True,
                                strict_hidden_test_namespace_isolation_exercised=True)
        try:
            validate_crash_matrix(seal_record(report), require_controls=False)
            report['adversarial_controls'] = adversarial_controls(seal_record(report))
            validate_crash_matrix(seal_record(report))
        except ValueError as exc:
            report.update(status='qualification_failed', error={'code': 'E_CRASH_EVIDENCE', 'message': str(exc)})
            report['claims'].update(all_task_checkpoint_crashes_exercised=False,
                                    strict_hidden_test_namespace_isolation_exercised=False)
    return seal_record(report)
