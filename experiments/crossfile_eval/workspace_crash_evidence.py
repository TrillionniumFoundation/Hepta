"""Semantic checks for the exact task/checkpoint crash matrix.

Hash seals detect changes; they are not signatures or remote attestation. The
checks below also reject re-sealed records with missing deaths, torn versions,
invented recovery, missing native cases, or a fabricated provider claim.
"""
from __future__ import annotations

import copy
import functools
import math
import re

from hepta.pipeline import compiler_hash
from .plan import evaluator_hash
from .records import seal_record, verify_record
from .tasks import ROOT, TASK_IDS, canonical, digest, task_request, verify_manifest

CHECKPOINTS = ('prepared', 'published')
CASE_WALL_SECONDS = 90.0
HIDDEN_CASE_COUNTS = {'api_migration': 75, 'owned_result': 24, 'native_bridge': 56,
                      'resource_cancel': 14, 'defect_repair': 143}
TRACE = ('initialize', 'inspect', 'inspect', 'prepare', 'task_native_check', 'commit',
         'observe', 'recover', 'recover', 'commit', 'recover', 'observe', 'pin')
CONTROL_IDS = ('missing_case', 'duplicate_case', 'successful_exit_instead_of_death', 'wrong_checkpoint',
               'namespace_omission', 'prepared_source_mismatch', 'torn_current', 'historical_pin_changed',
               'false_recovery', 'changed_retry_request', 'stale_retry_accepted', 'native_source_mismatch',
               'native_cases_omitted', 'ambiguous_outcome_erased', 'provider_claim_forged', 'wall_budget_erased')


def _require(condition, message):
    if not condition:
        raise ValueError('E_CRASH_EVIDENCE: ' + message)


def _sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _duration(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _schema_errors(function):
    @functools.wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (AttributeError, KeyError, TypeError, IndexError) as exc:
            raise ValueError('E_CRASH_EVIDENCE: malformed nested record') from exc
    return checked


def _non_provider(value):
    _require(type(value.get('actual_ai_model_runs')) is int and value['actual_ai_model_runs'] == 0
             and type(value.get('provider_tokens')) is int and value['provider_tokens'] == 0
             and value.get('provider_receipts') == [] and value.get('ai_comparison_eligible') is False
             and value.get('human_seconds') is None and value.get('monetary_cost_usd') is None,
             'scripted crash cases cannot invent model use, receipts or measured costs')
    for key in ('measured_ai_productivity', 'hepta_advantage_established', 'power_failure_durability_proved'):
        _require(value.get('claims', {}).get(key) is False, 'unmeasured or unproved claim: ' + key)


def _snapshot(value, profile):
    _require(isinstance(value, dict), 'missing bound snapshot')
    files = value.get('file_sha256')
    validation = value.get('validation', {})
    _require(isinstance(files, dict) and files and all(_sha(sha) for sha in files.values())
             and _sha(value.get('version')) and _sha(value.get('interface_sha256'))
             and value.get('source_sha256') == digest(canonical(files)), 'snapshot identities are incomplete or inconsistent')
    _require(value.get('profile') == profile and value.get('compiler_sha256') == profile['compiler_sha256']
             and validation.get('ok') is True and validation.get('backend_ok') is True
             and validation.get('rustc_sha256') == profile['rustc_sha256']
             and validation.get('backend_flags') == profile['native_flags']
             and validation.get('backend_target') == profile['native_target']
             and _sha(validation.get('report_sha256')), 'snapshot lacks its frozen complete native validation')


def _publication(value, before, after, current, state):
    _require(isinstance(value, dict), 'publication evidence missing')
    head = {'schema': 'hepta.workspace.v1', 'version': current}
    journal = None if state is None else {'schema': 'hepta.workspace.v1', 'before': before, 'after': after, 'state': state}
    _require(value.get('current') == head and value.get('journal') == journal,
             'CURRENT/journal contradict the checkpoint or recovery')
    _require(value.get('current_sha256') == digest(canonical(head) + b'\n')
             and value.get('journal_sha256') == (digest(canonical(journal) + b'\n') if journal is not None else None),
             'publication byte identities differ from their recorded contents')


@_schema_errors
def validate_crash_case(run, *, require_namespace=True):
    verify_record(run)
    _require(run.get('schema') == 'hepta.crossfile_workspace_crash_case.v1' and run.get('status') == 'qualified',
             'actual completed crash case required')
    _require(run.get('task_id') in TASK_IDS and run.get('checkpoint') in CHECKPOINTS,
             'unknown task or checkpoint')
    task, point = run['task_id'], run['checkpoint']
    request = task_request(task, 'hepta')
    _require(all(run.get(k) == request[k] for k in ('taskset_sha256', 'task_sha256', 'base_sha256')),
             'frozen task identity changed')
    _require(run.get('arm') == 'hepta_protocol' and run.get('language') == 'hepta', 'incorrect task arm')
    if require_namespace:
        _require(run.get('run_kind') == 'trusted_namespace_workspace_crash_fixture' and run.get('fixture_mode') is False
                 and run.get('isolation') == 'allowlisted_namespace_capsules', 'strict crash namespace run required')
    else:
        _require(run.get('run_kind') == 'offline_native_crash_unit_test' and run.get('fixture_mode') is True,
                 'explicit offline unit-test scope required')
    _non_provider(run)
    _require(run.get('wall_budget_seconds') == CASE_WALL_SECONDS and _duration(run.get('wall_seconds'))
             and 0 < run['wall_seconds'] <= CASE_WALL_SECONDS, 'whole case deadline missing or exceeded')
    session = run.get('session', {})
    profile = session.get('profile', {})
    compiler = run.get('compiler', {})
    _require(profile.get('compiler_sha256') == compiler.get('hepta_compiler_sha256')
             and profile.get('rustc_sha256') == compiler.get('rustc', {}).get('executable_sha256')
             and _sha(profile.get('compiler_sha256')) and _sha(profile.get('rustc_sha256')),
             'workspace profile differs from frozen compiler')
    initial, prepared = run.get('initial_snapshot'), run.get('prepared_snapshot')
    _snapshot(initial, profile)
    _snapshot(prepared, profile)
    before, after = initial['version'], prepared['version']
    _require(before != after and initial['source_sha256'] == request['base_sha256']
             and prepared['source_sha256'] != initial['source_sha256'], 'task changed no source or initial source differs')
    events = session.get('events')
    _require(isinstance(events, list) and tuple(e.get('operation') for e in events) == TRACE,
             'complete ordered crash/recovery/retry/pin trace required')
    _require(session.get('namespace_required') is require_namespace
             and all(e.get('namespace_required') is require_namespace for e in events),
             'every task RPC and native gate must retain its namespace policy')
    for event in events:
        _require(_duration(event.get('elapsed_seconds')), 'missing elapsed observation')
        if event['operation'] == 'task_native_check':
            continue
        if 'fault_injection' not in event:
            _require(event.get('process_status') == 'exited' and event.get('process_returncode') == 0,
                     'non-fault worker did not finish normally')
        _require(_sha(event.get('response_sha256')), 'worker response identity missing')
        for key in ('snapshot', 'current_snapshot', 'old_pinned_snapshot'):
            if key in event:
                _snapshot(event[key], profile)
    initialized, preview, checked, death = events[0], events[3], events[4], events[5]
    observed, recovered, recovered_again, retried, final_recovery, resolved, final = events[6:]
    _require(initialized.get('api') == 'initialize' and initialized.get('ok') is True
             and initialized.get('applied') is True and initialized.get('current_snapshot') == initial,
             'initial native workspace capture missing')
    _publication(initialized.get('publication'), before, after, before, None)
    for inspected in events[1:3]:
        _require(inspected.get('api') == 'inspect_workspace' and inspected.get('ok') is True
                 and inspected.get('current_snapshot') == initial, 'actual production node inspection missing')
    _require(preview.get('api') == 'apply_workspace_patch' and preview.get('ok') is True
             and preview.get('applied') is False and preview.get('before') == before and preview.get('after') == after
             and preview.get('snapshot') == prepared and preview.get('current_snapshot') == initial,
             'native checked prepare must not publish')
    native = checked.get('result', {})
    _require(native.get('ok') is True and native.get('source_sha256') == prepared['source_sha256']
             and all(_sha(native.get(k)) for k in ('artifact_sha256', 'rust_sha256', 'candidate_rlib_sha256')),
             'independent task/API native check must precede checkpoint death')
    preconditions = {'schema': 'hepta.patch.v4', 'expected_version': before,
                     'expected_interface_sha256': initial['interface_sha256'], 'interface_policy': request['interface_policy']}
    _require(_sha(preview.get('patch_sha256')) and all(e.get('patch_sha256') == preview['patch_sha256']
             and e.get('patch_preconditions') == preconditions for e in (preview, death, retried)),
             'prepare, dead commit and retry must bind the identical original request')
    expected_current = initial if point == 'prepared' else prepared
    expected_state = 'aborted' if point == 'prepared' else 'committed'
    _require(death.get('fault_injection') == {'checkpoint': point, 'exit_code': 71, 'mechanism': 'os._exit'}
             and death.get('process_status') == 'exited' and death.get('process_returncode') == 71
             and 'ok' not in death and 'applied' not in death,
             'actual checkpoint death required, never a normal return, timeout or fabricated acknowledgement')
    marker = death.get('crash_marker', {})
    _require(marker.get('schema') == 'hepta.workspace_crash_marker.v1' and marker.get('checkpoint') == point
             and marker.get('exit_code') == 71 and marker.get('mechanism') == 'os._exit'
             and marker.get('patch_sha256') == preview['patch_sha256']
             and death.get('crash_marker_sha256') == digest(canonical(marker)), 'actual crash marker differs')
    _require(marker.get('current_snapshot') == expected_current and marker.get('old_pinned_snapshot') == initial,
             'checkpoint did not observe one whole current snapshot and the unchanged old pin')
    _publication(marker.get('publication'), before, after, expected_current['version'], 'prepared')
    _require(run.get('injected_failure') == {'code': 'E_WORKSPACE_INJECTED_CRASH', 'publication_state': 'unverified_after_commit'},
             'ambiguous transport outcome must remain unverified before recovery')
    _require(observed.get('qualification_observation') == 'after_crash' and observed.get('api') == 'pin'
             and observed.get('ok') is True and observed.get('current_snapshot') == expected_current
             and observed.get('old_pinned_snapshot') == initial
             and observed.get('publication') == marker['publication'],
             'separate post-death process must observe checkpoint state and historical pin unchanged')
    for recovery in (recovered, recovered_again):
        _require(recovery.get('api') == 'recover' and recovery.get('ok') is True
                 and recovery.get('recovery') == expected_state and recovery.get('current_snapshot') == expected_current,
                 'recovery did not retain the expected complete version or was not idempotent')
        _publication(recovery.get('publication'), before, after, expected_current['version'], expected_state)
    _require(recovered['publication'] == recovered_again['publication'], 'idempotent recovery changed durable state')
    _require(retried.get('api') == 'apply_workspace_patch' and retried.get('current_snapshot') == prepared,
             'retry must return the final prepared snapshot')
    retry_summary = {key: retried[key] for key in ('ok', 'applied', 'status', 'before', 'after', 'diagnostics') if key in retried}
    _require(run.get('retry') == retry_summary, 'retry summary differs from worker outcome')
    if point == 'prepared':
        _require(retried.get('ok') is True and retried.get('applied') is True and retried.get('before') == before
                 and retried.get('after') == after and session.get('committed') is True
                 and session.get('prepared_workspace_version') == after and session.get('committed_workspace_version') == after,
                 'pre-publication exact retry must commit once')
    else:
        _require(retried.get('ok') is False and retried.get('applied') is False and retried.get('status') == 'rejected'
                 and [d.get('code') for d in retried.get('diagnostics', [])] == ['E_STALE_PROJECT']
                 and session.get('committed') is False and session.get('committed_workspace_version') is None,
                 'post-publication original request must fail stale, without inventing a commit acknowledgement')
    _publication(retried.get('publication'), before, after, after, 'committed')
    _require(final_recovery.get('api') == 'recover' and final_recovery.get('ok') is True
             and final_recovery.get('recovery') == 'committed' and final_recovery.get('current_snapshot') == prepared,
             'final committed recovery missing')
    _publication(final_recovery.get('publication'), before, after, after, 'committed')
    _require(resolved.get('qualification_observation') == 'after_resolution' and resolved.get('api') == 'pin'
             and resolved.get('ok') is True and resolved.get('current_snapshot') == prepared
             and resolved.get('old_pinned_snapshot') == initial, 'old pin changed after resolution')
    _publication(resolved.get('publication'), before, after, after, 'committed')
    _require(final.get('api') == 'pin' and final.get('ok') is True and final.get('current_snapshot') == prepared
             and run.get('submitted_version') == after and session.get('workspace_version') == after
             and run.get('submitted_sha256') == prepared['source_sha256']
             and session.get('source_sha256') == prepared['source_sha256'], 'final pin and submitted source differ')
    _publication(final.get('publication'), before, after, after, 'committed')
    _require(session.get('backend') == 'hepta.workspace/hepta.patch.v4'
             and all(session.get(k) is True for k in ('initialized', 'inspected', 'recovered', 'final_pinned'))
             and session.get('initial_workspace_version') == before and session.get('publication_state') == 'recovered_committed'
             and session.get('qualification_crash') == {'checkpoint': point, 'attempted': True, 'observed': True}
             and session.get('commit_acknowledgement_scope') == 'normal_success_response_only',
             'session does not substantiate crash/recovery capability')
    _require(session.get('production_workspace_v4_exercised') is (point == 'prepared'),
             'normal commit acknowledgement capability was relabeled after a crash')
    score = run.get('score', {})
    _require(run.get('final_pin_before_score') is True and score.get('ok') is True and score.get('compiled') is True
             and score.get('native_status') == 'exited' and score.get('native_returncode') == 0
             and score.get('protocol_error') is None and score.get('source_sha256') == prepared['source_sha256']
             and score.get('total') == HIDDEN_CASE_COUNTS[task] and score.get('passed') == HIDDEN_CASE_COUNTS[task]
             and score.get('visibility') == 'parent_private_after_adapter_exit'
             and all(_sha(score.get(k)) for k in ('artifact_sha256', 'rust_sha256', 'candidate_rlib_sha256')),
             'all native hidden cases must score the final recovered pinned source')
    _require(_duration(score.get('scoring_seconds')) and _duration(session.get('validation_seconds'))
             and sum(e['elapsed_seconds'] for e in events) + score['scoring_seconds'] <= run['wall_seconds'] + 0.001,
             'case wall accounting omitted validation or scoring')
    _require(run['claims'].get('workspace_crash_recovery_exercised') is True
             and run['claims'].get('no_torn_snapshot_observed') is True, 'completed case claims differ from evidence')
    return True


@_schema_errors
def validate_crash_matrix(report, *, require_controls=True):
    verify_record(report)
    _require(report.get('schema') == 'hepta.crossfile_workspace_crash_qualification.v1'
             and report.get('status') == 'qualified_workspace_crash_fixtures_only'
             and report.get('run_kind') == 'trusted_namespace_workspace_crash_qualification',
             'complete strict task crash qualification required')
    _require(report.get('environment', {}).get('available') is True and report.get('fixture_mode') is False
             and report.get('isolation') == 'allowlisted_namespace_capsules', 'actual namespace support required')
    _non_provider(report)
    _require(report.get('taskset_sha256') == verify_manifest()['taskset_sha256']
             and report.get('evaluator_sha256') == evaluator_hash()
             and report.get('compiler', {}).get('hepta_compiler_sha256') == compiler_hash(),
             'qualified taskset/evaluator/compiler snapshot differs from current implementation')
    expected = [{'task_id': task, 'checkpoint': point} for task in TASK_IDS for point in CHECKPOINTS]
    runs = report.get('runs')
    _require(report.get('planned_cases') == expected and isinstance(runs, list) and len(runs) == len(expected)
             and [{'task_id': run.get('task_id'), 'checkpoint': run.get('checkpoint')} for run in runs] == expected,
             'every task/checkpoint must occur exactly once, including failed or missing attempts')
    _require(report.get('qualified_crash_cases') == 10 and report.get('hidden_native_cases_passed') == 624
             and report.get('case_wall_budget_seconds') == CASE_WALL_SECONDS,
             'exact complete case/input denominator and frozen wall budget required')
    _require(report.get('qualification_worker_sha256') == digest((ROOT / '_workspace_crash_frontend.py').read_bytes()),
             'trusted crash worker identity differs from source')
    for run in runs:
        _require(run.get('compiler') == report['compiler'], 'compiler changed within the matrix')
        validate_crash_case(run)
        workers = [e for e in run['session']['events'] if 'qualification_worker_sha256' in e]
        _require(len(workers) == 3 and all(e['qualification_worker_sha256'] == report['qualification_worker_sha256'] for e in workers),
                 'commit and both observations must use the frozen qualification worker')
    _require(report.get('claims', {}).get('all_task_checkpoint_crashes_exercised') is True
             and report.get('claims', {}).get('strict_hidden_test_namespace_isolation_exercised') is True,
             'whole-matrix capability differs from evidence')
    if require_controls:
        controls = report.get('adversarial_controls')
        _require(isinstance(controls, list) and [c.get('id') for c in controls] == list(CONTROL_IDS)
                 and all(c.get('rejected') is True and isinstance(c.get('diagnostic'), str) and c['diagnostic']
                         and _sha(c.get('mutated_record_sha256')) for c in controls),
                 'all re-sealed semantic negative controls must be rejected')
    return True


def adversarial_controls(report):
    """Mutate and re-seal: a checksum-only validator would accept these."""
    validate_crash_matrix(report, require_controls=False)
    controls = []
    for name in CONTROL_IDS:
        changed = copy.deepcopy(report)
        run = changed['runs'][0]
        events = run['session']['events']
        if name == 'missing_case': changed['runs'].pop()
        elif name == 'duplicate_case': changed['runs'][-1] = copy.deepcopy(changed['runs'][0])
        elif name == 'successful_exit_instead_of_death': events[5]['process_returncode'] = 0
        elif name == 'wrong_checkpoint': events[5]['fault_injection']['checkpoint'] = 'published'
        elif name == 'namespace_omission': events[7]['namespace_required'] = False
        elif name == 'prepared_source_mismatch': run['prepared_snapshot']['source_sha256'] = '0' * 64
        elif name == 'torn_current': events[6]['publication']['current']['version'] = run['prepared_snapshot']['version']
        elif name == 'historical_pin_changed': events[11]['old_pinned_snapshot'] = copy.deepcopy(run['prepared_snapshot'])
        elif name == 'false_recovery': events[7]['recovery'] = 'committed'
        elif name == 'changed_retry_request': events[9]['patch_sha256'] = '0' * 64
        elif name == 'stale_retry_accepted':
            changed['runs'][1]['session']['events'][9]['ok'] = True
            changed['runs'][1]['retry']['ok'] = True
        elif name == 'native_source_mismatch': run['score']['source_sha256'] = run['base_sha256']
        elif name == 'native_cases_omitted': run['score']['passed'] -= 1
        elif name == 'ambiguous_outcome_erased': run['injected_failure']['publication_state'] = 'rolled_back'
        elif name == 'provider_claim_forged': changed['actual_ai_model_runs'] = 1
        elif name == 'wall_budget_erased': run['wall_seconds'] = 0
        changed['runs'] = [seal_record(r) for r in changed['runs']]
        changed = seal_record(changed)
        try:
            validate_crash_matrix(changed, require_controls=False)
        except ValueError as exc:
            controls.append({'id': name, 'rejected': True, 'diagnostic': str(exc),
                             'mutated_record_sha256': changed['record_sha256']})
        else:
            raise ValueError('E_CRASH_NEGATIVE_CONTROL: accepted ' + name)
    return controls
