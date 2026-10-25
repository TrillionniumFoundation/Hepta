"""JSONL provider runner and symmetric atomic study edit sessions.

Only fixture qualification may skip namespace isolation. Provider mode has no
unsafe override. The hidden oracle stays in this parent and runs only after the
adapter process group is terminated. Usage receipts are adapter-attested.
"""
from __future__ import annotations

from dataclasses import asdict
import datetime
import re
from pathlib import Path
import shutil
import tempfile
import time
import uuid

from experiments.agent_eval.harness import Budget, EvalError, JsonAdapter, validate_usage
from experiments.agent_eval.sandbox import probe_sandbox

from .adapter_binding import actual_config, bundle_digest, frozen_config
from .plan import default_budget, evaluator_hash, model_id, sample_id, verify_plan
from .records import seal_record, verify_record
from .scoring import check_candidate, compiler_identity, score_candidate, study_frontend
from .tasks import ARMS, ROOT, apply_files, canonical, digest, snapshot_id, task_request, validate_files


class FileStudySession:
    def __init__(self, request, arm, *, rustc=None, fixture=False, timeout=30.0):
        if ARMS.get(arm, {}).get('language') != request['language']:
            raise ValueError('E_ARM: language differs from arm')
        self.request, self.arm = request, arm
        self.files, self.version = dict(request['files']), request['base_sha256']
        self.rustc, self.fixture = rustc, fixture
        self.validation_seconds = 0.0
        profile = study_frontend(request, self.files, fixture=fixture, timeout=timeout)
        if not profile['ok']: raise EvalError('E_STUDY_INITIALIZE', str(profile.get('diagnostics')))
        self.interface_sha256 = profile['interface_sha256']

    def close(self):
        pass

    def finalize(self, timeout):
        return self.files

    def evidence(self):
        return {'backend': 'checked_memory_session', 'production_workspace_v4_exercised': False,
                'validation_seconds': self.validation_seconds}

    @property
    def tools(self):
        return ['read_file', 'check', 'public_test'] + (['query_nodes', 'replace_nodes'] if ARMS[self.arm]['semantic_tools'] else ['replace_files'])

    def execute(self, operation, arguments, timeout):
        deadline = time.monotonic() + timeout
        if operation not in self.tools: raise ValueError('E_TOOL: unavailable in the assigned arm')
        if not isinstance(arguments, dict): raise ValueError('E_TOOL_SCHEMA: arguments must be an object')
        before = self.version
        if operation == 'read_file':
            if set(arguments) != {'path'} or arguments['path'] not in self.files:
                raise ValueError('E_TOOL_SCHEMA: unknown file')
            path = arguments['path']
            return {'ok': True, 'version': before, 'path': path, 'source': self.files[path],
                    'source_sha256': digest(self.files[path].encode()), 'editable': path in self.request['editable']}
        if operation in {'query_nodes', 'check', 'public_test'}:
            if arguments: raise ValueError('E_TOOL_SCHEMA: this operation takes no arguments')
            if operation == 'query_nodes':
                result = study_frontend(self.request, self.files, operation, fixture=self.fixture, timeout=timeout)
                return {**result, 'version': before, 'operations': ['replace_function', 'replace_body', 'replace_declaration']}
            method = check_candidate if operation == 'check' else score_candidate
            started = time.monotonic()
            result = method(self.request, self.files, rustc=self.rustc, fixture=self.fixture,
                            timeout=timeout, **({'public': True} if operation == 'public_test' else {}))
            self.validation_seconds += time.monotonic() - started
            return {**result, 'version': before}
        payload = 'edits' if operation == 'replace_nodes' else 'files'
        if set(arguments) != {'expected_version', payload} or arguments['expected_version'] != before:
            raise ValueError('E_STALE_SNAPSHOT: complete exact current identity is required')
        if operation == 'replace_nodes':
            prepared = study_frontend(self.request, self.files, operation, fixture=self.fixture,
                                      timeout=max(0.001, deadline - time.monotonic()), edits=arguments['edits'])
            if not prepared['ok']: return {**prepared, 'applied': False, 'version': before}
            candidate = prepared['files']
        else:
            candidate = apply_files(self.request, self.files, arguments['files'])
        started = time.monotonic()
        checked = check_candidate(self.request, candidate, rustc=self.rustc, fixture=self.fixture,
                                  timeout=max(0.001, deadline - time.monotonic()))
        self.validation_seconds += time.monotonic() - started
        if not checked['ok']:
            return {'ok': False, 'applied': False, 'version': before, 'validation': checked}
        if self.request['interface_policy'] == 'preserve' and checked['interface_sha256'] != self.interface_sha256:
            return {'ok': False, 'applied': False, 'version': before,
                    'diagnostic': 'E_CONTRACT_CHANGE: the frozen task requires preserving declaration interfaces'}
        if time.monotonic() > deadline: raise EvalError('E_WALL_BUDGET', 'candidate validation exceeded the wall cap')
        # One parent assignment publishes the complete checked map; failed
        # preparation cannot partially change the current multi-file snapshot.
        self.files, self.version = candidate, snapshot_id(candidate)
        self.interface_sha256 = checked['interface_sha256']
        return {'ok': True, 'applied': True, 'before': before, 'version': self.version,
                'validation': checked, 'persistence': 'session_memory_only_not_production_workspace_v4'}


def StudySession(request, arm, *, rustc=None, fixture=False, timeout=30.0):
    if arm == 'hepta_protocol':
        from .workspace_session import ProductionWorkspaceSession
        return ProductionWorkspaceSession(request, rustc=rustc, fixture=fixture, timeout=timeout)
    return FileStudySession(request, arm, rustc=rustc, fixture=fixture, timeout=timeout)


def evaluate(task, arm, adapter_dir, command, model, *, kind='provider', plan=None, replicate=0,
             budget=None, fixture_qualification=False, rustc=None, pass_env=(), network=False):
    model_id(model)
    if arm not in ARMS: raise ValueError('E_ARM: unknown study arm')
    if kind not in {'provider', 'fixture'}: raise ValueError('E_ADAPTER_KIND: provider or fixture required')
    fixture = kind == 'fixture'
    if fixture != fixture_qualification:
        raise ValueError('E_FIXTURE_MODE: fixture runs require explicit qualification and cannot enter provider mode')
    configured = None
    if not fixture:
        if plan is None: raise ValueError('E_PLAN: provider runs require a frozen complete plan')
        verify_plan(plan, rustc=rustc, current_environment=True)
        if model not in plan['models'] or type(replicate) is not int or not 0 <= replicate < plan['replicates']:
            raise ValueError('E_PLAN: sample coordinates are outside the plan')
        configured = frozen_config(plan, model)
        budget = Budget(**plan['budget'])
    budget = budget or default_budget()
    request = task_request(task, ARMS[arm]['language'])
    report = {'schema': 'hepta.crossfile_run.v1', 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'run_kind': 'trusted_fixture_qualification' if fixture else 'provider_adapter_run',
              'protocol': 'hepta.crossfile_study.v2',
              'model': model, 'task_id': task, 'arm': arm, 'language': request['language'], 'replicate': replicate,
              'taskset_sha256': request['taskset_sha256'], 'task_sha256': request['task_sha256'], 'base_sha256': request['base_sha256'],
              'evaluator_sha256': evaluator_hash(), 'compiler': compiler_identity(rustc),
              'budget': asdict(budget), 'budget_sha256': budget.sha256,
              'plan_sha256': plan['plan_sha256'] if plan else None,
              'sample_id': sample_id(plan, model, task, arm, replicate) if plan else None,
              'status': 'not_started', 'adapter_invoked': False, 'sandbox': probe_sandbox(),
              'isolation': 'trusted_fixture_process_separation_only' if fixture else 'allowlisted_namespace_capsules',
              'provider_calls_attested': 0, 'provider_receipts_independently_verified': False,
              'ai_comparison_eligible': False, 'actual_ai_model_runs': 0,
              'usage_verification': 'fixture_zero_tokens' if fixture else 'adapter_attested_not_independently_verified',
              'usage': None, 'usage_complete': False, 'tools': [], 'score': None,
              'observed_tool_calls': 0, 'validated_tool_calls': 0,
              'human_seconds': None, 'monetary_cost_usd': None, 'agent_wall_seconds': None,
              'initialization_seconds': None, 'validation_seconds': None, 'session': None,
              'claims': {'measured_ai_productivity': False, 'hepta_advantage_established': False,
                         'production_workspace_v4_exercised': False, 'off_protocol_tool_calls_verified': False,
                         'provider_transport_token_hard_cap_verified': False}}
    # Bind the exact public adapter configuration even for unsuccessful samples.
    # No environment values or credential bytes are read into this identity.
    directory = Path(adapter_dir).resolve()
    report['adapter'], executable = actual_config(directory, command, pass_env, network)
    if configured is not None and report['adapter'] != configured:
        report.update(status='attempt_failed', error={'code': 'E_ADAPTER_CONFIG_MISMATCH',
                      'message': 'Actual adapter bundle, executable, argv, environment names or network differs from the plan'})
        return seal_record(report)
    if not fixture and not report['sandbox']['available']:
        report.update(status='environment_blocked', error={'code': 'E_SANDBOX_UNAVAILABLE', 'message': report['sandbox']['reason']})
        return seal_record(report)
    observed, usage, call_ids, adapter, session = 0, None, set(), None, None
    started, final = time.monotonic(), False
    deadline = started + budget.wall_seconds
    def remaining():
        left = deadline - time.monotonic()
        if left <= 0: raise EvalError('E_WALL_BUDGET', 'shared initialization/tool/final-pin wall budget exhausted')
        return left
    def accept_usage(supplied, *, defer_token_cap=False):
        nonlocal usage
        if isinstance(supplied, dict):
            report['last_claimed_counters'] = {k: supplied[k] for k in ('input_tokens', 'output_tokens', 'total_tokens', 'tool_calls')
                                               if type(supplied.get(k)) is int}
        try:
            usage = validate_usage(supplied, model, budget, observed, kind, usage)
        except EvalError as exc:
            if exc.code == 'E_TOKEN_BUDGET':
                # Metered over-budget calls still cost money. Keep their valid
                # evidence before failing; never manufacture a zero-cost error.
                relaxed = Budget(**{**asdict(budget), **{k: max(getattr(budget, k), supplied[k])
                                   for k in ('input_tokens', 'output_tokens', 'total_tokens')}})
                usage = validate_usage(supplied, model, relaxed, observed, kind, usage)
                if defer_token_cap: return exc
            raise
        return None
    try:
        # Crucially, neither source parsing nor a production workspace is created
        # before the namespace gate. Setup is charged to the same wall budget.
        init_started = time.monotonic()
        try:
            session = StudySession(request, arm, rustc=rustc, fixture=fixture, timeout=remaining())
        finally:
            report['initialization_seconds'] = round(time.monotonic() - init_started, 6)
        request_id = str(uuid.uuid4())
        request = {**request, 'schema': 'hepta.crossfile_request.v1', 'kind': 'start', 'request_id': request_id,
                   'arm': arm, 'adapter_kind': kind, 'model': model, 'budget': asdict(budget),
                   'version': session.version, 'tools': session.tools,
                   'remaining': {'wall_seconds': remaining(), 'tool_calls': budget.tool_calls,
                                 'total_tokens': budget.total_tokens},
                   'protocol': 'hepta.crossfile_study.v2', 'capabilities': {'abort_frame': True},
                   'production_workspace_v4': arm == 'hepta_protocol',
                   'response_contract': 'All frames echo request_id/task_sha256/base_sha256/model/adapter_kind and cumulative usage. '
                                        'tool_call: call_id/tool/arguments. final: version of current checked snapshot. '
                                        'abort: usage (last valid cumulative receipts or null), usage_complete:boolean '
                                        '(true only with valid nonempty receipts and no pending provider request), '
                                        'error:{code:stable E_CODE,message:fixed non-sensitive text}; never a final or hidden-score request. '
                                        'Edits are atomic complete native-validated transactions; do not return code in final.'}
        report['request_id'], report['request_sha256'] = request_id, digest(canonical(request))
        with tempfile.TemporaryDirectory(prefix='hepta-crossfile-adapter-') as temporary:
            capsule = Path(temporary)
            bundle = capsule / 'adapter'
            shutil.copytree(directory, bundle)
            if bundle_digest(bundle) != report['adapter']['bundle_sha256']:
                raise EvalError('E_ADAPTER_CONFIG_MISMATCH', 'Adapter bundle changed while capturing its isolated copy')
            argv = [executable] + [arg.replace('{adapter}', str(bundle)) for arg in command[1:]]
            try:
                remaining()
                adapter = JsonAdapter(argv, capsule, budget, fixture=fixture, pass_env=pass_env, network=network)
                report['adapter_invoked'] = True
                adapter.send(request, deadline)
                while not final:
                    frame = adapter.read(deadline)
                    if any(frame.get(k) != request[k] for k in ('request_id', 'task_sha256', 'base_sha256', 'model', 'adapter_kind')):
                        raise EvalError('E_STALE_IDENTITY', 'Frame identities differ from frozen request and exact provider revision')
                    frame_kind = frame.get('kind')
                    if frame_kind == 'abort':
                        # Aborting does not consume a public tool call. A null
                        # receipt leaves any already validated prefix intact.
                        if type(frame.get('usage_complete')) is not bool or 'usage' not in frame:
                            raise EvalError('E_PROTOCOL', 'Abort must explicitly mark usage completeness')
                        over_cap = accept_usage(frame['usage'], defer_token_cap=True) if frame['usage'] is not None else None
                        error = frame.get('error')
                        if (not isinstance(error, dict) or set(error) != {'code', 'message'}
                                or not isinstance(error['code'], str) or not re.fullmatch(r'E_[A-Z0-9_]{1,80}', error['code'])
                                or not isinstance(error['message'], str) or not 1 <= len(error['message']) <= 512):
                            raise EvalError('E_PROTOCOL', 'Abort requires a stable error code and bounded fixed explanation')
                        pending = frame.get('pending_provider_request')
                        if pending is not None:
                            if (not isinstance(pending, dict) or set(pending) != {'client_request_id', 'request_id', 'receipt_verified'}
                                    or pending['receipt_verified'] is not False
                                    or not isinstance(pending['client_request_id'], str)
                                    or not 1 <= len(pending['client_request_id']) <= 512
                                    or (pending['request_id'] is not None and (not isinstance(pending['request_id'], str)
                                        or not 1 <= len(pending['request_id']) <= 512))):
                                raise EvalError('E_PROTOCOL', 'Malformed unverified provider request metadata')
                            report['pending_provider_request'] = pending
                        if frame['usage_complete']:
                            if frame['usage'] is None or not usage['provider_calls'] or pending is not None:
                                raise EvalError('E_PROTOCOL', 'Complete abort costs require supplied verified receipts and no pending request')
                            report['usage_complete'] = True
                        report['adapter_aborted'] = True
                        # Never persist arbitrary server/error text; stable code
                        # and unknown-cost status are sufficient for accounting.
                        if over_cap is not None: raise over_cap
                        raise EvalError(error['code'], 'Adapter aborted the attempt; see usage_complete for cost coverage')
                    if frame_kind == 'tool_call':
                        observed += 1
                        if observed > budget.tool_calls: raise EvalError('E_TOOL_BUDGET', 'Observed protocol call cap exceeded')
                        call_id = frame.get('call_id')
                        if not isinstance(call_id, str) or not call_id or call_id in call_ids:
                            raise EvalError('E_PROTOCOL', 'Tool call identities must be unique nonempty strings')
                        call_ids.add(call_id)
                    elif frame_kind != 'final':
                        raise EvalError('E_PROTOCOL', 'Only tool_call, final or explicit abort frames are accepted')
                    accept_usage(frame.get('usage'))
                    if frame_kind == 'final':
                        if frame.get('version') != session.version:
                            raise EvalError('E_STALE_SNAPSHOT', 'Final must identify the current complete checked snapshot')
                        final = True
                        report['usage_complete'] = True
                        break
                    operation, arguments = frame.get('tool'), frame.get('arguments')
                    tool_started = time.monotonic()
                    try:
                        result = session.execute(operation, arguments, remaining())
                    except (ValueError, OSError) as exc:
                        result = {'ok': False, 'diagnostic': str(exc), 'version': session.version}
                    report['tools'].append({'call_id': call_id, 'tool': operation, 'arguments': arguments,
                                            'elapsed_seconds': round(time.monotonic() - tool_started, 6), 'result': result})
                    adapter.send({'schema': 'hepta.crossfile_tool_result.v1', 'kind': 'tool_result', 'request_id': request_id,
                                  'call_id': call_id, 'result': result, 'version': session.version,
                                  'remaining': {'wall_seconds': remaining(), 'tool_calls': budget.tool_calls - observed,
                                                'total_tokens': budget.total_tokens - usage['total_tokens']}}, deadline)
            finally:
                if adapter:
                    report['adapter_output_bytes'] = adapter.bytes_read
                    report['adapter_stderr_sha256'] = digest(bytes(adapter.stderr))
                    adapter.close()
                    adapter = None
        # Read the submitted bytes from a fresh production pin after the provider
        # process has exited. This final read still consumes the common budget.
        submitted = validate_files(session.request, session.finalize(remaining()))
        remaining()
        report.update(status='final_received', submitted_files=submitted,
                      submitted_sha256=snapshot_id(submitted), submitted_version=session.version)
    except (EvalError, OSError, ValueError, TypeError, KeyError) as exc:
        report['status'] = 'attempt_failed'
        report['error'] = {'code': exc.code if isinstance(exc, EvalError) else 'E_ADAPTER', 'message': str(exc)}
    finally:
        if adapter: adapter.close()
        report['agent_wall_seconds'] = round(time.monotonic() - started, 6)
        report['observed_tool_calls'], report['usage'] = observed, usage
        report['validated_tool_calls'] = usage['tool_calls'] if usage else 0
        report['provider_calls_attested'] = len(usage['provider_calls']) if usage else 0
        report['actual_ai_model_runs'] = int(not fixture and bool(report['provider_calls_attested']))
        if session:
            report['session'] = session.evidence()
            report['validation_seconds'] = report['session']['validation_seconds']
            report['claims']['production_workspace_v4_exercised'] = report['session']['production_workspace_v4_exercised']
            session.close()
    # All provider/workspace children have exited before parent-private inputs
    # are used. Hidden evaluation overhead is outside the interaction budget.
    if report['status'] == 'final_received':
        try:
            report['score'] = score_candidate(session.request, report['submitted_files'], rustc=rustc, fixture=fixture)
            report['status'] = 'fixture_scored' if fixture else 'provider_scored'
            report['ai_comparison_eligible'] = not fixture
        except (ValueError, OSError) as exc:
            report['status'] = 'attempt_failed'
            report['error'] = {'code': 'E_CANDIDATE', 'message': str(exc)}
    return seal_record(report)


def replay(report, *, rustc=None, trusted_fixture=False):
    verify_record(report)
    if report.get('schema') != 'hepta.crossfile_run.v1': raise ValueError('E_REPLAY: require an original run')
    fixture = report.get('run_kind') == 'trusted_fixture_qualification'
    if fixture != trusted_fixture:
        raise ValueError('E_FIXTURE_MODE: fixture replay must be explicitly marked trusted')
    if not fixture and report.get('run_kind') != 'provider_adapter_run':
        raise ValueError('E_REPLAY: unsupported run provenance')
    request = task_request(report['task_id'], report['language'])
    if any(report.get(key) != request[key] for key in ('taskset_sha256', 'task_sha256', 'base_sha256')):
        raise ValueError('E_REPLAY_STALE: frozen task identities changed')
    if report.get('evaluator_sha256') != evaluator_hash() or report.get('compiler') != compiler_identity(rustc):
        raise ValueError('E_REPLAY_STALE: evaluator or compiler changed; qualify a new experiment version')
    files = validate_files(request, report.get('submitted_files'))
    if snapshot_id(files) != report.get('submitted_sha256'):
        raise ValueError('E_REPLAY_STALE: submitted multi-file snapshot changed')
    score = score_candidate(request, files, rustc=rustc, fixture=fixture)
    return seal_record({'schema': 'hepta.crossfile_replay.v1', 'original_record_sha256': report['record_sha256'],
                        'status': 'replayed', 'score': score, 'actual_ai_model_runs': 0,
                        'provider_tokens': 0, 'ai_comparison_eligible': False,
                        'run_kind': 'trusted_fixture_replay' if fixture else 'provider_candidate_replay'})
