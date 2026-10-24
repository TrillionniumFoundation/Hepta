"""JSONL provider runner and symmetric atomic study edit sessions.

Only fixture qualification may skip namespace isolation. Provider mode has no
unsafe override. The hidden oracle stays in this parent and runs only after the
adapter process group is terminated. Usage receipts are adapter-attested.
"""
from __future__ import annotations

from dataclasses import asdict
import datetime
from pathlib import Path
import shutil
import tempfile
import time
import uuid

from experiments.agent_eval.harness import Budget, EvalError, JsonAdapter, validate_usage
from experiments.agent_eval.sandbox import probe_sandbox

from .plan import default_budget, evaluator_hash, model_id, sample_id, verify_plan
from .records import seal_record, verify_record
from .scoring import check_candidate, compiler_identity, score_candidate
from .semantic import inspect, replace_nodes
from .tasks import ARMS, ROOT, apply_files, canonical, digest, snapshot_id, task_request, validate_files


class StudySession:
    def __init__(self, request, arm, *, rustc=None, fixture=False):
        if ARMS.get(arm, {}).get('language') != request['language']:
            raise ValueError('E_ARM: language differs from arm')
        self.request, self.arm = request, arm
        self.files, self.version = dict(request['files']), request['base_sha256']
        self.rustc, self.fixture = rustc, fixture

    @property
    def tools(self):
        return ['read_file', 'check', 'public_test'] + (['query_nodes', 'replace_nodes'] if ARMS[self.arm]['semantic_tools'] else ['replace_files'])

    def execute(self, operation, arguments, timeout):
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
            if operation == 'query_nodes': return {**inspect(self.request, self.files), 'version': before}
            method = check_candidate if operation == 'check' else score_candidate
            result = method(self.request, self.files, rustc=self.rustc, fixture=self.fixture,
                            timeout=timeout, **({'public': True} if operation == 'public_test' else {}))
            return {**result, 'version': before}
        payload = 'edits' if operation == 'replace_nodes' else 'files'
        if set(arguments) != {'expected_version', payload} or arguments['expected_version'] != before:
            raise ValueError('E_STALE_SNAPSHOT: complete exact current identity is required')
        candidate = (replace_nodes(self.request, self.files, arguments['edits']) if operation == 'replace_nodes'
                     else apply_files(self.request, self.files, arguments['files']))
        checked = check_candidate(self.request, candidate, rustc=self.rustc, fixture=self.fixture, timeout=timeout)
        if not checked['ok']:
            return {'ok': False, 'applied': False, 'version': before, 'validation': checked}
        # One parent assignment publishes the complete checked map; failed
        # preparation cannot partially change the current multi-file snapshot.
        self.files, self.version = candidate, snapshot_id(candidate)
        return {'ok': True, 'applied': True, 'before': before, 'version': self.version,
                'validation': checked, 'persistence': 'session_memory_only_not_production_workspace_v4'}


def evaluate(task, arm, adapter_dir, command, model, *, kind='provider', plan=None, replicate=0,
             budget=None, fixture_qualification=False, rustc=None, pass_env=(), network=False):
    model_id(model)
    if arm not in ARMS: raise ValueError('E_ARM: unknown study arm')
    if kind not in {'provider', 'fixture'}: raise ValueError('E_ADAPTER_KIND: provider or fixture required')
    fixture = kind == 'fixture'
    if fixture != fixture_qualification:
        raise ValueError('E_FIXTURE_MODE: fixture runs require explicit qualification and cannot enter provider mode')
    if not fixture:
        if plan is None: raise ValueError('E_PLAN: provider runs require a frozen complete plan')
        verify_plan(plan, rustc=rustc, current_environment=True)
        if model not in plan['models'] or type(replicate) is not int or not 0 <= replicate < plan['replicates']:
            raise ValueError('E_PLAN: sample coordinates are outside the plan')
        budget = Budget(**plan['budget'])
    budget = budget or default_budget()
    request = task_request(task, ARMS[arm]['language'])
    session = StudySession(request, arm, rustc=rustc, fixture=fixture)
    report = {'schema': 'hepta.crossfile_run.v1', 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'run_kind': 'trusted_fixture_qualification' if fixture else 'provider_adapter_run',
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
              'claims': {'measured_ai_productivity': False, 'hepta_advantage_established': False,
                         'production_workspace_v4_exercised': False, 'off_protocol_tool_calls_verified': False,
                         'provider_transport_token_hard_cap_verified': False}}
    if not fixture and not report['sandbox']['available']:
        report.update(status='environment_blocked', error={'code': 'E_SANDBOX_UNAVAILABLE', 'message': report['sandbox']['reason']})
        return seal_record(report)
    directory = Path(adapter_dir).resolve()
    if (not directory.is_dir() or directory == ROOT or ROOT in directory.parents or directory in ROOT.parents
            or (ROOT.parent / 'agent_eval') == directory or (ROOT.parent / 'agent_eval') in directory.parents):
        raise ValueError('E_ADAPTER_BUNDLE: provide a standalone adapter bundle outside evaluator directories')
    entries = list(directory.rglob('*'))
    if any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in entries):
        raise ValueError('E_ADAPTER_BUNDLE: symlinks and special files are unsupported')
    files = sorted(path for path in entries if path.is_file())
    if sum(path.stat().st_size for path in files) > 5 * 1024 * 1024:
        raise ValueError('E_ADAPTER_BUNDLE: bundle exceeds 5 MiB')
    if not isinstance(command, list) or not command or any(not isinstance(arg, str) for arg in command):
        raise ValueError('E_ADAPTER_COMMAND: nonempty argv list required')
    executable = shutil.which(command[0])
    if not executable: raise ValueError('E_ADAPTER_COMMAND: use an installed executable and {adapter}/script argument')
    executable = str(Path(executable).resolve())
    report['adapter'] = {'bundle_sha256': digest(canonical([(str(p.relative_to(directory)), digest(p.read_bytes())) for p in files])),
                         'command': command, 'executable_sha256': digest(Path(executable).read_bytes()),
                         'passed_environment_names': list(pass_env), 'network_requested': bool(network)}
    request_id = str(uuid.uuid4())
    request = {**request, 'schema': 'hepta.crossfile_request.v1', 'kind': 'start', 'request_id': request_id,
               'arm': arm, 'adapter_kind': kind, 'model': model, 'budget': asdict(budget),
               'version': session.version, 'tools': session.tools,
               'protocol': 'hepta.crossfile_study.v1', 'production_workspace_v4': False,
               'response_contract': 'All frames echo request_id/task_sha256/base_sha256/model/adapter_kind and cumulative usage. '
                                    'tool_call: call_id/tool/arguments. final: version of current checked snapshot. '
                                    'Edits are atomic complete native-validated transactions; do not return code in final.'}
    report['request_id'], report['request_sha256'] = request_id, digest(canonical(request))
    observed, usage, call_ids, adapter = 0, None, set(), None
    started, final = time.monotonic(), False
    deadline = started + budget.wall_seconds
    with tempfile.TemporaryDirectory(prefix='hepta-crossfile-adapter-') as temporary:
        capsule = Path(temporary)
        bundle = capsule / 'adapter'
        shutil.copytree(directory, bundle)
        argv = [executable] + [arg.replace('{adapter}', str(bundle)) for arg in command[1:]]
        try:
            adapter = JsonAdapter(argv, capsule, budget, fixture=fixture, pass_env=pass_env, network=network)
            report['adapter_invoked'] = True
            adapter.send(request, deadline)
            while not final:
                frame = adapter.read(deadline)
                if any(frame.get(k) != request[k] for k in ('request_id', 'task_sha256', 'base_sha256', 'model', 'adapter_kind')):
                    raise EvalError('E_STALE_IDENTITY', 'frame identities differ from the frozen request and exact provider revision')
                frame_kind = frame.get('kind')
                if frame_kind == 'tool_call':
                    observed += 1
                    if observed > budget.tool_calls: raise EvalError('E_TOOL_BUDGET', 'observed protocol call cap exceeded')
                    call_id = frame.get('call_id')
                    if not isinstance(call_id, str) or not call_id or call_id in call_ids:
                        raise EvalError('E_PROTOCOL', 'tool call identities must be unique nonempty strings')
                    call_ids.add(call_id)
                elif frame_kind != 'final':
                    raise EvalError('E_PROTOCOL', 'only tool_call or final frames are accepted')
                supplied = frame.get('usage')
                if isinstance(supplied, dict):
                    report['last_claimed_counters'] = {k: supplied[k] for k in ('input_tokens', 'output_tokens', 'total_tokens', 'tool_calls')
                                                       if type(supplied.get(k)) is int}
                try:
                    usage = validate_usage(supplied, model, budget, observed, kind, usage)
                except EvalError as exc:
                    if exc.code == 'E_TOKEN_BUDGET':
                        # Valid receipt evidence exceeding a cap is still a
                        # cost. Preserve it, then reject the attempt.
                        relaxed = Budget(**{**asdict(budget), **{k: max(getattr(budget, k), supplied[k])
                                           for k in ('input_tokens', 'output_tokens', 'total_tokens')}})
                        usage = validate_usage(supplied, model, relaxed, observed, kind, usage)
                    raise
                report['provider_calls_attested'] = len(usage['provider_calls'])
                if frame_kind == 'final':
                    if frame.get('version') != session.version:
                        raise EvalError('E_STALE_SNAPSHOT', 'final must identify the current complete session snapshot')
                    final = True
                    report['usage_complete'] = True
                    break
                operation, arguments = frame.get('tool'), frame.get('arguments')
                tool_started = time.monotonic()
                try:
                    result = session.execute(operation, arguments, max(0.001, deadline - time.monotonic()))
                except (ValueError, OSError) as exc:
                    result = {'ok': False, 'diagnostic': str(exc), 'version': session.version}
                report['tools'].append({'call_id': call_id, 'tool': operation, 'arguments': arguments,
                                        'elapsed_seconds': round(time.monotonic() - tool_started, 6), 'result': result})
                adapter.send({'schema': 'hepta.crossfile_tool_result.v1', 'kind': 'tool_result', 'request_id': request_id,
                              'call_id': call_id, 'result': result, 'version': session.version,
                              'remaining': {'wall_seconds': max(0, deadline - time.monotonic()),
                                            'tool_calls': budget.tool_calls - observed,
                                            'total_tokens': budget.total_tokens - usage['total_tokens']}}, deadline)
            if time.monotonic() > deadline: raise EvalError('E_WALL_BUDGET', 'final frame exceeded the frozen wall cap')
            report['status'] = 'final_received'
        except (EvalError, OSError, ValueError, TypeError) as exc:
            report['status'] = 'attempt_failed'
            report['error'] = {'code': exc.code if isinstance(exc, EvalError) else 'E_ADAPTER', 'message': str(exc)}
        finally:
            report['agent_wall_seconds'] = round(time.monotonic() - started, 6)
            report['observed_tool_calls'], report['usage'] = observed, usage
            report['validated_tool_calls'] = usage['tool_calls'] if usage else 0
            report['provider_calls_attested'] = len(usage['provider_calls']) if usage else 0
            report['actual_ai_model_runs'] = int(not fixture and bool(report['provider_calls_attested']))
            if adapter:
                report['adapter_output_bytes'] = adapter.bytes_read
                report['adapter_stderr_sha256'] = digest(bytes(adapter.stderr))
                adapter.close()
    # No provider process is running when the private oracle inputs are used.
    if report['status'] == 'final_received':
        report['submitted_files'], report['submitted_sha256'] = session.files, session.version
        try:
            report['score'] = score_candidate(session.request, session.files, rustc=rustc, fixture=fixture)
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
