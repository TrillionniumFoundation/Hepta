"""Metered JSONL adapter protocol and preregistered paired-run identities."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import datetime
import json
import math
import os
import random
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import time
import uuid

from .tasks import ROOT, TASK_IDS, LANGUAGES, canonical, digest, materialize, task_request, verify_manifest
from .sandbox import clean_environment, kill_process, limits, probe_sandbox, wrap_command
from .scoring import check_candidate, compiler_identity, score_candidate
from ._private.oracles import hidden_cases


class EvalError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


@dataclass(frozen=True)
class Budget:
    input_tokens: int = 12000
    output_tokens: int = 4000
    total_tokens: int = 16000
    wall_seconds: float = 180.0
    tool_calls: int = 12
    protocol_bytes: int = 2 * 1024**2

    def __post_init__(self):
        for key in ('input_tokens', 'output_tokens', 'total_tokens', 'tool_calls', 'protocol_bytes'):
            if type(getattr(self, key)) is not int or getattr(self, key) < 0:
                raise ValueError('E_BUDGET: expected nonnegative integer ' + key)
        if type(self.wall_seconds) not in (int, float) or not math.isfinite(self.wall_seconds) or self.wall_seconds <= 0:
            raise ValueError('E_BUDGET: wall_seconds must be finite and positive')

    @property
    def sha256(self):
        return digest(canonical(asdict(self)))


def model_id(model):
    if not isinstance(model, dict) or set(model) != {'provider', 'name', 'revision'}:
        raise ValueError('E_MODEL: exact provider, name, and revision are required')
    if any(not isinstance(value, str) or not value.strip() for value in model.values()):
        raise ValueError('E_MODEL: model identity fields must be nonempty strings')
    return digest(canonical(model))


def make_plan(models, budget=None, replicates=1):
    budget = budget or Budget()
    if type(replicates) is not int or replicates < 1:
        raise ValueError('E_PLAN: replicates must be positive')
    identifiers = [model_id(model) for model in models]
    if len(identifiers) < 2 or len(set(identifiers)) != len(identifiers):
        raise ValueError('E_PLAN: at least two distinct exact model identities are required')
    manifest = verify_manifest()
    schedule = [{'model_index': index, 'task': task, 'language': language, 'replicate': replicate}
                for index in range(len(models)) for task in TASK_IDS for language in LANGUAGES
                for replicate in range(replicates)]
    random.Random(2026102402).shuffle(schedule)
    plan = {'schema': 'hepta.agent_plan.v1', 'taskset_sha256': manifest['taskset_sha256'],
            'models': models, 'tasks': list(TASK_IDS), 'languages': list(LANGUAGES),
            'replicates': replicates, 'budget': asdict(budget),
            'schedule_seed': 2026102402, 'schedule': schedule,
            'design': 'paired_tasks_same_nominal_token_wall_and_protocol_tool_caps',
            'usage_policy': 'provider_receipts_required_adapter_attested_not_independently_verified',
            'inference_scope': 'four_task_pilot_no_general_productivity_or_performance_claim'}
    plan['plan_sha256'] = digest(canonical(plan))
    return plan


def verify_plan(plan):
    if not isinstance(plan, dict) or plan.get('schema') != 'hepta.agent_plan.v1':
        raise ValueError('E_PLAN: unknown schema')
    expected = digest(canonical({key: value for key, value in plan.items() if key != 'plan_sha256'}))
    if expected != plan.get('plan_sha256') or plan['taskset_sha256'] != verify_manifest()['taskset_sha256']:
        raise ValueError('E_PLAN_STALE: plan or taskset identity changed')
    if plan['tasks'] != list(TASK_IDS) or plan['languages'] != list(LANGUAGES):
        raise ValueError('E_PLAN: the frozen paired task matrix cannot be narrowed after planning')
    Budget(**plan['budget'])
    identities = [model_id(model) for model in plan['models']]
    if len(identities) < 2 or len(identities) != len(set(identities)):
        raise ValueError('E_PLAN: at least two distinct model identities are required')
    if type(plan['replicates']) is not int or plan['replicates'] < 1:
        raise ValueError('E_PLAN: replicates must be positive')
    wanted = {(i, t, l, r) for i in range(len(identities)) for t in TASK_IDS for l in LANGUAGES
              for r in range(plan['replicates'])}
    try:
        scheduled = [(item['model_index'], item['task'], item['language'], item['replicate']) for item in plan['schedule']]
    except (KeyError, TypeError):
        raise ValueError('E_PLAN: malformed preregistered schedule')
    if len(scheduled) != len(wanted) or set(scheduled) != wanted:
        raise ValueError('E_PLAN: schedule must contain each planned cell exactly once')
    return plan


def sample_id(plan, model, task, language, replicate):
    return digest(canonical({'plan': plan['plan_sha256'], 'model': model_id(model),
                             'task': task, 'language': language, 'replicate': replicate}))


def evaluator_hash():
    records = [(str(path.relative_to(ROOT)), digest(path.read_bytes()))
               for path in sorted(ROOT.rglob('*.py')) if '__pycache__' not in path.parts]
    return digest(canonical(records))


def _secret_keys(value):
    if isinstance(value, dict):
        return any(str(key).lower() in {'authorization', 'api_key', 'access_token', 'secret', 'password'}
                   or _secret_keys(child) for key, child in value.items())
    if isinstance(value, list): return any(_secret_keys(child) for child in value)
    return False


def validate_usage(usage, model, budget, observed_tools, kind, previous=None):
    required = {'input_tokens', 'output_tokens', 'total_tokens', 'tool_calls', 'provider_calls'}
    if not isinstance(usage, dict) or set(usage) != required:
        raise EvalError('E_USAGE', 'complete cumulative provider usage is required on every adapter frame')
    for key in required - {'provider_calls'}:
        if type(usage[key]) is not int or usage[key] < 0:
            raise EvalError('E_USAGE', 'usage counters must be nonnegative integers')
    if usage['tool_calls'] != observed_tools:
        raise EvalError('E_TOOL_ACCOUNTING', 'reported tool calls differ from observed protocol requests')
    calls = usage['provider_calls']
    if not isinstance(calls, list): raise EvalError('E_USAGE', 'provider_calls must be a list')
    seen, input_count, output_count = {}, 0, 0
    for receipt in calls:
        if not isinstance(receipt, dict) or set(receipt) != {'request_id', 'model', 'input_tokens', 'output_tokens', 'raw_usage'}:
            raise EvalError('E_USAGE', 'each provider call requires an identity and exact token receipt')
        if receipt['model'] != model or not isinstance(receipt['request_id'], str) or not receipt['request_id']:
            raise EvalError('E_MODEL', 'receipt model/revision or request identity is missing or mismatched')
        if receipt['request_id'] in seen:
            raise EvalError('E_USAGE', 'duplicate provider request receipt')
        if any(type(receipt[key]) is not int or receipt[key] < 0 for key in ('input_tokens', 'output_tokens')):
            raise EvalError('E_USAGE', 'invalid provider token counters')
        if not isinstance(receipt['raw_usage'], dict) or not receipt['raw_usage'] or _secret_keys(receipt['raw_usage']):
            raise EvalError('E_USAGE', 'raw usage must be nonempty usage metadata without credentials')
        if len(canonical(receipt['raw_usage'])) > 16384:
            raise EvalError('E_USAGE', 'provider usage metadata is oversized')
        seen[receipt['request_id']] = receipt
        input_count += receipt['input_tokens']; output_count += receipt['output_tokens']
    if (usage['input_tokens'], usage['output_tokens'], usage['total_tokens']) != (input_count, output_count, input_count + output_count):
        raise EvalError('E_USAGE', 'aggregate usage does not equal the provider receipts')
    if previous:
        for receipt in previous['provider_calls']:
            if seen.get(receipt['request_id']) != receipt:
                raise EvalError('E_USAGE_RESET', 'cumulative usage cannot remove or alter earlier receipts')
    if kind == 'fixture':
        if calls or usage['total_tokens'] != 0:
            raise EvalError('E_FIXTURE_USAGE', 'fixtures must report zero model tokens and no provider calls')
    elif not calls or usage['total_tokens'] == 0:
        raise EvalError('E_USAGE', 'provider runs require nonempty metered provider receipts')
    for key in ('input_tokens', 'output_tokens', 'total_tokens'):
        if usage[key] > getattr(budget, key):
            raise EvalError('E_TOKEN_BUDGET', 'provider usage exceeds the frozen ' + key + ' budget')
    return usage


class JsonAdapter:
    def __init__(self, command, cwd, budget, *, fixture, pass_env=(), network=False):
        wrapped = wrap_command(command, cwd, fixture=fixture, network=network)
        self.proc = subprocess.Popen(wrapped, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=clean_environment(pass_env),
                                     start_new_session=True, preexec_fn=limits(budget.wall_seconds + 1))
        self.selector = selectors.DefaultSelector()
        for stream in (self.proc.stdout, self.proc.stderr):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ)
        os.set_blocking(self.proc.stdin.fileno(), False)
        self.buffer, self.stderr = bytearray(), bytearray()
        self.bytes_read, self.maximum = 0, budget.protocol_bytes

    def send(self, value, deadline):
        payload = canonical(value) + b'\n'
        offset = 0
        while offset < len(payload):
            if time.monotonic() >= deadline: raise EvalError('E_WALL_BUDGET', 'adapter exceeded the wall-time budget')
            try: offset += os.write(self.proc.stdin.fileno(), payload[offset:])
            except BlockingIOError:
                import select
                select.select([], [self.proc.stdin], [], min(0.1, max(0, deadline - time.monotonic())))
            except BrokenPipeError: raise EvalError('E_ADAPTER_EXIT', 'adapter stopped before consuming its request')

    def read(self, deadline):
        while True:
            if b'\n' in self.buffer:
                line, remainder = self.buffer.split(b'\n', 1)
                self.buffer = bytearray(remainder)
                try: value = json.loads(line)
                except (ValueError, UnicodeError): raise EvalError('E_PROTOCOL', 'adapter output is not JSONL')
                if not isinstance(value, dict): raise EvalError('E_PROTOCOL', 'adapter frame must be an object')
                return value
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise EvalError('E_WALL_BUDGET', 'adapter exceeded the wall-time budget')
            if not self.selector.get_map(): raise EvalError('E_ADAPTER_EXIT', 'adapter exited without a final response')
            for key, _ in self.selector.select(min(remaining, 0.1)):
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    self.selector.unregister(stream); stream.close(); continue
                self.bytes_read += len(chunk)
                if self.bytes_read > self.maximum: raise EvalError('E_PROTOCOL_BYTES', 'adapter exceeded its output-byte budget')
                (self.buffer if stream is self.proc.stdout else self.stderr).extend(chunk)

    def close(self):
        kill_process(self.proc)
        self.selector.close()
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if not stream.closed: stream.close()


def evaluate(task, language, adapter_dir, command, model, *, kind='provider', budget=None,
             plan=None, replicate=0, fixture_qualification=False, rustc=None, pass_env=(), network=False):
    model_id(model)
    request = task_request(task, language)
    budget = budget or Budget()
    if kind not in {'provider', 'fixture'}: raise ValueError('E_ADAPTER_KIND: provider or fixture required')
    fixture = kind == 'fixture'
    if fixture != fixture_qualification:
        raise ValueError('E_FIXTURE_MODE: fixtures require explicit fixture qualification and cannot enter provider mode')
    if not fixture:
        if plan is None: raise ValueError('E_PLAN: provider runs require a frozen paired evaluation plan')
        verify_plan(plan)
        if model not in plan['models'] or type(replicate) is not int or not 0 <= replicate < plan['replicates']:
            raise ValueError('E_PLAN: model or replicate is outside the planned matrix')
        budget = Budget(**plan['budget'])
    report = {'schema': 'hepta.agent_run.v1', 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'run_kind': 'trusted_fixture_qualification' if fixture else 'provider_adapter_run',
              'model': model, 'task_id': task, 'language': language, 'replicate': replicate,
              'taskset_sha256': request['taskset_sha256'], 'task_sha256': request['task_sha256'],
              'base_sha256': request['base_sha256'], 'evaluator_sha256': evaluator_hash(),
              'budget': asdict(budget), 'budget_sha256': budget.sha256,
              'plan_sha256': plan['plan_sha256'] if plan else None,
              'sample_id': sample_id(plan, model, task, language, replicate) if plan else None,
              'status': 'not_started', 'adapter_invoked': False,
              'provider_calls_attested': 0, 'provider_calls_independently_verified': False,
              'ai_comparison_eligible': False,
              'usage_verification': 'fixture_zero_tokens' if fixture else 'adapter_attested_not_independently_verified',
              'sandbox': probe_sandbox(), 'tools': [], 'score': None, 'usage': None,
              'claims': {'measured_ai_productivity': False, 'hepta_advantage_established': False,
                         'tokens_hard_capped_at_provider_transport': False,
                         'off_protocol_adapter_tool_calls_verified': False}}
    if not fixture and not report['sandbox']['available']:
        report.update(status='environment_blocked', error={'code': 'E_SANDBOX_UNAVAILABLE', 'message': report['sandbox']['reason']})
        return report
    report['isolation'] = 'trusted_fixture_process_separation_only' if fixture else 'allowlisted_namespace_capsules'
    directory = Path(adapter_dir).resolve()
    if not directory.is_dir() or ROOT == directory or ROOT in directory.parents or directory in ROOT.parents:
        raise ValueError('E_ADAPTER_BUNDLE: provide a standalone adapter directory outside the evaluator tree')
    files = sorted(path for path in directory.rglob('*') if path.is_file())
    if any(path.is_symlink() for path in directory.rglob('*')) or sum(path.stat().st_size for path in files) > 5 * 1024**2:
        raise ValueError('E_ADAPTER_BUNDLE: symlinks and oversized bundles are unsupported')
    if not isinstance(command, list) or not command or any(not isinstance(arg, str) for arg in command):
        raise ValueError('E_ADAPTER_COMMAND: a nonempty argv array is required')
    executable = shutil.which(command[0]) if not Path(command[0]).is_file() else command[0]
    if not executable: raise ValueError('E_ADAPTER_COMMAND: executable does not exist')
    report['adapter'] = {'bundle_sha256': digest(canonical([(str(path.relative_to(directory)), digest(path.read_bytes())) for path in files])),
                         'command': command, 'executable_sha256': digest(Path(executable).read_bytes()),
                         'passed_environment_names': list(pass_env), 'network_requested': network}
    report['compiler'] = compiler_identity(rustc)
    request_id = str(uuid.uuid4())
    request.update(schema='hepta.agent_request.v1', kind='start', request_id=request_id,
                   model=model, adapter_kind=kind, budget=asdict(budget), tools=['check', 'public_test'],
                   response_contract='Return JSONL tool_call frames or one final body; all frames need cumulative usage and frozen identities.')
    report['request_sha256'] = digest(canonical(request))
    report['request_id'] = request_id
    observed, usage, final_body, call_ids = 0, None, None, set()
    started = time.monotonic()
    deadline = started + budget.wall_seconds
    adapter = None
    with tempfile.TemporaryDirectory(prefix='hepta-agent-adapter-') as temporary:
        capsule = Path(temporary)
        bundle = capsule / 'adapter'
        shutil.copytree(directory, bundle)
        argv = [str(Path(executable).resolve())] + [arg.replace('{adapter}', str(bundle)) for arg in command[1:]]
        try:
            adapter = JsonAdapter(argv, capsule, budget, fixture=fixture, pass_env=pass_env, network=network)
            report['adapter_invoked'] = True
            adapter.send(request, deadline)
            while final_body is None:
                frame = adapter.read(deadline)
                if frame.get('request_id') != request_id or frame.get('task_sha256') != request['task_sha256'] or frame.get('base_sha256') != request['base_sha256']:
                    raise EvalError('E_STALE_IDENTITY', 'adapter response does not match the frozen request/task/source identities')
                if frame.get('model') != model or frame.get('adapter_kind') != kind:
                    raise EvalError('E_MODEL', 'adapter provenance does not match the planned model/revision/kind')
                frame_kind = frame.get('kind')
                if frame_kind == 'tool_call':
                    observed += 1
                    if observed > budget.tool_calls:
                        raise EvalError('E_TOOL_BUDGET', 'adapter exceeded the observed protocol tool-call cap')
                    call_id = frame.get('call_id')
                    if not isinstance(call_id, str) or not call_id or call_id in call_ids:
                        raise EvalError('E_PROTOCOL', 'tool call identifiers must be nonempty and unique')
                    call_ids.add(call_id)
                elif frame_kind != 'final':
                    raise EvalError('E_PROTOCOL', 'only tool_call and final frames are accepted')
                supplied_usage = frame.get('usage')
                # Retain metered overrun evidence without persisting arbitrary
                # secret-bearing unvalidated metadata from rejected frames.
                if isinstance(supplied_usage, dict):
                    report['last_claimed_counters'] = {key: supplied_usage[key] for key in
                        ('input_tokens', 'output_tokens', 'total_tokens', 'tool_calls')
                        if type(supplied_usage.get(key)) is int}
                usage = validate_usage(supplied_usage, model, budget, observed, kind, usage)
                report['provider_calls_attested'] = len(usage['provider_calls'])
                if frame_kind == 'final':
                    if not isinstance(frame.get('body'), str): raise EvalError('E_EDIT_SCOPE', 'final response must provide a body string')
                    final_body = frame['body']
                    break
                operation = frame.get('tool')
                if operation not in {'check', 'public_test'}:
                    raise EvalError('E_TOOL', 'unknown or unauthorized protocol tool')
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise EvalError('E_WALL_BUDGET', 'wall-time budget exhausted before tool execution')
                body = frame.get('body')
                tool_start = time.monotonic()
                try:
                    result = (check_candidate(request, body, rustc=rustc, fixture=fixture, timeout=remaining)
                              if operation == 'check' else score_candidate(request, body, public=True, rustc=rustc, fixture=fixture, timeout=remaining))
                except ValueError as exc:
                    result = {'ok': False, 'diagnostic': str(exc)}
                report['tools'].append({'call_id': call_id, 'tool': operation,
                                        'body': body, 'body_sha256': digest(body.encode()) if isinstance(body, str) else None,
                                        'elapsed_seconds': round(time.monotonic() - tool_start, 6),
                                        'ok': result.get('ok', False), 'result': result})
                adapter.send({'schema': 'hepta.agent_tool_result.v1', 'kind': 'tool_result', 'request_id': request_id,
                              'call_id': call_id, 'result': result,
                              'remaining': {'wall_seconds': max(0, deadline - time.monotonic()),
                                            'tool_calls': budget.tool_calls - observed,
                                            'total_tokens': budget.total_tokens - usage['total_tokens']}}, deadline)
            if time.monotonic() > deadline:
                raise EvalError('E_WALL_BUDGET', 'final response arrived after the wall-time budget')
            report['status'] = 'final_received'
        except (EvalError, OSError, ValueError) as exc:
            report['status'] = 'rejected'
            report['error'] = {'code': exc.code if isinstance(exc, EvalError) else 'E_ADAPTER',
                               'message': exc.message if isinstance(exc, EvalError) else str(exc)}
        finally:
            report['agent_wall_seconds'] = round(time.monotonic() - started, 6)
            report['observed_tool_calls'] = observed
            report['usage'] = usage
            if adapter:
                report['adapter_stderr_sha256'] = digest(bytes(adapter.stderr))
                report['adapter_output_bytes'] = adapter.bytes_read
                adapter.close()
    if report['status'] == 'final_received':
        try:
            source = materialize(request, final_body)
            report['submitted_body'] = final_body
            report['submitted_source_sha256'] = digest(source.encode())
            report['score'] = score_candidate(request, final_body, rustc=rustc, fixture=fixture)
            report['final_body_sha256'] = digest(final_body.encode())
            report['status'] = 'fixture_scored' if fixture else 'provider_run_scored'
            report['ai_comparison_eligible'] = not fixture
        except (ValueError, OSError) as exc:
            report['status'] = 'rejected'
            report['error'] = {'code': 'E_CANDIDATE', 'message': str(exc)}
    return report


def replay(report, *, rustc=None, trusted_fixture=False):
    """Re-score a saved final body without invoking an adapter or provider."""
    request = task_request(report['task_id'], report['language'])
    if any(report.get(key) != request[key] for key in ('taskset_sha256', 'task_sha256', 'base_sha256')):
        raise ValueError('E_REPLAY_STALE: task or source identity changed')
    if report.get('evaluator_sha256') != evaluator_hash() or report.get('compiler') != compiler_identity(rustc):
        raise ValueError('E_REPLAY_STALE: evaluator or compiler identity changed; a new qualification is required')
    body = report.get('submitted_body')
    source = materialize(request, body)
    if digest(body.encode()) != report.get('final_body_sha256') or digest(source.encode()) != report.get('submitted_source_sha256'):
        raise ValueError('E_REPLAY_STALE: submitted candidate identity changed')
    fixture = report.get('run_kind') == 'trusted_fixture_qualification'
    if fixture != trusted_fixture:
        raise ValueError('E_FIXTURE_MODE: saved fixture bodies require explicit trusted-fixture replay')
    if not fixture and report.get('run_kind') != 'provider_adapter_run':
        raise ValueError('E_REPLAY: unsupported run provenance')
    return {'schema': 'hepta.agent_replay.v1', 'status': 'replayed',
            'run_kind': 'trusted_fixture_replay' if fixture else 'provider_candidate_replay',
            'adapter_invoked': False, 'provider_calls': 0, 'ai_comparison_eligible': False,
            'taskset_sha256': request['taskset_sha256'], 'original_body_sha256': report['final_body_sha256'],
            'score': score_candidate(request, body, rustc=rustc, fixture=fixture)}


def compare(plan, reports):
    verify_plan(plan)
    wanted = {sample_id(plan, model, task, language, replicate)
              for model in plan['models'] for task in plan['tasks']
              for language in plan['languages'] for replicate in range(plan['replicates'])}
    received, issues = {}, []
    for report in reports:
        identity = report.get('sample_id')
        if identity not in wanted or identity in received:
            issues.append('unknown or duplicate planned sample'); continue
        received[identity] = report
        try:
            coordinates = (report['model'], report['task_id'], report['language'], report['replicate'])
            if (coordinates[0] not in plan['models'] or coordinates[1] not in TASK_IDS or
                coordinates[2] not in LANGUAGES or type(coordinates[3]) is not int or
                not 0 <= coordinates[3] < plan['replicates'] or
                sample_id(plan, *coordinates) != identity):
                issues.append('sample identity does not match its reported coordinates')
            frozen = task_request(coordinates[1], coordinates[2])
            if any(report.get(key) != frozen[key] for key in ('taskset_sha256', 'task_sha256', 'base_sha256')):
                issues.append('task or source identity mismatch')
            if report.get('budget') != plan['budget']:
                issues.append('run budget differs from the preregistered budget')
            body = report.get('submitted_body')
            source = materialize(frozen, body)
            if (digest(body.encode()) != report.get('final_body_sha256') or
                digest(source.encode()) != report.get('submitted_source_sha256')):
                issues.append('submitted candidate identity mismatch')
            validate_usage(report.get('usage'), report['model'], Budget(**plan['budget']),
                           report.get('observed_tool_calls'), 'provider')
            if report.get('observed_tool_calls', 0) > plan['budget']['tool_calls']:
                issues.append('reported tool budget overrun')
            if not 0 <= report.get('agent_wall_seconds', float('inf')) <= plan['budget']['wall_seconds']:
                issues.append('wall-time usage missing or over budget')
            if not isinstance(report.get('score'), dict) or type(report['score'].get('ok')) is not bool:
                issues.append('missing native score')
            elif report['score']['ok']:
                score = report['score']
                total = len(hidden_cases(coordinates[1]))
                if (score.get('compiled') is not True or type(score.get('passed')) is not int or
                    score['passed'] != total or score.get('total') != total or
                    score.get('native_status') != 'exited' or score.get('native_returncode') != 0 or
                    score.get('protocol_error') is not None or
                    score.get('source_sha256') != report['submitted_source_sha256']):
                    issues.append('successful score lacks matching native evidence')
        except (EvalError, KeyError, ValueError, TypeError):
            issues.append('invalid or missing run identities/usage')
        if report.get('plan_sha256') != plan['plan_sha256'] or report.get('budget_sha256') != Budget(**plan['budget']).sha256:
            issues.append('plan or budget mismatch')
        if (not report.get('ai_comparison_eligible') or report.get('run_kind') != 'provider_adapter_run' or
            report.get('status') != 'provider_run_scored' or not report.get('sandbox', {}).get('available') or
            report.get('isolation') != 'allowlisted_namespace_capsules'):
            issues.append('fixture, blocked, unmetered, or rejected run cannot qualify as AI evidence')
    missing = wanted - set(received)
    if missing: issues.append(f'{len(missing)} planned cells missing')
    evaluator_ids = {r.get('evaluator_sha256') for r in received.values()}
    compiler_ids = {digest(canonical(r.get('compiler'))) for r in received.values()}
    if len(evaluator_ids) > 1 or len(compiler_ids) > 1:
        issues.append('evaluator or compiler identity differs across paired runs')
    if None in evaluator_ids or any(not r.get('compiler') for r in received.values()):
        issues.append('missing evaluator or compiler identity')
    rows = []
    if not issues:
        for model in plan['models']:
            for language in plan['languages']:
                group = [r for r in received.values() if r['model'] == model and r['language'] == language]
                rows.append({'model': model, 'language': language, 'tasks_solved': sum(bool(r['score']['ok']) for r in group), 'planned_attempts': len(group)})
    return {'schema': 'hepta.agent_comparison.v1', 'plan_sha256': plan['plan_sha256'],
            'status': 'complete_adapter_attested_pilot' if not issues else 'not_qualified',
            'issues': issues, 'rows': rows, 'general_productivity_advantage_established': False,
            'provider_receipts_independently_verified': False}
