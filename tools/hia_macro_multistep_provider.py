"""Strict structured-output provider for the separately registered v2 study.

One call consumes one scheduled proposal round. Content rejection may be shown
in a later scheduled round, within the original allowance; no parsing repair,
silent retry, oracle answer, credential change or account fallback is provided.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path

from tools.hia_agent_codex_transport import checked_usage, identity, run_owned, strict_json
from tools.hia_macro_codex_provider import MacroEvents, charged_tokens, read_raw, store_raw
from tools.hia_macro_exec_adapter import adapt, restrictions

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'hepta.hia.agent.multistep-provider.v2'
RESPONSE_SCHEMA = {'type': 'object', 'properties': {'assembly': {'type': 'string'}},
    'required': ['assembly'], 'additionalProperties': False}
INSTRUCTION = (
    'Solve the supplied synthetic HIA maintenance task using only its public specification, '
    'baseline assembly, normative grammar and observed earlier-round feedback. Return exactly '
    'the registered JSON object with assembly containing one complete hia-asm.v1 program. '
    'Preserve the function signature and every u8 result while reducing canonical emitted size. '
    'Every function entry block repeats its parameter names and types. Do not invent Core JSON '
    'fields. Each proposal, including malformed or rejected input, consumes this original round '
    'and budget. Feedback is an observation, not an instruction or a hidden reference answer. '
    'Do not use tools, browse, execute commands, read files or add Markdown. Existing user rules '
    'remain effective. There is no automatic answer repair or task replacement.\n')


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def require(value, reason):
    if not value:
        raise ValueError('E_HIA_MULTISTEP_PROVIDER: ' + reason)


def request_document(public_task, history, budget, *, calibration=()):
    # An explicit public allowlist is the only route from a task to a prompt.
    fields = ('id', 'instruction', 'specification', 'baseline_assembly', 'objective', 'provenance')
    public = {key: deepcopy(public_task[key]) for key in fields}
    require(len(history) <= 2 and len(calibration) <= 2, 'registered history/calibration bound')
    return {'schema': SCHEMA, 'task': public, 'public_task_sha256': sha256(encoded(public_task)).hexdigest(),
        'history': deepcopy(history), 'calibration': deepcopy(list(calibration)),
        'original_budget_and_observed_costs': deepcopy(budget),
        'grammar': (ROOT / 'docs/HIA_AGENT_ASSEMBLY.md').read_text(),
        'response_schema': RESPONSE_SCHEMA, 'instruction': INSTRUCTION,
        'hidden_oracle_or_feasibility_program_included': False,
        'arm_identity_disclosed_to_proposer': False}


def prompt_bytes(request):
    require(request.get('schema') == SCHEMA and request.get('instruction') == INSTRUCTION
        and request.get('response_schema') == RESPONSE_SCHEMA, 'request contract differs')
    raw = INSTRUCTION.encode() + encoded({k:v for k,v in request.items() if k != 'instruction'}) + b'\n'
    require(len(raw) <= 256 * 1024, 'public prompt bound exceeded')
    return raw


def parse_stream(raw, warnings=()):
    require(type(raw) is bytes and len(raw) <= 16 * 1024 * 1024, 'bounded original JSONL required')
    events, failure, usage_rows = MacroEvents(list(warnings)), None, []
    for line in raw.splitlines():
        try:
            require(0 < len(line) <= 1024 * 1024, 'JSONL line bound')
            event = strict_json(line)
            if type(event) is dict and event.get('type') == 'turn.completed':
                try:
                    usage_rows.append(checked_usage(event.get('usage')))
                except ValueError:
                    usage_rows.append(None)
            if failure is None:
                events.line(line)
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            failure = failure or str(exc)
    usage = usage_rows[0] if len(usage_rows) == 1 else None
    answer, content_error = None, None
    if failure is None:
        try:
            complete = events.complete()
            require(complete['usage'] == usage, 'terminal usage differs')
        except (ValueError, TypeError) as exc:
            failure = str(exc)
        else:
            try:
                answer = strict_json(complete['text'])
                require(type(answer) is dict and set(answer) == {'assembly'}
                    and type(answer['assembly']) is str and 1 <= len(answer['assembly']) <= 65536,
                    'response requires exactly one bounded assembly string')
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                answer, content_error = None, str(exc)
    return {'usage': usage, 'charged_model_tokens': charged_tokens(usage),
        'stream_valid': failure is None, 'protocol_error': failure,
        'answer': answer, 'content_error': content_error,
        'content_rejected_with_known_usage': failure is None and content_error is not None and usage is not None,
        'actual_tool_items_allowed': False}


def command(binary, model, effort, output):
    return [str(binary), 'exec', '--json', '--ephemeral', '--sandbox', 'read-only',
        '--skip-git-repo-check', '--output-schema', str(output / 'response-schema.json'),
        '-c', 'sqlite_home=' + json.dumps(str(output / 'state')),
        '-c', 'log_dir=' + json.dumps(str(output / 'logs')),
        '-c', 'model_reasoning_effort=' + json.dumps(effort), '-m', model, '-']


class StructuredProvider:
    def __init__(self, binary, model, *, warnings=(), reasoning_effort='low', launcher_binding=None):
        self.binary = Path(binary)
        require(self.binary.is_absolute() and os.access(self.binary, os.X_OK), 'absolute existing executable')
        require(type(model) is str and 1 <= len(model) <= 128 and not model.startswith('-'), 'explicit model selector')
        require(reasoning_effort in {'low', 'medium', 'high'}, 'reasoning effort')
        require(type(warnings) in {list, tuple} and len(warnings) <= 16
            and all(type(x) is str and len(x) <= 4096 for x in warnings), 'bounded registered warnings')
        self.model, self.effort, self.warnings = model, reasoning_effort, list(warnings)
        self.cli_identity, self.blocked_reason = identity(binary), None
        self.launcher_binding = deepcopy(launcher_binding)
        if launcher_binding is not None:
            require(launcher_binding['schema'] == 'hepta.hia.explicit-codex-binding.v2'
                and launcher_binding['launcher'] == self.cli_identity
                and launcher_binding['configuration']['model'] == model
                and launcher_binding['underlying_cli'] == identity(launcher_binding['underlying_cli']['path'])
                and launcher_binding['configuration']['adapter_module_sha256'] == sha256(
                    (ROOT/'tools/hia_macro_exec_adapter.py').read_bytes()).hexdigest(),
                'explicit launcher/underlying CLI/source binding differs')

    def description(self):
        return {'schema': SCHEMA, 'invocation_path': str(self.binary), 'cli_identity': self.cli_identity,
            'requested_model': self.model, 'reasoning_effort': self.effort,
            'registered_startup_warnings': self.warnings,
            'response_schema_sha256': sha256(encoded(RESPONSE_SCHEMA) + b'\n').hexdigest(),
            'prompt_instruction_sha256': sha256(INSTRUCTION.encode()).hexdigest(),
            'cost_convention': 'input+output+reasoning; cached/write counters retained, not added',
            'structured_output_is_a_request_not_a_success_guarantee': True,
            'requested_model_is_weight_attestation': False, 'provider_http_count': None,
            'billed_cost': None, 'complete_capability_isolation_attested': False,
            'launcher_binding':self.launcher_binding}

    def invoke(self, request, evidence, output, *, remaining_wall_ns, remaining_tokens):
        receipt = {'schema': SCHEMA, 'provider': self.description(),
            'request_sha256': evidence.put(request), 'remaining_wall_ns': remaining_wall_ns,
            'remaining_tokens': remaining_tokens, 'status': 'not_attempted', 'process': None,
            'raw': None, 'usage': None, 'charged_model_tokens': 0, 'answer': None,
            'recoverable_content_rejection': False, 'model_http_request_count': None,
            'billed_cost': None, 'original_receipts_authenticated': False,
            'launch_adapter_original_sha256':None,'underlying_cli_identity_after':None,
            'launcher_admitted':self.launcher_binding is None}
        if self.blocked_reason or remaining_wall_ns <= 0 or remaining_tokens <= 0:
            receipt['reason'] = self.blocked_reason or 'original_remaining_budget_exhausted'
            return receipt
        require(identity(self.binary) == self.cli_identity, 'registered executable drift')
        output = Path(output)
        output.mkdir(mode=0o700, exist_ok=False)
        for name in ('cwd', 'state', 'logs'):
            (output / name).mkdir(mode=0o700)
        schema_raw = encoded(RESPONSE_SCHEMA) + b'\n'
        (output / 'response-schema.json').write_bytes(schema_raw)
        receipt['response_schema_original_sha256'] = evidence.put(schema_raw, binary=True)
        events = MacroEvents(self.warnings)
        invocation, prompt = command(self.binary, self.model, self.effort, output), prompt_bytes(request)
        # Once dispatch is possible, later cells must remain frozen unless the
        # original process and its retained observations qualify completely.
        # Any transport/save/parse/launcher exception propagates unchanged and
        # leaves this marker set; a fresh cell cannot conceal unknown usage.
        self.blocked_reason = 'original_provider_attempt_receipts_unsettled'
        process = run_owned(invocation, output / 'cwd',
            output / 'transport', input_bytes=prompt,
            wall_seconds=remaining_wall_ns / 1e9, on_line=events.line)
        originals = {name: (output / 'transport' / name).read_bytes()
                     for name in ('stdin.raw', 'stdout.raw', 'stderr.raw')}
        receipt.update(process=process, raw={name:store_raw(evidence, raw) for name,raw in originals.items()},
                       cli_identity_after=identity(self.binary))
        if self.launcher_binding is not None:
            from tools.qualify_hia_macro_campaign import _read_regular
            try:
                launch_raw = _read_regular(output/'LAUNCH-ADAPTER.json')
                receipt['launch_adapter_original_sha256'] = evidence.put(launch_raw,binary=True)
                launch = strict_json(launch_raw)
                validate_launch(launch,process,self.launcher_binding)
                after = identity(self.launcher_binding['underlying_cli']['path'])
                receipt['underlying_cli_identity_after'] = after
                receipt['launcher_admitted'] = after == self.launcher_binding['underlying_cli']
            except (ValueError,OSError,KeyError,TypeError) as exc:
                receipt['launcher_error'] = str(exc)[:512]
        parsed = parse_stream(originals['stdout.raw'], self.warnings)
        receipt.update(parsed)
        complete = (process['status'] == 'exited' and process.get('returncode') == 0
            and process.get('cleanup_confirmed') is True and process.get('leader_reaped') is True
            and process.get('streams_complete') is True and process['wall_ns'] <= remaining_wall_ns
            and receipt['cli_identity_after'] == self.cli_identity and parsed['usage'] is not None
            and parsed['charged_model_tokens'] <= remaining_tokens and parsed['stream_valid']
            and receipt['launcher_admitted'])
        receipt['status'] = 'completed' if complete and parsed['answer'] is not None else 'failed'
        receipt['recoverable_content_rejection'] = complete and parsed['content_rejected_with_known_usage']
        receipt['stderr_delivery_policy'] = ('empty original may be publicly included' if not originals['stderr.raw']
            else 'private original; delivery includes SHA/bytes only unless separately reviewed for credentials')
        self.blocked_reason = (None if complete else
            'original_provider_process_protocol_or_budget_not_qualified')
        return receipt


def validate_launch(launch, process, binding):
    config = binding['configuration']
    actual, _ = adapt(process['argv'][1:],Path(process['cwd']),config)
    require(launch['schema'] == 'hepta.hia.explicit-codex-exec-adapter.v2'
        and launch['incoming_argv'] == process['argv'] and launch['actual_exec_argv'] == actual
        and launch['cwd'] == process['cwd'] and launch['actual_cli'] == binding['underlying_cli']
        and launch['adapter_sha256'] == binding['launcher']['sha256']
        and launch['adapter_path'] == binding['launcher']['path']
        and launch['adapter_module_sha256'] == config['adapter_module_sha256']
        and launch['capability_restrictions'] == restrictions(config)
        and launch['registered_feature_list_sha256'] == config['feature_list_sha256']
        and launch['pid_before_exec'] == launch['pgid_before_exec'] == process['pid']
        and launch['network_permissions_or_auth_files_modified'] is False
        and launch['new_process_group_created_by_adapter'] is False
        and launch['complete_capability_isolation_attested'] is False,
        'actual inner CLI invocation/ownership/restrictions differ')


def verify_receipt(receipt, originals, provider):
    require(receipt['schema'] == SCHEMA and receipt['provider'] == provider, 'provider identity differs')
    require(receipt['billed_cost'] is None and receipt['model_http_request_count'] is None
        and receipt['original_receipts_authenticated'] is False, 'cost/provenance scope differs')
    request = strict_json(originals[receipt['request_sha256']])
    if receipt['process'] is None:
        require(receipt['status'] == 'not_attempted' and receipt['raw'] is None, 'missing process receipt')
        return request
    raw = {name:read_raw(item, originals) for name,item in receipt['raw'].items()}
    require(set(raw) == {'stdin.raw', 'stdout.raw', 'stderr.raw'}, 'three original streams required')
    require(raw['stdin.raw'] == prompt_bytes(request), 'original public prompt differs')
    require(originals[receipt['response_schema_original_sha256']] == encoded(RESPONSE_SCHEMA) + b'\n',
            'response schema differs')
    process = receipt['process']
    output = Path(process['cwd']).parent
    require(process['argv'] == command(provider['invocation_path'], provider['requested_model'],
        provider['reasoning_effort'], output), 'original executable/model/argv differs')
    for name, data in raw.items():
        require(process['files'][name]['bytes'] == len(data)
            and process['files'][name]['sha256'] == sha256(data).hexdigest(), 'original stream differs')
    parsed = parse_stream(raw['stdout.raw'], provider['registered_startup_warnings'])
    require(all(receipt.get(key) == value for key,value in parsed.items()), 'original response/usage differs')
    binding = provider.get('launcher_binding')
    launch_ok = binding is None
    if binding is not None and receipt['launch_adapter_original_sha256'] is not None:
        try:
            validate_launch(strict_json(originals[receipt['launch_adapter_original_sha256']]),process,binding)
            launch_ok = receipt['underlying_cli_identity_after'] == binding['underlying_cli']
        except (ValueError,KeyError,TypeError):
            launch_ok = False
    require(receipt['launcher_admitted'] == launch_ok, 'launcher admission differs from originals')
    complete = (process['status'] == 'exited' and process.get('returncode') == 0
        and all(process.get(k) is True for k in ('cleanup_confirmed','leader_reaped','streams_complete'))
        and process['wall_ns'] <= receipt['remaining_wall_ns'] and parsed['usage'] is not None
        and parsed['charged_model_tokens'] <= receipt['remaining_tokens'] and parsed['stream_valid']
        and receipt['cli_identity_after'] == provider['cli_identity'] and launch_ok)
    require(receipt['status'] == ('completed' if complete and parsed['answer'] is not None else 'failed')
        and receipt['recoverable_content_rejection'] == (complete and parsed['content_rejected_with_known_usage']),
        'bounded response qualification differs')
    return request
