#!/usr/bin/env python3
"""Prepare or run one separately authorized public CLI compatibility pilot.

This is not a maintenance task, a previous task retry, a provider campaign or
formal MCP first-use. It never loads a private task/oracle or calls an HIA tool.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.hia_agent_codex_transport import identity, run_owned, save, strict_json
from tools.hia_macro_codex_provider import MacroEvents
from tools.hia_macro_exec_adapter import (DISABLED_FEATURES, ENABLED_DEPENDENCIES,
    EXACT_SKIP_SKILL_WARNING, restrictions)
from tools.hia_macro_multistep_provider import RESPONSE_SCHEMA, command, encoded, parse_stream

SCHEMA = 'hepta.hia.public-cli-capability-pilot.v1'
PROMPT = (b'Return exactly the JSON object {"assembly":"READY"}. '
    b'This is a public transport capability check, not an HIA program or maintenance task. '
    b'Do not invoke any tools, browse, execute commands, read files, or add other text.\n')
SOURCES = ('tools/qualify_hia_cli_public_capability.py', 'tools/hia_agent_codex_transport.py',
    'tools/hia_macro_codex_provider.py', 'tools/hia_macro_exec_adapter.py',
    'tools/hia_macro_multistep_provider.py')
BUDGET = {'cli_sessions': 1, 'wall_seconds': 60, 'conservative_model_tokens': 8192,
    'stdout_limit_bytes': 1048576, 'stderr_limit_bytes': 1048576, 'max_jsonl_line_bytes': 65536}


def require(condition, reason):
    if not condition:
        raise ValueError('E_HIA_PUBLIC_CLI_PILOT: ' + reason)


def new_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def sources():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def invocation(cli, output, config):
    return command(cli, 'codex-auto-review', 'low', output)[:-1] + restrictions(config) + ['-']


def prepare(output, *, real_cli, feature_list, execution_directory):
    output, execution = Path(output).absolute(), Path(execution_directory).absolute()
    require(not output.exists() and not execution.exists(), 'new plan and unique output required')
    feature_raw = Path(feature_list).read_bytes()
    require(len(feature_raw) <= 65536, 'feature registry bound')
    registry = {}
    for line in feature_raw.decode().splitlines():
        parsed = re.fullmatch(r'([a-z][a-z0-9_.]*)\s+(.+?)\s+(true|false)', line.strip())
        require(parsed is not None and parsed[1] not in registry, 'original feature registry shape')
        registry[parsed[1]] = parsed[2]
    require(all(name in registry and registry[name] != 'removed'
        for name in (*DISABLED_FEATURES, *ENABLED_DEPENDENCIES, 'skip_host_skill_discovery')),
        'registered active CLI feature names required')
    require(Path(real_cli).is_absolute() and os.access(real_cli, os.X_OK)
        and os.access(Path(real_cli).with_name('codex-code-mode-host'), os.X_OK),
        'existing executable CLI and host dependency required')
    cli = identity(real_cli)
    host = identity(Path(real_cli).with_name('codex-code-mode-host'))
    config = {'schema': 'hepta.hia.explicit-codex-launch-config.v3',
        'disabled_features': list(DISABLED_FEATURES), 'enabled_dependencies': list(ENABLED_DEPENDENCIES),
        'registered_startup_warnings': [EXACT_SKIP_SKILL_WARNING],
        'host_dependency_identity': host, 'feature_list_sha256': sha256(feature_raw).hexdigest()}
    value = {'schema': SCHEMA, 'status': 'PREPARED_ONLY_ROOT_REVIEW_REQUIRED',
        'prepared_unix_ns': time.time_ns(), 'nonce': os.urandom(16).hex(), 'source_identity': sources(),
        'python_identity': identity(sys.executable), 'python_version': sys.version,
        'cli': cli, 'host_dependency_observation': host, 'configuration': config,
        'requested_model': 'codex-auto-review', 'reasoning_effort': 'low', 'budget': BUDGET,
        'prompt_utf8': PROMPT.decode(), 'prompt_sha256': sha256(PROMPT).hexdigest(),
        'response_schema': RESPONSE_SCHEMA, 'expected_response': {'assembly': 'READY'},
        'execution_directory': str(execution), 'actual_argv': invocation(cli['path'], execution, config),
        'monetary_cost': None, 'provider_http_request_count': None,
        'hard_mid_turn_token_cap': False, 'token_convention': 'input+output+reasoning; terminal review only',
        'cache_counters_added_again': False, 'complete_capability_isolation_attested': False,
        'host_dependency_scope': 'presence/identity and requested host=true; no binary-resolver attestation',
        'same_model_identity_or_weights_attested': False, 'formal_mcp_calls': 0, 'model_calls_started': 0,
        'private_task_inputs_loaded': False, 'previous_failed_task_resumed': False,
        'campaign_restart_authorized_by_pilot': False, 'p1_acceptance': 'HOLD',
        'economic_benefit_established': False}
    new_file(output, encoded(value) + b'\n')
    return value


def run(plan_path, expected_sha256):
    raw = Path(plan_path).read_bytes()
    require(sha256(raw).hexdigest() == expected_sha256, 'root-reviewed plan differs')
    plan = strict_json(raw)
    require(plan['schema'] == SCHEMA and plan['source_identity'] == sources()
        and plan['python_identity'] == identity(sys.executable) and plan['python_version'] == sys.version
        and plan['budget'] == BUDGET and plan['prompt_utf8'].encode() == PROMPT
        and plan['prompt_sha256'] == sha256(PROMPT).hexdigest()
        and plan['response_schema'] == RESPONSE_SCHEMA and plan['expected_response'] == {'assembly': 'READY'}
        and plan['requested_model'] == 'codex-auto-review' and plan['reasoning_effort'] == 'low',
        'frozen public-only protocol changed')
    started = time.monotonic_ns()
    started_unix = time.time_ns()
    cpu = [resource.getrusage(kind) for kind in (resource.RUSAGE_SELF, resource.RUSAGE_CHILDREN)]
    require(identity(plan['cli']['path']) == plan['cli']
        and identity(plan['host_dependency_observation']['path']) == plan['host_dependency_observation'],
        'CLI/host dependency differs before dispatch')
    output = Path(plan['execution_directory'])
    output.mkdir(mode=0o700)
    for name in ('cwd', 'state', 'logs'):
        (output / name).mkdir(mode=0o700)
    require(not any((p / '.git').exists() or (p / '.git').is_symlink()
        for p in (output / 'cwd', *(output / 'cwd').parents)), 'public pilot cwd belongs to a project')
    new_file(output / 'response-schema.json', encoded(RESPONSE_SCHEMA) + b'\n')
    argv = invocation(plan['cli']['path'], output, plan['configuration'])
    require(argv == plan['actual_argv'], 'exact registered invocation differs')
    new_file(output / 'START.json', encoded({'schema': SCHEMA, 'started_unix_ns': started_unix,
        'plan_sha256': expected_sha256, 'actual_argv': argv, 'single_new_session': True,
        'prior_unknown_usage_is_unchanged': True}) + b'\n')
    events = MacroEvents([EXACT_SKIP_SKILL_WARNING])
    process = run_owned(argv, output / 'cwd', output / 'transport', input_bytes=PROMPT,
        wall_seconds=max(0, BUDGET['wall_seconds'] - (time.monotonic_ns() - started) / 1e9),
        absolute_deadline_unix_ns=started_unix + BUDGET['wall_seconds'] * 1_000_000_000,
        on_line=events.line, transport_limits={key: BUDGET[key]
            for key in ('stdout_limit_bytes', 'stderr_limit_bytes', 'max_jsonl_line_bytes')})
    originals = {name: (output / 'transport' / name).read_bytes()
        for name in ('stdin.raw', 'stdout.raw', 'stderr.raw')}
    parsed = parse_stream(originals['stdout.raw'], [EXACT_SKIP_SKILL_WARNING])
    after = {'cli': identity(plan['cli']['path']),
        'host_dependency': identity(plan['host_dependency_observation']['path'])}
    passed = (process['status'] == 'exited' and process.get('returncode') == 0
        and all(process.get(key) is True for key in ('cleanup_confirmed', 'leader_reaped', 'streams_complete'))
        and parsed['stream_valid'] and parsed['answer'] == {'assembly': 'READY'}
        and parsed['charged_model_tokens'] is not None
        and parsed['charged_model_tokens'] <= BUDGET['conservative_model_tokens']
        and after['cli'] == plan['cli'] and after['host_dependency'] == plan['host_dependency_observation']
        and sources() == plan['source_identity'])
    cpu_after = [resource.getrusage(kind) for kind in (resource.RUSAGE_SELF, resource.RUSAGE_CHILDREN)]
    value = {'schema': SCHEMA, 'plan_sha256': expected_sha256, 'passed': passed,
        'process': process, 'parsed': parsed, 'identities_after': after,
        'observed_cli_sessions_started': int('pid' in process), 'provider_http_request_count': None,
        'monetary_cost': None, 'hard_mid_turn_token_cap': False, 'failed_attempt_retried': False,
        'outer_wall_ns_through_original_checks': time.monotonic_ns() - started,
        'cpu_ns': {name: round((end.ru_utime + end.ru_stime - begin.ru_utime - begin.ru_stime) * 1e9)
            for name, begin, end in zip(('parent', 'children'), cpu, cpu_after)},
        'nested_process_cost_added_again': False,
        'originals': {name: {'sha256': sha256(data).hexdigest(), 'bytes': len(data)} for name, data in originals.items()},
        'private_stderr_delivery': 'exclude nonempty original and encoded copies; retain identity',
        'original_response_model_identity_attested': False, 'formal_mcp_calls': 0,
        'maintenance_task_completion_claimed': False, 'private_tasks_exposed': False,
        'campaign_restart_authorized': False, 'p1_acceptance': 'HOLD', 'economic_benefit_established': False}
    save(output / 'RESULT.json', value)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='phase', required=True)
    prepare_cli = sub.add_parser('prepare')
    for name in ('output', 'real-cli', 'feature-list', 'execution-directory'):
        prepare_cli.add_argument('--' + name, required=True)
    execute = sub.add_parser('run')
    execute.add_argument('--plan', required=True)
    execute.add_argument('--plan-sha256', required=True)
    args = parser.parse_args(argv)
    if args.phase == 'prepare':
        prepare(args.output, real_cli=args.real_cli, feature_list=args.feature_list,
            execution_directory=args.execution_directory)
        print(json.dumps({'status': 'PREPARED_ONLY', 'model_calls': 0}))
    else:
        result = run(args.plan, args.plan_sha256)
        print(json.dumps({key: result[key] for key in ('schema', 'passed', 'observed_cli_sessions_started', 'p1_acceptance')}))
        return 0 if result['passed'] else 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
