"""Independent read-only review probes for the pinned byte-DAG implementation."""
import sys
for name in ('hia_program', 'hia_program_composite', 'hia_program_runtime',
             'hia_static_budget', 'hia_source_bridge', 'hia_program_llvm'):
    sys.modules['hepta.' + name] = None

import copy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import time
from unittest.mock import patch
from hepta.hia_rust_byte_dag import execute_rust_byte_dag, HIARustByteDagRejected
from hepta import hia_rust_crosscheck as transport

OUT = Path('/workspace/scratch/f0c12f106c89/p2-independent-review')
BUILD = json.loads((OUT / 'build.json').read_text())
EXE = BUILD['executable']['path']
PIN = BUILD['executable']['sha256']
SCALAR = dict(max_allocator_interactions=0, max_vm_ticks=2, max_call_depth=1)
OWNED = dict(max_allocator_interactions=2, max_vm_ticks=4, max_call_depth=1)
RUNTIME = dict(max_steps=4, max_heap_bytes=3, max_call_depth=1, allocation_fail_at=None)
observations, refusals, tampering = [], [], []
started = time.monotonic_ns()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def param(name, typ):
    return {'name': name, 'type': typ}


def function(name, params, returns, ops, values, effects):
    return {'name': name, 'params': params, 'returns': returns, 'effects': effects,
            'entry': 'entry', 'blocks': [{'id': 'entry', 'params': params,
            'ops': ops, 'term': {'op': 'ret', 'values': values}}]}


def op(opcode, args, out=(), **attrs):
    return {'op': opcode, 'args': args, 'out': list(out), 'attrs': attrs}


identity = {'schema': 'hepta.hia.program.v1', 'module': 'review', 'exports': ['identity'],
            'functions': [function('identity', [param('v', 'u32')], ['u32'], [], ['v'], [])]}
owned = {'schema': 'hepta.hia.program.v1', 'module': 'review', 'exports': ['owned'],
         'functions': [function('owned', [param('n', 'usize')], [], [
             op('buffer.new', ['n'], [param('owner', 'buffer')]),
             op('owner.drop', ['owner'])], [], ['alloc', 'trap'])]}


def invoke(label, source, function_name, arguments, static, **policy):
    payload = source if type(source) is bytes else wire(source)
    captured = []
    original = transport._run_pinned_shadow
    def record(binary, argv, stdin, timeout, **kwargs):
        before = time.monotonic_ns()
        result = original(binary, argv, stdin, timeout, **kwargs)
        captured.append({'executable_sha256': sha256(binary).hexdigest(), 'argv': argv,
            'input_utf8': stdin.decode(), 'input_sha256': sha256(stdin).hexdigest(),
            'stdout': result[0].decode(), 'stderr': result[1].decode(),
            'returncode': result[2], 'wall_ns': time.monotonic_ns() - before})
        return result
    with patch.object(transport, '_run_pinned_shadow', record):
        report = execute_rust_byte_dag(payload, function_name, arguments, EXE,
            executable_sha256=PIN, static_policy=static, **policy)['rust_report']
    assert len(captured) == 1 and captured[0]['executable_sha256'] == PIN
    observations.append({'label': label, 'process': captured[0], 'report': report})
    return report


def reject(label, source, function_name, arguments, static, expected_code):
    payload = source if type(source) is bytes else wire(source)
    argv = [EXE, '--byte-dag-admit-run', function_name, wire(arguments).decode(),
            wire(static).decode(), wire(RUNTIME).decode()]
    before = time.monotonic_ns()
    p = subprocess.run(argv, input=payload, capture_output=True, timeout=15,
                       env={'PATH': '/nonexistent', 'LANG': 'C', 'LC_ALL': 'C'})
    record = {'label': label, 'argv': argv, 'input_utf8': payload.decode(),
              'returncode': p.returncode, 'stdout': p.stdout.decode(), 'stderr': p.stderr.decode(),
              'wall_ns': time.monotonic_ns() - before}
    refusals.append(record)
    assert p.returncode == 1 and p.stdout == b'' and p.stderr.startswith(expected_code.encode()), record
    assert b'panicked' not in p.stderr


failure = None
try:
    for steps, status, ticks, live, allocations, frees in (
            (1, 'budget_exceeded', 2, 0, 0, 0),
            (2, 'budget_exceeded', 3, 3, 1, 0),
            (3, 'budget_exceeded', 4, 0, 1, 1),
            (4, 'returned', 4, 0, 1, 1)):
        report = invoke('stopped_prefix_' + str(steps), owned, 'owned', [3], OWNED,
                        max_steps=steps, max_heap_bytes=3, max_call_depth=1)
        run = report['runtime']['execution']
        assert (run['status'], run['steps'], run['resources']['live_bytes'],
                run['resources']['allocations'], run['resources']['frees']) == (
                    status, ticks, live, allocations, frees), run
        if status == 'budget_exceeded': assert run['error'] == {'code': 'steps'}
    run = invoke('zero_does_not_consume_failure_index', owned, 'owned', [0], OWNED,
                 max_steps=4, max_heap_bytes=0, max_call_depth=1, allocation_fail_at=1)['runtime']['execution']
    assert run['status'] == 'returned' and run['resources']['allocation_attempts'] == 0
    assert run['resources']['owners_created'] == run['resources']['owners_dropped'] == 1
    for name, size, heap, fail, status, code, attempts in (
            ('oversized_before_heap', (1 << 64) - 1, 0, None, 'trapped', 'allocation', 0),
            ('heap_before_allocator', 3, 2, 1, 'budget_exceeded', 'heap', 0),
            ('exact_refusal_index', 3, 3, 1, 'trapped', 'allocation', 1)):
        run = invoke(name, owned, 'owned', [size], OWNED, max_steps=4,
                     max_heap_bytes=heap, max_call_depth=1, allocation_fail_at=fail)['runtime']['execution']
        assert (run['status'], run['error']['code'], run['steps'], run['resources']['allocation_attempts']) == (status, code, 2, attempts)
        assert run['resources']['live_owners'] == 0
    helper = function('pass_owner', [param('incoming', 'buffer')], ['buffer'], [], ['incoming'], [])
    outer = function('run', [param('size', 'usize')], [], [
        op('buffer.new', ['size'], [param('first', 'buffer')]),
        op('call', ['first'], [param('returned', 'buffer')], function='pass_owner'),
        op('owner.drop', ['returned'])], [], ['alloc', 'trap'])
    calls = {'schema': 'hepta.hia.program.v1', 'module': 'depth_review', 'exports': ['run'], 'functions': [helper, outer]}
    run = invoke('depth_stop_retains_transferred_owner', calls, 'run', [3],
                 dict(max_allocator_interactions=2, max_vm_ticks=7, max_call_depth=2),
                 max_steps=7, max_heap_bytes=3, max_call_depth=1)['runtime']['execution']
    assert run['status'] == 'budget_exceeded' and run['error'] == {'code': 'calls'}
    assert run['steps'] == 3 and run['resources']['live_owners'] == 1 and run['resources']['live_bytes'] == 3
    assert run['resources']['frees'] == 0
    for metric in OWNED:
        policy = dict(OWNED); policy[metric] -= 1
        reject('one_below_' + metric, owned, 'owned', [0], policy, 'E_HIA_BUDGET_EXCEEDED')
    hidden = copy.deepcopy(identity); hidden['functions'] += copy.deepcopy(owned['functions'])
    reject('hidden_function_static_limit', hidden, 'identity', [7], SCALAR, 'E_HIA_BUDGET_EXCEEDED')
    hidden['functions'][-1]['blocks'][0]['ops'].pop()
    reject('hidden_live_owner', hidden, 'identity', [7], OWNED, 'E_HIA_RESOURCE')
    duplicate = wire(identity).replace(b'"module":"review"', b'"module":"review","\\u006dodule":"shadow"')
    reject('escaped_duplicate_raw_key', duplicate, 'identity', [7], SCALAR, 'E_HIA_FORMAT')
    raw = json.dumps(identity, indent=2).encode()
    original = invoke('pretty_raw_snapshot', raw, 'identity', [7], SCALAR)
    assert original['request']['input_sha256'] == sha256(raw).hexdigest()
    for field, replacement in (('input_sha256', original['request']['program_sha256']),
                               ('arguments', [8]), ('static_policy', {**SCALAR, 'max_vm_ticks': 3})):
        changed = copy.deepcopy(original)
        changed['request'][field] = replacement
        changed['request_sha256'] = sha256(wire(changed['request'])).hexdigest()
        with patch.object(transport, '_run_pinned_shadow', return_value=(wire(changed) + b'\n', b'', 0)):
            try:
                execute_rust_byte_dag(raw, 'identity', [7], EXE, executable_sha256=PIN, static_policy=SCALAR)
            except HIARustByteDagRejected as error:
                tampering.append({'field': field, 'rejected': True, 'message': str(error),
                                  'actual_execution_evidence': False})
            else: raise AssertionError('rehashed cross-request replay accepted')
    assert all(sys.modules['hepta.' + name] is None for name in ('hia_program', 'hia_program_composite',
        'hia_program_runtime', 'hia_static_budget', 'hia_source_bridge', 'hia_program_llvm'))
except Exception as error:
    failure = {'type': type(error).__name__, 'message': str(error)}
finally:
    report = {'schema': 'hepta.p2-independent-readonly-review.v1',
        'source_commit': BUILD['source_commit'], 'executable': BUILD['executable'],
        'ok': failure is None, 'error': failure, 'observations': observations, 'refusals': refusals,
        'tampering_negative_controls': tampering, 'semantic_python_modules_unavailable': True,
        'candidate_worktree_modified': False, 'wall_ns': time.monotonic_ns() - started,
        'model_productivity_trial': False, 'whole_language_or_backend_proof': False}
    (OUT / 'probes.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ('ok', 'error', 'wall_ns')} | {
    'actual_positive_processes': len(observations), 'actual_refusals': len(refusals),
    'tampering_negative_controls': len(tampering)}))
raise SystemExit(0 if failure is None else 1)
