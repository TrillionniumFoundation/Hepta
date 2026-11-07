"""Observe the unchanged published HIA CLI main, preserving partial failures.

No request, response, expected status, controller, or worker source is changed.
The two method wrappers only append decoded receipts and runtime stderr.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import types

source, runtime, config, output = map(Path, sys.argv[1:5])
binary = Path('/home/qq/hepta-hia-agent-native-20261106-f4e250f91ef4/bin/hepta-runtime-r4')
expected_source = '205f94ec811018f89fbf68c987c6ab8e826bb15b'
expected_runtime = '9f60a30530f47925f4f6ae495660a1d68bb6947d'
expected_config = '2742a0371feec2a16287dcff6d0cc7323df784e29bd49ef81d5096b961ad2063'
expected_binary = '6dcadf26053b35b9edb1270576bbbdc5f1ec8f37f958e9e5ca9b9350d2d5e13f'
os.umask(0o077)
output.mkdir(mode=0o700, exist_ok=False)
started = time.monotonic_ns()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def save(name, value):
    with (output / name).open('xb') as stream:
        stream.write(canonical(value) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())


def identity(path):
    digest = sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return {'bytes': path.stat().st_size, 'sha256': digest.hexdigest()}


def repository(path, expected):
    head = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain=v1', '--untracked-files=all'], text=True)
    if head != expected or dirty:
        raise RuntimeError('selected source identity or cleanliness changed')
    return {'commit': head, 'clean': True}


before = {'hepta': repository(source, expected_source), 'runtime': repository(runtime, expected_runtime),
          'configuration': identity(config), 'runtime_binary': identity(binary), 'observer': identity(Path(__file__))}
if before['configuration']['sha256'] != expected_config or before['runtime_binary']['sha256'] != expected_binary:
    raise RuntimeError('selected config or runtime executable differs from explicit pin')
entry = source / 'tools/hia_agent_native_qualification.py'
entry_bytes = entry.read_bytes()
committed = subprocess.check_output(['git', '-C', str(source), 'show', expected_source + ':tools/hia_agent_native_qualification.py'])
if entry_bytes != committed:
    raise RuntimeError('qualification entrypoint differs from the selected commit')
command = [str(binary), 'mcp', '--runtime-config', str(config)]
arguments = ['--mcp-command-json', json.dumps(command), '--cwd', str(runtime), '--output', str(output / 'RESULT.json')]
save('REGISTRATION.json', {'schema': 'hepta.hia.actual-mcp-qualification-observer.v1', 'before': before,
    'qualification_entrypoint_sha256': sha256(entry_bytes).hexdigest(), 'entrypoint_arguments': arguments,
    'instrumentation': 'append-only decoded MCP/application receipts; exact source main and original method results',
    'candidate_mutation': 'only the registered qualification slot through actual hia_adopt and hia_rollback',
    'production_deployed': False, 'model_experiment': False})
sys.path.insert(0, str(source))
sys.path.insert(0, str(source / 'tools'))
sys.dont_write_bytecode = True
module = types.ModuleType('observed_hia_native_qualification')
module.__file__ = str(entry)
module.__package__ = ''
exec(compile(entry_bytes, str(entry), 'exec'), module.__dict__)
application = (output / 'application-attempts.jsonl').open('xb')
protocol = (output / 'decoded-mcp-receipts.jsonl').open('xb')
original_call = module.ToolClient.call
original_rpc = module.MCPStdio.rpc
original_close = module.MCPStdio.close
counters = {'application_calls': 0, 'mcp_receipts': 0}
closure = []


def append(stream, value):
    stream.write(canonical(value) + b'\n')
    stream.flush()
    os.fsync(stream.fileno())


def observed_call(self, tool, arguments, **keywords):
    begin = time.monotonic_ns()
    result = failure = None
    try:
        result = original_call(self, tool, arguments, **keywords)
        return result
    except BaseException as error:
        failure = {'type': type(error).__name__, 'message': str(error)[:8192]}
        raise
    finally:
        counters['application_calls'] += 1
        row = {'ordinal': counters['application_calls'], 'tool': tool, 'arguments': arguments,
            'expected_status': keywords.get('expected_status', 'completed'), 'response': result,
            'error': failure, 'outer_wall_ns': time.monotonic_ns() - begin,
            'recorded_original_call_count': len(self.records)}
        append(application, row)
        print(json.dumps({'tool_call': row['ordinal'], 'tool': tool,
            'response_status': result.get('status') if isinstance(result, dict) else None,
            'expected_status': row['expected_status'], 'error_type': failure['type'] if failure else None}), flush=True)


def observed_rpc(self, method, params):
    offset = len(self.protocol_records)
    try:
        return original_rpc(self, method, params)
    finally:
        for record in self.protocol_records[offset:]:
            append(protocol, record)
            counters['mcp_receipts'] += 1


def observed_close(self):
    duplicate = None
    try:
        duplicate = os.dup(self.stderr_file.fileno())
    except (OSError, ValueError):
        pass
    try:
        return original_close(self)
    finally:
        observation = {'returncode': self.process.returncode,
                       'stderr_capture': duplicate is not None}
        if duplicate is not None:
            try:
                size = os.fstat(duplicate).st_size
                observation['stderr_original_bytes'] = size
                observation['stderr_complete'] = size <= 16 * 1024 * 1024
                raw = os.pread(duplicate, min(size, 16 * 1024 * 1024), 0)
                with (output / ('runtime-stderr-' + str(len(closure)) + '.raw')).open('xb') as stream:
                    stream.write(raw)
                observation['stderr_sha256'] = sha256(raw).hexdigest()
            finally:
                os.close(duplicate)
        closure.append(observation)


module.ToolClient.call = observed_call
module.MCPStdio.rpc = observed_rpc
module.MCPStdio.close = observed_close
error = None
try:
    module.main(arguments)
except BaseException as exc:
    error = {'type': type(exc).__name__, 'message': str(exc)[:8192]}
    with (output / 'FAILURE.txt').open('x') as stream:
        traceback.print_exc(file=stream)
finally:
    application.close()
    protocol.close()
try:
    after = {'hepta': repository(source, expected_source), 'runtime': repository(runtime, expected_runtime),
             'configuration': identity(config), 'runtime_binary': identity(binary), 'observer': identity(Path(__file__))}
    if after != before:
        raise RuntimeError('selected bytes changed during qualification')
except BaseException as exc:
    after = None
    error = error or {'type': type(exc).__name__, 'message': str(exc)[:8192]}
result = json.loads((output / 'RESULT.json').read_bytes()) if (output / 'RESULT.json').exists() else None
passed = error is None and result is not None and result['status'] == 'passed'
final = {'schema': 'hepta.hia.actual-mcp-qualification-observer-result.v1',
    'status': 'passed' if passed else 'failed', 'error': error, 'before': before, 'after': after,
    'observed_total_wall_ns': time.monotonic_ns() - started, 'receipt_counts': counters,
    'transport_close_observations': closure, 'production_deployed': False,
    'net_optimization_benefit_proved': False,
    'qualification_result': identity(output / 'RESULT.json') if result else None}
save('FINAL.json', final)
print(json.dumps({'qualification_observer_status': final['status'], **counters, 'error': error}), flush=True)
raise SystemExit(0 if passed else 1)
