"""Outer capture for the frozen V13 CLI; no task or generation changes."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path('/workspace/scratch/f0c12f106c89')
REPO = ROOT / 'hepta-integration'
BASE = Path(__file__).resolve().parents[1]
OUT = BASE / 'operations'
HEAD = (BASE / 'FROZEN_HEAD.txt').read_text().strip()
sys.path.insert(0, str(REPO))
from tools.qualify_hia_integrated import _source_state


def save(path, value):
    temporary = path.with_name(path.name + '.partial')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)


def identity(path):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
            size += len(block)
    return {'path': str(path), 'bytes': size, 'sha256': digest.hexdigest()}


def resources():
    disk = os.statvfs(ROOT)
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable', 'MemFree', 'SwapTotal', 'SwapFree'):
            memory[key + '_bytes'] = int(value.split()[0]) * 1024
    return {'available_disk_bytes': disk.f_bavail * disk.f_frsize, **memory}


def process_sample(pid):
    result = {'pid': pid}
    try:
        status = Path('/proc', str(pid), 'status').read_text()
        for line in status.splitlines():
            key, value = line.split(':', 1)
            if key in ('VmRSS', 'VmHWM', 'VmSize'):
                result[key + '_bytes'] = int(value.split()[0]) * 1024
            elif key in ('State', 'Threads'):
                result[key] = value.strip()
        children = Path('/proc', str(pid), 'task', str(pid), 'children').read_text().split()
        result['children'] = [process_sample(int(child)) for child in children]
    except (ProcessLookupError, FileNotFoundError):
        result['exited_during_observation'] = True
    except Exception as exc:
        result['observation_error'] = {'type': type(exc).__name__, 'message': str(exc)}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('stage', choices=('capacity', 'calibration', 'main'))
    args = parser.parse_args()
    stage = args.stage
    receipt = OUT / (stage.upper() + '_EXECUTION.json')
    if receipt.exists():
        raise RuntimeError('Refuse repeated stage; outer receipt already exists')
    runtime = ROOT / 'hepta-model-cache/runtime/llama-b11669'
    clang = ROOT / 'toolchains/llvm20/usr/lib/llvm-20/bin/clang'
    rustc = ROOT / 'toolchains/rust-1.90.0/bin/rustc'
    common = ['--output', str(BASE / stage), '--binary', str(runtime / 'llama-server'),
              '--tokenizer', str(runtime / 'llama-tokenize'),
              '--model', str(ROOT / 'hepta-model-cache/Qwen3.5-4B-Q4_K_M.gguf'),
              '--clang', str(clang), '--rustc', str(rustc)]
    if stage == 'capacity':
        argv = [sys.executable, str(REPO / 'tools/qualify_hia_agent_tool_capacity_v13.py'), *common]
    else:
        argv = [sys.executable, str(REPO / 'tools/qualify_hia_agent_toolstudy_v13.py'), stage, *common,
                '--capacity', str(BASE / 'capacity/CAPACITY.json')]
        if stage == 'main':
            argv += ['--calibration-result', str(BASE / 'calibration/RESULT.json')]
    selected_environment = {
        'PATH': ':'.join([str(ROOT / 'hepta-native-venv/bin'), str(clang.parent), str(rustc.parent), '/usr/bin', '/bin']),
        'LD_LIBRARY_PATH': str(ROOT / 'toolchains/llvm20/usr/lib/x86_64-linux-gnu'),
        'PYTHONPATH': str(REPO), 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
        'LLAMA_ARG_REPACK': '0', 'CLANG': str(clang), 'HEPTA_CLANG': str(clang), 'RUSTC': str(rustc),
    }
    env = dict(os.environ)
    env.update(selected_environment)
    # The removed optional package staging directories are not selected for P7.
    for key in ('CPATH', 'CPLUS_INCLUDE_PATH', 'C_INCLUDE_PATH', 'LIBRARY_PATH'):
        env.pop(key, None)
    stdout_path, stderr_path = OUT / (stage + '.stdout'), OUT / (stage + '.stderr')
    samples_path = OUT / (stage + '.resources.jsonl')
    started = time.monotonic_ns()
    record = {'schema': 'hepta.p7.frozen-stage-outer-execution.v1', 'stage': stage,
              'status': 'starting', 'argv': argv, 'cwd': str(REPO), 'expected_source_commit': HEAD,
              'selected_environment': selected_environment, 'postflight_errors': [],
              'removed_ambient_include_variables': ['CPATH', 'CPLUS_INCLUDE_PATH', 'C_INCLUDE_PATH', 'LIBRARY_PATH'],
              'pid_namespace': os.readlink('/proc/self/ns/pid'), 'wrapper_pid': os.getpid(),
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'resources_before': resources(), 'wrapper': identity(Path(__file__).resolve()),
              'wrapper_modified_frozen_study_parameters': False, 'execution_attempt': 1}
    save(receipt, record)
    proc = None
    before = None
    try:
        before = _source_state()
        if before['head'] != HEAD or before['status']:
            raise RuntimeError('Frozen raw Git source must remain exact and clean')
        record.update(source_commit=before['head'], source_tree=before['tree'], source_clean_before=True)
        source_before_path = OUT / (stage + '.source-before.json')
        save(source_before_path, before)
        record['source_before'] = identity(source_before_path)
        record['status'] = 'running'
        save(receipt, record)
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr, samples_path.open('x') as samples:
            proc = subprocess.Popen(argv, cwd=REPO, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
            record['runner_pid'] = proc.pid
            save(receipt, record)
            while True:
                sample = {'elapsed_wall_ns': time.monotonic_ns() - started,
                          'resources': resources(), 'runner': process_sample(proc.pid)}
                samples.write(json.dumps(sample, sort_keys=True) + '\n')
                samples.flush()
                try:
                    returncode = proc.wait(timeout=15)
                    break
                except subprocess.TimeoutExpired:
                    pass
            record['returncode'] = returncode
            record['status'] = 'process_exited'
    except BaseException as exc:
        record['outer_error'] = {'type': type(exc).__name__, 'message': str(exc)}
        record['status'] = 'outer_capture_failed'
        raise
    finally:
        record['outer_cleanup_scope'] = 'on interruption, signal the direct runner process group and reap its leader; this does not prove escaped descendant termination'
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGINT)
                try:
                    record['returncode'] = proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    record['returncode'] = proc.wait(timeout=10)
            except BaseException as exc:
                record['postflight_errors'].append({'where': 'runner_cleanup', 'type': type(exc).__name__, 'message': str(exc)})
        record['direct_runner_reaped'] = proc is None or proc.poll() is not None
        try:
            record['resources_after'] = resources()
        except BaseException as exc:
            record['postflight_errors'].append({'where': 'resources', 'type': type(exc).__name__, 'message': str(exc)})
        try:
            after = _source_state()
            record['source_commit_after'] = after['head']
            record['source_clean_after'] = not after['status']
            record['raw_source_unchanged'] = before is not None and before == after
            source_after_path = OUT / (stage + '.source-after.json')
            save(source_after_path, after)
            record['source_after'] = identity(source_after_path)
            if not record['raw_source_unchanged']:
                raise RuntimeError('Raw source changed during the actual stage')
        except BaseException as exc:
            record['postflight_errors'].append({'where': 'source', 'type': type(exc).__name__, 'message': str(exc)})
        for key, path in (('stdout', stdout_path), ('stderr', stderr_path), ('resource_samples', samples_path)):
            try:
                if path.exists():
                    record[key] = identity(path)
            except BaseException as exc:
                record['postflight_errors'].append({'where': key, 'type': type(exc).__name__, 'message': str(exc)})
        record['outer_wall_ns'] = time.monotonic_ns() - started
        record['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record['wall_scope'] = 'includes raw source preflight/postflight and stream identities; terminal receipt write is outside this interval'
        if record['postflight_errors']:
            record['status'] = 'outer_capture_failed'
        try:
            save(receipt, record)
        except BaseException as exc:
            record['status'] = 'outer_capture_failed'
            record['postflight_errors'].append({'where': 'terminal_receipt', 'type': type(exc).__name__, 'message': str(exc)})
            print(json.dumps(record, sort_keys=True), file=sys.stderr)
        print(json.dumps({key: record.get(key) for key in ('stage', 'status', 'returncode', 'outer_wall_ns', 'outer_error', 'source_clean_after')}))
    return record['returncode'] if not record['postflight_errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
