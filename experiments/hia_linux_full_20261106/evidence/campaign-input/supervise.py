#!/usr/bin/env python3
"""One-shot orchestration of the frozen full-image experiment.

`check` only reads existing source/evidence and prints readiness. `run` requires
the parent's separately frozen readiness receipt and its exact SHA256. There is
no resume, retry, seed replacement, performance filtering, or new compilation.
The frozen production driver is called through its actual main(argv) entry point
in this single supervisor process, so cancellation reaches the collector's owned
QEMU process-group cleanup rather than abandoning a nested launcher process.
"""
from __future__ import annotations
import argparse
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time
import traceback

ROOT = Path('/tmp/hepta-hia-linux-full-20261106-bedaafad8a2f-r1')
HERE = Path(__file__).resolve().parent
SPEC = HERE / 'spec.json'
MANIFEST = HERE / 'INPUTS.json'
SOURCE = ROOT / 'comparison-code-r1-frozen'
DRIVER = SOURCE / 'tools/qualify_hia_kernel_comparison.py'
COMMIT = '0f1d1b53b177b902453ca12c132a9cd45a6948ca'
CALIBRATION = ROOT / 'comparison-calibration-r1'
CAMPAIGN = ROOT / 'comparison-campaign-r1'
OUTPUT = ROOT / 'comparison-supervisor-r1'
REPLAY = ROOT / 'hia-replay-r1/RESULT.json'
INTEGRATION = ROOT / 'comparison-code-materialization-r1/RESULT.json'
MODULES = ('tests.test_core_seven_shared_source_closure', 'tests.test_core_seven_shared_acceptance',
           'tests.test_hia_linux_full_inventory', 'tests.test_hia_linux_system_benchmark',
           'tests.test_hia_kernel_comparison')
PHASES = ('syscall_process_pipe', 'anonymous_memory', 'tmpfs_files', 'unix_tcp')
ARMS = ('stock', 'hia-static', 'best-fixed', 'greedy', 'ordinary-mpc',
        'independent-same-objective', 'fixed-ndu', 'dynamic-ndu')

def require(ok, message):
    if not ok:
        raise ValueError(message)

def load(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def bad(value):
        raise ValueError('nonfinite JSON: ' + value)
    return json.loads(Path(path).read_bytes(), object_pairs_hook=pairs, parse_constant=bad)

def identity(path):
    path = Path(path).absolute()
    with path.open('rb') as stream:
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': value}

def bind(row):
    actual = identity(row['path'])
    require(actual == {key: row[key] for key in actual}, 'immutable binding changed: ' + row['path'])
    return actual

def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    return identity(path)

def log_path(row):
    return Path(row['path'] if isinstance(row, dict) else row)

def readiness_snapshot():
    manifest = load(MANIFEST)
    require(manifest['schema'] == 'hepta.hia.kernel-comparison.supervisor-inputs.v1', 'input manifest schema')
    for key in ('spec', 'supervisor', 'driver_source_manifest', 'benchmark_handoff'):
        bind(manifest[key])
    require(identity(Path(sys.executable).resolve()) == manifest['python'], 'different supervisor Python binary')
    spec = load(SPEC)
    require(spec['driver_source_commit'] == COMMIT and
            spec['campaign_id'] == 'full-linux-hia-ndu-20261106-r1', 'campaign/source identity changed')
    source_manifest = load(spec['driver_source_manifest'])
    require(source_manifest['commit'] == COMMIT and len(source_manifest['files']) == 6,
            'six-file source manifest changed')
    for name, expected in source_manifest['files'].items():
        body = (SOURCE / name).read_bytes()
        require(hashlib.sha1(('blob ' + str(len(body)) + '\0').encode() + body).hexdigest() == expected,
                'frozen source blob changed: ' + name)
    for args, expected in ((['rev-parse', 'HEAD'], COMMIT),
                            (['status', '--porcelain', '--untracked-files=all'], '')):
        result = subprocess.run(['git', '--no-replace-objects', '-C', str(SOURCE), *args],
                                capture_output=True, text=True, check=True)
        require(result.stdout.strip() == expected, 'frozen checkout HEAD/clean state differs')
    gates, missing = {}, []
    required = [INTEGRATION, REPLAY, ROOT / 'KVM_IMAGE_QUALIFICATIONS.json']
    for item in spec['images'].values():
        required += [Path(item['build_receipt']), Path(item['qualification'])]
    for path in required:
        if not path.is_file():
            missing.append(str(path))
    if missing:
        return {'status': 'PENDING', 'missing': missing, 'new_boots_started': 0}
    integration = load(INTEGRATION)
    require(integration['status'] == 'PASS' and integration['head'] == COMMIT and
            Path(integration['repo']) == SOURCE and all(x['exit_code'] == 0 for x in integration['commands']),
            'integration materialization failed')
    unit = integration['commands'][-1]
    require(unit['argv'][-5:] == list(MODULES) and 'unittest' in unit['argv'], 'different integrated unit suite')
    unit_text = log_path(unit['stdout']).read_bytes().decode('utf-8') + log_path(unit['stderr']).read_bytes().decode('utf-8')
    require(re.search(r'(?m)^Ran 93 tests in ', unit_text) and re.search(r'(?m)^OK\s*$', unit_text) and
            not re.search(r'(?m)^FAILED\b', unit_text), '93 integrated tests did not pass')
    gates['integration'] = {'result': identity(INTEGRATION), 'unit_stdout': identity(log_path(unit['stdout'])),
                            'unit_stderr': identity(log_path(unit['stderr'])), 'tests': 93}
    qualification = load(ROOT / 'KVM_IMAGE_QUALIFICATIONS.json')
    require(qualification['status'] == 'PASS', 'four-image KVM aggregate is not PASS')
    gates['qualification_aggregate'] = identity(ROOT / 'KVM_IMAGE_QUALIFICATIONS.json')
    for image, paths in spec['images'].items():
        build, guest = load(paths['build_receipt']), load(paths['qualification'])
        require(all(build[k] == 'PASS' for k in ('status', 'build_status', 'boot_status')),
                'incomplete full build: ' + image)
        if image != 'stock':
            require(build['all_configured_target_units_rewritten'] is True and build['fallback_c_units'] == 0 and
                    build['mode'] == 'import', 'HIA target completeness/import failure: ' + image)
        require(guest['status'] == 'PASS' and guest['profile'] == 'kvm' and guest['selection'] == 'all' and
                guest['seed'] == 20261106 and guest['iterations'] == 1024 and
                guest['host_affinity']['requested_cpus'] == [0, 1], 'wrong KVM qualification: ' + image)
        require(guest['inputs'][0] == build['kernel_image'] and guest['inputs'][1] == build['config'],
                'build/qualification image or config mismatch: ' + image)
        require(guest['collector_source_commit'] == spec['collector']['source_commit'] and
                guest['collector_source']['path'] == spec['collector']['path'] and
                guest['static_build_receipt']['path'] == spec['guest_build_receipt'],
                'different collector/guest: ' + image)
        require(guest['qemu']['path'] == spec['qemu'] and guest['bios']['path'] == spec['bios'] and
                guest['qemu_data']['path'] == spec['qemu_data'] and
                guest['qemu_modules']['path'] == spec['qemu_modules'], 'different QEMU runtime: ' + image)
        for row in (build['kernel_image'], build['config'], guest['preexecution_manifest'], guest['trace'],
                    guest['command_receipt']['stdout'], guest['command_receipt']['stderr']):
            bind(row)
        gates[image] = {'build': identity(paths['build_receipt']), 'qualification': identity(paths['qualification']),
                        'image': build['kernel_image'], 'config': build['config']}
    replay = load(REPLAY)
    require(all(replay[k] == 'PASS' for k in ('status', 'build_status', 'boot_status')) and
            replay['all_configured_target_units_rewritten'] is True and replay['fallback_c_units'] == 0 and
            replay['mode'] == 'replay', 'complete source-free replay is not PASS')
    gates['replay'] = identity(REPLAY)
    for path in (CALIBRATION, CAMPAIGN, OUTPUT, HERE / 'RUN_ONCE.json'):
        require(not path.exists(), 'previous or in-flight campaign output exists; resumption forbidden: ' + str(path))
    return {'status': 'READY', 'source_commit': COMMIT, 'gates': gates,
            'spec': identity(SPEC), 'supervisor': identity(__file__), 'driver': identity(DRIVER),
            'new_boots_started': 0, 'full_admission_deferred_to_production_driver': True}

def verify_readiness(path, expected_sha):
    receipt = identity(path)
    require(receipt['sha256'] == expected_sha, 'parent readiness SHA mismatch')
    value = load(path)
    require(value.get('schema') == 'hepta.hia.kernel-comparison.readiness.v1' and
            value.get('status') == 'PASS' and value.get('source_commit') == COMMIT,
            'parent readiness receipt is not the registered PASS')
    terminals = value.get('runtime_terminals')
    require(isinstance(terminals, list) and terminals, 'actual outer runtime terminal receipts required')
    ids = set()
    for terminal in terminals:
        require(terminal.get('state') == 'succeeded' and type(terminal.get('exit_code')) is int and
                terminal['exit_code'] == 0 and terminal.get('output_complete') is True and
                terminal.get('output_durable') is True and not terminal.get('cancelled') and
                not terminal.get('timed_out'), 'non-successful outer runtime job')
        require(terminal['job_id'] not in ids, 'duplicate outer runtime job identity')
        ids.add(terminal['job_id'])
    require({'1a1b21656b0-fc05-7c4e', '1a1b1f7ed7a-fc05-7bcc'} <= ids,
            'materialization and four-image KVM watcher terminals missing')
    return receipt

class Stopped(BaseException):
    pass

def stop(signum, frame):
    raise Stopped('supervisor received signal ' + str(signum) + '; no retry')

def invoke(driver, argv, number, name, records):
    stem = OUTPUT / 'commands' / f'{number:03d}-{name}'
    stem.parent.mkdir(parents=True, exist_ok=True)
    started, cpu = time.monotonic_ns(), time.process_time_ns()
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    record = {'schema': 'hepta.hia.kernel-comparison.supervisor-call.v1',
              'entrypoint': 'frozen production driver.main(argv)', 'argv': argv,
              'actual_supervisor_pid': os.getpid(), 'started_unix_ns': time.time_ns(),
              'new_launcher_subprocess': False}
    print(json.dumps({'stage': name, 'status': 'RUNNING', 'index': number}), flush=True)
    write_new(str(stem) + '.started.json', record)
    with open(str(stem) + '.stdout', 'x') as stdout, open(str(stem) + '.stderr', 'x') as stderr:
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                record['exit_code'] = driver.main(argv)
        except BaseException as error:
            record['exit_code'] = None
            record['error'] = {'type': type(error).__name__, 'message': str(error)}
            traceback.print_exc(file=stderr)
        finally:
            stdout.flush(); stderr.flush()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    record.update(wall_ns=time.monotonic_ns() - started, parent_cpu_ns=time.process_time_ns() - cpu,
                  child_user_seconds=after.ru_utime - children.ru_utime,
                  child_system_seconds=after.ru_stime - children.ru_stime, completed_unix_ns=time.time_ns(),
                  stdout=identity(str(stem) + '.stdout'), stderr=identity(str(stem) + '.stderr'))
    binding = write_new(str(stem) + '.json', record)
    records.append(binding)
    print(json.dumps({'stage': name, 'status': 'PASS' if record['exit_code'] == 0 else 'FAIL',
                      'index': number, 'receipt': binding}), flush=True)
    require(record['exit_code'] == 0, 'production driver call failed; inspect ' + str(stem) + '.json')

def state_gate(status, index, pending_count=None):
    state = load(CAMPAIGN / 'STATE.json')
    require(state['status'] == status and state['next_index'] == index and len(state['completed']) == index,
            'unexpected campaign state after production driver call')
    if pending_count is None:
        require(state['pending'] is None, 'unexpected pending work')
    else:
        require(state['pending']['inflight'] is None and len(state['pending']['executed']) == pending_count,
                'incomplete or repeated arm execution')
    return state

def run(readiness_path, readiness_sha, deadline):
    require(600 <= deadline <= 21600, 'bounded whole-campaign deadline required')
    readiness = verify_readiness(readiness_path, readiness_sha)
    snapshot = readiness_snapshot()
    require(snapshot['status'] == 'READY', 'prerequisites are not ready; no waiting/retry or boot started')
    owner = {'schema': 'hepta.hia.kernel-comparison.supervisor-owner.v1', 'status': 'STARTED',
             'pid': os.getpid(), 'host_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'start_ticks': int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]),
             'source_commit': COMMIT, 'readiness': readiness, 'spec': identity(SPEC),
             'supervisor': identity(__file__), 'started_unix_ns': time.time_ns(),
             'python': identity(Path(sys.executable).resolve()), 'python_version': sys.version,
             'deadline_seconds': deadline, 'resumption_allowed': False}
    write_new(HERE / 'RUN_ONCE.json', owner)
    OUTPUT.mkdir(exist_ok=False)
    intent = write_new(OUTPUT / 'INTENT.json', {'owner': owner, 'readiness_snapshot': snapshot,
                                              'input_manifest': identity(MANIFEST)})
    result = {'schema': 'hepta.hia.kernel-comparison.supervisor-result.v1', 'status': 'FAIL',
              'intent': intent, 'calls': [], 'actual_calls_completed': 0, 'implicit_retries': 0,
              'started_unix_ns': time.time_ns()}
    prior_handlers = {}
    try:
        for name in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
            prior_handlers[name] = signal.signal(name, stop)
        signal.alarm(deadline)
        os.environ.update(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')
        sys.dont_write_bytecode = True
        module_spec = importlib.util.spec_from_file_location('one_frozen_comparison_driver', DRIVER)
        driver = importlib.util.module_from_spec(module_spec)
        sys.modules[module_spec.name] = driver
        module_spec.loader.exec_module(driver)
        counter = 0
        def call(argv, name):
            nonlocal counter
            invoke(driver, argv, counter, name, result['calls'])
            counter += 1
            result['actual_calls_completed'] = counter
        call(['calibrate', '--spec', str(SPEC), '--output', str(CALIBRATION)], 'calibrate')
        require(load(CALIBRATION / 'RESULT.json')['status'] == 'PASS', 'calibration did not complete')
        call(['register', '--spec', str(SPEC), '--calibration-result', str(CALIBRATION / 'RESULT.json'),
              '--output', str(CAMPAIGN)], 'register')
        state_gate('READY', 0)
        registry = load(CAMPAIGN / 'REGISTRY.json')
        require(registry['campaign_id'] == 'full-linux-hia-ndu-20261106-r1' and len(registry['schedule']) == 20,
                'wrong admitted campaign schedule')
        for index, case in enumerate(registry['schedule']):
            require(case['index'] == index and case['phase'] == PHASES[index % 4] and case['seed'] == 20261200 + index
                    and set(case['arm_order']) == set(ARMS) and len(case['arm_order']) == 8,
                    'precommitted block/phase/arm schedule differs')
            state_gate('READY', index)
            call(['plan-next', '--output', str(CAMPAIGN), '--phase', case['phase'], '--seed', str(case['seed'])],
                 f'cell-{index:02d}-plan')
            planned = state_gate('PLANNED', index, 0)
            plan = load(planned['pending']['plan']['path'])
            require(plan['case'] == case and set(plan['arms']) == set(ARMS) and plan['no_boot_started'] is True,
                    'all eight actions were not frozen before first boot')
            for position, arm in enumerate(case['arm_order']):
                call(['execute-next', '--output', str(CAMPAIGN)], f'cell-{index:02d}-arm-{position}-{arm}')
                if position < 7:
                    next_state = state_gate('PLANNED', index, position + 1)
                    observation = load(next_state['pending']['executed'][-1]['path'])
                else:
                    next_state = state_gate('COMPLETE' if index == 19 else 'READY', index + 1)
                    observation = load(next_state['completed'][-1]['path'])['observations'][-1]
                require(observation['arm'] == arm and observation['run_id'] == case['run_ids'][arm],
                        'actual boot order/run identity differs from frozen plan')
        state_gate('COMPLETE', 20)
        call(['evaluate', '--output', str(CAMPAIGN)], 'evaluate')
        evaluation = load(CAMPAIGN / 'EVALUATION.json')
        require(evaluation['status'] == 'PASS' and evaluation['heldout_boots'] == evaluation['correct_boots'] == 160
                and evaluation['excluded_outliers'] == 0, 'complete registered evaluation missing')
        result.update(status='PASS', calibration=identity(CALIBRATION / 'RESULT.json'),
                      registry=identity(CAMPAIGN / 'REGISTRY.json'), evaluation=identity(CAMPAIGN / 'EVALUATION.json'),
                      independently_scheduled_calibration_boots=12, independently_scheduled_heldout_boots=160)
    except BaseException as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    finally:
        signal.alarm(0)
        for name, handler in prior_handlers.items():
            signal.signal(name, handler)
        result['completed_unix_ns'] = time.time_ns()
        result['terminal_state'] = load(CAMPAIGN / 'STATE.json') if (CAMPAIGN / 'STATE.json').exists() else None
        write_new(OUTPUT / 'RESULT.json', result)
    print(json.dumps({'status': result['status'], 'result': identity(OUTPUT / 'RESULT.json'),
                      'calls': result['actual_calls_completed'], 'error': result.get('error')}), flush=True)
    return 0 if result['status'] == 'PASS' else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check')
    execute = sub.add_parser('run')
    execute.add_argument('--readiness', required=True, type=Path)
    execute.add_argument('--readiness-sha256', required=True)
    execute.add_argument('--deadline-seconds', type=int, default=7200)
    args = parser.parse_args()
    if args.command == 'run':
        return run(args.readiness, args.readiness_sha256, args.deadline_seconds)
    snapshot = readiness_snapshot()
    print(json.dumps(snapshot, sort_keys=True, allow_nan=False))
    return 0 if snapshot['status'] == 'READY' else 2

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'FAIL', 'error': {'type': type(error).__name__, 'message': str(error)},
                          'implicit_retries': 0}), flush=True)
        raise SystemExit(1)
