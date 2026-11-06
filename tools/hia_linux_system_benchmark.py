#!/usr/bin/env python3
"""Collect and strictly admit the finite PID1 system benchmark.

Importing this module never starts a guest.  run_guest()/the CLI create a new
output, bind real inputs, run one bounded QEMU process group, and preserve raw
observations.  parse_serial() alone admits a trace against a supplied receipt;
synthetic parser fixtures are not execution or performance evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import statistics
import sys
import time

PREFIX = 'HIA_LINUX_BENCH '
PROTOCOL = 'hepta.hia.linux.system-benchmark.v1'
PHASES = ('syscall_process_pipe', 'anonymous_memory', 'tmpfs_files', 'unix_tcp')
UNITS = dict(zip(PHASES, (
    'pipe_request_response_cycles', 'pages_initialized_and_verified',
    'file_lifecycles', 'socket_request_response_cycles')))
WARMUPS, MEASURED, DEADLINE = 2, 5, 180
MASK = (1 << 64) - 1
PROFILES = {
    'tcg': {'accel': 'tcg,thread=multi', 'cpu': 'qemu64,-popcnt'},
    'kvm': {'accel': 'kvm', 'cpu': 'qemu64,-popcnt,-svm'},
}
BEGIN_KEYS = set(('event protocol run_id pid seed iterations release machine clock '
                  'cpu_affinity online_cpus page_bytes file_bytes hugepage_policy '
                  'deadline_seconds selection stage_count defined_stage_count '
                  'warmups_per_stage measured_per_stage expected_samples '
                  'dmi_vendor dmi_product').split())
SAMPLE_KEYS = set(('event run_id sequence stage warmup sample_index operation_count '
                   'operation_unit duration_ns checksum expected_checksum correctness '
                   'errno reason self_rusage_delta children_rusage_delta').split())
SUMMARY_KEYS = set(('event run_id status selection aborted expected_samples '
                    'emitted_samples successful_samples completed_stages '
                    'warmups_per_stage measured_per_stage shutdown_required').split())
USAGE_KEYS = set(('user_ns system_ns minor_faults major_faults input_blocks output_blocks '
                  'voluntary_switches involuntary_switches maxrss_before_kib '
                  'maxrss_after_kib').split())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def selected_phases(selection='all'):
    require(selection == 'all' or selection in PHASES, 'invalid phase selection')
    return PHASES if selection == 'all' else (selection,)


def validate_parameters(*, seed, iterations, selection, run_id, expected_release):
    selected_phases(selection)
    require(type(seed) is int and 0 <= seed <= 0xffffffff, 'invalid uint32 seed')
    require(type(iterations) is int and 64 <= iterations <= 8192, 'invalid iteration budget')
    require(isinstance(run_id, str) and re.fullmatch(r'[0-9a-f]{24}', run_id), 'invalid run id')
    require(isinstance(expected_release, str) and
            re.fullmatch(r'[A-Za-z0-9._+-]{1,64}', expected_release), 'invalid release')


def mix64(value):
    value &= MASK
    value ^= value >> 30
    value = value * 0xbf58476d1ce4e5b9 & MASK
    value ^= value >> 27
    value = value * 0x94d049bb133111eb & MASK
    return value ^ (value >> 31)


def expected_checksums(seed=20261106, iterations=1024, selection='all'):
    """Independent Python evaluation of the public uint64 workload contract."""
    validate_parameters(seed=seed, iterations=iterations, selection=selection,
                        run_id='0' * 24, expected_release='6.18.60')
    def request(channel, index):
        return mix64((seed << 32) ^ index ^ channel)
    def reply(value, rotation, constant):
        return (((value << rotation) | (value >> (64 - rotation))) & MASK) ^ constant
    def fold(value, word):
        return ((value ^ word) * 0x100000001b3) & MASK
    result = {}
    for phase in selected_phases(selection):
        value = 0xcbf29ce484222325
        for index in range(iterations):
            if phase == 'syscall_process_pipe':
                value = fold(value, reply(request(0x504950455f524551, index),
                                          17, 0x9e3779b97f4a7c15))
            elif phase == 'anonymous_memory':
                value = fold(value, request(0x504147455f544147, index) & 0xffff)
            elif phase == 'tmpfs_files':
                first = request(0x46494c455f544147, index)
                value = fold(fold(value, first), first ^ 0xd6e8feb86659fd93)
            else:
                value = fold(value, reply(request(0x554e49585f524551, index),
                                          23, 0xd6e8feb86659fd93))
                value = fold(value, reply(request(0x5443505f52455131, index),
                                          31, 0xa0761d6478bd642f))
        if phase == 'anonymous_memory':
            for index in range(iterations):
                value = fold(value, (request(0x504147455f544147, index) & 0xffff) ^ 0xa55a)
        result[phase] = f'{value:016x}'
    return result


def parse_config(text):
    result = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            key, value = line[2:-11], 'n'
        else:
            continue
        require(key not in result, 'duplicate config symbol: ' + key)
        result[key] = value
    return result


def expected_hugepage_policy(config_text, selection):
    if 'anonymous_memory' not in selected_phases(selection):
        return 'not_selected'
    return ('madvise_nohugepage' if parse_config(config_text).get('CONFIG_TRANSPARENT_HUGEPAGE') == 'y'
            else 'kernel_not_exposed')


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError('non-finite JSON constant: ' + value)


def _receipt_ok(receipt):
    if type(receipt) is not dict or 'interruption' in receipt or 'spawn_error' in receipt:
        return False
    if (type(receipt.get('exit_code')) is not int or receipt['exit_code'] != 0 or
            receipt.get('timed_out') is not False or receipt.get('cancelled', False) is not False or
            receipt.get('incomplete_process_group', False) is not False):
        return False
    group, cleanup = receipt.get('process_group'), receipt.get('process_group_cleanup')
    if type(group) is not int or group <= 1 or type(cleanup) is not dict:
        return False
    return (type(cleanup.get('group')) is int and cleanup['group'] == group and
            cleanup.get('scope') == 'owned_linux_process_group' and
            cleanup.get('drained') is True and
            all(type(cleanup.get(key)) is list and not cleanup[key]
                for key in ('signals', 'live_members_after', 'errors')) and
            type(cleanup.get('elapsed_ns')) is int and cleanup['elapsed_ns'] >= 0)


def _bind_text(text, identity, label):
    require(type(text) is str and type(identity) is dict, label + ' text/identity absent')
    raw = text.encode('utf-8')
    require(type(identity.get('bytes')) is int and identity['bytes'] == len(raw),
            label + ' byte count mismatch; preserve raw newlines')
    require(identity.get('sha256') == hashlib.sha256(raw).hexdigest(),
            label + ' hash mismatch; do not admit edited/excerpted logs')


def parse_serial(text, *, run_id, seed, iterations, selection, expected_release,
                 config_text, command_receipt, expected_argv, stderr_text=''):
    """Return a structured PASS/FAIL verdict, retaining decoded raw samples.

    text/stderr_text must be UTF-8-decoded raw bytes, with no universal-newline
    conversion or excerpting.  expected_argv must have been frozen before the
    command.  Full input-file binding is performed by run_guest(), not inferred
    from a fabricated parser fixture.
    """
    verdict = {'schema': 'hepta.hia.linux.benchmark-trace-verdict.v1',
               'scope': 'trace_admission_against_supplied_command_receipt',
               'status': 'FAIL', 'errors': [], 'records': [], 'samples': []}
    try:
        validate_parameters(seed=seed, iterations=iterations, selection=selection,
                            run_id=run_id, expected_release=expected_release)
        require(_receipt_ok(command_receipt), 'command/group outcome is not admissible')
        require(type(expected_argv) in (list, tuple) and expected_argv and
                all(type(item) is str for item in expected_argv), 'expected argv absent')
        require(command_receipt.get('argv') == list(expected_argv), 'command argv changed')
        require(len(text.encode('utf-8')) <= 2 * 1024 * 1024, 'oversized serial log')
        _bind_text(text, command_receipt.get('stdout'), 'stdout')
        _bind_text(stderr_text, command_receipt.get('stderr'), 'stderr')
        lines, locations = text.splitlines(), []
        for index, line in enumerate(lines):
            if line.startswith('HIA_LINUX_BENCH') and not line.startswith(PREFIX):
                raise ValueError('malformed benchmark prefix')
            if line.startswith(PREFIX):
                row = json.loads(line[len(PREFIX):], parse_constant=_invalid_constant,
                                 object_pairs_hook=_strict_object)
                require(type(row) is dict, 'record is not an object')
                verdict['records'].append(row)
                locations.append(index)
        records = verdict['records']
        chosen, expected = selected_phases(selection), expected_checksums(seed, iterations, selection)
        expected_count = len(chosen) * (WARMUPS + MEASURED)
        require(len(records) == expected_count + 2, 'record count differs from fixed schedule')
        begin, summary, samples = records[0], records[-1], records[1:-1]
        verdict['samples'] = samples
        require(set(begin) == BEGIN_KEYS and begin['event'] == 'begin', 'begin shape/order mismatch')
        values = {'protocol': PROTOCOL, 'run_id': run_id, 'pid': 1, 'seed': seed,
                  'iterations': iterations, 'release': expected_release, 'machine': 'x86_64',
                  'clock': 'CLOCK_MONOTONIC_RAW', 'cpu_affinity': [0], 'online_cpus': 2,
                  'page_bytes': 4096, 'file_bytes': 4096,
                  'hugepage_policy': expected_hugepage_policy(config_text, selection),
                  'deadline_seconds': DEADLINE, 'selection': selection, 'stage_count': len(chosen),
                  'defined_stage_count': 4, 'warmups_per_stage': WARMUPS,
                  'measured_per_stage': MEASURED, 'expected_samples': expected_count}
        for key, value in values.items():
            require(begin[key] == value and type(begin[key]) is type(value), 'begin mismatch: ' + key)
        require(all(type(item) is int for item in begin['cpu_affinity']), 'affinity bool/integer confusion')
        require(all(type(begin[key]) is str and len(begin[key]) <= 255
                    for key in ('dmi_vendor', 'dmi_product')), 'DMI string shape mismatch')
        require(any(marker in (begin['dmi_vendor'] + ' ' + begin['dmi_product']).lower()
                    for marker in ('qemu', 'bochs')), 'QEMU/Bochs DMI missing')
        for index, row in enumerate(samples):
            require(set(row) == SAMPLE_KEYS, 'sample field set mismatch')
            phase, local = chosen[index // 7], index % 7
            warmup = local < WARMUPS
            values = {'event': 'sample', 'run_id': run_id, 'sequence': index, 'stage': phase,
                      'warmup': warmup, 'sample_index': local if warmup else local - WARMUPS,
                      'operation_count': iterations * (2 if phase == 'unix_tcp' else 1),
                      'operation_unit': UNITS[phase], 'checksum': expected[phase],
                      'expected_checksum': expected[phase], 'correctness': True,
                      'errno': 0, 'reason': 'ok'}
            for key, value in values.items():
                require(row[key] == value and type(row[key]) is type(value),
                        'sample mismatch at ' + str(index) + ': ' + key)
            require(type(row['duration_ns']) is int and 0 < row['duration_ns'] <= DEADLINE * 10**9,
                    'invalid/non-measured RAW duration')
            for key in ('self_rusage_delta', 'children_rusage_delta'):
                usage = row[key]
                require(type(usage) is dict and set(usage) == USAGE_KEYS, 'rusage field set mismatch')
                require(all(type(value) is int and 0 <= value < 2**63 for value in usage.values()),
                        'invalid/nonmonotonic rusage counters')
                require(usage['maxrss_after_kib'] >= usage['maxrss_before_kib'], 'max RSS regressed')
        require(set(summary) == SUMMARY_KEYS, 'summary shape mismatch')
        values = {'event': 'summary', 'run_id': run_id, 'status': 'PASS', 'selection': selection,
                  'aborted': False, 'expected_samples': expected_count,
                  'emitted_samples': expected_count, 'successful_samples': expected_count,
                  'completed_stages': len(chosen), 'warmups_per_stage': WARMUPS,
                  'measured_per_stage': MEASURED, 'shutdown_required': True}
        for key, value in values.items():
            require(summary[key] == value and type(summary[key]) is type(value),
                    'summary mismatch: ' + key)
        require(any(index > locations[-1] and 'reboot: Power down' in line
                    for index, line in enumerate(lines)), 'powerdown missing after summary')
        require('Kernel panic' not in text, 'kernel panic observed')
        verdict.update(status='PASS', begin=begin, summary=summary,
                       independent_expected_checksums=expected, kernel_powerdown_observed=True)
        verdict['measured_samples'] = {
            phase: [row for row in samples if row['stage'] == phase and not row['warmup']]
            for phase in chosen}
        verdict['within_boot_median_ns'] = {
            phase: statistics.median(row['duration_ns'] for row in rows)
            for phase, rows in verdict['measured_samples'].items()}
    except (ValueError, KeyError, TypeError, IndexError, OverflowError) as error:
        verdict['errors'].append(str(error))
    return verdict


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(path):
    path = Path(path).resolve()
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def tree_identity(path):
    """Bounded, explicitly selected QEMU dependency tree; no full-disk search."""
    root = Path(path).resolve()
    require(root.is_dir(), 'dependency directory missing: ' + str(root))
    rows = []
    for base, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            item = Path(base) / name
            relative = item.relative_to(root).as_posix()
            if item.is_symlink():
                row = {'path': relative, 'symlink': os.readlink(item)}
                if item.is_file():
                    row['resolved_file'] = identity(item)
                rows.append(row)
            elif item.is_file():
                rows.append({'path': relative, **{k: v for k, v in identity(item).items() if k != 'path'}})
    rows.sort(key=lambda row: row['path'])
    body = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
    return {'path': str(root), 'entries': rows, 'inventory_sha256': hashlib.sha256(body).hexdigest()}


def _baseline():
    path = Path(__file__).with_name('qualify_hia_linux_baseline.py')
    spec = importlib.util.spec_from_file_location('_benchmark_pinned_baseline', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module, identity(path)


def qemu_argv(*, qemu, qemu_data, bios, kernel, initramfs, profile, run_id,
              expected_release, seed, iterations, selection):
    require(profile in PROFILES, 'unsupported QEMU qualification profile')
    validate_parameters(seed=seed, iterations=iterations, selection=selection,
                        run_id=run_id, expected_release=expected_release)
    cfg = PROFILES[profile]
    cmdline = (f'console=ttyS0,115200 rdinit=/init panic=-1 nokaslr hia_bench=1 '
               f'hia_run_id={run_id} hia_expected_release={expected_release} '
               f'hia_seed={seed} hia_iterations={iterations} hia_phase={selection}')
    return [str(qemu), '-machine', 'pc-i440fx-8.2', '-accel', cfg['accel'],
            '-cpu', cfg['cpu'], '-smp', '2', '-m', '1024', '-nodefaults',
            '-no-user-config', '-display', 'none', '-monitor', 'none',
            '-serial', 'stdio', '-nic', 'none', '-no-reboot', '-L', str(qemu_data),
            '-bios', str(bios), '-kernel', str(kernel), '-initrd', str(initramfs),
            '-append', cmdline]


def normalize_host_cpus(requested, allowed):
    allowed = tuple(sorted(allowed))
    require(allowed and all(type(cpu) is int and cpu >= 0 for cpu in allowed),
            'allowed host CPU set is invalid')
    if requested is None:
        return None, allowed
    require(type(requested) in (tuple, list) and requested and
            all(type(cpu) is int and cpu >= 0 for cpu in requested),
            'host_cpus must be a nonempty integer tuple/list')
    require(len(set(requested)) == len(requested), 'duplicate requested host CPU')
    require(set(requested).issubset(allowed), 'requested host CPU outside current allowed set')
    return tuple(sorted(requested)), allowed


def run_guest(*, kernel, kernel_sha256, config, config_sha256, guest_build_receipt,
              qemu, qemu_data, qemu_modules, bios, output, collector_source_commit,
              expected_release='6.18.60', seed=20261106, iterations=1024,
              selection='all', profile='tcg', run_id=None, timeout=240, host_cpus=None):
    """Run exactly one new, bounded VM collector qualification; never run its ELF on host."""
    run_id = run_id or secrets.token_hex(12)
    requested_cpus, allowed_cpus = normalize_host_cpus(host_cpus, os.sched_getaffinity(0))
    validate_parameters(seed=seed, iterations=iterations, selection=selection,
                        run_id=run_id, expected_release=expected_release)
    require(profile in PROFILES and type(timeout) is int and 181 <= timeout <= 600,
            'unsupported profile/outer deadline')
    require(re.fullmatch(r'[0-9a-f]{40}', collector_source_commit), 'exact collector source commit required')
    for digest in (kernel_sha256, config_sha256):
        require(re.fullmatch(r'[0-9a-f]{64}', digest), 'precommitted kernel/config SHA required')
    kernel, config, receipt_path = map(lambda value: Path(value).resolve(),
                                       (kernel, config, guest_build_receipt))
    output = Path(output).resolve()
    static = json.loads(receipt_path.read_bytes())
    require(static.get('status') == 'PASS' and static.get('source_unchanged') is True
            and static.get('guest_executed_on_host') is False, 'static guest build receipt rejected')
    require(re.fullmatch(r'[0-9a-f]{40}', static.get('source_commit', '')), 'guest source commit missing')
    guest = Path(static['guest_binary']['path']).resolve()
    require(static.get('files') and any(row.get('repository_path', '').endswith('/guest_bench.c')
                                      for row in static['files']), 'guest source binding absent')
    protocol_files = [row for row in static['files'] if row.get('repository_path', '').endswith('/PROTOCOL.json')]
    require(len(protocol_files) == 1, 'guest protocol binding missing/ambiguous')
    protocol = json.loads(Path(protocol_files[0]['path']).read_bytes())
    require(protocol.get('schema') == 'hepta.hia.linux.system-benchmark.protocol.v1',
            'guest protocol version mismatch')
    for protected in (kernel, config, guest, receipt_path, Path(__file__).resolve(),
                      Path(qemu_data).resolve(), Path(qemu_modules).resolve()):
        require(not output.is_relative_to(protected) and not protected.is_relative_to(output),
                'output overlaps immutable input')
    output.mkdir(parents=True, exist_ok=False)
    owner = {'schema': 'hepta.hia.benchmark-owner.v1', 'active': True, 'pid': os.getpid(),
             'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'start_ticks': int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]),
             'profile': profile, 'output': str(output), 'source_commit': collector_source_commit}
    (output / 'OWNER.json').write_text(json.dumps(owner, sort_keys=True, indent=2) + '\n')
    result = {'schema': 'hepta.hia.linux.system-benchmark-run.v1', 'status': 'FAIL',
              'scope': 'one_qualified_guest_run_not_cross_image_comparison',
              'guest_executed_on_host': False, 'cross_image_advantage_claim': False,
              'profile': profile, 'selection': selection, 'seed': seed, 'iterations': iterations,
              'run_id': run_id, 'expected_release': expected_release,
              'collector_source_commit': collector_source_commit,
              'collector_source': identity(__file__), 'guest_source_commit': static['source_commit'],
              'static_build_receipt': identity(receipt_path), 'started_unix_ns': time.time_ns()}
    runner = None
    try:
        inputs = [identity(kernel), identity(config), static['guest_binary'], *static['files'],
                  static['compiler'], static['linker']]
        require(inputs[0]['sha256'] == kernel_sha256 and inputs[1]['sha256'] == config_sha256,
                'kernel/config differs from precommitted input')
        for row in inputs:
            require(identity(row['path'])['sha256'] == row['sha256'], 'input hash mismatch: ' + row['path'])
        result['inputs'] = inputs
        result['qemu'] = identity(qemu)
        result['bios'] = identity(bios)
        result['qemu_data'] = tree_identity(qemu_data)
        result['qemu_modules'] = tree_identity(qemu_modules)
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
                       'PYTHONDONTWRITEBYTECODE': '1', 'QEMU_MODULE_DIR': str(Path(qemu_modules).resolve())}
        result['environment'] = environment
        baseline, helper_identity = _baseline()
        result['execution_helper'] = helper_identity
        initramfs = output / 'initramfs.cpio.gz'
        baseline.create_initramfs(guest, initramfs)
        result['initramfs'] = identity(initramfs)
        command = qemu_argv(qemu=Path(qemu).resolve(), qemu_data=Path(qemu_data).resolve(),
                            bios=Path(bios).resolve(), kernel=kernel, initramfs=initramfs,
                            profile=profile, run_id=run_id, expected_release=expected_release,
                            seed=seed, iterations=iterations, selection=selection)
        result['qemu_argv'] = list(command)
        result['host_affinity'] = {
            'launcher_allowed_cpus': list(allowed_cpus),
            'requested_cpus': list(requested_cpus) if requested_cpus is not None else None,
            'effective_inherited_cpus': list(requested_cpus or allowed_cpus),
            'enforcement': 'taskset before QEMU exec' if requested_cpus else 'inherit launcher affinity',
            'per_thread_live_sampling_claim': False}
        if requested_cpus is not None:
            taskset = shutil.which('taskset', path=environment['PATH'])
            require(taskset is not None, 'taskset missing for requested host affinity')
            result['host_affinity_program'] = identity(taskset)
            command = [taskset, '--cpu-list', ','.join(map(str, requested_cpus)), *command]
        manifest = {'schema': 'hepta.hia.benchmark-preexecution-manifest.v1',
                    'run_id': run_id, 'profile': profile, 'seed': seed, 'iterations': iterations,
                    'selection': selection, 'expected_release': expected_release,
                    'kernel': inputs[0], 'config': inputs[1], 'guest': static['guest_binary'],
                    'guest_source_commit': static['source_commit'],
                    'collector_source_commit': collector_source_commit,
                    'collector_source': result['collector_source'], 'protocol': protocol_files[0],
                    'initramfs': result['initramfs'], 'qemu': result['qemu'], 'bios': result['bios'],
                    'qemu_data_inventory_sha256': result['qemu_data']['inventory_sha256'],
                    'qemu_modules_inventory_sha256': result['qemu_modules']['inventory_sha256'],
                    'argv': command, 'qemu_argv': result['qemu_argv'],
                    'host_affinity': result['host_affinity'],
                    'host_affinity_program': result.get('host_affinity_program'),
                    'timeout_seconds': timeout, 'environment': environment}
        with (output / 'PREEXECUTION.json').open('x') as stream:
            json.dump(manifest, stream, sort_keys=True, indent=2); stream.write('\n')
        result['preexecution_manifest'] = identity(output / 'PREEXECUTION.json')
        runner = baseline.CommandRunner(output, environment)
        receipt = runner.run('boot-system-benchmark-' + profile, command, timeout=timeout, check=False)
        result['command_receipt'] = receipt
        stdout_path, stderr_path = Path(receipt['stdout']['path']), Path(receipt['stderr']['path'])
        require(stdout_path.stat().st_size <= 2 * 1024 * 1024 and stderr_path.stat().st_size <= 1024 * 1024,
                'oversized process logs')
        text = stdout_path.read_bytes().decode('utf-8', errors='strict')
        stderr = stderr_path.read_bytes().decode('utf-8', errors='strict')
        verdict = parse_serial(text, run_id=run_id, seed=seed, iterations=iterations,
                               selection=selection, expected_release=expected_release,
                               config_text=config.read_text(), command_receipt=receipt,
                               expected_argv=command, stderr_text=stderr)
        result['verdict'] = verdict
        with (output / 'TRACE.json').open('x') as stream:
            json.dump(verdict, stream, sort_keys=True, indent=2); stream.write('\n')
        result['trace'] = identity(output / 'TRACE.json')
        result['inputs_unchanged'] = all(identity(row['path'])['sha256'] == row['sha256'] for row in inputs)
        require(result['inputs_unchanged'], 'immutable input changed during guest')
        require(identity(qemu) == result['qemu'] and identity(bios) == result['bios'], 'QEMU/BIOS changed')
        if 'host_affinity_program' in result:
            require(identity(result['host_affinity_program']['path']) == result['host_affinity_program'],
                    'taskset changed during guest')
        require(tree_identity(qemu_data) == result['qemu_data'], 'QEMU data changed')
        require(tree_identity(qemu_modules) == result['qemu_modules'], 'QEMU modules changed')
        require(identity(__file__) == result['collector_source'] and
                identity(helper_identity['path']) == helper_identity, 'execution source changed')
        require(identity(output / 'PREEXECUTION.json') == result['preexecution_manifest'],
                'preexecution binding changed')
        require(verdict['status'] == 'PASS', 'guest trace rejected: ' + '; '.join(verdict['errors']))
        result['status'] = 'PASS'
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        result['commands'] = runner.records if runner else []
        result['completed_unix_ns'] = time.time_ns()
        with (output / 'RESULT.json').open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2); stream.write('\n')
        owner.update(active=False, status=result['status'])
        (output / 'OWNER.json').write_text(json.dumps(owner, sort_keys=True, indent=2) + '\n')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('kernel', 'config', 'guest-build-receipt', 'qemu', 'qemu-data',
                   'qemu-modules', 'bios', 'output'):
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--kernel-sha256', required=True)
    parser.add_argument('--config-sha256', required=True)
    parser.add_argument('--collector-source-commit', required=True)
    parser.add_argument('--expected-release', default='6.18.60')
    parser.add_argument('--seed', type=int, default=20261106)
    parser.add_argument('--iterations', type=int, default=1024)
    parser.add_argument('--selection', choices=('all', *PHASES), default='all')
    parser.add_argument('--profile', choices=tuple(PROFILES), default='tcg')
    parser.add_argument('--run-id')
    parser.add_argument('--timeout', type=int, default=240)
    def cpu_list(value):
        require(re.fullmatch(r'[0-9]+(?:,[0-9]+)*', value), 'invalid host CPU list')
        return tuple(map(int, value.split(',')))
    parser.add_argument('--host-cpus', type=cpu_list)
    args = parser.parse_args(argv)
    result = run_guest(**vars(args))
    print(json.dumps({'result': str(args.output / 'RESULT.json'), 'status': result['status'],
                      'profile': result['profile'], 'selection': result['selection'],
                      'error': result.get('error')}), flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
