#!/usr/bin/python3
"""Validate one explicitly frozen remote head with external offline Cargo state.

The metadata/build preflights are distinct from the two formal validation gates.
No invocation is made until this file is explicitly executed with the final SHA.
"""
import argparse
import collections
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

DEFAULT_ROOT = Path('/workspace/scratch/4bc91e0ee48c/hepta-followup-integration')
CARGO_HOME = Path('/tmp/hepta-cargo-home')
CARGO_TARGET = Path('/tmp/hepta-p2-independent-v2-v7-target')
RETAINED_VM = Path('/tmp/hepta-p2-retained-vm-dfdf944f/hia-core-shadow')
RETAINED_RECEIPT = RETAINED_VM.with_name('copy-receipt.json')
RETAINED_SHA = 'a792687bc3248b010c35633cc6d5295903349cd2bd03f007a3ed36bbaa4e6e0c'
RETAINED_BYTES = 17332568
TOOLS = {
    'python': '/usr/bin/python3',
    'cargo': '/tmp/hepta-toolchains/rust-1.90.0/bin/cargo',
    'rustc': '/tmp/hepta-toolchains/rust-1.90.0/bin/rustc',
    'rustdoc': '/tmp/hepta-toolchains/rust-1.90.0/bin/rustdoc',
    'clang': '/usr/lib/llvm-20/bin/clang', 'clangxx': '/usr/lib/llvm-20/bin/clang++',
    'gcc': '/usr/bin/gcc', 'gxx': '/usr/bin/g++', 'cc': '/usr/bin/cc', 'cxx': '/usr/bin/c++',
    'linker': '/usr/lib/llvm-20/bin/ld.lld',
    'llvm_readobj': '/usr/lib/llvm-20/bin/llvm-readobj',
    'llvm_objdump': '/usr/lib/llvm-20/bin/llvm-objdump',
    'lean': '/tmp/hepta-toolchains/lean-4.19.0/bin/lean',
    'qemu_aarch64': '/tmp/hepta-qemu-reviewed-20261027/qemu-aarch64-static',
    'qemu_aarch64_static': '/usr/bin/qemu-aarch64-static',
    'qemu_riscv64_static': '/usr/bin/qemu-riscv64-static',
    'qemu_system_arm': '/usr/bin/qemu-system-arm',
    'gdb': '/usr/bin/gdb', 'nm': '/usr/bin/nm', 'ar': '/usr/bin/ar',
    'objdump': '/usr/bin/objdump', 'readelf': '/usr/bin/readelf',
    'libclang': '/usr/lib/llvm-20/lib/libclang-20.so.1',
}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def tool_identity(versions):
    result = {}
    for name, value in TOOLS.items():
        path = Path(value)
        row = {'path': value}
        try:
            resolved = path.resolve(strict=True)
            row.update(resolved_path=str(resolved), bytes=resolved.stat().st_size, sha256=sha(resolved))
            if versions and name != 'libclang':
                start = time.monotonic()
                command = [value, '--version']
                probe = subprocess.run(command, capture_output=True, text=True, timeout=30)
                row.update(version_argv=command, version_returncode=probe.returncode,
                           version_stdout=probe.stdout, version_stderr=probe.stderr,
                           version_duration_seconds=time.monotonic() - start)
                if probe.returncode:
                    row['error'] = 'version probe failed'
        except (OSError, subprocess.TimeoutExpired) as exc:
            row['error'] = str(exc)
        result[name] = row
    return result


def same_tools(before, after):
    return (set(before) == set(after)
            and all('error' not in row and 'error' not in after[name]
                    and all(row.get(key) == after[name].get(key)
                            for key in ('path', 'resolved_path', 'bytes', 'sha256'))
                    for name, row in before.items()))


def process(pid):
    path = Path('/proc') / str(pid)
    try:
        raw = (path / 'stat').read_text()
        fields = raw[raw.rfind(')') + 2:].split()
        cmdline = (path / 'cmdline').read_bytes()
        return {'pid': pid, 'ppid': int(fields[1]), 'pgid': int(fields[2]), 'sid': int(fields[3]),
                'state': fields[0], 'start_time_ticks': int(fields[19]),
                'argv0': cmdline.split(b'\0')[0].decode(errors='replace'),
                'cmdline_sha256': hashlib.sha256(cmdline).hexdigest()}
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None


def process_tree(root_pid):
    rows = {}
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            row = process(int(path.name))
            if row is not None:
                rows[row['pid']] = row
    selected = {root_pid}
    while True:
        children = {pid for pid, row in rows.items() if row['ppid'] in selected}
        if children.issubset(selected):
            return {pid: rows[pid] for pid in selected if pid in rows}
        selected |= children


def stop_owned_tree(child, original, log_path):
    """Stop only PID/start-time pinned descendants on a declared hard timeout."""
    events, known = [], process_tree(child.pid)
    errors = []
    root = process(child.pid)
    if root is None:
        child.poll()
        return {'events': events, 'remaining': [], 'errors': errors}
    if original is None or root['start_time_ticks'] != original['start_time_ticks'] or root['ppid'] != os.getpid():
        return {'events': events, 'remaining': [root],
                'errors': ['Process identity differs; refusing unrelated signals']}
    try:
        stream = log_path.open('x', buffering=1)
    except OSError as exc:
        stream = None
        errors.append('Signal log could not be opened: ' + str(exc))

    def send(row, sig):
        current = process(row['pid'])
        event = {'utc': utc(), 'pid': row['pid'], 'start_time_ticks': row['start_time_ticks'],
                 'signal': sig.name, 'signal_number': int(sig), 'sent': False}
        if current is not None and current['state'] != 'Z' and current['start_time_ticks'] == row['start_time_ticks']:
            try:
                fd = os.pidfd_open(row['pid'], 0)
                try:
                    checked = process(row['pid'])
                    if checked is not None and checked['start_time_ticks'] == row['start_time_ticks']:
                        signal.pidfd_send_signal(fd, sig)
                        event['sent'] = True
                finally:
                    os.close(fd)
            except ProcessLookupError:
                event['not_sent_reason'] = 'The pinned process exited during signalling'
            except OSError as exc:
                event['signal_error'] = str(exc)
                errors.append('Signal error for PID ' + str(row['pid']) + ': ' + str(exc))
        events.append(event)
        if stream is not None:
            try:
                stream.write(json.dumps(event, sort_keys=True) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            except OSError as exc:
                errors.append('Signal log write failed: ' + str(exc))
        return event['sent']

    try:
        root_stopped = send(root, signal.SIGSTOP)
        stopped = {(root['pid'], root['start_time_ticks'])}
        for _ in range(20 if root_stopped else 0):
            rows = process_tree(child.pid)
            new = [row for row in rows.values() if row['state'] != 'Z'
                   and (row['pid'], row['start_time_ticks']) not in stopped]
            if not new:
                break
            for row in new:
                known[row['pid']] = row
                if send(row, signal.SIGSTOP):
                    stopped.add((row['pid'], row['start_time_ticks']))
        known[root['pid']] = root
        for pid, row in sorted(known.items(), reverse=True):
            if pid != child.pid:
                send(row, signal.SIGKILL)
        send(root, signal.SIGKILL)
    finally:
        if stream is not None:
            stream.close()
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        errors.append('Pinned child did not terminate within the cleanup budget')
    remaining = []
    for row in known.values():
        current = process(row['pid'])
        if current is not None and current['state'] != 'Z' and current['start_time_ticks'] == row['start_time_ticks']:
            remaining.append(current)
    return {'events': events, 'remaining': remaining, 'errors': errors}


def canonical_python_tests(raw):
    ids = []
    for line in raw.splitlines():
        found = re.match(r'^(test[^\s(]+) \(([^)\r\n]+)\)', line)
        if found:
            method, identifier = found.groups()
            ids.append(identifier if identifier.endswith('.' + method) else identifier + '.' + method)
    counts = collections.Counter(ids)
    return {'test_ids': ids, 'observed_test_starts': len(ids), 'unique_test_ids': len(counts),
            'duplicate_test_ids': {item: count for item, count in counts.items() if count > 1},
            'normalization': 'Keep the parenthesized unittest ID when it already ends in the display method; append the method only otherwise.'}


def cargo_test_outcome(stdout, code):
    summaries = []
    last_footer_end = None
    pattern = r'(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9]+(?:\.[0-9]+)?s)\r?$'
    for match in re.finditer(pattern, stdout):
        last_footer_end = match.end()
        status, passed, failed, ignored, measured, filtered, duration = match.groups()
        summaries.append({'status': status, 'passed': int(passed), 'failed': int(failed),
                          'ignored': int(ignored), 'measured': int(measured),
                          'filtered_out': int(filtered), 'duration_display': duration})
    running = [int(item) for item in re.findall(r'(?m)^running (\d+) tests?\r?$', stdout)]
    accepted = (code == 0 and summaries and len(summaries) == len(running)
                and last_footer_end is not None and not stdout[last_footer_end:].strip()
                and sum(row['passed'] for row in summaries) > 0
                and all(row['status'] == 'ok' and row['failed'] == row['ignored'] == row['measured'] == row['filtered_out'] == 0
                        and count == row['passed'] for row, count in zip(summaries, running)))
    return {'passed': bool(accepted), 'summaries': summaries, 'running_counts': running,
            'total_passed': sum(row['passed'] for row in summaries),
            'total_ignored': sum(row['ignored'] for row in summaries)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--output-directory', required=True, type=Path)
    parser.add_argument('--source-root', type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.expected_commit):
        parser.error('expected-commit must be the full frozen SHA')
    root = args.source_root.resolve(strict=True)
    output = args.output_directory.absolute()
    if output.exists() or output.is_symlink() or output.resolve().is_relative_to(root):
        parser.error('output directory must be new and outside the source tree')
    cargo_home, cargo_target = CARGO_HOME.resolve(strict=True), CARGO_TARGET.resolve(strict=True)
    if any(path.is_relative_to(root) or not path.is_dir() for path in (cargo_home, cargo_target)):
        parser.error('the pre-existing Cargo home and target must be directories outside the source tree')
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        parser.error('Linux pidfd support is required for owned timeout cleanup')
    if (not RETAINED_VM.is_file() or RETAINED_VM.stat().st_size != RETAINED_BYTES
            or sha(RETAINED_VM) != RETAINED_SHA or not RETAINED_RECEIPT.is_file()):
        parser.error('the old actually executed P2 VM must remain byte-exactly retained before target reuse')
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    from tools.release_check import snapshot
    from tools.qualify_hia_unified import unittest_outcome

    def git(*argv):
        return subprocess.check_output(['git', '-C', str(root), *argv], text=True, timeout=30).strip()

    def source():
        result = {'git_commit': None, 'git_tree': None, 'git_status': None,
                  'official_snapshot': None, 'capture_errors': []}
        for name, argv in (('git_commit', ('rev-parse', 'HEAD')),
                           ('git_tree', ('rev-parse', 'HEAD^{tree}')),
                           ('git_status', ('status', '--porcelain'))):
            try:
                result[name] = git(*argv)
            except Exception as exc:
                result['capture_errors'].append({'field': name, 'type': type(exc).__name__, 'message': str(exc)})
        try:
            result['official_snapshot'] = snapshot()
        except Exception as exc:
            result['capture_errors'].append({'field': 'official_snapshot', 'type': type(exc).__name__, 'message': str(exc)})
        return result

    def same_source(before, after):
        return (not before['capture_errors'] and not after['capture_errors']
                and before['git_commit'] == after['git_commit'] == args.expected_commit
                and before['git_tree'] == after['git_tree']
                and before['official_snapshot'] == after['official_snapshot']
                and not before['git_status'] and not after['git_status'])

    frozen = source()
    if frozen['capture_errors'] or frozen['git_commit'] != args.expected_commit or frozen['git_status']:
        raise RuntimeError('Final remote HEAD/clean-source precondition failed; no output or command started')
    lock_path = cargo_target.with_name(cargo_target.name + '.final-validation.lock')
    lock = lock_path.open('a+')
    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    output.mkdir()
    (output / 'runner.py').write_bytes(Path(__file__).read_bytes())
    aliases = output / 'tool-bin'
    aliases.mkdir()
    (aliases / 'qemu-aarch64').symlink_to(TOOLS['qemu_aarch64'])
    controlled = {
        'PATH': os.pathsep.join([str(aliases), str(Path(TOOLS['cargo']).parent),
                  str(Path(TOOLS['clang']).parent), str(Path(TOOLS['lean']).parent), os.environ.get('PATH', '')]),
        'CARGO_HOME': str(cargo_home), 'CARGO_TARGET_DIR': str(cargo_target), 'CARGO_NET_OFFLINE': 'true',
        'CARGO': TOOLS['cargo'], 'RUSTC': TOOLS['rustc'], 'RUSTDOC': TOOLS['rustdoc'],
        'CLANG': TOOLS['clang'], 'CLANGXX': TOOLS['clangxx'], 'CC': TOOLS['gcc'], 'CXX': TOOLS['gxx'],
        'LEAN': TOOLS['lean'], 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
        'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1', 'HF_DATASETS_OFFLINE': '1',
    }
    env = dict(os.environ)
    env.update(controlled)
    before_tools = tool_identity(versions=True)
    manifest = root / 'rust/hia-core-shadow/Cargo.toml'
    cargo_base = [TOOLS['cargo']]
    stages = [
        ('cargo-metadata', 'preflight', cargo_base + ['metadata', '--locked', '--offline', '--no-deps', '--format-version', '1', '--manifest-path', str(manifest)], 60),
        ('cargo-build', 'preflight', cargo_base + ['build', '--locked', '--offline', '--manifest-path', str(manifest)], 240),
        ('unit-discovery', 'formal_validation', [TOOLS['python'], '-m', 'unittest', 'discover', '-s', 'tests', '-v'], 3600),
        ('cargo-test', 'formal_validation', cargo_base + ['test', '--locked', '--offline', '--manifest-path', str(manifest)], 240),
    ]
    launch = {'schema': 'hepta.final-integrated-validation-launch.v1', 'started_utc': utc(),
              'runner_pid': os.getpid(), 'runner_sha256': sha(Path(__file__)), 'cwd': str(root),
              'expected_commit': args.expected_commit, 'source_before': frozen, 'tools_before': before_tools,
              'sandbox_permissions': 'require_escalated', 'controlled_environment': controlled,
              'resolved_path_tools': {name: shutil.which(name, path=controlled['PATH'])
                  for name in ('cargo', 'rustc', 'rustdoc', 'clang', 'clang++', 'lean', 'qemu-aarch64', 'ld.lld')},
              'cargo_target_advisory_lock': str(lock_path),
              'cargo_target_reused_only_after_parent_confirmed_prior_P2_processes_completed': True,
              'retained_previous_P2_vm': {'path': str(RETAINED_VM), 'bytes': RETAINED_BYTES,
                  'sha256': sha(RETAINED_VM), 'receipt_path': str(RETAINED_RECEIPT), 'receipt_sha256': sha(RETAINED_RECEIPT)},
              'stages': [{'name': name, 'classification': classification, 'argv': argv, 'timeout_seconds': limit}
                         for name, classification, argv, limit in stages],
              'preflight_is_not_unit_validation': True, 'remote_ci_used': False,
              'native_migration_gates_repeated': False, 'performance_qualification_requested': False,
              'model_experiment_or_download_requested': False}
    write(output / 'plan.json', launch)
    reports, not_started = [], []

    def execute(stage):
        name, classification, argv, limit = stage
        dest = output / name
        dest.mkdir()
        start_source, start_tools = source(), tool_identity(versions=False)
        plan = {'schema': 'hepta.final-integrated-validation-stage.v1', 'stage': name,
                'classification': classification, 'runner_pid': os.getpid(), 'cwd': str(root),
                'argv': argv, 'timeout_seconds': limit, 'started_utc': utc(),
                'controlled_environment': controlled, 'source_before': start_source, 'tools_before': start_tools}
        write(dest / 'plan.json', plan)
        code, timed_out, error, termination, child_identity, child = None, False, None, None, None, None
        start = time.monotonic()
        with (dest / 'stdout.log').open('xb', buffering=0) as stdout, (dest / 'stderr.log').open('xb', buffering=0) as stderr:
            if not same_source(frozen, start_source) or not same_tools(before_tools, start_tools):
                error = 'Source or tool identity changed before this stage; command not started'
            else:
                try:
                    child = subprocess.Popen(argv, cwd=root, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
                    child_identity = process(child.pid)
                    write(dest / 'process.json', {'pid': child.pid, 'pgid': child.pid,
                          'runner_pid': os.getpid(), 'started_utc': utc(), 'identity': child_identity,
                          'argv': argv, 'timeout_seconds': limit, 'controlled_environment': controlled})
                    print(json.dumps({'stage': name, 'classification': classification, 'status': 'running',
                                      'runner_pid': os.getpid(), 'pid': child.pid, 'timeout_seconds': limit}), flush=True)
                    try:
                        code = child.wait(timeout=limit)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        termination = stop_owned_tree(child, child_identity, dest / 'timeout-signals.jsonl')
                        code = child.returncode
                except Exception as exc:
                    error = {'type': type(exc).__name__, 'message': str(exc)}
                    # A post-Popen bookkeeping error must not leave a live
                    # unit using the shared target while the next gate runs.
                    if child is not None:
                        if child.poll() is None:
                            try:
                                termination = stop_owned_tree(child, child_identity, dest / 'error-signals.jsonl')
                            except Exception as cleanup_exc:
                                termination = {'events': [], 'remaining': [process(child.pid)],
                                               'errors': [str(cleanup_exc)]}
                        code = child.poll()
        duration = time.monotonic() - start
        end_source, end_tools = source(), tool_identity(versions=False)
        report = {**plan, 'finished_utc': utc(), 'duration_seconds': duration,
                  'returncode': code, 'timed_out': timed_out, 'launch_error': error,
                  'unsafe_to_continue': bool(termination is not None and termination['remaining']),
                  'timeout_termination': termination, 'source_after': end_source,
                  'source_unchanged': same_source(start_source, end_source),
                  'tools_after': end_tools, 'tools_unchanged': same_tools(start_tools, end_tools),
                  'stdout': {'path': str(dest / 'stdout.log'), 'sha256': sha(dest / 'stdout.log'), 'bytes': (dest / 'stdout.log').stat().st_size},
                  'stderr': {'path': str(dest / 'stderr.log'), 'sha256': sha(dest / 'stderr.log'), 'bytes': (dest / 'stderr.log').stat().st_size}}
        accepted = code == 0
        if name == 'cargo-metadata':
            try:
                payload = json.loads((dest / 'stdout.log').read_bytes())
                actual_target = Path(payload['target_directory']).resolve()
                report['observed_cargo_target_directory'] = str(actual_target)
                report['cargo_target_outside_source'] = not actual_target.is_relative_to(root)
                accepted = accepted and actual_target == cargo_target and report['cargo_target_outside_source']
            except (ValueError, KeyError, TypeError) as exc:
                report['metadata_error'] = str(exc)
                accepted = False
        elif name == 'unit-discovery':
            raw = (dest / 'stderr.log').read_text(errors='replace')
            report['outcome'] = unittest_outcome(raw, code)
            report['canonical_tests'] = canonical_python_tests(raw)
            report['canonical_test_count_matches_footer'] = report['canonical_tests']['observed_test_starts'] == report['outcome']['tests_run']
            accepted = report['outcome']['passed']
        elif name == 'cargo-test':
            report['outcome'] = cargo_test_outcome((dest / 'stdout.log').read_text(errors='replace'), code)
            accepted = report['outcome']['passed']
        report['ok'] = bool(accepted and not timed_out and not error and report['source_unchanged']
                            and report['tools_unchanged'] and (termination is None or not termination['remaining']))
        write(dest / 'report.json', report)
        print(json.dumps({key: report[key] for key in ('stage', 'classification', 'returncode', 'timed_out',
              'duration_seconds', 'source_unchanged', 'tools_unchanged', 'ok')}, sort_keys=True), flush=True)
        return report

    preflight_failed = any('error' in row for row in before_tools.values())
    cleanup_blocked = False
    for stage in stages:
        if preflight_failed or cleanup_blocked:
            not_started.append({'stage': stage[0], 'classification': stage[1],
                                'reason': 'owned child cleanup incomplete' if cleanup_blocked else 'preflight failed; no command executed'})
            continue
        report = execute(stage)
        reports.append(report)
        if stage[1] == 'preflight' and not report['ok']:
            preflight_failed = True
        if report['unsafe_to_continue']:
            cleanup_blocked = True
    end_source, end_tools = source(), tool_identity(versions=False)
    formal = [row for row in reports if row['classification'] == 'formal_validation']
    summary = {'schema': 'hepta.final-integrated-validation-summary.v1', 'started_utc': launch['started_utc'],
               'finished_utc': utc(), 'git_commit': args.expected_commit, 'source_before': frozen,
               'source_after': end_source, 'source_unchanged': same_source(frozen, end_source),
               'tools_before': before_tools, 'tools_after': end_tools, 'tools_unchanged': same_tools(before_tools, end_tools),
               'controlled_environment': controlled, 'preflight_failed': preflight_failed,
               'owned_child_cleanup_blocked_further_execution': cleanup_blocked,
               'planned_formal_gate_count': 2, 'completed_formal_gate_count': len(formal),
               'not_started': not_started,
               'stages': [{'name': row['stage'], 'classification': row['classification'], 'ok': row['ok'],
                    'returncode': row['returncode'], 'duration_seconds': row['duration_seconds'],
                    'report_path': str(output / row['stage'] / 'report.json'),
                    'report_sha256': sha(output / row['stage'] / 'report.json')} for row in reports],
               'remote_ci_used': False, 'all_19_gates_requalified': False,
               'native_migration_gates_repeated': False, 'performance_requalified': False,
               'model_experiments_or_downloads_executed': False}
    summary['ok'] = bool(not preflight_failed and not cleanup_blocked and len(formal) == 2 and all(row['ok'] for row in formal)
                         and summary['source_unchanged'] and summary['tools_unchanged'])
    write(output / 'summary.json', summary)
    entries = []
    for path in sorted(output.rglob('*')):
        if path.is_dir() or path.name in ('manifest.json', 'driver.stdout.log', 'driver.stderr.log'):
            continue
        row = {'path': str(path.relative_to(output)), 'sha256': sha(path), 'bytes': path.stat().st_size}
        if path.is_symlink():
            row['symlink_target'] = os.readlink(path)
        entries.append(row)
    write(output / 'manifest.json', {'schema': 'hepta.final-integrated-validation-manifest.v1',
          'files': entries, 'excludes_self_and_still_open_driver_logs': True})
    print(json.dumps({'completed': True, 'ok': summary['ok'], 'summary': str(output / 'summary.json'),
                      'summary_sha256': sha(output / 'summary.json')}, sort_keys=True), flush=True)
    lock.close()
    return 0 if summary['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
