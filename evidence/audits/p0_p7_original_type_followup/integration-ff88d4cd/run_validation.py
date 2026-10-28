#!/usr/bin/python3
"""Append-only actual execution records for the frozen integration checkout."""
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/4bc91e0ee48c/hepta-followup-integration')
OUT = Path('/tmp/hepta-followup-integrated-ff88d4cd')
EXPECTED = 'ff88d4cd378435c745ce339107f38622a5cc91a6'
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from tools.release_check import snapshot
from tools.qualify_hia_unified import unittest_outcome


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True, timeout=30).strip()


def source():
    return {'git_commit': git('rev-parse', 'HEAD'), 'git_tree': git('rev-parse', 'HEAD^{tree}'),
            'git_status': git('status', '--porcelain'),
            'git_tracked_status': git('status', '--porcelain', '--untracked-files=no'),
            'official_snapshot': snapshot()}


def tool(path, versions=True, executable=True):
    resolved = str(Path(path).resolve(strict=True))
    row = {'path': str(path), 'resolved_path': resolved, 'sha256': digest(resolved),
           'bytes': Path(resolved).stat().st_size}
    if versions and executable:
        value = subprocess.run([str(path), '--version'], capture_output=True, text=True, timeout=30)
        row.update(version_argv=[str(path), '--version'], version_returncode=value.returncode,
                   version_stdout=value.stdout, version_stderr=value.stderr)
        if value.returncode:
            raise RuntimeError('tool identity version probe failed: ' + str(path))
    return row


TOOL_PATHS = {
    'python': '/usr/bin/python3',
    'clang': '/usr/lib/llvm-20/bin/clang',
    'clangxx': '/usr/lib/llvm-20/bin/clang++',
    'rustc': '/tmp/hepta-toolchains/rust-1.90.0/bin/rustc',
    'cargo': '/tmp/hepta-toolchains/rust-1.90.0/bin/cargo',
    'gcc': '/usr/bin/gcc', 'gxx': '/usr/bin/g++',
    'cc': '/usr/bin/cc', 'cxx': '/usr/bin/c++',
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


def tools_identity(versions=True):
    return {name: tool(path, versions=versions, executable=name != 'libclang')
            for name, path in TOOL_PATHS.items()}


def tools_same(before, after):
    return all(all(row[key] == after[name][key] for key in ('resolved_path', 'sha256', 'bytes'))
               for name, row in before.items())


def same_source(before, after):
    return (before['git_commit'] == after['git_commit'] == EXPECTED
            and before['git_tree'] == after['git_tree']
            and before['official_snapshot'] == after['official_snapshot']
            and not before['git_tracked_status'] and not after['git_tracked_status'])


def canonical_tests(stderr):
    rows = []
    for line in stderr.splitlines():
        match = re.match(r'^(test[^\s(]+) \(([^)\r\n]+)\)', line)
        if match is None:
            continue
        method, parenthesized = match.groups()
        identifier = parenthesized if parenthesized.endswith('.' + method) else parenthesized + '.' + method
        rows.append({'id': identifier, 'display_method': method, 'raw_line': line})
    counts = collections.Counter(row['id'] for row in rows)
    return {'normalization': 'Use parenthesized ID unchanged when it already ends in display method; otherwise append method once.',
            'test_ids': [row['id'] for row in rows], 'test_start_rows': rows,
            'observed_test_starts': len(rows), 'unique_test_ids': len(counts),
            'duplicate_test_ids': {name: count for name, count in counts.items() if count > 1}}


def run_stage(stage, env, frozen):
    name, argv, limit, relative_evidence = stage
    dest = OUT / name
    dest.mkdir()
    before, before_tools = source(), tools_identity()
    if not same_source(frozen, before):
        raise RuntimeError('Frozen source precondition changed before ' + name)
    plan = {'schema': 'hepta.integrated-followup-stage.v1', 'stage': name,
            'runner_pid': os.getpid(), 'cwd': str(ROOT), 'argv': argv,
            'timeout_seconds': limit, 'hard_timeout_action': 'SIGKILL process group',
            'started_utc': utc(), 'source_before': before, 'tools_before': before_tools}
    write(dest / 'plan.json', plan)
    start = time.monotonic()
    timed_out, launch_error, code = False, None, None
    with (dest / 'stdout.log').open('xb', buffering=0) as stdout, (dest / 'stderr.log').open('xb', buffering=0) as stderr:
        try:
            child = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
            write(dest / 'process.json', {'pid': child.pid, 'pgid': child.pid,
                                         'runner_pid': os.getpid(), 'started_utc': utc(),
                                         'argv': argv, 'timeout_seconds': limit})
            print(json.dumps({'stage': name, 'status': 'running', 'pid': child.pid,
                              'runner_pid': os.getpid(), 'timeout_seconds': limit}), flush=True)
            try:
                code = child.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = child.wait()
        except OSError as exc:
            launch_error = {'type': type(exc).__name__, 'message': str(exc)}
    duration = time.monotonic() - start
    after, after_tools = source(), tools_identity(versions=False)
    report = {**plan, 'finished_utc': utc(), 'duration_seconds': duration,
              'returncode': code, 'timed_out': timed_out, 'launch_error': launch_error,
              'source_after': after, 'source_unchanged': same_source(before, after),
              'tools_after': after_tools, 'tools_unchanged': tools_same(before_tools, after_tools),
              'stdout': {'path': str(dest / 'stdout.log'), 'sha256': digest(dest / 'stdout.log'),
                         'bytes': (dest / 'stdout.log').stat().st_size},
              'stderr': {'path': str(dest / 'stderr.log'), 'sha256': digest(dest / 'stderr.log'),
                         'bytes': (dest / 'stderr.log').stat().st_size}}
    if relative_evidence is None:
        stderr_text = (dest / 'stderr.log').read_text(errors='replace')
        report['outcome'] = unittest_outcome(stderr_text, code)
        report['canonical_tests'] = canonical_tests(stderr_text)
        report['canonical_test_count_matches_footer'] = report['canonical_tests']['observed_test_starts'] == report['outcome']['tests_run']
        gate_ok = report['outcome']['passed']
    else:
        evidence = OUT / relative_evidence
        gate_ok = False
        try:
            if not evidence.is_file() or evidence.is_symlink():
                raise ValueError('missing ordinary qualification receipt')
            payload = json.loads(evidence.read_bytes())
            report['evidence'] = {'path': str(evidence), 'sha256': digest(evidence),
                                  'ok': payload.get('ok'), 'status': payload.get('status'),
                                  'error': payload.get('error'), 'diagnostic': payload.get('diagnostic')}
            gate_ok = code == 0 and payload.get('ok') is True
        except (OSError, ValueError, AttributeError) as exc:
            report['evidence_error'] = {'type': type(exc).__name__, 'message': str(exc)}
    report['ok'] = (gate_ok and not timed_out and not launch_error
                    and report['source_unchanged'] and report['tools_unchanged'])
    write(dest / 'report.json', report)
    print(json.dumps({key: report[key] for key in ('stage', 'returncode', 'timed_out', 'duration_seconds',
                                                   'source_unchanged', 'tools_unchanged', 'ok')}, sort_keys=True), flush=True)
    return report


def main():
    os.chdir(ROOT)
    frozen = source()
    if frozen['git_commit'] != EXPECTED or frozen['git_status']:
        raise RuntimeError('Exact committed clean source precondition failed')
    bin_dir = OUT / 'tool-bin'
    bin_dir.mkdir()
    (bin_dir / 'qemu-aarch64').symlink_to(TOOL_PATHS['qemu_aarch64'])
    env = dict(os.environ)
    selected = {'PATH': os.pathsep.join([str(bin_dir), '/usr/lib/llvm-20/bin',
                    '/tmp/hepta-toolchains/rust-1.90.0/bin', '/tmp/hepta-toolchains/lean-4.19.0/bin', os.environ['PATH']]),
                'RUSTC': TOOL_PATHS['rustc'], 'CLANG': TOOL_PATHS['clang'], 'CLANGXX': TOOL_PATHS['clangxx'],
                'CC': TOOL_PATHS['gcc'], 'CXX': TOOL_PATHS['gxx'], 'LEAN': TOOL_PATHS['lean'],
                'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
                'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1', 'HF_DATASETS_OFFLINE': '1'}
    env.update(selected)
    stages = [
        ('unit-discovery', ['/usr/bin/python3', '-m', 'unittest', 'discover', '-s', 'tests', '-v'], 3600, None),
        ('hia-migration', ['/usr/bin/python3', 'tools/qualify_hia_migration.py', '--workdir', str(OUT / 'hia-migration/artifacts'),
                           '--clang', TOOL_PATHS['clang'], '--clangxx', TOOL_PATHS['clangxx'],
                           '--cc', TOOL_PATHS['gcc'], '--cxx', TOOL_PATHS['gxx']], 1800, 'hia-migration/artifacts/qualification.json'),
        ('c-resource-matrix', ['/usr/bin/python3', 'tools/qualify_c_resource_matrix.py', '--workdir', str(OUT / 'c-resource-matrix/artifacts'),
                               '--clang', TOOL_PATHS['clang'], '--rustc', TOOL_PATHS['rustc']], 1800, 'c-resource-matrix/artifacts/qualification.json'),
    ]
    launch = {'schema': 'hepta.integrated-followup-launch.v1', 'started_utc': utc(),
              'runner_pid': os.getpid(), 'runner_sha256': digest(__file__), 'source_before': frozen,
              'sandbox_permissions': 'require_escalated',
              'tools_before': tools_identity(), 'environment': selected,
              'stages': [{'name': name, 'argv': argv, 'timeout_seconds': limit} for name, argv, limit, _ in stages],
              'remote_ci_used': False, 'model_download_requested': False,
              'full_release_or_all_19_gates_requested': False, 'performance_qualification_requested': False,
              'acceptance_policy': 'Independent exact-source stages; no skips accepted for unit discovery; failures retained.'}
    write(OUT / 'plan.json', launch)
    reports = [run_stage(stage, env, frozen) for stage in stages]
    after, after_tools = source(), tools_identity(versions=False)
    summary = {'schema': 'hepta.integrated-followup-summary.v1', 'started_utc': launch['started_utc'],
               'finished_utc': utc(), 'git_commit': EXPECTED, 'source_before': frozen, 'source_after': after,
               'source_unchanged': same_source(frozen, after), 'tools_before': launch['tools_before'],
               'tools_after': after_tools, 'tools_unchanged': tools_same(launch['tools_before'], after_tools),
               'stages': [{'name': report['stage'], 'report': str(OUT / report['stage'] / 'report.json'),
                           'report_sha256': digest(OUT / report['stage'] / 'report.json'),
                           'ok': report['ok'], 'returncode': report['returncode'],
                           'timed_out': report['timed_out'], 'duration_seconds': report['duration_seconds']}
                          for report in reports],
               'all_requested_stages_passed': all(report['ok'] for report in reports),
               'remote_ci_used': False, 'all_19_gates_requalified': False,
               'performance_requalified': False, 'model_experiment_repeated': False}
    write(OUT / 'summary.json', summary)
    entries = []
    for path in sorted(OUT.rglob('*')):
        if path.name in ('manifest.json', 'driver.stdout.log', 'driver.stderr.log') or path.is_dir():
            continue
        row = {'path': str(path.relative_to(OUT)), 'sha256': digest(path), 'bytes': path.stat().st_size}
        if path.is_symlink():
            row['symlink_target'] = os.readlink(path)
        entries.append(row)
    write(OUT / 'manifest.json', {'schema': 'hepta.integrated-followup-manifest.v1', 'files': entries,
                                'manifest_excludes_self_and_still_open_driver_logs': True})
    print(json.dumps({'completed': True, 'summary': str(OUT / 'summary.json'),
                      'summary_sha256': digest(OUT / 'summary.json'),
                      'all_requested_stages_passed': summary['all_requested_stages_passed']}, sort_keys=True), flush=True)
    return 0 if summary['all_requested_stages_passed'] and summary['source_unchanged'] and summary['tools_unchanged'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
