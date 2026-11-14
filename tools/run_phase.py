"""Supervise one original R20 fresh admission; no warmup, test or qualification."""
from __future__ import annotations
import argparse
import ast
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback
import zlib
from diagnose_source_scan import identity, snapshot, write_json


def retained_map(root):
    return {p.relative_to(root).as_posix(): {'mode': stat.S_IMODE(p.stat().st_mode), **identity(p.read_bytes())}
            for p in sorted(root.rglob('*')) if p.is_file()}


def unpack(harness, output, expected):
    index = json.loads((harness / 'inputs/RETAINED-PARTS.json').read_bytes())
    chunks = []
    for part in index['parts']:
        assert part['offset'] == sum(map(len, chunks))
        raw = (harness / 'inputs' / part['path']).read_bytes()
        assert identity(raw) == {key: part[key] for key in ('bytes', 'sha256', 'git_blob')}
        chunks.append(raw)
    encoded = b''.join(chunks)
    assert identity(encoded) == index['complete'] == expected['retained_packet']
    wrapper = json.loads(encoded)
    raw = zlib.decompress(base64.b64decode(wrapper['payload'], validate=True))
    assert identity(raw) == wrapper['decoded']
    packet = json.loads(raw)
    assert wrapper['members'] == len(packet['files']) == 16
    output.mkdir()
    rows = {}
    for name, row in packet['files'].items():
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        data = base64.b64decode(row['base64'], validate=True)
        assert identity(data) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.open('xb').write(data)
        target.chmod(row['mode'])
        assert target.read_bytes() == data and stat.S_IMODE(target.stat().st_mode) == row['mode']
        rows[name] = {key: value for key, value in row.items() if key != 'base64'}
    return rows


def run_case(command, source, output, seconds):
    record = {'argv': command, 'cwd': str(source), 'remaining_group_seconds': seconds,
              'original_group_seconds': 1800, 'cleanup_seconds': 3, 'timed_out': False}
    started = time.monotonic_ns()
    with (output / 'stdout.log').open('xb') as stdout, (output / 'stderr.log').open('xb') as stderr:
        process = subprocess.Popen(command, cwd=source, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            start_new_session=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        record['pid'] = process.pid
        try:
            record['returncode'] = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            record['timed_out'] = True
            os.killpg(process.pid, signal.SIGKILL)
            record['returncode'] = process.wait(timeout=3)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            record['same_process_group_absent'] = True
        else:
            record['same_process_group_absent'] = False
            os.killpg(process.pid, signal.SIGKILL)
    record['elapsed_ns'] = time.monotonic_ns() - started
    write_json(output / 'PROCESS.json', record)
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    source, harness, evidence = args.source.resolve(), args.harness.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    inputs_path = harness / 'inputs/EXECUTION-INPUTS.json'
    expected_raw = inputs_path.read_bytes()
    expected = json.loads(expected_raw)
    report = {'schema': 'hepta.r20.single-original-fresh-supervisor.v1', 'status': 'INCOMPLETE',
              'python': sys.version, 'source_commit': expected['source_commit'],
              'source_tree': expected['source_tree'], 'original_run': expected['original_run'],
              'original_native_job': expected['original_native_job'], 'qualification': False,
              'whole_native': False, 'new_fixture_compilations': 0,
              'runtime_executables': {'clang': shutil.which('clang'), 'cc': shutil.which('cc')},
              'execution_inputs': identity(expected_raw), 'cases': [],
              'process_launch_attempts': 0, 'planned_product_calls': 1,
              'planned_product_warmups': 0, 'planned_business_tests': 0,
              'planned_compilers': 0, 'planned_native_images': 0, 'planned_vm_runs': 0,
              'supervision_scope': 'original child wait and same process-group absence; no ECHILD or subreaper assertion',
              'automatic_retry': False}
    before = bindings_before = None
    terminal_errors = []

    def execution_bindings():
        rows = {}
        for name, row in expected['execution_files'].items():
            relative = PurePosixPath(name)
            assert not relative.is_absolute() and str(relative) == name
            assert name and '..' not in relative.parts and '.' not in relative.parts
            target = harness / name
            for parent in target.parents:
                if parent == harness:
                    break
                assert not parent.is_symlink()
            info = target.lstat()
            assert stat.S_ISREG(info.st_mode) and not target.is_symlink()
            value = {'mode': stat.S_IMODE(info.st_mode), **identity(target.read_bytes())}
            assert value == row, ('execution file differs', name)
            rows[name] = value
        assert inputs_path.read_bytes() == expected_raw
        return rows

    def attempt_terminal(label, action):
        try:
            return action()
        except BaseException:
            detail = {'action': label, 'traceback': traceback.format_exc()}
            terminal_errors.append(detail)
            try:
                print(json.dumps({'terminal_evidence_error': detail}, sort_keys=True), file=sys.stderr, flush=True)
            except BaseException:
                pass
            return None

    try:
        assert expected['schema'] == 'hepta.r20.single-original-fresh-execution-inputs.v1'
        assert tuple(sys.version_info[:3]) == (3, 14, 4) == tuple(expected['python_version'])
        assert expected['source_commit'] == '26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d'
        assert expected['source_tree'] == '84df4b42f1e20fd7d0c7229e658cf3b458984ffb'
        assert expected['source_files'] == 3177
        assert expected['operations'] == ['tools.build_hia_json_preflight.current_sources']
        assert expected['group_limit_seconds'] == 1800 and expected['cleanup_seconds'] == 3
        assert expected['planned_product_calls'] == 1 and expected['planned_product_warmups'] == 0
        assert set(expected['function_source']) == {'bytes', 'git_blob', 'sha256'}
        assert expected['fresh_paths'] == 1551 and expected['fresh_bytes'] == 58637295
        bindings_before = execution_bindings()
        write_json(evidence / 'EXECUTION-FILES-BEFORE.json', bindings_before)
        before = snapshot(source, expected)
        write_json(evidence / 'SOURCE-BEFORE.json', before)
        manifest_raw = (harness / expected['source_manifest_file']).read_bytes()
        assert identity(manifest_raw) == expected['source_manifest']
        expected_files = json.loads(manifest_raw)
        assert before['files'] == {name: {'mode': row['git_mode'], **{key: row[key]
            for key in ('bytes', 'sha256', 'git_blob')}} for name, row in expected_files.items()}
        fresh_raw = (harness / expected['fresh_map_file']).read_bytes()
        assert identity(fresh_raw) == expected['fresh_map']
        expected_fresh = json.loads(fresh_raw)
        assert len(expected_fresh) == expected['fresh_paths']
        assert all(expected_files[name]['sha256'] == digest for name, digest in expected_fresh.items())
        assert sum(expected_files[name]['bytes'] for name in expected_fresh) == expected['fresh_bytes']
        # Original production prerequisite admission, before the observed group.
        # The child remains a fresh interpreter; no product provider is replaced.
        sys.path.insert(0, str(source))
        from tools.qualify_hia_store_lifecycle import _prerequisites
        report['prerequisites'] = _prerequisites(dict(os.environ))
        write_json(evidence / 'PREREQUISITES.json', report['prerequisites'])
        report['group_started_ns'] = time.monotonic_ns()
        deadline = time.monotonic() + 1800
        output = evidence / 'case-0'
        output.mkdir()
        remaining = deadline - time.monotonic()
        assert remaining > 0, 'original shared 1800-second diagnostic group exhausted'
        command = [sys.executable, '-B', str(harness / 'tools/observe_single_fresh.py'),
            '--source', str(source), '--harness', str(harness),
            '--inputs', str(inputs_path), '--evidence', str(output / 'observations')]
        report['process_launch_attempts'] += 1
        terminal = run_case(command, source, output, remaining)
        report['group_elapsed_ns'] = time.monotonic_ns() - report['group_started_ns']
        report_path = output / 'observations/REPORT.json'
        child_raw = report_path.read_bytes() if report_path.is_file() else None
        child = json.loads(child_raw) if child_raw is not None else None
        report['cases'].append({'operation': expected['operations'][0], 'process': terminal,
            'observation_status': child.get('status') if child else None,
            'product_calls_attempted': child.get('product_calls_attempted') if child else None,
            'report_path': report_path.relative_to(evidence).as_posix(),
            'report_identity': identity(child_raw) if child_raw is not None else None})
        completed = (terminal['returncode'] == 0 and not terminal['timed_out']
            and terminal['same_process_group_absent'] is True
            and type(child) is dict and child.get('status') == 'ONE_ORIGINAL_FRESH_OBSERVATION_COMPLETE'
            and child.get('source_commit') == expected['source_commit']
            and child.get('source_tree') == expected['source_tree']
            and child.get('product_calls_attempted') == 1
            and all(child.get(name) == 0 for name in ('product_tests', 'compilers', 'Native', 'VM'))
            and child.get('actual_fresh_paths') == 1551 and child.get('actual_current_sources_paths') == 1552
            and child.get('source_unchanged') is True
            and child.get('bindings_and_function_definitions_unchanged') is True
            and child.get('profile_is_original_none') is True and child.get('monitor_tool_released') is True
            and child.get('observer_cleanup_errors') == [] and child.get('terminal_evidence_errors') == []
            and child.get('qualification') is False and child.get('whole_native') is False
            and child.get('automatic_retry') is False)
        report['status'] = 'ONE_ORIGINAL_FRESH_OBSERVATION_COMPLETE' if completed else 'DIAGNOSTIC_FAILURE'
    except BaseException:
        report['status'] = 'DIAGNOSTIC_FAILURE'
        report['error'] = traceback.format_exc()
    finally:
        after = None
        try:
            after = snapshot(source, expected)
            report['source_unchanged'] = before is not None and before == after
        except BaseException:
            report['source_unchanged'] = False
            report['source_readback_error'] = traceback.format_exc()
        if after is not None:
            attempt_terminal('source after save', lambda: write_json(evidence / 'SOURCE-AFTER.json', after))
        bindings_after = None
        try:
            bindings_after = execution_bindings()
            report['execution_files_unchanged'] = bindings_before is not None and bindings_before == bindings_after
        except BaseException:
            report['execution_files_unchanged'] = False
            report['execution_readback_error'] = traceback.format_exc()
        if bindings_after is not None:
            attempt_terminal('execution files after save', lambda: write_json(evidence / 'EXECUTION-FILES-AFTER.json', bindings_after))
        report['terminal_evidence_errors'] = terminal_errors
        if terminal_errors or report['source_unchanged'] is not True or report['execution_files_unchanged'] is not True:
            report['status'] = 'DIAGNOSTIC_FAILURE'
        attempt_terminal('terminal report save', lambda: write_json(evidence / 'REPORT.json', report))
        if terminal_errors:
            report['status'] = 'DIAGNOSTIC_FAILURE'
        attempt_terminal('terminal stdout report', lambda: print(json.dumps(report, sort_keys=True), flush=True))
        if terminal_errors:
            report['status'] = 'DIAGNOSTIC_FAILURE'
    return 0 if report['status'] == 'ONE_ORIGINAL_FRESH_OBSERVATION_COMPLETE' else 1

if __name__ == '__main__':
    raise SystemExit(main())
