"""Supervise three unchanged methods on the fixed source; no build or qualification."""
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
    expected = json.loads((harness / 'inputs/INPUTS.json').read_bytes())
    report = {'schema': 'hepta.original-namespace-three-method-diagnostic.v1', 'status': 'INCOMPLETE',
              'python': sys.version, 'source_commit': expected['source_commit'],
              'source_tree': expected['source_tree'], 'original_run': expected['original_run'],
              'original_native_job': expected['original_native_job'], 'qualification': False,
              'whole_native': False, 'new_fixture_compilations': 0,
              'runtime_executables': {'clang': shutil.which('clang'), 'cc': shutil.which('cc')}, 'cases': []}
    before = None
    selected_before = None
    retained = evidence / 'retained-original-inputs'
    try:
        assert tuple(sys.version_info[:3]) == tuple(expected['python_version'])
        before = snapshot(source, expected)
        write_json(evidence / 'SOURCE-BEFORE.json', before)
        selected = unpack(harness, retained, expected)
        write_json(evidence / 'RETAINED-INPUT-READBACK.json', selected)
        selected_before = retained_map(retained)
        test_path = source / 'tests/test_hia_agent_native_tools.py'
        tree = ast.parse(test_path.read_bytes())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'NativeLifecycleTests')
        methods = {node.name: node for node in owner.body if isinstance(node, ast.FunctionDef)}
        assert len(expected['methods']) == len(set(expected['methods'])) == 3
        report['original_method_ast'] = {name: ast.dump(methods[name], include_attributes=False) for name in expected['methods']}
        report['original_test_file'] = identity(test_path.read_bytes())
        report['group_started_ns'] = time.monotonic_ns()
        deadline = time.monotonic() + 1800
        for number, method in enumerate(expected['methods']):
            output = evidence / ('case-%d' % number)
            output.mkdir()
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'original shared 1800-second diagnostic group exhausted'
            command = [sys.executable, '-B', str(harness / 'tools/observe_case.py'),
                '--source', str(source), '--retained', str(retained),
                '--evidence', str(output / 'observations'), '--method', method]
            terminal = run_case(command, source, output, remaining)
            report_path = output / 'observations/REPORT.json'
            child = json.loads(report_path.read_bytes()) if report_path.is_file() else None
            report['cases'].append({'method': method, 'process': terminal,
                'observation_status': child.get('status') if child else None,
                'tests_run': child.get('tests_run') if child else None,
                'original_outcome': child.get('original_outcome') if child else None,
                'report_path': report_path.relative_to(evidence).as_posix(),
                'report_identity': identity(report_path.read_bytes()) if child else None})
        report['group_elapsed_ns'] = time.monotonic_ns() - report['group_started_ns']
        completed = all(row['process']['returncode'] == 0 and not row['process']['timed_out']
                        and row['process']['same_process_group_absent'] is True
                        and row['observation_status'] == 'OBSERVATIONS_COMPLETE' and row['tests_run'] == 1
                        for row in report['cases'])
        report['status'] = 'OBSERVATIONS_COMPLETE' if completed else 'DIAGNOSTIC_FAILURE'
    except BaseException:
        report['status'] = 'DIAGNOSTIC_FAILURE'
        report['error'] = traceback.format_exc()
    finally:
        try:
            after = snapshot(source, expected)
            write_json(evidence / 'SOURCE-AFTER.json', after)
            report['source_unchanged'] = before == after
            selected_after = retained_map(retained) if retained.exists() else None
            write_json(evidence / 'RETAINED-AFTER.json', selected_after)
            report['retained_inputs_unchanged'] = selected_before is not None and selected_before == selected_after
            if report['source_unchanged'] is not True or report['retained_inputs_unchanged'] is not True:
                report['status'] = 'DIAGNOSTIC_FAILURE'
        except BaseException:
            report['status'] = 'DIAGNOSTIC_FAILURE'
            report['readback_error'] = traceback.format_exc()
        write_json(evidence / 'REPORT.json', report)
        print(json.dumps({key: value for key, value in report.items() if key != 'original_method_ast'}, sort_keys=True))
    return 0 if report['status'] == 'OBSERVATIONS_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
