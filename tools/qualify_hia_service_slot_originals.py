"""Supervise the independent original stream or compare one admitted image.

Original mode runs complete base and derived-fault streams twice in four fresh
children. Derivation uses only the first original base cutpoints and is frozen
before any fault run. Candidate mode consumes that completed immutable bundle;
it never builds or replaces original expectations.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / 'tests/fixtures/hia_service_slot_observation_inputs_v1/inputs.json'
OBSERVER = ROOT / 'tests/hia_service_slot_observer.py'
INPUTS_SHA256 = '625d6fdb004b28e0f207f1fc22052dca55b28bacea09d9f3053674a78ee9d001'
BASE_COUNT = 348
BASIS_COUNT = 13
ORIGINAL_SECONDS = 600
CANDIDATE_SECONDS = 1800
CLEANUP_SECONDS = 3


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def file_hash(path):
    result = sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1 << 20), b''):
            result.update(chunk)
    return result.hexdigest()


def put(path, value):
    with Path(path).open('xb') as target:
        target.write(encoded(value))


def environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME')
            and not key.startswith('HEPTA_HIA_')}


def source_pins():
    paths = (Path(__file__).resolve(), OBSERVER,
        ROOT / 'tests/hia_service_slot_original_oracle.py', INPUTS,
        ROOT / 'tests/fixtures/hia_service_slot_original_bc011/rollback.bc011.py.txt',
        ROOT / 'tests/fixtures/hia_service_slot_original_bc011/adopt.bc011.py.txt',
        ROOT / 'tests/fixtures/hia_service_slot_original_bc011/FREEZE.json')
    return {str(path.relative_to(ROOT)): {'sha256': file_hash(path), 'bytes': path.stat().st_size}
            for path in paths}


def group_absent(pid):
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return True
    return False


def child(parent, label, kind, cases, expected=None, manifest=None):
    control = parent / (label + '-supervisor')
    control.mkdir(mode=0o700)
    destination = parent / label
    command = [sys.executable, '-I', '-B', str(OBSERVER), '--kind', kind,
               '--cases', str(cases), '--cases-sha256', file_hash(cases),
               '--output', str(destination)]
    if expected is not None:
        command += ['--expected', str(expected)]
    if manifest is not None:
        command += ['--manifest', str(manifest)]
    seconds = ORIGINAL_SECONDS if kind == 'original' else CANDIDATE_SECONDS
    start_ns = time.time_ns()
    record = {'schema': 'hepta.hia.service-slot-child-supervisor.v1',
        'label': label, 'kind': kind, 'command': command, 'cwd': str(ROOT),
        'timeout_seconds': seconds, 'cleanup_seconds': CLEANUP_SECONDS,
        'source_before': source_pins(), 'parent_pid': os.getpid(),
        'parent_pgid': os.getpgid(0), 'started_time_ns': start_ns,
        'case_file_sha256': file_hash(cases), 'pid': None, 'returncode': None,
        'timeout': False, 'signals': [], 'reaped': False, 'group_absent': None,
        'launch_error': None, 'supervision_error': None, 'cleanup_error': None}
    process = None
    stdout = stderr = b''
    try:
        process = subprocess.Popen(command, cwd=ROOT, env=environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        # Every post-Popen allocation/write is inside this custody region.
        record['pid'] = process.pid
        record['pgid'] = process.pid
        put(control / 'started.json', record)
        try:
            stdout, stderr = process.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            record['timeout'] = True
            raise
    except BaseException as error:
        record['launch_error' if process is None else 'supervision_error'] = {
            'type': type(error).__name__, 'message': str(error)}
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    record['signals'].append('SIGKILL')
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    record['cleanup_error'] = {'type': type(error).__name__, 'message': str(error)}
                try:
                    stdout, stderr = process.communicate(timeout=CLEANUP_SECONDS)
                except BaseException as error:
                    record['cleanup_error'] = {'type': type(error).__name__, 'message': str(error)}
            else:
                # communicate may have failed after natural exit but before
                # collecting pipe data; retain the real remaining bytes.
                try:
                    rest_out, rest_err = process.communicate(timeout=CLEANUP_SECONDS)
                    if not stdout:
                        stdout = rest_out
                    if not stderr:
                        stderr = rest_err
                except BaseException as error:
                    record['cleanup_error'] = {'type': type(error).__name__, 'message': str(error)}
            record['returncode'] = process.poll()
            record['reaped'] = process.returncode is not None
            record['group_absent'] = group_absent(process.pid)
        record['finished_time_ns'] = time.time_ns()
        record['source_after'] = source_pins()
        record['elapsed_ns'] = record['finished_time_ns'] - start_ns
        record['stdout_sha256'] = sha256(stdout).hexdigest()
        record['stderr_sha256'] = sha256(stderr).hexdigest()
        (control / 'stdout.log').write_bytes(stdout)
        (control / 'stderr.log').write_bytes(stderr)
        report_file = destination / 'report.json'
        report_raw = report_file.read_bytes() if report_file.is_file() else None
        report = json.loads(report_raw) if report_raw is not None else None
        record['inner_report_sha256'] = None if report_raw is None else sha256(report_raw).hexdigest()
        record['inner_status'] = None if report is None else report.get('status')
        record['status'] = ('PASS' if record['returncode'] == 0 and record['reaped']
            and record['group_absent'] is True and not record['timeout']
            and not record['signals'] and record['launch_error'] is None
            and record['supervision_error'] is None and record['cleanup_error'] is None
            and record['source_before'] == record['source_after']
            and report is not None and report.get('status') == 'PASS'
            and report.get('scope_complete') is True and report.get('pid') == process.pid
            and report.get('parent_pid') == os.getpid() and report.get('pgid') == process.pid
            and report.get('argv') == command[3:] and report.get('cwd') == str(ROOT)
            and report_file.read_bytes() == report_raw
            else 'HOLD')
        put(control / 'result.json', record)
    return record


def compare_files(left, right):
    # Full streaming equality, not an inferred equivalence from two hashes.
    with Path(left).open('rb') as a, Path(right).open('rb') as b:
        while True:
            first, second = a.read(1 << 20), b.read(1 << 20)
            if first != second:
                return False
            if not first:
                return True


def build_originals(output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    inputs_raw = INPUTS.read_bytes()
    inputs = json.loads(inputs_raw)
    if (sha256(inputs_raw).hexdigest() != INPUTS_SHA256 or len(inputs['cases']) != BASE_COUNT or len(inputs['fault_basis']) != BASIS_COUNT
            or len({row['id'] for row in inputs['cases']}) != BASE_COUNT
            or inputs['source_pins'] != {
                'rollback': 'a519b619fab259455444da24aba65883e2bf7d9101a4ba73ea6a147a297a7e5a',
                'adopt': '8bc5c40abacc8364e811accc520d6a5bb737eabd50651759b71d56b03ccb6ad8'}):
        raise ValueError('fixed original input domain changed')
    before = source_pins()
    (output / 'inputs.json').write_bytes(inputs_raw)
    base = output / 'base-inputs.jsonl'
    with base.open('xb') as target:
        for row in inputs['cases']:
            target.write(encoded(row))
    records = [child(output, 'base-first', 'original', base),
               child(output, 'base-second', 'original', base)]
    comparisons = []
    ready = all(row['status'] == 'PASS' for row in records)
    if ready:
        for name in ('observations.jsonl', 'late-events.jsonl', 'tracebacks.jsonl', 'cutpoints.jsonl'):
            equal = compare_files(output / 'base-first' / name, output / 'base-second' / name)
            comparisons.append({'kind': 'base', 'file': name, 'full_bytes_equal': equal})
            ready = ready and equal
    faults = output / 'fault-inputs.jsonl'
    fault_count = 0
    if ready:
        basis = {row['id']: row for row in inputs['cases'] if row['id'] in inputs['fault_basis']}
        actual_cuts = {}
        with (output / 'base-first/cutpoints.jsonl').open('rb') as source:
            for raw in source:
                value = json.loads(raw)
                if value['case'] in basis:
                    actual_cuts[value['case']] = value['cutpoints']
        if set(actual_cuts) != set(inputs['fault_basis']):
            raise ValueError('original basis was not completely observed')
        with faults.open('xb') as target:
            for case_id in inputs['fault_basis']:
                for cut_index, cut in enumerate(actual_cuts[case_id]):
                    for family in inputs['fault_families']:
                        for outer in inputs['fault_outer_states']:
                            row = json.loads(encoded(basis[case_id]))
                            row['id'] = (case_id + '.fault-' + str(cut_index) + '.' + family
                                         + '.outer' + str(int(outer)))
                            row['outer'] = outer
                            row['fault'] = {'event': cut['event'], 'occurrence': cut['occurrence'],
                                            'family': family}
                            target.write(encoded(row))
                            fault_count += 1
        # This file is the immutable derived domain. It exists before the
        # first fault observation, and well before any candidate import.
        put(output / 'fault-input-freeze.json', {
            'schema': 'hepta.hia.service-slot-derived-fault-freeze.v1',
            'source_inputs_sha256': sha256(inputs_raw).hexdigest(),
            'basis_ids': inputs['fault_basis'], 'count': fault_count,
            'sha256': file_hash(faults), 'bytes': faults.stat().st_size,
            'basis_cutpoints_sha256': file_hash(output / 'base-first/cutpoints.jsonl'),
            'frozen_time_ns': time.time_ns(), 'candidate_imported_or_executed': False})
        records += [child(output, 'fault-first', 'original', faults),
                    child(output, 'fault-second', 'original', faults)]
        ready = ready and all(row['status'] == 'PASS' for row in records)
        if ready:
            for name in ('observations.jsonl', 'late-events.jsonl', 'tracebacks.jsonl', 'cutpoints.jsonl'):
                equal = compare_files(output / 'fault-first' / name, output / 'fault-second' / name)
                comparisons.append({'kind': 'fault', 'file': name, 'full_bytes_equal': equal})
                ready = ready and equal
    after = source_pins()
    files = {}
    for path in sorted(output.rglob('*')):
        if path.is_file():
            files[str(path.relative_to(output))] = {'bytes': path.stat().st_size, 'sha256': file_hash(path)}
    runtimes = [json.loads((output / label / 'report.json').read_bytes())['runtime']
                for label in ('base-first', 'base-second', 'fault-first', 'fault-second')
                if (output / label / 'report.json').is_file()]
    ready = ready and before == after and len(runtimes) == 4 and all(row == runtimes[0] for row in runtimes)
    report = {'schema': 'hepta.hia.service-slot-original-bundle.v1',
        'status': 'PASS_ORIGINAL_OBSERVATION' if ready else 'HOLD',
        'runtime': runtimes[0] if runtimes else None,
        'source_before': before, 'source_after': after,
        'base_count': BASE_COUNT, 'base_ordered_ids': [row['id'] for row in inputs['cases']],
        'basis_count': BASIS_COUNT, 'basis_ids': inputs['fault_basis'],
        'fault_count': fault_count, 'total_count': BASE_COUNT + fault_count,
        'input_sha256': sha256(inputs_raw).hexdigest(), 'files': files,
        'commands': records, 'repeated_full_streams': comparisons,
        'product_or_native_or_VM_or_SQL_executed': False,
        'candidate_results_used_as_expected': False,
        'whole_qualification': False}
    put(output / 'original-bundle.json', report)
    return report


def read_originals(directory, *, report_raw=None):
    report_path = directory / 'original-bundle.json'
    if report_raw is None:
        report_raw = report_path.read_bytes()
    report = json.loads(report_raw)
    if (report.get('schema') != 'hepta.hia.service-slot-original-bundle.v1'
            or report.get('status') != 'PASS_ORIGINAL_OBSERVATION'
            or report.get('base_count') != BASE_COUNT or report.get('basis_count') != BASIS_COUNT
            or report.get('source_before') != source_pins()
            or report.get('source_after') != source_pins()
            or report.get('input_sha256') != INPUTS_SHA256
            or file_hash(INPUTS) != INPUTS_SHA256
            or report.get('product_or_native_or_VM_or_SQL_executed') is not False):
        raise ValueError('complete prior independent original bundle is unavailable or differs')
    for name, pin in report['files'].items():
        path = directory / name
        if path.stat().st_size != pin['bytes'] or file_hash(path) != pin['sha256']:
            raise ValueError('original bundle file changed: ' + name)
    if len(report['commands']) != 4 or any(row['status'] != 'PASS' for row in report['commands']):
        raise ValueError('all four original fresh children are required')
    if len(report['repeated_full_streams']) != 8 or any(
            row['full_bytes_equal'] is not True for row in report['repeated_full_streams']):
        raise ValueError('original repeats were not fully equal')
    if report_path.read_bytes() != report_raw:
        raise ValueError('original bundle changed after its captured-byte admission')
    return report


def compare_candidate(output, originals, manifest):
    original_bundle_raw = (originals / 'original-bundle.json').read_bytes()
    expected = read_originals(originals, report_raw=original_bundle_raw)
    original_bundle_hash = sha256(original_bundle_raw).hexdigest()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    before = source_pins()
    commands = []
    for label, case_name, expected_name in (
            ('base', 'base-inputs.jsonl', 'base-first'),
            ('fault', 'fault-inputs.jsonl', 'fault-first')):
        commands.append(child(output, label, 'native', originals / case_name,
                              originals / expected_name, manifest))
    after = source_pins()
    read_originals(originals, report_raw=original_bundle_raw)
    reports = []
    report_captures = []
    for index, label in enumerate(('base', 'fault')):
        report_file = output / label / 'report.json'
        if report_file.is_file():
            report_raw = report_file.read_bytes()
            if sha256(report_raw).hexdigest() != commands[index]['inner_report_sha256']:
                raise ValueError('candidate child report differs from supervised bytes: ' + label)
            reports.append(json.loads(report_raw))
            report_captures.append((report_file, report_raw))
    ready = (all(row['status'] == 'PASS' for row in commands) and len(reports) == 2
             and reports[0]['count'] == expected['base_count']
             and reports[1]['count'] == expected['fault_count']
             and all(row['actual_public_dispatch_selected'] is True
                     and row['retained_reference_poisoned'] is True
                     and sum(row['public_dispatch_calls'].values()) >= row['count']
                     and sum(row['actual_frames'].values()) > 0
                     for row in reports)
             and before == after
             and (originals / 'original-bundle.json').read_bytes() == original_bundle_raw)
    report = {'schema': 'hepta.hia.service-slot-candidate-comparison.v1',
        'status': 'PASS' if ready else 'HOLD',
        'source_before': before, 'source_after': after,
        'original_bundle': str(originals / 'original-bundle.json'),
        'original_bundle_sha256': original_bundle_hash,
        'base_count': expected['base_count'], 'fault_count': expected['fault_count'],
        'commands': commands, 'reports': reports,
        'runtime': expected['runtime'], 'manifest': str(manifest),
        'manifest_sha256': file_hash(manifest),
        'original_expectations_replaced_or_normalized': False,
        'all_candidate_cases_use_actual_public_dispatch': ready,
        'whole_qualification': False}
    for report_file, report_raw in report_captures:
        if report_file.read_bytes() != report_raw:
            raise ValueError('candidate child report changed before aggregate publication: ' + report_file.parent.name)
    put(output / 'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--originals', type=Path)
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    if (args.originals is None) != (args.manifest is None):
        raise ValueError('candidate comparison requires both originals and manifest')
    value = (build_originals(args.output) if args.originals is None else
             compare_candidate(args.output, args.originals, args.manifest))
    print(encoded({'status': value['status'], 'output': str(args.output)}).decode(), end='')
    return 0 if value['status'].startswith('PASS') else 1


if __name__ == '__main__':
    raise SystemExit(main())
