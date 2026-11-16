"""Original-first finite authority and complete isolated candidate supervisor."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
import platform
from pathlib import Path
import signal
import subprocess
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
from tests.hia_store_file_capture_oracle import canonical
INPUTS = ROOT / 'tests/fixtures/hia_store_file_capture_inputs_v1.json'
OBSERVER = ROOT / 'tests/hia_store_file_capture_observer.py'

def write(path, value):
    raw = canonical(value) + b'\n'
    with Path(path).open('xb') as stream:
        stream.write(raw)
    return sha256(raw).hexdigest()

def captured_json(path):
    raw = Path(path).read_bytes()
    return raw, json.loads(raw), sha256(raw).hexdigest()

def group_members(group):
    rows = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            value = (path / 'stat').read_text()
            fields = value[value.rindex(')') + 2:].split()
            if int(fields[2]) == group:
                rows.append({'pid': int(path.name), 'state': fields[0]})
        except (OSError, ValueError, IndexError):
            continue
    return sorted(rows, key=lambda x: x['pid'])

def stop_owned(process):
    deadline = time.monotonic() + 3
    before = group_members(process.pid)
    if before:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=max(0.001, deadline - time.monotonic()))
    while time.monotonic() < deadline:
        after = group_members(process.pid)
        if not after:
            return {'before': before, 'after': after, 'reaped': True}
        time.sleep(0.01)
    raise RuntimeError('owned process group did not leave within cleanup budget')

def child(parent, label, lane, inputs, *, authority=None, manifest=None):
    directory = parent / label
    command = [sys.executable, '-I', '-B', str(OBSERVER), '--lane', lane,
               '--inputs', str(inputs), '--output', str(directory)]
    if authority is not None:
        command += ['--expected', str(authority)]
    if manifest is not None:
        command += ['--manifest', str(manifest)]
    timeout = 600 if lane == 'original' else 1800
    started, start_ns = time.monotonic(), time.time_ns()
    process = None
    timed_out, cleanup_error, cleanup = False, None, None
    with (parent / (label + '.stdout.log')).open('xb') as out, \
         (parent / (label + '.stderr.log')).open('xb') as err:
        try:
            process = subprocess.Popen(command, cwd=ROOT, env=os.environ.copy(),
                                       stdout=out, stderr=err, start_new_session=True)
            write(parent / (label + '.start.json'), {'schema': 'hepta.hia.file-capture-child-start.v1',
                  'command': command, 'cwd': str(ROOT), 'pid': process.pid, 'pgid': process.pid,
                  'started_time_ns': start_ns, 'timeout_seconds': timeout, 'cleanup_seconds': 3})
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            if process is not None:
                try:
                    cleanup = stop_owned(process)
                except BaseException as error:
                    cleanup_error = {'type': type(error).__name__, 'text': str(error)}
    raw = report = report_pin = None
    if (directory / 'report.json').exists():
        raw, report, report_pin = captured_json(directory / 'report.json')
    value = {'schema': 'hepta.hia.file-capture-child-result.v1', 'command': command,
             'cwd': str(ROOT), 'pid': None if process is None else process.pid,
             'pgid': None if process is None else process.pid,
             'returncode': None if process is None else process.returncode,
             'timeout': timed_out, 'cleanup_error': cleanup_error, 'cleanup': cleanup,
             'reaped': process is not None and process.poll() is not None,
             'elapsed_seconds': time.monotonic() - started, 'started_time_ns': start_ns,
             'ended_time_ns': time.time_ns(), 'timeout_seconds': timeout, 'cleanup_seconds': 3,
             'report_sha256': report_pin,
             'stdout_sha256': sha256((parent / (label + '.stdout.log')).read_bytes()).hexdigest(),
             'stderr_sha256': sha256((parent / (label + '.stderr.log')).read_bytes()).hexdigest()}
    write(parent / (label + '.result.json'), value)
    if timed_out or cleanup_error or process is None or process.returncode != 0 or report is None:
        raise RuntimeError('complete child did not pass: ' + label)
    if (report['lane'] != lane or report['runtime'] != sys.version
            or report['runtime_version'] != list(sys.version_info[:3])
            or report['implementation'] != platform.python_implementation()
            or report['source_before'] != report['source_after']
            or report['differences'] != 0
            or (lane == 'original' and report['native_or_VM_entries'] != 0)
            or (lane != 'original' and report['native_or_VM_entries'] <= 0)):
        raise ValueError('child runtime, original source custody or complete comparison differs')
    for name, pin in report['files'].items():
        if Path(name).name != name or sha256((directory/name).read_bytes()).hexdigest() != pin:
            raise ValueError('child observations differ from their actual report')
    if (directory / 'report.json').read_bytes() != raw:
        raise ValueError('child report changed after its receipt')
    return value, report, raw

def originals(output):
    output = Path(output)
    output.mkdir(mode=0o700)
    input_raw, inputs, input_pin = captured_json(INPUTS)
    write(output / 'base-inputs.json', inputs)
    commands = []
    for label in ('basis-first', 'basis-second'):
        receipt, report, raw = child(output, label, 'original', output / 'base-inputs.json')
        commands.append(receipt)
    base_first = (output / 'basis-first/observations.jsonl').read_bytes()
    base_second = (output / 'basis-second/observations.jsonl').read_bytes()
    if base_first != base_second:
        raise ValueError('two complete base originals differ')
    by_id = {x['id']: x for x in inputs['cases']}
    basis = {}
    for line in base_first.splitlines():
        row = json.loads(line)
        if row['id'] in inputs['basis_ids']:
            basis[row['id']] = row
    if set(basis) != set(inputs['basis_ids']):
        raise ValueError('original basis is incomplete')
    cases = list(inputs['cases'])
    for case_id in inputs['basis_ids']:
        base_fault = by_id[case_id].get('base_fault')
        prerequisites = [hit for hit in basis[case_id]['hits']
                         if hit['label'] == base_fault] if base_fault is not None else []
        if base_fault is not None and (len(prerequisites) != 1
                or basis[case_id]['injected_fault_fired'] is not True):
            raise ValueError('original basis prerequisite is not unique and observed')
        for hit in basis[case_id]['hits']:
            for family in inputs['fault_families']:
                case = dict(by_id[case_id])
                case['id'] = case_id + '.fault.' + str(hit['index']) + '.' + family
                case['fault'] = {'index': hit['index'], 'label': hit['label'], 'family': family}
                # Targets before or at the basis error replace it. Later targets
                # require that exact error to enter the recorded cleanup path.
                if not prerequisites or hit['index'] <= prerequisites[0]['index']:
                    case.pop('base_fault', None)
                cases.append(case)
    complete = {'schema': 'hepta.hia.store-file-capture-complete-inputs.v1',
                'basis_inputs_sha256': input_pin, 'cases': cases,
                'derived_only_from_original': True}
    complete_pin = write(output / 'complete-inputs.json', complete)
    # Freeze the complete derived domain before any complete lane/candidate.
    write(output / 'derived-input-freeze.json', {'inputs_sha256': complete_pin, 'count': len(cases),
          'ordered_ids': [x['id'] for x in cases], 'basis_observations_sha256': sha256(base_first).hexdigest()})
    for label in ('complete-first', 'complete-second'):
        receipt, report, raw = child(output, label, 'original', output / 'complete-inputs.json')
        commands.append(receipt)
        if report['count'] != len(cases):
            raise ValueError('original complete input count differs')
    left = output / 'complete-first/observations.jsonl'
    right = output / 'complete-second/observations.jsonl'
    left_raw, right_raw = left.read_bytes(), right.read_bytes()
    if left_raw != right_raw:
        raise ValueError('complete original lanes are not byte equal')
    if INPUTS.read_bytes() != input_raw:
        raise ValueError('frozen baseline input changed')
    write(output / 'commands.json', commands)
    authority = {'schema': 'hepta.hia.store-file-capture-original-authority.v1',
         'status': 'ORIGINAL_ONLY', 'inputs_sha256': complete_pin, 'count': len(cases),
         'ordered_ids': [x['id'] for x in cases],
         'first': {'path': str(left.absolute()), 'sha256': sha256(left_raw).hexdigest()},
         'second': {'path': str(right.absolute()), 'sha256': sha256(right_raw).hexdigest()},
         'runtime': sys.version, 'runtime_version': list(sys.version_info[:3]),
         'implementation': platform.python_implementation(), 'commands_sha256': sha256((output / 'commands.json').read_bytes()).hexdigest(),
         'candidate_executed': False}
    if left.read_bytes() != left_raw or right.read_bytes() != right_raw:
        raise ValueError('complete original bytes changed before freeze')
    write(output / 'original-authority.json', authority)
    return output / 'original-authority.json'

def compare(output, original, lane, manifest=None):
    output, original = Path(output), Path(original)
    output.mkdir(mode=0o700)
    authority_path = original / 'original-authority.json'
    authority_raw, authority, authority_pin = captured_json(authority_path)
    inputs_raw = (original / 'complete-inputs.json').read_bytes()
    if sha256(inputs_raw).hexdigest() != authority['inputs_sha256']:
        raise ValueError('complete frozen input differs')
    receipt, report, report_raw = child(output, 'candidate', lane, original / 'complete-inputs.json',
                                       authority=authority_path, manifest=manifest)
    if report['ordered_ids'] != authority['ordered_ids'] or report['count'] != authority['count']:
        raise ValueError('candidate scope differs from complete original authority')
    if sha256(report_raw).hexdigest() != receipt['report_sha256']:
        raise ValueError('aggregate inner report differs from confirmed child receipt')
    if authority_path.read_bytes() != authority_raw or (original / 'complete-inputs.json').read_bytes() != inputs_raw:
        raise ValueError('original authority or inputs changed')
    if (output / 'candidate/report.json').read_bytes() != report_raw:
        raise ValueError('candidate inner report changed before aggregate write')
    write(output / 'comparison.json', {'schema': 'hepta.hia.store-file-capture-comparison.v1',
          'lane': lane, 'count': report['count'], 'differences': report['differences'],
          'authority_sha256': authority_pin, 'inner_report_sha256': receipt['report_sha256'],
          'command': receipt, 'whole_stack_qualified': False})
    return output / 'comparison.json'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--originals', type=Path)
    parser.add_argument('--lane', choices=('vm', 'native'))
    parser.add_argument('--manifest', type=Path)
    args = parser.parse_args()
    if args.originals is None:
        if args.lane or args.manifest:
            parser.error('original-only mode has no candidate arguments')
        originals(args.output)
    else:
        if args.lane is None:
            parser.error('candidate comparison requires a lane')
        compare(args.output, args.originals, args.lane, args.manifest)
if __name__ == '__main__':
    main()
