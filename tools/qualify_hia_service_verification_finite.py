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
from tests.hia_service_verification_oracle import canonical
INPUTS = ROOT / 'tests/fixtures/hia_service_verification_original_r12/cases.json'
OBSERVER = ROOT / 'tests/hia_service_verification_observer.py'

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
    parent=Path(parent).absolute();inputs=Path(inputs).absolute()
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
            process = subprocess.Popen(command, cwd=ROOT, env={key:value for key,value in os.environ.items()
                                            if not key.startswith(('HEPTA_HIA_', 'PYTHON'))},
                                       stdout=out, stderr=err, start_new_session=True)
            write(parent / (label + '.start.json'), {'schema': 'hepta.hia.verification-child-start.v1',
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
    value = {'schema': 'hepta.hia.verification-child-result.v1', 'command': command,
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
            or (lane in ('vm', 'native') and report['native_or_VM_entries'] <= 0)
            or report.get('retained_body_calls') != 0):
        raise ValueError('child runtime, original source custody or complete comparison differs')
    for name, pin in report['files'].items():
        if Path(name).name != name or sha256((directory/name).read_bytes()).hexdigest() != pin:
            raise ValueError('child observations differ from their actual report')
    if (directory / 'report.json').read_bytes() != raw:
        raise ValueError('child report changed after its receipt')
    return value, report, raw

def originals(output, *, complete=True):
    output=Path(output).absolute()
    output.mkdir(mode=0o700)
    input_raw, inputs, input_pin = captured_json(INPUTS)
    consumed={str(INPUTS):input_raw}
    def consume(path, expected=None):
        path=Path(path).absolute()
        raw=path.read_bytes()
        if expected is not None and sha256(raw).hexdigest()!=expected:
            raise ValueError('actually consumed original bytes differ from child receipt')
        previous=consumed.setdefault(str(path),raw)
        if raw!=previous:
            raise ValueError('original bytes changed between uses')
        return raw
    base={'schema':'hepta.hia.service-verification-base-inputs.v1','cases':inputs['base_cases']}
    base_pin=write(output/'base-inputs.json',base)
    consume(output/'base-inputs.json',base_pin)
    commands=[];children={}
    def observe(label,input_path,wanted):
        receipt,report,report_raw=child(output,label,'original',input_path)
        commands.append(receipt)
        directory=output/label
        consume(directory/'report.json',receipt['report_sha256'])
        if consume(directory/'report.json')!=report_raw:
            raise ValueError('original report differs from captured child result')
        result_raw=consume(output/(label+'.result.json'))
        if json.loads(result_raw)!=receipt:
            raise ValueError('original child result differs from returned receipt')
        start_raw=consume(output/(label+'.start.json'))
        for suffix in ('stdout','stderr'):
            consume(output/(label+'.'+suffix+'.log'),receipt[suffix+'_sha256'])
        files={}
        for name,pin in report['files'].items():
            if Path(name).name!=name:
                raise ValueError('original raw file is not a basename')
            raw=consume(directory/name,pin)
            files[name]={'path':str((directory/name).absolute()),'sha256':sha256(raw).hexdigest()}
        actual_input=consume(input_path)
        if (type(report['count']) is not int or report['count']!=len(wanted)
                or report['ordered_ids']!=[x['id'] for x in wanted]
                or report['inputs_sha256']!=sha256(actual_input).hexdigest()):
            raise ValueError('complete original input scope differs')
        children[label]={'report_path':str(directory/'report.json'),
            'report_sha256':sha256(report_raw).hexdigest(),
            'result_path':str(output/(label+'.result.json')),
            'result_sha256':sha256(result_raw).hexdigest(),
            'start_path':str(output/(label+'.start.json')),
            'start_sha256':sha256(start_raw).hexdigest(),
            'input_path':str(Path(input_path).absolute()),
            'inputs_sha256':sha256(actual_input).hexdigest(),'files':files}
        return consume(directory/'observations.jsonl',report['files']['observations.jsonl'])
    base_first=observe('basis-first',output/'base-inputs.json',base['cases'])
    base_second=observe('basis-second',output/'base-inputs.json',base['cases'])
    if base_first!=base_second:
        raise ValueError('two complete base originals differ')
    first_label,second_label='basis-first','basis-second'
    cases=list(base['cases']);complete_inputs=base
    if complete:
        by_id={x['id']:x for x in base['cases']};basis={}
        for line in base_first.splitlines():
            row=json.loads(line)
            if row['id'] in inputs['fault_basis']:
                basis[row['id']]=row
        if set(basis)!=set(inputs['fault_basis']):
            raise ValueError('declared verification original basis is incomplete')
        for case_id in inputs['fault_basis']:
            for event in basis[case_id]['events']:
                if 'occurrence' not in event:
                    continue
                for family in inputs['fault_families']:
                    fault={'label':event['event'],'occurrence':event['occurrence'],'family':family}
                    case=dict(by_id[case_id])
                    case['id']='derived.'+case_id+'.'+sha256(canonical(fault)).hexdigest()[:16]
                    case['base_fault']=fault
                    cases.append(case)
        complete_inputs={'schema':'hepta.hia.service-verification-complete-inputs.v1',
                         'basis_inputs_sha256':input_pin,'cases':cases,
                         'derived_only_from_original':True}
    complete_pin=write(output/'complete-inputs.json',complete_inputs)
    consume(output/'complete-inputs.json',complete_pin)
    derived_pin=write(output/'derived-input-freeze.json',{'inputs_sha256':complete_pin,'count':len(cases),
          'scope':'BASE_AND_ALL_DECLARED_FAULTS' if complete else 'ALL_FIXED_BASE_CASES',
          'ordered_ids':[x['id'] for x in cases],
          'basis_observations_sha256':sha256(base_first).hexdigest()})
    consume(output/'derived-input-freeze.json',derived_pin)
    if complete:
        first_label,second_label='complete-first','complete-second'
        left_raw=observe(first_label,output/'complete-inputs.json',cases)
        right_raw=observe(second_label,output/'complete-inputs.json',cases)
    else:
        left_raw,right_raw=base_first,base_second
    if left_raw!=right_raw:
        raise ValueError('complete original lanes differ')
    commands_pin=write(output/'commands.json',commands)
    consume(output/'commands.json',commands_pin)
    authority={'schema':'hepta.hia.service-verification-original-authority.v1',
        'status':'ORIGINAL_ONLY','inputs_sha256':complete_pin,'count':len(cases),
        'ordered_ids':[x['id'] for x in cases],
        'first':dict(children[first_label]['files']['observations.jsonl'],label=first_label),
        'second':dict(children[second_label]['files']['observations.jsonl'],label=second_label),
        'runtime':sys.version,'runtime_version':list(sys.version_info[:3]),
        'implementation':platform.python_implementation(),
        'scope':'BASE_AND_ALL_DECLARED_FAULTS' if complete else 'ALL_FIXED_BASE_CASES',
        'declared_inputs':{'path':str(INPUTS),'sha256':input_pin},
        'base_inputs_sha256':base_pin,'derived_input_freeze_sha256':derived_pin,
        'children':children,'child_order':list(children),
        'commands_sha256':commands_pin,'candidate_executed':False}
    for name,raw in consumed.items():
        if Path(name).read_bytes()!=raw:
            raise ValueError('consumed original/report/log bytes changed before authority freeze')
    write(output/'original-authority.json',authority)
    return output/'original-authority.json'

def compare(output, original, lane, manifest=None):
    output, original = Path(output).absolute(), Path(original).absolute()
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
    write(output / 'comparison.json', {'schema': 'hepta.hia.service-verification-comparison.v1',
          'lane': lane, 'count': report['count'], 'differences': report['differences'],
          'authority_sha256': authority_pin, 'inner_report_sha256': receipt['report_sha256'],
          'command': receipt, 'whole_stack_qualified': False})
    return output / 'comparison.json'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--originals', type=Path)
    parser.add_argument('--lane', choices=('vm', 'native', 'unselected'))
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--base-only', action='store_true')
    args = parser.parse_args()
    if args.originals is None:
        if args.lane or args.manifest:
            parser.error('original-only mode has no candidate arguments')
        originals(args.output, complete=not args.base_only)
    else:
        if args.base_only:
            parser.error('candidate scope comes only from the frozen original authority')
        if args.lane is None:
            parser.error('candidate comparison requires a lane')
        compare(args.output, args.originals, args.lane, args.manifest)
if __name__ == '__main__':
    main()
