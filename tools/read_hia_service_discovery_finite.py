"""Independent complete raw finite readback; imports no product module."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path

def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()

class Captures:
    def __init__(self):
        self.raw={}
    def bytes(self,path,pin=None):
        path=Path(path).absolute();name=str(path)
        if name not in self.raw:
            self.raw[name]=path.read_bytes()
        raw=self.raw[name]
        if pin is not None and sha256(raw).hexdigest()!=pin:
            raise ValueError('actually consumed bytes differ from their recorded SHA: '+name)
        return raw
    def json(self,path,pin=None):
        raw=self.bytes(path,pin)
        return raw,json.loads(raw),sha256(raw).hexdigest()
    def finish(self):
        for name,raw in self.raw.items():
            if Path(name).read_bytes()!=raw:
                raise ValueError('finite evidence changed during exact readback: '+name)

def integer(value,wanted=None):
    if type(value) is not int or (wanted is not None and value!=wanted):
        raise ValueError('strict finite integer metadata differs')
    return value

def checked_command(captures,parent,label,result,report,report_pin,timeout,lane,input_path):
    parent=Path(parent)
    start_raw,start,start_pin=captures.json(parent/(label+'.start.json'))
    for name in ('pid','pgid','started_time_ns'):
        integer(start[name]);integer(result[name],start[name])
    integer(result['ended_time_ns'])
    integer(result['returncode'],0)
    integer(result['timeout_seconds'],timeout);integer(start['timeout_seconds'],timeout)
    integer(result['cleanup_seconds'],3);integer(start['cleanup_seconds'],3)
    if result['pid']<=0 or result['pgid']!=result['pid']:
        raise ValueError('finite owned process identity differs')
    if (result['timeout'] is not False or result['cleanup_error'] is not None
            or result['reaped'] is not True or result['cleanup']['after']!=[]
            or result['cleanup']['reaped'] is not True
            or result['report_sha256']!=report_pin
            or result['command']!=start['command'] or result['cwd']!=start['cwd']):
        raise ValueError('finite child lacks an owned clean original-budget terminal')
    command=result['command']
    prefix=[report['executable'],'-I','-B']
    if (command[:3]!=prefix or Path(command[3]).name!='hia_service_discovery_observer.py'
            or command[4:10]!=['--lane',lane,'--inputs',str(input_path),'--output',str(parent/label)]):
        raise ValueError('finite actual child command differs')
    for suffix in ('stdout','stderr'):
        captures.bytes(parent/(label+'.'+suffix+'.log'),result[suffix+'_sha256'])
    return start_pin

def checked_report(captures,directory,report,*,lane,inputs,input_pin,authority):
    directory=Path(directory)
    ids=[x['id'] for x in inputs['cases']]
    integer(report['count'],len(ids));integer(report['differences'],0)
    integer(report['retained_body_calls'],0)
    entries=integer(report['native_or_VM_entries'])
    if ((entries>0)!=(lane in ('native','vm')) or entries<0 or report['lane']!=lane
            or report['ordered_ids']!=ids or report['inputs_sha256']!=input_pin
            or report['source_before']!=report['source_after']
            or report['runtime']!=authority['runtime']
            or report['runtime_version']!=authority['runtime_version']
            or report['implementation']!=authority['implementation']):
        raise ValueError('same-runtime complete finite child report differs')
    required={'observations.jsonl','raw-tracebacks.jsonl','differences.jsonl'}
    if set(report['files'])!=required:
        raise ValueError('finite raw evidence domain differs')
    files={name:captures.bytes(directory/name,pin) for name,pin in report['files'].items()}
    observations=[json.loads(line) for line in files['observations.jsonl'].splitlines()]
    tracebacks=[json.loads(line) for line in files['raw-tracebacks.jsonl'].splitlines()]
    if ([row['id'] for row in observations]!=ids or [row['id'] for row in tracebacks]!=ids
            or any(type(row['tracebacks']) is not list for row in tracebacks)):
        raise ValueError('complete original observation/traceback stream differs')
    if lane=='original':
        if files['differences.jsonl']!=b'' or report['candidate_source_manifest_image_pins']!={}:
            raise ValueError('original authority contains a candidate comparison')
    else:
        for name,pin in report['candidate_source_manifest_image_pins'].items():
            captures.bytes(name,pin)
    return files

def read(original,candidate):
    original,candidate=Path(original).absolute(),Path(candidate).absolute()
    held=Captures()
    authority_raw,authority,authority_pin=held.json(original/'original-authority.json')
    inputs_raw,inputs,inputs_pin=held.json(original/'complete-inputs.json',authority['inputs_sha256'])
    base_raw,base,base_pin=held.json(original/'base-inputs.json',authority['base_inputs_sha256'])
    declared_raw,declared,declared_pin=held.json(authority['declared_inputs']['path'],authority['declared_inputs']['sha256'])
    derived_raw,derived,derived_pin=held.json(original/'derived-input-freeze.json',authority['derived_input_freeze_sha256'])
    commands_raw,commands,commands_pin=held.json(original/'commands.json',authority['commands_sha256'])
    ids=[x['id'] for x in inputs['cases']]
    integer(authority['count'],len(ids));integer(derived['count'],len(ids))
    if (authority['schema']!='hepta.hia.service-discovery-original-authority.v1'
            or authority['status']!='ORIGINAL_ONLY' or authority['candidate_executed'] is not False
            or authority['ordered_ids']!=ids or derived['ordered_ids']!=ids
            or derived['inputs_sha256']!=inputs_pin or base['cases']!=declared['base']):
        raise ValueError('finite original authority/input identity differs')
    complete=authority['scope']=='BASE_AND_ALL_DECLARED_FAULTS'
    order=['basis-first','basis-second']+(['complete-first','complete-second'] if complete else [])
    if (authority['scope'] not in ('BASE_AND_ALL_DECLARED_FAULTS','ALL_FIXED_BASE_CASES')
            or authority['child_order']!=order or set(authority['children'])!=set(order)
            or len(commands)!=len(order)):
        raise ValueError('original complete two-lane command domain differs')
    child_files={};original_sources=None
    for index,label in enumerate(order):
        link=authority['children'][label];directory=original/label
        expected_input=original/('base-inputs.json' if label.startswith('basis-') else 'complete-inputs.json')
        if (Path(link['report_path'])!=directory/'report.json'
                or Path(link['result_path'])!=original/(label+'.result.json')
                or Path(link['start_path'])!=original/(label+'.start.json')
                or Path(link['input_path'])!=expected_input):
            raise ValueError('original child evidence path binding differs')
        case_inputs=base if label.startswith('basis-') else inputs
        case_pin=base_pin if label.startswith('basis-') else inputs_pin
        if link['inputs_sha256']!=case_pin:
            raise ValueError('original child consumed a different input')
        raw,report,pin=held.json(link['report_path'],link['report_sha256'])
        result_raw,result,result_pin=held.json(link['result_path'],link['result_sha256'])
        if canonical(result)!=canonical(commands[index]):
            raise ValueError('original command list differs from actual child result')
        start_pin=checked_command(held,original,label,result,report,pin,600,'original',expected_input)
        if start_pin!=link['start_sha256']:
            raise ValueError('original child start receipt changed')
        files=checked_report(held,directory,report,lane='original',inputs=case_inputs,
                             input_pin=case_pin,authority=authority)
        if set(link['files'])!=set(files):
            raise ValueError('original child raw-file link domain differs')
        for name,raw in files.items():
            expected_link={'path':str(directory/name),'sha256':sha256(raw).hexdigest()}
            if link['files'][name]!=expected_link:
                raise ValueError('original consumed bytes differ from authority child link')
        if original_sources is None:original_sources=report['source_before']
        elif report['source_before']!=original_sources:
            raise ValueError('original source identities changed across the fresh lanes')
        child_files[label]=files
    basis=child_files['basis-first']['observations.jsonl']
    if (basis!=child_files['basis-second']['observations.jsonl']
            or sha256(basis).hexdigest()!=derived['basis_observations_sha256']):
        raise ValueError('complete original derivation basis differs')
    expected=list(base['cases'])
    if complete:
        rule=declared['fault_rule'];by_id={row['id']:row for row in base['cases']}
        basis_rows={row['id']:row for row in (json.loads(line) for line in basis.splitlines())}
        for case_id in rule['basis']:
            for hit in basis_rows[case_id]['hits']:
                for family in rule['families']:
                    for retained in rule['retain_traceback']:
                        case=dict(by_id[case_id])
                        case['id']=case_id+'.fault.'+str(hit['index'])+'.'+family+'.retain'+str(int(retained))
                        case['fault']={'index':hit['index'],'label':hit['label'],'family':family}
                        case['retain_traceback']=retained;case.pop('base_fault',None)
                        expected.append(case)
        if inputs['basis_inputs_sha256']!=declared_pin or inputs['derived_only_from_original'] is not True:
            raise ValueError('complete fault inputs lack their original basis')
    if canonical(expected)!=canonical(inputs['cases']) or derived['scope']!=authority['scope']:
        raise ValueError('complete original-derived input domain changed')
    final_labels=order[-2:]
    original_bytes=child_files[final_labels[0]]['observations.jsonl']
    if original_bytes!=child_files[final_labels[1]]['observations.jsonl']:
        raise ValueError('two complete original observation streams differ')
    for key,label in zip(('first','second'),final_labels):
        expected_link=dict(authority['children'][label]['files']['observations.jsonl'],label=label)
        if authority[key]!=expected_link:
            raise ValueError('selected original authority lane differs')
    comparison_raw,comparison,comparison_pin=held.json(candidate/'comparison.json')
    report_raw,report,report_pin=held.json(candidate/'candidate/report.json')
    command_raw,command,command_pin=held.json(candidate/'candidate.result.json')
    lane=report['lane']
    if lane not in ('vm','native','unselected'):
        raise ValueError('candidate lane differs')
    if (comparison['authority_sha256']!=authority_pin or comparison['inner_report_sha256']!=report_pin
            or canonical(command)!=canonical(comparison['command'])
            or comparison['count']!=len(ids) or comparison['lane']!=lane):
        raise ValueError('finite candidate aggregate receipt differs')
    integer(comparison['count'],len(ids));integer(comparison['differences'],0)
    checked_command(held,candidate,'candidate',command,report,report_pin,1800,lane,original/'complete-inputs.json')
    suffix=command['command'][10:]
    expected_suffix=['--expected',str(original/'original-authority.json')]
    if lane=='native':
        if len(suffix)!=4 or suffix[:2]!=expected_suffix or suffix[2]!='--manifest':
            raise ValueError('native candidate manifest/authority command differs')
    elif suffix!=expected_suffix:
        raise ValueError('candidate original-authority command differs')
    files=checked_report(held,candidate/'candidate',report,lane=lane,inputs=inputs,
                         input_pin=inputs_pin,authority=authority)
    if report['source_before']!=original_sources or files['observations.jsonl']!=original_bytes:
        raise ValueError('complete candidate source/observation bytes differ')
    diffs=[json.loads(line) for line in files['differences.jsonl'].splitlines()]
    if len(diffs)!=len(ids):
        raise ValueError('raw finite differences are incomplete')
    for case_id,diff in zip(ids,diffs):
        if (type(diff.get('equal_bytes')) is not bool
                or diff!={'id':case_id,'equal_bytes':True,'differences':[]}):
            raise ValueError('complete typed finite comparison differs')
    held.finish()
    return {'status':'FINITE_READBACK_PASS','count':len(ids),'lane':lane,
            'original_authority_sha256':authority_pin,'candidate_report_sha256':report_pin,
            'actual_entries':report['native_or_VM_entries'],'whole_native':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--originals',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    value=read(a.originals,a.candidate)
    with a.output.open('xb') as f:f.write(canonical(value)+b'\n')
if __name__=='__main__':
    main()
