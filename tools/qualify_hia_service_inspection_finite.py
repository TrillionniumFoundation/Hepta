"""Compare a real selected image to all independently frozen original cases."""
from __future__ import annotations
import argparse
from collections import Counter
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import struct
import sys
import time
import traceback

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):
    sys.path.insert(0,str(ROOT))
IDENTITY='tests/fixtures/hia_service_inspection_original_bc011/source-identity.json'
IDENTITY_SHA256='c89710abd3c416ff8b8ac5b7588b27e083ed03f39e8cfba47960396345f43070'


def digest(path):
    value=sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1<<20),b''):
            value.update(chunk)
    return value.hexdigest()

def validate_original_group(directory, group, cases, *, file_pins):
    """Admit every immutable row and its complete separate late observation."""
    from tools.observe_hia_service_inspection_immutable_originals import late_observation
    def canonical(value):
        return json.dumps(value,sort_keys=True,separators=(',',':'),
                          ensure_ascii=True,allow_nan=False).encode()
    directory=Path(directory)
    raw_digest,late_digest=sha256(),sha256()
    raw_bytes=late_bytes=0
    with (directory/(group+'.jsonl')).open('rb') as stream, \
         (directory/(group+'-late-observations.jsonl')).open('rb') as late_stream:
        for case in cases:
            line,late_line=stream.readline(),late_stream.readline()
            if not line or not late_line:
                raise ValueError('complete immutable original row stream was truncated')
            raw_digest.update(line);late_digest.update(late_line)
            raw_bytes+=len(line);late_bytes+=len(late_line)
            row,late=json.loads(line),json.loads(late_line)
            if (set(row)!={'case_id','first','second','canonical_equal'}
                    or row['case_id']!=case['id'] or row['canonical_equal'] is not True
                    or row['first']['case_id']!=case['id'] or row['second']['case_id']!=case['id']
                    or canonical(row['first'])!=canonical(row['second'])
                    or set(late)!={'case_id','first','second','phase'}
                    or late['case_id']!=case['id']
                    or late['phase']!='before_existing_observation_reference_release'):
                raise ValueError('original per-case identity or immutable equality differs')
            for lane in ('first','second'):
                expected=late_observation(canonical(row[lane]),late[lane]['later_complete'],canonical)
                if expected['status']!='PASS' or canonical(late[lane])!=canonical(expected):
                    raise ValueError('original late evidence changed the sealed observation')
        if stream.read(1) or late_stream.read(1):
            raise ValueError('original immutable or late stream has undeclared rows')
    consumed={group+'.jsonl':{'bytes':raw_bytes,'sha256':raw_digest.hexdigest()},
              group+'-late-observations.jsonl':{'bytes':late_bytes,'sha256':late_digest.hexdigest()}}
    if any(value!=file_pins.get(name) for name,value in consumed.items()):
        raise ValueError('actual consumed original observation bytes differ from the frozen pins')



def admit_originals(path,wanted):
    path=Path(path)
    raw=path.read_bytes()
    if sha256(raw).hexdigest()!=wanted:
        raise ValueError('original report is not the external frozen pin')
    report=json.loads(raw)
    identity=(ROOT/IDENTITY).read_bytes()
    if sha256(identity).hexdigest()!=IDENTITY_SHA256:
        raise ValueError('original source identity differs')
    sources=json.loads(identity)['files']
    if (report.get('schema')!='hepta.hia.service-inspection-original-observations.v2'
            or report.get('status')!='PASS' or report.get('scope')!='ORIGINAL_ONLY_FINITE_SAME_RUNTIME'
            or report.get('source_identity_sha256')!=IDENTITY_SHA256
            or report.get('source_pins')!=sources or report.get('source_unchanged') is not True
            or report.get('runtime',{}).get('version')!=list(sys.version_info[:3])
            or report.get('runtime',{}).get('implementation')!=platform.python_implementation()
            or report.get('planned')!=report.get('started') or report.get('planned')!=report.get('stopped')
            or report.get('mismatches') or report.get('observer_errors') or report.get('faults_not_observed')):
        raise ValueError('complete original observations are unavailable in this runtime')
    from tools.observe_hia_service_inspection_immutable_originals import (
        OBSERVER_SOURCE,CAPTURE_POLICY,DERIVED_FAULT_INPUTS_SHA256)
    observer_raw=(ROOT/OBSERVER_SOURCE).read_bytes()
    observer_pin={'path':OBSERVER_SOURCE,'bytes':len(observer_raw),
                  'sha256':sha256(observer_raw).hexdigest()}
    required_files={'base.jsonl','base-tracebacks.jsonl','base-late-observations.jsonl',
                    'faults.jsonl','faults-tracebacks.jsonl','faults-late-observations.jsonl',
                    'derived-fault-inputs.json'}
    if (report.get('observer_source')!=observer_pin
            or report.get('capture_policy')!=CAPTURE_POLICY
            or report.get('canonical_equality_uses_frozen_bytes') is not True
            or report.get('stored_first_and_second_are_exact_equality_operands') is not True
            or report.get('independent_frozen_fault_domain_matches') is not True
            or report.get('derived_fault_inputs_sha256')!=DERIVED_FAULT_INPUTS_SHA256
            or report.get('late_integrity_errors')!=[]
            or report.get('late_observations_phase')!='before_existing_observation_reference_release'
            or report.get('late_records_replace_expected_observations') is not False
            or report.get('forced_GC_or_heat_reset_or_added_traceback_clearing') is not False
            or set(report.get('files',{}))!=required_files):
        raise ValueError('immutable original observer or capture policy differs')
    for name,expected in sources.items():
        if digest(ROOT/name)!=expected:
            raise ValueError('original observer source changed: '+name)
    for name,record in report['files'].items():
        if Path(name).name!=name or not name:
            raise ValueError('original evidence name is not a basename')
        file=path.parent/name
        if file.stat().st_size!=record['bytes'] or digest(file)!=record['sha256']:
            raise ValueError('original observation bytes differ')
    base_name='tests/fixtures/hia_service_inspection_original_bc011/cases.json'
    base_raw=(ROOT/base_name).read_bytes()
    fault_raw=(path.parent/'derived-fault-inputs.json').read_bytes()
    if (sha256(base_raw).hexdigest()!=sources[base_name]
            or {'bytes':len(fault_raw),'sha256':sha256(fault_raw).hexdigest()}
               !=report['files']['derived-fault-inputs.json']
            or sha256(fault_raw).hexdigest()!=DERIVED_FAULT_INPUTS_SHA256):
        raise ValueError('actual consumed original input bytes differ from the frozen pins')
    base=json.loads(base_raw)
    faults=json.loads(fault_raw)
    planned=[row['id'] for row in base['cases']]+[row['id'] for row in faults['cases']]
    if (planned!=report['planned'] or len(base['cases'])!=report['base_count']
            or len(faults['cases'])!=report['fault_count']
            or faults.get('derived_from_original_observation_only') is not True
            or faults.get('candidate_executed') is not False):
        raise ValueError('original complete case order differs')
    validate_original_group(path.parent,'base',base['cases'],file_pins=report['files'])
    validate_original_group(path.parent,'faults',faults['cases'],file_pins=report['files'])
    return raw,report,base['cases'],faults['cases']


def run(manifest,original_report,original_sha256,evidence):
    from tests.hia_service_inspection_oracle import observe_case, canonical
    from tools.observe_hia_service_inspection_immutable_originals import late_observation
    from hepta import hia_agent_service as service_api
    from hepta import hia_service_inspection_native as native
    from hepta.hia_service_inspection_native import (
        ServiceInspectionFrame,installed_service_inspection,REQUEST_MAGIC,OUTPUT_BYTES)
    from tools.build_hia_service_inspection import INPUTS
    from hepta.hia_native_delivery import custody_snapshot
    if custody_snapshot():
        raise ValueError('finite comparison started with retained delivery custody')
    source_before={name:digest(ROOT/name) for name in INPUTS}
    original_raw,original,bases,faults=admit_originals(original_report,original_sha256)
    evidence=Path(evidence);evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    manifest=Path(manifest).resolve(strict=True)
    manifest_raw=manifest.read_bytes()
    image=installed_service_inspection(str(manifest))
    image_path=manifest.parent/json.loads(manifest_raw)['image_path']
    image_bytes=image_path.read_bytes()
    entry=image._entry
    counts=Counter();frames=Counter();active_case=['outside-case']
    per_case=Counter()
    def observed_entry(source,size,output,capacity,state,extent):
        head=struct.unpack('<8Q',ctypes.string_at(source,64))
        value=entry(source,size,output,capacity,state,extent)
        if head[0]!=REQUEST_MAGIC or value!=OUTPUT_BYTES:
            raise AssertionError('candidate entry did not return the complete declared receipt')
        counts[str(head[1])]+=1;per_case[active_case[0]]+=1
        return value
    # Exercise the real lazy public dispatch and real fresh image admission.
    # Only the constructor receives the frozen fixture's globals/local layout.
    # The factory returns the frame; the unmodified public wrapper calls finish.
    constructor_context=[None]
    def constructor(admitted,mode,service,arguments,**kwargs):
        current=constructor_context[0]
        if current is None or admitted is not image or kwargs:
            raise AssertionError('unexpected public inspection constructor context')
        namespace,original_code=current
        names=original_code.co_varnames+original_code.co_cellvars
        if tuple(names)!=tuple(service_api._SERVICE_INSPECTION_LOCAL_NAMES[mode]):
            raise AssertionError('public original local layout differs')
        frames[str(mode)]+=1
        return ServiceInspectionFrame(admitted,mode,service,arguments,namespace=namespace,
            global_builtins=namespace['__builtins__'],local_names=names)
    def owner(mode,service,arguments,namespace,original_code):
        if constructor_context[0] is not None:
            raise AssertionError('finite observer unexpectedly reentered its fixture')
        constructor_context[0]=(namespace,original_code)
        try:
            method=(service_api.HIAAgentService._hia_inspect if mode==1
                    else service_api.HIAAgentService._hia_candidate)
            return method(service,arguments)
        finally:
            constructor_context[0]=None
    def forbidden_original(*args,**kwargs):
        raise AssertionError('selected public finite route called a retained complete handler')
    saved_constructor=native.ServiceInspectionFrame
    saved_inspect=service_api._SERVICE_INSPECTION_INSPECT_REFERENCE
    saved_candidate=service_api._SERVICE_INSPECTION_CANDIDATE_REFERENCE
    saved_class_inspect=service_api.HIAAgentService._hia_inspect_reference
    saved_class_candidate=service_api.HIAAgentService._hia_candidate_reference
    missing=object()
    previous_selector=os.environ.get(native.SELECTOR,missing)
    started=[];stopped=[];mismatches=[];errors=[]
    difference_files=[];late_integrity_errors=[]
    (evidence/'differences').mkdir()
    begin=time.monotonic()
    image._entry=observed_entry
    native.ServiceInspectionFrame=constructor
    service_api._SERVICE_INSPECTION_INSPECT_REFERENCE=forbidden_original
    service_api._SERVICE_INSPECTION_CANDIDATE_REFERENCE=forbidden_original
    service_api.HIAAgentService._hia_inspect_reference=forbidden_original
    service_api.HIAAgentService._hia_candidate_reference=forbidden_original
    os.environ[native.SELECTOR]=str(manifest)
    try:
        with (evidence/'candidate-observations.jsonl').open('xb') as output, \
             (evidence/'candidate-tracebacks.jsonl').open('xb') as rawlog, \
             (evidence/'candidate-late-observations.jsonl').open('xb') as latelog:
            for group,cases in [('base',bases),('faults',faults)]:
                expected_digest=sha256();expected_bytes=0
                with (Path(original_report).parent/(group+'.jsonl')).open('rb') as expected_stream:
                    for case in cases:
                        expected_line=expected_stream.readline()
                        if not expected_line:
                            raise ValueError('original full observation table was truncated')
                        expected_digest.update(expected_line);expected_bytes+=len(expected_line)
                        expected=json.loads(expected_line)
                        if (expected['case_id']!=case['id'] or not expected['canonical_equal']
                                or canonical(expected['first'])!=canonical(expected['second'])):
                            raise ValueError('original per-case identity or equality differs')
                        active_case[0]=case['id'];started.append(case['id'])
                        try:
                            actual,raw_trace=observe_case(case,owner)
                            # Seal the actual operand at the unchanged comparison point.
                            # Later destructor events remain separately observable.
                            actual_bytes=canonical(actual)
                            original_bytes=canonical(expected['first'])
                            equal=actual_bytes==original_bytes
                            frozen_actual=json.loads(actual_bytes)
                            if not equal:
                                mismatches.append(case['id'])
                                name='differences/'+str(len(mismatches)).zfill(6)+'-'+sha256(case['id'].encode()).hexdigest()[:16]+'.json'
                                difference=canonical({'case_id':case['id'],'original':expected['first'],'candidate':frozen_actual})
                                (evidence/name).write_bytes(difference)
                                difference_files.append({'path':name,'bytes':len(difference),'sha256':sha256(difference).hexdigest()})
                            output.write(canonical({'case_id':case['id'],'actual':frozen_actual,
                                'original_sha256':sha256(original_bytes).hexdigest(),
                                'canonical_equal':equal})+b'\n');output.flush()
                            rawlog.write(canonical({'case_id':case['id'],'raw_traceback':raw_trace})+b'\n');rawlog.flush()
                            late=late_observation(actual_bytes,actual,canonical)
                            if late['status']!='PASS':
                                late_integrity_errors.append(case['id'])
                            latelog.write(canonical({'case_id':case['id'],'actual':late,
                                'phase':'after_immutable_candidate_comparison'})+b'\n');latelog.flush()
                        except BaseException as error:
                            errors.append({'case_id':case['id'],'class':type(error).__name__,'message':str(error)})
                            rawlog.write(canonical({'case_id':case['id'],'observer_error':traceback.format_exc()})+b'\n');rawlog.flush()
                        finally:
                            stopped.append(case['id'])
                    if expected_stream.read(1):
                        raise ValueError('original full table has undeclared rows')
                if ({'bytes':expected_bytes,'sha256':expected_digest.hexdigest()}
                        !=original['files'][group+'.jsonl']):
                    raise ValueError('actual consumed comparison originals differ from the frozen pin')
    finally:
        image._entry=entry
        native.ServiceInspectionFrame=saved_constructor
        service_api._SERVICE_INSPECTION_INSPECT_REFERENCE=saved_inspect
        service_api._SERVICE_INSPECTION_CANDIDATE_REFERENCE=saved_candidate
        service_api.HIAAgentService._hia_inspect_reference=saved_class_inspect
        service_api.HIAAgentService._hia_candidate_reference=saved_class_candidate
        if previous_selector is missing:
            os.environ.pop(native.SELECTOR,None)
        else:
            os.environ[native.SELECTOR]=previous_selector
    stable=(source_before=={name:digest(ROOT/name) for name in INPUTS}
        and manifest.read_bytes()==manifest_raw and image_path.read_bytes()==image_bytes
        and Path(original_report).read_bytes()==original_raw
        and all((Path(original_report).parent/name).stat().st_size==row['bytes']
                and digest(Path(original_report).parent/name)==row['sha256']
                for name,row in original['files'].items()))
    expected_ids=original['planned']
    remaining = custody_snapshot()
    passed=(stable and not remaining and not late_integrity_errors
        and started==stopped==expected_ids and not mismatches and not errors
        and frames['1']>0 and frames['2']>0 and all(counts[str(event)]>0 for event in (0,1,2,3,4)))
    report={'schema':'hepta.hia.service-inspection-finite-native.v1','status':'PASS' if passed else 'HOLD',
        'scope':'FINITE_COMPLETE_ORIGINAL_METHODS_SAME_RUNTIME','base_count':len(bases),'fault_count':len(faults),
        'planned':expected_ids,'started':started,'stopped':stopped,'mismatches':mismatches,'errors':errors,
        'complete_mismatch_files':difference_files,
        'candidate_comparison_uses_immutable_operand_bytes':True,
        'late_integrity_errors':late_integrity_errors,
        'late_records_replace_expected_or_candidate_observations':False,
        'observation_files':{name:{'bytes':(evidence/name).stat().st_size,
                                  'sha256':digest(evidence/name)}
            for name in ('candidate-observations.jsonl','candidate-tracebacks.jsonl',
                         'candidate-late-observations.jsonl')},
        'source_pins':source_before,'source_and_images_unchanged':stable,
        'manifest':str(manifest),'manifest_sha256':sha256(manifest_raw).hexdigest(),
        'image_sha256':sha256(image_bytes).hexdigest(),'original_report':str(original_report),
        'original_report_sha256':original_sha256,'native_entries':dict(counts),'entries_by_case':dict(per_case),
        'remaining_delivery_custody':remaining,
        'runtime':{'version':list(sys.version_info[:3]),'python':sys.version,'implementation':platform.python_implementation()},
        'frames_by_mode':dict(frames),'wall_seconds':time.monotonic()-begin,
        'actual_public_dispatcher_and_loader':True,
        'retained_complete_handlers_poisoned':True,
        'constructor_only_injects_original_fixture_namespace':True,
        'actual_sql_filesystem_compiler_providers_executed':False,
        'whole_input_or_native_closure':False,'production_budget_changed':False}
    (evidence/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--original-report',type=Path,required=True)
    parser.add_argument('--original-report-sha256',required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    report=run(args.manifest,args.original_report,args.original_report_sha256,args.evidence)
    print(json.dumps({key:report[key] for key in ('status','base_count','fault_count','wall_seconds','frames_by_mode')}))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
