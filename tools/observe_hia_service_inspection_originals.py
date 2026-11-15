"""Observe both complete frozen handlers before any candidate execution."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
DIRECTORY = ROOT / 'tests/fixtures/hia_service_inspection_original_bc011'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--expected-source-identity-sha256', required=True)
    args = parser.parse_args()
    identity_raw = (DIRECTORY/'source-identity.json').read_bytes()
    if sha256(identity_raw).hexdigest() != args.expected_source_identity_sha256:
        raise ValueError('original observer identity is not the independently frozen input')
    identity = json.loads(identity_raw)
    pins = {name:(ROOT/name).read_bytes() for name in identity['files']}
    if any(sha256(raw).hexdigest() != identity['files'][name] for name,raw in pins.items()):
        raise ValueError('original-only observer source differs')
    if any(name=='hepta' or name.startswith('hepta.') for name in sys.modules):
        raise ValueError('original-only observer process already imported product')
    from tests.hia_service_inspection_oracle import observe_case, canonical
    cases_raw = pins['tests/fixtures/hia_service_inspection_original_bc011/cases.json']
    inputs = json.loads(cases_raw)
    output=args.evidence
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    runtime={'python':sys.version,'implementation':platform.python_implementation(),
             'version':list(sys.version_info[:3])}
    begin=time.monotonic()
    started=[]; stopped=[]; mismatches=[]; faults_not_observed=[]; observer_errors=[]
    basis={}
    def group(name,cases,expected_fault=False):
        count=0
        with (output/(name+'.jsonl')).open('xb') as stream, (output/(name+'-tracebacks.jsonl')).open('xb') as rawlog:
            for case in cases:
                started.append(case['id'])
                try:
                    first,first_tb=observe_case(case)
                    first_bytes=canonical(first)
                    if name=='base' and case['id'] in inputs['fault_basis_ids']:
                        basis[case['id']]=(case,first)
                    second,second_tb=observe_case(case)
                    second_bytes=canonical(second)
                    equal=first_bytes==second_bytes
                    if not equal:
                        mismatches.append(case['id'])
                    if expected_fault and (first['fault_hits']!=1 or second['fault_hits']!=1):
                        faults_not_observed.append(case['id'])
                    stream.write(canonical({'case_id':case['id'],'first':first,'second':second,
                        'canonical_equal':equal})+b'\n');stream.flush()
                    rawlog.write(canonical({'case_id':case['id'],
                        'first_raw_traceback':first_tb,'second_raw_traceback':second_tb})+b'\n')
                    rawlog.flush()
                    first=second=first_tb=second_tb=first_bytes=second_bytes=None
                except BaseException as error:
                    observer_errors.append({'case_id':case['id'],'class':type(error).__name__,
                                            'message':str(error)})
                    rawlog.write(canonical({'case_id':case['id'],
                        'observer_error':traceback.format_exc()})+b'\n');rawlog.flush()
                finally:
                    stopped.append(case['id'])
                    count+=1
        return count
    base_count=group('base',inputs['cases'])
    fault_cases=[]
    if set(basis)==set(inputs['fault_basis_ids']):
        for case_id in inputs['fault_basis_ids']:
            case,observation=basis[case_id]
            for event in observation['trace']:
                if event.get('at') not in ('before','after'):
                    continue
                for family in inputs['fault_types']:
                    spec={'operation':event['operation'],'at':event['at'],
                          'occurrence':event['occurrence'],'kind':family}
                    digest=sha256(canonical(spec)).hexdigest()[:24]
                    fault_cases.append({**case,'id':'fault-'+case_id+'-'+digest,'fault':spec})
    else:
        observer_errors.append({'phase':'derive','message':'a frozen basis was not observed'})
    fault_document={'schema':'hepta.hia.service-inspection-derived-original-faults.v1',
        'inputs_sha256':sha256(cases_raw).hexdigest(),'basis':inputs['fault_basis_ids'],
        'fault_types':inputs['fault_types'],'cases':fault_cases,
        'derived_from_original_observation_only':True,'candidate_executed':False}
    # This complete finite input is frozen before its first fault observation.
    fault_raw=canonical(fault_document)+b'\n'
    (output/'derived-fault-inputs.json').write_bytes(fault_raw)
    fault_count=group('faults',fault_cases,True)
    stable=(identity_raw==(DIRECTORY/'source-identity.json').read_bytes()
            and all((ROOT/name).read_bytes()==raw for name,raw in pins.items()))
    all_planned=[case['id'] for case in inputs['cases']]+[case['id'] for case in fault_cases]
    passed=(stable and not mismatches and not faults_not_observed and not observer_errors
            and started==stopped==all_planned and base_count==inputs['case_count']
            and len(basis)==len(inputs['fault_basis_ids']) and fault_count>0)
    files={p.name:{'bytes':p.stat().st_size,'sha256':sha256(p.read_bytes()).hexdigest()}
           for p in output.iterdir() if p.is_file()}
    report={'schema':'hepta.hia.service-inspection-original-observations.v1',
        'status':'PASS' if passed else 'HOLD','scope':'ORIGINAL_ONLY_FINITE_SAME_RUNTIME',
        'runtime':runtime,'wall_seconds':time.monotonic()-begin,'base_count':base_count,
        'fault_count':fault_count,'actual_original_invocations':2*(base_count+fault_count),
        'planned':all_planned,'started':started,'stopped':stopped,
        'mismatches':mismatches,'faults_not_observed':faults_not_observed,
        'observer_errors':observer_errors,'source_identity_sha256':sha256(identity_raw).hexdigest(),
        'source_pins':identity['files'],'source_unchanged':stable,'files':files,
        'native_or_VM_or_SQL_or_compiler_executed':False,
        'complete_input_equivalence':False,'whole_native_closed':False,
        'all_runtime_or_specialization_histories_proved':False}
    (output/'report.json').write_bytes(canonical(report)+b'\n')
    print(json.dumps({key:report[key] for key in ('status','base_count','fault_count','actual_original_invocations','wall_seconds')}))
    return 0 if passed else 1


if __name__=='__main__':
    raise SystemExit(main())
