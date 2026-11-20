"""Seal original observation bytes at their existing canonical capture points.

The original observer, oracle, complete bodies and inputs remain frozen.
This independent writer records immutable equality operands and separately
preserves the live observations immediately before their existing release.
It does not collect garbage, reset interpreter history or alter exceptions.
"""
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

DERIVED_FAULT_INPUTS_SHA256 = '02acdbdcc68c03c91b94b478cfa9438a7a24e29f68761700d2cbbe0937ffb114'
OBSERVER_SOURCE = 'tools/observe_hia_service_inspection_immutable_originals.py'
CAPTURE_POLICY = 'immutable-original-canonical-operands.v1'


def frozen_record(case_id, first_bytes, second_bytes, canonical):
    """Write the exact already-observed bytes, never the live containers."""
    return (b'{"canonical_equal":' + (b'true' if first_bytes == second_bytes else b'false')
            + b',"case_id":' + canonical(case_id) + b',"first":' + first_bytes
            + b',"second":' + second_bytes + b'}\n')


def late_observation(frozen_bytes, live, canonical):
    """Preserve a complete later snapshot; only trace suffixes are admissible."""
    frozen = json.loads(frozen_bytes)
    live_bytes = canonical(live)
    later = json.loads(live_bytes)
    first_trace, late_trace = frozen['trace'], later['trace']
    prefix_preserved = canonical(late_trace[:len(first_trace)]) == canonical(first_trace)
    fields_preserved = (canonical({key: value for key, value in frozen.items() if key != 'trace'})
                        == canonical({key: value for key, value in later.items() if key != 'trace'}))
    passed = prefix_preserved and fields_preserved
    return {'capture_sha256': sha256(frozen_bytes).hexdigest(),
            'capture_trace_length': len(first_trace),
            'later_complete': later, 'later_sha256': sha256(live_bytes).hexdigest(),
            'trace_prefix_preserved': prefix_preserved,
            'all_nontrace_fields_preserved': fields_preserved,
            'late_suffix': late_trace[len(first_trace):] if prefix_preserved else None,
            'status': 'PASS' if passed else 'HOLD'}


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
    observer_raw = (ROOT/OBSERVER_SOURCE).read_bytes()
    observer_pin = {'path': OBSERVER_SOURCE, 'bytes': len(observer_raw),
                    'sha256': sha256(observer_raw).hexdigest()}
    late_integrity_errors=[]
    runtime={'python':sys.version,'implementation':platform.python_implementation(),
             'version':list(sys.version_info[:3])}
    begin=time.monotonic()
    started=[]; stopped=[]; mismatches=[]; faults_not_observed=[]; observer_errors=[]
    basis={}
    def group(name,cases,expected_fault=False):
        count=0
        with (output/(name+'.jsonl')).open('xb') as stream, \
             (output/(name+'-tracebacks.jsonl')).open('xb') as rawlog, \
             (output/(name+'-late-observations.jsonl')).open('xb') as latelog:
            for case in cases:
                started.append(case['id'])
                try:
                    first,first_tb=observe_case(case)
                    first_bytes=canonical(first)
                    if name=='base' and case['id'] in inputs['fault_basis_ids']:
                        basis[case['id']]=(case,first_bytes)
                    second,second_tb=observe_case(case)
                    second_bytes=canonical(second)
                    equal=first_bytes==second_bytes
                    if not equal:
                        mismatches.append(case['id'])
                    if expected_fault and (json.loads(first_bytes)['fault_hits']!=1
                                           or json.loads(second_bytes)['fault_hits']!=1):
                        faults_not_observed.append(case['id'])
                    stream.write(frozen_record(case['id'],first_bytes,second_bytes,canonical));stream.flush()
                    rawlog.write(canonical({'case_id':case['id'],
                        'first_raw_traceback':first_tb,'second_raw_traceback':second_tb})+b'\n')
                    rawlog.flush()
                    first_late = late_observation(first_bytes,first,canonical)
                    second_late = late_observation(second_bytes,second,canonical)
                    if first_late['status']!='PASS' or second_late['status']!='PASS':
                        late_integrity_errors.append(case['id'])
                    latelog.write(canonical({'case_id':case['id'],'first':first_late,
                        'second':second_late,
                        'phase':'before_existing_observation_reference_release'})+b'\n')
                    latelog.flush()
                    first_late=second_late=None
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
            case,observation_bytes=basis[case_id]
            observation=json.loads(observation_bytes)
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
    frozen_fault_domain_matches = sha256(fault_raw).hexdigest()==DERIVED_FAULT_INPUTS_SHA256
    if not frozen_fault_domain_matches:
        raise ValueError('complete derived fault input differs from the independent original freeze')
    fault_count=group('faults',fault_cases,True)
    stable=(identity_raw==(DIRECTORY/'source-identity.json').read_bytes()
            and all((ROOT/name).read_bytes()==raw for name,raw in pins.items())
            and (ROOT/OBSERVER_SOURCE).read_bytes()==observer_raw)
    all_planned=[case['id'] for case in inputs['cases']]+[case['id'] for case in fault_cases]
    passed=(stable and frozen_fault_domain_matches and not late_integrity_errors
            and not mismatches and not faults_not_observed and not observer_errors
            and started==stopped==all_planned and base_count==inputs['case_count']
            and len(basis)==len(inputs['fault_basis_ids']) and fault_count>0)
    files={p.name:{'bytes':p.stat().st_size,'sha256':sha256(p.read_bytes()).hexdigest()}
           for p in output.iterdir() if p.is_file()}
    report={'schema':'hepta.hia.service-inspection-original-observations.v2',
        'status':'PASS' if passed else 'HOLD','scope':'ORIGINAL_ONLY_FINITE_SAME_RUNTIME',
        'runtime':runtime,'wall_seconds':time.monotonic()-begin,'base_count':base_count,
        'fault_count':fault_count,'actual_original_invocations':2*(base_count+fault_count),
        'planned':all_planned,'started':started,'stopped':stopped,
        'mismatches':mismatches,'faults_not_observed':faults_not_observed,
        'observer_errors':observer_errors,'source_identity_sha256':sha256(identity_raw).hexdigest(),
        'source_pins':identity['files'],'source_unchanged':stable,'files':files,
        'observer_source':observer_pin,'capture_policy':CAPTURE_POLICY,
        'canonical_equality_uses_frozen_bytes':True,
        'stored_first_and_second_are_exact_equality_operands':True,
        'late_integrity_errors':late_integrity_errors,
        'late_observations_phase':'before_existing_observation_reference_release',
        'late_records_replace_expected_observations':False,
        'all_future_finalizers_accounted':False,
        'forced_GC_or_heat_reset_or_added_traceback_clearing':False,
        'derived_fault_inputs_sha256':sha256(fault_raw).hexdigest(),
        'independent_frozen_fault_domain_matches':frozen_fault_domain_matches,
        'native_or_VM_or_SQL_or_compiler_executed':False,
        'complete_input_equivalence':False,'whole_native_closed':False,
        'all_runtime_or_specialization_histories_proved':False}
    (output/'report.json').write_bytes(canonical(report)+b'\n')
    print(json.dumps({key:report[key] for key in ('status','base_count','fault_count','actual_original_invocations','wall_seconds')}))
    return 0 if passed else 1


if __name__=='__main__':
    raise SystemExit(main())
