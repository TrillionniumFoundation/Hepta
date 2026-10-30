#!/usr/bin/env python3
"""Read final CI receipts only; do not execute native code or rerun CRC."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import zipfile

ROOT=Path(__file__).resolve().parent
HEAD='46d88bd18b1b3dadb246e92eb22c49fe44ec2d72'
PROTOCOL='75f5f0bef5b5c49020b14b83c7c1f9257f989c5f2f0b3a365f5b7ba858329948'


def identity(path):
    raw=Path(path).read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':sha256(raw).hexdigest()}


def main():
    api=json.loads((ROOT/'API_STATUS.json').read_bytes())
    artifact=api['artifacts']['artifacts'][0]
    assert artifact['workflow_run']['head_sha']==HEAD
    assert artifact['workflow_run']['id']==41039944804
    job=api['jobs']['jobs'][0]
    assert job['id']==124010002605 and job['status']=='completed'
    archive=ROOT/'hia-crc-context-41039944804.zip'
    archive_id=identity(archive)
    assert archive_id['bytes']==artifact['size_in_bytes']
    assert 'sha256:'+archive_id['sha256']==artifact['digest']
    with zipfile.ZipFile(archive) as z:
        for member,name in [('study/RESULT.json','RESULT.json'),('study-summary.json','study-summary.json'),('controls.log','controls.log')]:
            (ROOT/name).write_bytes(z.read(member))
        r=json.loads(z.read('study/RESULT.json'))
        frozen=z.read('study/frozen-protocol.json')
        assert sha256(frozen).hexdigest()==PROTOCOL
        assert frozen==z.read('preregistered-protocol.json')
        p=json.loads(frozen)
        assert p['max_study_wall_ns']==120000000000 and p['expected_observations']==210
        assert p['requests_per_trace']==64 and p['calls_per_trace']==65536 and p['trials_per_phase']==7
        assert r['expected_source']==HEAD==z.read('source-sha.txt').decode().strip()
        assert r['source_state_before']==r['source_state_after']
        assert r['source_state_before']['head']==HEAD and r['source_state_before']['status']==''
        assert r['source_inputs_unchanged'] is True
        assert r['release']['complete'] is True
        assert job['conclusion']=='success' and r['qualified'] is True
        assert 0<r['whole_study_wall_ns']<=p['max_study_wall_ns']
        assert len(r['samples'])==210 and r['contexts_attempted']==2856
        expected_schedule=[]
        for phase in ('training','validation'):
            for trial in range(7):
                workloads=p['workloads'][trial%3:]+p['workloads'][:trial%3]
                for workload in workloads:
                    shift=(trial+p['workloads'].index(workload))%5
                    arms=p['arms'][shift:]+p['arms'][:shift]
                    for arm in reversed(arms) if trial%2 else arms:
                        expected_schedule.append((phase,trial,workload,arm))
        assert [tuple(s[k] for k in ('phase','trial','workload','arm')) for s in r['samples']]==expected_schedule
        counts=Counter()
        for sample in r['samples']:
            assert sample['status']=='completed'
            count=64 if sample['arm']=='fresh_child_baseline' else 1
            assert sample['context_count']==len(sample['contexts'])==count
            assert sample['completed_requests']==64 and sample['calls']==65536
            native_ns=0
            for record in sample['contexts']:
                member='study/'+record['path'].split('/study/',1)[1]
                raw=z.read(member)
                assert len(raw)==record['bytes'] and sha256(raw).hexdigest()==record['sha256']
                context=json.loads(raw)
                assert context['status']=='completed' and context['returncode']==0
                assert context['prefix']['complete'] and context['prefix']['prefix_error'] is None
                assert context['owned_child_cleanup']=='confirmed_by_bounded_capture'
                assert context['replay_permitted'] is False
                native_ns+=context['outer_wall_ns']
                counts['contexts_hash_checked_and_complete']+=1
                counts['completed_requests_in_context_receipts']+=len(context['prefix']['completed_requests'])
                counts['calls_in_context_receipts']+=sum(v['calls'] for v in context['prefix']['completed_requests'])
            assert native_ns==sample['native_outer_wall_ns']
        assert counts=={'contexts_hash_checked_and_complete':2856,'completed_requests_in_context_receipts':13440,'calls_in_context_receipts':13762560}
        codes={label:row['code']['sha256'] for label,row in r['bank']['candidates'].items()}
        distinct=len(set(codes.values()))==3
        rows=[]
        for phase in ('training','validation'):
            for workload in p['workloads']:
                values={arm:[s['native_outer_wall_ns'] for s in r['samples'] if
                             (s['phase'],s['workload'],s['arm'])==(phase,workload,arm)] for arm in p['arms']}
                assert all(len(v)==7 for v in values.values())
                gross=min(v for arm in ('coalesced_baseline','coalesced_ieee_only','coalesced_castagnoli_only')
                          for v in values[arm])-max(values['coalesced_poly_dispatch'])
                rows.append({'phase':phase,'workload':workload,
                    'arm_envelopes_ns':{a:{'min':min(v),'max':max(v)} for a,v in values.items()},
                    'batching_lower_envelope_ns':min(values['fresh_child_baseline'])-max(values['coalesced_baseline']),
                    'guarded_increment_lower_envelope_ns':gross,'cold_net_lower_envelope_ns':gross-r['cold_setup_ns'],
                    'conditional_break_even_traces':(r['cold_setup_ns']+gross-1)//gross if gross>0 else None})
        assert rows==r['economics']['rows']
        gate=distinct and all(v['cold_net_lower_envelope_ns']>0 for v in rows)
        assert r['economics']['economic_gate_passed']==gate
        assert r['status']==('qualified_cold_opportunity' if gate else 'qualified_no_cold_opportunity')
        control_text=z.read('controls.log').decode()
        match=re.search(r'Ran (\d+) tests in ([0-9.]+)s\s+OK\s*$',control_text)
        assert match and int(match.group(1))==54
        assert not re.search(r'\.\.\. skipped|\(skipped=',control_text)
        result={
            'schema':'hepta.hia.final-crc-ci-receipt-check.v1','head_sha':HEAD,
            'run_id':41039944804,'job_id':job['id'],'artifact_id':artifact['id'],
            'job_conclusion':job['conclusion'],'artifact':archive_id,'official_digest_matches':True,
            'source_before_after_identical_and_clean':True,'protocol_sha256':PROTOCOL,
            'observations':len(r['samples']),**dict(counts),
            'max_study_wall_ns':p['max_study_wall_ns'],'whole_study_wall_ns':r['whole_study_wall_ns'],
            'cold_setup_ns':r['cold_setup_ns'],
            'trace_preparation_wall_ns':sum(s['trace_preparation_wall_ns'] for s in r['samples']),
            'native_outer_wall_ns':sum(s['native_outer_wall_ns'] for s in r['samples']),
            'qualified':r['qualified'],'status':r['status'],'economic_gate_recomputed':gate,
            'controls':{'tests':int(match.group(1)),'reported_wall_seconds':float(match.group(2)),'skips':0,'failures':0,'errors':0},
            'c4fe_output_audit_reused_as_this_cohort_output_proof':False,
            'full_bytewise_crc_recomputation_performed':False,
            'scope':'Official artifact digest, exact source/protocol, schedule, all context receipt hashes/completion and economic arithmetic were checked. The c4fe full independent bytewise audit remains a separate cohort; it was not repeated or reassigned here.',
            'repository_files_written':0,'native_or_model_executions':0,'workflow_reruns_triggered':0,
        }
        (ROOT/'VERIFICATION.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    main()
