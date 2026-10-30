#!/usr/bin/env python3
"""Read-only independent audit of retained CI output; never launch its code."""
from __future__ import annotations

from base64 import b64decode
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
import zipfile

ROOT=Path(__file__).resolve().parent
HEAD='c4fe3fa00e9ba9356dc99a98cf43f0a8385be5c5'
PROTOCOL='75f5f0bef5b5c49020b14b83c7c1f9257f989c5f2f0b3a365f5b7ba858329948'
ZIP_SHA='6907e821e521b2f8536293df1b60d8088cef8dd3ffabee7976ea658bbf7db649'
MASK64=(1<<64)-1


def wire(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')


def identity(path):
    raw=Path(path).read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':sha256(raw).hexdigest()}


def expected_crc(values, polynomial, seed):
    state=seed
    checksum=0
    for value in values:
        state^=value
        for bit in range(8):
            low=state&1
            state>>=1
            if low:
                state^=polynomial
        checksum=(checksum*1099511628211+state)&MASK64
    return ('returned',state,checksum)


def main():
    archive=ROOT/'hia-crc-context-41038692291.zip'
    assert identity(archive)['sha256']==ZIP_SHA
    api=json.loads((ROOT/'API_STATUS.json').read_bytes())
    artifact=api['artifacts']['artifacts'][0]
    assert artifact['workflow_run']['head_sha']==HEAD
    assert artifact['workflow_run']['id']==41038692291
    assert artifact['digest']=='sha256:'+ZIP_SHA
    assert api['jobs']['jobs'][0]['status']=='completed'
    assert api['jobs']['jobs'][0]['conclusion']=='success'
    with zipfile.ZipFile(archive) as z:
        report=json.loads(z.read('study/RESULT.json'))
        frozen=z.read('study/frozen-protocol.json')
        assert sha256(frozen).hexdigest()==PROTOCOL
        assert z.read('preregistered-protocol.json')==frozen
        p=json.loads(frozen)
        assert p['max_study_wall_ns']==120000000000
        assert p['expected_observations']==210
        assert p['requests_per_trace']==64 and p['calls_per_trace']==65536
        assert p['bytes_per_request']==1024 and p['trials_per_phase']==7
        assert report['expected_source']==HEAD
        assert z.read('source-sha.txt').decode().strip()==HEAD
        assert report['source_state_before']==report['source_state_after']
        assert report['source_state_before']['head']==HEAD
        assert report['source_state_before']['status']==''
        assert report['source_inputs_unchanged'] is True
        assert report['whole_study_wall_ns']<=p['max_study_wall_ns']
        assert report['release']['complete'] is True
        assert report['qualified'] is True
        assert report['contexts_attempted']==2856
        assert len(report['samples'])==210
        checked_files=0
        def bound_file(record):
            nonlocal checked_files
            member='study/'+record['path'].split('/study/',1)[1]
            raw=z.read(member)
            assert len(raw)==record['bytes']
            assert sha256(raw).hexdigest()==record['sha256']
            checked_files+=1
            return raw
        data={phase:bound_file(record) for phase,record in report['inputs'].items()}
        assert all(len(data[phase])==p['data'][phase]['bytes'] for phase in data)
        bank=report['bank']
        labels=bank['labels']
        assert labels==['baseline','ieee_guard','castagnoli_guard']
        code_hashes={}
        image_hashes={}
        for label,entry in bank['candidates'].items():
            assert entry['core_sha256']==p['kernel']['canonical_sha256'][label]
            assert entry['translation']['status']=='proved'
            assert entry['lowering']['status']=='verified'
            image_hashes[label]=entry['compilation']['artifact_sha256']
            assert sha256(z.read('study/bank/'+label+'.so')).hexdigest()==image_hashes[label]
            assert entry['native_differential']['artifact_sha256']==image_hashes[label]
            code_hashes[label]=entry['code']['sha256']
        assert sha256(z.read('study/bank/context_driver')).hexdigest()==bank['driver']['sha256']
        assert sha256(z.read('study/bank/context_driver.c')).hexdigest()==bank['driver']['source_sha256']
        wanted=[]
        for phase in ('training','validation'):
            for trial in range(7):
                workloads=p['workloads'][trial%3:]+p['workloads'][:trial%3]
                for workload in workloads:
                    shift=(trial+p['workloads'].index(workload))%5
                    arms=p['arms'][shift:]+p['arms'][:shift]
                    for arm in reversed(arms) if trial%2 else arms:
                        wanted.append((phase,trial,workload,arm))
        assert [tuple(row[k] for k in ('phase','trial','workload','arm')) for row in report['samples']]==wanted
        oracle={}
        counts=Counter()
        for sample in report['samples']:
            assert sample['status']=='completed'
            phase,workload,arm=sample['phase'],sample['workload'],sample['arm']
            plan=json.loads(bound_file(sample['plan']))
            assert len(plan)==64
            for i,request in enumerate(plan):
                polynomial=(0xedb88320 if workload=='ieee' else 0x82f63b78 if workload=='castagnoli'
                            else (0xedb88320 if i%2==0 else 0x82f63b78))
                label=('ieee_guard' if arm=='coalesced_ieee_only' else
                       'castagnoli_guard' if arm=='coalesced_castagnoli_only' else
                       ('ieee_guard' if polynomial==0xedb88320 else 'castagnoli_guard')
                       if arm=='coalesced_poly_dispatch' else 'baseline')
                values=list(data[phase][i*1024:(i+1)*1024])
                assert request=={'id':i,'candidate':label,'mode':'xor_fold','parameter':polynomial,
                                 'seed':p['seed_per_request'],'values':values}
                key=(phase,polynomial,i)
                if key not in oracle:
                    oracle[key]=expected_crc(values,polynomial,p['seed_per_request'])
            groups=[[r] for r in plan] if arm=='fresh_child_baseline' else [plan]
            assert len(sample['contexts'])==len(groups)
            native_ns=0
            loaded_labels=set()
            for group,reference in zip(groups,sample['contexts']):
                context=json.loads(bound_file(reference))
                assert context['status']=='completed' and context['returncode']==0
                assert context['owned_child_cleanup']=='confirmed_by_bounded_capture'
                assert context['execution_attempted'] is True
                assert context['online_feedback'] is False
                assert context['persistent_hia_owners']==context['persistent_hia_loans']==[]
                assert context['replay_permitted'] is False
                assert context['bank_sha256']==bank['bank_sha256']
                images=tuple(sorted({labels.index(r['candidate']) for r in group}))
                normalized=tuple((r['id'],images.index(labels.index(r['candidate'])),1,r['seed'],r['parameter'],tuple(r['values'])) for r in group)
                expectations=tuple(oracle[(phase,r['parameter'],r['id'])] for r in group)
                digest=sha256(wire({'profile':bank['profile'],'bank':bank['bank_sha256'],'images':images,
                                    'requests':normalized,'expected':expectations})).hexdigest()
                assert context['trace_sha256']==digest
                inventory=[{'artifact_sha256':image_hashes[labels[i]],'bank_index':i,'candidate':labels[i],'slot':slot}
                           for slot,i in enumerate(images)]
                assert context['planned_load_inventory']==context['loaded_inventory']==context['ready_inventory']==inventory
                prefix=context['prefix']
                assert prefix['complete'] and prefix['finish_observed'] and prefix['native_limits_observed']
                assert prefix['prefix_error'] is None and prefix['pending_request_seq'] is None
                raw=b64decode(context['raw_stdout_base64'],validate=True)
                raw_rows=[json.loads(line) for line in raw.splitlines()]
                assert all(wire(row)==line for row,line in zip(raw_rows,raw.splitlines()))
                assert raw_rows==prefix['events']
                assert b64decode(context['raw_stderr_base64'],validate=True)==b''
                assert raw_rows[-1]=={'acquired':len(images),'closed':len(images),'kind':'finish','ok':True,'trace':digest}
                actual=prefix['completed_requests']
                assert len(actual)==len(group)
                for seq,(request,result,expected) in enumerate(zip(group,actual,expectations)):
                    assert all(type(v) is int for k,v in result.items() if k not in ('kind','trace'))
                    assert result=={'calls':1024,'candidate':normalized[seq][1],'checksum':expected[2],
                                    'id':request['id'],'kind':'result','mode':1,'parameter':request['parameter'],
                                    'seed':request['seed'],'seq':seq,'state':expected[1],'trace':digest}
                    counts['native_requests_rechecked']+=1
                    counts['native_calls_covered']+=1024
                native_ns+=context['outer_wall_ns']
                loaded_labels.update(row['candidate'] for row in inventory)
                counts['contexts_rechecked']+=1
            assert sample['native_outer_wall_ns']==native_ns
            assert sample['calls']==65536 and sample['completed_requests']==64
            assert sample['context_count']==len(groups)
            assert sample['loaded_candidates']==sorted(loaded_labels)
        assert counts['contexts_rechecked']==2856
        assert counts['native_requests_rechecked']==13440
        assert counts['native_calls_covered']==13762560
        distinct=len(set(code_hashes.values()))==3
        cold=report['cold_setup_ns']
        computed=[]
        for phase in ('training','validation'):
            for workload in p['workloads']:
                values={arm:[s['native_outer_wall_ns'] for s in report['samples']
                             if (s['phase'],s['workload'],s['arm'])==(phase,workload,arm)] for arm in p['arms']}
                assert all(len(v)==7 for v in values.values())
                batching=min(values['fresh_child_baseline'])-max(values['coalesced_baseline'])
                static=min(v for arm in ('coalesced_baseline','coalesced_ieee_only','coalesced_castagnoli_only') for v in values[arm])
                increment=static-max(values['coalesced_poly_dispatch'])
                computed.append({'phase':phase,'workload':workload,
                    'arm_envelopes_ns':{arm:{'min':min(v),'max':max(v)} for arm,v in values.items()},
                    'batching_lower_envelope_ns':batching,'guarded_increment_lower_envelope_ns':increment,
                    'cold_net_lower_envelope_ns':increment-cold,
                    'conditional_break_even_traces':(cold+increment-1)//increment if increment>0 else None})
        assert report['economics']['rows']==computed
        gate=distinct and all(row['cold_net_lower_envelope_ns']>0 for row in computed)
        assert report['economics']['all_three_exported_codes_distinct']==distinct
        assert report['economics']['economic_gate_passed']==gate
        assert report['status']==('qualified_cold_opportunity' if gate else 'qualified_no_cold_opportunity')
        assert report['economics']['NDU_incremental_value_established'] is False
        assert report['economics']['online_admission_authorized'] is False
        controls=z.read('controls.log').decode()
        assert re.search(r'Ran 54 tests in 8\.631s\s+OK\s*$',controls)
        old_path=Path('/workspace/scratch/793cbcdf54ed/ci-triage-20261030/crc-000ac-study-RESULT.json')
        old=json.loads(old_path.read_bytes())
        assert old['qualified'] is False
        result={
            'schema':'hepta.hia.final-crc-ci-artifact-audit.v1',
            'workflow_run_id':41038692291,'job_id':124005799941,'artifact_id':12968099978,
            'head_sha':HEAD,'github_job_conclusion':'success','artifact':identity(archive),
            'artifact_digest_matches_github':True,'frozen_protocol_sha256':PROTOCOL,
            'observations_checked':210,**dict(counts),
            'plan_context_and_input_file_hashes_checked':checked_files,
            'all_raw_native_result_rows_match_independent_bytewise_crc':True,
            'all_trace_digests_reconstructed':True,'all_contexts_complete_with_confirmed_cleanup':True,
            'source_before_after_identical_and_clean':True,
            'whole_study_wall_ns':report['whole_study_wall_ns'],'max_study_wall_ns':p['max_study_wall_ns'],
            'cold_setup_ns':cold,
            'trace_preparation_wall_ns':sum(s['trace_preparation_wall_ns'] for s in report['samples']),
            'native_outer_wall_ns':sum(s['native_outer_wall_ns'] for s in report['samples']),
            'economic_gate_recomputed':gate,'economics':report['economics'],'qualification_status':report['status'],
            'controls':{'tests':54,'errors':0,'failures':0,'skips':0,'reported_wall_seconds':8.631},
            'old_failed_result':identity(old_path),'old_status':old['status'],
            'old_qualified':old['qualified'],'old_whole_study_wall_ns':old['whole_study_wall_ns'],
            'old_contexts_attempted':old['contexts_attempted'],
            'old_trace_preparation_wall_ns':sum(s.get('trace_preparation_wall_ns',0) for s in old['samples']),
            'no_repo_files_written':True,'new_native_or_model_executions':0,'workflow_reruns_triggered':0,
            'audit_scope':'Only retained ZIP bytes were read. Independent Python CRC calculations cover each recorded request and rolling checksum, with exact plan and trace-hash binding. No native artifact was executed. Equal repeated phase/input oracle calculations are reused only in this post-run audit; recorded study budgets and cost ledgers are unchanged.',
            'limitations':['CI completion does not establish a cold optimization opportunity; its economic gate is false.',
                           'Old and new CI runs have different completion counts and source/host observations; raw wall-time comparisons are not a controlled performance ratio.',
                           'This finite-output audit is not a machine-code refinement proof or a universal safety/performance claim.'],
        }
        (ROOT/'AUDIT.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        print(json.dumps({k:result[k] for k in ('head_sha','observations_checked','contexts_rechecked','native_requests_rechecked','native_calls_covered',
               'whole_study_wall_ns','trace_preparation_wall_ns','economic_gate_recomputed','qualification_status')}))


if __name__=='__main__':
    main()
