#!/usr/bin/env python3
"""Verify retained repair bytes and process outcomes without native execution."""
import ast
import base64
from collections import Counter
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import tarfile

COMMIT='8c88308eb9b6a8acf612ae9e8f7d9a7d89f5a776'
PUBLISHED='4ac39e626acd7f78e2f66708be741e78308b4e6a'
TREE='99a2273d45a333a1a9cc87110742399e7413d512'
ORIGINAL_ROOT='/tmp/hepta-task-io-observation-fix-20261027/'
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def require(value,message):
    if not value: raise ValueError(message)

def identity(raw,row):
    require(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'retained byte identity differs')

def path_name(name):
    p=PurePosixPath(name)
    require(type(name) is str and name and not p.is_absolute() and '..' not in p.parts
            and '\\' not in name and '\0' not in name and p.as_posix()==name,'unsafe archive name')
    return name

def unpack(directory,manifest):
    encoded=b''
    require(manifest['schema']=='hepta.task-io-observation-repair.archive.v1'
            and manifest['source_commit']==COMMIT,'archive source identity')
    for index,row in enumerate(manifest['parts']):
        require(row['path']=='native-records.tar.xz.b64.part%02d'%(index+1),'part order')
        data=(directory/row['path']).read_bytes();identity(data,row)
        require(len(data)<=3500000,'archive part bound');encoded+=data
    require(len(encoded)==manifest['encoded_bytes']<=16*1024*1024
            and sha(encoded)==manifest['encoded_sha256'],'encoded archive identity')
    packed=base64.b64decode(b''.join(encoded.split()),validate=True)
    require(len(packed)==manifest['packed_bytes'] and sha(packed)==manifest['packed_sha256'],'packed archive identity')
    decoder=lzma.LZMADecompressor(memlimit=96*1024*1024)
    raw=decoder.decompress(packed,max_length=128*1024*1024+1)
    require(decoder.eof and not decoder.unused_data and len(raw)<=128*1024*1024,'bounded xz stream')
    require(len(raw)==manifest['tar_bytes'] and sha(raw)==manifest['tar_sha256'],'tar identity')
    expected={path_name(row['path']):row for row in manifest['members']}
    require(len(expected)==len(manifest['members'])==manifest['member_count']<=512,'member inventory')
    found={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            name=path_name(member.name)
            require(member.type==tarfile.REGTYPE and not member.pax_headers and name in expected
                    and name not in found and member.size<=16*1024*1024,'ordinary bounded member')
            require(member.mode==expected[name]['mode'],'retained mode')
            data=archive.extractfile(member).read(member.size+1);identity(data,expected[name]);found[name]=data
    require(set(found)==set(expected) and sum(map(len,found.values()))==manifest['uncompressed_bytes'],
            'complete archive denominator')
    return found

def process_references(value,members):
    checked=0
    if isinstance(value,list):
        return sum(process_references(row,members) for row in value)
    if not isinstance(value,dict): return 0
    if {'path','bytes','sha256'}<=set(value) and isinstance(value['path'],str) and value['path'].startswith(ORIGINAL_ROOT):
        name='records/'+value['path'][len(ORIGINAL_ROOT):]
        identity(members[name],value);checked+=1
        if 'base64' in value:
            require(base64.b64decode(value['base64'],validate=True)==members[name],'process raw/base64 link')
            require(value['text']==members[name].decode('utf-8'),'process raw/text link')
    return checked+sum(process_references(row,members) for row in value.values())

def verify(directory):
    directory=Path(directory)
    seal=json.loads((directory/'MANIFEST.json').read_bytes())
    require(seal['source_commit']==COMMIT,'bundle commit')
    actual={p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    require(actual==set(seal['files'])|{'MANIFEST.json'},'sidecar inventory')
    sidecars={}
    for name,row in seal['files'].items():
        p=directory/path_name(name);require(not p.is_symlink(),'sidecar symlink')
        raw=p.read_bytes();identity(raw,row);sidecars[name]=raw
    manifest=json.loads(sidecars['archive-manifest.json']);members=unpack(directory,manifest)
    origins=json.loads(sidecars['source-identities.json'])
    require(origins['source_commit']==COMMIT and origins['published_commit']==PUBLISHED
            and origins['source_tree']==origins['published_tree']==TREE,'published equivalent source tree')
    for oid,encoded in origins['git_commit_objects'].items():
        raw=base64.b64decode(encoded,validate=True)
        require(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==oid,'Git commit object')
        if oid in (COMMIT,PUBLISHED):require(raw.splitlines()[0]==('tree '+TREE).encode(),'Git source tree')
    fixed_sources={}
    for row in origins['files']:
        raw=members[row['archived_path']];identity(raw,row)
        require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob_sha1'],'Git source blob')
        if row['commit']==COMMIT:fixed_sources[row['path']]=raw
    before=json.loads(members['records/fixed-source-identity.json'])
    after=json.loads(members['records/fixed-source-identity-after.json'])
    require(before==after and before['source_commit']==COMMIT,'fixed source changed during qualification')
    require({r['path']:r['sha256'] for r in before['source_files']}=={n:sha(v) for n,v in fixed_sources.items()},'fixed source input inventory')
    report=json.loads(members['records/fixed-three-rounds.json'])
    require(report['ok'] is True and report['status']=='passed' and report['repeats']==3,'fixed actual result')
    task_names=set(fixed_sources)-{'tests/test_task_io.py','docs/TASK_TREE_IO_COMPOSITION.md'}
    require(len(task_names)==10 and report['source_files']=={n:sha(fixed_sources[n]) for n in task_names},'fixed task source inputs')
    cases=['pipeline','cancellation','recovery','positive','lost_wakeup','budget_bypass','reservation_leak','buffer_leak','drop_lock_inversion','native_alias']
    require([r['name'] for r in report['cases']]==cases and all(r['status']=='passed' for r in report['cases']),'fixed planned cases')
    outcomes=[]
    for row in report['cases']:
        if row['name']=='native_alias':
            require(row['runs']==[] and row['binary'] is None and row['build']['returncode']!=0
                    and 'E0499' in row['build']['stderr']['text'],'actual native alias compile rejection');continue
        require(len(row['runs'])==3,'fixed repeats')
        for index,trial in enumerate(row['runs']):
            require(trial['trial']==index and trial['binary_before']==trial['binary_after']==row['binary'],'trial/binary identity')
            p=trial['process'];outcomes.append((p['status'],p['returncode']))
            if row['name'] in ('lost_wakeup','drop_lock_inversion'):
                require(p['status']=='timed_out' and p['timed_out'] is True and p['returncode'] is None
                        and p['elapsed_ns']>=2000000000,'actual wrong-runtime timeout')
            else:
                require(p['status']=='completed' and p['timed_out'] is False,'actual native completion')
                require(p['returncode']==0 if row['kind']!='mutant' else p['returncode']!=0,'actual native exit')
    control_tree=ast.parse(fixed_sources['tools/qualify_task_io.py'])
    counts=next(ast.literal_eval(n.value) for n in control_tree.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='CONTROL_COUNTS' for t in n.targets))
    metrics=[]
    for trial in report['cases'][3]['runs']:
        row=trial['metrics'];require(json.loads(trial['process']['stdout']['text'])==row,'metrics/raw stdout')
        require(all(row[k]==v for k,v in counts.items()) and 208<=row['tracked_allocations']<=272
                and row['tracked_allocations']==row['tracked_frees'] and row['live_buffers']==0,'native control denominators')
        metrics.append(row)
    require(len(report['rejections'])==10 and all(r['report']['ok'] is False for r in report['rejections']),'source rejection denominator')
    refs=process_references(report,members)
    baseline=json.loads(members['records/baseline/report.json']);refs+=process_references(baseline,members)
    original_task_inputs={n:sha(fixed_sources[n]) for n in task_names}
    original_task_inputs['tools/fixtures/task_io_controls.rs']=sha(members['source/base/tools/fixtures/task_io_controls.rs'])
    require(baseline['source_files']==original_task_inputs,'baseline retained source inputs')
    require(baseline['runs']['held_arc_boundary']['execution']['returncode']==0,'original held-Arc positive')
    failed=baseline['runs']['unfenced_closed_assertion']['execution']
    require(failed['returncode']==-6 and 'left: 1' in failed['stderr']['text'] and 'right: 0' in failed['stderr']['text'],
            'deterministic old-observation abort')
    old=json.loads(members['ci44/task_io_composition.json']);require(old['source_files']==baseline['source_files'],'baseline source differs from failed CI')
    old_case=old['cases'][3];old_trial=old_case['runs'][2]
    require(old_case['name']=='positive' and old_case['status']=='failed' and old_trial['process']['returncode']==-6,'original CI failure')
    identity(members['ci44/task_io_composition.files/positive.rs'],old_case['source'])
    for channel in ('stdout','stderr'):
        identity(members['ci44/task_io_composition.files/positive-run-2.'+channel+'.bin'],old_trial['process'][channel])
    ci_summary=json.loads(sidecars['ci44-failure-summary.json'])
    old_processes=[r['process'] for c in old['cases'] for r in c['runs'] if 'process' in r]
    require(ci_summary['cases']==len(old['cases']) and ci_summary['recorded_native_processes']==len(old_processes)
            and ci_summary['case_statuses']==dict(Counter(c['status'] for c in old['cases']))
            and ci_summary['process_statuses']==dict(Counter(p['status'] for p in old_processes))
            and ci_summary['native_exit_codes']==dict(Counter(str(p['returncode']) for p in old_processes)),
            'original CI completed/failing/timeout denominators')
    review=json.loads(sidecars['independent-review.json'])
    require(review['source_commit']==COMMIT and review['source_tree']==TREE
            and review['fixed_report_read']['sha256']==sha(members['records/fixed-three-rounds.json'])
            and all(sha(fixed_sources[n])==digest for n,digest in review['reviewed_file_sha256'].items()),
            'independent review input identity')
    require(re.search(r'Ran 12 tests in [0-9.]+s\s+OK\s*\Z',sidecars['targeted-unit.log'].decode()) is not None,'unit terminal denominator')
    for copy,member in [('fixed-three-rounds.json','records/fixed-three-rounds.json'),('fixed-three-rounds.log','records/fixed-three-rounds.log'),
                        ('targeted-unit.log','records/targeted-unit.log'),('baseline-counterexample.json','records/baseline/report.json'),
                        ('ci44-failure-summary.json','records/ci44-failure-summary.json')]:require(sidecars[copy]==members[member],'original sidecar copy')
    summary={'verified':True,'source_commit':COMMIT,'published_commit':PUBLISHED,'source_tree':TREE,
        'archive_members':len(members),'uncompressed_bytes':sum(map(len,members.values())),
        'retained_source_files':len(origins['files']),'fixed_source_inputs':len(fixed_sources),
        'fixed_cases':10,'fixed_repeats':3,'actual_native_runs':len(outcomes),
        'native_outcomes':{str(k):v for k,v in Counter(outcomes).items()},'unit_tests':12,'source_rejections':10,
        'positive_metrics':metrics,'retained_artifact_and_stream_links_checked':refs,
        'original_44_abort_preserved':True,'baseline_task_inputs_match_failed_ci':True,
        'native_execution_repeated':False,'performance_remeasured':False,'whole_project_blockers_closed':False,
        'scope':'sealed originals and data consistency; source/Git path correspondence checked at capture, no new native execution or general lifetime proof'}
    if 'verification.json' in sidecars:
        require(json.loads(sidecars['verification.json'])==summary,'retained verification summary differs')
    return summary

if __name__=='__main__':print(json.dumps(verify(Path(__file__).resolve().parent),indent=2,sort_keys=True))
