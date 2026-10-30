from __future__ import annotations
import hashlib, importlib.util, json, pathlib, tempfile
from unittest import mock
ROOT=pathlib.Path('/workspace/scratch/5567a9db5cf4/hepta-work')
SOURCE=ROOT/'experiments/hia_agent_assembly_recovery_20261030/run_recovery.py'
source_bytes=SOURCE.read_bytes()
spec=importlib.util.spec_from_file_location('reviewed_finalizer_recovery',SOURCE)
module=importlib.util.module_from_spec(spec)
exec(compile(source_bytes,str(SOURCE),'exec'),module.__dict__)
rows=[]
summary={'complete_valid_coverage':True,'errors':[],'descriptive_cross_family_gates':{'maintenance':False,'upgrade':False},'descriptive_assembly_vs_json_gates':{'maintenance':False,'upgrade':False}}
def stage_files(base,bad=None,symlink=False,mutate=False,deadline=False):
    evidence=base/'evidence';destination=base/'artifact';evidence.mkdir()
    safe=evidence/'raw-suite'/'fake-model'/'engine-00'/'transport-001.response.raw';safe.parent.mkdir(parents=True);safe.write_bytes(b'{"content":"fake control only"}\n')
    (evidence/'TERMINAL.json').write_text('{"status":"incomplete"}\n')
    if bad is not None: (evidence/bad).write_bytes(b'fake forbidden payload, not model weights')
    if symlink:
        outside=base/'outside.txt';outside.write_bytes(b'outside sentinel must not be followed')
        (evidence/'unsafe-link.txt').symlink_to(outside)
    original_copy=module.copy_new
    def changed(source,destination):
        original_copy(source,destination)
        if pathlib.Path(source).name=='TERMINAL.json': pathlib.Path(source).write_bytes(b'modified after copy')
    patches=[]
    if mutate: patches.append(mock.patch.object(module,'copy_new',side_effect=changed))
    if deadline: patches.append(mock.patch.object(module.time,'monotonic',side_effect=[0.0,301.0]))
    from contextlib import ExitStack
    with ExitStack() as stack:
        for patch in patches: stack.enter_context(patch)
        receipt=module.stage_artifact(evidence,destination,summary)
    result=json.loads((destination/'RECOVERY_RESULT.json').read_bytes())
    actual_files={str(path.relative_to(destination)):path.read_bytes() for path in destination.rglob('*') if path.is_file()}
    listed=receipt['files']
    hashes_match=all(name in actual_files and value['bytes']==len(actual_files[name]) and value['sha256']==hashlib.sha256(actual_files[name]).hexdigest() for name,value in listed.items())
    all_files_listed=set(actual_files)==set(listed)|{'ARTIFACT_STAGING.json'}
    return evidence,destination,receipt,result,hashes_match,all_files_listed
with tempfile.TemporaryDirectory(prefix='hepta-pure-artifact-') as folder:
    evidence,destination,receipt,result,hashes,listed=stage_files(pathlib.Path(folder))
    inv=module.evidence_inventory(evidence)
    rows.append({'name':'regular_raw_exact_staging','passed':receipt['complete'] and not receipt['errors'] and hashes and listed and result['publication_evidence_qualified'] and result['general_agent_advantage_claim'] is False and result['artifact_upload_duration_ns'] is None and inv['member_count']==2,'receipt':receipt,'result':result,'all_output_files_manifested':listed})
for bad in ('fake.GGUF','fake.gguf.partial','fake.deb','fake.rpm.partial','llama-b11669-bin-ubuntu-x64.tar.gz','llama-server'):
    with tempfile.TemporaryDirectory(prefix='hepta-pure-artifact-') as folder:
        evidence,destination,receipt,result,hashes,listed=stage_files(pathlib.Path(folder),bad=bad)
        rejected=False
        try: module.evidence_inventory(evidence)
        except ValueError: rejected=True
        rows.append({'name':'reject_'+bad,'passed':rejected and not receipt['complete'] and len(receipt['rejected'])==1 and not (destination/bad).exists() and hashes and listed and not result['publication_evidence_qualified'] and result['qualified_descriptive_cross_family_gates']=={'maintenance':False,'upgrade':False},'receipt':receipt,'result':result,'all_output_files_manifested':listed})
for mode in ('symlink','source_change','deadline'):
    with tempfile.TemporaryDirectory(prefix='hepta-pure-artifact-') as folder:
        evidence,destination,receipt,result,hashes,listed=stage_files(pathlib.Path(folder),symlink=mode=='symlink',mutate=mode=='source_change',deadline=mode=='deadline')
        closed=not result['publication_evidence_qualified'] and not receipt['complete'] and bool(receipt['rejected'] or receipt['errors'])
        rows.append({'name':mode,'passed':closed and hashes and listed and (mode!='symlink' or not (destination/'unsafe-link.txt').exists()) and (mode!='source_change' or receipt['files'].get('TERMINAL.json',{}).get('source_copy_verified') is False),'receipt':receipt,'result':result,'all_output_files_manifested':listed})
with tempfile.TemporaryDirectory(prefix='hepta-pure-model-presence-') as folder:
    suite=pathlib.Path(folder)/'raw-suite';cell=suite/'qwen'/'first-cell';cell.mkdir(parents=True);(cell/'CELL.json').write_text('{"status":"failed"}\n')
    observed=module.raw_model_inventory(suite,[{'id':'qwen'},{'id':'granite'}])
    rows.append({'name':'partial_records_do_not_fabricate_complete_coverage_or_shutdown','passed':observed[0]['retained_cell_files']==1 and observed[0]['unattempted_or_no_terminal_cell_receipt']==11 and observed[1]['retained_cell_files']==0 and observed[1]['unattempted_or_no_terminal_cell_receipt']==12 and all(row['all_descendants_closed'] is None and row['terminal_present'] is False and row['reported_valid_observation'] is None for row in observed),'observed':observed})
report={'schema':'hepta.independent.pure-recovery-finalizer-review.v1','source':{'path':str(SOURCE.relative_to(ROOT)),'sha256':hashlib.sha256(source_bytes).hexdigest()},'source_unchanged':SOURCE.read_bytes()==source_bytes,'cases':rows,'count':len(rows),'passed':sum(row['passed'] for row in rows),'model_completions':0,'native_executions':0,'real_subprocesses':0,'real_network_requests':0,'scope':'Tiny fake raw file staging and failure accounting; no execution of retained contents; model outcome values are explicit control fixtures, not study results'}
path=pathlib.Path('/workspace/scratch/5567a9db5cf4/hepta-work/experiments/hia_agent_assembly_recovery_20261030/independent-runtime-review01/final-source-controls02/staging.json')
with path.open('x') as stream:json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
(pathlib.Path('/workspace/scratch/5567a9db5cf4/hepta-work/experiments/hia_agent_assembly_recovery_20261030/independent-runtime-review01/final-source-controls02/staging.source.py')).write_bytes(source_bytes)
print(json.dumps({'path':str(path),'count':report['count'],'passed':report['passed'],'source_sha256':report['source']['sha256'],'source_unchanged':report['source_unchanged'],'failed':[row['name'] for row in rows if not row['passed']]}))
