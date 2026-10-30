from __future__ import annotations
import hashlib,json,pathlib,subprocess,time
ROOT=pathlib.Path('/workspace/scratch/5567a9db5cf4/hepta-work')
REVIEW=ROOT/'experiments/hia_agent_assembly_recovery_20261030/independent-runtime-review01'
FINAL=REVIEW/'final-source-controls';FINAL.mkdir(exist_ok=False)
source_names=[
 'experiments/hia_agent_assembly_recovery_20261030/run_recovery.py',
 'experiments/hia_agent_assembly_recovery_20261030/resource_gate.py',
 'experiments/hia_agent_assembly_recovery_20261030/measure_child.py',
 'experiments/hia_agent_assembly_recovery_20261030/prepare_controls.py',
 'experiments/hia_agent_assembly_recovery_20261030/PROTOCOL.json',
 'experiments/hia_agent_assembly_recovery_20261030/README.md',
 'experiments/hia_agent_assembly_recovery_20261030/test_recovery.py',
 '.github/workflows/hepta-agent-recovery.yml',
 'experiments/hia_agent_assembly_v4_readout_20261030/archive_evidence.py',
 'experiments/hia_agent_assembly_v4_readout_20261030/readout.py',
 'experiments/hia_agent_assembly_v4_readout_20261030/diagnose.py']
before={}
for name in source_names:
    data=(ROOT/name).read_bytes();before[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    path=FINAL/'reviewed-source'/name;path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as stream:stream.write(data)
groups=[('resource','resource-review-02'),('tar','io-review-01'),('download','download-review-01'),('stop','stop-review-02'),('credential','credential-review-01'),('staging','finalizer-review-01')]
rows=[]
for name,previous in groups:
    origin=pathlib.Path('/tmp/hepta-recovery-'+previous+'.py')
    code=origin.read_text()
    code=code.replace('/tmp/hepta-recovery-'+previous, str(FINAL/name))
    if name=='credential':
        code=code.replace("'pending':['Final workflow must disable checkout persisted credentials and upload only evidence/publication directories.']", "'pending':['Actual future CI artifact contents remain to be audited; final workflow static credential/upload checks are recorded separately.']")
    if name=='staging':
        code=code.replace("closed and hashes and listed and (mode!='symlink' or not (destination/'unsafe-link.txt').exists())", "closed and hashes and listed and (mode!='symlink' or not (destination/'unsafe-link.txt').exists()) and (mode!='source_change' or receipt['files'].get('TERMINAL.json',{}).get('source_copy_verified') is False)")
    path=FINAL/(name+'.py')
    with path.open('x') as stream:stream.write(code)
    started=time.monotonic_ns()
    with (FINAL/(name+'.stdout')).open('x') as out,(FINAL/(name+'.stderr')).open('x') as err:
        result=subprocess.run(['/usr/bin/python3','-B',str(path)],cwd=ROOT,stdout=out,stderr=err,timeout=30)
    report_path=FINAL/(name+'.json')
    data=json.loads(report_path.read_bytes()) if report_path.exists() else None
    cases=(data.get('cases',data.get('rows',data.get('records',[]))) if data else [])
    rows.append({'group':name,'script':str(path.relative_to(REVIEW)),'script_sha256':hashlib.sha256(code.encode()).hexdigest(),'report':str(report_path.relative_to(REVIEW)),'report_sha256':hashlib.sha256(report_path.read_bytes()).hexdigest() if report_path.exists() else None,'exit_code':result.returncode,'case_count':len(cases),'case_passed':sum(row.get('passed') is True for row in cases),'all_cases_passed':bool(cases) and all(row.get('passed') is True for row in cases),'source_unchanged_claim':data.get('source_unchanged',data.get('sources_unchanged_during_review')) if data else None,'wall_ns':time.monotonic_ns()-started,'previous_attempt':origin.name})
after={name:{'bytes':(ROOT/name).stat().st_size,'sha256':hashlib.sha256((ROOT/name).read_bytes()).hexdigest()} for name in source_names}
record={'schema':'hepta.independent.recovery-final-source-control-execution.v1','sources_before':before,'sources_after':after,'all_sources_unchanged':before==after,'groups':rows,'all_groups_passed':all(row['exit_code']==0 and row['all_cases_passed'] for row in rows),'duplicate_scope':'tar group includes two repeated resource cases; historical attempts and repeated controls are not additional independent cases','real_model_completions':0,'real_downloads':0,'real_native_workloads':0,'live_process_signals':0,'scope':'Pure mocks, fake kernel metadata and tiny local files; no retained executable content was run'}
with (FINAL/'EXECUTION.json').open('x') as stream:json.dump(record,stream,indent=2,sort_keys=True);stream.write('\n')
print(json.dumps({'report':str(FINAL/'EXECUTION.json'),'all_sources_unchanged':record['all_sources_unchanged'],'all_groups_passed':record['all_groups_passed'],'groups':[{k:row[k] for k in ('group','case_count','case_passed','exit_code')} for row in rows],'run_recovery_sha256':before[source_names[0]]['sha256']}))
