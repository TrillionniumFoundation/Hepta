from pathlib import Path
from hashlib import sha256
import json,subprocess,zipfile
B=Path(__file__).resolve().parents[1];E=B/'evidence';R=B/'agent-core-retained-regression-review-development'
head='e89b7094a509ce8db276660eaaa401085e1499bf'
p=E/'core-retained-remote-native-failure-01.zip'
assert p.stat().st_size==49178960
assert sha256(p.read_bytes()).hexdigest()=='30af480d9cc3a80ff85a185214ab5093b9e495b56feb0799e5b33c6bb58c99ac'
with zipfile.ZipFile(p) as z:
 cold=json.loads(z.read('hia-cold.json'));owner=json.loads(z.read('hia-cold.cold/process-owner.json'))
 index=json.loads(z.read('hia-cold.cold/qualification.evidence/phase-index.json'))
 payloads=[]
 for name,digest in sorted(cold['source_manifest'].items()):
  raw=z.read('hia-cold.cold/source/'+name)
  expected=subprocess.check_output(['git','show',head+':'+name],cwd=R)
  assert sha256(raw).hexdigest()==digest and raw==expected,name
  payloads.append(dict(path=name,bytes=len(raw),sha256=digest))
 assert len(payloads)==411
 assert owner['status']=='QUALIFICATION_TIMEOUT' and owner['cleanup']['complete']
 assert owner['qualification_seconds']==180 and owner['cleanup_seconds']==3
 record=dict(run_id=42825541295,job_id=129861759640,source_job_id=129861759062,
  source_job_status='SUCCESS',native_job_status='FAIL',qualified_review_head=head,
  artifact=dict(id=13768367922,bytes=p.stat().st_size,sha256=sha256(p.read_bytes()).hexdigest()),
  source_payloads=payloads,all_payloads_compared_to_git_blobs=True,
  cold_checks_passed=sum(v is True for v in cold['checks'].values()),cold_checks_total=len(cold['checks']),
  phase_completed=index['completed'],phase_exceptions=index['exceptions'],
  phase_unfinished=[v for v in index['phases'] if v['state']!='completed'],
  qualification_seconds=180,cleanup_seconds=3,cleanup_complete=True,
  wall_elapsed_ns=cold['wall_elapsed_ns'],generation_hashes_admitted=cold['generation_sha256'],
  later_language_and_native_application_steps='SKIPPED',
  local_full_repository_pass_relabels_remote_failure=False,whole_native_closure=False)
with (E/'core-retained-remote-failure-source-custody-01.json').open('x') as f:json.dump(record,f,sort_keys=True,indent=2)
print(json.dumps({k:v for k,v in record.items() if k not in ('source_payloads','phase_unfinished')}))
