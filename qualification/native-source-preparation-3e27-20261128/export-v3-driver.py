from pathlib import Path
import subprocess,json,hashlib,tarfile,stat,os,sys
base=Path('/home/qq/hia-final-native-cold-20261128-2ac5');source=base/'source'
prep=base/'source3e27-preparation-v1';out=base/'source3e27-preparation-export-v3';out.mkdir(mode=0o700,exist_ok=False)
head='3e27f633586a71531846b3e189d3b1f69b4ae4b5'
report=json.loads((prep/'preparation/report.json').read_bytes());assert report['passed'] and report['phase_count']==60 and report['qualification_nodes']==479882
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()==head
changed=subprocess.check_output(['git','diff','--name-only'],cwd=source).decode().splitlines()
extra={'docs/HIA_WORKER_MANIFEST_CURRENT_RECORDS.json','examples/hia_bootstrap/cold_report_admit.hepta'}
expected=set(report['changed_sources'])|extra
assert set(changed)==expected,(changed,sorted(expected))
assert (source/'examples/hia_bootstrap/cold_report_admit.hepta').read_bytes()==(source/'examples/hia_bootstrap/source_release_cold_admit.hepta').read_bytes()
assert set(report['changed_development_artifacts'])=={'examples/hia_bootstrap/cold_build_plans/build-plan.json','examples/hia_bootstrap/cold_source_bootstrap_plans/build-plan.json'}
for name in report['changed_development_artifacts']:
 assert not subprocess.check_output(['git','ls-files','--',name],cwd=source).strip()
 assert subprocess.run(['git','check-ignore','--quiet','--',name],cwd=source).returncode==1
inputs=json.loads(sys.argv[1])
for version in ['v1','v2']:
 prior=base/('source3e27-preparation-export-'+version)
 (prior/'driver.py').write_text(inputs[version]['driver'])
 (prior/'original-terminal.json').write_text(json.dumps(inputs[version]['terminal'],sort_keys=True,indent=2)+'\n')
assert set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],cwd=source).decode().splitlines())==set(report['changed_development_artifacts'])
rows=[];identities={}
for name in changed:
 p=source/name;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 raw=p.read_bytes();old=subprocess.check_output(['git','show',head+':'+name],cwd=source)
 rows.append({'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':stat.S_IMODE(s.st_mode),'before_bytes':len(old),'before_sha256':hashlib.sha256(old).hexdigest()})
 identities[name]=[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
record={'schema':'hepta.hia.native-source-preparation-export.v1','head':head,'source':str(source),'passed':True,'source_count':report['source_count'],'phase_count':60,'qualification_nodes':479882,'changed_sources':report['changed_sources'],'changed_development_artifacts':report['changed_development_artifacts'],'products':rows,'additional_retained_development_derivatives':sorted(extra),'whole_cold_qualified':False,'development_plan_git_state':'untracked and not ignored; independently read and exactly bounded to two original preparation outputs'}
(out/'manifest.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
with tarfile.open(out/'prepared-sources.tar.gz','w:gz') as t:
 t.add(out/'manifest.json',arcname='manifest.json',recursive=False)
 for row in rows:t.add(source/row['path'],arcname=row['path'],recursive=False)
 for name in report['changed_development_artifacts']:t.add(source/name,arcname='development/'+name,recursive=False)
with tarfile.open(out/'prepared-sources.tar.gz','r:gz') as t:
 assert json.loads(t.extractfile('manifest.json').read())==record
 for row in rows:
  raw=t.extractfile(row['path']).read();assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
 for name in report['changed_development_artifacts']:assert t.extractfile('development/'+name).read()==(source/name).read_bytes()
for name,old in identities.items():
 s=(source/name).lstat();assert old==[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
archive=out/'complete-preseed-and-preparation-originals.tar.gz'
physical=[]
with tarfile.open(archive,'w:gz') as t:
 for name in ['source3e27-preseed-v1','source3e27-preparation-v1','source3e27-preparation-export-v1','source3e27-preparation-export-v2','source3e27-preparation-export-scope-read-v1']:
  for p in sorted((base/name).rglob('*')):
   s=p.lstat()
   if stat.S_ISDIR(s.st_mode):continue
   assert stat.S_ISREG(s.st_mode),str(p)
   raw=p.read_bytes();rel=str(p.relative_to(base))
   physical.append({'path':rel,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':stat.S_IMODE(s.st_mode)})
   t.add(p,arcname=rel,recursive=False)
(out/'complete-originals-manifest.json').write_text(json.dumps(physical,sort_keys=True,indent=2)+'\n')
with tarfile.open(archive,'r:gz') as t:
 assert len(t.getmembers())==len(physical)
 for row in physical:
  raw=t.extractfile(row['path']).read();assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
receipt={'status':'CURRENT_NATIVE_PREPARATION_SOURCES_AND_ALL_ORIGINALS_EXPORTED','head':head,'products':len(rows),'native_sources':len(report['changed_sources']),'development_outputs':len(report['changed_development_artifacts']),'original_files':len(physical),'artifacts':[]}
for name in ['prepared-sources.tar.gz','complete-preseed-and-preparation-originals.tar.gz','complete-originals-manifest.json','manifest.json']:
 p=out/name;raw=p.read_bytes();receipt['artifacts'].append({'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
(out/'receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
print(json.dumps(receipt,sort_keys=True),flush=True)
