"""Apply the one-test c81a delta only after the original 942d job has completed."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--host-kind',choices=['mac','linux'],required=True);a=p.parse_args();r=a.root.resolve(strict=True);s=r/'source'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snapshot():return {str(p.relative_to(s)):sha(p) for p in sorted(s.rglob('*')) if p.is_file() and '.git' not in p.relative_to(s).parts}
old_path=r/'runtime-r5-expected-input-projection.json';new_path=r/'runtime-r6-expected-input-projection.json';old=json.loads(old_path.read_text());new=json.loads(new_path.read_text());assert len(old)==len(new)==959 and snapshot()==old
manifest_path=r/'runtime-mac-r6-source.json';m=json.loads(manifest_path.read_text());assert m['previous_published_commit']=='942d470d155c65ba7235eb19c5bbfd07f1ce2ad0'
prior_path=r/('mac-r5-final-gates.json' if a.host_kind=='mac' else 'linux-r5-inode-recheck-gates.json');prior=json.loads(prior_path.read_text());assert prior['completed_utc'] and prior['source_unchanged'];assert prior['published_commit']==m['previous_published_commit']
if a.host_kind=='linux':assert prior['passed']
for n,item in m['files'].items():assert sha(s/n)==item['previous'],n
patch=r/'runtime-mac-platform-r6.patch';assert sha(patch)==m['delta_patch_sha256'];assert sha(r/'runtime-mac-compatibility-r6.patch')==m['combined_patch_sha256']
subprocess.run(['/usr/bin/git','apply','--check',str(patch)],cwd=s,check=True);subprocess.run(['/usr/bin/git','apply',str(patch)],cwd=s,check=True)
assert snapshot()==new
for n,item in m['files'].items():assert sha(s/n)==item['after'],n
identity=json.loads((r/'runtime-r6-expected-targets.json').read_text());assert identity['published_commit']=='c81a938150d2e533843a42af77739cb888812338'
record={'schema':'hepta-runtime-r6-projected-source-staging-v1','published_commit':identity['published_commit'],'published_tree':identity['published_tree'],'source_manifest_sha256':sha(manifest_path),'prior_gate_sha256':sha(prior_path),'prior_gate_passed':prior['passed'],'prior_projection_sha256':sha(old_path),'final_projection_sha256':sha(new_path),'delta_patch_sha256':sha(patch),'changed_paths':[n for n in old if old[n]!=new[n]],'source_count':len(new),'production_modified':False,'staged':True}
q=r/(a.host_kind+'-r6-source-staging.json');assert not q.exists();q.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record),flush=True)
if a.host_kind=='mac':cargo='/opt/homebrew/opt/rustup/bin/cargo';home='/Users/qianqi/work/hepta-runtime-mac-controller-20261103/cargo-home';bins=[str(r/'tools/bin'),'/opt/homebrew/bin'];tmp='/private/tmp/hr372e7-m7'
else:cargo='/home/qq/.cargo/bin/cargo';home='/home/qq/.cargo';bins=['/home/qq/hepta-hia-agent-native-20261106-f4e250f91ef4/tools/bin'];tmp='/home/qq/hia-tmp-l8'
argv=[sys.executable,str(r/'runtime-ci-gates-r6.py'),'--root',str(r),'--cargo',cargo,'--cargo-home',home,'--manifest','runtime-mac-r6-source.json','--patch','runtime-mac-compatibility-r6.patch','--tag',a.host_kind+'-r6-final','--tmp-dir',tmp,'--expected-targets','runtime-r6-expected-targets.json','--expected-projection','runtime-r6-expected-input-projection.json']
for b in bins:argv+=['--tool-bin',b]
if a.host_kind=='mac':argv+=['--focused-cache-regression','--release']
raise SystemExit(subprocess.run(argv,cwd=r).returncode)
