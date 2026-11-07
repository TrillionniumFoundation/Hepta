"""Stage the published r5 projection only inside the owned qualification root."""
import argparse,hashlib,json,os,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--host-kind',choices=['mac','linux'],required=True);a=p.parse_args()
r=a.root.resolve(strict=True);s=r/'source'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def snap():return {str(p.relative_to(s)):sha(p) for p in sorted(s.rglob('*')) if p.is_file() and '.git' not in p.relative_to(s).parts}
m=json.loads((r/'runtime-mac-r5-source.json').read_text());old=json.loads((r/'runtime-r4f-expected-input-projection.json').read_text());native=json.loads((r/'runtime-r5-formatted-input-projection.json').read_text());final=json.loads((r/'runtime-r5-expected-input-projection.json').read_text())
assert len(old)==958 and len(native)==958 and len(final)==959
prior_path=r/('mac-r4f-final-gates.json' if a.host_kind=='mac' else 'linux-r4f-final-gates.json');prior=json.loads(prior_path.read_text());assert prior['completed_utc'] and prior['source_unchanged']
if a.host_kind=='linux':assert prior['passed']
before=snap();assert before==(old if a.host_kind=='mac' else native),'unexpected staging source'
record={'schema':'hepta-runtime-r5-projected-source-staging-v1','published_commit':'942d470d155c65ba7235eb19c5bbfd07f1ce2ad0','published_tree':'a19f1dd724bdf80a388ddae17d828b01e5fc42f0','prior_gate_sha256':sha(prior_path),'prior_gate_passed':prior['passed'],'native_projection_sha256':sha(r/'runtime-r5-formatted-input-projection.json'),'final_projection_sha256':sha(r/'runtime-r5-expected-input-projection.json'),'original_count':len(before),'native_patch_applied':False,'production_modified':False}
assert sha(r/'runtime-mac-compatibility-r5.patch')==m['combined_patch_sha256']
if a.host_kind=='mac':
 delta=r/'runtime-mac-platform-r5.patch';assert sha(delta)==m['delta_patch_sha256']
 subprocess.run(['/usr/bin/git','apply','--check',str(delta)],cwd=s,check=True)
 subprocess.run(['/usr/bin/git','apply',str(delta)],cwd=s,check=True)
 record['native_patch_applied']=True
assert snap()==native
ledger='docs/rea-native/compatibility/REA_6_8_0_LEDGER.json';payload=r/'runtime-r5-final-ledger.json';dest=s/ledger
assert sha(payload)==m['files'][ledger]['after']==final[ledger]
for d in [s/'docs',s/'docs/rea-native',s/'docs/rea-native/compatibility']:
 if d.exists():assert d.is_dir() and not d.is_symlink()
 else:d.mkdir(mode=0o755)
with dest.open('xb') as output:output.write(payload.read_bytes());output.flush();os.fsync(output.fileno())
assert snap()==final
record['final_count']=len(final);record['staged']=True
receipt=r/(a.host_kind+'-r5-source-staging.json');assert not receipt.exists();receipt.write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record),flush=True)
if a.host_kind=='mac':
 cargo='/opt/homebrew/opt/rustup/bin/cargo';home='/Users/qianqi/work/hepta-runtime-mac-controller-20261103/cargo-home';bins=[str(r/'tools/bin'),'/opt/homebrew/bin'];tmp='/private/tmp/hr372e7-m6'
else:
 cargo='/home/qq/.cargo/bin/cargo';home='/home/qq/.cargo';bins=['/home/qq/hepta-hia-agent-native-20261106-f4e250f91ef4/tools/bin'];tmp='/tmp/hr372e7-l6'
argv=[sys.executable,str(r/'runtime-ci-gates-r5.py'),'--root',str(r),'--cargo',cargo,'--cargo-home',home,'--manifest','runtime-mac-r5-source.json','--patch','runtime-mac-compatibility-r5.patch','--tag',a.host_kind+'-r5-final','--tmp-dir',tmp,'--expected-targets','runtime-r5-expected-targets.json','--expected-projection','runtime-r5-expected-input-projection.json']
for b in bins:argv+=['--tool-bin',b]
if a.host_kind=='mac':argv+=['--release']
raise SystemExit(subprocess.run(argv,cwd=r).returncode)
