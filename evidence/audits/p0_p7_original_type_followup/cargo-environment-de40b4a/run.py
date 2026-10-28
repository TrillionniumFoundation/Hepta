from pathlib import Path
import os,sys,json,subprocess,time,hashlib,datetime
ROOT=Path('/workspace/scratch/4bc91e0ee48c/hepta-followup-integration')
OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from tools.release_check import snapshot
os.chdir(ROOT)
def git(*a):return subprocess.check_output(['git',*a],text=True).strip()
def digest(p):
 b=Path(p).read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
expected='de40b4a029c00e5958663d8a30e44df7e6647904'
assert git('rev-parse','HEAD')==expected and not git('status','--porcelain=v1','--untracked-files=no')
before=snapshot();(OUT/'source-before.json').write_text(json.dumps(before,indent=2,sort_keys=True)+'\n')
env=dict(os.environ)
env.update(PATH='/tmp/hepta-toolchains/rust-1.90.0/bin:'+env['PATH'],RUSTC='/tmp/hepta-toolchains/rust-1.90.0/bin/rustc',CARGO_HOME='/tmp/hepta-cargo-home',CARGO_TARGET_DIR='/tmp/hepta-p2-independent-v2-v7-target',PYTHONDONTWRITEBYTECODE='1')
argv=['/usr/bin/python3','-m','unittest','tests.test_qualification_cargo_environment','tests.test_bootstrap_install_integrity','-v']
tools={n:digest(p) for n,p in {'python':'/usr/bin/python3','rustc':env['RUSTC'],'cargo':'/tmp/hepta-toolchains/rust-1.90.0/bin/cargo'}.items()}
plan={'schema':'hepta.audit.cargo-environment-validation.v1','git_commit':expected,'argv':argv,'timeout_seconds':120,'environment':{k:env[k] for k in ('CARGO_HOME','CARGO_TARGET_DIR','RUSTC','PYTHONDONTWRITEBYTECODE')},'source_snapshot_before':before['sha256'],'tools':tools,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
(OUT/'plan.json').write_text(json.dumps(plan,indent=2,sort_keys=True)+'\n')
start=time.monotonic()
with (OUT/'stdout.log').open('w') as out,(OUT/'stderr.log').open('w') as err:
 r=subprocess.run(argv,cwd=ROOT,env=env,stdout=out,stderr=err,timeout=120)
after=snapshot();(OUT/'source-after.json').write_text(json.dumps(after,indent=2,sort_keys=True)+'\n')
report={**plan,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'seconds':time.monotonic()-start,'returncode':r.returncode,'source_snapshot_after':after['sha256'],'source_unchanged':after==before,'git_unchanged':git('rev-parse','HEAD')==expected and not git('status','--porcelain=v1','--untracked-files=no'),'tools_unchanged':all(digest(v['path'])==v for v in tools.values()),'stdout':digest(OUT/'stdout.log'),'stderr':digest(OUT/'stderr.log')}
report['ok']=r.returncode==0 and report['source_unchanged'] and report['git_unchanged'] and report['tools_unchanged']
(OUT/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:report[k] for k in ('ok','git_commit','seconds','returncode','source_unchanged','tools_unchanged')}))
raise SystemExit(0 if report['ok'] else 1)
