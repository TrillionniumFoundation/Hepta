from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys,time
R=Path(__file__).resolve().parent;A=R.parent;os.umask(0o077)
old=A/'default-install-v4';m=json.loads((old/'source-transport.json').read_bytes())
s=R/'source';s.mkdir(mode=0o700)
for name,expected in m['files'].items():
 p=old/'source'/name;raw=p.read_bytes();assert len(raw)==expected['bytes'] and hashlib.sha256(raw).hexdigest()==expected['sha256']
 q=s/name;q.parent.mkdir(mode=0o700,parents=True,exist_ok=True);q.write_bytes(raw);q.chmod(p.stat().st_mode&0o777)
p=R/'test-candidate.py';raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()=='aefb60ee2d3ceb77f57279b01289f598ab0a7ca531000e436d716e097323ccd3'
(s/'tests/test_hia_carrier_default_install.py').write_bytes(raw)
def snapshot():return {name:{'bytes':len((s/name).read_bytes()),'sha256':hashlib.sha256((s/name).read_bytes()).hexdigest()} for name in m['files']}
before=snapshot();(R/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
argv=[sys.executable,'-I','-B',str(s/'tests/test_hia_carrier_default_install.py'),'--installation',str(old/'installation'),'--output',str(R/'controls')]
(R/'intent.json').write_text(json.dumps({'argv':argv,'timeout_seconds':180})+'\n')
t=time.monotonic();p=subprocess.run(argv,capture_output=True,timeout=180,cwd=s,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(R)))
(R/'stdout').write_bytes(p.stdout);(R/'stderr').write_bytes(p.stderr)
after=snapshot();(R/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
terminal={'returncode':p.returncode,'seconds':time.monotonic()-t,'source_unchanged':before==after};(R/'terminal.json').write_text(json.dumps(terminal)+'\n')
print(p.stdout.decode(),p.stderr.decode(),json.dumps(terminal),flush=True)
assert before==after
raise SystemExit(p.returncode)
