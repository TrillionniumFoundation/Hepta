from pathlib import Path
import hashlib,json,shlex,subprocess,time
R=Path(__file__).resolve().parent
Q=R/'default-slot-installed-controls-v1';Q.mkdir(mode=0o700)
remote='/home/qq/hia-native-carrier-policy-20261128-2ac5/default-slot-installed-controls-v1'
test=R/'source/tests/test_hia_carrier_default_install.py';raw=test.read_bytes()
(Q/'test-candidate.py').write_bytes(raw)
code='''from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys,time
R=Path(__file__).resolve().parent;A=R.parent;os.umask(0o077)
old=A/'default-install-v4';m=json.loads((old/'source-transport.json').read_bytes())
s=R/'source';s.mkdir(mode=0o700)
for name,expected in m['files'].items():
 p=old/'source'/name;raw=p.read_bytes();assert len(raw)==expected['bytes'] and hashlib.sha256(raw).hexdigest()==expected['sha256']
 q=s/name;q.parent.mkdir(mode=0o700,parents=True,exist_ok=True);q.write_bytes(raw);q.chmod(p.stat().st_mode&0o777)
p=R/'test-candidate.py';raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==TEST_SHA
(s/'tests/test_hia_carrier_default_install.py').write_bytes(raw)
def snapshot():return {name:{'bytes':len((s/name).read_bytes()),'sha256':hashlib.sha256((s/name).read_bytes()).hexdigest()} for name in m['files']}
before=snapshot();(R/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\\n')
argv=[sys.executable,'-I','-B',str(s/'tests/test_hia_carrier_default_install.py'),'--installation',str(old/'installation'),'--output',str(R/'controls')]
(R/'intent.json').write_text(json.dumps({'argv':argv,'timeout_seconds':180})+'\\n')
t=time.monotonic();p=subprocess.run(argv,capture_output=True,timeout=180,cwd=s,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(R)))
(R/'stdout').write_bytes(p.stdout);(R/'stderr').write_bytes(p.stderr)
after=snapshot();(R/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\\n')
terminal={'returncode':p.returncode,'seconds':time.monotonic()-t,'source_unchanged':before==after};(R/'terminal.json').write_text(json.dumps(terminal)+'\\n')
print(p.stdout.decode(),p.stderr.decode(),json.dumps(terminal),flush=True)
assert before==after
raise SystemExit(p.returncode)
'''.replace('TEST_SHA',repr(hashlib.sha256(raw).hexdigest()))
(Q/'driver.py').write_text(code)
def run(label,argv):
 t=time.monotonic();p=subprocess.run(argv,capture_output=True)
 (Q/(label+'.stdout')).write_bytes(p.stdout);(Q/(label+'.stderr')).write_bytes(p.stderr)
 (Q/(label+'.terminal.json')).write_text(json.dumps({'returncode':p.returncode,'seconds':time.monotonic()-t})+'\n')
 if p.returncode:print(p.stderr.decode(),flush=True)
 return p
ssh=['/usr/bin/ssh','-oBatchMode=yes','-oConnectTimeout=12','ai395']
assert run('directory',ssh+['python3 -c '+shlex.quote('from pathlib import Path;Path('+repr(remote)+').mkdir(mode=0o700)')]).returncode==0
for name in ('driver.py','test-candidate.py'):
 assert run('upload-'+name,['/usr/bin/scp','-oBatchMode=yes','-oConnectTimeout=12',str(Q/name),'ai395:'+remote+'/'+name]).returncode==0
p=run('actual',ssh+['python3 '+shlex.quote(remote+'/driver.py')]);print(p.stdout.decode(),flush=True)
raise SystemExit(p.returncode)
