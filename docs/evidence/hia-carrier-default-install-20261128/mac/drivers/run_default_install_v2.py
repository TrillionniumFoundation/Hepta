from pathlib import Path
import hashlib,json,shlex,subprocess,time
R=Path(__file__).resolve().parent;Q=R/'default-install-v2';Q.mkdir(mode=0o700)
source=R/'source/tools/install_hia_carrier_compat.py';raw=source.read_bytes()
(Q/'installer.py').write_bytes(raw);pin=hashlib.sha256(raw).hexdigest()
remote='/home/qq/hia-native-carrier-policy-20261128-2ac5/default-install-v2'
driver=r'''from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys,time
R=Path(__file__).resolve().parent;A=R.parent;P=A/'default-install-v1';Q=R/'qualification';Q.mkdir(mode=0o700);os.umask(0o077)
S=R/'source';S.mkdir(mode=0o700)
M=json.loads((P/'source-transport.json').read_bytes())
for name,want in M['files'].items():
 raw=(P/'source'/name).read_bytes();assert len(raw)==want['bytes'] and hashlib.sha256(raw).hexdigest()==want['sha256']
 dest=S/name;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);dest.write_bytes(raw);dest.chmod(0o600)
new=(R/'installer.py').read_bytes();assert hashlib.sha256(new).hexdigest()==REPLACE_PIN
(S/'tools/install_hia_carrier_compat.py').write_bytes(new)
def inventory():
 return {p.relative_to(S).as_posix():{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':p.stat().st_mode&0o777} for p in S.rglob('*') if p.is_file()}
before=inventory();(Q/'before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
def pin(path):return hashlib.sha256(path.read_bytes()).hexdigest()
wheel,=(P/'wheels').glob('*.whl');graph=P/'native-graph';typed=graph/'typed-page.json';compiler=A/'hia-source-build'
argv=[sys.executable,'-I','-B',str(S/'tools/install_hia_carrier_compat.py'),
 '--wheel',str(wheel),'--expected-wheel-sha256',pin(wheel),'--compiler',str(compiler),'--expected-compiler-sha256',pin(compiler),
 '--cc',str(Path('/usr/bin/cc').resolve(strict=True)),'--native-root',str(graph),'--base-bundle',str(typed),'--expected-base-sha256',pin(typed),
 '--policy-release',str(graph/'release'),'--expected-publication-sha256','a98a3fe382aac7f62a20de387a87b90197016cf0d1189dd33973698963150214',
 '--target',str(R/'installed'),'--output',str(R/'installation')]
(Q/'actual.intent.json').write_text(json.dumps({'argv':argv,'timeout_seconds':600})+'\n')
start=time.monotonic();env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(Q));p=subprocess.run(argv,capture_output=True,timeout=600,cwd=S,env=env)
(Q/'actual.stdout').write_bytes(p.stdout);(Q/'actual.stderr').write_bytes(p.stderr)
after=inventory();(Q/'after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
terminal={'returncode':p.returncode,'seconds':time.monotonic()-start,'source_unchanged':before==after}
(Q/'terminal.json').write_text(json.dumps(terminal,indent=2)+'\n');print(json.dumps(terminal),p.stdout.decode(),p.stderr.decode(),flush=True)
if (R/'installation/result.json').is_file():print((R/'installation/result.json').read_text()[:5000],flush=True)
assert before==after
raise SystemExit(p.returncode)
'''.replace('REPLACE_PIN',repr(pin))
(Q/'driver.py').write_text(driver)
def call(label,argv):
 start=time.monotonic()
 with (Q/(label+'.stdout')).open('xb') as out,(Q/(label+'.stderr')).open('xb') as err:
  p=subprocess.Popen(argv,stdout=out,stderr=err);(Q/(label+'.started.json')).write_text(json.dumps({'pid':p.pid,'argv':argv})+'\n');rc=p.wait()
 (Q/(label+'.terminal.json')).write_text(json.dumps({'returncode':rc,'seconds':time.monotonic()-start})+'\n')
 if rc:print((Q/(label+'.stderr')).read_text()[-4000:],flush=True)
 return rc
ssh=['/usr/bin/ssh','-oBatchMode=yes','-oConnectTimeout=12','ai395']
assert call('directory',ssh+['python3 -c '+shlex.quote('from pathlib import Path;Path('+repr(remote)+').mkdir(mode=0o700)')])==0
for name in ('installer.py','driver.py'):
 assert call('upload-'+name,['/usr/bin/scp','-oBatchMode=yes','-oConnectTimeout=12',str(Q/name),'ai395:'+remote+'/'+name])==0
rc=call('actual',ssh+['python3 '+shlex.quote(remote+'/driver.py')])
print((Q/'actual.stdout').read_text()[-18000:],flush=True)
raise SystemExit(rc)
