from pathlib import Path
import sys,os,json,time,hashlib,subprocess,stat,traceback
spec=json.load(sys.stdin)
old=Path('/home/qian-qi/hia-bootstrap-admission-lifetime-20261127-2807/src')
scope=Path('/home/qian-qi/hia-bootstrap-source-custody-20261127-2807')
root=scope/'src';data=scope/'controls'
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def git(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
for name,expected in spec['source_before'].items():assert pin((old/name).read_bytes())==expected,name
for name,raw in spec['product_files'].items():
 expected=spec['product_pins'][name];data_raw=raw.encode()
 assert pin(data_raw)=={'bytes':expected['bytes'],'sha256':expected['sha256']},name
 assert git(data_raw)==expected['git_blob'],name
scope.mkdir(mode=0o700);root.mkdir(mode=0o700);data.mkdir(mode=0o700)
names=set(spec['source_before'])
for prefix in ('hepta','tools','tests'):
 for path in (old/prefix).rglob('*'):
  if path.is_file() and (path.suffix=='.py' or str(path.relative_to(old)).startswith('tests/fixtures/')):
   names.add(str(path.relative_to(old)))
for name in ('pyproject.toml','setup.py','README.md'):
 if (old/name).is_file():names.add(name)
total=sum((old/name).stat().st_size for name in names)
available=os.statvfs(scope).f_bavail*os.statvfs(scope).f_frsize
assert total<512_000_000 and available>total+4_000_000_000
copied={}
for name in sorted(names):
 source=old/name;st=source.lstat()
 assert stat.S_ISREG(st.st_mode) and not source.is_symlink() and st.st_nlink==1,name
 raw=source.read_bytes();record=pin(raw)
 public=spec['public_tree'][name]
 assert len(raw)==public['bytes'] and git(raw)==public['git_blob'],name
 target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
 with target.open('xb') as stream:stream.write(raw)
 assert target.read_bytes()==raw and source.read_bytes()==raw,name
 copied[name]={**record,'git_blob':git(raw)}
for name,expected in spec['source_before'].items():assert pin((root/name).read_bytes())==expected,name
for name,text in spec['product_files'].items():
 target=root/name
 if name not in spec['source_before']:assert not target.exists(),name
 target.write_bytes(text.encode())
for name,expected in spec['unchanged_test_pins'].items():assert pin((root/name).read_bytes())==expected,name
(data/'reconstruction.json').write_text(json.dumps({'source_origin':str(old),'public_base':spec['base_commit'],
 'public_tree':spec['base_tree'],'independent_snapshot_not_git_checkout':True,
 'all_copied_sources_match_public_Git_blobs':True,'copied_files':copied,'copied_bytes':total,
 'home_available_before':available,'product_pins':spec['product_pins'],
 'original_test_pins':spec['unchanged_test_pins'],'execution_inventory':spec['execution_inventory']},sort_keys=True,indent=2)+'\n')
(data/'invocation.json').write_text(json.dumps(spec,sort_keys=True,indent=2)+'\n')
for key in list(os.environ):
 if key.startswith(('HEPTA_HIA_','PYTHON','HIA_BOOTSTRAP_DIAG_')) or key=='LD_PRELOAD':del os.environ[key]
tmp=scope/'temporary';tmp.mkdir(mode=0o700);os.environ['TMPDIR']=str(tmp)
os.chdir(root);sys.path.insert(0,str(root))
from tests import hia_service_bootstrap_support as s
source=s.source_snapshot()
expected_source={**spec['source_before'],**{name:pin(text.encode()) for name,text in spec['product_files'].items()}}
assert source==expected_source and len(source)==159
command=['/usr/bin/python3','-I','-B','tools/run_hia_unittest_gate.py',
 'tests.test_hia_bootstrap_terminal_business.BootstrapTerminalBusinessTests',
 'tests.test_hia_service_bootstrap_sources.ServiceBootstrapStaticSourceTests',
 'tests.test_hia_service_bootstrap_fixed_words.ServiceBootstrapFixedWordSourceTests',
 'tests.test_hia_service_bootstrap_word.ServiceBootstrapWordSourceTests',
 'tests.test_hia_bootstrap_observer_source_custody.BootstrapObserverSourceCustodyTests']
started=time.monotonic()
with (data/'tests.stdout').open('xb') as stdout,(data/'tests.stderr').open('xb') as stderr:
 result=subprocess.run(command,cwd=root,env=os.environ.copy(),stdout=stdout,stderr=stderr,timeout=180)
after=s.source_snapshot();assert after==source
for name,expected in spec['unchanged_test_pins'].items():assert pin((root/name).read_bytes())==expected,name
record={'schema':'hepta.hia.bootstrap-observer-source-custody-controls.v1',
 'status':'PASS_CONTROLS_ONLY' if result.returncode==0 else 'HOLD','qualification_claim':False,
 'command':command,'returncode':result.returncode,'timeout_seconds':180,'seconds':time.monotonic()-started,
 'source_before':source,'source_after':after,'original_test_pins':spec['unchanged_test_pins'],
 'stdout':s.file_pin(data/'tests.stdout'),'stderr':s.file_pin(data/'tests.stderr'),
 'copied_public_Git_blobs_verified':len(copied),'home_available_before':available}
s.write_json(data/'result.json',record)
print(json.dumps({'status':record['status'],'returncode':result.returncode,'seconds':record['seconds'],
 'source_count':len(source),'copied_bytes':total,'record':s.file_pin(data/'result.json')},sort_keys=True),flush=True)
sys.exit(result.returncode)
