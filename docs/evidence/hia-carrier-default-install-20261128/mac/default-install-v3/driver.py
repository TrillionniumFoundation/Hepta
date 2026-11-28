from pathlib import Path
import hashlib,json,os,shutil,stat,subprocess,sys,tarfile,time
R=Path(__file__).resolve().parent;A=R.parent;Q=R/'qualification';Q.mkdir(mode=0o700)
os.umask(0o077)
archive=R/'source.tar.gz';raw=archive.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='f3f12bdb5bbefc97b16d8e145f506efe996dcc4e163f9c59b586f360bf3036e6'
with tarfile.open(archive,'r:gz') as tf:
 for member in tf:
  assert (member.isdir() or member.isfile()) and not member.name.startswith('/') and '..' not in Path(member.name).parts
  target=R/member.name
  if member.isdir():target.mkdir(mode=0o700,parents=True,exist_ok=True)
  else:
   target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   with target.open('xb') as f:f.write(tf.extractfile(member).read())
   target.chmod(member.mode)
S=R/'source'
M=json.loads((R/'source-transport.json').read_bytes())
for name,pin in M['files'].items():
 raw=(S/name).read_bytes()
 assert len(raw)==pin['bytes'] and hashlib.sha256(raw).hexdigest()==pin['sha256']
def snapshot():
 return {name:{'bytes':len((S/name).read_bytes()),'sha256':hashlib.sha256((S/name).read_bytes()).hexdigest()} for name in M['files']}
before=snapshot()
def run(label,argv,timeout=60,cwd=S):
 (Q/(label+'.intent.json')).write_text(json.dumps({'argv':list(map(str,argv)),'timeout_seconds':timeout})+'\n')
 start=time.monotonic()
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PIP_DISABLE_PIP_VERSION_CHECK='1',TMPDIR=str(Q))
 result=subprocess.run(argv,capture_output=True,cwd=cwd,env=env,timeout=timeout)
 (Q/(label+'.stdout')).write_bytes(result.stdout);(Q/(label+'.stderr')).write_bytes(result.stderr)
 terminal={'returncode':result.returncode,'seconds':time.monotonic()-start}
 (Q/(label+'.terminal.json')).write_text(json.dumps(terminal)+'\n')
 print(label,json.dumps(terminal),result.stdout.decode(errors='replace')[-3000:],result.stderr.decode(errors='replace')[-6000:],flush=True)
 assert result.returncode==0,label
 return result
run('python-packaging-prerequisites',[sys.executable,'-I','-B','-c',
 "import sys,sysconfig,importlib.metadata,json;print(json.dumps({'executable':sys.executable,'python':sys.version,'soabi':sysconfig.get_config_var('SOABI'),'setuptools':importlib.metadata.version('setuptools'),'wheel':importlib.metadata.version('wheel'),'pip':importlib.metadata.version('pip')}))"])
wheels=R/'wheels';wheels.mkdir(mode=0o700)
run('actual-setuptools-component-wheel',[sys.executable,'-I','-B','-c',
 "from setuptools import build_meta; print(build_meta.build_wheel("+repr(str(wheels))+"))"],60)
wheel,=wheels.glob('*.whl')
graph=R/'native-graph';graph.mkdir(mode=0o700)
shutil.copytree(A/'current-carrier-development-v1/components',graph/'components')
shutil.copytree(A/'stage19-native-component-v2/qualification/stage',graph/'release')
def pin(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def canonical(x):return (json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()
helpers=[]
for selector,name in [('HEPTA_HIA_SERVICE_ARTIFACT_MANIFEST','artifact'),('HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST','verification')]:
 p=graph/'components'/name/'manifest.json'
 helpers.append({'selector':selector,'manifest_path':str(p),'manifest_sha256':pin(p)})
base=graph/'base-v1.json';base.write_bytes(canonical({'schema':'hepta.hia.native-helpers.v1','target':'linux-x86_64-lp64','abi':'hia-byte-six-argument-v1','helpers':helpers}))
page=graph/'components/page/manifest.json'
typed=graph/'typed-page.json';typed.write_bytes(canonical({'schema':'hepta.hia.artifact-page-worker-bundle.v1','target':'linux-x86_64-lp64','abi':'hia-byte-six-argument-v1','base_bundle':str(base),'base_bundle_sha256':pin(base),'page_bundle':str(page),'page_bundle_sha256':pin(page)}))
for p in graph.rglob('*'):
 if p.is_file():p.chmod(0o600)
compiler=A/'hia-source-build'
argv=[sys.executable,'-I','-B',str(S/'tools/install_hia_carrier_compat.py'),
 '--wheel',str(wheel),'--expected-wheel-sha256',pin(wheel),
 '--compiler',str(compiler),'--expected-compiler-sha256',pin(compiler),
 '--cc',str(Path('/usr/bin/cc').resolve(strict=True)),
 '--native-root',str(graph),'--base-bundle',str(typed),'--expected-base-sha256',pin(typed),
 '--policy-release',str(graph/'release'),'--expected-publication-sha256','a98a3fe382aac7f62a20de387a87b90197016cf0d1189dd33973698963150214',
 '--target',str(R/'installed'),'--output',str(R/'installation')]
run('actual-target-bound-installation',argv,600)
run('actual-installed-controls',[sys.executable,'-I','-B',str(S/'tests/test_hia_carrier_default_install.py'),'--installation',str(R/'installation'),'--output',str(Q/'installed-controls')],180)
after=snapshot()
assert after==before
result=json.loads((R/'installation/result.json').read_bytes())
assert result['status']=='PASS'
(Q/'source-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
(Q/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
report={'status':'PASS','source_unchanged':True,'source_files':len(before),'installed_file_count':result['installed_file_count'],'scope':'ACTUAL_TARGET_BOUND_HOST_COMPAT_INSTALL; native publication is an actual standalone stage19 component; final whole release remains separate'}
(Q/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report),flush=True)
