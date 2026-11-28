from pathlib import Path
import ast,hashlib,json,os,subprocess,tarfile
R=Path('/Users/qianqi/work/hia-native-carrier-policy-20261128-2ac5')
S=R/'source'; O=R/'default-install-input-v4'; O.mkdir(mode=0o700)
def git(*args):
 r=subprocess.run(['/usr/bin/git','-C',str(S),*args],capture_output=True)
 (O/'git.stderr').open('ab').write(r.stderr)
 if r.returncode:raise RuntimeError(r.stderr.decode())
 return r.stdout
head=git('rev-parse','HEAD').decode().strip()
rows={}
for line in git('ls-tree','-rz','HEAD','--','hepta').split(b'\0'):
 if not line:continue
 metadata,name=line.split(b'\t');mode,typ,oid=metadata.split()
 if typ!=b'blob':raise ValueError('not blob')
 rows[name.decode()]=(mode.decode(),oid.decode())
captured={}
def read(name):
 p=S/name
 if p.is_file():
  raw=p.read_bytes();captured[name]=(p,raw)
 else:raw=git('show','HEAD:'+name)
 return raw
def literal(tree,name):
 nodes=[n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
 if len(nodes)!=1:raise ValueError(name)
 return ast.literal_eval(nodes[0])
setup=ast.parse(read('setup.py'))
contract=ast.parse(read('hepta/hia_agent_contract.py'))
symbols=('DISCOVERY_FILES','NATIVE_SOURCE_FILES','SOURCE_BUILD_FILES','COMPILER_BUILD_FILES','PUBLICATION_BUILD_FILES','BACKEND_BUILD_FILES','EMITTER_BUILD_FILES','BYTE_WRAPPER_BUILD_FILES','MACHINE_OBJECT_BUILD_FILES','EXECUTION_OBSERVATION_BUILD_FILES','CONTINUATION_BUILD_FILES')
resources=[]
for symbol in symbols:
 values=literal(contract,symbol)
 resources.extend(('docs/'+v if symbol=='DISCOVERY_FILES' else v) for v in values)
for name in ('hepta/hia_executable_capture.py','hepta/hia_nominal_program_native.py'):
 resources.extend(literal(ast.parse(read(name)),'PACKAGE_RESOURCES'))
for name in ('VM_INTEGER_DIVREM_RESOURCES','VM_INTEGER_ARITHMETIC_RESOURCES','VM_INTEGER_SCALAR_RESOURCES','NOMINAL_BYTE_BOUNDARY_RESOURCES','CARRIER_POLICY_RESOURCES'):
 resources.extend(literal(setup,name))
names=set(rows)|set(resources)|{'setup.py','pyproject.toml','MANIFEST.in','hepta/hia_carrier_default.py','tools/install_hia_carrier_compat.py','tests/test_hia_carrier_default_install.py','tools/capture_hia_current_carrier_bundle.py','tools/capture_hia_native_carrier_bundle.py'}
source=O/'source';source.mkdir(mode=0o700)
pins={}
for name in sorted(names):
 raw=read(name);p=source/name;p.parent.mkdir(parents=True,exist_ok=True)
 p.write_bytes(raw);p.chmod(0o600)
 pins[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'source':'physical' if name in captured else 'committed_git'}
for name,(p,raw) in captured.items():
 if p.read_bytes()!=raw:raise ValueError('source changed:'+name)
(O/'manifest.json').write_text(json.dumps({'head':head,'scope':'actual candidate packaging inputs; not frozen native qualification','files':pins},indent=2,sort_keys=True)+'\n')
archive=O/'source.tar.gz'
with tarfile.open(archive,'w:gz') as t:
 t.add(source,arcname='source');t.add(O/'manifest.json',arcname='source-transport.json')
raw=archive.read_bytes()
print(json.dumps({'head':head,'files':len(pins),'bytes':sum(v['bytes'] for v in pins.values()),'archive':str(archive),'archive_bytes':len(raw),'archive_sha256':hashlib.sha256(raw).hexdigest()},sort_keys=True),flush=True)
