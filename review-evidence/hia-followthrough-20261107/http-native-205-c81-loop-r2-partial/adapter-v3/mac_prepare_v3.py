import hashlib,io,json,os,pathlib,stat,subprocess,sys,tarfile,time
parent=pathlib.Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
archive=parent/'http-native-qualification-205-c81-r3.tar.gz'
destination=parent/'http-native-qualification-205-c81-r3'
dependency_root=parent/'http-native-qualification-205-c81-r1'
expected='8fcf7acb183be7228ae77682c9c6dbe013c055ddf45de8b0779988b54532da57'
sha=lambda b:hashlib.sha256(b).hexdigest()
def owned(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as source:
  info=os.fstat(source.fileno())
  assert stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and not info.st_mode&0o022
  return source.read()
prior=owned(dependency_root/'PREPARATION.json')
assert sha(prior)=='1b58554b9b2a95beb403fda00565ecca2a1b19eb9af05b84117871cc2ae990df'
prior=json.loads(prior);assert prior['status']=='prepared' and prior['global_install_performed'] is False and prior['http_calls_performed'] is False
raw=owned(archive);assert len(raw)==29060 and sha(raw)==expected
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as tar:
 members=tar.getmembers()
 assert len(members)==14 and len({x.name for x in members})==len(members)
 assert all(x.isfile() and not pathlib.PurePosixPath(x.name).is_absolute() and '..' not in pathlib.PurePosixPath(x.name).parts and 0<=x.size<=1024*1024 for x in members)
 payload={x.name:tar.extractfile(x).read() for x in members}
manifest=json.loads(payload['PACKAGE_V3.json'])
assert set(payload)=={'PACKAGE_V3.json'}|{x['path'] for x in manifest['files']}
for row in manifest['files']:
 assert len(payload[row['path']])==row['bytes'] and sha(payload[row['path']])==row['sha256']
destination.mkdir(mode=0o700)
for name,data in payload.items():
 target=destination/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as output:
  output.write(data);output.flush();os.fsync(output.fileno())
python=str(dependency_root/'venv/bin/python')
commands=[]
def run(label,argv):
 started=time.monotonic()
 p=subprocess.run(argv,cwd=destination,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 (destination/(label+'.stdout')).write_bytes(p.stdout);(destination/(label+'.stderr')).write_bytes(p.stderr)
 commands.append({'name':label,'argv':argv,'exit_code':p.returncode,'duration_seconds':time.monotonic()-started,'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)})
 assert p.returncode==0,(label,p.returncode)
 return p.stdout
run('adapter-v3-tests',[python,'-B','-m','unittest','-v','test_http_qualification'])
validation="import importlib.metadata,json,pathlib,sys;from jsonschema import Draft202012Validator;c=json.loads(pathlib.Path('docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes());[(Draft202012Validator.check_schema(t['inputSchema']),Draft202012Validator.check_schema(t['outputSchema'])) for t in c['tools']];print(json.dumps({'python':sys.version,'executable':sys.executable,'validated_schemas':2*len(c['tools']),'dependencies':{n:importlib.metadata.version(n) for n in ['jsonschema','jsonschema-specifications','referencing','rpds-py','attrs']}}))"
versions=json.loads(run('catalog-schema-validation',[python,'-B','-c',validation]))
assert versions==prior['actual_environment']
receipt={'schema':'hia-http-isolated-mac-preparation-v3','status':'prepared','archive_sha256':expected,'archive_bytes':len(raw),'destination':str(destination),'adapter_sha256':sha((destination/'http_qualification.py').read_bytes()),'source':json.loads((destination/'EXACT_SOURCE.json').read_bytes()),'commands':commands,'actual_environment':versions,'dependency_preparation_sha256':'1b58554b9b2a95beb403fda00565ecca2a1b19eb9af05b84117871cc2ae990df','dependency_environment':str(dependency_root/'venv'),'global_install_performed':False,'token_read':False,'http_calls_performed':False}
(destination/'PREPARATION.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'status':'prepared','destination':str(destination),'adapter_tests':11,'validated_schemas':22,'adapter_sha256':receipt['adapter_sha256'],'preparation_sha256':sha((destination/'PREPARATION.json').read_bytes()),'http_calls_performed':False}),flush=True)
