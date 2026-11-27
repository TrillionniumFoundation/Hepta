from pathlib import Path
import ast,sys,json,hashlib,os,stat,subprocess,time
spec=json.load(sys.stdin)
scope=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807');root=scope/'src'
data=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807')
out=data/'isolated-current-v2-apply-and-controls'
def pin(raw):
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
assert root.is_dir() and root.resolve()==root and not root.is_symlink()
oldterminal=json.loads((data/'source-suite-v1.result.json').read_bytes())
assert oldterminal['returncode']==1 and oldterminal['ended_time_ns']>=oldterminal['started_time_ns']
old={}
for name,text in spec['files'].items():
 path=root/name;raw=path.read_bytes()
 assert pin(raw)==spec['before'][name],('before',name,pin(raw))
 changed=text.encode();assert pin(changed)==spec['pins'][name],name
 compile(changed,str(path),'exec',dont_inherit=True)
 old[name]=raw
def defs(raw):
 return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
for name in ('tests/hia_bootstrap_current_dispatch.py',):
 before=defs(old[name]);after=defs(spec['files'][name])
 assert all(after[key]==value for key,value in before.items())
originals={}
for name in ('tests/test_hia_service_bootstrap_sources.py','tests/test_hia_service_bootstrap_qualification.py','tests/test_hia_service_bootstrap_fixed_words.py','hepta/hia_agent_service.py'):
 raw=(root/name).read_bytes();originals[name]=pin(raw)
assert originals['hepta/hia_agent_service.py']['sha256']=='afc92b555bd0dfa23f25c4f9c2661af30853474342f4e32a036d37c1ce663a57'
out.mkdir(mode=0o700)
(out/'proposal.json').write_text(json.dumps(spec,sort_keys=True,indent=2)+'\n')
for name,raw in old.items():
 path=out/'before'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
for name,text in spec['files'].items():
 path=root/name;tmp=path.with_name(path.name+'.isolated-current-v2-tmp')
 with tmp.open('xb') as stream:stream.write(text.encode())
 os.chmod(tmp,stat.S_IMODE(path.stat().st_mode));os.replace(tmp,path)
 assert pin(path.read_bytes())==spec['pins'][name]
assert all(pin((root/name).read_bytes())==expected for name,expected in originals.items())
(out/'applied.json').write_text(json.dumps({'before':spec['before'],'after':spec['pins'],'unchanged_originals':originals,'applied_time_ns':time.time_ns(),'whole_native_stack_qualified':False},sort_keys=True,indent=2)+'\n')
print(json.dumps({'event':'four_file_isolation_applied','paths':list(spec['files']),'originals_unchanged':True},sort_keys=True),flush=True)
env={k:v for k,v in os.environ.items() if not k.startswith(('HEPTA_HIA_','PYTHON'))}
env['TMPDIR']=str(scope/'temporary')
command=[sys.executable,'-I','-B','-c',"import sys,unittest,json;sys.path.insert(0,"+repr(str(root))+");suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in ['tests.test_hia_service_bootstrap_sources.ServiceBootstrapStaticSourceTests','tests.test_hia_service_bootstrap_fixed_words.ServiceBootstrapFixedWordSourceTests','tests.test_hia_service_bootstrap_word.ServiceBootstrapWordSourceTests']);assert suite.countTestCases()==13;result=unittest.TextTestRunner(verbosity=2).run(suite);print(json.dumps({'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped)}));sys.exit(0 if result.wasSuccessful() and not result.skipped else 1)"]
started=time.monotonic()
with (out/'strict.stdout').open('xb') as stdout,(out/'strict.stderr').open('xb') as stderr:
 p=subprocess.run(command,cwd=root,env=env,stdout=stdout,stderr=stderr,timeout=90)
value={'command':command,'returncode':p.returncode,'seconds':time.monotonic()-started,'stdout':pin((out/'strict.stdout').read_bytes()),'stderr':pin((out/'strict.stderr').read_bytes()),'unchanged_originals':originals,'whole_native_stack_qualified':False}
assert all(pin((root/name).read_bytes())==expected for name,expected in originals.items())
assert all(pin((root/name).read_bytes())==expected for name,expected in spec['pins'].items())
(out/'strict-result.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
print(json.dumps({'event':'strict_controls_terminal',**value},sort_keys=True),flush=True)
if p.returncode:raise RuntimeError('strict controls failed')
