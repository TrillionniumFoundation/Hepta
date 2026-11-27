from pathlib import Path
import sys,json,hashlib,subprocess,time,os,stat
spec=json.load(sys.stdin);scope=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807');root=scope/'src'
data=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807')
assert data.is_dir() and not data.is_symlink() and data.resolve()==data and stat.S_IMODE(data.stat().st_mode)==0o700
for name,expected in {**spec['source_pins'],**spec['original_test_pins']}.items():
 raw=(root/name).read_bytes();assert len(raw)==expected['bytes'] and hashlib.sha256(raw).hexdigest()==expected['sha256'],name
assert os.statvfs(data).f_bavail*os.statvfs(data).f_frsize>8_000_000_000
tmp=scope/'temporary';tmp.mkdir(mode=0o700,exist_ok=True)
env={k:v for k,v in os.environ.items() if not k.startswith(('HEPTA_HIA_','PYTHON'))};env['TMPDIR']=str(tmp)
def filepin(path):
 raw=path.read_bytes();return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
native=scope/'word-native-v5'
command=[sys.executable,'-I','-B',str(root/'tools/qualify_hia_service_bootstrap_word.py'),'--development-compiler',str(scope/'development-B3-acb6478.flat'),'--output',str(native)]
start=time.monotonic();p=subprocess.run(command,cwd=root,env=env,capture_output=True,timeout=480)
(scope/'word-native-v5.stdout').write_bytes(p.stdout);(scope/'word-native-v5.stderr').write_bytes(p.stderr)
record={'command':command,'returncode':p.returncode,'seconds':time.monotonic()-start,'stdout':filepin(scope/'word-native-v5.stdout'),'stderr':filepin(scope/'word-native-v5.stderr')}
if (native/'qualification.json').is_file():record['qualification']=filepin(native/'qualification.json')
(scope/'word-native-v5.result.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(json.dumps({'event':'fresh_final_source_native_component_terminal',**record},sort_keys=True),flush=True)
if p.returncode:raise RuntimeError('final-source native component did not pass')
out=data/'source-suite-v1';assert not out.exists()
command=[sys.executable,'-I','-B',str(root/'tools/qualify_hia_service_bootstrap.py'),'--suite','source','--output',str(out)]
started=time.time_ns()
record={'command':command,'source_pins':spec['source_pins'],'unchanged_original_test_pins':spec['original_test_pins'],'started_time_ns':started,'source_outer_budget_seconds':1800,'original_inner_seconds':600,'candidate_inner_seconds':1800,'cleanup_seconds':3,'raw_data_outside_executable_tree':True,'whole_native_stack_qualified':False}
(data/'source-suite-v1.invocation.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(json.dumps({'event':'original_owned_source_suite_started','output':str(out),'started_time_ns':started,'outer_seconds':1800,'cleanup_seconds':3},sort_keys=True),flush=True)
with (data/'source-suite-v1.stdout').open('xb') as stdout,(data/'source-suite-v1.stderr').open('xb') as stderr:
 p=subprocess.run(command,cwd=root,env=env,stdout=stdout,stderr=stderr,timeout=1850)
record.update({'ended_time_ns':time.time_ns(),'returncode':p.returncode,'stdout':filepin(data/'source-suite-v1.stdout'),'stderr':filepin(data/'source-suite-v1.stderr')})
if (out/'report.json').is_file():record['owned_report']=filepin(out/'report.json')
(data/'source-suite-v1.result.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(json.dumps({'event':'original_owned_source_suite_terminal',**record},sort_keys=True),flush=True)
if p.returncode:raise RuntimeError('original owned source suite did not pass')
