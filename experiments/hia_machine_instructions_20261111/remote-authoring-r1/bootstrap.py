import importlib.util,json,os,sys,time
from pathlib import Path
from hashlib import sha1,sha256
payload=json.loads(sys.stdin.buffer.read(1048577))
request=payload['request']
root=Path(request['root'])
assert root==Path('/home/qian-qi/he26instructionsr1')
assert request['original_source']=='/home/qian-qi/he26v67r2/s'
binary=Path(sys.executable).resolve()
assert sha256(binary.read_bytes()).hexdigest()==request['python_binary_sha256']
worker=payload['worker'].encode()
assert sha1(b'blob '+str(len(worker)).encode()+b'\0'+worker).hexdigest()==request['worker_git_blob']
root.mkdir(mode=0o700)
(root/'request.json').write_text(json.dumps(request,indent=2,sort_keys=True)+'\n')
(root/'worker.py').write_bytes(worker)
(root/'launch-payload.json').write_text(json.dumps(payload,indent=2,sort_keys=True)+'\n')
owner=Path(request['original_source'])/'tools/hia_selfhost_process_owner.py'
owner_raw=owner.read_bytes()
assert sha256(owner_raw).hexdigest()==request['owner_sha256']
spec=importlib.util.spec_from_file_location('_hia_original_process_owner',owner)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
 'PYTHONDONTWRITEBYTECODE':'1','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null',
 'GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0'}
started=time.monotonic()
life=module.run_owned([sys.executable,'-B',str(root/'worker.py'),str(root)],
 cwd=root,env=env,stdout_path=root/'child.stdout',stderr_path=root/'child.stderr',
 receipt_path=root/'lifecycle.json',qualification_seconds=180)
clean=life.get('cleanup',{})
okay=(life.get('status')=='OWNED_PROCESS_COMPLETED' and life.get('returncode')==0
 and life.get('exit_observed_before_deadline') is True and life.get('timed_out') is False
 and not life.get('interrupted_signals') and not life.get('event_overflow') and not life.get('owner_error')
 and clean.get('complete') is True and clean.get('observed_echild') is True
 and clean.get('leader_reaped') is True and not clean.get('deadline_exceeded')
 and not clean.get('errors') and not clean.get('remaining_direct_children')
 and not any(e.get('kind')=='owned_child_sigkill' for e in life.get('events',[])))
inner=json.loads((root/'report.json').read_bytes()) if (root/'report.json').is_file() else None
result={'schema':'hia.machine-instructions-owned-authoring.v1',
 'status':'PASS' if okay and inner and inner['status']=='SOURCE_GENERATED_WITHIN_ORIGINAL_LIMITS_NOT_NATIVE_QUALIFIED' else 'HOLD',
 'scope':'ISOLATED_SOURCE_MATERIALIZATION_AND_AUTHORING_ONLY',
 'lifecycle':life,'natural_owner_success':okay,
 'inner_status':inner.get('status') if inner else None,
 'inner_report_sha256':sha256((root/'report.json').read_bytes()).hexdigest() if inner else None,
 'seconds':time.monotonic()-started,'native_compilation_executed':False,
 'product_tests_executed':False,'whole_native_delivery':False,
 'owner_source_stable':owner.read_bytes()==owner_raw}
(root/'control.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:result[k] for k in ('status','scope','natural_owner_success',
 'inner_status','seconds')},sort_keys=True),flush=True)
raise SystemExit(0 if result['status']=='PASS' else 1)
