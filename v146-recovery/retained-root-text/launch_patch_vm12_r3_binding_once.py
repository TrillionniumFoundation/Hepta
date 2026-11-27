"""One fixed PatchResult VM12 R3 binder command, no product launch."""
import hashlib,json,os,subprocess,time
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7');B=Path('/tmp/hia-patch-result-execution-r1-dda7/vm12-r3');O=Path('/tmp/hia-root-patch-vm12-r3-binding-dda7')
def pin(raw):return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def put(name,v):
 raw=v if type(v)is bytes else (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
 with (O/name).open('xb') as f:f.write(raw)
launch_raw=(B/'BINDING-LAUNCH.json').read_bytes();launch=json.loads(launch_raw)
assert pin(launch_raw)['git_blob']=='cb3c61ec6cde15df973eca85877558e098727848'
assert pin((B/'AUTHORITY.json').read_bytes())['git_blob']=='b277e061c45f6ace1074177261f9747958cddad7'
assert pin((B/'bind_vm12.py').read_bytes())['git_blob']=='827b1caabac47aeb1fb61795fba02c205d45941d'
assert pin((D/'patch-vm12-r3-root-binding-preflight.json').read_bytes())['git_blob']=='0db4857620e08b82b18911d653d9cfd72ee54e11'
auth=(D/'patch-vm12-r3-root-binding-authorization.json').read_bytes()
assert not os.path.lexists(O) and not os.path.lexists(launch['output'])
O.mkdir(mode=0o700);put('LAUNCH.json',launch_raw);put('AUTHORIZATION.json',auth)
start=time.monotonic_ns()
with (O/'stdout.raw').open('xb') as stdout,(O/'stderr.raw').open('xb') as stderr:
 child=subprocess.Popen(launch['argv'],cwd=launch['cwd'],env=launch['environment'],stdout=stdout,stderr=stderr)
 put('STARTED.json',{'pid':child.pid,'started_ns':start,'binding_attempts':1,'products':0})
 rc=child.wait()
end=time.monotonic_ns()
result={'schema':'hepta.root.patch-vm12-r3-binding-outer.v1','status':'EXITED','returncode':rc,'binding_attempts':1,'product_calls':0,'automatic_retry':False,'started_ns':start,'finished_ns':end,'elapsed_ns':end-start,'launch':pin(launch_raw),'authorization':pin(auth),'stdout.raw':pin((O/'stdout.raw').read_bytes()),'stderr.raw':pin((O/'stderr.raw').read_bytes())}
put('OUTER.json',result);print(json.dumps(result,sort_keys=True));raise SystemExit(rc)
