"""One original VM12 owner via its actual bound launch; no retries."""
import hashlib,json,os,subprocess,time
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7');B=Path('/tmp/hia-patch-result-execution-r1-dda7/vm12-r3');R=B/'bindings/04-vm12';O=Path('/tmp/hia-root-patch-vm12-r3-execution-dda7')
def pin(raw):return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def put(name,v):
 raw=v if type(v)is bytes else (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
 with (O/name).open('xb') as f:f.write(raw)
proof=(D/'patch-vm12-r3-root-binding-terminal.json').read_bytes();assert pin(proof)['git_blob']=='bd2527f149027ccfa3779b39371621ac4b1a7c88'
review=json.loads(proof);launch_raw=(R/'LAUNCH.json').read_bytes();launch=json.loads(launch_raw)
assert pin(launch_raw)==review['actual_launch'] and pin((R/'PLAN.json').read_bytes())==review['actual_plan']
assert pin((B/'bind_vm12.py').read_bytes())['git_blob']=='827b1caabac47aeb1fb61795fba02c205d45941d'
assert pin((B/'run_controls.py').read_bytes())['git_blob']=='625229147d5f160a3c746c7b0a20d0fa0818539b'
assert launch['kind']=='vm' and launch['argv'][-2:]==['--launch','vm']
assert not os.path.lexists(O) and not os.path.lexists('/dev/shm/hia-patch-result-controls-r1-dda7/04-vm12') and not os.path.lexists(R/'LAUNCH-INTENT.json')
auth=(D/'patch-vm12-r3-root-product-authorization.json').read_bytes();O.mkdir(mode=0o700);put('LAUNCH.json',launch_raw);put('AUTHORIZATION.json',auth)
start=time.monotonic_ns()
with (O/'stdout.raw').open('xb') as stdout,(O/'stderr.raw').open('xb') as stderr:
 child=subprocess.Popen(launch['argv'],cwd=launch['cwd'],env=launch['environment'],stdout=stdout,stderr=stderr)
 put('STARTED.json',{'pid':child.pid,'started_ns':start,'execution_attempts':1})
 rc=child.wait()
end=time.monotonic_ns()
result={'schema':'hepta.root.patch-vm12-r3-execution-outer.v1','status':'EXITED','returncode':rc,'execution_attempts':1,'automatic_retry':False,'started_ns':start,'finished_ns':end,'elapsed_ns':end-start,'launch':pin(launch_raw),'authorization':pin(auth),'stdout.raw':pin((O/'stdout.raw').read_bytes()),'stderr.raw':pin((O/'stderr.raw').read_bytes())}
put('OUTER.json',result);print(json.dumps(result,sort_keys=True));raise SystemExit(rc)
