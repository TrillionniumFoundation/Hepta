"""One actual repaired R5 original control sequence; no retries or budget changes."""
import hashlib,json,os,subprocess,time
from pathlib import Path
D=Path('/tmp/hia-root-v141-dda7');B=Path('/tmp/hia-inspect-cli-controls-r5-dda7');R=Path('/dev/shm/hia-inspect-cli-controls-r5-dda7');O=Path('/tmp/hia-root-inspect-cli-r5-execution-dda7')
def pin(raw,mode=None):
 v={'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
 if mode is not None:v['mode']=mode
 return v
def put(name,v):
 raw=v if type(v)is bytes else (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
 with (O/name).open('xb') as f:f.write(raw)
auth=(D/'inspect-cli-r5-product-root-authorization.json').read_bytes()
proof=(D/'inspect-cli-r5-binding-root-terminal.json').read_bytes()
assert pin(proof)['git_blob']=='601bc8e55d1f69de2363980a31e27daf7777e998'
braw=(R/'BINDING-RESULT.json').read_bytes();b=json.loads(braw)
praw=(R/'EXECUTION-PLAN.json').read_bytes();p=json.loads(praw)
assert pin(braw,'100644')==json.loads(proof)['binding_result']
assert pin(praw,'100644')==b['plan']['pin'] and pin(praw)['git_blob']=='fc2619602ffbaf2ac9baf93aa31435eb8d3d46b9'
assert b['status']=='BOUND_NOT_EXECUTED' and p['source_tree']=='d5e3ca6576607e3bfaad4bae09058a6c9fcfd1a5'
runner=(B/'run_inspect_cli_controls.py').read_bytes()
assert pin(runner)['git_blob']=='2f70f0a250f023a0e19bea07a990f463177271b6'
expected=[p['runtime']['launch_executable'],'-I','-B',str(B/'run_inspect_cli_controls.py'),'--execute',str(R/'EXECUTION-PLAN.json'),'--plan-sha256',pin(praw)['sha256']]
assert b['argv']==expected
environment=json.loads((B/'PREPARATION-LAUNCH.json').read_bytes())['environment']
old_launch=json.loads(Path('/tmp/hia-inspect-cli-controls-r3-preparation-handoff-dda7/PRODUCT-LAUNCH.json').read_bytes())
assert environment==old_launch['environment']
assert not os.path.lexists(O) and not os.path.lexists(p['attempt'])
launch={'schema':'hepta.root.inspect-cli-r5.actual-launch.v1','argv':expected,'cwd':str(B),'environment':environment,'plan':pin(praw),'binding_result':pin(braw),'runner':pin(runner),'scope':{'groups':18,'method_invocations':76,'compiles':7},'retry':False}
O.mkdir(mode=0o700);put('LAUNCH.json',launch);put('AUTHORIZATION.json',auth)
start=time.monotonic_ns()
with (O/'stdout.raw').open('xb') as stdout,(O/'stderr.raw').open('xb') as stderr:
 child=subprocess.Popen(expected,cwd=B,env=environment,stdout=stdout,stderr=stderr)
 put('STARTED.json',{'pid':child.pid,'started_ns':start,'execution_attempts':1})
 code=child.wait()
finish=time.monotonic_ns()
result={'schema':'hepta.root.inspect-cli-r5.execution-outer.v1','status':'EXITED','pid':child.pid,'returncode':code,'execution_attempts':1,'automatic_retry':False,'started_ns':start,'finished_ns':finish,'elapsed_ns':finish-start,'authorization':pin(auth),'launch':pin((O/'LAUNCH.json').read_bytes()),'stdout.raw':pin((O/'stdout.raw').read_bytes()),'stderr.raw':pin((O/'stderr.raw').read_bytes())}
put('OUTER.json',result);print(json.dumps(result,sort_keys=True));raise SystemExit(code)
