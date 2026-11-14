"""Root one-shot outer record; the frozen runner owns all original product budgets."""
import hashlib,json,os,stat,subprocess,time,traceback
from pathlib import Path
ROOT=Path('/tmp/hia-root-op10-r3-execution-dda7')
LAUNCH=Path('/tmp/hia-inspect-cli-controls-r3-preparation-handoff-dda7/PRODUCT-LAUNCH.json')
AUTH=Path('/tmp/hia-root-v141-dda7/op10-r3-root-product-authorization.json')
def pin(raw):
 return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':hashlib.sha256(raw).hexdigest()}
def seven(s):
 return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p,expected=None):
 p=Path(p);s=p.lstat();assert stat.S_ISREG(s.st_mode)
 raw=p.read_bytes();assert seven(p.lstat())==seven(s)
 if expected is not None:
  assert pin(raw)=={k:expected[k] for k in ('bytes','git_blob','sha256')}
 return raw
def save(name,v):
 raw=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
 with (ROOT/name).open('xb') as f:f.write(raw)
 return pin(raw)
raw=read(LAUNCH);assert pin(raw)['git_blob']=='6ec238ca3ed168c65257eca7a25b5b99e478e0a4'
launch=json.loads(raw);authraw=read(AUTH)
assert pin(authraw)['git_blob']=='8f1a287184c596f6db9220b9cf59efab4feb5924'
praw=read(launch['plan']['path'],launch['plan']['pin']);plan=json.loads(praw)
braw=read(launch['binding_result']['path'],launch['binding_result']['pin']);binding=json.loads(braw)
read(launch['runner']['path'],launch['runner']['pin'])
assert launch['argv']==binding['argv'] and launch['group_order']==plan['group_order'] and launch['limits']==plan['limits']
assert launch['owner_groups']==18 and launch['method_invocations']==76 and launch['compile_calls']==7 and launch['retry'] is False
assert not ROOT.exists() and not Path(plan['attempt']).exists()
ROOT.mkdir(mode=0o700)
save('INTENT.json',{'schema':'hepta.root.op10-r3-execution-intent.v1','launch':pin(raw),'authorization':pin(authraw),'plan':pin(praw),'argv':launch['argv'],'cwd':launch['cwd'],'environment':launch['environment'],'automatic_retry':False})
start=time.monotonic_ns();result={'schema':'hepta.root.op10-r3-execution-outer.v1','status':'STARTING','started_ns':start,'launch':pin(raw),'authorization':pin(authraw),'automatic_retry':False,'product_execution_attempts':0}
process=None
try:
 with (ROOT/'stdout.raw').open('xb') as out,(ROOT/'stderr.raw').open('xb') as err:
  result['product_execution_attempts']=1
  process=subprocess.Popen(launch['argv'],cwd=launch['cwd'],env=launch['environment'],stdout=out,stderr=err)
  save('PROCESS.json',{'pid':process.pid,'created_ns':time.monotonic_ns(),'argv':launch['argv']})
  result['pid']=process.pid
  result['returncode']=process.wait()
 result['status']='EXITED'
except BaseException:
 result['status']='OUTER_ERROR';result['error']=traceback.format_exc()
 raise
finally:
 result['finished_ns']=time.monotonic_ns();result['elapsed_ns']=result['finished_ns']-start
 for name in ('stdout.raw','stderr.raw'):
  path=ROOT/name
  if path.exists():result[name]=pin(read(path))
 save('OUTER.json',result)
 print(json.dumps(result,sort_keys=True),flush=True)
raise SystemExit(result['returncode'])
