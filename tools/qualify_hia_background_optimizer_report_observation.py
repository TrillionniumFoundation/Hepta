from pathlib import Path
from hashlib import sha256
import ctypes as C,struct,types,copy,json,threading,collections,os,sys,resource,importlib.util
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');B=A.parent/'cleanup-audit-20261124T0745Z';W=A/'native-background-source'
D=A/'native-background-report-observed-timing-v2';D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.path.insert(0,str(W));os.environ['Z3_LIBRARY_PATH']=str(T/'qa-z3-4.15.4')
from hepta import hia_background_optimizer as bg
def module(path,name):
 sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
h=module(A/'background-report-observed-pure-harness-v1.py','observed_reports');m=h.m;ve=h.value_entry
cellpath=A/'native-background-future-cell-v4/future-cell.so';cellpin='a070bd290676e3b6bb89772b2e9c668be89749428762274f0c8675c8ebee70b9';assert sha256(cellpath.read_bytes()).hexdigest()==cellpin
so=C.CDLL(str(cellpath));entry=so.hia_mv_background_future_cell;entry.argtypes=[C.c_void_p,C.c_uint64]*3;entry.restype=C.c_uint32
kernelso=C.CDLL(str(B/'native-multiversion-future-v2/future-component.so'));kernel=kernelso.hia_mv_future;kernel.argtypes=entry.argtypes;kernel.restype=C.c_uint32
def u(b,n):return struct.unpack_from('<Q',b,n)[0]
calls=0
class Cells:
 def __init__(self,v):
  self.v=v;self.ctx=C.create_string_buffer(256);self.refs=[]
  self.call(0,a=(C.cast(kernel,C.c_void_p).value,C.cast(ve,C.c_void_p).value,C.addressof(v.ctx)),x=256)
 def call(self,op,a=(0,0,0),b=(0,0,0),x=0,kind=0,ns=0,infinite=0,status=0):
  global calls
  s=bytearray(128);s[:8]=b'HIABFQ01';struct.pack_into('<Q',s,8,op);struct.pack_into('<3Q',s,24,*a);struct.pack_into('<3Q',s,48,*b)
  if op==0:struct.pack_into('<Q',s,48,x)
  struct.pack_into('<Q',s,80,kind);struct.pack_into('<QQ',s,104,ns,infinite)
  sb=C.create_string_buffer(bytes(s));out=C.create_string_buffer(b'\xb5'*16384,16384)
  rc=entry(sb,128,out,16384,self.ctx,256);calls+=1
  assert rc==0 and out.raw[:8]==b'HIABFR01',(op,rc,out.raw[:128].hex())
  assert u(out.raw,8)==status,(op,u(out.raw,8),status,out.raw[:128].hex())
  return out.raw
 def take(self,r):
  cap=struct.unpack_from('<3Q',r,16);assert cap[0];self.refs.append(cap);return cap
 def make(self):return self.take(self.call(1))
 def retain(self,c):return self.take(self.call(2,c))
 def drop(self,c):r=self.call(3,c);self.refs.remove(c);return r
 def result(self,c,ns=0,infinite=0):
  r=self.call(10,c,ns=ns,infinite=infinite)
  if u(r,40)==0:
   cap=struct.unpack_from('<3Q',r,80);assert cap[0];self.v.held.append(cap);return cap,r
  return None,r
 def finish(self):
  for c in self.refs[:]:self.drop(c)
  self.call(5)

def kcall(ptr,op):
 s=struct.pack('<8s7Q',b'HIAMVFQ1',op,0,0,0,0,0,0);sb=C.create_string_buffer(s);o=C.create_string_buffer(512)
 rc=kernel(sb,64,o,512,ptr,512);assert rc==0 and o.raw[:8]==b'HIAMVFR1' and u(o.raw,8)==0,(op,rc,o.raw[:72].hex())
 return o.raw
def ordered(x):
 if type(x)is dict:return('dict',[(k,ordered(v))for k,v in x.items()])
 if type(x)is list:return('list',[ordered(v)for v in x])
 return(type(x).__name__,x)
def meta(started):
 return dict(job=7,generation=3,epoch=6,function='main',before_sha256='b'*64,before_input_sha256='c'*64,original_baseline_sha256='a'*64,submit_work_ns=41,status='abstained',reason='no_admitted_candidate',now_ns=100000,submitted_ns=99900,work_started_ns=99930 if started else None,enqueued_ns=99920)
def original_base(d):
 owner=bg.BackgroundOptimizer.__new__(bg.BackgroundOptimizer);owner._function=d['function'];owner._baseline=types.SimpleNamespace(sha256=d['original_baseline_sha256'])
 job=types.SimpleNamespace(number=d['job'],generation=d['generation'],epoch=d['epoch'],baseline=types.SimpleNamespace(sha256=d['before_sha256'],input_sha256=d['before_input_sha256']),submit_work_ns=d['submit_work_ns'])
 return owner._report(job,d['status'],d['reason'])
def concurrently(fn):
 failures=[]
 def body():
  try:fn()
  except BaseException as e:failures.append(repr(e))
 th=threading.Thread(target=body);th.start();th.join(5);assert not th.is_alive()and not failures,failures
def run_original(d,initial,scenario):
 token=bg.PublicationCancellation();future=bg._OptimizationFuture(token);stages=[];observations=[]
 owner=bg.BackgroundOptimizer.__new__(bg.BackgroundOptimizer);owner._condition=threading.Condition();owner._recent_jobs=collections.deque(maxlen=64);owner._settled_jobs=0;owner._observed_work_ns=0;owner._outcomes={}
 job=types.SimpleNamespace(number=d['job'],generation=d['generation'],epoch=d['epoch'],baseline=types.SimpleNamespace(sha256=d['before_sha256'],input_sha256=d['before_input_sha256']),submit_work_ns=d['submit_work_ns'],submitted_ns=d['submitted_ns'],work_started_ns=d['work_started_ns'],enqueued_ns=d['enqueued_ns'],accounted=False,cancellation=token,future=future)
 result=copy.deepcopy(initial);saved_commit=token.committed;saved_state=future._accounting_state
 def event(which):
  if which=='cancel':future.cancel()
  elif which=='finish':future._complete({'native-value':1})
  elif which=='token':token.cancel()
  elif which=='settle':future._settle_token_cancellation()
  elif which=='commit':
   with token._lock:
    assert not token._event.is_set();token._committed=True
 def observe(stage):
  stages.append(stage)
  cost=result['costs'];assert cost['job_wall_before_future_completion_ns']==100 and cost['worker_elapsed_ns']==(70 if d['work_started_ns']is not None else 0) and cost['observed_submit_and_worker_ns']==(111 if d['work_started_ns']is not None else 41)
  if stage==1:assert result.get('publication_committed')==initial.get('publication_committed')
  else:assert result['publication_committed']==bool(observations[0])
  if scenario=='cancel-before-token'and stage==1:concurrently(lambda:event('cancel'))
  if scenario=='finish-before-token'and stage==1:concurrently(lambda:event('finish'))
  if scenario=='commit-before-token'and stage==1:concurrently(lambda:event('commit'))
  if scenario=='cancel-before-state'and stage==2:concurrently(lambda:event('cancel'))
  if scenario=='finish-before-state'and stage==2:concurrently(lambda:event('finish'))
  if scenario=='token-only-before-state'and stage==2:concurrently(lambda:event('token'))
  if scenario=='token-then-settle':
   concurrently(lambda:event('token'if stage==1 else'settle'))
  value=int(saved_commit())if stage==1 else('pending','cancelled','finished').index(saved_state())
  observations.append(value)
  if scenario=='commit-after-token'and stage==1:concurrently(lambda:event('commit'))
  if scenario=='cancel-after-state'and stage==2:concurrently(lambda:event('cancel'))
  if scenario=='finish-after-state'and stage==2:concurrently(lambda:event('finish'))
  return value
 token.committed=lambda:bool(observe(1));future._accounting_state=lambda:('pending','cancelled','finished')[observe(2)]
 captured=[];clock=bg.time.perf_counter_ns;pack=bg._pack
 try:
  bg.time.perf_counter_ns=lambda:d['now_ns']
  def capturing(value):captured.append(copy.deepcopy(value));return pack(value)
  bg._pack=capturing;owner._account_job(job,result)
 finally:bg.time.perf_counter_ns=clock;bg._pack=pack
 assert stages==[1,2]and job.accounted and len(captured)==1
 return result,captured[0],owner._observed_work_ns,observations,saved_state(),saved_commit()
def run_native(d,initial,scenario):
 v=h.fresh();f=Cells(v);fc=f.make();ptr=u(f.call(6,fc),64);mc=h.imported(v,d);result=h.imported(v,initial);stages=[];observations=[]
 completed=v.empty(dict)
 def event(which):
  if which=='cancel':f.call(7,fc)
  elif which=='finish':f.call(11,fc,b=completed,kind=1)
  elif which=='token':kcall(ptr,8)
  elif which=='settle':f.call(8,fc)
  elif which=='commit':kcall(ptr,7)
 def observe(stage,value_owner,resultcap):
  stages.append(stage);actual=h.exported(v,resultcap);cost=actual['costs']
  assert cost['job_wall_before_future_completion_ns']==100 and cost['worker_elapsed_ns']==(70 if d['work_started_ns']is not None else 0) and cost['observed_submit_and_worker_ns']==(111 if d['work_started_ns']is not None else 41)
  if stage==1:assert actual.get('publication_committed')==initial.get('publication_committed')
  else:assert actual['publication_committed']==bool(observations[0])
  if scenario=='cancel-before-token'and stage==1:concurrently(lambda:event('cancel'))
  if scenario=='finish-before-token'and stage==1:concurrently(lambda:event('finish'))
  if scenario=='commit-before-token'and stage==1:concurrently(lambda:event('commit'))
  if scenario=='cancel-before-state'and stage==2:concurrently(lambda:event('cancel'))
  if scenario=='finish-before-state'and stage==2:concurrently(lambda:event('finish'))
  if scenario=='token-only-before-state'and stage==2:concurrently(lambda:event('token'))
  if scenario=='token-then-settle':concurrently(lambda:event('token'if stage==1 else'settle'))
  value=int(u(kcall(ptr,9),32)==2)if stage==1 else u(kcall(ptr,5),24)
  observations.append(value)
  if scenario=='commit-after-token'and stage==1:concurrently(lambda:event('commit'))
  if scenario=='cancel-after-state'and stage==2:concurrently(lambda:event('cancel'))
  if scenario=='finish-after-state'and stage==2:concurrently(lambda:event('finish'))
  return value
 runner=h.Reports(observe=observe,check_caps=False);ret,receipt,cost=runner.run(v,1,mc,result)
 assert stages==[1,2]and m.u(v.call(8,result,ret),48)==1
 actual=(h.exported(v,ret),h.exported(v,receipt),int(v.raw(cost)),observations,('pending','cancelled','finished')[u(kcall(ptr,5),24)],u(kcall(ptr,9),32)==2)
 f.finish();assert h.caps(v)==len(v.held),(h.caps(v),len(v.held));v.finish();return actual,runner.calls
rows=[];policy_calls=0
scenarios=('pending','cancel-before-token','finish-before-token','commit-before-token','cancel-before-state','finish-before-state','token-only-before-state','token-then-settle','commit-after-token','cancel-after-state','finish-after-state')
for started in(False,True):
 for i,scenario in enumerate(scenarios):
  d=meta(started);initial=original_base(d)
  if i&1:initial['publication_committed']=True
  expected=run_original(d,initial,scenario);actual,n=run_native(d,initial,scenario);policy_calls+=n
  assert all(ordered(a)==ordered(b)for a,b in zip(actual,expected)),(scenario,started,actual,expected)
  rows.append({'case':scenario+'-started-'+str(started),'passed':True,'actual_native_observations':actual[3],'final_state':actual[4],'final_committed':actual[5]})
  print('REPORT_OBSERVATION_TIMING',scenario,started,flush=True)
# A malformed private feedback reclaims owned report refs and never executes a later observation.
for failstage,answer in[(1,(1,0)),(1,(0,2)),(1,((1<<64)-1,(1<<64)-1)),(2,(1,0)),(2,(0,3)),(2,((1<<64)-1,(1<<64)-1))]:
 v=h.fresh();d=meta(True);mc=h.imported(v,d);source=h.imported(v,original_base(d));stages=[]
 def fault(stage,vo,result):
  stages.append(stage);return answer if stage==failstage else 0
 runner=h.Reports(observe=fault);runner.run(v,1,mc,source,expected=11)
 assert stages==list(range(1,failstage+1));actual=h.exported(v,source);assert actual['costs']['observed_submit_and_worker_ns']==111
 assert('publication_committed'in actual)==(failstage==2)
 v.finish();rows.append({'case':'feedback-refusal-'+str(failstage)+'-'+str(answer),'passed':True})
# New private profile cannot use captured observations or base-report operation.
v=h.fresh();mc=h.imported(v,meta(True));result=h.imported(v,original_base(meta(True)));raw=bytearray(128);raw[:8]=b'HIABRP02';struct.pack_into('<Q',raw,8,1);struct.pack_into('<3Q',raw,24,*mc);struct.pack_into('<3Q',raw,48,*result)
bad=[('short',bytes(raw[:127])),('long',bytes(raw)+b'x')]
for off,value in[(8,0),(8,2),(16,1),(72,1),(80,1),(120,1)]:
 x=bytearray(raw);struct.pack_into('<Q',x,off,value);bad.append((str(off)+'-'+str(value),bytes(x)))
for name,packet in bad:
 s=C.create_string_buffer(packet);o=C.create_string_buffer(b'Z'*8192,8192);w=C.create_string_buffer(b'Y'*32768,32768);C.memset(w,0,128);struct.pack_into('<8s3Q',w,0,b'HIABRC01',C.cast(ve,C.c_void_p).value,C.addressof(v.ctx),256);struct.pack_into('<Q',o,128,0);before=w.raw;ohead=o.raw[:128];count=h.caps(v)
 rc=h.policy_entry(s,len(packet),o,8192,w,32768);assert rc==0xfffffffd and w.raw==before and o.raw[:128]==ohead and h.caps(v)==count,(name,rc)
 rows.append({'case':'new-profile-private-atomic-'+name,'passed':True})
# Value rejection before the timing boundary does not invoke either observation.
seen=[];runner=h.Reports(observe=lambda *x:seen.append(x)or 0);badresult=h.imported(v,{});runner.run(v,1,mc,badresult,expected=3);assert not seen;rows.append({'case':'cost-lookup-failure-before-any-observation','passed':True})
v.finish()
report={'passed':True,'scope':'actual HIA report policy + actual mutable values + actual native Future/token observation at original mutation points; fixed account and public Future integration remain separate','whole_background_closed':False,'policy_sha256':h.POLICY_PIN,'cell_sha256':cellpin,'count':len(rows),'actual_cell_calls':calls,'actual_policy_steps':policy_calls,'cases':rows}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT_OBSERVED_TIMING_PASS',len(rows),calls,policy_calls,flush=True)
