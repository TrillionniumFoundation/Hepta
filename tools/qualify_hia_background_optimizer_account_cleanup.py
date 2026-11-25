from pathlib import Path
from hashlib import sha256
import ctypes as C,struct,types,copy,collections,json,os,sys,time,threading,resource,importlib.util
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');B=A.parent/'cleanup-audit-20261124T0745Z';T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');W=A/'native-background-source'
D=A/'native-background-account-quarantine-v1';D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.path.insert(0,str(W));sys.set_int_max_str_digits(0);os.environ['Z3_LIBRARY_PATH']=str(T/'qa-z3-4.15.4')
from tools.qualify_hia_multiversion_background_jobs import Jobs,addr
from tools.qualify_hia_multiversion_background_queue import Queue
from tools.qualify_hia_multiversion_background_ledger import Ledger
from tools.qualify_hia_multiversion_values import Owner as Decimal
from tools.qualify_hia_multiversion_background_payload import Owner as Payload
from hepta import hia_background_optimizer as bg
def module(p,name):
 sp=importlib.util.spec_from_file_location(name,p);z=importlib.util.module_from_spec(sp);sp.loader.exec_module(z);return z
h=module(A/'background-report-observed-pure-harness-v1.py','rp');m=h.m;ve=h.value_entry
SIX=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
def u(b,at):return struct.unpack_from('<Q',b,at)[0]
def image(path,name,pin=None):
 if pin:assert sha256(path.read_bytes()).hexdigest()==pin
 z=C.CDLL(str(path));f=getattr(z,name);f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32;libs.append(z);return f
libs=[];rows=[];calls=0;account_calls=0
public_entry=m.load(T/'future-public-native-v1/future-public.flat','b65ff1e400335e5744c35d71cb053c31e9aafab23f3299548d145a95eebee382')
kernelso=C.CDLL(str(B/'native-multiversion-future-v2/future-component.so'));kernel=kernelso.hia_mv_future;kernel.argtypes=[C.c_void_p,C.c_uint64]*3;kernel.restype=C.c_uint32
entry=public_entry
JP=A/'native-background-jobs-external-v3/jobs-component.so';PP=A/'native-background-payload-v1/payload-component.so'
REFP=A/'native-background-job-refs-v2/job-refs.so';reff=image(REFP,'hia_mv_background_job_refs','eb4479c0b38a356ba826fe6397e6098d0a8d3f9ee453aaf4720f6fcba9206de3')
QI=A/'native-background-queue-transaction-v3/queue-component.so'
io=image(A/'native-background-value-transport-v1/value-transport.so','hia_background_value_transport','7e98a89a07d3e3bc28469fd0090829141a6eca5305afcca3e769321d2026584c')
capture=m.load(A/'native-background-json-capture-v4/background_optimizer_json_capture.flat','62f62e547a346c631697a4c0ced3385afb78d6a6472a11ecad2e8c57da0faf1f')
freeze=m.load(A/'native-background-freeze-v2/background_optimizer_freeze.flat','f32bf4a811481a3baa007919710549a8e231caa3cb44c6afcb180f4c124d210d')
fz=image(A/'native-background-value-freeze-v3/value-freeze.so','hia_background_value_freeze','d98bcca699d12fd34c1168b0757e29c08f746f6879ecf47cd4e8c3585542695d')
account_image=A/'native-background-account-v2/account.so';account_pin='614da156ffe0ae6d0ab46afb2955d8720c72a9832d1eeab8895cd451251cf695';account=image(account_image,'hia_background_account',account_pin)
class Public:
 def __init__(self,v):
  self.v=v;self.ctx=C.create_string_buffer(256);self.fs=[];self.leases=[]
  self.call(0,fid=(C.addressof(v.ctx),256,0))
 def call(self,op,fid=(0,0,0),cap=(0,0,0),value=(0,0,0),fn=0,kind=0,timeout=(0,0,0),status=0):
  global calls
  raw=bytearray(192);raw[:8]=b'HIABFP01';struct.pack_into('<Q',raw,8,op)
  for at,x in [(16,fid),(40,cap),(64,value),(104,timeout)]:struct.pack_into('<3Q',raw,at,*x)
  struct.pack_into('<2Q',raw,88,fn,kind);s=C.create_string_buffer(bytes(raw));o=C.create_string_buffer(b'\xb5'*65536,65536)
  rc=public_entry(s,192,o,65536,self.ctx,256);calls+=1
  assert rc==0 and o.raw[:8]==b'HIABFRP1',(op,rc,o.raw[:128].hex())
  assert u(o.raw,8)==status,(op,status,o.raw[:128].hex())
  return o.raw
 def factory(self):
  r=self.call(1);x=(struct.unpack_from('<3Q',r,24),struct.unpack_from('<3Q',r,48));assert u(r,16)==3 and x[1][0];self.leases.append(x);return x
 def make(self,fac):
  r=self.call(4,*fac);x=(struct.unpack_from('<3Q',r,24),struct.unpack_from('<3Q',r,48));assert u(r,16)==2 and x[1][0];self.fs.append(x);return x
 def retain(self,f):
  r=self.call(5,*f);x=(struct.unpack_from('<3Q',r,24),struct.unpack_from('<3Q',r,48));assert u(r,16)==2;self.fs.append(x);return x
 def drop(self,f):self.call(6,*f);self.fs.remove(f)
 def drop_factory(self,f):self.call(3,*f);self.leases.remove(f)
 def complete(self,f,v,kind=1,status=0):return self.call(12,*f,value=v,kind=kind,status=status)
 def result(self,f,status=0,exception=False,timeout=(0,0,0)):
  r=self.call(11 if exception else 10,*f,timeout=timeout,status=status)
  cap=struct.unpack_from('<3Q',r,72)
  if cap[0]:self.v.held.append(cap)
  return cap,r
 def finish(self):
  for f in self.fs[:]:self.drop(f)
  for f in self.leases[:]:self.drop_factory(f)
  self.call(18)


class External(Jobs):
 def __init__(self,p,fac):
  self.image=JP;self.lib=C.CDLL(str(JP));self.f=self.lib.hia_mv_background_jobs;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
  self.futurelib=kernelso;self.ff=kernel;self.payload=Payload(PP);self.w=C.create_string_buffer(256);self.calls=0;self.lock=threading.Lock();self.keep=[]
  self.public=p;self.fac=fac;r=p.call(17,*fac);assert u(r,16)==6 and u(r,88)==256
  self.cellfn=SIX(u(r,72));self.cellctx=u(r,80)
  raw=bytearray(self.packet(9));raw[:8]=b'HIABJO02';struct.pack_into('<7Q',raw,24,addr(kernel),addr(self.payload.f),C.addressof(self.payload.w),256,addr(self.cellfn),self.cellctx,256)
  self.run(9,wire=bytes(raw))
 def external(self,cap,raw):
  wire=bytearray(self.packet(10,cap,raw));wire[:8]=b'HIABJO02';return struct.unpack_from('<3Q',self.run(10,wire=bytes(wire)),16)
class Ref:
 def __init__(self,jobs):
  self.jobs=jobs;self.ctx=C.create_string_buffer(64);self.calls=0
  C.memmove(self.ctx,struct.pack('<8s7Q',b'HIABJRC1',C.cast(jobs.f,C.c_void_p).value,C.addressof(jobs.w),256,0,0,0,0),64)
 def call(self,op,cap,want=0):
  raw=struct.pack('<8s7Q',b'HIABJRF1',op,*cap,0,0,0)
  s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xa6'*128,128);before=self.ctx.raw
  rc=reff(s,64,o,128,self.ctx,64);self.calls+=1
  assert rc==0 and o.raw[:8]==b'HIABJRO1' and u(o.raw,8)==want,(op,rc,o.raw.hex())
  assert self.ctx.raw==before
  return struct.unpack_from('<3Q',o.raw,16)
class Q(Queue):
 def __init__(self,jobs,max_pending=8):
  self.values=jobs;self.future_lib=kernelso;self.lib=C.CDLL(str(QI));self.f=self.lib.hia_mv_background_queue
  self.f.argtypes=entry.argtypes;self.f.restype=C.c_uint32;self.w=C.create_string_buffer(4096)
  assert C.addressof(self.w)%8==0
  self.calls=0;self.mutex=threading.Lock();self.errors=[];self.provider=Ref(jobs)
  self.run(0,fields={16:max_pending,64:C.cast(reff,C.c_void_p).value,80:C.addressof(self.provider.ctx),88:64})
 def tx(self,op,fields=None,want=0):
  raw=bytearray(self.packet(op,fields));raw[:8]=b'HIABGQ02';return self.run(op,raw=bytes(raw),want=want)
 def add(self,j,tx=False,want=0):
  fp,mp,ip,n=self.values.view(j);a,b,c=j
  fields={24:a,32:b,40:c,48:fp,56:512}
  return self.tx(1,fields,want)if tx else self.run(1,fields,want)
 def settled(self,r,tx=False):
  z=self.refs(r)[0];a,b,c=z['cap'];fields={16:z['slot'],24:a,32:b,40:c}
  return self.tx(3,fields)if tx else self.run(3,fields)


def make(v,x):
 if type(x)is list:
  a=v.empty(list)
  for y in x:v.call(16,a,make(v,y))
  return a
 if type(x)is dict:
  a=v.empty(dict)
  for k,y in x.items():v.call(10,a,make(v,k),make(v,y))
  return a
 return v.scalar(x)
def ordered(x):
 if type(x)is dict:return ('dict',[(k,ordered(y))for k,y in x.items()])
 if type(x)is list:return ('list',[ordered(y)for y in x])
 return (type(x).__name__,x)
def original_base(d):
 owner=bg.BackgroundOptimizer.__new__(bg.BackgroundOptimizer);owner._function=d['function'];owner._baseline=types.SimpleNamespace(sha256=d['original_baseline_sha256'])
 job=types.SimpleNamespace(number=d['job'],generation=d['generation'],epoch=d['epoch'],baseline=types.SimpleNamespace(sha256=d['before_sha256'],input_sha256=d['before_input_sha256']),submit_work_ns=d['submit_work_ns'])
 return owner._report(job,d['status'],d['reason'])
def original_account(d,initial,state,committed,limit=4300):
 token=bg.PublicationCancellation();future=bg._OptimizationFuture(token)
 if committed:
  with token._lock:token._committed=True
 if state=='cancelled':assert future.cancel()
 elif state=='finished':future._complete(copy.deepcopy(initial))
 owner=bg.BackgroundOptimizer.__new__(bg.BackgroundOptimizer);owner._condition=threading.Condition();owner._recent_jobs=collections.deque(maxlen=64);owner._settled_jobs=0;owner._observed_work_ns=0;owner._outcomes={}
 job=types.SimpleNamespace(submit_work_ns=d['submit_work_ns'],submitted_ns=d['submitted_ns'],work_started_ns=d['work_started_ns'],enqueued_ns=d['enqueued_ns'],accounted=False,cancellation=token,future=future)
 result=copy.deepcopy(initial);clock=bg.time.perf_counter_ns;saved_limit=sys.get_int_max_str_digits()
 try:
  sys.set_int_max_str_digits(limit);bg.time.perf_counter_ns=lambda:d['now_ns'];owner._account_job(job,result)
 finally:bg.time.perf_counter_ns=clock;sys.set_int_max_str_digits(saved_limit)
 return result,list(owner._recent_jobs),owner._observed_work_ns
class Actual:
 def __init__(self,limit=4300):
  self.v=h.fresh(limit);self.p=Public(self.v);self.fac=self.p.factory();self.f=self.p.make(self.fac)
  self.jobs=External(self.p,self.fac);self.q=Q(self.jobs);self.q.run(7)
  self.dec=Decimal(B/'native-multiversion-values-v1/values-component.so');self.ledger=Ledger(A/'native-background-ledger-v1/ledger-component.so',self.jobs,self.dec)
  self.freezectx=C.create_string_buffer(2048);struct.pack_into('<8s10Q',self.freezectx,0,b'HIABFZC1',addr(ve),C.addressof(self.v.ctx),256,addr(io),addr(capture),addr(freeze),addr(self.jobs.payload.f),C.addressof(self.jobs.payload.w),256,limit)
  self.ctx=C.create_string_buffer(4096);struct.pack_into('<8s30Q',self.ctx,0,b'HIABACC1',addr(ve),C.addressof(self.v.ctx),256,addr(h.policy_entry),addr(fz),C.addressof(self.freezectx),2048,addr(self.ledger.f),C.addressof(self.ledger.w),4096,addr(self.jobs.f),C.addressof(self.jobs.w),256,addr(public_entry),C.addressof(self.p.ctx),256,*self.fac[0],addr(kernel),addr(self.dec.f),C.addressof(self.dec.w),256,addr(self.jobs.cellfn),self.jobs.cellctx,256,0,addr(self.q.f),C.addressof(self.q.w),4096)
  self.out=C.create_string_buffer(524288);self.job=self.jobs.external(self.f[1],b'actual accepted Job payload')
  self.q.add(self.job);self.active=self.q.run(2);assert self.q.refs(self.active)[0]['cap']==self.job
 def call(self,meta=(0,0,0),result=(0,0,0),op=0,status=0,held=True,future=None,job=None):
  global account_calls
  raw=bytearray(128);raw[:8]=b'HIABACQ1';struct.pack_into('<Q',raw,8,op)
  if op==0:
   for at,cap in[(24,self.job if job is None else job),(48,meta),(72,result),(96,self.f[1]if future is None else future)]:struct.pack_into('<3Q',raw,at,*cap)
  sb=C.create_string_buffer(bytes(raw),128);out=C.create_string_buffer(b'\xa6'*524288,524288)
  if held:self.q.tx(10)
  t0=time.perf_counter_ns()
  try:rc=account(sb,128,out,len(out),self.ctx,4096)
  finally:
   t1=time.perf_counter_ns()
   if held:self.q.tx(11)
  account_calls+=1;r=out.raw
  assert rc==0 and r[:8]==b'HIABACR1',(account_calls,rc,r[:128].hex())
  assert u(r,8)==status,(account_calls,status,r[:128].hex())
  assert sb.raw==bytes(raw)
  return r,(t0,t1)
 def close(self):
  assert u(self.ctx.raw,248)==0,self.ctx.raw[:256].hex()
  self.ledger.destroy();owned=self.q.settled(self.active);self.jobs.drop(self.q.refs(owned)[0]['cap'])
  self.q.run(4);assert u(self.q.run(2),16)==(1<<64)-1;self.q.run(8);self.q.destroy();self.jobs.destroy()
  self.dec.run(9);self.p.finish();self.v.finish()
def done(name,**kw):
 rows.append({'case':name,'passed':True,**kw});(D/'report.json').write_text(json.dumps({'passed':False,'cases':rows},indent=2)+'\n');print('BG_ACCOUNT_WHOLE_CASE',name,flush=True)
def run_case(name,state='pending',committed=False,started=True,submit=41,rich=False,limit=4300):
 a=Actual(limit);v=a.v;now=time.perf_counter_ns()
 d=dict(job=7,generation=3,epoch=6,function='main',before_sha256='b'*64,before_input_sha256='c'*64,original_baseline_sha256='a'*64,submit_work_ns=submit,status='published'if committed else'abstained',reason='prepared'if committed else'no_admitted_candidate',now_ns=0,submitted_ns=now-100000,work_started_ns=now-70000 if started else None,enqueued_ns=now-80000)
 initial=original_base(d)
 if rich:
  initial['costs'].update(queue_wait_ns=99,rank_call_wall_ns=123)
  initial['ranking']={'native_rank_admission':{'invoked':True},'request_sha256':'d'*64,'bridge':{'binary_sha256':'e'*64},'costs':{'supplied_search_ns':2**100,'actual_adapter_ns':4,'total_search_ns':2**100+4,'search_at_native_rank_ns':False}}
  initial['publication']={'prepare_ns':87};initial['detail']='actual detail'
 meta=make(v,d);result=make(v,initial);identity=v.type(result)[3:];before=h.caps(v)
 if committed:assert a.jobs.future(a.job,7)[0]==0
 if state=='cancelled':a.p.call(7,*a.f)
 elif state=='finished':a.p.complete(a.f,result)
 r,span=a.call(meta,result);assert u(r,16)==0 and u(r,24)==1 and u(r,56)==0
 current=h.child(v,meta,'now_ns');d['now_ns']=int(v.raw(current));v.drop(current);assert span[0]<=d['now_ns']<=span[1]
 want,receipts,cost=original_account(d,initial,state,committed,limit);got=h.exported(v,result);snapshot=a.ledger.snapshot()
 assert ordered(got)==ordered(want),(name,got,want)
 assert v.type(result)[3:]==identity
 assert snapshot['settled']==1 and snapshot['observed']==cost and snapshot['recent']==receipts,(name,snapshot,receipts,cost)
 assert snapshot['outcomes'][got['status']]==1
 # Already-settled check occurs before clock, result validation, or observations.
 before_repeat=h.exported(v,meta);s0=a.ledger.snapshot();r2,_=a.call(meta,result);assert u(r2,16)==1 and u(r2,24)==0
 assert h.exported(v,meta)==before_repeat and a.ledger.snapshot()==s0
 # Mutable result and callback-visible identity do not rewrite frozen payment.
 h.setitem(v,result,'after-account',1001);assert a.ledger.snapshot()['recent']==receipts
 if state=='pending':
  a.p.complete(a.f,result);gotcap,_=a.p.result(a.f);assert v.type(gotcap)[3:]==identity
  h.setitem(v,gotcap,'mutated-through-public-Future',True);assert h.exported(v,result)['mutated-through-public-Future']is True and a.ledger.snapshot()['recent']==receipts
 a.close();done(name,observed_ns_digits=len(str(cost)),actual_state=state,committed=committed,started=started)
def fixture(a):
 now=time.perf_counter_ns();d=dict(job=7,generation=3,epoch=6,function='main',before_sha256='b'*64,before_input_sha256='c'*64,original_baseline_sha256='a'*64,submit_work_ns=41,status='abstained',reason='control',now_ns=0,submitted_ns=now-1000,work_started_ns=now-700,enqueued_ns=now-800)
 return d,make(a.v,d),make(a.v,original_base(d))

CALL=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
a=Actual();d,meta,result=fixture(a);state={'drop_refused':0,'real_drop':0}
@CALL
def delayed_drop(s,sn,o,on,w,wn):
 raw=C.string_at(s,sn);op=u(raw,8)
 if op==6 and state['drop_refused']==0:
  state['drop_refused']+=1;b=bytearray(128);b[:8]=b'HIABFRP1';struct.pack_into('<Q',b,8,1);C.memmove(o,bytes(b),128);return 0
 if op==6:state['real_drop']+=1
 return public_entry(s,sn,o,on,w,wn)
struct.pack_into('<Q',a.ctx,112,addr(delayed_drop));fds=len(os.listdir('/proc/self/fd'))
r,_=a.call(meta,result,status=9);assert u(r,24)==1 and u(r,56)==1 and u(a.ctx.raw,248)==1
before=a.ledger.snapshot();clock=h.exported(a.v,meta)['now_ns'];result_before=h.exported(a.v,result)
assert before['settled']==1
r,_=a.call(meta,result,status=6);assert a.ledger.snapshot()==before
r,_=a.call(op=1);assert u(r,24)==1 and u(r,56)==0 and u(a.ctx.raw,248)==0
assert a.ledger.snapshot()==before and h.exported(a.v,meta)['now_ns']==clock and h.exported(a.v,result)==result_before
assert state=={'drop_refused':1,'real_drop':1}and len(os.listdir('/proc/self/fd'))==fds,state
a.close();done('post-marker-public-Future-guard-release-retry-never-reaccounts',state=state)
# The inner fixed freezer and the outer account each preserve cleanup custody.
a=Actual();d,meta,result=fixture(a);state={'created':0,'refused':0,'drops':0}
@CALL
def delayed_payload(s,sn,o,on,w,wn):
 raw=C.string_at(s,sn);op=u(raw,8)
 if op==3 and state['refused']<2:
  state['refused']+=1;b=bytearray(128);b[:8]=b'HIABPYR1';struct.pack_into('<Q',b,8,9);C.memmove(o,bytes(b),128);return 0
 rc=a.jobs.payload.f(s,sn,o,on,w,wn)
 if op==1 and rc==0 and u(C.string_at(o,128),8)==0:
  state['created']+=1;n=u(C.string_at(o,128),40);C.memmove(o+40,struct.pack('<Q',n+1),8)
 if op==3:state['drops']+=1
 return rc
struct.pack_into('<Q',a.freezectx,56,addr(delayed_payload));fds=len(os.listdir('/proc/self/fd'));caps=h.caps(a.v)
r,_=a.call(meta,result,status=9);assert u(r,24)==0 and u(r,56)==1 and u(a.ctx.raw,248)==1,(r[:128].hex(),state)
before=a.ledger.snapshot();clock=h.exported(a.v,meta)['now_ns'];assert before['settled']==0
r,_=a.call(op=1,status=9);assert u(r,56)==0 and u(a.ctx.raw,248)==0
assert state=={'created':1,'refused':2,'drops':1}and a.ledger.snapshot()==before,state
assert h.exported(a.v,meta)['now_ns']==clock and h.caps(a.v)==caps and len(os.listdir('/proc/self/fd'))==fds
a.close();done('nested-freezer-retained-cap-recovery-without-recreation',state=state)
report={'passed':True,'whole_background_closed':False,'groups':len(rows),'actual_account_calls':account_calls,'cases':rows,'image_sha256':account_pin,'fault_scope':'private fixed dependency refusal after actual native effects; no production stub'}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_ACCOUNT_QUARANTINE_PASS',len(rows),account_calls,flush=True)
