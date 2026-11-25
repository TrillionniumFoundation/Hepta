from pathlib import Path
from hashlib import sha256
import os,sys,ctypes as C,struct,json,types,time,threading,collections,copy,runpy,resource,traceback
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');B=A.parent/'cleanup-audit-20261124T0745Z';T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');W=A/'native-background-source';D=A/'native-background-submission-final-v1/original';D.mkdir(exist_ok=False)
resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.set_int_max_str_digits(0);os.environ['Z3_LIBRARY_PATH']=str(T/'qa-z3-4.15.4')
ns=runpy.run_path(str(A/'native-background-submission-helper-final-v1.py'));pm=runpy.run_path(str(B/'qualify-runtime-provider-smoke-v2.py'))
h=ns['h'];m=ns['m'];ve=ns['ve'];Public=ns['Public'];External=ns['External'];Q=ns['Q'];make=ns['make'];bg=ns['bg'];addr=ns['addr'];u=ns['u']
libs=[]
def image(path,name):
 lib=C.CDLL(str(path));libs.append(lib);f=getattr(lib,name);f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32;return f
entry=image(A/'native-background-submission-v8/submission.so','hia_background_submission')
typed=m.load(T/'verify-value-structure-v5/value-structure.flat','8ac533174506bb5dea7206fae1b0031d32d4d86e6c31c94d6ba241d7bf48e944')
admit=m.load(A/'native-background-admission-v4/background_optimizer_admission.flat','7f0bac9de47c969d637c7d0f792235fba4b247a874259303191afe1b08cfac9c')
rawthreshold=(W/'examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat').read_bytes();assert sha256(rawthreshold).hexdigest()=='735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706';threshold=C.create_string_buffer(rawthreshold,len(rawthreshold))
paths=[T/'normalizer-84619bd.bin',B/'native-primitive-proof-absolute-v2/hia-native-scalar-proof',T/'production-p3/products/hia-build-object-539ce9.bin']
files=[(pm['sealed'](p.read_bytes()),p.read_bytes())for p in paths]
rows=[];actualcalls=0
class Actual:
 def __init__(self,maximum=8,limit=4300):
  self.v=h.fresh(limit);self.p=Public(self.v);self.fac=self.p.factory();self.jobs=External(self.p,self.fac);self.q=Q(self.jobs,maximum);self.q.run(7)
  self.provider=pm['Provider'](B/'native-multiversion-background-runtime-v4/runtime-provider.so',[]);self.provider.call(pm['control'](0));self.parent=D/('runtime-'+str(len(rows))+'-'+str(time.monotonic_ns()));self.parent.mkdir(mode=0o700)
  self.program=pm['scalar_program'](None);self.raw=pm['rawdoc'](self.program);self.rcap=self.provider.create(files,self.parent,self.program)
  snap=self.provider.q(1,self.rcap);self.snapshot=snap['payload'];assert self.snapshot[:8]==b'HIAMVBS1';self.provider.drop_reply(snap)
  self.corecaps=[self.jobs.payload.create(self.raw)for _ in range(2)]
  self.freezectx=C.create_string_buffer(2048)
  struct.pack_into('<8s10Q',self.freezectx,0,b'HIABFZC1',addr(ve),C.addressof(self.v.ctx),256,addr(ns['io']),addr(ns['capture']),addr(ns['freeze']),addr(self.jobs.payload.f),C.addressof(self.jobs.payload.w),256,limit)
  self.one=self.v.scalar(1);self.number=self.v.scalar(1);self.v.held.remove(self.number);self.function=self.v.scalar(self.program['functions'][0]['name'])
  self.ctx=C.create_string_buffer(8192);self.ctx[:8]=b'HIABSSC1'
  def put(at,*v):struct.pack_into('<'+'Q'*len(v),self.ctx,at,*v)
  put(8,addr(ve),C.addressof(self.v.ctx),256);put(32,addr(self.q.f),C.addressof(self.q.w),4096);put(56,addr(self.jobs.f),C.addressof(self.jobs.w),256)
  put(80,addr(ns['public_entry']),C.addressof(self.p.ctx),256);put(104,*self.fac[0]);put(128,*self.fac[1])
  put(152,addr(self.provider.f),C.addressof(self.provider.w),1024);put(176,*self.rcap)
  put(200,addr(self.jobs.payload.f),C.addressof(self.jobs.payload.w),256);put(224,addr(typed),C.addressof(threshold),len(rawthreshold))
  put(248,addr(ns['fz']),C.addressof(self.freezectx),2048,addr(admit),addr(ns['capture']));put(288,*self.one);put(312,*self.number)
  C.memmove(C.addressof(self.ctx)+512,self.snapshot[64:128],64);C.memmove(C.addressof(self.ctx)+576,self.snapshot[128:192],64)
  put(640,*self.corecaps[0]);put(664,*self.corecaps[1]);put(688,*self.function)
  self.out=C.create_string_buffer(524288);self.user=[];self.closed=False
 def call(self,candidates,observations,objective,status=0):
  global actualcalls
  args=[make(self.v,x)for x in(candidates,observations,objective)]
  s=bytearray(128);s[:8]=b'HIABSQ01'
  for off,c in zip((24,48,72),args):struct.pack_into('<3Q',s,off,*c)
  sb=C.create_string_buffer(bytes(s),128);C.memset(self.out,0xb6,len(self.out));t0=time.monotonic_ns();rc=entry(sb,128,self.out,len(self.out),self.ctx,len(self.ctx));t1=time.monotonic_ns();r=self.out.raw;actualcalls+=1
  print('SUBMIT_REPLY',rc,r[:128].hex(),'ns',t1-t0,flush=True)
  assert sb.raw==bytes(s);assert rc==0 and r[:8]==b'HIABSRP1',(rc,r[:128].hex())
  assert u(r,8)==status,(status,r[:128].hex(),r[128:128+min(u(r,80),1024)])
  assert u(self.q.w.raw,128)&0xffffffff==0
  if status==0:
   f=(struct.unpack_from('<3Q',r,24),struct.unpack_from('<3Q',r,48));self.user.append(f);self.p.fs.append(f)
  return r,args,(t0,t1)
 def metadata(self,r):
  index=u(r,72);mc=struct.unpack_from('<3Q',self.ctx.raw,1024+128*index+24);return h.exported(self.v,mc)
 def close(self):
  assert u(self.ctx.raw,792)==0,self.ctx.raw[784:800].hex()
  drained=self.q.run(6)
  for row in self.q.refs(drained):
   idx=row['slot'];at=1024+idx*128;job=struct.unpack_from('<3Q',self.ctx.raw,at);meta=struct.unpack_from('<3Q',self.ctx.raw,at+24);future=struct.unpack_from('<3Q',self.ctx.raw,at+48)
   assert job==row['cap'];self.jobs.drop(job);self.v.call(6,meta);self.p.call(6,self.fac[0],future);C.memset(C.addressof(self.ctx)+at,0,128)
  self.q.run(8);self.q.destroy()
  for cap in self.corecaps:self.jobs.payload.drop(cap)
  self.jobs.destroy();self.provider.q(4,self.rcap);self.provider.call(pm['control'](2));assert not list(self.parent.iterdir())
  self.v.call(6,struct.unpack_from('<3Q',self.ctx.raw,312))
  self.p.drop_factory(self.fac)
  for f in self.user:
   self.p.call(7,*f);assert u(self.p.call(15,*f),96)==1
  self.p.finish();self.v.finish()
def mark(name,**kw):
 rows.append({'case':name,'passed':True,**kw});(D/'report.json').write_text(json.dumps({'passed':False,'actual_submit_calls':actualcalls,'cases':rows},indent=2)+'\n');print('SUBMISSION_GATE',name,flush=True)

def graph(v,x,seen=None):
 if seen is None:seen={}
 if type(x) in (list,dict):
  if id(x) in seen:return seen[id(x)]
  c=v.empty(type(x));seen[id(x)]=c
  if type(x)is list:
   for item in x:v.call(16,c,graph(v,item,seen))
  else:
   for k,y in x.items():v.call(10,c,graph(v,k,seen),graph(v,y,seen))
  return c
 return v.scalar(x)
def invoke_caps(a,args,status=0):
 global actualcalls
 raw=bytearray(128);raw[:8]=b'HIABSQ01'
 for at,c in zip((24,48,72),args):struct.pack_into('<3Q',raw,at,*c)
 s=C.create_string_buffer(bytes(raw),128);C.memset(a.out,0xd6,len(a.out));t0=time.perf_counter_ns();rc=entry(s,128,a.out,len(a.out),a.ctx,8192);t1=time.perf_counter_ns();r=a.out.raw;actualcalls+=1
 assert rc==0 and r[:8]==b'HIABSRP1',(rc,r[:128].hex());assert s.raw==bytes(raw)
 assert u(r,8)==status,(actualcalls,status,r[:128].hex(),r[128:128+min(u(r,80),1024)])
 assert u(a.q.w.raw,128)&0xffffffff==0
 if status==0:
  f=(struct.unpack_from('<3Q',r,24),struct.unpack_from('<3Q',r,48));a.user.append(f);a.p.fs.append(f)
 return r,(t0,t1)
def oracle(a,candidates,observations,objective,clocks,closed=False,pending=0,limit=4300):
 original=bg.BackgroundOptimizer.__new__(bg.BackgroundOptimizer);sha=a.snapshot[128:160].hex();inp=a.snapshot[160:192].hex()
 original._baseline=types.SimpleNamespace(sha256=sha,input_sha256=inp);original._last_program=original._baseline
 original._runtime=types.SimpleNamespace(snapshot=lambda:dict(closed=False,generations=[dict(generation=0,program_sha256=sha,input_sha256=inp)],current_generation=0,selection_epoch=0))
 original._closed=closed;original._max_pending=u(a.q.w.raw,24);original._pending={i:None for i in range(pending)};original._condition=threading.Condition();original._next=1;original._queue=collections.deque()
 oldclock=bg.time.perf_counter_ns;saved=sys.get_int_max_str_digits();seq=iter(clocks)
 try:
  sys.set_int_max_str_digits(limit);bg.time.perf_counter_ns=lambda:next(seq)
  try:result=original.submit(candidates,observations,objective)
  except BaseException as e:return dict(type=type(e).__name__,message=str(e)),None
  return None,original._queue[-1]
 finally:bg.time.perf_counter_ns=oldclock;sys.set_int_max_str_digits(saved)
a=Actual(8)
obs={'abstain':{'program_sha256':a.snapshot[128:160].hex(),'search_ns':0}}
objective={'target':'x86_64-unknown-linux-gnu'}
cases=[
 ('wrong-objective-after-structural-success',[],obs,None),
 ('wrong-objective-type',[],obs,[]),
 ('wrong-objective-target',[],obs,{'target':'foreign'}),
 ('wrong-observations',[],[],objective),
 ('missing-incumbent',[],{},objective),
 ('wrong-incumbent-source',[],{'abstain':{'program_sha256':'0'*64}},objective),
 ('non-string-objective-key',[],obs,{1:None}),
 ('boolean-dict-key',[],obs,{True:None}),
 ('non-string-observation-key',[float('nan')],{2:None},objective),
 ('float-objective-before-bad-candidate',[b'x'],obs,{'target':'x86_64-unknown-linux-gnu','value':1.0}),
 ('infinite-candidate',[float('inf')],obs,objective),
 ('nan-candidate',[float('nan')],obs,objective),
 ('bytes-candidate',[b'\0'],obs,objective),
 ('lone-surrogate-value',[],obs,{'target':'x86_64-unknown-linux-gnu','bad':'\ud800'}),
 ('lone-surrogate-key',[],obs,{'target':'x86_64-unknown-linux-gnu','\udc00':0}),
 ('bad-integer-default4300',[],obs,{'target':'x86_64-unknown-linux-gnu','cost':10**4300}),
 ('unicode-astral-valid',[],obs,{'target':'x86_64-unknown-linux-gnu','note':'😀é\0'}),
]
cyc=[];cyc.append(cyc);cases.append(('cyclic-candidate',[cyc],obs,objective))
deep=0
for _ in range(65):deep=[deep]
cases.append(('deep-candidate',deep,obs,objective))
for name,c,o,z in cases:
 expected,_=oracle(a,c,o,z,[0,1])
 caps=[graph(a.v,x)for x in(c,o,z)];pending=u(a.q.w.raw,40)
 r,span=invoke_caps(a,caps,status=int(expected is not None))
 if expected:
  actual=json.loads(r[128:128+u(r,80)])
  assert actual==expected,(name,actual,expected)
  assert u(a.q.w.raw,40)==pending
 else:
  meta=a.metadata(r);_,job=oracle(a,c,o,z,[meta['submitted_ns'],meta['enqueued_ns']])
  jc=struct.unpack_from('<3Q',a.ctx.raw,1024+128*u(r,72));fp,mp,ip,n=a.jobs.view(jc)
  assert job.payload==C.string_at(ip,n) and job.submit_work_ns==meta['submit_work_ns']
 mark(name,error=expected,submit_elapsed_ns=span[1]-span[0])
# 139,000 nodes exceeds the admission role's minimum scratch, remains in its
# original 262,144-node domain, and is captured by the actual native allocator.
for count in (139000,262130):
 c=[None]*count;encoded=json.dumps(c,separators=(',',':')).encode();cc=a.v.take(a.v.call(1,tail=encoded))
 caps=[cc,graph(a.v,obs),graph(a.v,objective)]
 r,span=invoke_caps(a,caps)
 meta=a.metadata(r);_,job=oracle(a,c,obs,objective,[meta['submitted_ns'],meta['enqueued_ns']])
 jc=struct.unpack_from('<3Q',a.ctx.raw,1024+128*u(r,72));fp,mp,ip,n=a.jobs.view(jc)
 assert job.payload==C.string_at(ip,n) and meta['submit_work_ns']==job.submit_work_ns
 mark('actual-large-admission-'+str(count),nodes=count,packed_bytes=n,elapsed_ns=span[1]-span[0])
c=[None]*262144;cc=a.v.take(a.v.call(1,tail=json.dumps(c,separators=(',',':')).encode()));expected,_=oracle(a,c,obs,objective,[0,1])
r,span=invoke_caps(a,[cc,graph(a.v,obs),graph(a.v,objective)],1);assert json.loads(r[128:128+u(r,80)])==expected
mark('original-queued-node-refusal-priority',error=expected)
a.q.run(4);expected,_=oracle(a,[float('nan')],None,None,[0],closed=True,pending=8)
r,_=invoke_caps(a,[graph(a.v,[float('nan')]),graph(a.v,None),graph(a.v,None)],1);assert json.loads(r[128:128+u(r,80)])==expected
mark('closed-before-capacity-and-typed-admission',error=expected)
a.close()
for fd,_ in files:os.close(fd)
report={'passed':True,'whole_background_closed':False,'actual_submit_calls':actualcalls,'cases':rows,'image_sha256':sha256((A/'native-background-submission-v8/submission.so').read_bytes()).hexdigest()}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('SUBMISSION_ORIGINAL_PASS',len(rows),actualcalls,flush=True)
