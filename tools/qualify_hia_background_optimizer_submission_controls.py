from pathlib import Path
from hashlib import sha256
import os,sys,ctypes as C,struct,json,types,time,threading,collections,copy,runpy,resource,traceback
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');B=A.parent/'cleanup-audit-20261124T0745Z';T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');W=A/'native-background-source';D=A/'native-background-submission-final-v1/controls';D.mkdir(exist_ok=False)
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

hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;cnt=hooks.values_fault_count;cnt.argtypes=[C.c_uint64];cnt.restype=C.c_uint64
def bounds(path):
 maps=[r.split()[0].split('-')for r in Path('/proc/self/maps').read_text().splitlines()if str(path)in r];assert maps,path
 return min(int(a,16)for a,b in maps),max(int(b,16)for a,b in maps)
def wire(caps,op=0):
 x=bytearray(128);x[:8]=b'HIABSQ01';struct.pack_into('<Q',x,8,op)
 if op==0:
  for at,c in zip((24,48,72),caps):struct.pack_into('<3Q',x,at,*c)
 return bytes(x)
def invoke(a,caps,status=0,raw=None):
 global actualcalls
 raw=wire(caps)if raw is None else raw;sb=C.create_string_buffer(raw,len(raw));out=C.create_string_buffer(b'\xa6'*524288,524288);rc=entry(sb,len(raw),out,524288,a.ctx,8192);r=out.raw;actualcalls+=1
 assert rc==0 and r[:8]==b'HIABSRP1',(rc,r[:128].hex());assert sb.raw==raw
 if status is not None:assert u(r,8)==status,(status,r[:128].hex(),r[128:128+min(1024,u(r,80))])
 return r
a=Actual(8);obs={'abstain':{'program_sha256':a.snapshot[128:160].hex(),'search_ns':0}};objective={'target':'x86_64-unknown-linux-gnu'}
caps=[make(a.v,x)for x in([],obs,objective)]
lo,hi=bounds(A/'native-background-submission-v8/submission.so')
faults=[]
for nth in range(1,10):
 before=h.caps(a.v);fds=set(os.listdir('/proc/self/fd'));arm(lo,hi,nth)
 r=invoke(a,caps,5);counts=[cnt(i)for i in range(3)];arm(lo,hi,0)
 assert counts[0]>=nth and counts[1]==counts[2],(nth,counts)
 assert u(r,16)==0 and u(r,88)==0 and u(a.ctx.raw,792)==0 and u(a.q.w.raw,40)==0
 assert h.caps(a.v)==before and fds==set(os.listdir('/proc/self/fd')),(nth,before,h.caps(a.v))
 faults.append(counts)
mark('nine-actual-submission-allocation-failures-unwind-with-no-accepted-job',counts=faults)
for name,path in [('actual-payload',A/'native-background-payload-v1/payload-component.so'),('actual-Job',A/'native-background-jobs-external-v3/jobs-component.so'),('actual-runtime-provider',B/'native-multiversion-background-runtime-v4/runtime-provider.so')]:
 before=h.caps(a.v);lo,hi=bounds(path);arm(lo,hi,1);r=invoke(a,caps,5);counts=[cnt(i)for i in range(3)];arm(lo,hi,0)
 assert counts[0]>=1 and counts[1]==counts[2],(name,counts)
 assert h.caps(a.v)==before and u(a.q.w.raw,40)==0 and u(a.ctx.raw,792)==0,(name,h.caps(a.v),before)
 mark('allocation-failure-'+name,counts=counts)
# Context and envelope/view controls preserve all original public output bytes.
raw=wire(caps);controls=0
for sn,on,wn in [(0,524288,8192),(1,524288,8192),(127,524288,8192),(129,524288,8192),(128,0,8192),(128,524287,8192),(128,524288,0),(128,524288,8191)]:
 s=C.create_string_buffer(raw+b'x');o=C.create_string_buffer(b'\xa7'*524288,524288);before=a.ctx.raw
 rc=entry(s,sn,o,on,a.ctx,wn);assert rc==0xfffffffd and o.raw[:128]==b'\xa7'*128 and a.ctx.raw==before,(sn,on,wn,rc);controls+=1
for at,val in[(0,0),(8,2),(16,1),(96,1),(120,1)]:
 x=bytearray(raw);struct.pack_into('<Q',x,at,val);s=C.create_string_buffer(bytes(x));o=C.create_string_buffer(b'\xa7'*524288,524288);old=a.ctx.raw
 assert entry(s,128,o,524288,a.ctx,8192)==0xfffffffd and o.raw[:128]==b'\xa7'*128 and a.ctx.raw==old;controls+=1
for at,val in[(0,0),(8,0),(24,255),(32,0),(48,4095),(72,255),(96,255),(104,0),(128,0),(168,1023),(176,0),(216,255),(224,0),(232,0),(240,10100890),(264,2047),(272,0),(280,0),(288,0),(312,0),(792,2)]:
 prior=a.ctx.raw;struct.pack_into('<Q',a.ctx,at,val);changed=a.ctx.raw;s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xa8'*524288,524288)
 assert entry(s,128,o,524288,a.ctx,8192)==0xfffffffd and a.ctx.raw==changed and o.raw[:128]==b'\xa8'*128,(at,val)
 C.memmove(a.ctx,prior,8192);controls+=1
for i in (0,2,4):
 sb=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xa9'*524288,524288);args=[C.addressof(sb),128,C.addressof(o),524288,C.addressof(a.ctx),8192];args[i]=0;prior=a.ctx.raw
 assert entry(*args)==0xfffffffd and o.raw==b'\xa9'*524288 and a.ctx.raw==prior;controls+=1
# The held-condition violation is a private failure, never recursive locking.
a.q.tx(10);r=invoke(a,caps,6);assert u(a.q.w.raw,128)&0xffffffff==1;a.q.tx(11);controls+=1
pid=os.fork()
if pid==0:
 try:invoke(a,caps,6);os._exit(0)
 except BaseException:os._exit(78)
assert os.waitpid(pid,0)[1]==0;controls+=1
mark('private-envelopes-views-context-pid-and-nonrecursive-condition',controls=controls)
# Nine actual submitters share one condition and exactly eight accepted slots.
bar=threading.Barrier(10);replies=[];errors=[];mu=threading.Lock()
def submitter():
 try:
  bar.wait();r=invoke(a,caps,None)
  with mu:replies.append(r)
 except BaseException as e:
  with mu:errors.append(repr(e))
ts=[threading.Thread(target=submitter)for _ in range(9)]
for t in ts:t.start()
bar.wait()
for t in ts:t.join(30);assert not t.is_alive()
assert not errors,errors
success=[r for r in replies if u(r,8)==0];rejected=[r for r in replies if u(r,8)==1]
assert len(success)==8 and len(rejected)==1 and u(a.q.w.raw,40)==8,(len(success),len(rejected))
assert json.loads(rejected[0][128:128+u(rejected[0],80)])['message']=='E_HIA_BACKGROUND: finite outstanding job capacity is exhausted'
metas=[]
for r in success:
 f=(struct.unpack_from('<3Q',r,24),struct.unpack_from('<3Q',r,48));a.user.append(f);a.p.fs.append(f);metas.append(a.metadata(r))
assert sorted(r['job']for r in metas)==list(range(1,9))
assert int(a.v.raw(struct.unpack_from('<3Q',a.ctx.raw,312)))==9
for f in a.user:a.p.call(7,*f)
assert u(a.q.w.raw,40)==8
mark('nine-real-threads-eight-fifo-jobs-and-unbounded-counter',jobs=[x['job']for x in metas])
a.close()
for fd,_ in files:os.close(fd)
report={'passed':True,'whole_background_closed':False,'actual_submit_calls':actualcalls,'cases':rows,'image_sha256':sha256((A/'native-background-submission-v8/submission.so').read_bytes()).hexdigest()}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('SUBMISSION_CONTROLS_PASS',len(rows),actualcalls,flush=True)
