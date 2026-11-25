from pathlib import Path
from hashlib import sha256
import os,sys,ctypes as C,struct,json,types,time,threading,collections,copy,runpy,resource,traceback
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');B=A.parent/'cleanup-audit-20261124T0745Z';T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');W=A/'native-background-source';D=A/'native-background-submission-final-v1/ownership';D.mkdir(exist_ok=False)
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


def raw_packet(caps,op=0):
 b=bytearray(128);b[:8]=b'HIABSQ01';struct.pack_into('<Q',b,8,op)
 if op==0:
  for at,c in zip((24,48,72),caps):struct.pack_into('<3Q',b,at,*c)
 return bytes(b)
def invoke(a,caps=None,op=0,status=0):
 global actualcalls
 raw=raw_packet(caps or [],op);s=C.create_string_buffer(raw,128);o=C.create_string_buffer(b'\xc6'*524288,524288)
 rc=entry(s,128,o,524288,a.ctx,8192);r=o.raw;actualcalls+=1
 assert rc==0 and r[:8]==b'HIABSRP1' and u(r,8)==status,(rc,status,r[:128].hex())
 assert u(a.q.w.raw,128)&0xffffffff==0 and s.raw==raw
 return r
def inputs(a):
 return [make(a.v,x)for x in([],{'abstain':{'program_sha256':a.snapshot[128:160].hex(),'search_ns':0}},{'target':'x86_64-unknown-linux-gnu'})]
SIX=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
for operation in (4,5):
 a=Actual();caps=inputs(a);seen=[];errors=[];origin=ns['public_entry']
 @SIX
 def actual_public(*args):
  try:
   s,sn,o,on,w,wn=args;op=u(C.string_at(s,16),8)
   if op!=operation or seen:return origin(*args)
   before=Path('/proc/self/status').read_text();vm=int(next(line.split()[1]for line in before.splitlines()if line.startswith('VmSize:')))*1024;old=resource.getrlimit(resource.RLIMIT_AS)
   try:
    resource.setrlimit(resource.RLIMIT_AS,(vm,old[1]));rc=origin(*args)
   finally:resource.setrlimit(resource.RLIMIT_AS,old)
   reply=C.string_at(o,128);seen.append((rc,reply));return rc
  except BaseException as e:
   errors.append(repr(e));return 0xfffffffd
 struct.pack_into('<Q',a.ctx,80,addr(actual_public))
 r=invoke(a,caps,status=3)
 assert not errors and len(seen)==1 and seen[0][0]==0,(operation,seen,errors)
 original=seen[0][1];assert u(original,8)==1 and u(original,16) in (103,200),original.hex()
 assert u(r,48)==u(original,16) and u(r,56)==1 and u(r,64)==u(original,96) and u(a.q.w.raw,40)==0 and u(a.ctx.raw,792)==0
 cap=struct.unpack_from('<3Q',r,24);assert cap==struct.unpack_from('<3Q',original,72)
 if cap[0]:
  info=h.exported(a.v,cap);assert info['class']=='MemoryError',info
  a.v.call(6,cap)
 struct.pack_into('<Q',a.ctx,80,addr(origin))
 a.close();mark('actual-public-Future-kernel-ENOMEM-'+str(operation),owned_original_exception=bool(cap[0]))
# A real, accepted Job remains owned when a later fixed dependency refuses.
a=Actual();caps=inputs(a);original=ve;seen=[];errors=[]
@SIX
def refuse_after_accept(*args):
 try:
  s,sn,o,on,w,wn=args;op=u(C.string_at(s,16),8)
  if op==6 and u(a.q.w.raw,40)==1 and len(seen)<2:
   seen.append(C.string_at(s,128));return 0xfffffffd
  return original(*args)
 except BaseException as e:errors.append(repr(e));return 0xfffffffd
struct.pack_into('<Q',a.ctx,8,addr(refuse_after_accept))
# Fresh freezing/typed structure must capture the same actual function used
# for all values; the wrapper forwards every operation before accepted state.
struct.pack_into('<Q',a.freezectx,8,addr(refuse_after_accept))
r=invoke(a,caps,status=9)
assert not errors and len(seen)==2 and u(r,16)==1 and u(a.ctx.raw,792)==1 and u(a.q.w.raw,40)==1
number=int(a.v.raw(struct.unpack_from('<3Q',a.ctx.raw,312)));assert number==2
at=1024+128*u(r,72);meta=struct.unpack_from('<3Q',a.ctx.raw,at+24);before=h.exported(a.v,meta)
assert before['job']==1 and before['enqueued_ns']>=before['submitted_ns'] and before['submit_work_ns']==0
r2=invoke(a,op=1,status=7)
assert u(a.ctx.raw,792)==0 and u(a.q.w.raw,40)==1 and int(a.v.raw(struct.unpack_from('<3Q',a.ctx.raw,312)))==number
assert h.exported(a.v,meta)==before and len(seen)==2
struct.pack_into('<Q',a.ctx,8,addr(ve));struct.pack_into('<Q',a.freezectx,8,addr(ve))
a.close();mark('post-accept-cleanup-quarantine-retries-only-owned-release',actual_dependency_refusals=2)
# Job numbering is not subject to the integer-to-text conversion policy.
a=Actual();caps=inputs(a);old=struct.unpack_from('<3Q',a.ctx.raw,312);big=a.v.scalar(10**100000);a.v.held.remove(big);a.v.call(6,old);struct.pack_into('<3Q',a.ctx,312,*big)
r=invoke(a,caps)
f=(struct.unpack_from('<3Q',r,24),struct.unpack_from('<3Q',r,48));a.user.append(f);a.p.fs.append(f)
at=1024+128*u(r,72);meta=struct.unpack_from('<3Q',a.ctx.raw,at+24);jobcap=h.child(a.v,meta,'job')
assert a.v.raw(jobcap)==b'1'+b'0'*100000;a.v.drop(jobcap)
assert a.v.raw(struct.unpack_from('<3Q',a.ctx.raw,312))==b'1'+b'0'*99999+b'1'
a.close();mark('100001-digit-next-job-counter-with-captured-4300-render-policy')
for fd,_ in files:os.close(fd)
report={'passed':True,'whole_background_closed':False,'actual_submit_calls':actualcalls,'cases':rows,'image_sha256':sha256((A/'native-background-submission-v8/submission.so').read_bytes()).hexdigest()}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('SUBMISSION_OWNERSHIP_PASS',len(rows),actualcalls,flush=True)
