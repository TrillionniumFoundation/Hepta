from pathlib import Path
from hashlib import sha256
import os,sys,ctypes as C,struct,json,types,time,threading,collections,copy,runpy,resource,traceback
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');B=A.parent/'cleanup-audit-20261124T0745Z';T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');W=A/'native-background-source';D=A/'native-background-submission-cleanup-v4';D.mkdir(exist_ok=False)
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

a=Actual();caps=inputs(a);before=h.caps(a.v);original=ve;failed=[];typed_calls=[];errors=[];active_out=None;retrying=False;retry_failed=[]
@SIX
def typed_drop_fault(*args):
 try:
  s,sn,o,on,w,wn=args;op=u(C.string_at(s,16),8)
  pointer=u(active_out.raw,248) if active_out is not None else 0
  if pointer and s==pointer+1024:
   cap=struct.unpack_from('<3Q',C.string_at(s,128),24);phase=u(C.string_at(pointer+128,8),0)
   typed_calls.append({'op':op,'phase':phase,'retry':retrying,'cap':list(cap)})
   if op==6 and phase==301 and not retrying and len(failed)<2:
    failed.append(cap);return 0xfffffffd
   if op==6 and phase==301 and retrying and cap==failed[0] and not retry_failed:
    retry_failed.append(cap);return 0xfffffffd
  return original(*args)
 except BaseException as e:errors.append(repr(e));return 0xfffffffd
struct.pack_into('<Q',a.ctx,8,addr(typed_drop_fault));struct.pack_into('<Q',a.freezectx,8,addr(typed_drop_fault))
def actual(op):
 global actualcalls,active_out
 raw=raw_packet(caps if op==0 else [],op);s=C.create_string_buffer(raw,128);active_out=C.create_string_buffer(b'\xd7'*524288,524288)
 rc=entry(s,128,active_out,524288,a.ctx,8192);r=active_out.raw;actualcalls+=1
 assert rc==0 and r[:8]==b'HIABSRP1' and s.raw==raw,(rc,r[:128].hex())
 assert not errors,errors
 assert u(a.q.w.raw,128)&0xffffffff==0
 return r
r=actual(0);assert u(r,8)==9 and u(r,16)==0 and u(r,88)==1 and failed
assert u(a.q.w.raw,40)==0 and a.v.raw(struct.unpack_from('<3Q',a.ctx.raw,312))==b'1'
retained=(u(a.ctx.raw,3072+240-128),u(a.ctx.raw,3072+248-128))
assert all(retained)
# Fresh submit is blocked by owned cleanup, before input decoding and effects.
prior_calls=len(typed_calls);bad=actual(0);assert u(bad,8)==6 and u(bad,88)==1 and len(typed_calls)==prior_calls
retrying=True
before_retry=len(typed_calls);r=actual(1)
assert u(r,8)==9 and u(r,88)==1 and len(failed)==2 and failed[0]!=failed[1],{'header':r[:128].hex(),'failed':failed,'retry_failed':retry_failed,'typed':typed_calls[before_retry:],'control':{str(at):u(active_out.raw,at)for at in range(128,512,8)}}
assert (u(a.ctx.raw,3072+240-128),u(a.ctx.raw,3072+248-128))==retained
r=actual(1);assert u(r,8)==9 and u(r,88)==0 and u(a.ctx.raw,792)==0
retry_calls=typed_calls[before_retry:];assert retry_calls and all(x['op']==6 for x in retry_calls),retry_calls
assert {tuple(x['cap'])for x in retry_calls}==set(failed),retry_calls
assert h.caps(a.v)==before,(before,h.caps(a.v))
assert u(a.q.w.raw,40)==0 and a.v.raw(struct.unpack_from('<3Q',a.ctx.raw,312))==b'1'
# An empty retry is an actual no-op. It neither consumes nor repeats a submit.
r=actual(1);assert u(r,8)==0 and u(r,88)==0 and h.caps(a.v)==before
struct.pack_into('<Q',a.ctx,8,addr(ve));struct.pack_into('<Q',a.freezectx,8,addr(ve))
a.close();mark('typed-cleanup-owned-continuation-only-no-resubmit',failed_refs=[list(x)for x in failed],typed_retry_calls=retry_calls)
for fd,_ in files:os.close(fd)
report={'passed':True,'whole_background_closed':False,'actual_submit_calls':actualcalls,'cases':rows,'image_sha256':sha256((A/'native-background-submission-v8/submission.so').read_bytes()).hexdigest(),'typed_sha256':'8ac533174506bb5dea7206fae1b0031d32d4d86e6c31c94d6ba241d7bf48e944'}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('SUBMISSION_CLEANUP_PASS',len(rows),actualcalls,flush=True)
