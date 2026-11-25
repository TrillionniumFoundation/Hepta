from pathlib import Path
from hashlib import sha256
import ctypes as C,importlib.util,struct,json,threading,time,resource
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z')
B=A.parent/'cleanup-audit-20261124T0745Z'
D=A/'native-background-external-future-jobs-qualification-v2';D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
sp=importlib.util.spec_from_file_location('value_client',T/'qualify-result-value-core-smoke-v1.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
vp=T/'result-value-native-v4/result-value.flat';ve=m.load(vp,'6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c')
p=A/'native-background-future-cell-v4/future-cell.so';assert sha256(p.read_bytes()).hexdigest()=='a070bd290676e3b6bb89772b2e9c668be89749428762274f0c8675c8ebee70b9'
so=C.CDLL(str(p));entry=so.hia_mv_background_future_cell;entry.argtypes=[C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64];entry.restype=C.c_uint32
kernelso=C.CDLL(str(B/'native-multiversion-future-v2/future-component.so'));kernel=kernelso.hia_mv_future;kernel.argtypes=entry.argtypes;kernel.restype=C.c_uint32
rows=[];calls=0
def u(b,n):return struct.unpack_from('<Q',b,n)[0]
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
def done(name,**kw):
 rows.append({'case':name,'passed':True,**kw});(D/'report.json').write_text(json.dumps({'passed':False,'calls':calls,'cases':rows},indent=2)+'\n');print('FUTURE_CELL_CASE',name,calls,flush=True)


import sys,os
sys.path.insert(0,str(A/'native-background-source'))
from tools.qualify_hia_multiversion_background_jobs import Jobs
from tools.qualify_hia_multiversion_background_payload import Owner as Payload
JP=A/'native-background-jobs-external-v3/jobs-component.so'
assert sha256(JP.read_bytes()).hexdigest()=='209cce0ce13288f6d52afa41e9bbb28c0ffa5b198ffc248f7f527d85c7d2964e'
PP=A/'native-background-payload-v1/payload-component.so'
class External(Jobs):
 def __init__(self,cell):
  self.image=JP;self.lib=C.CDLL(str(JP));self.f=self.lib.hia_mv_background_jobs;self.f.argtypes=entry.argtypes;self.f.restype=C.c_uint32
  self.futurelib=kernelso;self.ff=kernel;self.payload=Payload(PP);self.w=C.create_string_buffer(256);self.calls=0;self.lock=threading.Lock();self.keep=[];self.cell=cell
  raw=bytearray(self.packet(9));raw[:8]=b'HIABJO02';struct.pack_into('<7Q',raw,24,C.cast(kernel,C.c_void_p).value,C.cast(self.payload.f,C.c_void_p).value,C.addressof(self.payload.w),256,C.cast(entry,C.c_void_p).value,C.addressof(cell.ctx),256)
  self.run(9,wire=bytes(raw))
 def external(self,cap,raw):
  wire=bytearray(self.packet(10,cap,raw));wire[:8]=b'HIABJO02'
  r=self.run(10,wire=bytes(wire));return struct.unpack_from('<3Q',r,16)

v=m.Values(entry=ve);f=Cells(v);q=External(f);cap=f.make()
for raw in (b'',b'\x00\xff',b'plain',b'x'*(8<<20)):
 j=q.external(cap,raw);fp,mp,ip,n=q.view(j)
 assert fp==u(f.call(6,cap),64) and n==len(raw) and C.string_at(ip,n)==raw and C.string_at(mp,64)==bytes(64)
 other=q.retain(j);q.drop(j);assert q.copy(other,0,min(n,4096))==raw[:4096]
 q.drop(other);assert u(q.w.raw,16)==u(q.w.raw,40)==0
 assert u(f.call(9,cap),48)==0
q.destroy();value=v.empty(dict);v.call(10,value,v.scalar('still'),v.scalar('alive'))
f.call(11,cap,b=value,kind=1);result,r=f.result(cap);assert v.type(result)[3:]==v.type(value)[3:]
f.finish();v.finish();done('Job-drops-all-input-storage-before-Future-completion',job_calls=q.calls)

# User Future reference, internal job reference, and returned mutable result
# have three different lifetimes.
v=m.Values(entry=ve);f=Cells(v);q=External(f);cap=f.make();job=q.external(cap,b'input that must be freed')
hold=f.retain(cap);f.drop(cap);jkeep=q.retain(job);q.drop(job)
obj=v.empty(list);v.call(16,obj,v.scalar(7));f.call(11,hold,b=obj,kind=1)
r1,_=f.result(hold);q.drop(jkeep);q.destroy();f.drop(hold);f.call(5)
v.call(16,r1,v.scalar(8));assert v.type(r1)[1]==2
v.finish();done('user-Job-result-independent-lifetimes',job_calls=q.calls)

# Legacy embedded and external references coexist in one configured Jobs owner.
v=m.Values(entry=ve);f=Cells(v);q=External(f);cap=f.make();legacy=q.create(b'legacy');external=q.external(cap,b'external')
assert q.view(legacy)[0]!=q.view(external)[0]
assert q.future(legacy,2,123)[0]==0 and q.future(legacy,6,0,0)[1][2]==123
for j in (legacy,external):
 payload=q.payload.create(b'detached journal');q.set(j,2,payload)
 r=q.field(j,2);assert q.payload.copy(r,0,16)==b'detached journal';q.payload.drop(r)
q.drop(legacy);q.drop(external);q.destroy();f.finish();v.finish();done('legacy-external-coexistence-and-owned-payloads',job_calls=q.calls)

# The actual completion callback drops the Job (and its independent Future ref)
# while the Future-cell method still owns its in-flight pin.
v=m.Values(entry=ve);f=Cells(v);q=External(f);cap=f.make();job=q.external(cap,b'captured input')
events=[];errors=[];CB=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64);DROP=C.CFUNCTYPE(None,C.c_uint64)
@CB
def cb(owner,data):
 try:
  q.drop(job);q.destroy();events.append('job gone')
  f.drop(cap);f.call(5,status=5);events.append('user gone')
  return 0
 except BaseException as e:errors.append(repr(e));return 2
@DROP
def drop(data):events.append('closure gone')
f.call(12,cap,b=(C.cast(cb,C.c_void_p).value,0,C.cast(drop,C.c_void_p).value),kind=1)
value=v.scalar(9);r=f.call(11,cap,b=value,kind=1)
assert not errors and u(r,40)==0 and events==['job gone','user gone','closure gone'],(errors,events,r[:128].hex())
f.call(5);v.finish();done('actual-callback-drops-Job-and-last-user-Future',job_calls=q.calls)

# The new private framing preserves every old HIABJO01 refusal.
v=m.Values(entry=ve);f=Cells(v);q=External(f);cap=f.make()
for op in (9,10):q.run(op,wire=q.packet(op),want=0xfffffffd)
for bad in[(0,0,0),(1,2,3),(cap[0],cap[1]^1,cap[2])]:
 raw=bytearray(q.packet(10,bad,b'x'));raw[:8]=b'HIABJO02';before=q.w.raw
 q.run(10,wire=bytes(raw),want=1);assert q.w.raw==before
foreign=Cells(v);other=foreign.make();raw=bytearray(q.packet(10,other,b'x'));raw[:8]=b'HIABJO02';q.run(10,wire=bytes(raw),want=1);foreign.finish()
q.destroy();f.finish();v.finish();done('separate02profile-and-real-foreign-cap-rejection',job_calls=q.calls)
(D/'report.json').write_text(json.dumps({'passed':True,'whole_background_closed':False,'calls':calls,'count':len(rows),'cases':rows,'future_image_sha256':sha256(p.read_bytes()).hexdigest(),'jobs_image_sha256':sha256(JP.read_bytes()).hexdigest(),'value_sha256':sha256(vp.read_bytes()).hexdigest()},indent=2)+'\n')
print('EXTERNAL_FUTURE_JOBS_PASS',len(rows),calls,flush=True)
