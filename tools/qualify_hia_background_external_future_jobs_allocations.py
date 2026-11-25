from pathlib import Path
from hashlib import sha256
import ctypes as C,importlib.util,struct,json,threading,time,resource
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z')
B=A.parent/'cleanup-audit-20261124T0745Z'
D=A/'native-background-external-future-jobs-allocation-v3';D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
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


hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;count=hooks.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
def region(path):
 maps=[line.split()[0].split('-')for line in Path('/proc/self/maps').read_text().splitlines()if str(path)in line]
 return min(int(x,16)for x,y in maps),max(int(y,16)for x,y in maps)
counts=lambda:[count(i)for i in range(3)]
v=m.Values(entry=ve);f=Cells(v);q=External(f);cap=f.make()
lo,hi=region(JP);clo,chi=region(p)
for raw in (b'',b'opaque\\x00bytes',b'x'*(8<<20)):
 for nth in (1,2):
  before=q.w.raw;fc=f.ctx.raw
  wire=bytearray(q.packet(10,cap,raw));wire[:8]=b'HIABJO02'
  arm(lo,hi,nth);q.run(10,wire=bytes(wire),want=4);seen=counts()
  assert seen==[nth,nth-1,nth-1],(nth,seen)
  assert q.w.raw==before and f.ctx.raw==fc
  arm(lo,hi,0);j=q.external(cap,raw);q.drop(j)
  assert u(q.w.raw,16)==u(q.w.raw,40)==0
  done('job-own-allocation-failure-'+str(len(raw))+'-'+str(nth),actual_counts=seen)
# Deny the actual cell's node allocation in Job -> Future retain.
wire=bytearray(q.packet(10,cap,b'capture'));wire[:8]=b'HIABJO02'
before=q.w.raw;fc=f.ctx.raw;arm(clo,chi,1);q.run(10,wire=bytes(wire),want=4)
assert counts()==[1,0,0] and q.w.raw==before and f.ctx.raw==fc
arm(clo,chi,0);done('actual-cell-retain-allocation-failure',actual_counts=[1,0,0])
# Actual Job malloc/free accounting: 8MiB input plus private continuation
# is freed while the independent Future stays pending.
arm(lo,hi,0);j=q.external(cap,b'x'*(8<<20))
assert counts()==[2,2,0],counts()
r=q.retain(j);assert counts()==[3,3,0]
q.drop(j);assert counts()==[3,3,1]
arm(lo,hi,1);q.drop(r);seen=counts();assert seen==[0,0,2],seen
arm(lo,hi,0);assert u(f.call(9,cap),48)==0
q.destroy();value=v.scalar('after Job free');f.call(11,cap,b=value,kind=1)
got,_=f.result(cap);assert v.raw(got)==b'after Job free'
f.finish();v.finish();done('8MiB-job-input-free-pending-Future',actual_counts=seen)
(D/'report.json').write_text(json.dumps({'passed':True,'whole_background_closed':False,'cases':rows,'count':len(rows),'future_calls':calls,'future_image_sha256':sha256(p.read_bytes()).hexdigest(),'jobs_image_sha256':sha256(JP.read_bytes()).hexdigest(),'value_sha256':sha256(vp.read_bytes()).hexdigest()},indent=2)+'\n')
print('EXTERNAL_FUTURE_ALLOCATIONS_PASS',len(rows),calls,flush=True)
