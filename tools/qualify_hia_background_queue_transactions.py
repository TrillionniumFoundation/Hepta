from pathlib import Path
from hashlib import sha256
import ctypes as C,importlib.util,struct,json,threading,time,resource
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z')
B=A.parent/'cleanup-audit-20261124T0745Z'
D=A/'native-background-queue-combined-qualification-v2';D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
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


from tools.qualify_hia_multiversion_background_queue import Queue
REFP=A/'native-background-job-refs-v2/job-refs.so'
assert sha256(REFP.read_bytes()).hexdigest()=='eb4479c0b38a356ba826fe6397e6098d0a8d3f9ee453aaf4720f6fcba9206de3'
refso=C.CDLL(str(REFP));reff=refso.hia_mv_background_job_refs;reff.argtypes=entry.argtypes;reff.restype=C.c_uint32
QDIR=A/'native-background-queue-transaction-v3';QI=QDIR/'queue-component.so';qmeta=json.loads((QDIR/'packing.json').read_text())
assert sha256(QI.read_bytes()).hexdigest()==qmeta['image_sha256']
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

v=m.Values(entry=ve);f=Cells(v);jobs=External(f);ref=Ref(jobs);future=f.make()
for j in (jobs.create(b'legacy'),jobs.external(future,b'actual external')):
 a=ref.call(1,j);assert a!=j and jobs.copy(a,0,jobs.view(j)[3])in(b'legacy',b'actual external')
 ref.call(2,a);ref.call(2,a,1);ref.call(1,(a[0],a[1]^1,a[2]),1)
 jobs.drop(j)
for bad in ((0,0,0),(1,2,3)):
 ref.call(1,bad,1);ref.call(2,bad,1)
jobs.destroy();f.finish();v.finish();done('native-Job-provider-real-retain-drop-and-refusal',provider_calls=ref.calls)

# Full native entry rejects malformed views/frames before output or context writes.
v=m.Values(entry=ve);f=Cells(v);jobs=External(f);ref=Ref(jobs);cap=jobs.create(b'guard')
raw=struct.pack('<8s7Q',b'HIABJRF1',1,*cap,0,0,0);bad=[]
for n in (0,1,63,65):bad.append((raw+b'x',n,128,64))
for n in (0,1,127):bad.append((raw,64,n,64))
for n in (0,1,63):bad.append((raw,64,128,n))
for at,val in [(0,0),(8,0),(8,3),(8,(1<<64)-1),(40,1),(48,1),(56,1)]:
 x=bytearray(raw);struct.pack_into('<Q',x,at,val);bad.append((bytes(x),64,128,64))
for wire,sn,on,wn in bad:
 s=C.create_string_buffer(wire);o=C.create_string_buffer(b'\xa4'*128,128);prior=ref.ctx.raw
 assert reff(s,sn,o,on,ref.ctx,wn)==0xfffffffd and o.raw==b'\xa4'*128 and ref.ctx.raw==prior
for at,val in [(0,0),(8,0),(16,0),(24,255),(32,1),(40,1),(48,1),(56,1)]:
 old=ref.ctx.raw;struct.pack_into('<Q',ref.ctx,at,val);s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xaa'*128,128)
 assert reff(s,64,o,128,ref.ctx,64)==0xfffffffd and o.raw==b'\xaa'*128
 C.memmove(ref.ctx,old,64)
for which in range(3):
 s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xab'*128,128);args=[C.addressof(s),64,C.addressof(o),128,C.addressof(ref.ctx),64]
 args[which*2]=0;assert reff(*args)==0xfffffffd and o.raw==b'\xab'*128
for which,ptr in [(0,(1<<64)-32),(1,(1<<64)-64),(2,(1<<64)-32)]:
 s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xac'*128,128);args=[C.addressof(s),64,C.addressof(o),128,C.addressof(ref.ctx),64];args[which*2]=ptr
 assert reff(*args)==0xfffffffd and o.raw==b'\xac'*128
for src,srcn,out,outn,ctx,ctxn in [(0,64,32,128,256,64),(0,64,256,128,32,64),(0,64,256,128,320,64)]:
 buf=C.create_string_buffer(b'\xad'*1024,1024);before=buf.raw;p0=C.addressof(buf)
 assert reff(p0+src,srcn,p0+out,outn,p0+ctx,ctxn)==0xfffffffd and buf.raw==before
jobs.drop(cap);jobs.destroy();f.finish();v.finish();done('native-provider-private-frames-views-and-overlap',controls=len(bad)+8+3+3+3)

v=m.Values(entry=ve);f=Cells(v);jobs=External(f);q=Q(jobs);q.run(7)
fs=[f.make()for _ in range(8)];js=[jobs.external(c,b'job'+bytes([i]))for i,c in enumerate(fs)]
q.tx(10)
for j in js:q.add(j,tx=True)
assert u(q.tx(5),32)==8
closed=q.tx(4,{16:1});assert u(closed,56)==8 and u(closed,64)==1
assert u(q.w.raw,128)&0xffffffff==1
q.tx(11)
for z in q.refs(closed):jobs.drop(z['cap'])
for i in range(8):
 r=q.run(2);assert q.refs(r)[0]['cap']==js[i]
 q.tx(10);owned=q.settled(r,tx=True);q.tx(11)
 jobs.drop(q.refs(owned)[0]['cap'])
 assert u(f.call(9,fs[i]),48)==0
 value=v.scalar(i);f.call(11,fs[i],b=value,kind=1)
 assert v.raw(f.result(fs[i])[0])==str(i).encode()
assert u(q.run(2),16)==(1<<64)-1
q.run(8);q.destroy();jobs.destroy();f.finish();v.finish();done('eight-real-Jobs-under-one-condition-with-early-input-release',queue_calls=q.calls)

# A real worker must not dequeue between capacity checking / freezing /
# insertion and the caller's condition release.
v=m.Values(entry=ve);f=Cells(v);jobs=External(f);q=Q(jobs)
ready=threading.Event();begin=threading.Event();started=threading.Event();taken=threading.Event();settled=threading.Event();closing=threading.Event();errors=[]
future=f.make();j=jobs.external(future,b'condition-owned')
def worker():
 try:
  q.run(7);ready.set();assert begin.wait(5);started.set()
  r=q.run(2);taken.set();q.tx(10);owned=q.settled(r,tx=True);q.tx(11);jobs.drop(q.refs(owned)[0]['cap']);settled.set()
  assert closing.wait(5);assert u(q.run(2),16)==(1<<64)-1;q.run(8)
 except BaseException as e:errors.append(repr(e));taken.set();settled.set()
t=threading.Thread(target=worker);t.start();assert ready.wait(5)
q.tx(10);q.add(j,tx=True);begin.set();assert started.wait(5)
assert not taken.wait(.03) and u(q.w.raw,48)==(1<<64)-1
q.tx(11);assert taken.wait(5) and settled.wait(5)
q.run(4);closing.set();t.join(5);assert not t.is_alive()and not errors,errors
q.destroy();jobs.destroy();f.finish();v.finish();done('actual-worker-blocks-through-freeze-condition-and-wakes-after-release',queue_calls=q.calls)

# Exactly the same condition serializes shutdown against a submitted transaction.
v=m.Values(entry=ve);f=Cells(v);jobs=External(f);q=Q(jobs);q.run(7);future=f.make();j=jobs.external(future,b'shutdown')
q.tx(10);q.add(j,tx=True);entered=threading.Event();finished=threading.Event();rows_close=[];errors=[]
def shut():
 try:entered.set();rows_close.append(q.run(4,{16:1}));finished.set()
 except BaseException as e:errors.append(repr(e));finished.set()
t=threading.Thread(target=shut);t.start();assert entered.wait(5);assert not finished.wait(.03)
q.tx(11);assert finished.wait(5);t.join(5);assert not errors,errors
assert u(rows_close[0],56)==1
jobs.drop(q.refs(rows_close[0])[0]['cap']);r=q.run(2);jobs.drop(q.refs(q.settled(r))[0]['cap'])
q.run(8);q.destroy();jobs.destroy();f.finish();v.finish();done('actual-shutdown-clone-waits-for-transaction',queue_calls=q.calls)

v=m.Values(entry=ve);f=Cells(v);jobs=External(f);q=Q(jobs)
for op in (10,11):q.run(op,want=0xfffffffd)
for op in (0,2,7,8,9,12,(1<<64)-1):q.tx(op,want=0xfffffffd)
for op in (1,3,4,5,6,11):q.tx(op,want=65)
q.tx(10);q.tx(10,want=65);q.run(5,want=65)
foreign=[]
def wrong():foreign.append(q.tx(11,want=65))
t=threading.Thread(target=wrong);t.start();t.join(3);assert not t.is_alive()and len(foreign)==1
assert u(q.w.raw,128)&0xffffffff==1
pid=os.fork()
if pid==0:
 try:q.tx(11,want=65);os._exit(0)
 except BaseException:os._exit(77)
assert os.waitpid(pid,0)[1]==0
q.tx(11);q.tx(11,want=65);q.run(4);q.destroy();jobs.destroy();f.finish();v.finish();done('original-profile-and-thread-transaction-guards',queue_calls=q.calls)

# Actual malloc refusal from the Job owner triggers rollback of every clone;
# no semantic provider is implemented by this observer.
hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;cnt=hooks.values_fault_count;cnt.argtypes=[C.c_uint64];cnt.restype=C.c_uint64
maps=[line.split()[0].split('-')for line in Path('/proc/self/maps').read_text().splitlines()if str(JP)in line]
lo=min(int(x,16)for x,y in maps);hi=max(int(y,16)for x,y in maps)
v=m.Values(entry=ve);f=Cells(v);jobs=External(f);q=Q(jobs);q.run(7)
fs=[f.make()for _ in range(8)];js=[jobs.external(c,b'rollback')for c in fs]
for j in js:q.add(j)
faults=[]
for nth in range(1,9):
 q.tx(10);old=jobs.w.raw;arm(lo,hi,nth);r=q.tx(4,{16:1},want=5)
 actual=[cnt(i)for i in range(3)];assert actual==[nth,nth-1,nth-1],(nth,actual)
 assert jobs.w.raw==old and u(r,56)==0 and u(q.w.raw,40)==8 and u(q.w.raw,128)&0xffffffff==1
 arm(lo,hi,0);q.tx(11);faults.append(actual)
owned=q.run(6)
for r in q.refs(owned):jobs.drop(r['cap'])
q.run(8);q.destroy();jobs.destroy();f.finish();v.finish();done('eight-actual-Job-allocation-rollback-sites-under-held-condition',actual_counts=faults,queue_calls=q.calls)
report={'passed':True,'whole_background_closed':False,'cases':rows,'count':len(rows),'future_direct_calls':calls,'provider_sha256':sha256(REFP.read_bytes()).hexdigest(),'queue_sha256':sha256(QI.read_bytes()).hexdigest(),'jobs_sha256':sha256(JP.read_bytes()).hexdigest(),'value_sha256':sha256(vp.read_bytes()).hexdigest()}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('BG_QUEUE_NATIVE_COMBINED_PASS',len(rows),calls,flush=True)
