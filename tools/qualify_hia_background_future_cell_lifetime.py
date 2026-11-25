from pathlib import Path
from hashlib import sha256
import ctypes as C,importlib.util,struct,json,threading,time,resource
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z')
B=A.parent/'cleanup-audit-20261124T0745Z'
D=A/'native-background-future-cell-lifetime-v3';D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
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


import os
# Capability identity, exact private framing and fork isolation.
v=m.Values(entry=ve);f=Cells(v);a=f.make();b=f.retain(a)
for bad in [(0,0,0),(1,2,3),(a[0],a[1]^1,a[2]),(a[0],a[1],a[2]^1)]:
 f.call(9,bad,status=1)
other=Cells(v);other.call(9,a,status=1);other.finish()
for op in [0,1,2,3,5,6,7,8,9,10,11,12,13]:
 used={0:{24,32,40,48},2:{24,32,40},3:{24,32,40},6:{24,32,40},7:{24,32,40},8:{24,32,40},9:{24,32,40},10:{24,32,40,104,112},11:{24,32,40,48,56,64,80},12:{24,32,40,48,56,64,80}}.get(op,set())
 for at in range(16,128,8):
  if at in used:continue
  raw=bytearray(128);raw[:8]=b'HIABFQ01';struct.pack_into('<Q',raw,8,op);struct.pack_into('<Q',raw,at,1)
  if op==11:struct.pack_into('<Q',raw,80,1)
  if op==12:struct.pack_into('<Q',raw,48,1)
  s=C.create_string_buffer(bytes(raw));o=C.create_string_buffer(b'\xa7'*16384,16384);before=f.ctx.raw
  rc=entry(s,128,o,16384,f.ctx,256);calls+=1
  assert rc==0xfffffffd and o.raw[:128]==b'\xa7'*128 and f.ctx.raw==before,(op,at,rc)
for op in (4,14,(1<<64)-1):
 raw=struct.pack('<8s15Q',b'HIABFQ01',op,*([0]*14));s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xaa'*16384,16384)
 assert entry(s,128,o,16384,f.ctx,256)==0xfffffffd and o.raw[:128]==b'\xaa'*128;calls+=1
for sn,on,wn in [(127,16384,256),(129,16384,256),(128,16383,256),(128,16384,255)]:
 s=C.create_string_buffer(129);C.memmove(s,b'HIABFQ01',8);o=C.create_string_buffer(b'\xaa'*16384,16384)
 assert entry(s,sn,o,on,f.ctx,wn)==0xfffffffd and o.raw[:128]==b'\xaa'*128;calls+=1
pid=os.fork()
if pid==0:
 try:f.call(9,a,status=5);os._exit(0)
 except BaseException:os._exit(77)
assert os.waitpid(pid,0)[1]==0
f.drop(a);f.call(9,a,status=1);f.drop(b);f.finish();v.finish();done('private-caps-atomic-frames-and-actual-fork')

# Strong result sharing and container mutation after native Future destruction.
v=m.Values(entry=ve);f=Cells(v);a=f.make();obj=v.empty(list);v.call(16,obj,v.scalar('original'))
f.call(11,a,b=obj,kind=1)
caps=[f.result(a)[0] for _ in range(100)]
assert len(set(caps))==100 and len(set(v.type(c)[3:]for c in caps))==1
for i in range(100):v.call(16,caps[i],v.scalar(i))
assert v.type(caps[-1])[1]==101
f.drop(a);f.finish();assert v.type(caps[0])[1]==101
v.finish();done('100-retained-result-aliases-and-mutation')

# Actual simultaneous completion/cancellation: every offered value remains
# caller-owned, exactly one box is stored or every candidate box is dropped.
for iteration in range(80):
 v=m.Values(entry=ve);f=Cells(v);a=f.make();b=f.retain(a)
 left=v.scalar(iteration);right=v.scalar(-iteration-1);bar=threading.Barrier(3);answers=[];errors=[]
 def actor(mode):
  try:
   bar.wait()
   answers.append((mode,f.call(7,b)if mode==2 else f.call(11,a if mode==0 else b,b=left if mode==0 else right,kind=1)))
  except BaseException as e:errors.append(repr(e))
 threads=[threading.Thread(target=actor,args=(mode,))for mode in (0,1,2)]
 for t in threads:t.start()
 for t in threads:t.join(5);assert not t.is_alive()
 assert not errors,errors
 state=f.call(9,a);assert u(state,48)in(1,2)
 cap,r=f.result(a)
 if u(state,48)==1:assert cap is None and u(r,40)==1
 else:assert cap is not None and v.raw(cap)in(str(iteration).encode(),str(-iteration-1).encode())
 for mode,row in answers:
  if mode==2 and u(row,64)==1:assert u(state,48)==1
  if mode!=2:assert u(row,40)in(0,6)
 f.finish();v.finish()
done('80-three-way-complete-cancel-races')

# Different last-drop callbacks retire simultaneously; their neighbours may
# change while no registry mutex is held.
v=m.Values(entry=ve);f=Cells(v);count=8;bar=threading.Barrier(count);events=[];errors=[];caps=[]
CB=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64);DROP=C.CFUNCTYPE(None,C.c_uint64)
@CB
def cb(owner,data):return 0
@DROP
def drop(data):
 try:
  bar.wait(8);f.call(5,status=5);events.append(data)
 except BaseException as e:errors.append(repr(e))
for i in range(count):
 cap=f.make();caps.append(cap)
 f.call(12,cap,b=(C.cast(cb,C.c_void_p).value,i,C.cast(drop,C.c_void_p).value),kind=i+1)
def retire(cap):
 try:f.drop(cap)
 except BaseException as e:errors.append(repr(e))
threads=[threading.Thread(target=retire,args=(cap,))for cap in caps]
for t in threads:t.start()
for t in threads:t.join(12);assert not t.is_alive()
assert not errors and sorted(events)==list(range(count)),(errors,events)
assert u(f.ctx.raw,16)==u(f.ctx.raw,40)==u(f.ctx.raw,48)==0
f.finish();v.finish();done('8-overlapping-retirements-and-context-guards')

# Callback Exception is caught by the original kernel, BaseException escapes
# completion classification, while the accepted shared result remains stable.
for callback_rc in (1,2):
 v=m.Values(entry=ve);f=Cells(v);a=f.make();obj=v.scalar(17);events=[]
 @CB
 def callback(owner,data):events.append('call');return callback_rc
 @DROP
 def dropper(data):events.append('drop')
 f.call(12,a,b=(C.cast(callback,C.c_void_p).value,3,C.cast(dropper,C.c_void_p).value),kind=77)
 r=f.call(11,a,b=obj,kind=1);assert u(r,40)==(0 if callback_rc==1 else 4) and u(r,48)==2
 got,_=f.result(a);assert v.raw(got)==b'17'
 f.finish();assert events==['call','drop'];v.finish()
done('callback-Exception-and-BaseException-box-ownership')

(D/'report.json').write_text(json.dumps({'passed':True,'whole_background_closed':False,'calls':calls,'count':len(rows),'cases':rows,'image_sha256':sha256(p.read_bytes()).hexdigest()},indent=2)+'\n')
print('FUTURE_CELL_LIFETIME_PASS',len(rows),calls,flush=True)
