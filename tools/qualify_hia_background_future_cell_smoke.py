from pathlib import Path
from hashlib import sha256
import ctypes as C,importlib.util,struct,json,threading,time,resource
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z')
B=A.parent/'cleanup-audit-20261124T0745Z'
D=A/'native-background-future-cell-smoke-v3';D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
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

v=m.Values(entry=ve);f=Cells(v);a=f.make();b=f.retain(a);assert a!=b
v.call(20,status=6);f.call(5,status=5)
borrow=f.call(6,a);assert u(borrow,64)!=0
none,r=f.result(a,ns=0);assert none is None and u(r,40)==2 and u(r,48)==0
obj=v.empty(dict);key=v.scalar('n');one=v.scalar(1);v.call(10,obj,key,one)
r=f.call(11,a,b=obj,kind=1);assert u(r,40)==0 and u(r,48)==2
r1,_=f.result(a);r2,_=f.result(b);assert r1!=r2 and v.type(r1)[3:]==v.type(r2)[3:]==v.type(obj)[3:]
two=v.scalar(2);v.call(10,r1,key,two)
get=v.take(v.call(9,r2,key));assert v.raw(get)==b'2'
f.drop(a);f.drop(b);f.call(5);assert v.raw(v.take(v.call(9,r2,key)))==b'2'
v.finish();done('shared-value-result-survives-future')

v=m.Values(entry=ve);f=Cells(v);a=f.make();r=f.call(7,a);assert u(r,48)==1 and u(r,56)==1 and u(r,64)==1
data=v.scalar(19);r=f.call(11,a,b=data,kind=1);assert u(r,48)==1
none,r=f.result(a);assert none is None and u(r,40)==1
f.finish();v.finish();done('cancel-rejects-box-and-releases-context')

v=m.Values(entry=ve);f=Cells(v);a=f.make();data=v.empty(dict);v.call(10,data,v.scalar('class'),v.scalar('ValueError'))
f.call(11,a,b=data,kind=2);r1,r=f.result(a);assert u(r,72)==2 and v.type(r1)[3:]==v.type(data)[3:]
f.finish();v.finish();done('exception-box-same-value')

# A waiting native call owns a pin independently from the externally held cap.
v=m.Values(entry=ve);f=Cells(v);a=f.make();b=f.retain(a);result=[];errors=[]
def wait():
 try:result.append(f.result(a,infinite=1))
 except BaseException as e:errors.append(repr(e))
t=threading.Thread(target=wait);t.start();time.sleep(.02);f.drop(a)
value=v.scalar(42);f.call(11,b,b=value,kind=1);f.drop(b);t.join(5)
assert not t.is_alive() and not errors and len(result)==1 and v.raw(result[0][0])==b'42',(errors,result)
f.call(5);v.finish();done('wait-strong-pin-last-external-drop')

# Callback reentry may drop the last user cap and change the result.
v=m.Values(entry=ve);f=Cells(v);a=f.make();obj=v.empty(dict);key=v.scalar('callback');mark=v.scalar(True)
observed=[];drops=[]
CB=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64);DROP=C.CFUNCTYPE(None,C.c_uint64)
@CB
def cb(owner,data):
 try:
  cap,r=f.result(a);v.call(10,cap,key,mark);observed.append((owner,data,v.type(cap)[3:]))
  # Another object changes the intrusive registry neighbours while the
  # first Future's completion is unlocked and strongly pinned.
  other=f.make();f.drop(other)
  f.drop(a);f.call(5,status=5)
  return 0
 except BaseException as e:observed.append(('error',repr(e)));return 2
@DROP
def drop(data):drops.append(data)
f.call(12,a,b=(C.cast(cb,C.c_void_p).value,99,C.cast(drop,C.c_void_p).value),kind=7)
r=f.call(11,a,b=obj,kind=1);assert u(r,40)==0 and u(r,104)==1 and observed and observed[0][1]==99,(r[:128].hex(),observed)
assert drops==[99],drops
f.call(5);assert v.raw(v.take(v.call(9,obj,key)))==b'\x01';v.finish();done('callback-reentry-last-drop-neighbour-change')

# Independent nonce context token: release the initial anchor before completion,
# then drop the Future while a separately retained result value still survives.
v=m.Values(entry=ve);f=Cells(v);a=f.make();obj=v.scalar('alive');f.call(11,a,b=obj,kind=1);out,r=f.result(a)
v.drop(obj);v.call(22);f.drop(a);f.call(5);assert v.raw(out)==b'alive'
v.drop(out);assert not v.held
v.call(22,status=6);done('released-anchor-future-to-result-handoff')

report={'passed':True,'whole_background_closed':False,'calls':calls,'count':len(rows),'cases':rows,'image_sha256':sha256(p.read_bytes()).hexdigest(),'value_sha256':sha256(vp.read_bytes()).hexdigest()}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('FUTURE_CELL_SMOKE_PASS',calls,len(rows),flush=True)
