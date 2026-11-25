from pathlib import Path
from hashlib import sha256
import ctypes as C,importlib.util,struct,json,threading,time,resource
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z')
B=A.parent/'cleanup-audit-20261124T0745Z'
D=A/'native-background-future-cell-allocation-v3';D.mkdir(exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
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


hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;count=hooks.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
maps=[line.split()[0].split('-')for line in Path('/proc/self/maps').read_text().splitlines()if str(p)in line]
lo=min(int(x,16)for x,y in maps);hi=max(int(y,16)for x,y in maps)
v=m.Values(entry=ve);f=Cells(v);base=f.make();value=v.scalar(33)
for op,nth in [(1,1),(1,2),(2,1),(11,1)]:
 before=f.ctx.raw;arm(lo,hi,nth)
 r=f.call(op,base if op in(2,11)else(0,0,0),b=value if op==11 else(0,0,0),kind=1 if op==11 else 0,status=4)
 observed=[count(i)for i in range(3)]
 assert observed==[nth,nth-1,nth-1],(op,nth,observed)
 assert f.ctx.raw==before and u(f.call(9,base),48)==0,(op,nth)
 arm(lo,hi,0)
 retry=f.make()if op==1 else(f.retain(base)if op==2 else None)
 if retry:f.drop(retry)
 done('malloc-'+str(op)+'-'+str(nth),actual_counts=observed)
arm(lo,hi,0);f.call(11,base,b=value,kind=1);extra=f.make();f.drop(extra)
# Retirement is allocation-free in this owner, so a denied next allocation
# cannot prevent releasing its box, nonce node and independent context token.
arm(lo,hi,1);f.drop(base);observed=[count(i)for i in range(3)];assert observed==[0,0,3],observed
arm(lo,hi,0);f.finish();v.finish();done('last-drop-no-owner-allocation',actual_counts=observed)
v=m.Values(entry=ve);f=Cells(v);arm(lo,hi,0);cap=f.make();cs=[cap]+[f.retain(cap)for _ in range(1000)]
assert[count(i)for i in range(3)]==[1002,1002,0]
for cap in cs:f.drop(cap)
assert[count(i)for i in range(3)]==[1002,1002,1002]
arm(lo,hi,0);f.finish();v.finish();done('1001-independent-nonce-cap-releases')
# Already-settled original _complete ignores even an invalid value and
# performs no owner allocation before that decision.
for completed in (False,True):
 v=m.Values(entry=ve);f=Cells(v);cap=f.make()
 original=v.scalar("original")
 if completed:f.call(11,cap,b=original,kind=1)
 else:f.call(7,cap)
 arm(lo,hi,1)
 r=f.call(11,cap,b=(1,2,3),kind=1)
 assert [count(i)for i in range(3)]==[0,0,0]
 assert u(r,48)==(2 if completed else 1),r[:128].hex()
 arm(lo,hi,0)
 if completed:
  got,_=f.result(cap);assert v.type(got)[3:]==v.type(original)[3:]
 else:
  got,r=f.result(cap);assert got is None and u(r,40)==1
 f.finish();v.finish();done('already-done-ignores-value-before-allocation-'+str(completed),actual_counts=[0,0,0])
(D/'report.json').write_text(json.dumps({'passed':True,'whole_background_closed':False,'calls':calls,'count':len(rows),'cases':rows,'image_sha256':sha256(p.read_bytes()).hexdigest()},indent=2)+'\n')
print('FUTURE_CELL_ALLOCATIONS_PASS',len(rows),calls,flush=True)
