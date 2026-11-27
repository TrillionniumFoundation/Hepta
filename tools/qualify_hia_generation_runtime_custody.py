"""Real Runtime terminal resource custody in the single native root.

This oracle never writes a production prefix, lock, arena, capability or reply.
Failure rules apply only to the actual new ledger mechanical syscall IP span.
"""
from pathlib import Path
from types import SimpleNamespace
import argparse,concurrent.futures,ctypes as C,errno,hashlib,json,mmap,os,struct
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_generation_runtime_global import Global,sidecar
from tools.qualify_hia_native_runtime_resources import ready,retired
from tools import qualify_hia_native_fixed_component_loader as faults
from tools.qualify_hia_clang_capture_faults import isolated
from tools import generate_hia_generation_runtime_borrow_packer as spec
Q=int.from_bytes(b'HIARTLQ1','little');R=int.from_bytes(b'HIARTLR1','little')
ANCHOR=7341056;ZERO=(0,0,0);REGISTER_OUT=(96<<20)+32768;OUT=262144
E=Path('/home/qian-qi/hia-followthrough-evidence-20261126-620a')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def wire(op,cap=ZERO):return struct.pack('<16Q',Q,op,0,*cap,*([0]*10))
class Borrow:
 def __init__(self,owner):
  self.owner=owner;self.context=owner.context;self.entry=owner.lib.hia_generation_runtime_borrow
  self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
  self.address=C.cast(self.entry,C.c_void_p).value
 def raw(self,request,context=None,n=None):
  n=(REGISTER_OUT if len(request)>=16 and q.get(request,8)==0 else OUT)if n is None else n
  src=C.create_string_buffer(request)
  with mmap.mmap(-1,n)as out:
   out[:1024]=b'\xa5'*1024
   rc=int(self.entry(src,len(request),q.address(out),n,self.context if context is None else context,2048))
   result=bytes(out[:1024])
  assert src.raw==request+b'\0';return rc,result
 def call(self,op,cap=ZERO):
  rc,raw=self.raw(wire(op,cap));assert rc==0 and q.get(raw,0)==R,(rc,raw[:128].hex())
  row={k:q.get(raw,v)for k,v in dict(status=8,registered=16,object=48,pending=80,known=88,removed=96,retired=104,detail=112,count=120).items()}
  assert all(row[k]in(0,1)for k in('registered','pending','known','removed','retired'));return row
 def deny(self,rules,fn):
  def run():
   old=faults.spec;faults.spec=SimpleNamespace(OUTER=spec.BRIDGE)
   try:faults.native_seccomp(self,rules)
   finally:faults.spec=old
   return fn()
  return faults.in_thread(run)
class PrivateCarrier:
 def __init__(self,owner):
  F=C.CFUNCTYPE(C.c_uint32,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
  self.entry=F(q.get(owner.context,32));self.context=(C.c_char*256).from_buffer(owner.context,256)
 def call(self,op,kind=0,cap=ZERO):
  frame=bytearray(128);frame[:8]=b'HIAMVHA1';struct.pack_into('<Q',frame,8,op);struct.pack_into('<Q',frame,16,kind);struct.pack_into('<3Q',frame,24,*cap)
  src=C.create_string_buffer(bytes(frame))
  with mmap.mmap(-1,96<<20)as out:
   rc=int(self.entry(src,128,q.address(out),len(out),self.context,256));raw=bytes(out[:128])
  assert rc==0 and raw[:8]==b'HIAMVHA2',(rc,raw.hex())
  return {k:q.get(raw,v)for k,v in dict(status=8,kind=16,retained=72,finalizer=80,known=96,consumed=104,pending=112).items()}
class Fixture:
 def __init__(self,path,out):
  self.owner=q.Owner(path);self.owner.initialize();self.g=Global(self.owner);self.before=set(os.listdir('/proc/self/fd'))
  ready(self.g.call(0));assert sidecar(self.owner,0)['status']==0
  self.c=q.Carrier(self.owner);self.p=PrivateCarrier(self.owner);self.b=Borrow(self.owner);self.api=q.Lifecycle(self.owner)
  self.parent=out/'artifacts';self.parent.mkdir()
  self.files=[(q.get(self.owner.context,88+8*i),(E/'shared-custody'/name).read_bytes())for i,name in enumerate(('normalizer-84619bd.bin','proof-3fc158.bin','builder-539ce9.bin'))]
  self.active=q.get(self.owner.context,72);self.side=q.get(self.owner.context,1208)
 def create(self):return q.old.create(self.c,self.files,self.parent)
 def register(self,cap):
  row=self.b.call(0,cap);assert row['status']==0 and row['registered']==1 and row['known']==1 and row['pending']==0,row;return row
 def guard(self,count):
  row=self.b.call(2);assert row['count']==count and row['status']==0,row
  assert q.get(self.owner.context,72)==self.active+count
  assert q.get(self.owner.context,1208)==self.side+count
  return row
 def blocked(self):
  assert self.g.call(1)['status']==6
  x=sidecar(self.owner,1);assert x['status']!=0 and x['retired']==0,x
  assert self.owner.call(3)['status']==2
 def close_runtime(self,cap):self.c.q(4,cap,q.old.public_request(8),child=0)
 def finish(self):
  self.guard(0)
  assert all(q.get(self.c.w,at)==0 for at in(16,40,64))
  x=sidecar(self.owner,1);assert x['status']==0 and x['retired']==1,x
  retired(self.g.call(1));last=self.owner.call(3);assert last['status']==0 and last['state']==3,last
  assert not list(self.parent.iterdir())
  assert set(os.listdir('/proc/self/fd'))==self.before
  return dict(actual_registry_arena_fd_artifacts_retired=True)
def orders(path,out):
 rows=[]
 for first in('runtime','lease'):
  d=out/first;d.mkdir();f=Fixture(path,d);rt=f.create();f.register(rt);ls=q.old.lease(f.c,rt)
  f.guard(1);f.blocked();f.guard(1)
  if first=='runtime':
   f.close_runtime(rt);r=f.p.call(3,1,rt);assert r['known']==r['consumed']==1 and r['pending']==0,r
   f.guard(1);f.c.call(ls,43)
   q.old.ok(f.api.call(6,ls))
  else:
   q.old.ok(f.api.call(6,ls));f.guard(1);f.close_runtime(rt)
   r=f.p.call(3,1,rt);assert r['known']==r['consumed']==1 and r['pending']==0,r
  f.guard(0);rows.append(dict(order=first,**f.finish()))
 return dict(passed=True,two_actual_terminal_orders=rows)
def refusal(path,out):
 f=Fixture(path,out);rt=f.create();r=f.register(rt);f.guard(1);ls=q.old.lease(f.c,rt)
 before=bytes(f.owner.context);base=f.b.call(2)
 for cap in(rt,(rt[0],rt[1]^1,rt[2]),ls,(1,1,1)):
  row=f.b.call(0,cap);assert row['status']!=0 and row['registered']==0 and row['pending']==0,row
  f.guard(1)
 row=f.b.call(1,(r['object'],0,0));assert row['status']==6 and row['retired']==0,row
 f.guard(1)
 bad=[b'',wire(3),wire(2)+b'x']
 for at in(0,16,24,48,120):
  raw=bytearray(wire(2));struct.pack_into('<Q',raw,at,1);bad.append(bytes(raw))
 for raw in bad:
  rc,returned=f.b.raw(raw);assert rc==q.BAD and returned==b'\xa5'*1024,(rc,raw,returned[:128])
  assert bytes(f.owner.context)==before
 copied=C.create_string_buffer(before);rc,_=f.b.raw(wire(2),copied)
 assert rc==q.BAD and copied.raw[:2048]==before
 rd,wr=os.pipe();pid=os.fork()
 if pid==0:
  try:
   os.close(rd);rc,_=f.b.raw(wire(2));os.write(wr,json.dumps([rc,bytes(f.owner.context)==before]).encode());os._exit(0)
  except BaseException:os._exit(90)
 os.close(wr);fork=json.loads(os.read(rd,4096));os.close(rd);_,status=os.waitpid(pid,0)
 assert status==0 and fork==[q.BAD,True],fork
 q.old.ok(f.api.call(6,ls));f.close_runtime(rt);r=f.p.call(3,1,rt);assert r['consumed']==1 and r['pending']==0,r
 return dict(passed=True,static_controls=len(bad),duplicate_wrong_kind_nonce_and_live_terminal_refused=True,copied_and_forked_context_unchanged=True,**f.finish())
def allocation_failure(path,out):
 f=Fixture(path,out);rt=f.create()
 row=f.b.deny([(9,errno.EIO,None)],lambda:f.b.call(0,rt))
 assert row['status']==5 and row['known']==1 and row['pending']==0 and row['registered']==0,row
 f.guard(0);assert f.p.call(6,1,rt)['status']==0
 f.register(rt);f.guard(1);f.close_runtime(rt);r=f.p.call(3,1,rt);assert r['consumed']==1 and r['pending']==0,r
 return dict(passed=True,actual_kernel_mmap_eio_compensates_both_guards=row,native_retry_registers_same_actual_runtime=True,**f.finish())
def terminal_retry(path,out):
 f=Fixture(path,out);rt=f.create();r=f.register(rt);f.guard(1);f.close_runtime(rt)
 first=f.b.deny([(11,errno.EIO,None)],lambda:f.p.call(3,1,rt))
 assert first['known']==first['consumed']==first['pending']==1 and first['retained']==1,first
 f.guard(1);f.blocked()
 absent=f.p.call(6,1,rt);assert absent['status']==1 and absent['known']==1 and absent['consumed']==0,absent
 retry=f.p.call(7);assert retry['status']==0 and retry['known']==1 and retry['consumed']==retry['pending']==0,retry
 f.guard(0)
 again=f.p.call(7);assert again['known']==1 and again['consumed']==again['pending']==0,again
 return dict(passed=True,actual_record_munmap_eio_retains_native_object_and_guards=first,actual_no_double_drop_retry=retry,**f.finish())
def concurrent_records(path,out):
 f=Fixture(path,out);caps=[f.create()for _ in range(3)]
 with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:
  rows=list(pool.map(f.register,caps))
 f.guard(3)
 aliases=[f.c.q(2,c)['cap']for c in caps]
 with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:replies=list(pool.map(lambda c:f.p.call(3,1,c),caps))
 assert all(r['known']==r['consumed']==1 and r['pending']==0 for r in replies),replies
 f.guard(3)
 for cap in aliases:f.close_runtime(cap)
 with concurrent.futures.ThreadPoolExecutor(max_workers=3)as pool:replies=list(pool.map(lambda c:f.p.call(3,1,c),aliases))
 assert all(r['known']==r['consumed']==1 and r['pending']==0 for r in replies),replies
 return dict(passed=True,three_actual_independent_runtime_records=True,concurrent_links_and_last_alias_retirement=True,**f.finish())
def legacy(path,out):
 f=Fixture(path,out);rt=f.create();ls=q.old.lease(f.c,rt);f.guard(0)
 f.close_runtime(rt);r=f.p.call(3,1,rt);assert r['consumed']==1 and r['pending']==0,r
 q.old.ok(f.api.call(6,ls));return dict(passed=True,unregistered_old_carrier_consumers_preserved=True,**f.finish())
CASES=(('two-terminal-orders',orders),('actual-capability-and-wire-refusals',refusal),('registration-allocation-failure',allocation_failure),('terminal-record-retirement-retry',terminal_retry),('concurrent-record-link-retirement',concurrent_records),('legacy-unregistered-carrier',legacy))
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 b=json.loads((a.build/'build.json').read_bytes());path=a.build/'install/hia-generation-component-root.so'
 assert pin(path.read_bytes())==b['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);rows=[]
 for name,fn in CASES:
  here=a.output/name;here.mkdir();rows.append(isolated(name,lambda fn=fn,here=here:fn(path,here)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n');print('RUNTIME_CUSTODY_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=pin(path.read_bytes()),construction=pin((a.build/'build.json').read_bytes()),qualifier=pin(Path(__file__).read_bytes()),
 actual_last_runtime_holder_retirement_hook=True,actual_global_borrow_and_two_parent_guards=True,public_constructor_qualified=False,whole_public_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print('RUNTIME_CUSTODY_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
