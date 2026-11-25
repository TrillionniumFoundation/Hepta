"""Heap Job/Future ownership using actual HIA Future and immutable payload owners."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,random,struct,threading,time
from tools.qualify_hia_multiversion_background_payload import Owner as Payload
get=lambda data,at:struct.unpack_from('<Q',data,at)[0]
U64=(1<<64)-1
CB=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_uint64)
DROP=C.CFUNCTYPE(C.c_uint64,C.c_uint64)
SIX=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
addr=lambda f:C.cast(f,C.c_void_p).value
class Jobs:
 def __init__(self,image,future,payload,poison=False,wrapped=False):
  self.image=Path(image);self.lib=C.CDLL(str(image));self.f=self.lib.hia_mv_background_jobs;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
  self.futurelib=C.CDLL(str(future));self.ff=self.futurelib.hia_mv_future;self.ff.argtypes=[C.c_void_p,C.c_uint64]*3;self.ff.restype=C.c_uint32
  self.payload=Payload(payload);self.w=C.create_string_buffer(256);self.calls=0;self.lock=threading.Lock();self.keep=[]
  if poison:C.memset(self.w,0xa5,256);C.memset(self.w,0,8)
  ffn,pfn=addr(self.ff),addr(self.payload.f)
  if wrapped:
   @SIX
   def fw(*args):return self.ff(*args)|(0xa5a5a5a5<<32)
   @SIX
   def pw(*args):return self.payload.f(*args)|(0xb6b6b6b6<<32)
   self.keep.extend((fw,pw));ffn,pfn=addr(fw),addr(pw)
  wire=bytearray(self.packet(0));struct.pack_into('<4Q',wire,24,ffn,pfn,C.addressof(self.payload.w),len(self.payload.w));self.run(0,wire=bytes(wire))
 @staticmethod
 def packet(op,cap=(0,0,0),raw=b'',offset=0,count=0,value=(0,0,0),slot=0):
  out=bytearray(128);out[:8]=b'HIABJO01';struct.pack_into('<Q',out,8,op);struct.pack_into('<3Q',out,24,*cap)
  if op==4:struct.pack_into('<2Q',out,48,offset,count)
  if op==7:struct.pack_into('<3Q',out,48,*value)
  struct.pack_into('<Q',out,72,len(raw));struct.pack_into('<Q',out,80,slot)
  return bytes(out)+raw
 def run(self,op,cap=(0,0,0),raw=b'',offset=0,count=0,value=(0,0,0),slot=0,on=2048,want=0,wire=None,wn=256):
  wire=self.packet(op,cap,raw,offset,count,value,slot) if wire is None else wire
  source=C.create_string_buffer(wire);out=C.create_string_buffer(max(on,2048));C.memset(out,0xa5,len(out));rc=self.f(source,len(wire),out,on,self.w,wn)
  with self.lock:self.calls+=1
  assert source.raw==wire+b'\0'
  if want>=0xfffffff0:assert rc==want,(op,rc,want);return out.raw
  assert rc==0 and out.raw[:8]==b'HIABJOR1',(op,rc,out.raw[:128].hex())
  assert get(out.raw,8)==want,(op,get(out.raw,8),want,out.raw[:128].hex())
  return out.raw
 def create(self,raw):
  r=self.run(1,raw=raw);return struct.unpack_from('<3Q',r,16)
 def retain(self,cap):
  r=self.run(2,cap);return struct.unpack_from('<3Q',r,16)
 def drop(self,cap):return self.run(3,cap)
 def view(self,cap):
  r=self.run(6,cap);assert get(r,88)==64 and get(r,96)==512;return tuple(get(r,x) for x in (64,72,80,40))
 def copy(self,cap,off,n):
  r=self.run(4,cap,offset=off,count=n,on=2048+n);assert get(r,48)==n;return r[2048:]
 def set(self,cap,slot,value=(0,0,0)):
  r=self.run(7,cap,value=value,slot=slot);assert get(r,112)==int(bool(value[0]));return r
 def field(self,cap,slot):
  r=self.run(8,cap,slot=slot)
  if get(r,16)==0:return None
  assert get(r,104)==1;return struct.unpack_from('<3Q',r,16)
 def future(self,cap,op,*args):
  # A method guard, including reentrant callback calls, owns a distinct node.
  guard=self.retain(cap)
  try:
   wp,_,_,_=self.view(guard);wire=struct.pack('<8s7Q',b'HIAMVFQ1',op,*(list(args)+[0]*(6-len(args))))
   source=C.create_string_buffer(wire);out=C.create_string_buffer(512);rc=self.ff(source,64,out,512,wp,512)
   assert source.raw==wire+b'\0' and out.raw[:8]==b'HIAMVFR1';return rc,struct.unpack_from('<16Q',out.raw)
  finally:self.drop(guard)
 def destroy(self):
  self.run(5);self.payload.run(5)

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--future',type=Path,required=True);p.add_argument('--payload',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 q=Jobs(a.image,a.future,a.payload,True);cases=[]
 def record(name,fn):
  started=time.monotonic_ns()
  try:
   detail=fn();assert get(q.w.raw,16)==0 and get(q.w.raw,40)==0,('jobs live',q.w.raw.hex());assert get(q.payload.w.raw,16)==0,'payload live'
  except BaseException as exc:
   (a.output/'failure.json').write_text(json.dumps({'case':name,'error':repr(exc),'completed':cases},indent=2)+'\n');raise
  cases.append({'name':name,'passed':True,'elapsed_ns':time.monotonic_ns()-started,'detail':detail});print('BG_JOBS_PASS',name,flush=True)
 def basic():
  rows=[b'',b'\0',b'\xff',bytes(range(256)),b'{"x":1,"x":2}\n']
  for raw in rows:
   cap=q.create(raw);held=q.retain(cap);assert cap!=held
   fp,mp,ip,n=q.view(cap);assert n==len(raw) and C.string_at(ip,n)==raw and C.string_at(mp,64)==bytes(64)
   rc,v=q.future(cap,5);assert rc==0 and v[3]==0
   q.drop(cap);assert C.string_at(ip,n)==raw and q.copy(held,0,n)==raw
   rc,v=q.future(held,2,73);assert rc==0
   rc,v=q.future(held,6,0,0);assert rc==0 and v[2]==73
   q.run(6,cap,want=1);q.drop(held)
  return {'input_cases':len(rows),'native_future_initialized_and_completed':True}
 record('opaque-immutable-input-and-retained-native-future',basic)
 def owner_lifetime():
  pending=q.create(b'job-input');user=q.retain(pending);val=q.payload.create(b'actual result bytes')
  q.set(pending,0,val);q.drop(pending)
  q.run(5,want=5);q.payload.run(5,want=5)
  assert q.future(user,2,913)[0]==0 and q.future(user,6,0,0)[1][2]==913
  out=q.field(user,0);assert out is not None and out!=val
  q.drop(user);q.payload.run(6,val,want=1)
  assert q.payload.copy(out,0,19)==b'actual result bytes'
  q.payload.drop(out)
  return {'pending_release_preserves_public_future':True,'copied_result_reference_survives_last_job_release':True}
 record('queue-release-and-user-future-result-lifetime',owner_lifetime)
 def slots():
  cap=q.create(b'opaque')
  originals=[]
  for i in range(8):
   value=q.payload.create(bytes([i])*31);originals.append(value);q.set(cap,i,value)
  q.run(7,cap,value=originals[0],slot=1,want=3)
  for i in range(8):
   c=q.field(cap,i);assert q.payload.copy(c,0,31)==bytes([i])*31;q.payload.drop(c)
  newer=q.payload.create(b'replacement');q.set(cap,3,newer);q.payload.run(6,originals[3],want=1)
  q.set(cap,4);assert q.field(cap,4) is None;q.payload.run(6,originals[4],want=1)
  q.drop(cap)
  for c in originals+[newer]:q.payload.run(6,c,want=1)
  return {'owned_slots':8,'replacement_clear_duplicate_and_last_drop':True}
 record('eight-transferred-payload-slots-with-exact-retirement',slots)
 def reentry():
  outer=q.create(b'outer');inner=q.create(b'inner');events=[];errors=[]
  q.set(outer,0,q.payload.create(b'outer result'));q.set(inner,0,q.payload.create(b'inner result'))
  @CB
  def callback(w,data):return 0
  @DROP
  def drop(data):
   try:
    assert get(q.w.raw,32)&0xffffffff==0
    assert get(q.w.raw,40)!=0
    q.run(5,want=5);events.append(data)
    if data==1:q.drop(inner)
   except BaseException as exc:errors.append(repr(exc))
   return 0
  q.keep.extend((callback,drop))
  assert q.future(inner,4,addr(callback),2,addr(drop),2)[0]==0
  assert q.future(outer,4,addr(callback),1,addr(drop),1)[0]==0
  q.drop(outer);assert events==[1,2] and not errors,(events,errors)
  return {'reentrant_closure_drops':events,'destroy_refused_until_retirement_list_empty':True}
 record('nested-closure-destruction-outside-registry-lock',reentry)
 def method_guard():
  cap=q.create(b'public');errors=[];events=[]
  @CB
  def callback(w,data):
   try:
    q.drop(cap);events.append('user handle released during completion')
    q.run(5,want=5)
    # Method's private strong guard still owns all native Future storage.
    assert C.string_at(w,8)==b'HIAMVFS1'
   except BaseException as exc:errors.append(repr(exc))
   return 0
  @DROP
  def drop(data):events.append('closure dropped');return 0
  q.keep.extend((callback,drop))
  assert q.future(cap,4,addr(callback),0,addr(drop),1)[0]==0
  rc,_=q.future(cap,2,73);assert rc==0 and not errors,(rc,errors)
  assert events==['user handle released during completion','closure dropped'],events
  q.run(6,cap,want=1)
  return {'method_strong_reference_covers_reentrant_last_public_drop':True}
 record('last-user-reference-dropped-inside-completion-callback',method_guard)
 def concurrent_retirement():
  count=12;barrier=threading.Barrier(count);errors=[];events=[];lock=threading.Lock()
  @CB
  def callback(w,data):return 0
  @DROP
  def drop(data):
   try:
    barrier.wait(10);q.run(5,want=5)
    with lock:events.append(data)
   except BaseException as exc:errors.append(repr(exc))
   return 0
  q.keep.extend((callback,drop));caps=[]
  for i in range(count):
   cap=q.create(struct.pack('<Q',i));q.set(cap,i%8,q.payload.create(struct.pack('<Q',i)));caps.append(cap)
   assert q.future(cap,4,addr(callback),i,addr(drop),i)[0]==0
  def worker(cap):
   try:q.drop(cap)
   except BaseException as exc:errors.append(repr(exc))
  ts=[threading.Thread(target=worker,args=(cap,)) for cap in caps]
  for t in ts:t.start()
  for t in ts:t.join(15);assert not t.is_alive()
  assert not errors and sorted(events)==list(range(count)),(errors,events)
  return {'actual_overlapping_retirements':count,'retiring_links_reread_after_callbacks':True}
 record('12-concurrent-last-releases-and-reentrant-context-checks',concurrent_retirement)
 def threads():
  base=q.create(b'input');q.set(base,0,q.payload.create(b'v0'));copies=[q.retain(base) for _ in range(8)];errors=[]
  def reader(cap):
   try:
    for i in range(100):
     ref=q.field(cap,0);raw=q.payload.copy(ref,0,q.payload.view(ref)[1]);assert raw.startswith(b'v');q.payload.drop(ref)
     keep=q.retain(cap);assert q.copy(keep,0,5)==b'input';q.drop(keep)
    q.drop(cap)
   except BaseException as exc:errors.append(repr(exc))
  ts=[threading.Thread(target=reader,args=(cap,)) for cap in copies]
  for t in ts:t.start()
  for i in range(100):q.set(base,0,q.payload.create(('v'+str(i)).encode()))
  for t in ts:t.join(20);assert not t.is_alive()
  assert not errors,errors;q.drop(base)
  return {'threads':8,'result_clones_and_job_reference_cycles':800,'concurrent_owned_replacements':100}
 record('concurrent-result-retain-replace-and-job-retain-copy-drop',threads)
 def guards():
  cap=q.create(b'0123456789');other=Jobs(a.image,a.future,a.payload);other.run(6,cap,want=1);other.destroy()
  foreign=Payload(a.payload);bad=foreign.create(b'bad');q.run(7,cap,value=bad,slot=0,want=1);foreign.drop(bad);foreign.run(5)
  for bad in ((1,2,3),(cap[0],cap[1]^1,cap[2]),(cap[0],cap[1],cap[2]^1)):q.run(6,bad,want=1)
  for off,n in ((11,0),(10,1),(0,11),(U64,0),(0,U64),(U64,U64)):
   r=q.run(4,cap,offset=off,count=n,on=2100,want=3);assert r[2048:]==b'\xa5'*52
  r=q.run(4,cap,count=10,on=2057,want=7);assert r[2048:]==b'\xa5'*9
  q.run(7,cap,slot=8,want=3);q.run(8,cap,slot=U64,want=3)
  checks=0
  for op in range(9):
   used={0:{24,32,40,48},1:{72},2:{24,32,40},3:{24,32,40},4:{24,32,40,48,56},6:{24,32,40},7:{24,32,40,48,56,64,80},8:{24,32,40,80}}.get(op,set())
   for at in range(16,128,8):
    if at not in used:
     raw=bytearray(q.packet(op));struct.pack_into('<Q',raw,at,1);saved=q.w.raw;q.run(op,wire=bytes(raw),want=0xfffffffd);assert q.w.raw==saved;checks+=1
  for raw in (b'',q.packet(0)[:127],q.packet(0)+b'x',b'x'+q.packet(0)[1:],q.packet(9)):
   saved=q.w.raw;q.run(0,wire=raw,want=0xfffffffd);assert q.w.raw==saved;checks+=1
  q.run(0,on=2047,want=0xfffffffd);q.run(0,wn=255,want=0xfffffffd)
  q.run(5,want=5);q.drop(cap);q.run(3,cap,want=1)
  return {'private_frame_refusals':checks+2,'range_refusals':8,'foreign_payload_never_transferred':True}
 record('private-fields-ranges-stale-foreign-job-and-payload-controls',guards)
 def large_and_reuse():
  raw=bytes(range(256))*32768+b'x';cap=q.create(raw);ptr=q.view(cap)[2];assert hashlib.sha256(C.string_at(ptr,len(raw))).digest()==hashlib.sha256(raw).digest()
  for off in (0,1,255,4096,len(raw)-1):assert q.copy(cap,off,min(65537,len(raw)-off))==raw[off:off+65537]
  q.drop(cap)
  for i in range(500):
   stale=q.create(struct.pack('<Q',i));q.drop(stale);live=q.create(b'live');q.run(6,stale,want=1);q.drop(live)
  return {'opaque_bytes':len(raw),'stale_allocator_reuse_controls':500}
 record('opaque-input-boundaries-and-stale-node-reuse',large_and_reuse)
 def u32_and_fork():
  wrapped=Jobs(a.image,a.future,a.payload,wrapped=True);cap=wrapped.create(b'x');wrapped.set(cap,0,wrapped.payload.create(b'payload'));wrapped.drop(cap);wrapped.destroy()
  cap=q.create(b'parent');pid=os.fork()
  if pid==0:
   try:q.run(6,cap,want=5);os._exit(0)
   except BaseException:os._exit(71)
  _,status=os.waitpid(pid,0);assert status==0
  assert q.copy(cap,0,6)==b'parent';q.drop(cap)
  return {'actual_provider_upper_RAX_discarded':True,'actual_fork_PID_rejected':True}
 record('fixed-u32-provider-and-actual-pid-boundaries',u32_and_fork)
 q.destroy();q.run(5,want=5);q.run(1,raw=b'x',want=5)
 report={'schema':'hepta.hia.background-native-jobs.v1','whole_background_qualified':False,'scope':'Native heap Job/Future ownership and immutable owned payload slots only; no rank/runtime or optimizer business fixture is admitted as a product.','image':str(a.image),'image_bytes':a.image.stat().st_size,'image_sha256':hashlib.sha256(a.image.read_bytes()).hexdigest(),'future_sha256':hashlib.sha256(a.future.read_bytes()).hexdigest(),'payload_sha256':hashlib.sha256(a.payload.read_bytes()).hexdigest(),'passed':len(cases),'failed':0,'actual_job_calls':q.calls,'actual_external_payload_calls':q.payload.calls,'cases':cases}
 (a.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_JOBS_QUALIFIED',len(cases),q.calls,q.payload.calls,flush=True)
if __name__=='__main__':main()
