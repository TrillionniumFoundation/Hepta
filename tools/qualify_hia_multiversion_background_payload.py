"""Actual immutable native ownership; external reference bytes and real threads."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,random,struct,threading,time
U64=(1<<64)-1
get=lambda data,at:struct.unpack_from('<Q',data,at)[0]
class Owner:
 def __init__(self,image,poison=False):
  self.image=Path(image);self.lib=C.CDLL(str(image));self.f=self.lib.hia_mv_background_payload;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
  self.w=C.create_string_buffer(256);self.calls=0;self.lock=threading.Lock()
  if poison:C.memset(self.w,0xa5,256);C.memset(self.w,0,8)
  self.run(0)
 @staticmethod
 def packet(op,cap=(0,0,0),raw=b'',offset=0,count=0):
  out=bytearray(128);out[:8]=b'HIABPY01';struct.pack_into('<Q',out,8,op);struct.pack_into('<3Q',out,24,*cap);struct.pack_into('<2Q',out,48,offset,count);struct.pack_into('<Q',out,72,len(raw));return bytes(out)+raw
 def run(self,op,cap=(0,0,0),raw=b'',offset=0,count=0,on=512,want=0,wire=None,wn=256):
  wire=self.packet(op,cap,raw,offset,count) if wire is None else wire
  source=C.create_string_buffer(wire);out=C.create_string_buffer(max(on,512));C.memset(out,0xa5,len(out));rc=self.f(source,len(wire),out,on,self.w,wn)
  with self.lock:self.calls+=1
  assert source.raw==wire+b'\0'
  if want>=0xfffffff0:assert rc==want,(op,rc,want);return out.raw
  assert rc==0 and out.raw[:8]==b'HIABPYR1',(op,rc,out.raw[:128].hex())
  assert get(out.raw,8)==want,(op,get(out.raw,8),want,out.raw[:128].hex())
  return out.raw
 def create(self,raw):
  out=self.run(1,raw=raw);return struct.unpack_from('<3Q',out,16)
 def retain(self,cap):
  out=self.run(2,cap);return struct.unpack_from('<3Q',out,16)
 def drop(self,cap):self.run(3,cap)
 def copy(self,cap,offset,count):
  r=self.run(4,cap,offset=offset,count=count,on=512+count)
  assert get(r,48)==count
  return r[512:]
 def view(self,cap):
  r=self.run(6,cap);return get(r,64),get(r,40)

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 q=Owner(a.image,True);cases=[]
 def record(name,fn):
  start=time.monotonic_ns()
  try:detail=fn();assert get(q.w.raw,16)==0,'live native ownership nodes remain'
  except BaseException as exc:
   (a.output/'failure.json').write_text(json.dumps({'case':name,'error':repr(exc),'completed':cases},indent=2)+'\n');raise
  cases.append({'name':name,'passed':True,'elapsed_ns':time.monotonic_ns()-start,'detail':detail});print('BG_PAYLOAD_PASS',name,flush=True)
 def basic():
  rows=[b'',b'\0',b'\xff',bytes(range(256)),b'{"x":1,"x":2}\n',b'\xff\x00not-decimal\0\xed\xa0\x80']
  for data in rows:
   cap=q.create(data);keep=q.retain(cap);assert cap!=keep
   ptr,n=q.view(cap);assert n==len(data) and C.string_at(ptr,n)==data
   q.drop(cap);assert C.string_at(ptr,n)==data and q.copy(keep,0,n)==data
   q.run(6,cap,want=1);q.run(3,cap,want=1);q.drop(keep)
  return {'empty_and_arbitrary_byte_values':len(rows),'borrow_lives_while_retained':True}
 record('empty-arbitrary-bytes-and-independent-strong-nodes',basic)
 def segmented():
  rng=random.Random(0xa479);runs=0
  for n in (0,1,2,7,8,63,64,127,128,511,512,513,4095,4096,65535,65536,65537,1048577):
   data=rng.randbytes(n);cap=q.create(data)
   for i in range(50):
    off=rng.randrange(n+1);count=rng.randrange(n-off+1);assert q.copy(cap,off,count)==data[off:off+count];runs+=1
   ptr,size=q.view(cap);assert size==n and C.string_at(ptr,n)==data;q.drop(cap)
  return {'random_exact_segments':runs,'boundary_extents':18}
 record('900-fresh-segments-and-boundary-extents',segmented)
 def large():
  n=(64<<20)+1;unit=bytes(range(256));data=(unit*((n+255)//256))[:n];cap=q.create(data);keep=q.retain(cap);q.drop(cap)
  digest=hashlib.sha256();off=0;count=0
  while off<n:
   size=min(1<<20,n-off);chunk=q.copy(keep,off,size);assert chunk==data[off:off+size];digest.update(chunk);off+=size;count+=1
  ptr,size=q.view(keep);assert size==n and hashlib.sha256(C.string_at(ptr,n)).digest()==digest.digest()==hashlib.sha256(data).digest()
  q.drop(keep)
  return {'actual_payload_bytes':n,'actual_chunks':count,'sha256':digest.hexdigest(),'no_8m_or_64m_payload_cap':True}
 record('67108865-byte-payload-complete-chunk-and-borrow-equality',large)
 def guards():
  data=b'0123456789';cap=q.create(data);owner=Owner(a.image);owner.run(6,cap,want=1);owner.run(5)
  for bad in ((1,2,3),(cap[0],cap[1]^1,cap[2]),(cap[0],cap[1],cap[2]^1)):q.run(6,bad,want=1)
  for off,count in ((11,0),(10,1),(0,11),(U64,0),(0,U64),(U64,U64)):
   out=q.run(4,cap,offset=off,count=count,on=600,want=3);assert out[512:]==b'\xa5'*88
  out=q.run(4,cap,count=10,on=521,want=7);assert out[512:]==b'\xa5'*9 and get(out,40)==10
  assert q.copy(cap,0,10)==data
  q.run(5,want=5);q.drop(cap);q.run(3,cap,want=1)
  failures=0
  for op in range(7):
   used={1:{72},2:{24,32,40},3:{24,32,40},4:{24,32,40,48,56},6:{24,32,40}}.get(op,set())
   for at in range(16,128,8):
    if at not in used:
     raw=bytearray(q.packet(op));struct.pack_into('<Q',raw,at,1);saved=q.w.raw;q.run(op,wire=bytes(raw),want=0xfffffffd);assert q.w.raw==saved;failures+=1
  for raw in (b'',q.packet(0)[:127],q.packet(0)+b'x',b'x'+q.packet(0)[1:],q.packet(7)):
   saved=q.w.raw;q.run(0,wire=raw,want=0xfffffffd);assert q.w.raw==saved;failures+=1
  q.run(0,on=511,want=0xfffffffd);q.run(0,wn=255,want=0xfffffffd)
  return {'framing_guards':failures+2,'range_guards':6,'short_copy_has_no_partial_payload_write':True}
 record('range-overflow-stale-cross-owner-and-frame-guards',guards)
 def references():
  cap=q.create(b'live-result');caps=[cap]+[q.retain(cap) for _ in range(1000)]
  assert len(set(caps))==1001
  for c in caps[:-1]:q.drop(c)
  assert q.copy(caps[-1],0,11)==b'live-result';q.drop(caps[-1])
  stale=[]
  for i in range(1000):
   cap=q.create(struct.pack('<Q',i));stale.append(cap);q.drop(cap)
   current=q.create(b'x')
   q.run(6,cap,want=1);q.drop(current)
  return {'simultaneous_individual_references':1001,'stale_after_allocator_reuse_rounds':1000}
 record('1001-live-refs-and-1000-stale-node-reuse-controls',references)
 def concurrent():
  data=bytes(range(256))*16;original=q.create(data);caps=[q.retain(original) for _ in range(16)];q.drop(original);errors=[]
  def worker(cap):
   try:
    for i in range(100):
     keep=q.retain(cap);off=(i*43)%2048;assert q.copy(keep,off,2048)==data[off:off+2048];q.drop(keep)
    q.drop(cap)
   except BaseException as e:errors.append(repr(e))
  ts=[threading.Thread(target=worker,args=(c,),daemon=True) for c in caps]
  for t in ts:t.start()
  for t in ts:t.join(20);assert not t.is_alive()
  assert not errors,errors
  return {'actual_threads':16,'retain_copy_drop_cycles':1600}
 record('16-native-futex-threads-1600-reference-cycles',concurrent)
 def fork():
  cap=q.create(b'parent')
  pid=os.fork()
  if pid==0:
   try:q.run(6,cap,want=5);os._exit(0)
   except BaseException:os._exit(71)
  _,status=os.waitpid(pid,0);assert status==0,status
  assert q.copy(cap,0,6)==b'parent';q.drop(cap)
  return {'actual_fork_refused_without_touching_parent':True}
 record('actual-fork-pid-refusal',fork)
 q.run(5);q.run(5,want=5);q.run(1,raw=b'x',want=5);q.run(0,want=5)
 cases.append({'name':'exclusive-final-destruction-and-no-reinitialization','passed':True})
 report={'schema':'hepta.hia.background-owned-payload.qualification.v1','whole_background_qualified':False,'scope':'Immutable byte ownership component only; actual malloc/free, getrandom, futex, threads and native reads. No BG/rank business facts are trusted from fixtures.','image':str(a.image),'image_bytes':a.image.stat().st_size,'image_sha256':hashlib.sha256(a.image.read_bytes()).hexdigest(),'passed':len(cases),'failed':0,'actual_native_calls':q.calls,'cases':cases}
 (a.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_PAYLOAD_QUALIFIED',len(cases),q.calls,flush=True)
if __name__=='__main__':main()
