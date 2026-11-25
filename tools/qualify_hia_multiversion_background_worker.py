"""Actual pthread worker kernel. Business callbacks are external fixtures only."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,threading,time
from tools.qualify_hia_multiversion_background_queue import Queue,Owner,get,U64
CALL=C.CFUNCTYPE(C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64,C.c_void_p,C.c_uint64)
class Worker:
 def __init__(self,image,queue,handler):
  self.q=queue;self.lib=C.CDLL(str(image));self.f=self.lib.hia_mv_background_worker;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32;self.w=C.create_string_buffer(512);self.errors=[];self.calls=0;self.lock=threading.Lock()
  @CALL
  def callback(s,n,o,on,ctx,cn):
   try:
    assert n==128 and on==128 and ctx==C.addressof(queue.w) and cn==len(queue.w)
    raw=C.string_at(s,n);assert raw[:8]==b'HIABGWQ1';status=handler(self,raw)
    out=bytearray(128);out[:8]=b'HIABGWR1';struct.pack_into('<Q',out,8,status);C.memmove(o,bytes(out),128)
    return 0x1234567800000000
   except BaseException as e:self.errors.append(repr(e));return 65
  self.callback=callback
  self.run(0,{16:C.cast(queue.f,C.c_void_p).value,24:C.addressof(queue.w),32:len(queue.w),40:C.cast(callback,C.c_void_p).value,48:C.addressof(queue.w),56:len(queue.w)})
 @staticmethod
 def packet(op,fields=None):
  raw=bytearray(128);raw[:8]=b'HIABGW01';struct.pack_into('<Q',raw,8,op)
  for at,v in (fields or {}).items():struct.pack_into('<Q',raw,at,v)
  return bytes(raw)
 def run(self,op,fields=None,want=0,wire=None,on=8192,wn=512):
  raw=self.packet(op,fields) if wire is None else wire;s=C.create_string_buffer(raw);o=C.create_string_buffer(max(on,8192));C.memset(o,0xa5,len(o));rc=self.f(s,len(raw),o,on,self.w,wn)
  with self.lock:self.calls+=1
  assert s.raw==raw+b'\0'
  if want>=0xfffffff0:assert rc==want,(op,rc,want);return o.raw
  assert rc==0 and o.raw[:8]==b'HIABGWO1',(op,rc,o.raw[:128].hex())
  assert get(o.raw,8)==want,(op,get(o.raw,8),want,o.raw[:128].hex())
  return o.raw
 def settle(self,raw):
  a,b,c=struct.unpack_from('<3Q',raw,16);return self.q.run(3,{16:get(raw,56),24:a,32:b,40:c})
 def try_admit(self,job):
  a,b,c=job['cap'];wire=self.q.packet(1,{24:a,32:b,40:c,48:C.addressof(job['future'].work),56:512});s=C.create_string_buffer(wire);o=C.create_string_buffer(4096);rc=self.q.f(s,128,o,4096,self.q.w,4096)
  assert rc==0 and o.raw[:8]==b'HIABGQR1' and get(o.raw,8) in (0,2)
  return get(o.raw,8)==0

def main():
 p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--queue',type=Path,required=True);p.add_argument('--values',type=Path,required=True);p.add_argument('--future',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
 values=Owner(a.values);future=C.CDLL(str(a.future));cases=[];workers=[]
 def qnew(cap=8):return Queue(a.queue,values,future,cap)
 def new(q,handler):
  w=Worker(a.image,q,handler);workers.append(w);return w
 def record(name,fn):
  t=time.monotonic_ns()
  try:detail=fn();assert get(values.w.raw,16)==0,'native refs remain'
  except BaseException as e:
   (a.output/'failure.json').write_text(json.dumps({'case':name,'error':repr(e),'completed':cases},indent=2)+'\n');raise
  cases.append({'name':name,'passed':True,'elapsed_ns':time.monotonic_ns()-t,'detail':detail});print('BG_WORKER_PASS',name,flush=True)
 def empty():
  tids=[]
  for i in range(40):
   q=qnew();q.run(4);w=new(q,lambda w,r:0);w.run(1);r=w.run(2);assert get(r,24)==4 and get(r,32)>1 and get(r,32)!=threading.get_native_id() and get(r,40)==0
   assert not w.errors and get(q.w.raw,144)==1
   tids.append(get(r,32));w.run(2);w.run(5);q.destroy()
  return {'actual_pthread_create_join_pairs':40,'unique_worker_tids':len(set(tids))}
 record('40-native-pthread-create-empty-close-join',empty)
 def jobs():
  q=qnew();all_jobs={};completed=[];selfjoins=[];threadids=[]
  def handler(w,r):
   assert get(r,8)==1
   cap=struct.unpack_from('<3Q',r,16);j=all_jobs[cap];threadids.append(threading.get_native_id())
   assert get(r,40)==C.addressof(j['future'].work) and get(r,48)==512
   if j['value']%31==0:selfjoins.append(get(w.run(2),16))
   owned=w.settle(r);j['future'].complete(j['value']);q.release_refs(owned);completed.append(j['value']);return 0
  w=new(q,handler);w.run(1);w.run(1,want=4)
  js=[]
  for i in range(400):
   j=q.job(i);js.append(j);all_jobs[j['cap']]=j
   until=time.monotonic()+10
   while not w.try_admit(j):assert time.monotonic()<until;time.sleep(.0001)
  q.run(4);r=w.run(2);assert get(r,24)==4 and get(r,40)==0 and not w.errors,w.errors
  assert completed==list(range(400)) and set(threadids)=={get(r,32)} and selfjoins==[1]*13
  for j in js:assert j['future'].result()==j['value'];j['future'].destroy()
  w.run(5);q.destroy()
  return {'jobs':400,'actual_native_worker_tid':get(r,32),'self_join_avoided':len(selfjoins),'provider_u32_upper_bits_ignored':True}
 record('400-jobs-native-thread-fifo-future-and-self-join',jobs)
 def parallel_join():
  q=qnew(1);entered=threading.Event();proceed=threading.Event();j=q.job(9);results=[];errors=[]
  def handler(w,r):
   entered.set();assert proceed.wait(8);owned=w.settle(r);j['future'].complete(9);q.release_refs(owned);return 0
  w=new(q,handler);q.admit(j);w.run(1);assert entered.wait(5)
  q.run(4);w.run(5,want=4)
  def join():
   try:results.append(w.run(2))
   except BaseException as e:errors.append(repr(e))
  threads=[threading.Thread(target=join,daemon=True) for _ in range(12)]
  for t in threads:t.start()
  time.sleep(.03);assert not results
  proceed.set()
  for t in threads:t.join(10);assert not t.is_alive()
  assert not errors and len(results)==12 and all(get(x,24)==4 and get(x,40)==0 for x in results),(errors,len(results))
  assert j['future'].result()==9;j['future'].destroy();w.run(5);q.destroy()
  return {'simultaneous_joiners':12,'all_same_completed_worker':True}
 record('12-concurrent-joiners-wait-for-one-actual-thread',parallel_join)
 def cancellation():
  q=qnew(8);entered=threading.Event();proceed=threading.Event();jobs=[q.job(i) for i in range(8)];by={j['cap']:j for j in jobs};seen=[]
  def handler(w,r):
   j=by[struct.unpack_from('<3Q',r,16)]
   if j['value']==0:entered.set();assert proceed.wait(8)
   assert j['future'].token_state()==1;j['future'].settle();owned=w.settle(r);q.release_refs(owned);seen.append(j['value']);return 0
  w=new(q,handler)
  for j in jobs:q.admit(j)
  w.run(1);assert entered.wait(5);refs=q.run(4,{16:1});assert len(q.refs(refs))==8
  for j in jobs:j['future'].cancel()
  q.release_refs(refs);proceed.set();r=w.run(2)
  assert seen==list(range(8)) and get(r,40)==0 and not w.errors,w.errors
  for j in jobs:assert j['future'].state()=='cancelled';j['future'].destroy()
  w.run(5);q.destroy()
  return {'cancelled_jobs_observed_by_worker':8,'queue_slots_drained_only_by_worker':True}
 record('shutdown-cancelled-jobs-settle-on-native-worker',cancellation)
 def failure():
  q=qnew(8);jobs=[q.job(i) for i in range(8)];failure_phases=[]
  def handler(w,r):
   if get(r,8)==1:return 99
   assert get(r,8)==2;failure_phases.append(get(r,64));drained=q.run(6)
   assert [x['cap'] for x in q.refs(drained)]==[j['cap'] for j in jobs]
   for j in jobs:j['future'].cancel()
   q.release_refs(drained);return 1
  w=new(q,handler)
  for j in jobs:q.admit(j)
  w.run(1);r=w.run(2);assert get(r,24)==4 and get(r,40)==65 and failure_phases==[503] and not w.errors,w.errors
  for j in jobs:assert j['future'].state()=='cancelled';j['future'].destroy()
  w.run(5);q.destroy()
  return {'actual_failure_handler_called_once':True,'native_phase':503,'all_pending_owned_jobs_released':8}
 record('invalid-provider-response-routes-one-native-failure-continuation',failure)
 def controls():
  q=qnew();w=new(q,lambda w,r:0);w.run(4,want=4);w.run(2,want=4)
  for op in (0,1,2,3,4,5):
   used={16,24,32,40,48,56} if op==0 else set()
   for at in range(16,128,8):
    if at not in used:
     before=w.w.raw;w.run(op,{at:1},want=0xfffffffd);assert w.w.raw==before
  for raw in (b'',w.packet(3)[:127],w.packet(3)+b'x',b'x'+w.packet(3)[1:],w.packet(6)):
   before=w.w.raw;w.run(3,wire=raw,want=0xfffffffd);assert w.w.raw==before
  w.run(3,on=8191,want=0xfffffffd);w.run(3,wn=511,want=0xfffffffd)
  w.run(1);pid=os.fork()
  if pid==0:
   try:w.run(3,want=65);os._exit(0)
   except BaseException:os._exit(71)
  _,status=os.waitpid(pid,0);assert status==0,status
  q.run(4);w.run(2);w.run(5);w.run(3,want=65);q.destroy()
  return {'private_frame_and_lifecycle_controls':True,'fork_refused_without_joining_parent_thread':True}
 record('private-frames-double-start-fork-and-context-lifecycle',controls)
 values.run(9)
 report={'schema':'hepta.hia.background-native-worker.qualification.v1','whole_background_qualified':False,'scope':'Actual pthread start/join, worker thread, queue/future/ownership plumbing. The business handler in these component gates is an external fixture, not the complete BG semantic owner.','image':str(a.image),'image_bytes':a.image.stat().st_size,'image_sha256':hashlib.sha256(a.image.read_bytes()).hexdigest(),'passed':len(cases),'failed':0,'cases':cases,'actual_public_worker_calls':sum(w.calls for w in workers),'all_kernel_workers_reaped':True}
 (a.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_WORKER_QUALIFIED',len(cases),flush=True)
if __name__=='__main__':main()
