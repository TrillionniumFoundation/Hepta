"""Native accounting ownership: independent bigint/deque reference and real threads."""
from pathlib import Path
import argparse,collections,ctypes as C,hashlib,json,os,random,struct,threading,time
from tools.qualify_hia_multiversion_background_jobs import Jobs,get,addr
from tools.qualify_hia_multiversion_values import Owner as Values
STATUSES=('published','abstained','stale','rejected','cancelled','interrupted')
class Ledger:
 def __init__(self,image,jobs,values,poison=False,auto_init=True):
  self.image=Path(image);self.lib=C.CDLL(str(image));self.f=self.lib.hia_mv_background_ledger;self.f.argtypes=[C.c_void_p,C.c_uint64]*3;self.f.restype=C.c_uint32
  self.jobs=jobs;self.payload=jobs.payload;self.values=values;self.w=C.create_string_buffer(4096);self.calls=0;self.lock=threading.Lock()
  if poison:C.memset(self.w,0xa5,len(self.w));C.memset(self.w,0,8)
  if auto_init:self.initialize()
 @staticmethod
 def packet(op,job=(0,0,0),receipt=(0,0,0),cost=(0,0,0),status=0):
  b=bytearray(128);b[:8]=b'HIABLG01';struct.pack_into('<Q',b,8,op)
  struct.pack_into('<3Q',b,24,*job);struct.pack_into('<3Q',b,48,*receipt);struct.pack_into('<3Q',b,72,*cost);struct.pack_into('<Q',b,96,status)
  return bytes(b)
 def initialize(self,want=0):
  wire=bytearray(self.packet(0));struct.pack_into('<9Q',wire,24,addr(self.values.f),C.addressof(self.values.w),256,addr(self.payload.f),C.addressof(self.payload.w),256,addr(self.jobs.f),C.addressof(self.jobs.w),256)
  return self.run(0,wire=bytes(wire),want=want)
 def run(self,op,job=(0,0,0),receipt=(0,0,0),cost=(0,0,0),status=0,want=0,wire=None,on=8192,wn=4096):
  wire=self.packet(op,job,receipt,cost,status) if wire is None else wire
  src=C.create_string_buffer(wire);out=C.create_string_buffer(max(on,8192));C.memset(out,0xa5,len(out));rc=self.f(src,len(wire),out,on,self.w,wn)
  with self.lock:self.calls+=1
  assert src.raw==wire+b'\0'
  if want>=0xfffffff0:assert rc==want,(op,rc,want);return out.raw
  assert rc==0 and out.raw[:8]==b'HIABLGR1',(op,rc,out.raw[:128].hex())
  assert get(out.raw,8)==want,(op,get(out.raw,8),want,out.raw[:128].hex())
  return out.raw
 def snapshot(self,retain=False):
  raw=self.run(2);n=get(raw,32);count=get(raw,16);assert n==8+count and count<=64
  entries=[];counters=[];receipts=[]
  try:
   for i in range(n):
    at=4096+i*48;kind=get(raw,at);index=get(raw,at+8);cap=tuple(get(raw,at+x) for x in (16,24,32));size=get(raw,at+40)
    entries.append((kind,cap,size))
    if i<8:
     assert kind==1 and index==i;counters.append(int(self.values.copy(cap,size)))
    else:
     assert kind==2 and index==i-8;receipts.append(self.payload.copy(cap,0,size))
   assert sum(counters[2:])==counters[0]
   assert get(raw,24)==sum(1<<i for i,c in enumerate(counters[2:]) if c)
   answer={'settled':counters[0],'observed':counters[1],'outcomes':dict(zip(STATUSES,counters[2:])),'recent':receipts}
   return (answer,entries) if retain else answer
  finally:
   if not retain:self.release_entries(entries)
 def release_entries(self,entries):
  for kind,cap,size in entries:(self.values if kind==1 else self.payload).drop(cap)
 def record(self,job,raw,n,status):
  receipt=self.payload.create(raw);cost=self.values.create(str(n).encode())
  try:
   out=self.run(1,job,receipt,cost,status);assert get(out,40)==1 and get(out,48)==0
  finally:self.values.drop(cost)
  return receipt
 def destroy(self):self.run(3)
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--jobs',type=Path,required=True);p.add_argument('--future',type=Path,required=True);p.add_argument('--payload',type=Path,required=True);p.add_argument('--values',type=Path,required=True);a=p.parse_args();D=a.directory
 q=Jobs(a.jobs,a.future,a.payload);v=Values(a.values);l=Ledger(D/'ledger-component.so',q,v,True);cases=[]
 def record(name,fn):
  start=time.monotonic_ns()
  try:detail=fn()
  except BaseException as e:
   (D/'failure.json').write_text(json.dumps({'case':name,'error':repr(e),'completed':cases},indent=2)+'\n');raise
  cases.append({'name':name,'passed':True,'detail':detail,'elapsed_ns':time.monotonic_ns()-start});print('BG_LEDGER_PASS',name,flush=True)
 def empty_and_once():
  assert l.snapshot()=={'settled':0,'observed':0,'outcomes':dict.fromkeys(STATUSES,0),'recent':[]}
  job=q.create(b'job');assert get(l.run(4,job),48)==0
  source=bytearray(b'{"cost":7,"status":"published"}');receipt=l.record(job,bytes(source),7,0);source[:]=b'x'*len(source)
  assert get(l.run(4,job),48)==1
  other=q.payload.create(b'not consumed');cost=v.create(b'999999999999999999999999')
  r=l.run(1,job,other,cost,5);assert get(r,40)==0 and get(r,48)==1
  assert q.payload.copy(other,0,12)==b'not consumed';q.payload.drop(other);v.drop(cost)
  snapshot=l.snapshot();assert snapshot['settled']==1 and snapshot['observed']==7 and snapshot['outcomes']['published']==1
  assert snapshot['recent']==[b'{"cost":7,"status":"published"}']
  q.drop(job);assert q.payload.view(receipt)[1]==len(b'{"cost":7,"status":"published"}')
  return {'accounted_once_marker_from_actual_job':True,'receipt_input_detached':True,'duplicate_does_not_consume_new_receipt':True}
 record('initial-state-and-once-only-job-accounting',empty_and_once)
 expected_count=1;expected_sum=7;expected_outcomes=collections.Counter({'published':1});expected_recent=collections.deque([b'{"cost":7,"status":"published"}'],maxlen=64)
 def wide_ring():
  nonlocal expected_count,expected_sum
  rng=random.Random(0x9847)
  for i in range(300):
   n=rng.randrange(10**rng.randrange(1,300));status=i%6;raw=json.dumps({'job':i+2,'observed':n,'status':STATUSES[status]},sort_keys=True,separators=(',',':')).encode()
   job=q.create(struct.pack('<Q',i));l.record(job,raw,n,status);q.drop(job)
   expected_count+=1;expected_sum+=n;expected_outcomes[STATUSES[status]]+=1;expected_recent.append(raw)
   if i%31==0:
    s=l.snapshot();assert s['settled']==expected_count and s['observed']==expected_sum and s['recent']==list(expected_recent)
  s=l.snapshot();assert s['settled']==expected_count and s['observed']==expected_sum and s['outcomes']==dict(expected_outcomes) and s['recent']==list(expected_recent)
  return {'fresh_bigint_inputs':300,'largest_input_digits':299,'recent_window':64,'full_sums_and_counts_match_independent_integers':True}
 record('unbounded-sums-six-outcomes-and-64-receipt-window',wide_ring)
 def cancellation_observation():
  job=q.create(b'cancel after accounting')
  raw=b'{"execution_status":"stale","future_state_at_accounting":"pending"}'
  l.record(job,raw,0,2)
  assert q.future(job,1)[1][2]==1
  assert l.snapshot()['recent'][-1]==raw
  q.drop(job)
  return {'later_actual_native_future_cancel_does_not_rewrite_receipt':True}
 record('later-native-future-cancellation-preserves-accounting-observation',cancellation_observation)
 def retained():
  snapshot,refs=l.snapshot(True);held=[(k,c,n) for k,c,n in refs if k==2]
  for i in range(65):
   j=q.create(b'next');l.record(j,str(i).encode(),1,1);q.drop(j)
  old=[q.payload.copy(c,0,n) for k,c,n in held]
  assert old==snapshot['recent']
  l.release_entries(refs)
  return {'retained_old_receipts_survive_ring_eviction':64,'new_settlements':65}
 record('snapshot-reference-lifetime-across-all-ring-evictions',retained)
 def concurrency():
  jobs=[q.create(struct.pack('<Q',i)) for i in range(400)];before=l.snapshot();errors=[];observed=[];start=threading.Barrier(9);finish=threading.Event()
  def settle(thread):
   try:
    start.wait()
    for i in range(thread*50,(thread+1)*50):
     l.record(jobs[i],b'concurrent-'+str(i).encode(),1,i%6)
     r=l.run(1,jobs[i]);assert get(r,48)==1 and get(r,40)==0
     q.drop(jobs[i])
   except BaseException as e:errors.append(repr(e))
  ts=[threading.Thread(target=settle,args=(i,)) for i in range(8)]
  def snapshots():
   try:
    start.wait()
    while not finish.is_set():
     s=l.snapshot();delta=s['settled']-before['settled'];assert s['observed']-before['observed']==delta
     assert len(s['recent'])==min(s['settled'],64)
     observed.append(s['settled'])
   except BaseException as e:errors.append(repr(e))
  st=threading.Thread(target=snapshots);st.start()
  for t in ts:t.start()
  for t in ts:t.join(30);assert not t.is_alive()
  finish.set();st.join(30);assert not st.is_alive() and not errors,errors
  after=l.snapshot();assert after['settled']==before['settled']+400 and after['observed']==before['observed']+400
  assert len(after['recent'])==64 and len(set(after['recent']))==64
  for i,name in enumerate(STATUSES):assert after['outcomes'][name]==before['outcomes'][name]+sum(j%6==i for j in range(400))
  return {'threads':8,'accepted_once_each':400,'duplicate_settlements':400,'actual_concurrent_snapshots':len(observed),'all_snapshot_counter_sums_consistent':True}
 record('concurrent-once-only-settlement-and-atomic-detached-snapshots',concurrency)
 def guards():
  before=l.w.raw
  for raw in (b'',l.packet(2)[:127],l.packet(2)+b'x',b'x'+l.packet(2)[1:],l.packet(5)):
   l.run(2,wire=raw,want=0xfffffffd);assert l.w.raw==before
  checks=5
  for op in range(5):
   used={0:set(range(24,96,8)),1:set(range(24,104,8)),4:{24,32,40}}.get(op,set())
   for at in range(16,128,8):
    if at not in used:
     raw=bytearray(l.packet(op));struct.pack_into('<Q',raw,at,1);l.run(op,wire=bytes(raw),want=0xfffffffd);assert l.w.raw==before;checks+=1
  l.run(1,status=6,want=0xfffffffd);l.run(2,on=8191,want=0xfffffffd);l.run(2,wn=4095,want=0xfffffffd)
  l.run(4,(1,2,3),want=1)
  job=q.create(b'invalid receipt');cost=v.create(b'7');l.run(1,job,(1,2,3),cost,0,want=1);assert get(l.run(4,job),48)==0
  receipt=q.payload.create(b'retry');l.run(1,job,receipt,(1,2,3),0,want=1);assert get(l.run(4,job),48)==0
  assert q.payload.copy(receipt,0,5)==b'retry'
  l.run(1,job,receipt,cost,0);q.drop(job);v.drop(cost)
  # The same owned node cannot be installed twice for two jobs.
  job=q.create(b'duplicate-owned-receipt');cost=v.create(b'1');l.run(1,job,receipt,cost,0,want=3);assert get(l.run(4,job),48)==0;q.drop(job);v.drop(cost)
  return {'frame_controls':checks+3,'invalid_job_payload_value_controls':4,'failed_settlement_keeps_receipt_and_job_marker':True}
 record('private-frame-foreign-ref-and-ownership-transfer-guards',guards)
 def fork_and_destroy():
  pid=os.fork()
  if pid==0:
   try:l.run(2,want=5);os._exit(0)
   except BaseException:os._exit(71)
  _,status=os.waitpid(pid,0);assert status==0
  saved,refs=l.snapshot(True);l.destroy();l.run(2,want=5);l.run(3,want=5)
  counters=[int(v.copy(c,n)) for k,c,n in refs if k==1];recent=[q.payload.copy(c,0,n) for k,c,n in refs if k==2]
  assert counters[0]==saved['settled'] and counters[1]==saved['observed'] and recent==saved['recent']
  l.release_entries(refs);assert get(v.w.raw,16)==0 and get(q.payload.w.raw,16)==0 and get(q.w.raw,16)==0
  q.destroy();v.run(9)
  return {'fork_refused':True,'retained_snapshot_survives_ledger_destruction':True,'all_component_reference_registries_empty':True}
 record('pid-and-independent-snapshot-lifetime-at-final-destruction',fork_and_destroy)
 report={'schema':'hepta.hia.background-native-ledger.v1','whole_background_qualified':False,'scope':'Atomic native storage/summation of accounted-job receipt bytes and detached owned snapshots. Receipt formatting, real clocks and full optimizer business are separate.','image_sha256':hashlib.sha256((D/'ledger-component.so').read_bytes()).hexdigest(),'passed':len(cases),'failed':0,'ledger_calls':l.calls,'jobs_calls':q.calls,'external_values_calls':v.calls,'external_payload_calls':q.payload.calls,'cases':cases}
 (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_LEDGER_QUALIFIED',len(cases),l.calls,flush=True)
if __name__=='__main__':main()
