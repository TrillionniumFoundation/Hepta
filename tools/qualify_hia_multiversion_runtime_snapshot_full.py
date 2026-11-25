from pathlib import Path
import importlib.util,sys,random,copy,json,struct,threading,time,ctypes,os,hashlib
from collections import OrderedDict,deque
from unittest.mock import patch
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');Q=T/'multiversion-runtime-snapshot-qa'
from tools import qualify_hia_multiversion_runtime_snapshot as h
Q=h.Q;T=h.T
R=h.runtime_original
D=Q/'full-v1';D.mkdir();native=h.Native(Q/'native-v4/snapshot.flat');rows=[]
def verify(label,item,offset=0):
 raw=h.packet(item.wire);expected=h.jbytes(item.expected)
 status,out,w,elapsed=native.run(raw,max(len(expected)+8,128),max(65536+16*1000,65536),offset=offset)
 if status!=len(expected)or out[:status]!=expected:
  (D/'failure.input').write_bytes(raw);(D/'failure.expected.json').write_bytes(expected);(D/'failure.actual.bin').write_bytes(out);(D/'failure.work').write_bytes(w)
  raise AssertionError((label,status,len(expected),struct.unpack('<8Q',w[:64]),out[:800],expected[:800]))
 rows.append({'case':label,'json_bytes':len(expected),'json_sha256':h.sha(expected),'elapsed_ns':elapsed})
 return raw,expected
def generation(number,leases=0,retired=False,pinitem=None,totality=None,types=None):
 types=types or ('u64','bool')
 abi=tuple(R.ScalarABI('f'+str(i),(typ,),typ)for i,typ in enumerate(types))
 info=R.GenerationInfo(number,'a'*64,'b'*64,'c'*64,4096,abi,1,2,number==0,totality_proofs=2,loaded_mapping=h.jbytes({'mapped':True,'pid':os.getpid(),'proof':{'exact':True}}))
 pinitem=pinitem or h.pin(path=b'/private/g'+h.decimal(number),bound=True,held=True,attempted=True)
 proofs=totality if totality is not None else [{'status':'proved','generation':number,'tags':['\ud800','🙂']}]
 gen=R._Generation(info,47,object(),{},Path('/private/a'),(13,1),pinitem.oracle,leases=leases,retired=retired,totality=tuple(h.jbytes(x)for x in proofs))
 expected={**info.as_dict(),'active_leases':leases,'retired':retired,'artifact_identity_pin':pinitem.expected,'totality_evidence':proofs}
 wire=h.frame(8,[h.jbytes(info.as_dict()),h.decimal(number),h.decimal(leases),pinitem.wire,h.jsonlist(proofs)],int(retired))
 return h.Item(wire,expected,gen)
def snapshot(gens=(),tasks=(),closed=False,epoch=0,current=None,attempts=0,events=(),cleanup_events=(),pinitem=None,obs=None,dircleanup=None):
 pi=pinitem or h.pin(path=b'/private',directory=True,bound=True,held=not closed,attempted=True,released=closed,close_attempted=closed,close_status=3 if closed else 1,close_finished=closed)
 obs=obs or h.observation(status=1 if closed else 2,inode=None if closed else(13,123456))
 dc=dircleanup or h.directory()
 runtime=R.ScalarMultiversionRuntime.__new__(R.ScalarMultiversionRuntime)
 runtime._lock=threading.RLock();runtime._profile=R.PROFILE;runtime._closed=closed;runtime._epoch=epoch;runtime._current=current
 runtime._states=OrderedDict((x.oracle.info.generation,x.oracle)for x in gens)
 runtime._events=deque(events,maxlen=128);runtime._cleanup_pending=OrderedDict((x.oracle.generation,x.oracle)for x in tasks)
 runtime._cleanup_attempts=attempts;runtime._cleanup_events=deque(cleanup_events,maxlen=128);runtime._directory_cleanup=dc.expected
 runtime._directory=Path('/private');runtime._directory_inode=(13,123456);runtime._directory_pin=pi.oracle
 with patch.object(R,'observe_directory',lambda *args,**kw:copy.deepcopy(obs.expected)):
  expected=runtime.snapshot();clean_expected=runtime._cleanup_snapshot()
 cleanup=h.frame(2,[h.decimal(attempts),h.array(x.wire for x in tasks),h.jsonlist(list(runtime._cleanup_events)),dc.wire,obs.wire,pi.wire],int(closed)|(2 if not gens else 0))
 wire=h.frame(1,[h.text(R.PROFILE),h.decimal(epoch),b''if current is None else h.decimal(current),h.array(x.wire for x in gens),h.jsonlist(list(runtime._events)),cleanup],int(closed))
 return h.Item(wire,expected),h.Item(cleanup,clean_expected)

def main():
 rng=random.Random(0x521417)
 verify('empty-open',snapshot()[0]);verify('empty-closed',snapshot(closed=True)[0])
 # Three numeric orders, one deliberately nonlexical insertion order.
 nums=[10,2,100,1,0,99,11];gens=[generation(n,n*10,n%2==0)for n in nums]
 pending=[h.task(n,pinitem=h.pin(path=b'/private/p'+h.decimal(n),bound=True,held=True,attempted=True),disk_status=2,disk_attempts=0)for n in [100,2,11,1]]
 item,cl=snapshot(gens,pending,epoch=1<<130,current=10,attempts=10**80,events=[{'kind':'x','sequence':i}for i in range(128)],cleanup_events=[{'status':'error','sequence':i}for i in range(128)])
 raw,expected=verify('full-sorted-and-insertion',item,7);verify('cleanup-insertion',cl)
 assert [x['generation']for x in cl.expected['pending']]==[1,2,11,100]
 assert [x['generation']for x in cl.expected['pending_identity_releases']]==[100,2,11,1]
 for i in range(200):
  nums=rng.sample(range(1000),rng.randrange(0,12));gens=[generation(n,rng.getrandbits(rng.choice([0,16,64,200])),bool(rng.getrandbits(1)))for n in nums]
  pending=[]
  for n in rng.sample(range(1000,2000),rng.randrange(0,10)):
   hold=bool(rng.getrandbits(1));pi=h.pin(path=b'/private/p'+str(n).encode(),directory=False,bound=True,held=hold,attempted=True,released=not hold,close_attempted=not hold,close_status=1 if hold else 3,close_finished=not hold)
   pending.append(h.task(n,pinitem=pi,library_status=rng.randrange(4),fd_status=rng.randrange(4),disk_status=rng.randrange(7),disk_attempts=rng.randrange(3)))
  item,cl=snapshot(gens,pending,closed=bool(rng.getrandbits(1)),epoch=rng.getrandbits(256),current=nums[0]if nums else None,attempts=rng.getrandbits(180),events=[{'i':j,'text':'Ω\udc00'}for j in range(rng.randrange(9))])
  verify('random-full-'+str(i),item,i%8);verify('random-cleanup-'+str(i),cl)
 # Unbounded source integers remain decimal, including more than CPython's
 # default string conversion limit (the original method returns Python ints).
 for digits in [1,20,4301,100001]:
  number=int('7'*digits);gs=[generation(number,number+1,False,totality=[])]
  item,_=snapshot(gs,epoch=number+2,current=number,attempts=number+3)
  verify('big-decimal-'+str(digits),item)
 # Full histories and no new 128-generation/pending cap.
 gs=[generation(n,n,False,totality=[])for n in reversed(range(257))]
 verify('257-generations',snapshot(gs,epoch=258,current=256)[0])
 tasks=[h.task(n,disk_status=2,disk_attempts=0)for n in reversed(range(137))]
 verify('137-pending',snapshot(tasks=tasks,closed=True)[0])
 # No aggregate JSON/source 8 MiB cap.
 huge='abcde'*1900000
 verify('9MiB-events',snapshot(events=[{'actual_blob':huge}])[0])
 # Fenced native diagnostics: retained header fields are diagnostic only.
 fe=h.error(h.native_original.NativeRetirementFailure('native retirement state/token refused: 4'))
 for stage in [0,1,2]:
  pi=h.pin(native=True,bound=True,held=True,attempted=True,fenced=fe,quarantine={'returned':51,'close_retry_permitted':False},slot=(stage,-9 if stage==2 else None))
  verify('fenced-pin-'+str(stage),pi)
 # Required length / no output writes on all undersized outputs.
 samples=[snapshot()[0],item,cl,h.directory(),h.pin(),h.task(),h.observation(),h.Item(*h.oserror(13,b'/denied'))]
 for i,it in enumerate(samples):
  raw=h.packet(it.wire);ex=h.jbytes(it.expected)
  for cap in sorted({0,1,7,63,64,len(ex)-1}):
   if cap>=len(ex):continue
   status,out,w,elapsed=native.run(raw,cap)
   assert status==h.U-1 and struct.unpack_from('<Q',w,0)[0]==len(ex),(i,cap,status)
   rows.append({'case':'nospace-'+str(i)+'-'+str(cap),'expected_length':len(ex)})
  for cap in [0,1,15,16,65535]:
   status,out,w,_=native.run(raw,len(ex),cap)
   assert status==h.U-2,(i,cap,status)
   if cap>=16:assert struct.unpack_from('<Q',w,8)[0]==65536
   rows.append({'case':'needwork-'+str(i)+'-'+str(cap)})
 # Sorting workspace requires exactly two u64 index arrays.
 x=snapshot([generation(n,totality=[])for n in [10,2,7]])[0];raw=h.packet(x.wire);ex=h.jbytes(x.expected)
 status,out,w,_=native.run(raw,len(ex),65536+16*3-1)
 assert status==h.U-2 and struct.unpack_from('<Q',w,8)[0]==65536+48
 status,out,w,_=native.run(raw,len(ex),65536+48);assert status==len(ex)and out==ex
 rows.append({'case':'exact-sort-workspace'})
 # Malformed frames and ordinal duplication: atomic rejection.
 base=h.packet(snapshot()[0].wire);bad=[]
 for n in list(range(0,100))+[len(base)-1]:bad.append(('truncated-'+str(n),base[:n]))
 for at in [0,8,16,24,32,40,48,56,64,72,80,88,96,104]:
  z=bytearray(base);struct.pack_into('<Q',z,at,h.U);bad.append(('u64-'+str(at),bytes(z)))
 bad.extend([('trailing',base+b'x'),('duplicate-generation',h.packet(snapshot([generation(1),generation(1)])[0].wire))])
 # Incompatible cleanup closed/state-empty flags in otherwise valid root.
 z=bytearray(base);root=64;coff=struct.unpack_from('<Q',z,root+32+5*16)[0]+root;struct.pack_into('<Q',z,coff+8,3);bad.append(('capture-mismatch',bytes(z)))
 for label,data in bad:
  status,out,w,_=native.run(data,4096);assert status==h.U,(label,status);rows.append({'case':label})
 (D/'report.json').write_text(json.dumps({'status':'PASS','cases':len(rows),'native_sha256':h.sha(native.raw),'original_runtime_source_sha256':h.sha((S/'hepta/hia_multiversion.py').read_bytes()),'original_retirement_source_sha256':h.sha((S/'hepta/hia_native_retirement.py').read_bytes()),'rows':rows},indent=2)+'\n')
 print('SNAPSHOT_FULL_PASS',len(rows),flush=True)
S=h.S
if __name__=='__main__':main()
