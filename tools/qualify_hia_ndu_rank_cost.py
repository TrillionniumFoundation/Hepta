from pathlib import Path
from hashlib import sha256
import ctypes as C,fcntl,json,os,random,resource,struct,sys,time
import argparse
parser=argparse.ArgumentParser();parser.add_argument('--flat',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
P=Path(__file__).resolve().parents[1];D=args.output;D.mkdir(parents=True,exist_ok=False);sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from hepta.hia_ndu_optimizer import ns_to_ms_q32,OptimizationRejected
raw=args.flat.read_bytes();pin=sha256(raw).hexdigest();assert pin=='f6c4aa1ac0f0de5e0971456d615407d8d67954b6be58fc609e5cdbe7f441d29b'
fd=os.memfd_create('native-ndu-rank-exact-cost',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value)
entry=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(address)
rows=[];counts={};report={'passed':False,'flat_sha256':pin,'whole_native_rank_closed':False,'scope':'Actual sealed HIA cost role; original ns_to_ms_q32 and independent unbounded Python arithmetic for bounded public operands, full 128-bit products and signed margins. No evaluator/proof/publication authority.','rows':rows,'counts':counts}
MAX=(1<<63)-1;U=(1<<64)-1
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def wire(mode,v):return struct.pack('<8s15Q',b'HIANRC01',mode,*v,*([0]*5))
def expected(mode,v):
 out=bytearray(256);struct.pack_into('<8sQ',out,0,b'HIANRR01',mode)
 def put(at,value):struct.pack_into('<Q',out,at,value)
 def pair(at,value):put(at,value&U);put(at+8,value>>64)
 def signed(at,value):put(at,int(value<0));pair(at+8,abs(value))
 if mode==0:
  n=v[0]+(v[1]<<64)
  try:q=ns_to_ms_q32(n)
  except OptimizationRejected as exc:
   put(16,1 if 'nanoseconds must' in str(exc) else 2)
  else:put(40,q)
 else:
  base,unc,cand,cunc,calls,supplied,elapsed,cap,requested=v
  lower=max(0,base-unc);spent=supplied+elapsed;bt=lower*calls;ct=(cand+cunc)*calls;budget=cap-spent;margin=bt-ct-spent
  pair(48,spent);pair(64,bt);pair(80,ct);signed(96,budget);signed(120,margin);put(144,lower)
  if mode==1:
   reason=1 if budget<=0 else 2 if margin<=0 else 3 if budget<1000000 else 4 if margin<=1000000 else 0
  elif mode==2:
   reason=5 if budget<0 else 6 if margin<=0 else 7 if budget<1000000 else 8 if margin<=1000000 else 0
  else:reason=5 if spent>cap else 6 if margin<=0 else 0
  put(24,reason)
  if mode!=3 and reason==0:put(32,min(requested,budget//1000000,(margin-1)//1000000))
 return bytes(out)
def run(label,packet,wanted,code=0,capacity=256,work_capacity=256,group='cost'):
 ib=C.create_string_buffer(packet);ob=C.create_string_buffer(288);wb=C.create_string_buffer(288)
 C.memset(ob,0xdb,288);C.memset(wb,0xa5,288)
 start=time.monotonic_ns();actual=entry(ib,len(packet),C.addressof(ob)+16,capacity,C.addressof(wb)+16,work_capacity);elapsed=time.monotonic_ns()-start
 assert actual==code,(label,actual,code)
 assert ib.raw[:len(packet)]==packet
 assert ob.raw[:16]+ob.raw[-16:]==b'\xdb'*32 and wb.raw[:16]+wb.raw[-16:]==b'\xa5'*32
 if code==0:assert ob.raw[16:272]==wanted,(label,struct.unpack('<32Q',ob.raw[16:272]),struct.unpack('<32Q',wanted))
 else:assert ob.raw==b'\xdb'*288 and wb.raw==b'\xa5'*288,(label,'non-atomic invalid-frame/short-output')
 counts[group]=counts.get(group,0)+1;rows.append({'case':label,'group':group,'return':actual,'input_sha256':sha256(packet).hexdigest(),'output_sha256':sha256(wanted).hexdigest() if wanted else None,'elapsed_ns':elapsed,'passed':True})
 if len(rows)%1000==0:save();print('NDU_COST_CASES',len(rows),flush=True)
def check(label,mode,v,group):run(label,wire(mode,v),expected(mode,v),group=group)
rng=random.Random(2026112502)
values={0,1,2,999999,1000000,1000001,MAX,MAX-1,MAX+1,U,U+1,(1<<128)-1}
for k in range(-5,6):values.add(2147483648000000+k)
for bits in (31,32,52,53,63,64,65,95,96,127):
 for delta in (-1,0,1):values.add((1<<bits)+delta)
for i in range(1200):values.add(rng.getrandbits(rng.choice((20,40,51,52,63,64,96,128))))
for i,n in enumerate(sorted(values)):check('q32-'+str(i),0,[n&U,n>>64,0,0,0,0,0,0,0],'original_q32')
corners=[0,1,999999,1000000,1000001,(1<<32)-1,1<<32,(1<<62),MAX]
for i in range(2200):
 v=[rng.choice(corners) if i%3==0 else rng.getrandbits(63) for _ in range(9)]
 v[4]=max(1,v[4]);v[6]=rng.getrandbits(64);v[8]=rng.randint(1,5000)
 if i%4==0:v=[rng.randrange(1,10000000001),rng.randrange(1000000),rng.randrange(10000000),rng.randrange(1000000),rng.randrange(1,1001),rng.randrange(1000000),rng.randrange(1000000),rng.randrange(10000000001),rng.randint(1,5000)]
 for mode in (1,2,3):check('arithmetic-'+str(i)+'-'+str(mode),mode,v,'full_width_cost')
for budget in (-1,0,1,999999,1000000,1000001,4999999999,5000000000,5000000001):
 for margin in (-1,0,1,999999,1000000,1000001,4999999999,5000000000,5000000001):
  spent=20000000000
  v=[spent+margin+10000000000,0,10000000000,0,1,spent,0,spent+budget,5000]
  for mode in (1,2,3):check('threshold-'+str(budget)+'-'+str(margin)+'-'+str(mode),mode,v,'original_priority_thresholds')
base=wire(1,[MAX,0,0,0,MAX,0,0,5000000000,5000])
for mode in(1,2,3):check('huge-positive-margin-'+str(mode),mode,[MAX,0,0,0,MAX,0,0,5000000000,5000],'full_width_cost')
for cap in (0,1,7,8,64,128,255):run('short-output-'+str(cap),base,None,code=0xfffffffe,capacity=cap,group='atomic_guards')
for size in(0,7,8,63,127):run('short-input-'+str(size),base[:size],None,code=0xfffffffd,group='atomic_guards')
for off,value in [(0,0),(8,4),(16,1<<63),(24,1<<63),(32,1<<63),(40,1<<63),(48,0),(48,1<<63),(56,1<<63),(72,1<<63),(80,0),(80,5001),(88,1),(96,1),(104,1),(112,1),(120,1)]:
 data=bytearray(base);struct.pack_into('<Q',data,off,value);run('bad-frame-'+str(off)+'-'+str(value),bytes(data),None,code=0xfffffffd,group='atomic_guards')
run('trailing-data',base+b'0',None,code=0xfffffffd,group='atomic_guards')
run('short-work',base,None,code=0xfffffffd,work_capacity=255,group='atomic_guards')
report.update(passed=True,count=len(rows),maximum_exact_product_bits=127,original_q32_used=True,original_budget_reason_priority=True,seed=2026112502);save();print('NDU_RANK_COST_ALL_PASS',len(rows),counts,flush=True)
