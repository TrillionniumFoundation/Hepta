from pathlib import Path
from hashlib import sha256
import ctypes as C,fcntl,json,math,os,random,resource,struct,time
import argparse
parser=argparse.ArgumentParser();parser.add_argument('--flat',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
D=args.output;D.mkdir(parents=True,exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
raw=args.flat.read_bytes();pin=sha256(raw).hexdigest();assert pin=='f3dfec793b05805db93a2b4b0e794201b13e495dba40a74909f2bf2117b4902e'
fd=os.memfd_create('native-ndu-exact-binary64-budget',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p
address=lib.mmap(None,len(raw),5,2,fd,0);assert address not in(None,C.c_void_p(-1).value)
entry=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(address)
rows=[];counts={};report={'passed':False,'flat_sha256':pin,'whole_native_rank_closed':False,'scope':'Actual sealed HIA binary64 budget selection and original Python min/float multiplication/int conversion. No renewed deadline, proof, evaluator or publication authority.','rows':rows,'counts':counts}
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def bits(x):return struct.unpack('<Q',struct.pack('<d',x))[0]
def number(b):return struct.unpack('<d',struct.pack('<Q',b))[0]
def wire(b,integer,remaining):return struct.pack('<8s7Q',b'HIANRB01',b,integer,remaining,0,0,0,0)
def expected(bridge,remaining):
 out=bytearray(64);struct.pack_into('<8sQ',out,0,b'HIANBR01',0)
 if not 0<bridge<=60:struct.pack_into('<Q',out,8,1)
 elif remaining==0:struct.pack_into('<Q',out,8,2)
 else:
  seconds=remaining/1_000_000_000
  selected=min(bridge,seconds)
  ratio=bits(seconds) if remaining<60_000_000_000 else 0
  struct.pack_into('<6Q',out,16,bits(selected),int(type(selected)is int),int(selected*1_000_000_000),ratio,selected if type(selected)is int else 0,int(bridge>seconds))
 return bytes(out)
def run(label,packet,wanted,code=0,capacity=64,work_capacity=128,group='budget'):
 ib=C.create_string_buffer(packet);ob=C.create_string_buffer(96);wb=C.create_string_buffer(160)
 C.memset(ob,0xdb,96);C.memset(wb,0xa5,160)
 start=time.monotonic_ns();actual=entry(ib,len(packet),C.addressof(ob)+16,capacity,C.addressof(wb)+16,work_capacity);elapsed=time.monotonic_ns()-start
 assert actual==code,(label,actual,code)
 assert ib.raw[:len(packet)]==packet
 assert ob.raw[:16]+ob.raw[-16:]==b'\xdb'*32 and wb.raw[:16]+wb.raw[-16:]==b'\xa5'*32
 if code==0:assert ob.raw[16:80]==wanted,(label,struct.unpack('<8Q',ob.raw[16:80]),struct.unpack('<8Q',wanted),struct.unpack('<8Q',packet))
 else:assert ob.raw==b'\xdb'*96 and wb.raw==b'\xa5'*160,(label,'non-atomic invalid-frame/short-output')
 counts[group]=counts.get(group,0)+1;rows.append({'case':label,'group':group,'return':actual,'input_sha256':sha256(packet).hexdigest(),'output_sha256':sha256(wanted).hexdigest() if wanted else None,'elapsed_ns':elapsed,'passed':True})
 if len(rows)%1000==0:save();print('NDU_CLOCK_CASES',len(rows),flush=True)
def check(label,bridge,remaining,group='budget'):run(label,wire(bits(bridge),int(type(bridge)is int),remaining),expected(bridge,remaining),group=group)
rng=random.Random(2026112503);remainders=[0,1,2,3,999999,1000000,1000001,999999999,1000000000,1000000001,59_999_999_999,60_000_000_000,60_000_000_001,(1<<63)-1,(1<<64)-1]
for integer in range(1,61):
 for rem in remainders+[integer*1_000_000_000-1,integer*1_000_000_000,integer*1_000_000_000+1]:
  check('int-'+str(integer)+'-'+str(rem),integer,rem,'exact_integer')
for i in range(3200):
 rem=rng.randrange(1,60_000_000_000) if i%3 else rng.getrandbits(64)
 b=rng.randrange(1,bits(60.0)+1) if i%2 else bits(rng.uniform(0,60))
 check('random-'+str(i),number(b),rem,'float_budget')
for rem in [1,2,3,7,11,63,64,65,2**20,2**24,2**30,2**35,59_999_999_999]+[rng.randrange(1,60_000_000_000) for _ in range(600)]:
 q=bits(rem/1_000_000_000)
 for delta in (-1,0,1):
  if q+delta<=bits(60.0):check('ratio-adjacent-'+str(rem)+'-'+str(delta),number(q+delta),rem,'binary64_min_boundary')
for x in [0.0,-0.0,-1.0,-60.0,60.00000000000001,61,math.inf,-math.inf,math.nan]:
 for rem in (0,1,10**9,(1<<64)-1):check('invalid-timeout-'+str(bits(x))+'-'+str(rem),x,rem,'original_timeout_refusals')
for b in (1,2,3,(1<<52)-1,1<<52,(1<<52)+1,bits(1e-100),bits(1e-10),bits(1e-9),bits(0.5),bits(1),bits(60.0)):
 for rem in remainders:check('extreme-'+str(b)+'-'+str(rem),number(b),rem,'subnormal_and_extreme')
base=wire(bits(1.0),1,10**9)
for cap in (0,1,7,8,32,63):run('short-output-'+str(cap),base,None,code=0xfffffffe,capacity=cap,group='atomic_guards')
for size in (0,7,8,16,63):run('short-input-'+str(size),base[:size],None,code=0xfffffffd,group='atomic_guards')
for off,value in ((0,0),(16,2),(32,1),(40,1),(48,1),(56,1),(8,bits(0.5)),(8,bits(1.5))):
 data=bytearray(base);struct.pack_into('<Q',data,off,value);run('bad-frame-'+str(off)+'-'+str(value),bytes(data),None,code=0xfffffffd,group='atomic_guards')
run('trailing-data',base+b'0',None,code=0xfffffffd,group='atomic_guards')
run('short-work',base,None,code=0xfffffffd,work_capacity=127,group='atomic_guards')
report.update(passed=True,count=len(rows),original_binary64_semantics=True,seed=2026112503);save();print('NDU_RANK_CLOCK_BUDGET_ALL_PASS',len(rows),counts,flush=True)
