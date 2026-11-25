from pathlib import Path
from hashlib import sha256
import ctypes as C,importlib.util,json,os,sys,struct,resource,copy,random,math,time
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');W=A/'native-background-source'
D=A/'native-background-value-structure-qualification-v3';D.mkdir(exist_ok=False);sys.path.insert(0,str(W));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
spec=importlib.util.spec_from_file_location('values_client',T/'qualify-result-value-core-smoke-v1.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
from hepta.hia_program import _structure,_bounded_detached_snapshot,HIAProgramRejected
from tools.generate_hia_background_optimizer_value_structure import ERRORS,C as K
policy=m.load(A/'native-background-value-structure-v4/background_optimizer_value_structure.flat','ba309a16928557417888575da260056816c84fc2e20f683ee44932d00ad25629')
value_entry=m.load(T/'result-value-native-v3/result-value.flat','32b9ec44279379d9d99343fd3ec5ef7d26144e082e11a3babd13f1aff62bf3eb')
threshold=(W/'examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat').read_bytes()
assert len(threshold)==10100891 and sha256(threshold).hexdigest()=='735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706'
frame=C.create_string_buffer(128+len(threshold));C.memmove(C.addressof(frame)+128,threshold,len(threshold))
lib=m.lib;lib.munmap.argtypes=(C.c_void_p,C.c_size_t);lib.munmap.restype=C.c_int
extent=96<<20;out=lib.mmap(None,extent,3,0x22,-1,0);assert out not in(None,C.c_void_p(-1).value)
def read(off,n=8):return C.string_at(out+off,n)
def get(off):return struct.unpack('<Q',read(off))[0]
def put(off,value):C.memmove(out+off,struct.pack('<Q',value),8)
rows=[];groups={};calls=0
def save(passed=False):
 (D/'report.json').write_text(json.dumps({'passed':passed,'whole_background_optimizer_closed':False,'count':len(rows),'groups':groups,'native_value_callback_calls':calls,'structure_flat_sha256':'ba309a16928557417888575da260056816c84fc2e20f683ee44932d00ad25629','value_owner_candidate_sha256':'32b9ec44279379d9d99343fd3ec5ef7d26144e082e11a3babd13f1aff62bf3eb','cases':rows},indent=2)+'\n')
threshold_values={}
def capture(v,value,memo=None):
 if id(value) in threshold_values:return v.take(v.call(2,tail=threshold_values[id(value)],arg0=2,cap=8192))
 if memo is None:
  if type(value)is list and len(value)>10000 and all(x is None for x in value):return v.take(v.call(1,tail=json.dumps(value,separators=(',',':')).encode()))
  memo={}
 ident=id(value)
 if ident in memo:return memo[ident]
 if type(value)in(list,dict):
  cap=v.empty(type(value));memo[ident]=cap
  if type(value)is list:
   for child in value:v.call(16,cap,capture(v,child,memo))
  else:
   for key,child in value.items():v.call(10,cap,capture(v,key,memo),capture(v,child,memo))
 else:
  old=sys.get_int_max_str_digits()
  try:sys.set_int_max_str_digits(0);cap=v.scalar(value)
  finally:sys.set_int_max_str_digits(old)
  memo[ident]=cap
 return cap
def children(v,cap):
 h=v.call(23,cap,arg1=0);n=m.u(h,48);h=v.call(23,cap,arg1=n,cap=8192+64*n);assert m.u(h,64)==n
 result=[]
 for i in range(n):
  at=8192+64*i;key=struct.unpack_from('<3Q',h,at+16);val=struct.unpack_from('<3Q',h,at+40)
  if key[0]:v.held.append(key)
  v.held.append(val);result.append((key,val))
 return result
def export_value(v,cap):
 t=v.type(cap);kind=t[0]
 if kind in(5,6):
  if t[1]>10000:
   payload=v.take(v.call(18,cap));return json.loads(v.raw(payload))
  pairs=children(v,cap)
  if kind==5:return [export_value(v,value)for key,value in pairs]
  return {export_value(v,key):export_value(v,value)for key,value in pairs}
 raw=v.raw(cap)
 if kind==0:return None
 if kind==1:return bool(raw[0])
 if kind==2:
  old=sys.get_int_max_str_digits()
  try:sys.set_int_max_str_digits(0);return int(raw)
  finally:sys.set_int_max_str_digits(old)
 if kind==3:return struct.unpack('<d',raw)[0]
 if kind==4:return raw.decode('utf8','surrogatepass')
 if kind==7:return raw
 raise AssertionError(kind)
def expected(value,mode,limit):
 old=sys.get_int_max_str_digits()
 try:
  sys.set_int_max_str_digits(limit)
  detached=_bounded_detached_snapshot(value)if mode else value
  n=_structure(detached)
  return 0,None,n,detached
 except HIAProgramRejected as e:
  matches=[key for key,text in ERRORS.items()if text==str(e)]
  assert len(matches)==1,(str(e),ERRORS);return matches[0],str(e),None,None
 except ValueError as e:
  assert 'integer string conversion'in str(e)
  return 9,str(e),None,None
 finally:sys.set_int_max_str_digits(old)
def run(label,value,mode=0,limit=4300,group='original_pairs',mutability=False):
 global calls
 started=time.monotonic_ns()
 if group=='wide':print('TYPED_WIDE_STARTED',label,flush=True)
 error,message,size,detached=expected(value,mode,limit)
 v=m.Values(entry=value_entry);root=capture(v,value)
 h=bytearray(128);h[:8]=b'HIABTC01';struct.pack_into('<Q',h,8,mode);struct.pack_into('<3Q',h,16,*root);struct.pack_into('<QQ',h,40,limit,len(threshold));C.memmove(frame,bytes(h),128)
 context=C.create_string_buffer(128);struct.pack_into('<8s3Q',context,0,b'HIABVC01',C.cast(value_entry,C.c_void_p).value,C.addressof(v.ctx),256)
 # Only the documented continuation state is initialized; other old work is deliberately retained.
 C.memset(out,0x9a,4096);put(K['PHASE'],0);transitions=0;actualcalls=0;trace=[]
 while True:
  rc=policy(frame,len(frame),out,extent,context,128);transitions+=1
  if rc==0:break
  assert transitions<10000000,(label,'qualification observer runaway')
  if rc==10:continue
  assert rc==4,(label,rc,get(K['PHASE']),read(0,128).hex(),trace[-12:])
  fn=get(0);mask=get(8);args=[get(16+8*i)for i in range(6)]
  assert fn==C.cast(value_entry,C.c_void_p).value and mask==51
  for i in(0,2,4):args[i]+=[0,C.addressof(context),C.addressof(frame),out][(mask>>(i*2))&3]
  assert args[4:]==[C.addressof(v.ctx),256]
  op=struct.unpack('<Q',C.string_at(args[0]+8,8))[0]
  C.memset(args[2],0xb7,8192)
  result=value_entry(*args);put(K['FEEDBACK'],result);actualcalls+=1;calls+=1
  trace.append((get(K['PHASE']),op,result,struct.unpack('<Q',C.string_at(args[2]+8,8))[0]))
  if len(trace)>30:trace=trace[-30:]
 head=struct.unpack('<8s15Q',read(0,128));assert head[0]==b'HIABTV01'
 if head[1]not in(0,1)or head[2]!=error:
  (D/'failure.json').write_text(json.dumps({'label':label,'head':head,'error':error,'message':message,'trace':trace},default=str,indent=2)+'\n')
 assert head[1]==int(error!=0)and head[2]==error,(label,head,error,message,trace[-15:])
 assert head[13]==0,(label,'cleanup failures',head)
 if error==0:
  cap=tuple(head[3:6]);assert cap[0];v.held.append(cap)
  assert head[7]==size,(label,head[7],size)
  actual=export_value(v,cap);assert actual==detached,(label,actual,detached)
  def ordered(a,e):
   if type(a)is dict:
    assert list(a)==list(e)
    for key in a:ordered(a[key],e[key])
   elif type(a)is list:
    assert len(a)==len(e)
    for x,y in zip(a,e):ordered(x,y)
   else:assert type(a)is type(e)
  ordered(actual,detached)
  if type(value)in(list,dict):assert v.type(cap)[3:]!=v.type(root)[3:]
  else:assert v.type(cap)[3:]==v.type(root)[3:]
  if mutability:
   old=copy.deepcopy(actual);v.call(16,root,v.scalar(91));assert export_value(v,cap)==old
 else:assert head[3:6]==(0,0,0)
 v.finish()
 rows.append({'case':label,'group':group,'mode':mode,'captured_int_digits':limit,'error_id':error,'message':message,'bytes':size,'native_callbacks':actualcalls,'continuation_steps':transitions,'elapsed_ns':time.monotonic_ns()-started,'passed':True});groups[group]=groups.get(group,0)+1
 if group=='wide':save();print('TYPED_WIDE_DONE',label,rows[-1]['elapsed_ns'],actualcalls,flush=True)
 if len(rows)%20==0:save();print('TYPED_STRUCTURE_CASE',len(rows),label,flush=True)

power=1<<33554432
decimal_rows=[
 ('below',power-1,threshold[:-1]+b'5'),
 ('exact',power,threshold),
 ('above',power+1,threshold[:-1]+b'7'),
]
assert threshold[-1:]==b'6'
for sign in(1,-1):
 for label,integer,digits in decimal_rows:
  value=integer if sign==1 else -integer
  threshold_values[id(value)]=(b'' if sign==1 else b'-')+digits
  for mode in(0,1):
   run('threshold-'+str(sign)+'-'+label+'-'+str(mode),value,mode,4300,group='wide')
  del threshold_values[id(value)]
 # Both signs pass the bit-length check, then the actual original str conversion
 # under unlimited policy reaches the separate 8 MiB byte-budget rejection.
 value=(power-1)*sign;digits=threshold[:-1]+b'5'
 threshold_values[id(value)]=(b'' if sign==1 else b'-')+digits
 for mode in(0,1):
  run('threshold-unlimited-'+str(sign)+'-'+str(mode),value,mode,0,group='wide')
 del threshold_values[id(value)]

# Private framing guards preserve all public reply bytes and never call a provider.
v=m.Values(entry=value_entry);root=v.scalar(None)
h=bytearray(128);h[:8]=b'HIABTC01';struct.pack_into('<3Q',h,16,*root)
struct.pack_into('<QQ',h,40,4300,len(threshold))
context=C.create_string_buffer(128)
struct.pack_into('<8s3Q',context,0,b'HIABVC01',C.cast(value_entry,C.c_void_p).value,C.addressof(v.ctx),256)
good_ctx=context.raw
guards=[]
def guard(label,header=None,ctx=None,sn=None,on=None,wn=None):
 C.memmove(frame,bytes(h if header is None else header),128)
 C.memmove(context,good_ctx if ctx is None else ctx,128)
 C.memset(out,0xa6,4096);put(K['PHASE'],0)
 before=read(0,128)
 rc=policy(frame,len(frame)if sn is None else sn,out,extent if on is None else on,context,128 if wn is None else wn)
 assert rc==4294967293 and read(0,128)==before,(label,rc,read(0,128).hex())
 guards.append({'case':label,'passed':True})
guard('input-short',sn=len(frame)-1)
guard('output-short',on=extent-1)
guard('context-short',wn=127)
for off,value in [(0,0),(8,2),(40,1),(40,639),(40,2147483648),(48,len(threshold)-1)]+[(i,1)for i in range(56,128,8)]:
 b=bytearray(h);struct.pack_into('<Q',b,off,value);guard('header-'+str(off)+'-'+str(value),b)
for off,value in[(0,0),(8,0),(16,0),(24,255)]:
 b=bytearray(good_ctx);struct.pack_into('<Q',b,off,value);guard('context-'+str(off)+'-'+str(value),ctx=bytes(b))
v.finish()
# Invalid root capabilities traverse the actual owner and release any temporary
# retains; no claimed caller type or identity enters the continuation.
for label,which in [('zero','zero'),('wrong-tag','tag'),('stale','stale'),('other-context','cross')]:
 v=m.Values(entry=value_entry);other=None;cap=v.scalar(19)
 if which=='zero':bad=(0,0,0)
 elif which=='tag':bad=(cap[0],cap[1]^1,cap[2])
 elif which=='stale':bad=cap;v.drop(cap)
 else:other=m.Values(entry=value_entry);bad=other.scalar(7)
 h2=bytearray(h);struct.pack_into('<3Q',h2,16,*bad);C.memmove(frame,bytes(h2),128)
 struct.pack_into('<8s3Q',context,0,b'HIABVC01',C.cast(value_entry,C.c_void_p).value,C.addressof(v.ctx),256)
 C.memset(out,0xb9,4096);put(K['PHASE'],0)
 actual=0
 while True:
  rc=policy(frame,len(frame),out,extent,context,128)
  if rc==0:break
  if rc==10:continue
  assert rc==4
  args=[get(16+8*i)for i in range(6)];mask=get(8)
  for i in(0,2,4):args[i]+=[0,C.addressof(context),C.addressof(frame),out][(mask>>(i*2))&3]
  C.memset(args[2],0xdb,8192);rc=value_entry(*args);put(K['FEEDBACK'],rc);actual+=1;calls+=1
 head=struct.unpack('<8s15Q',read(0,128))
 assert head[0]==b'HIABTV01' and head[1]==2 and head[2]==1000 and head[3:6]==(0,0,0) and head[12]==1 and head[13]==0,(label,head)
 v.finish()
 if other:other.finish()
 guards.append({'case':'actual-invalid-cap-'+label,'actual_callbacks':actual,'passed':True})
(D/'private-guards.json').write_text(json.dumps({'passed':True,'count':len(guards),'cases':guards},indent=2)+'\n')
assert lib.munmap(out,extent)==0
save(True)
print('TYPED_THRESHOLD_PRIVATE_PASS',len(rows),calls,'private',len(guards),flush=True)
