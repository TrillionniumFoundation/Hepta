from pathlib import Path
from hashlib import sha256
import ctypes as C,importlib.util,json,os,sys,struct,resource,copy,random,math,time
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');W=A/'native-background-source'
D=A/'native-background-value-structure-qualification-v1';D.mkdir(exist_ok=False);sys.path.insert(0,str(W));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
spec=importlib.util.spec_from_file_location('values_client',T/'qualify-result-value-core-smoke-v1.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
from hepta.hia_program import _structure,_bounded_detached_snapshot,HIAProgramRejected
from tools.generate_hia_background_optimizer_value_structure import ERRORS,C as K
policy=m.load(A/'native-background-value-structure-v3/background_optimizer_value_structure.flat','9160d08ca63103f4ae42103f9ba09b77fdb761746dcef65e1c34801cd0197686')
value_entry=m.load(T/'result-value-native-v1/result-value.flat','54deebff41eeee880c9f62a77793c0ab640f9bb6635bdba660c32f44aa1936ab')
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
 (D/'report.json').write_text(json.dumps({'passed':passed,'whole_background_optimizer_closed':False,'count':len(rows),'groups':groups,'native_value_callback_calls':calls,'structure_flat_sha256':'9160d08ca63103f4ae42103f9ba09b77fdb761746dcef65e1c34801cd0197686','value_owner_candidate_sha256':'54deebff41eeee880c9f62a77793c0ab640f9bb6635bdba660c32f44aa1936ab','cases':rows},indent=2)+'\n')
def capture(v,value,memo=None):
 if memo is None:memo={}
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
 rows.append({'case':label,'group':group,'mode':mode,'captured_int_digits':limit,'error_id':error,'message':message,'bytes':size,'native_callbacks':actualcalls,'continuation_steps':transitions,'passed':True});groups[group]=groups.get(group,0)+1
 if len(rows)%20==0:save();print('TYPED_STRUCTURE_CASE',len(rows),label,flush=True)
atoms=[None,False,True,0,1,-1,10**30,'','x','é🙂','\ud800','\udfff','\ud800\udfff','\U0001f642',b'',b'x',0.0,-0.0,1.5,float('nan'),float('inf'),float('-inf')]
for mode in(0,1):
 for i,value in enumerate(atoms):
  run('atom-'+str(mode)+'-'+str(i),value,mode)
  run('nested-'+str(mode)+'-'+str(i),{'z':[None,value],'a':[1,True]},mode)
 for i,value in enumerate([[],{},[1,2,3],{'z':1,'a':2},{1:'bad','ok':0},{'ok':0,False:'bad'},{'\ud800':0,1:0},{1:0,'\ud800':0}]):
  run('container-'+str(mode)+'-'+str(i),value,mode)
 for depth in(63,64,65,66):
  value=0
  for _ in range(depth):value=[value]
  run('depth-'+str(mode)+'-'+str(depth),value,mode,group='depth')
 shared={'z':[1,2],'a':False};run('shared-container-'+str(mode),[shared,shared],mode,group='alias')
 x=[];x.append(x);run('list-cycle-'+str(mode),x,mode,group='cycle')
 x={};x['self']=x;run('dict-cycle-'+str(mode),x,mode,group='cycle')
 x=[];y={'back':x};x.append(y);run('mutual-cycle-'+str(mode),x,mode,group='cycle')
 run('detached-mutation-'+str(mode),[{'x':1},2],mode,mutability=True,group='alias')
 for limit in(0,640,4300):
  for digits in(639,640,641,4299,4300,4301):
   run('digits-'+str(mode)+'-'+str(limit)+'-'+str(digits),[10**(digits-1)],mode,limit,group='decimal')
 rng=random.Random(2026112519+mode)
 for i in range(40):
  value={'first':rng.choice(atoms),'second':[rng.choice(atoms)for _ in range(rng.randrange(5))]}
  run('random-'+str(mode)+'-'+str(i),value,mode,group='random')
assert lib.munmap(out,extent)==0
save(True);print('TYPED_STRUCTURE_ACTUAL_VALUE_PASS',len(rows),calls,groups,flush=True)
