from pathlib import Path
import ctypes as C,hashlib,importlib.util,json,math,os,random,resource,struct,sys,time
resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.set_int_max_str_digits(0)
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');W=A/'native-background-source';T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');D=A/'native-background-value-freeze-v3';R=A/'native-background-value-freeze-controls-v1';R.mkdir();sys.path.insert(0,str(W))
from tools.qualify_hia_multiversion_background_payload import Owner
sp=importlib.util.spec_from_file_location('vc',T/'qualify-result-value-core-smoke-v1.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
v=m.Values(entry=m.load(T/'result-value-native-v4/result-value.flat','6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c'))
payload=Owner(A/'native-background-payload-v1/payload-component.so')
io_lib=C.CDLL(str(A/'native-background-value-transport-v1/value-transport.so'));io=io_lib.hia_background_value_transport;io.argtypes=[C.c_void_p,C.c_uint64]*3;io.restype=C.c_uint32
capture=m.load(A/'native-background-json-capture-v4/background_optimizer_json_capture.flat','62f62e547a346c631697a4c0ced3385afb78d6a6472a11ecad2e8c57da0faf1f')
freeze=m.load(A/'native-background-freeze-v2/background_optimizer_freeze.flat','f32bf4a811481a3baa007919710549a8e231caa3cb44c6afcb180f4c124d210d')
pin=json.loads((D/'packing.json').read_text())['image']['sha256'];assert hashlib.sha256((D/'value-freeze.so').read_bytes()).hexdigest()==pin
lib=C.CDLL(str(D/'value-freeze.so'));entry=lib.hia_background_value_freeze;entry.argtypes=[C.c_void_p,C.c_uint64]*3;entry.restype=C.c_uint32
ctx=C.create_string_buffer(2048);struct.pack_into('<8s10Q',ctx,0,b'HIABFZC1',C.cast(v.entry,C.c_void_p).value,C.addressof(v.ctx),256,C.cast(io,C.c_void_p).value,C.cast(capture,C.c_void_p).value,C.cast(freeze,C.c_void_p).value,C.cast(payload.f,C.c_void_p).value,C.addressof(payload.w),256,4300)
out=C.create_string_buffer(262144);rows=[];calls=0
def make(x):
 if type(x)is list:
  a=v.empty(list)
  for y in x:v.call(16,a,make(y))
  return a
 if type(x)is dict:
  a=v.empty(dict)
  for k,y in x.items():v.call(10,a,make(k),make(y))
  return a
 return v.scalar(x)
def original(x,limit):
 old=sys.get_int_max_str_digits();sys.set_int_max_str_digits(limit)
 try:
  try:return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode(),None
  except BaseException as e:return {'type':type(e).__name__,'message':str(e)},[e.start,e.end]if isinstance(e,UnicodeEncodeError)else None
 finally:sys.set_int_max_str_digits(old)
def call(a=(0,0,0),op=0,wctx=ctx):
 global calls
 b=bytearray(128);b[:8]=b'HIABFZQ1';struct.pack_into('<Q',b,8,op);struct.pack_into('<3Q',b,24,*a);s=C.create_string_buffer(bytes(b),128)
 C.memset(out,0xaa,len(out));t=time.monotonic_ns();rc=entry(s,128,out,len(out),wctx,len(wctx));elapsed=time.monotonic_ns()-t;calls+=1
 r=out.raw;assert rc==0 and r[:8]==b'HIABFZR1',(calls,rc,r[:128].hex())
 return r,elapsed
def case(name,x,limit=4300):
 cap=make(x);want,span=original(x,limit);struct.pack_into('<Q',ctx,80,limit);fds=len(os.listdir('/proc/self/fd'));r,elapsed=call(cap)
 assert m.u(r,56)==0 and m.u(ctx.raw,96)==0,(name,r[:128].hex())
 if type(want)is bytes:
  assert m.u(r,8)==0 and m.u(r,40)==len(want),(name,r[:128].hex(),len(want))
  c=struct.unpack_from('<3Q',r,16);actual=payload.copy(c,0,len(want));assert actual==want,(name,actual[:64],want[:64]);payload.drop(c)
 else:
  assert m.u(r,8)==1,(name,r[:128].hex(),want)
  got=json.loads(r[128:128+m.u(r,48)]);assert got==want,(name,got,want)
  if span is not None:assert [m.u(r,80),m.u(r,88)]==span,(name,span,r[:128].hex())
 assert len(os.listdir('/proc/self/fd'))==fds and m.u(payload.w.raw,16)==0,(name,'fd/ref')
 rows.append({'case':name,'elapsed_ns':elapsed,'passed':True,'error':want if type(want)is dict else None,'bytes':len(want)if type(want)is bytes else None})
 for a in v.held[:]:v.drop(a)
 if len(rows)%40==0:print('BG_VALUE_FREEZE_WHOLE',len(rows),name,flush=True)

import signal,threading
hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;count=hooks.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
def region(p):
 rows=[x.split()[0].split('-')for x in Path('/proc/self/maps').read_text().splitlines()if str(p)in x]
 return min(int(x,16)for x,y in rows),max(int(y,16)for x,y in rows)
io_lo,io_hi=region(A/'native-background-value-transport-v1/value-transport.so')
p_lo,p_hi=region(A/'native-background-payload-v1/payload-component.so')
def note(name,**kw):
 rows.append({'case':name,'passed':True,**kw});print('BG_FREEZE_CONTROL',name,flush=True)
def empty_resources(r):
 assert m.u(ctx.raw,96)==0 and m.u(r,56)==0
 assert all(m.u(r,i)==0 for i in(184,192,208,232,248)),r[128:384].hex()
 assert m.u(payload.w.raw,16)==0
root=make({'z':[1,2,3],'a':{'x':'string'}})
for where,nth,lo,hi in[('IO',i,io_lo,io_hi)for i in range(1,5)]+[('payload',i,p_lo,p_hi)for i in(1,2)]:
 fds=len(os.listdir('/proc/self/fd'));arm(lo,hi,nth);r,_=call(root);seen=[count(i)for i in range(3)];arm(lo,hi,0)
 assert m.u(r,8)==5 and seen==[nth,nth-1,nth-1],(where,nth,r[:128].hex(),seen)
 empty_resources(r);assert len(os.listdir('/proc/self/fd'))==fds
 r,_=call(root);assert m.u(r,8)==0;c=struct.unpack_from('<3Q',r,16);payload.drop(c)
 note('actual-'+where+'-malloc-'+str(nth),observed=seen)
arm(lo,hi,0)
# Four actual kernel virtual-memory failures, using measured native capture
# capacities, cover the mapped stream, arena frame, workspace and output.
large=make('x'*(9<<20));r,_=call(large);assert m.u(r,8)==0;payload.drop(struct.unpack_from('<3Q',r,16))
raw=b'"'+b'x'*(9<<20)+b'"';s=C.create_string_buffer(raw);st=C.create_string_buffer(64);sw=C.create_string_buffer(128);assert capture(s,len(raw),st,64,sw,128)==0
arena=m.u(st.raw,32);work=max(m.u(st.raw,40),131072,arena+16384);sizes=[len(raw),128+len(raw)+arena,work,128+len(raw)]
page=os.sysconf('SC_PAGESIZE');roundp=lambda n:(n+page-1)//page*page;old=resource.getrlimit(resource.RLIMIT_AS);prefix=0
for i,n in enumerate(sizes):
 basevm=int(Path('/proc/self/statm').read_text().split()[0])*page;limit=basevm+prefix+roundp(n)-page
 fds=len(os.listdir('/proc/self/fd'))
 try:resource.setrlimit(resource.RLIMIT_AS,(limit,old[1]));r,_=call(large)
 finally:resource.setrlimit(resource.RLIMIT_AS,old)
 assert m.u(r,8)==5,(i,r[:128].hex(),sizes,limit,basevm)
 empty_resources(r);assert len(os.listdir('/proc/self/fd'))==fds
 note('actual-kernel-ENOMEM-map-'+str(i),mapping_bytes=n,limit=limit,detail=m.u(r,64))
 prefix+=roundp(n)
# OS failures from the real stream are preserved through the fixed owner.
oldsize=resource.getrlimit(resource.RLIMIT_FSIZE);oldsignal=signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
try:resource.setrlimit(resource.RLIMIT_FSIZE,(1024,oldsize[1]));r,_=call(large)
finally:resource.setrlimit(resource.RLIMIT_FSIZE,oldsize);signal.signal(signal.SIGXFSZ,oldsignal)
assert m.u(r,8)==8 and m.u(r,64)==(1<<64)-27,r[:128].hex();empty_resources(r);note('actual-EFBIG-forwarded-after-partial-stream')
CALL=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
# A malformed dependency reply after real creation cannot leak its owned cap;
# a refused cleanup is quarantined and actually retried without recreating it.
state={'created':0,'refused':False}
@CALL
def bad_payload(s,sn,o,on,w,wn):
 op=m.u(C.string_at(s,sn),8)
 if op==3 and not state['refused']:
  state['refused']=True;h=bytearray(128);h[:8]=b'HIABPYR1';struct.pack_into('<Q',h,8,9);C.memmove(o,bytes(h),128);return 0
 rc=payload.f(s,sn,o,on,w,wn)
 if op==1 and rc==0 and m.u(C.string_at(o,128),8)==0:
  state['created']+=1;n=m.u(C.string_at(o,128),40);C.memmove(o+40,struct.pack('<Q',n+1),8)
 return rc
oldfn=m.u(ctx.raw,56);struct.pack_into('<Q',ctx,56,C.cast(bad_payload,C.c_void_p).value)
fds=len(os.listdir('/proc/self/fd'));r,_=call(root);assert m.u(r,8)==9 and m.u(r,56)==1 and m.u(ctx.raw,96)==1
r,_=call(root);assert m.u(r,8)==6
r,_=call(op=1);assert m.u(r,8)==9 and m.u(r,56)==0 and state['created']==1,r[:128].hex()
struct.pack_into('<Q',ctx,56,oldfn);empty_resources(r);assert len(os.listdir('/proc/self/fd'))==fds
note('actual-payload-cap-quarantine-and-retry-no-second-create')
state={'refused':0}
@CALL
def bad_drop(s,sn,o,on,w,wn):
 if m.u(C.string_at(s,sn),8)==6 and state['refused']<2:
  state['refused']+=1;h=bytearray(128);h[:8]=b'HIABVR01';struct.pack_into('<Q',h,8,9);C.memmove(o,bytes(h),128);return 0
 return v.entry(s,sn,o,on,w,wn)
oldfn=m.u(ctx.raw,8);struct.pack_into('<Q',ctx,8,C.cast(bad_drop,C.c_void_p).value)
fds=len(os.listdir('/proc/self/fd'));r,_=call(root);assert m.u(r,8)==9 and m.u(r,56)==1 and m.u(ctx.raw,96)==1,r[:128].hex()
r,_=call(op=1);assert m.u(r,8)==7 and m.u(r,56)==0 and state['refused']==2
struct.pack_into('<Q',ctx,8,oldfn);empty_resources(r);assert len(os.listdir('/proc/self/fd'))==fds
note('actual-input-refs-quarantine-through-native-stream-and-retry')
# Dependency failure controls preserve both existing captures and identities.
for which in(40,48):
 target=capture if which==40 else freeze
 @CALL
 def bad(s,sn,o,on,w,wn):return 0xfffffffd
 oldfn=m.u(ctx.raw,which);struct.pack_into('<Q',ctx,which,C.cast(bad,C.c_void_p).value);fds=len(os.listdir('/proc/self/fd'));r,_=call(root);struct.pack_into('<Q',ctx,which,oldfn)
 assert m.u(r,8)==7 and m.u(r,64)==0xfffffffd;empty_resources(r);assert len(os.listdir('/proc/self/fd'))==fds
 note('private-dependency-rejection-'+str(which))
# Full framing/private bounds preserve public output before any native effects.
wire=bytearray(128);wire[:8]=b'HIABFZQ1';struct.pack_into('<3Q',wire,24,*root);cases=[]
for at,x in[(0,0),(8,2)]+[(i,1)for i in range(16,128,8)if i not in(24,32,40)]:
 b=bytearray(wire);struct.pack_into('<Q',b,at,x);cases.append(('input-'+str(at),bytes(b),128,262144,2048,None,0))
for n in(0,1,127,129):cases.append(('inputN-'+str(n),bytes(wire)+b'x',n,262144,2048,None,0))
for n in(0,127,262143):cases.append(('outN-'+str(n),bytes(wire),128,n,2048,None,0))
for n in(0,255,2047):cases.append(('workN-'+str(n),bytes(wire),128,262144,n,None,0))
for at,x in[(0,0),(8,0),(16,0),(24,255),(32,0),(40,0),(48,0),(56,0),(64,0),(72,255),(80,1),(80,639),(80,2147483648),(96,2),(104,1),(112,1),(120,1)]:
 cases.append(('context-'+str(at)+'-'+str(x),bytes(wire),128,262144,2048,at,x))
for name,raw,sn,on,wn,at,x in cases:
 src=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xa3'*262144,262144);cw=C.create_string_buffer(ctx.raw,2048)
 if at is not None:struct.pack_into('<Q',cw,at,x)
 before=cw.raw;rc=entry(src,sn,o,on,cw,wn);assert rc==0xfffffffd and o.raw[:128]==b'\xa3'*128 and cw.raw==before,(name,rc)
note('private-frame-context-view-domain',controls=len(cases))
v.finish();payload.run(5)
(R/'report.json').write_text(json.dumps({'passed':True,'whole_background_qualified':False,'groups':len(rows),'image_sha256':pin,'cases':rows},indent=2)+'\n')
print('BG_VALUE_FREEZE_CONTROLS_PASS',len(rows),flush=True)
