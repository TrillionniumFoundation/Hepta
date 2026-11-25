from pathlib import Path
import ctypes as C,fcntl,hashlib,importlib.util,json,math,os,random,resource,struct,sys,time
resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.set_int_max_str_digits(0)
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');D=A/'native-background-value-transport-v1';R=A/'native-background-value-transport-controls-v1';R.mkdir()
spec=importlib.util.spec_from_file_location('vc',T/'qualify-result-value-core-smoke-v1.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
v=m.Values(entry=m.load(T/'result-value-native-v4/result-value.flat','6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c'))
image=(D/'value-transport.so').read_bytes();assert hashlib.sha256(image).hexdigest()=='7e98a89a07d3e3bc28469fd0090829141a6eca5305afcca3e769321d2026584c'
lib=C.CDLL(str(D/'value-transport.so'));entry=lib.hia_background_value_transport;entry.argtypes=[C.c_void_p,C.c_uint64]*3;entry.restype=C.c_uint32
ctx=C.create_string_buffer(256);struct.pack_into('<8s3Q',ctx,0,b'HIABIC01',C.cast(v.entry,C.c_void_p).value,C.addressof(v.ctx),256)
out=C.create_string_buffer(131072);rows=[];calls=0
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
def transmit(a,status=0):
 global calls
 wire=bytearray(128);wire[:8]=b'HIABIQ01';struct.pack_into('<3Q',wire,24,*a);s=C.create_string_buffer(bytes(wire),128)
 C.memset(out,0xa6,len(out));rc=entry(s,128,out,len(out),ctx,256);calls+=1
 r=out.raw[:128];assert rc==0 and r[:8]==b'HIABIO01'and m.u(r,8)==status,(calls,rc,r.hex())
 assert m.u(r,48)==0,('quarantined',r.hex())
 if status:return None
 fd,n=m.u(r,16),m.u(r,24)
 try:
  assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15 and os.fstat(fd).st_size==n
  chunks=[];at=0
  while at<n:
   b=os.pread(fd,min(1<<20,n-at),at);assert b;chunks.append(b);at+=len(b)
  return b''.join(chunks)
 finally:os.close(fd)
def equivalent(x,y):
 if type(x)is not type(y):return False
 if type(x)is float:return math.isnan(x)and math.isnan(y)or struct.pack('<d',x)==struct.pack('<d',y)
 if type(x)is dict:return list(x)==list(y)and all(equivalent(x[k],y[k])for k in x)
 if type(x)is list:return len(x)==len(y)and all(equivalent(a,b)for a,b in zip(x,y))
 return x==y

import signal,threading
hooks=C.CDLL(None);arm=hooks.values_fault_arm;arm.argtypes=[C.c_uint64]*3;count=hooks.values_fault_count;count.argtypes=[C.c_uint64];count.restype=C.c_uint64
maps=[x.split()[0].split('-')for x in Path('/proc/self/maps').read_text().splitlines()if str(D/'value-transport.so')in x];lo=min(int(x,16)for x,y in maps);hi=max(int(y,16)for x,y in maps)
def qcall(a=(0,0,0),op=0,wctx=ctx):
 wire=bytearray(128);wire[:8]=b'HIABIQ01';struct.pack_into('<Q',wire,8,op);struct.pack_into('<3Q',wire,24,*a)
 s=C.create_string_buffer(bytes(wire),128);o=C.create_string_buffer(131072);C.memset(o,0x93,len(o))
 rc=entry(s,128,o,len(o),wctx,256);assert rc==0 and o.raw[:8]==b'HIABIO01',(rc,o.raw[:128].hex())
 return o.raw[:128]
def note(name,**kw):
 rows.append({'case':name,'passed':True,**kw});print('BG_TRANSPORT_CONTROL',name,flush=True)
root=make({'z':[[[1]],2],'a':[3,4,5],'last':'text'})
for nth in range(1,13):
 fds=len(os.listdir('/proc/self/fd'));arm(lo,hi,nth);r=qcall(root);observed=[count(i)for i in range(3)];arm(lo,hi,0)
 assert m.u(r,8)==5 and m.u(r,48)==0 and observed==[nth,nth-1,nth-1],(nth,r.hex(),observed)
 assert len(os.listdir('/proc/self/fd'))==fds
 raw=transmit(root);assert json.loads(raw)=={'z':[[[1]],2],'a':[3,4,5],'last':'text'}
 note('actual-malloc-'+str(nth),observed=observed)
arm(lo,hi,0)
# Selected value operation failures are a separately labeled dependency-control
# fixture; all other calls still execute the captured actual native value owner.
CALL=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
for failop in (5,7,19,23):
 state={'done':False,'calls':0}
 @CALL
 def wrapped(s,sn,o,on,w,wn):
  raw=C.string_at(s,sn);op=m.u(raw,8);state['calls']+=1
  if op==failop and not state['done']:
   state['done']=True;h=bytearray(128);h[:8]=b'HIABVR01';struct.pack_into('<Q',h,8,5);C.memmove(o,bytes(h),128);return 0
  return v.entry(s,sn,o,on,w,wn)
 old=m.u(ctx.raw,8);struct.pack_into('<Q',ctx,8,C.cast(wrapped,C.c_void_p).value)
 fds=len(os.listdir('/proc/self/fd'));r=qcall(root);struct.pack_into('<Q',ctx,8,old)
 assert state['done']and m.u(r,8)==7 and m.u(r,48)==0 and len(os.listdir('/proc/self/fd'))==fds,(failop,r.hex())
 note('value-operation-control-'+str(failop),calls=state['calls'])
# A refused actual owned-capability drop remains explicitly quarantined;
# fresh work is blocked and the same native owner can retry that cleanup.
state={'done':False}
@CALL
def refusedrop(s,sn,o,on,w,wn):
 if m.u(C.string_at(s,sn),8)==6 and not state['done']:
  state['done']=True;h=bytearray(128);h[:8]=b'HIABVR01';struct.pack_into('<Q',h,8,9);C.memmove(o,bytes(h),128);return 0
 return v.entry(s,sn,o,on,w,wn)
old=m.u(ctx.raw,8);struct.pack_into('<Q',ctx,8,C.cast(refusedrop,C.c_void_p).value)
fds=len(os.listdir('/proc/self/fd'));r=qcall(root)
assert m.u(r,8)==7 and m.u(r,48)==1 and m.u(ctx.raw,32)!=0,r.hex()
r=qcall(root);assert m.u(r,8)==6
r=qcall(op=1);assert m.u(r,8)==0 and m.u(r,48)==0 and m.u(r,16)==(1<<64)-1,r.hex()
struct.pack_into('<Q',ctx,8,old);assert m.u(ctx.raw,32)==m.u(ctx.raw,40)==m.u(ctx.raw,64)==0 and len(os.listdir('/proc/self/fd'))==fds
note('failed-drop-quarantine-retry-no-lost-cap')
# Real kernel file size limit produces a partial write followed by EFBIG.
large=make('x'*20000);oldlimit=resource.getrlimit(resource.RLIMIT_FSIZE);oldsig=signal.signal(signal.SIGXFSZ,signal.SIG_IGN);fds=len(os.listdir('/proc/self/fd'))
try:
 resource.setrlimit(resource.RLIMIT_FSIZE,(1024,oldlimit[1]));r=qcall(large)
finally:
 resource.setrlimit(resource.RLIMIT_FSIZE,oldlimit);signal.signal(signal.SIGXFSZ,oldsig)
assert m.u(r,8)==8 and m.u(r,40)==(1<<64)-27 and len(os.listdir('/proc/self/fd'))==fds,r.hex()
note('actual-kernel-partial-write-EFBIG-close')
# Real descriptor exhaustion, while all policy inputs are already resident.
oldlimit=resource.getrlimit(resource.RLIMIT_NOFILE);opened=[]
try:
 now=[int(x)for x in os.listdir('/proc/self/fd')];resource.setrlimit(resource.RLIMIT_NOFILE,(max(now)+12,oldlimit[1]))
 while True:
  try:opened.append(os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC))
  except OSError as e:assert e.errno==24;break
 r=qcall(root)
finally:
 for fd in opened:os.close(fd)
 resource.setrlimit(resource.RLIMIT_NOFILE,oldlimit)
assert m.u(r,8)==8 and m.u(r,40)==(1<<64)-24,r.hex();note('actual-kernel-EMFILE-after-owned-root-retain')
# Malformed source/context envelopes and short/overflowing/overlapping views
# preserve every byte of the public reply and the captured context.
base=bytearray(128);base[:8]=b'HIABIQ01';struct.pack_into('<3Q',base,24,*root)
cases=[]
for off,x in [(0,0),(8,2)]+[(i,1)for i in range(16,128,8)if i not in(24,32,40)]:
 b=bytearray(base);struct.pack_into('<Q',b,off,x);cases.append(('wire-'+str(off),bytes(b),128,131072,256,None))
for n in (0,1,127,129):cases.append(('wire-size-'+str(n),bytes(base)+b'x',n,131072,256,None))
for n in(0,127,131071):cases.append(('out-size-'+str(n),bytes(base),128,n,256,None))
for n in(0,255):cases.append(('work-size-'+str(n),bytes(base),128,131072,n,None))
for off in(0,8,16,24,88,248):cases.append(('context-'+str(off),bytes(base),128,131072,256,off))
for name,raw,sn,on,wn,changed in cases:
 s=C.create_string_buffer(raw);o=C.create_string_buffer(b'\xa3'*131072,131072);cw=C.create_string_buffer(ctx.raw,256)
 if changed is not None:struct.pack_into('<Q',cw,changed,1 if changed>=88 else 0)
 before=cw.raw;rc=entry(s,sn,o,on,cw,wn)
 assert rc==0xfffffffd and o.raw[:128]==b'\xa3'*128 and cw.raw==before,(name,rc)
note('complete-private-frames-and-short-views',controls=len(cases))
for pointers in[(None,128,C.addressof(out),len(out),C.addressof(ctx),256),(C.addressof(out),128,C.addressof(out),len(out),C.addressof(ctx),256),(C.addressof(out),128,C.addressof(out)+64,len(out)-64,C.addressof(ctx),256),((1<<64)-64,128,C.addressof(out),len(out),C.addressof(ctx),256),(C.addressof(out),128,C.addressof(out),1<<63,C.addressof(ctx),256)]:
 C.memset(out,0xc7,len(out));rc=entry(*pointers);assert rc==0xfffffffd and out.raw[:128]==b'\xc7'*128
note('null-overflow-and-overlap-views',controls=5)
# Read-only concurrent transports each own a continuation context and output.
errors=[]
def worker():
 try:
  cw=C.create_string_buffer(256);struct.pack_into('<8s3Q',cw,0,b'HIABIC01',C.cast(v.entry,C.c_void_p).value,C.addressof(v.ctx),256)
  for _ in range(30):
   r=qcall(root,wctx=cw);assert m.u(r,8)==0
   fd,n=m.u(r,16),m.u(r,24)
   try:assert json.loads(os.pread(fd,n,0))=={'z':[[[1]],2],'a':[3,4,5],'last':'text'}
   finally:os.close(fd)
 except BaseException as e:errors.append(repr(e))
threads=[threading.Thread(target=worker)for _ in range(8)]
for t in threads:t.start()
for t in threads:t.join(30);assert not t.is_alive()
assert not errors,errors;note('8-thread-independent-continuations-240-transports')
v.finish()
(R/'report.json').write_text(json.dumps({'passed':True,'whole_background_qualified':False,'groups':len(rows),'cases':rows,'image_sha256':hashlib.sha256(image).hexdigest()},indent=2)+'\n')
print('BG_TRANSPORT_CONTROLS_PASS',len(rows),flush=True)
