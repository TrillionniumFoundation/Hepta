from pathlib import Path
import ctypes as C,fcntl,hashlib,importlib.util,json,math,os,random,resource,struct,sys,time
resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.set_int_max_str_digits(0)
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');D=A/'native-background-value-transport-v1';R=A/'native-background-value-transport-smoke-v1';R.mkdir()
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
cases=[None,False,True,0,-1,10**100,-0.0,0.0,1.0,1e300,5e-324,float('nan'),float('inf'),float('-inf'),'','a\0\n\t"\\','\ud800','\ud800\udc00','𐀀','a\udfff🙂',[],{},[1,{'z':'\ud800','a':float('inf')},[2,3]],{'z':1,'a':2,'odd\ud800':'value'}]
for i,x in enumerate(cases):
 a=make(x);raw=transmit(a);y=json.loads(raw)
 assert equivalent(x,y),(i,repr(x),repr(y),raw[:100])
 rows.append({'case':i,'bytes':len(raw),'passed':True})
 print('BG_TRANSPORT_SMOKE',i,len(raw),flush=True)
rng=random.Random(992)
for i in range(300):
 bits=rng.getrandbits(64);x=struct.unpack('<d',struct.pack('<Q',bits))[0];a=v.scalar(x);raw=transmit(a);y=json.loads(raw)
 assert equivalent(x,y),(i,bits,raw)
 v.drop(a)
rows.append({'case':'300-binary64-bit-patterns','passed':True})
a=make({'big':'x'*(9*1024*1024),'after':123});raw=transmit(a);assert json.loads(raw)=={'big':'x'*(9*1024*1024),'after':123};rows.append({'case':'9MiB-string-stream','passed':True})
a=v.take(v.call(2,arg0=2,tail=b'9'*100001));raw=transmit(a);assert raw==b'9'*100001;rows.append({'case':'100001-int-digits-no-conversion-policy','passed':True})
a=v.empty(list);v.call(16,a,a);transmit(a,3);rows.append({'case':'actual-cycle-refusal-and-cleanup','passed':True})
a=v.empty(dict);v.call(10,a,v.scalar(3),v.scalar(4));transmit(a,2);rows.append({'case':'private-nonstrkey-refusal-and-cleanup','passed':True})
a=v.scalar(b'bytes');transmit(a,2);rows.append({'case':'private-bytes-refusal-and-cleanup','passed':True})
v.finish();assert m.u(ctx.raw,32)==m.u(ctx.raw,40)==m.u(ctx.raw,64)==0
report={'passed':True,'whole_background_qualified':False,'groups':len(rows),'transport_calls':calls,'value_fixture_calls':v.calls,'rows':rows,'image_sha256':hashlib.sha256(image).hexdigest()}
(R/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_TRANSPORT_SMOKE_PASS',len(rows),calls,flush=True)
