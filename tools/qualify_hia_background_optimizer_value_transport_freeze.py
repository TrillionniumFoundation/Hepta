from pathlib import Path
import ctypes as C,fcntl,hashlib,importlib.util,json,math,os,random,resource,struct,sys,time
resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.set_int_max_str_digits(0)
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');D=A/'native-background-value-transport-v1';R=A/'native-background-value-transport-freeze-v1';R.mkdir()
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

capture=m.load(A/'native-background-json-capture-v4/background_optimizer_json_capture.flat','62f62e547a346c631697a4c0ced3385afb78d6a6472a11ecad2e8c57da0faf1f')
freeze=m.load(A/'native-background-freeze-v2/background_optimizer_freeze.flat','f32bf4a811481a3baa007919710549a8e231caa3cb44c6afcb180f4c124d210d')
def decode(raw):
 s=C.create_string_buffer(raw);stats=C.create_string_buffer(64);work=C.create_string_buffer(128)
 rc=capture(s,len(raw),stats,64,work,128);assert rc==0,(rc,raw[:40])
 nodes,keys,depth,an,wn=struct.unpack_from('<5Q',stats.raw,8)
 arena=C.create_string_buffer(an);w=C.create_string_buffer(wn)
 for off,n in [(48,nodes),(56,depth),(96,keys),(104,1)]:struct.pack_into('<Q',w,off,n)
 rc=capture(s,len(raw),arena,an,w,wn);assert rc==0,(rc,raw[:40])
 return arena.raw[:m.u(arena.raw,24)]
def checked(raw,limit=4300):
 arena=decode(raw);h=struct.pack('<8s15Q',b'HIABJF01',0,0,len(raw),len(arena),limit,*([0]*10));frame=h+raw+arena
 s=C.create_string_buffer(frame);o=C.create_string_buffer(1024);w=C.create_string_buffer(max(131072,len(arena)+16384))
 rc=freeze(s,len(frame),o,len(o),w,len(w));assert rc==0,rc
 r=o.raw
 if m.u(r,8):return json.loads(r[128:128+m.u(r,32)]),[m.u(r,48),m.u(r,56)]
 n=m.u(r,24);s2=bytearray(frame);struct.pack_into('<Q',s2,8,1);s=C.create_string_buffer(bytes(s2));o=C.create_string_buffer(128+n)
 rc=freeze(s,len(s2),o,len(o),w,len(w));assert rc==0
 return o.raw[128:],None
def expected(x,limit):
 old=sys.get_int_max_str_digits();sys.set_int_max_str_digits(limit)
 try:
  try:return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode(),None
  except BaseException as e:return {'type':type(e).__name__,'message':str(e)},[e.start,e.end] if isinstance(e,UnicodeEncodeError)else None
 finally:sys.set_int_max_str_digits(old)
def case(name,x,limit=4300):
 a=make(x);raw=transmit(a);want=expected(x,limit);got=checked(raw,limit)
 assert got[0]==want[0]and(want[1]is None or got[1]==want[1]),(name,got,want)
 rows.append({'case':name,'raw_bytes':len(raw),'output_bytes':len(got[0])if type(got[0])is bytes else None,'error':got[0]if type(got[0])is dict else None,'passed':True})
 for cap in v.held[:]:v.drop(cap)
big=int('9'*4301)
special=[None,False,True,-0.0,5e-324,1.7976931348623157e308,'x\ud800y','\ud800\udc00','𐀀',{'z':big,'a':float('inf')},{'z':float('inf'),'a':big},{'a':'\ud800','z':big},{'a':'\ud800','z':float('nan')},{'a':big,'z':'\ud800'},{'\ud800':'x','z':float('inf')},{'x':'\ud800\udfff\udc00'},{'a':'\ud800','b':'\udfff'}]
for i,x in enumerate(special):case('priority-'+str(i),x)
rng=random.Random(491)
for i in range(120):
 bad=''.join(chr(rng.randrange(0xd800,0xe000))for _ in range(rng.randrange(1,6)))
 x={rng.choice(['z','a','中','😀'])+str(i):rng.choice(['é','中','😀','\0','"','\\'])+bad,'m':rng.choice([big,float('nan'),float('inf'),1.25])}
 case('transport-capture-sorted-error-'+str(i),x)
for bits in [0,1,2,(1<<52)-1,1<<52,(1023<<52),(1024<<52)-1,(2047<<52)-1,(1<<63),(1<<63)|1]+[rng.getrandbits(64)for _ in range(100)]:
 x=struct.unpack('<d',struct.pack('<Q',bits))[0];case('exact-binary64-'+hex(bits),{'z':x,'a':[x]})
for limit in (0,640,4300):
 for size in (639,640,641,4300,4301,100001):
  case('original-intdigits-'+str(limit)+'-'+str(size),{'z':'last','a':int('9'*size)},limit)
case('streamed-9MiB-string',{'z':'x'*(9<<20),'a':[1,-0.0]})
v.finish()
(R/'report.json').write_text(json.dumps({'passed':True,'whole_background_qualified':False,'groups':len(rows),'transport_calls':calls,'value_fixture_calls':v.calls,'cases':rows,'transport_sha256':hashlib.sha256(image).hexdigest()},indent=2)+'\n')
print('BG_TRANSPORT_FREEZE_PASS',len(rows),calls,flush=True)
