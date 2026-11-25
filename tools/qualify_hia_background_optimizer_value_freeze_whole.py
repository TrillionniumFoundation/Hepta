from pathlib import Path
import ctypes as C,hashlib,importlib.util,json,math,os,random,resource,struct,sys,time
resource.setrlimit(resource.RLIMIT_CORE,(0,0));sys.set_int_max_str_digits(0)
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');W=A/'native-background-source';T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');D=A/'native-background-value-freeze-v3';R=A/'native-background-value-freeze-whole-v1';R.mkdir();sys.path.insert(0,str(W))
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
big=int('9'*4301)
atoms=[None,False,True,-1,10**100,-0.0,5e-324,1.7976931348623157e308,'\ud800','\ud800\udc00','𐀀',float('inf'),float('-inf'),float('nan'),[],{},['x',{'z':3,'a':2}]]
for i,x in enumerate(atoms):case('atoms-'+str(i),x)
priority=[{'z':big,'a':float('inf')},{'z':float('inf'),'a':big},{'a':'\ud800','z':big},{'a':'\ud800','z':float('nan')},{'a':big,'z':'\ud800'},{'\ud800':'x','z':float('inf')},{'x':'\ud800\udfff\udc00'},{'a':'\ud800','b':'\udfff'}]
for i,x in enumerate(priority):case('ordered-errors-'+str(i),x)
rng=random.Random(8744)
for i in range(100):
 bad=''.join(chr(rng.randrange(0xd800,0xe000))for _ in range(rng.randrange(1,5)))
 x={rng.choice(['a','z','中','😀'])+str(i):rng.choice(['é','中','😀','\0','"','\\'])+bad,'m':rng.choice([big,float('nan'),float('inf'),1.25])}
 case('real-sorted-error-'+str(i),x)
for i in range(80):
 bits=rng.getrandbits(64);x=struct.unpack('<d',struct.pack('<Q',bits))[0];case('binary64-'+hex(bits),{'z':x,'a':[x]})
for limit in(0,640,4300):
 for n in(639,640,641,4300,4301,100001):case('digits-'+str(limit)+'-'+str(n),{'a':int('9'*n)},limit)
case('actual-stream-map-freeze-9MiB',{'z':'x'*(9<<20),'a':1})
case('wide-5001-values',list(range(5001)))
# Returned payload is detached from all later changes to the original value.
struct.pack_into('<Q',ctx,80,4300);a=make({'z':{'counter':1},'a':2});r,_=call(a);assert m.u(r,8)==0;c=struct.unpack_from('<3Q',r,16);expected=b'{"a":2,"z":{"counter":1}}'
v.call(10,a,v.scalar('new'),v.scalar('later'));assert payload.copy(c,0,len(expected))==expected
for cap in v.held[:]:v.drop(cap)
assert payload.copy(c,0,len(expected))==expected;payload.drop(c);rows.append({'case':'all-input-refs-freed-detached-payload-live','passed':True})
v.finish();payload.run(5)
report={'passed':True,'whole_background_qualified':False,'component':'actual value -> native lossless stream -> native capture -> native checked freezer -> actual immutable payload','groups':len(rows),'native_whole_calls':calls,'value_fixture_calls':v.calls,'payload_fixture_calls':payload.calls,'image_sha256':pin,'cases':rows}
(R/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_VALUE_FREEZE_WHOLE_PASS',len(rows),calls,flush=True)
