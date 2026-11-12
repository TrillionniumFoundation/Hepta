"""New actual six-image private digest composition, no namespace effects."""
from __future__ import annotations
import ast,ctypes,json,math,os,pathlib,resource,struct,sys,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from unittest.mock import patch
ROOT=pathlib.Path('/workspace/scratch/hia-worker-digest-next')
REF=pathlib.Path('/workspace/scratch/hia-root-r31/reference-0ef-subset')
OUT=ROOT/'development/smoke-r1'
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
sys.path.insert(0,str(REF))
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_program_tools import bounded_json_wire
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int]+[ctypes.c_ulong]*4;libc.prctl.restype=ctypes.c_int
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
M=lambda s:int.from_bytes(s,'little')
pack=lambda *w:struct.pack('<'+'Q'*len(w),*w)
GRAPH=M(b'HIAGRF01');BAD=0xfffffffd;CANARY=bytes(range(32))
source=(ROOT/'dependencies/graph_harness_r3.py').read_bytes()
assert sha256(source).hexdigest()=='75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c'
tree=ast.parse(source);capture_node=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='capture')
exec(compile(ast.Module(body=[capture_node],type_ignores=[]),'frozen-private-graph-issuer','exec'),globals())
pins={};saved=set();images={};counts={};cases=[];status='FAIL';failure=None
log=(OUT/'entries.jsonl').open('w')
def save(raw):
 key=sha256(raw).hexdigest()
 if key not in saved:
  (OUT/'cas'/(key+'.zlib')).write_bytes(zlib.compress(raw));saved.add(key)
 return dict(bytes=len(raw),sha256=key)
def frozen(path,expected=None):
 raw=path.read_bytes()
 if expected is not None:assert sha256(raw).hexdigest()==expected,(str(path),sha256(raw).hexdigest())
 pins[str(path)]=dict(bytes=len(raw),sha256=sha256(raw).hexdigest(),mode=path.stat().st_mode&4095)
 return raw
class Buffer:
 def __init__(self,size,raw=b''):
  assert size>=len(raw);self.n=size;self.memory=ctypes.create_string_buffer(size+32)
  if raw:ctypes.memmove(self.memory,raw,len(raw))
  ctypes.memmove(ctypes.addressof(self.memory)+size,CANARY,32)
 def raw(self):return ctypes.string_at(self.memory,self.n)
 def check(self):assert ctypes.string_at(ctypes.addressof(self.memory)+self.n,32)==CANARY
 def grow(self,size):
  assert size>self.n
  return Buffer(size,self.raw())
def invoke(role,s,r,w,label):
 before=(s.raw(),r.raw(),w.raw());n=counts.get(role,0)+1;counts[role]=n
 pending=dict(role=role,entry=n,label=label,s=save(before[0]),r=save(before[1]),w=save(before[2]))
 (OUT/'pending.json').write_text(json.dumps(pending,sort_keys=True)+'\n')
 ret=int(images[role]._entry(s.memory,s.n,r.memory,r.n,w.memory,w.n))
 s.check();r.check();w.check();assert s.raw()==before[0]
 if role!='sha':assert r.raw()==before[1]
 row=dict(**pending,result=ret,same_inputs=True,after_r=save(r.raw()),after_w=save(w.raw()))
 log.write(json.dumps(row,sort_keys=True)+'\n');log.flush()
 return ret
def load_images():
 reg=ROOT/'dependencies/recovered-registry'
 bundle=json.loads(frozen(reg/'bundle.json'))
 for role in ('registry','merge','scan','emit'):
  row=bundle['components'][role]
  raw=frozen(reg/(role+'.image.bin'),row['image_sha256'])
  source=frozen(reg/(role+'.input.bin'),row['source_sha256'])
  receipt=json.loads(frozen(reg/(role+'.receipt.json')))
  assert len(raw)==row['image_bytes'] and len(source)==row['source_bytes']
  assert receipt['input_sha256']==row['source_sha256'] and receipt['produced_sha256']==row['image_sha256']
  images[role]=(raw,row['image_sha256'])
 st=ROOT/'dependencies/recovered-storage'
 raw=frozen(st/'sha256_stream.image.bin','e9b0c18a52518af8d9e9909451d8174a02b7d6adc2910f8ca68d1b284a7093cb')
 frozen(st/'sha256_stream.input.bin','7fdc436867514b3d1dd741e3c3d86c0b95cc19d5b69907d5df9febf29639cb68')
 images['sha']=(raw,sha256(raw).hexdigest())
 comp=ROOT/'development/compile-r2';rec=json.loads(frozen(comp/'worker-store-wire-digest.receipt.json'))
 raw=frozen(comp/'worker-store-wire-digest.image.bin',rec['produced_sha256'])
 frozen(comp/'worker-store-wire-digest.input.bin',rec['input_sha256'])
 images['digest']=(raw,sha256(raw).hexdigest())
 for path,row in pins.items():
  assert pathlib.Path(path).read_bytes() and sha256(pathlib.Path(path).read_bytes()).hexdigest()==row['sha256']
 for role,(raw,expected) in list(images.items()):images[role]=NativeHiaJsonImage(raw,expected)
 (OUT/'source-before.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
class Registry:
 def __init__(self):
  self.g=Buffer(128,capture(None,lease=53));self.w=Buffer(8192)
  self.seq=0;self.completed=0;self.command=0
  self.step(1,digits=4300)
 def step(self,mode,payload=b'',root=0,actual=0,foreign_bytes=0,child_bytes=0,digits=0):
  if mode in (1,2,6):self.command=self.completed+1
  first=self.g.raw()
  raw=pack(M(b'HIAWGC01'),mode,37,83,self.command,self.seq,
   struct.unpack_from('<Q',first,8)[0],len(first),len(payload),actual,root,digits,53,foreign_bytes,child_bytes,0)+payload
  second=Buffer(len(raw),raw)
  ret=invoke('registry',self.g,second,self.w,'registry-'+str(mode))
  assert ret==768,(ret,struct.unpack_from('<32Q',self.w.raw(),512))
  f=struct.unpack_from('<32Q',self.w.raw(),512)
  assert f[:4]==(M(b'HIAWGE01'),f[1],37,83) and f[4]==self.seq+1
  self.seq=f[4];self.completed=f[29];self.f=f;self.r=second
  return f
 def reserve(self):
  f=self.step(2);assert f[1]==2;return self.w.raw()[512:768]
 def packet(self,foreign):
  f=self.step(3,foreign,foreign_bytes=len(foreign))
  while f[1]==1:
   self.w=self.w.grow(f[8]);f=self.step(5,foreign,foreign_bytes=len(foreign))
  assert f[1]==3
  child=Buffer(512)
  while True:
   source=self.w.raw()[f[13]:f[13]+f[14]]
   first=Buffer(len(source),source);second=Buffer(len(foreign),foreign)
   ret=invoke('merge',first,second,child,'actual-merge')
   assert ret==384
   f=self.step(4,foreign+child.raw(),actual=ret,foreign_bytes=len(foreign),child_bytes=child.n)
   if f[1]==4:
    child=child.grow(f[12]);continue
   assert f[1]==6
   raw=self.r.raw()[f[18]:f[18]+f[19]];self.g=Buffer(len(raw),raw)
   return f[21],self.w.raw()[512:768]
 def import_value(self,value):
  reserved=struct.unpack('<32Q',self.reserve())
  return self.packet(capture(value,lease=reserved[9]))[0]
 def borrow(self,handle):
  f=self.step(6,root=handle);assert f[1]==5
  return self.w.raw()[512:768],self.w.raw()[f[22]:f[22]+f[23]]
def command(g,w,op,payload=b'',actual=0,role=0,extent=0,kind=0):
 return pack(M(b'HIAWDC01'),op,37,83,909,struct.unpack_from('<Q',w.raw(),16)[0],
  struct.unpack_from('<Q',g.raw(),8)[0],g.n,len(payload),actual,role,extent,kind,53,
  struct.unpack_from('<Q',w.raw(),192)[0],0)+payload
# D_ACTION is 24*8=192 in the exact authoring state table.
def dcall(reg,w,op,payload=b'',actual=0,role=0,extent=0,kind=0,label='digest'):
 raw=command(reg.g,w,op,payload,actual,role,extent,kind)
 r=Buffer(len(raw),raw);ret=invoke('digest',reg.g,r,w,label)
 f=struct.unpack_from('<32Q',w.raw(),512)
 assert ret==768,(ret,f,struct.unpack_from('<36Q',w.raw()))
 assert f[0]==M(b'HIAWDE01') and f[2:5]==(37,83,909) and f[7]==0
 return f
def pipeline(value,expected,expected_error,label):
 before=dict(counts);reg=Registry();handle=reg.import_value(value)
 borrow,config=reg.borrow(handle);reserved=reg.reserve()
 w=Buffer(131072);f=dcall(reg,w,1,borrow+config+reserved,actual=768,role=4,extent=768)
 ww=None;so=Buffer(32);sw=Buffer(1184);last=None;grows=0
 while True:
  if f[1]==1:
   if ww is None:ww=Buffer(f[14])
   elif f[14]>ww.n:ww=ww.grow(f[14])
   raw=w.raw()[f[16]:f[16]+f[17]];second=Buffer(len(raw),raw)
   ret=invoke({1:'scan',2:'emit'}[f[13]],reg.g,second,ww,label+'-actual-wire')
   last=(ww.raw(),ret,f[13],ww.n)
   f=dcall(reg,w,2,*last,label=label+'-wire-reply')
  elif f[1]==2:
   w=w.grow(f[12]);grows+=1
   f=dcall(reg,w,4,*last,label=label+'-own-grow')
  elif f[1]==3:
   raw=w.raw()[f[16]:f[16]+f[17]];first=Buffer(len(raw),raw)
   ret=invoke('sha',first,so,sw,label+'-actual-sha')
   f=dcall(reg,w,3,so.raw()+sw.raw(),ret,3,1184,label=label+'-sha-reply')
  elif f[1]==4:
   assert expected_error is None
   wire=w.raw()[f[18]:f[18]+f[19]];digest=w.raw()[f[20]:f[20]+f[21]]
   assert wire==expected and digest==sha256(expected).digest(),label
   foreign=w.raw()[f[22]:f[22]+f[23]]
   actual_handle,event=reg.packet(foreign)
   f=dcall(reg,w,5,event,768,4,256,label=label+'-bind')
   assert f[1]==5
   reply=w.raw()[f[28]:f[28]+f[29]]
   q=struct.unpack('<32Q',reply);assert q[6]==7 and q[8]==actual_handle and reply[128:160]==digest
   break
  elif f[1]==6:
   assert expected_error is not None
   reply=w.raw()[f[28]:f[28]+f[29]];q=struct.unpack_from('<32Q',reply)
   exception=struct.unpack_from('<8Q',reply,256)
   text=reply[320:].decode()
   assert q[5]==1 and exception[0]==M(b'HIAWDX01') and exception[5]==len(reply)-320
   assert text==expected_error,(label,expected_error,text)
   assert counts.get('sha',0)==before.get('sha',0)
   wire=None;digest=None;break
  else:raise AssertionError(('unexpected-event',f))
 row=dict(label=label,status='PASS',entries={k:v-before.get(k,0) for k,v in counts.items()},own_grows=grows,
  expected_error=expected_error,wire_bytes=None if wire is None else len(wire),wire=None if wire is None else save(wire),
  digest=None if digest is None else digest.hex(),complete_native_reply=save(reply),foreign_graph_issuer=True,
  namespace_entries=0,actual_initializer_entry=False)
 cases.append(row);(OUT/'cases.json').write_text(json.dumps(cases,sort_keys=True,indent=2)+'\n')
 print(json.dumps(dict(label=label,status='PASS')),flush=True)
started=time.monotonic_ns()
try:
 load_images()
 cycle=[];cycle.append(cycle)
 values=[('none',None),('bool',True),('integer',-(1<<200)),('negative-zero',-0.0),
  ('finite',1.25),('unicode','é中🙂'),('map-order',{'z':2,'é':1,'a':3}),
  ('tuple',(1,'x',None)),('bytes',b'x'),('nan',float('nan')),('surrogate','\ud800'),('cycle',cycle)]
 for label,value in values:
  expected=None;error=None
  try:expected=bounded_json_wire(value,8388608,ensure_ascii=False,sort_keys=True)
  except Exception as exc:error=str(exc)
  with patch('hepta.hia_program_tools.bounded_json_wire',side_effect=AssertionError('host wire disabled')):
   pipeline(value,expected,error,label)
 status='PASS'
except BaseException as exc:
 failure=dict(error_class=type(exc).__name__,error=str(exc));(OUT/'failure.log').write_text(traceback.format_exc())
 traceback.print_exc()
finally:
 log.close()
 unchanged=all(pathlib.Path(p).stat().st_size==v['bytes'] and sha256(pathlib.Path(p).read_bytes()).hexdigest()==v['sha256'] for p,v in pins.items())
 summary=dict(status=status,cases=len(cases),planned_cases=12,entries=counts,total_actual_entries=sum(counts.values()),
  failure=failure,source_unchanged=unchanged,elapsed_ns=time.monotonic_ns()-started,
  scope='NEW_ACTUAL_PRIVATE_REGISTRY_WIRE_SHA_DIGEST_BIND_SIX_IMAGE_COMPOSITION',
  actual_initializer_entries=0,foreign_source_graph_issuer=True,actual_namespace_entries=0,
  limits=dict(cpu_seconds=90,address_space_bytes=1<<30),ordinary_worker_closed=False)
 (OUT/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
 print(json.dumps(summary,sort_keys=True),flush=True)
 for obj in images.values():
  if isinstance(obj,NativeHiaJsonImage):obj._mapping.close()
 assert unchanged
if status!='PASS':raise SystemExit(1)
