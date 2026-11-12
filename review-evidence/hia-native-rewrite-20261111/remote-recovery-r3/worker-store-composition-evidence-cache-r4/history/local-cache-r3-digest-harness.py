"""Private actual-image routing for the new digest peer. NEW CI revision.

Derived from the exact first smoke harness; it remains mechanical development
routing with an explicit controlled Graph issuer, not the fixed Worker.
"""
from __future__ import annotations
import ast,ctypes,json,math,os,pathlib,resource,struct,sys,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from unittest.mock import patch
ROOT=pathlib.Path(os.environ['HIA_DIGEST_ROOT']).resolve()
REF=pathlib.Path(os.environ['HIA_WORKER_REFERENCE']).resolve()
OUT=None
sys.path.insert(0,str(REF))
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_program_tools import bounded_json_wire
M=lambda s:int.from_bytes(s,'little')
pack=lambda *w:struct.pack('<'+'Q'*len(w),*w)
GRAPH=M(b'HIAGRF01');BAD=0xfffffffd;CANARY=bytes(range(32))
source=(ROOT/'dependencies/graph_harness_r3.py').read_bytes()
assert sha256(source).hexdigest()=='75fe54554a93e19e30251073ac225deff944d6673d87ccc2b597e47a19e8be7c'
tree=ast.parse(source);capture_node=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='capture')
exec(compile(ast.Module(body=[capture_node],type_ignores=[]),'frozen-private-graph-issuer','exec'),globals())
pins={};saved=set();images={};counts={};cases=[];status='FAIL';failure=None
log=None
# Immutable byte-content cache: equality is checked before reusing a prior
# content-addressed identity. This changes only evidence encoding work.
cache=[]
cache_bytes=0
def save(raw):
 global cache_bytes
 for at in range(len(cache)-1,-1,-1):
  previous,key=cache[at]
  if len(previous)==len(raw) and raw==previous:
   cache.append(cache.pop(at))
   return dict(bytes=len(raw),sha256=key)
 key=sha256(raw).hexdigest()
 if key not in saved:
  (OUT/'cas'/(key+'.zlib')).write_bytes(zlib.compress(raw,1));saved.add(key)
 if len(raw)<=64*1024*1024:
  cache.append((raw,key));cache_bytes+=len(raw)
  while len(cache)>12 or cache_bytes>64*1024*1024:
   removed,_=cache.pop(0);cache_bytes-=len(removed)
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
 sha_receipt=json.loads(frozen(st/'sha256_stream.receipt.json'))
 assert sha_receipt['image_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
 assert sha_receipt['input_sha256']=='7fdc436867514b3d1dd741e3c3d86c0b95cc19d5b69907d5df9febf29639cb68'
 assert sha_receipt['produced_sha256']==sha256(raw).hexdigest()
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

def same():
 return all(pathlib.Path(p).stat().st_size==v['bytes'] and pathlib.Path(p).stat().st_mode&4095==v['mode'] and sha256(pathlib.Path(p).read_bytes()).hexdigest()==v['sha256'] for p,v in pins.items())
def setup(output,extra_roles=()):
 global OUT,log
 OUT=pathlib.Path(output);OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
 log=(OUT/'entries.jsonl').open('w')
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 libc=ctypes.CDLL(None,use_errno=True);libc.prctl.argtypes=[ctypes.c_int]+[ctypes.c_ulong]*4;libc.prctl.restype=ctypes.c_int
 assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
 load_images()
 reg=ROOT/'dependencies/recovered-registry';bundle=json.loads(frozen(reg/'bundle.json'))
 for role in extra_roles:
  assert role not in images
  row=bundle['components'][role]
  image=frozen(reg/(role+'.image.bin'),row['image_sha256'])
  source=frozen(reg/(role+'.input.bin'),row['source_sha256'])
  receipt=json.loads(frozen(reg/(role+'.receipt.json')))
  assert len(image)==row['image_bytes'] and len(source)==row['source_bytes']
  assert receipt['input_sha256']==row['source_sha256'] and receipt['produced_sha256']==row['image_sha256']
  assert receipt['image_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
  images[role]=NativeHiaJsonImage(image,row['image_sha256'])
 for p in (pathlib.Path(__file__),*ROOT.joinpath('tools').glob('*.py')):frozen(p)
 assert same()
 (OUT/'source-before.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
def close():
 if log is not None:log.close()
 if OUT is not None:(OUT/'source-after.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
 for image in images.values():
  if isinstance(image,NativeHiaJsonImage):image._mapping.close()
 assert same()
class InitialRegistry(Registry):
 def __init__(self,paths):
  raw=capture(['/state',list(paths)],lease=53)
  self.g=Buffer(len(raw),raw);self.original=self.g;self.w=Buffer(8192)
  self.seq=0;self.completed=0;self.command=0
  f=self.step(1,digits=4300)
  assert f[1]==0 and f[22:24]==(1024,192)
  self.initial_config=self.w.raw()[1024:1216]
class Route:
 def __init__(self,reg,handle,initializer_event=None,capture_steps=False,label='digest'):
  self.reg=reg;self.label=label;self.w=Buffer(131072);self.ww=None
  self.so=Buffer(32);self.sw=Buffer(1184);self.last=None
  self.records=[];self.capture_steps=capture_steps;self.own_grows=0;self.peer_grows=0
  self.sha_calls=0;self.producer_calls=0;self.reply=None;self.handle=None
  borrow,config=reg.borrow(handle);reserved=reg.reserve()
  self.begin_payload=borrow+config+reserved+(initializer_event or b'')
  self.call(1,self.begin_payload,768,4,768,1 if initializer_event is not None else 0)
 def call(self,op,payload=b'',actual=0,role=0,extent=0,kind=0):
  raw=command(self.reg.g,self.w,op,payload,actual,role,extent,kind)
  before=self.w.raw();second=Buffer(len(raw),raw)
  ret=invoke('digest',self.reg.g,second,self.w,self.label+'-digest-'+str(op))
  f=struct.unpack_from('<32Q',self.w.raw(),512)
  if self.capture_steps:self.records.append(dict(op=op,phase=struct.unpack_from('<Q',before,8)[0],
    source=self.reg.g.raw(),command=raw,workspace=before,result=ret,after=self.w.raw(),event=f))
  assert ret==768,(ret,f,struct.unpack_from('<36Q',self.w.raw()))
  assert f[0]==M(b'HIAWDE01') and f[2:5]==(37,83,909) and f[7]==0
  self.f=f;return f
 def step(self):
  f=self.f
  if f[1]==1:
   if self.ww is None:self.ww=Buffer(f[14])
   elif f[14]>self.ww.n:self.ww=self.ww.grow(f[14]);self.peer_grows+=1
   raw=self.w.raw()[f[16]:f[16]+f[17]];second=Buffer(len(raw),raw)
   ret=invoke({1:'scan',2:'emit'}[f[13]],self.reg.g,second,self.ww,self.label+'-actual-wire')
   self.producer_calls+=1;self.last=(self.ww.raw(),ret,f[13],self.ww.n)
   return self.call(2,*self.last)
  if f[1]==2:
   self.w=self.w.grow(f[12]);self.own_grows+=1
   return self.call(4,*self.last)
  if f[1]==3:
   raw=self.w.raw()[f[16]:f[16]+f[17]];first=Buffer(len(raw),raw)
   ret=invoke('sha',first,self.so,self.sw,self.label+'-actual-sha')
   self.sha_calls+=1
   return self.call(3,self.so.raw()+self.sw.raw(),ret,3,1184)
  if f[1]==4:
   foreign=self.w.raw()[f[22]:f[22]+f[23]]
   self.handle,event=self.reg.packet(foreign)
   return self.call(5,event,768,4,256)
  assert f[1] in (5,6),f
  self.reply=self.w.raw()[f[28]:f[28]+f[29]]
  return None
 def finish(self):
  while self.step() is not None:pass
  return self.reply
 def validate(self,expected,error):
  f=self.f;reply=self.reply
  assert reply is not None
  q=struct.unpack_from('<32Q',reply)
  if error is not None:
   assert f[1]==6 and q[5]==1 and self.sha_calls==0
   exception=struct.unpack_from('<8Q',reply,256)
   assert exception[0]==M(b'HIAWDX01') and exception[5]==len(reply)-320
   assert reply[320:].decode()==error,(error,reply[320:])
   return
  assert f[1]==5 and q[5:7]==(0,7) and q[8]==self.handle
  wire=self.w.raw()[f[18]:f[18]+f[19]];digest=self.w.raw()[f[20]:f[20]+f[21]]
  assert wire==expected and digest==sha256(expected).digest()
  assert reply[128:160]==digest
  assert self.sha_calls==2+(len(wire)+65535)//65536
  actual_graph=self.w.raw()[f[22]:f[22]+f[23]]
  assert len(actual_graph)==192 and struct.unpack_from('<8Q',actual_graph,64)==(4,128,64,0,0,0,64,0)
  assert actual_graph[128:]==digest.hex().encode()
