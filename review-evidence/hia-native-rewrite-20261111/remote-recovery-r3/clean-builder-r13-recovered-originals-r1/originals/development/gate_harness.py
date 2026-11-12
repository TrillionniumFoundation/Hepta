"""Development-only mechanical fixed-peer runner, no gate policy in Python."""
from pathlib import Path
from hashlib import sha256
import ctypes,json,struct,time,zlib
BASE=Path('/workspace/scratch/9acdfa9f5639')
BAD=(1<<32)-3;GROW=(1<<32)-2
class Evidence:
 def __init__(self,path):
  self.path=Path(path);self.path.mkdir(parents=True,exist_ok=False);self.cas=self.path/'raw';self.cas.mkdir();self.ledger=(self.path/'entries.jsonl').open('xb');self.entries=0
 def buffer(self,b):
  b=bytes(b);h=sha256(b).hexdigest();p=self.cas/(h+'.zlib')
  if not p.exists():p.write_bytes(zlib.compress(b,3));assert zlib.decompress(p.read_bytes())==b
  return dict(bytes=len(b),sha256=h,storage=p.name,compression='zlib')
 def call(self,label,image,s,r,w,second_write=False):
  before=bytes(w);rb=bytes(r);sb=bytes(s);source=ctypes.create_string_buffer(sb,max(1,len(sb)));second=ctypes.create_string_buffer(rb,max(1,len(rb)))
  start=time.perf_counter_ns();ret=int(image._entry(source,len(sb),second,len(rb),w,len(w)));elapsed=time.perf_counter_ns()-start
  assert ctypes.string_at(source,len(sb))==sb
  if not second_write:assert ctypes.string_at(second,len(rb))==rb
  row=dict(label=label,return_value=ret,native_elapsed_ns=elapsed,first=self.buffer(sb),second_before=self.buffer(rb),work_before=self.buffer(before),work_after=self.buffer(bytes(w)),second_after=self.buffer(ctypes.string_at(second,len(rb))))
  self.ledger.write((json.dumps(row,sort_keys=True)+'\n').encode());self.ledger.flush();self.entries+=1
  return ret,ctypes.string_at(second,len(rb))
 def close(self):self.ledger.close()
def load(path,evidence):
 from hepta.hia_json_preflight_native import NativeHiaJsonImage
 p=Path(path);raw=p.read_bytes();m=json.loads(raw);assert m['schema']=='hepta.hia.clean-build-development.v1'
 sp=Path(m['source_path']);ip=Path(m['image_path']);source=sp.read_bytes();image=ip.read_bytes()
 assert sha256(source).hexdigest()==m['source_sha256'] and sha256(image).hexdigest()==m['image_sha256']
 for role,data in [('manifest',raw),('source',source),('image',image)]:
  f=evidence.path/(p.stem+'.'+role);f.write_bytes(data)
 obj=NativeHiaJsonImage(image,m['image_sha256'])
 assert p.read_bytes()==raw and sp.read_bytes()==source and ip.read_bytes()==image
 return obj,[(p,raw),(sp,source),(ip,image)]
def decode_native(evidence,decoder,wire):
 from hepta.hia_json_decode_native import arena_sizes
 outsz,worksz=arena_sizes(len(wire),1048576,128);w=ctypes.create_string_buffer(worksz);struct.pack_into('<QQ',w,48,1048576,128)
 ret,out=evidence.call('actual-agent-data-json',decoder,wire,bytes(outsz),w,True)
 if ret>=4294967292:return ret,b''
 assert 0<ret<=outsz
 return ret,out[:ret]
def run(evidence,gate,decoder,packet,initial=8192):
 w=ctypes.create_string_buffer(initial);reply=b'';last=0;transitions=[]
 while True:
  before=bytes(w);ret,_=evidence.call('actual-clean-build-gate',gate,packet,reply,w)
  event=struct.unpack_from('<16Q',w,1024);transitions.append(dict(return_value=ret,event=list(event),workspace_bytes=len(w)))
  if ret==BAD:return dict(status='BAD',event=list(event),transitions=transitions),bytes(w)
  assert event[0]==int.from_bytes(b'HIABBE01','little')
  if ret==GROW:
   assert event[1]==2 and event[5]>len(w);nw=ctypes.create_string_buffer(event[5]);ctypes.memmove(nw,w,len(w));w=nw;continue
  assert ret==128
  if event[1] in (0,3):return dict(status='PASS' if event[1]==0 else 'REFUSED',event=list(event),transitions=transitions),bytes(w)
  assert event[1]==1 and event[2]==last+1;last=event[2];off,size=event[3:5];assert off<=len(packet) and size<=len(packet)-off
  result,arena=decode_native(evidence,decoder,packet[off:off+size]);reply=struct.pack('<8Q',int.from_bytes(b'HIABRP01','little'),last,1,result,len(arena),0,0,0)+arena
