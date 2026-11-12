"""Development fixed mechanics for the two implementation-file native images.
No filenames, digest values, file order or open/read/close policy is selected here.
The optional intercept is test-only fault injection; ordinary runs never supply it.
Only the fixed HIACDE01 descriptor operations select buffer actions and image calls.
"""
from pathlib import Path
from hashlib import sha256
import ctypes,importlib.util,json,os,struct,sys,time,types
MAGIC=int.from_bytes(b"HIACDE01","little")
ACK=int.from_bytes(b"HIACDA01","little")
BAD=0xfffffffd
READ_TWO=frozenset()
CONTROLLERS=frozenset((1,))
HELPER=Path(__file__).resolve().with_name("function_frame_test_reference.py")
HELPER_SHA="b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
def digest(raw):return sha256(raw).hexdigest()
def load(name,path,expected=None):
 raw=Path(path).read_bytes()
 if expected:assert digest(raw)==expected
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
 exec(compile(raw,str(path),"exec"),module.__dict__);return module
def q(raw,at=0):return struct.unpack_from("<Q",raw,at)[0]
F=load("emitter_buffer_evidence_reference",HELPER,HELPER_SHA)
class Mechanical:
 def __init__(self,assets,reference,out):
  self.out=Path(out);self.out.mkdir(parents=True,exist_ok=False)
  self.evidence=F.Evidence(self.out);self.buffers=F.Buffers();self.images={};self.slots={};self.entries=0;self.calls={};self.commands=0;self.closed=False
  self.evidence.pin(__file__);self.evidence.pin(HELPER,HELPER_SHA)
  self.owned=-1;self.syscalls=0
  libc=self.buffers.libc
  libc.openat.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_int];libc.openat.restype=ctypes.c_int
  libc.read.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t];libc.read.restype=ctypes.c_ssize_t
  libc.fstat.argtypes=[ctypes.c_int,ctypes.c_void_p];libc.fstat.restype=ctypes.c_int
  libc.close.argtypes=[ctypes.c_int];libc.close.restype=ctypes.c_int
  doc=json.loads(self.evidence.pin(assets))
  assert doc["schema"]=="hia-implementation-files-runtime-assets-v1" and set(map(int,doc["roles"]))=={1,2}
  loader_path=Path(reference)/"hepta/hia_json_preflight_native.py"
  self.evidence.pin(loader_path)
  loader=load("emitter_actual_flat_loader",loader_path)
  try:
   for number,row in doc["roles"].items():
    m=row["manifest"];source=self.evidence.pin(m["source_path"],m["source_sha256"]);image=self.evidence.pin(m["image_path"],m["image_sha256"])
    assert len(source)==m["source_bytes"] and len(image)==m["image_bytes"]
    self.images[int(number)]=loader.NativeHiaJsonImage(image,expected_sha256=digest(image))
  except BaseException:
   for image in self.images.values():image._mapping.close()
   raise
 def protect(self,slot,readonly):
  b=self.slots[slot]
  if self.buffers.libc.mprotect(b["mapping"]+4096,b["middle"],1 if readonly else 3):raise OSError(ctypes.get_errno(),"mprotect")
  b["readonly"]=bool(readonly)
 def span(self,slot,at,count):
  assert type(slot) is int and 0<=slot<64 and slot in self.slots
  b=self.slots[slot]
  assert 0<=at<=b["size"] and 0<=count<=b["size"]-at
  return dict(address=b["address"]+at,size=count,readonly=b["readonly"]),b
 def read(self,slot,at,count):
  v,b=self.span(slot,at,count);self.buffers.check(b)
  return ctypes.string_at(v["address"],v["size"])
 def native(self,role,operands,parents,keys):
  number=self.entries;self.entries+=1;self.calls[role]=self.calls.get(role,0)+1
  before=[self.evidence.memory(v,k) for v,k in zip(operands,keys)]
  row=dict(number=number,role=role,status="ENTERING",before=before,capacities=[v["size"] for v in operands],readonly=[v["readonly"] for v in operands])
  self.evidence.entry(row)
  start=time.monotonic_ns();a,b,w=operands
  result=int(self.images[role]._entry(a["address"],a["size"],b["address"],b["size"],w["address"],w["size"]))
  for parent in parents:self.buffers.check(parent)
  after=[self.evidence.memory(v,k) for v,k in zip(operands,keys)]
  for i,v in enumerate(operands):
   if v["readonly"]:assert before[i]["sha256"]==after[i]["sha256"]
  event_buffer=b if role in CONTROLLERS else w
  event=ctypes.string_at(event_buffer["address"],min(event_buffer["size"],128))
  self.evidence.entry(dict(row,status="RETURNED",returned=result,after=after,event_hex=event.hex(),elapsed_ns=time.monotonic_ns()-start,canaries_intact=True))
  return result
 def release_slots(self):
  first=None
  for slot,b in tuple(self.slots.items()):
   del self.slots[slot]
   try:self.buffers.close(b)
   except BaseException as e:
    if first is None:first=e
    else:first.add_note(repr(e))
  if first:raise first
 def run(self,initial,limit=1000000,intercept=None):
  self.close_owned()
  self.release_slots()
  self.slots={0:self.buffers.allocate(0,b"",True),1:self.buffers.allocate(len(initial),initial,True),2:self.buffers.allocate(65536),3:self.buffers.allocate(128)}
  first=self.slots[1];sequence=0;lease=None
  self.last_original_ack=None;self.last_sent_ack=None;self.interceptions=0
  for step in range(limit):
   temporary=first is not self.slots[1]
   try:
    result=self.native(1,(first,self.slots[3],self.slots[2]),(first,self.slots[3],self.slots[2]),("controller-input","slot3","slot2"))
   finally:
    if temporary:self.buffers.close(first)
   event=self.read(3,0,128)
   if result==BAD:
    return dict(status="PRIVATE_BAD",returned=result,event=event,controller=self.read(2,0,65536),entries=self.entries,mechanical_steps=step)
   assert result==128
   fields=struct.unpack("<16Q",event);magic,op,current_lease,current_sequence=fields[:4];a=fields[4:]
   assert magic==MAGIC and current_lease!=0
   if lease is None:lease=current_lease
   assert current_lease==lease
   if op==7:
    assert current_sequence==sequence and self.owned<0
    assert a[2] in self.slots and self.slots[a[2]]["readonly"]
    payload=self.read(a[2],a[3],a[4])
    return dict(status="TERMINAL",returned=result,event=event,payload=payload,entries=self.entries,mechanical_steps=step)
   assert current_sequence==sequence+1;sequence=current_sequence
   returned=0;observed=b""
   if op==1:
    role,src,at,n,second,second_n,work,work_n,observe,observe_at,observe_n,reserved=a
    assert role==2 and reserved==0 and len({src,second,work})==3 and work>=4 and observe_n<=256
    first_view,first_parent=self.span(src,at,n);second_view,second_parent=self.span(second,0,second_n);work_view,work_parent=self.span(work,0,work_n)
    assert not work_parent["readonly"]
    if role not in READ_TWO:assert second>=4 and not second_parent["readonly"]
    self.span(observe,observe_at,observe_n)
    old_first=first_parent["readonly"];old_second=second_parent["readonly"]
    try:
     self.protect(src,True);first_view["readonly"]=True
     if role in READ_TWO:self.protect(second,True);second_view["readonly"]=True
     returned=self.native(role,(first_view,second_view,work_view),(first_parent,second_parent,work_parent),(str(src)+":"+str(at)+":"+str(n),str(second)+":0:"+str(second_n),str(work)+":0:"+str(work_n)))
    finally:
     self.protect(src,old_first)
     if role in READ_TWO:self.protect(second,old_second)
    observed=self.read(observe,observe_at,observe_n)
   elif op==2:
    target,size=a[:2];assert 4<=target<64 and size>0 and a[2:]==(0,)*10
    old=self.slots.get(target);old_size=0 if old is None else old["size"];assert size>old_size
    raw=b"" if old is None else self.read(target,0,old_size)
    new=self.buffers.allocate(size,raw,False);self.slots[target]=new
    self.buffers.close(old)
   elif op==3:
    target,at,n=a[:3];assert target>=4 and a[3:]==(0,)*9
    v,b=self.span(target,at,n);assert not b["readonly"];ctypes.memset(v["address"],0,n);self.buffers.check(b)
   elif op==4:
    src,at,target,to,n=a[:5];assert target>=4 and src!=target and a[5:]==(0,)*7
    v,b=self.span(target,to,n);assert not b["readonly"]
    raw=self.read(src,at,n);ctypes.memmove(v["address"],raw,n);self.buffers.check(b)
   elif op==5:
    target=a[0];assert 4<=target<64 and a[1:]==(0,)*11
    old=self.slots.pop(target);self.buffers.close(old)
   elif op==6:
    target,readonly=a[:2];assert 4<=target<64 and readonly in(0,1) and a[2:]==(0,)*10
    self.protect(target,readonly)
   elif op==14:
    src,at,n=a[:3];assert n<=256 and a[3:]==(0,)*9
    observed=self.read(src,at,n)
   elif op==19:
    returned,observed=self.syscall(a,event)
   else:raise AssertionError(("unsupported mechanical opcode",op))
   self.commands+=1
   ack=struct.pack("<8Q",ACK,lease,sequence,op,0,returned,len(observed),0)+observed
   self.evidence.entry(dict(status="MECHANICAL_ACK",event_hex=event.hex(),ack=self.evidence.raw(ack)))
   self.last_original_ack=ack
   if intercept is not None:
    changed=intercept(self,event,ack)
    assert type(changed) is bytes
    if changed!=ack:self.interceptions+=1
    ack=changed
   self.last_sent_ack=ack
   first=self.buffers.allocate(len(ack),ack,True)
  raise AssertionError("development finite event budget exhausted")

 def close_owned(self):
  if self.owned<0:return
  descriptor=self.owned;self.owned=-1
  ctypes.set_errno(0);result=self.buffers.libc.close(descriptor);error=ctypes.get_errno() if result<0 else 0
  self.evidence.entry(dict(status="PRIVATE_ABORT_FD_CLEANUP",fd=descriptor,raw_result=result,errno=error))
  if result<0:raise OSError(error,"private descriptor cleanup")
 def syscall(self,a,event):
  libc=self.buffers.libc;primitive=a[0];before=self.owned;observed=b"";payload=b""
  ctypes.set_errno(0)
  if primitive==1:
   _,source,at,n,flags,*reserved=a
   assert self.owned<0 and n>0 and flags==os.O_CLOEXEC and reserved==[0]*7
   view,parent=self.span(source,at,n);assert parent["readonly"]
   path=self.read(source,at,n);assert path[-1:]==b"\0"
   payload=path
   raw=int(libc.openat(-100,view["address"],flags));error=ctypes.get_errno() if raw<0 else 0
   if raw>=0:self.owned=raw;returned=1
   else:returned=(-error)&((1<<64)-1)
  elif primitive==2:
   _,token,target,at,n,*reserved=a
   assert self.owned>=0 and token==1 and target>=4 and n<1<<63 and reserved==[0]*7
   view,parent=self.span(target,at,n);assert not parent["readonly"]
   raw=int(libc.read(self.owned,view["address"],n));error=ctypes.get_errno() if raw<0 else 0
   returned=((-error)&((1<<64)-1)) if raw<0 else raw
   self.buffers.check(parent)
   if raw>=0:payload=self.read(target,at,raw)
  elif primitive==3:
   assert self.owned>=0 and a[1]==1 and a[2:]==(0,)*10
   descriptor=self.owned;self.owned=-1
   raw=int(libc.close(descriptor));error=ctypes.get_errno() if raw<0 else 0
   returned=((-error)&((1<<64)-1)) if raw<0 else raw
  elif primitive==4:
   _,token,target,at,n,*reserved=a
   assert self.owned>=0 and token==1 and target>=4 and n==144 and reserved==[0]*7
   view,parent=self.span(target,at,n);assert not parent["readonly"]
   ctypes.memset(view["address"],0,n)
   raw=int(libc.fstat(self.owned,view["address"]));error=ctypes.get_errno() if raw<0 else 0
   returned=((-error)&((1<<64)-1)) if raw<0 else raw
   self.buffers.check(parent);observed=self.read(target,at,n);payload=observed
  else:raise AssertionError(("unknown fixed syscall",primitive))
  self.syscalls+=1
  self.evidence.entry(dict(status="RAW_SYSCALL",number=self.syscalls,event_hex=event.hex(),
      primitive=primitive,fd_before=before,raw_result=raw,errno=error,returned=returned,
      fd_after=self.owned,full_payload=self.evidence.raw(payload)))
  return returned,observed
 def close(self):
  if self.closed:return
  self.closed=True;first=None
  try:self.close_owned()
  except BaseException as e:first=e
  try:self.release_slots()
  except BaseException as e:
   if first is None:first=e
   else:first.add_note(repr(e))
  for image in self.images.values():
   try:image._mapping.close()
   except BaseException as e:
    if first is None:first=e
    else:first.add_note(repr(e))
  result=None
  try:result=self.evidence.finish()
  except BaseException as e:
   if first is None:first=e
   else:first.add_note(repr(e))
  if first:raise first
  return result
