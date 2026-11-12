"""New fixed nine-role UnixOpen transport; no Python completion issuer.

The immutable base owns subprocess limits, watchdog, actual PID/executable
binding, kill/wait4 and unconditional FD cleanup. This adapter adds only boot
observation and the two original-USER transport envelopes. It never supplies
a parent ACK, completed capsule, framer peer or raw descriptor capability.
"""
from __future__ import annotations
import hashlib,json,struct,time,types,sys
from pathlib import Path
BASE_GIT="c489da3fc832d9caecaa271069bfc3608746ffec"
BASE_SHA="e5cad29b23957856c3a3ae08645eb7a14a62f6b0263fe67720a9560b88e58270"
BASE_BYTES=22281
BASE_PATH=Path(__file__).with_name("namespace-db-join-r1-client.py")
base_raw=BASE_PATH.read_bytes()
assert (len(base_raw),hashlib.sha256(base_raw).hexdigest(),
 hashlib.sha1(b"blob "+str(len(base_raw)).encode()+b"\0"+base_raw).hexdigest())==(BASE_BYTES,BASE_SHA,BASE_GIT)
base=types.ModuleType("namespace_unixopen_actual_transport_base")
base.__file__=str(BASE_PATH);sys.modules[base.__name__]=base
exec(compile(base_raw,str(BASE_PATH),"exec"),base.__dict__)
LIMITS=base.LIMITS
frame=base.frame
save=base.save
sha=base.sha
def magic(value):return int.from_bytes(value,"little")
BOOT=magic(b"HIAUIB01")
TRANSPORT=magic(b"HIAUIP01")
PARENT=magic(b"HIANUO01")
BAD=0xfffffffd

def envelope(kind,raw):
 raw=bytes(raw)
 assert kind in (1,2)
 return struct.pack("<8Q",TRANSPORT,kind,len(raw),0,0,0,0,0)+raw

class Carrier(base.Carrier):
 def __init__(self,executable,output,cwd,*,session=(71,83),initialize=True,launcher=()):
  self.boot=None
  super().__init__(executable,output,cwd,session=session,initialize=False,launcher=launcher)
  try:
   deadline=min(self.deadline,time.monotonic()+LIMITS["request_wall_seconds"])
   length=struct.unpack("<Q",self._read(8,deadline))[0]
   assert length==64,("actual boot extent",length)
   raw=self._read(length,deadline)
   (self.output/"boot.bin").write_bytes(raw)
   fields=struct.unpack("<8Q",raw)
   pid=self._bind_native_identity()
   assert fields==(BOOT,pid,6,7,8,9,1,4096),fields
   self.boot=dict(actual_process=pid,shared_FS=6,parent=7,framer=8,issuer=9,
    generation=1,page_bytes=4096,raw_sha256=sha(raw),
    observation_only_not_transferable_authority=True)
   save(self.output/"boot.json",self.boot)
   if initialize:
    h,_=self.request(frame(1,session=session,a=171,b=183),label="initialize")
    assert h[1]==0 and h[4]==0 and h[5]==1
    assert h[6:8]==(0,0) and h[15]==h[17]==0 and h[22]==1
  except BaseException as error:
   try:self.abort()
   except BaseException as cleanup:error.add_note("actual issuer construction cleanup: "+repr(cleanup))
   raise

 def _exchange(self,wire,raw,kind,label,*,expected_magic):
  assert not self.completed
  wire,raw=bytes(wire),bytes(raw)
  index=len(self.requests)
  directory=self.output/"requests"/str(index);directory.mkdir(parents=True)
  (directory/"input.bin").write_bytes(raw)
  (directory/"transport.bin").write_bytes(wire)
  row=dict(index=index,label=label,transport_kind=kind,input_bytes=len(raw),
   input_sha256=sha(raw),transport_bytes=len(wire),transport_sha256=sha(wire),
   status="INCOMPLETE")
  self.requests.append(row)
  save(directory/"result.json",row);save(self.output/"requests.json",self.requests)
  start=time.monotonic_ns()
  try:
   deadline=min(self.deadline,time.monotonic()+LIMITS["request_wall_seconds"])
   self._write(struct.pack("<Q",len(wire))+wire,deadline)
   capacity=struct.unpack("<Q",self._read(8,deadline))[0]
   # Finite test recording safety only; not a production namespace quota.
   assert 256<=capacity<=16<<20,("fixture response extent",capacity)
   output=self._read(capacity,deadline)
   (directory/"output.bin").write_bytes(output)
   h=struct.unpack_from("<32Q",output)
   assert h[0]==expected_magic,(label,h)
   assert h[16]<=len(output)-256
   if kind==1:
    assert h[1] in (0,BAD) and h[22]==1 and not any(h[26:])
   elif kind==2:
    assert h[1] in (0,1,BAD)
   else:raise AssertionError("normal exchange requires one original USER kind")
   row.update(status="COMPLETE",output_bytes=len(output),output_sha256=sha(output),
    header=list(h),elapsed_ns=time.monotonic_ns()-start)
   save(directory/"result.json",row);save(self.output/"requests.json",self.requests)
   return h,output[256:256+h[16]]
  except BaseException as error:
   row.update(status="FAIL",error_class=type(error).__name__,error=str(error),
    elapsed_ns=time.monotonic_ns()-start)
   for path,value in ((directory/"result.json",row),(self.output/"requests.json",self.requests)):
    try:save(path,value)
    except BaseException as secondary:error.add_note("request evidence "+str(path)+": "+repr(secondary))
   raise

 def request(self,raw,*,label="request"):
  return self._exchange(envelope(1,raw),raw,1,label,expected_magic=base.MAGIC)

 def parent_begin(self,raw,*,label="parent-BEGIN"):
  # The fixed executable, not this fixture, copies and sets actual PID.
  return self._exchange(envelope(2,raw),raw,2,label,expected_magic=PARENT)

 def invalid_transport(self,raw,*,label="invalid-transport",expected_exit=110):
  """Explicit mechanical rejection control, never used as a valid ACK route."""
  assert not self.completed
  raw=bytes(raw);index=len(self.requests)
  directory=self.output/"requests"/str(index);directory.mkdir(parents=True)
  (directory/"input.bin").write_bytes(raw);(directory/"transport.bin").write_bytes(raw)
  row=dict(index=index,label=label,transport_kind="EXPLICIT_INVALID",
   input_bytes=len(raw),input_sha256=sha(raw),transport_bytes=len(raw),
   transport_sha256=sha(raw),status="INCOMPLETE")
  self.requests.append(row);save(directory/"result.json",row)
  save(self.output/"requests.json",self.requests)
  deadline=min(self.deadline,time.monotonic()+LIMITS["request_wall_seconds"])
  self._write(struct.pack("<Q",len(raw))+raw,deadline)
  try:
   observed=self._read(8,deadline)
  except EOFError:
   row["status"]="EXPECTED_TRANSPORT_REFUSAL"
   self.expected_exit=expected_exit
   save(directory/"result.json",row);save(self.output/"requests.json",self.requests)
   return self.finish(expected_exit)
  raise AssertionError(("invalid private transport unexpectedly returned a frame",observed.hex()))

 def finish(self,expected_exit=0):
  if self.completed:
   assert self.process.returncode==expected_exit
   return None
  result=super().finish(expected_exit)
  assert 0<=result["usage"]["user"]+result["usage"]["system"]<90,result
  assert 0<=result["elapsed_ns"]<180_000_000_000,result
  assert BASE_PATH.read_bytes()==base_raw
  save(self.output/"actual-issuer-process.json",dict(result,
   scope="NEW_LIVE_NATIVE_ISSUER_PROCESS_NO_HOST_COMPLETION_PROVIDER",
   boot=self.boot,base_client_git=BASE_GIT,base_client_sha256=BASE_SHA,
   no_external_ACK_or_capsule_route=True,non_raw_UnixOpen_peers_closed=False,
   original_parent_BEGIN_is_private_predecessor=True,ordinary_Store_closed=False))
  return result
