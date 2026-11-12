"""Fresh-process two-role implementation-file mechanics and original evidence.
The HIA owner chooses filenames, order, error policy and SHA updates. This
adapter only starts the fixed syscall/image carrier and validates its full
actual trace. Python full-CAS runs separately cover intermediate buffers;
that stronger evidence is never attributed to this final-buffer carrier.
"""
from pathlib import Path
from hashlib import sha256
import json,lzma,os,signal,stat,struct,subprocess,time,traceback
MASK=(1<<64)-1
BAD=0xfffffffd
C_SOURCE_SHA="0886ad565d13beb22e62e81652ba98b68e83bf841d4f9f8048c1f27d77de533b"
def digest(raw):return sha256(raw).hexdigest()
def read_exact(stream,count):
 out=bytearray()
 while len(out)<count:
  chunk=stream.read(count-len(out))
  if not chunk:raise ValueError("truncated exact carrier evidence")
  out.extend(chunk)
 return bytes(out)
def file_hash(path):
 h=sha256();n=0
 with Path(path).open("rb") as f:
  while True:
   b=f.read(1<<20)
   if not b:break
   h.update(b);n+=len(b)
 return dict(bytes=n,sha256=h.hexdigest())
def save(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def encode_closed_evidence(paths,directory):
 """Only after the caller finished comparisons and no file handle remains open.
 Keep raw on any compression/readback/manifest failure. Retire only the exact
 new-harness temporary files after all encoded originals are independently read.
 """
 wall=time.monotonic();cpu=time.process_time();rows=[]
 for path in paths:
  path=Path(path);info=path.lstat()
  assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
  original=file_hash(path);encoded=path.with_name(path.name+".xz")
  assert not encoded.exists()
  with path.open("rb") as src,lzma.open(encoded,"xb",format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC64,preset=3) as dst:
   while True:
    block=src.read(1<<18)
    if not block:break
    dst.write(block)
  encoded.chmod(stat.S_IMODE(info.st_mode))
  decoded=sha256();length=0
  with path.open("rb") as src,lzma.open(encoded,"rb") as dec:
   while True:
    block=src.read(1<<18);other=dec.read(len(block) if block else 1)
    assert block==other,"encoded original differs from actual complete raw bytes"
    if not block:break
    length+=len(block);decoded.update(block)
  now=path.lstat()
  assert (now.st_dev,now.st_ino,now.st_mode,now.st_size)==(info.st_dev,info.st_ino,info.st_mode,info.st_size)
  assert dict(bytes=length,sha256=decoded.hexdigest())==original
  assert file_hash(path)==original and stat.S_IMODE(encoded.stat().st_mode)==stat.S_IMODE(info.st_mode)
  rows.append(dict(raw_path=str(path),raw=original,raw_mode=stat.S_IMODE(info.st_mode),
      encoded_path=str(encoded),encoded=file_hash(encoded),encoded_mode=stat.S_IMODE(encoded.stat().st_mode),
      compression="xz-crc64-preset3",all_decoded_bytes_compared_to_actual_raw=True,
      decoded=dict(bytes=length,sha256=decoded.hexdigest())))
 receipt=dict(schema="hia-complete-raw-lossless-encoding-v1",rows=rows,
     full_effective_extents_retained=True,no_target_entry_during_encoding=True,
     wall_seconds=time.monotonic()-wall,cpu_seconds=time.process_time()-cpu)
 manifest=Path(directory)/"exact-raw-encoding.json"
 save(manifest,receipt)
 assert json.loads(manifest.read_bytes())==receipt
 # Every original remains until all rows and the complete manifest passed.
 for row in rows:
  path=Path(row["raw_path"])
  assert file_hash(path)==row["raw"] and stat.S_IMODE(path.stat().st_mode)==row["raw_mode"]
  path.unlink()
 return receipt
def trace_records(path):
 with Path(path).open("rb") as f:
  while True:
   head=f.read(16)
   if not head:return
   if len(head)!=16:raise ValueError("truncated carrier record")
   kind,n=struct.unpack("<2Q",head)
   if kind not in range(1,12):raise ValueError("unknown carrier evidence record")
   # A trace is issued by this fixed child. Bound by the complete file extent,
   # not by a public Graph or JSON policy.
   if n>os.fstat(f.fileno()).st_size-f.tell():raise ValueError("record extent")
   yield kind,read_exact(f,n)
def signed(value):return value if value<1<<63 else value-(1<<64)
def validate_trace(path,assets,initial):
 counts={1:0,2:0};image_seen=set();limits=None;input_seen=False
 current=None;last_return=None;pending=None;last_ack=True;commands=0;terminal=None
 raw_call=None;payload_seen=False;syscalls=0;owned=-1;cleanup_seen=False;lease=None
 for kind,raw in trace_records(path):
  if kind==8:
   assert limits is None and len(raw)==64 and not image_seen
   limits=struct.unpack("<8Q",raw);assert limits==(90,90,1<<30,1<<30,0,0,180,4096)
  elif kind==1:
   assert limits and not input_seen and len(raw)>=16
   role,n=struct.unpack_from("<2Q",raw);assert role not in image_seen and role in counts and n==len(raw)-16
   m=assets["roles"][str(role)]["manifest"];assert n==m["image_bytes"] and digest(raw[16:])==m["image_sha256"]
   assert raw[16:]==Path(m["image_path"]).read_bytes()
   image_seen.add(role)
  elif kind==2:
   assert image_seen==set(counts) and not input_seen and raw==initial
   input_seen=True
  elif kind==3:
   assert input_seen and terminal is None and current is None and len(raw)==128
   v=struct.unpack("<16Q",raw);serial,role=v[:2]
   assert role in counts and serial==sum(counts.values())+1 and v[9:12]==(1,0,0) and v[12:]==(0,)*4
   if role==1:
    assert pending is None and last_ack and v[5:9]==(3,128,2,65536)
    assert v[2] in(1,64) and v[3]==0
   else:
    assert pending is not None and pending[1]==1 and pending[4]==2
    assert v[2:9]==(pending[5],pending[6],pending[7],pending[8],pending[9],pending[10],pending[11])
   current=v;counts[role]+=1
  elif kind==4:
   assert current is not None and len(raw)>=32
   serial,role,returned,n=struct.unpack_from("<4Q",raw)
   assert (serial,role)==current[:2] and n==len(raw)-32 and n==min(128,current[6] if role==1 else current[8])
   last_return=(role,returned,raw[32:]);current=None
  elif kind==5:
   assert current is None and pending is None and terminal is None
   assert last_return is not None and last_return[0:2]==(1,128) and raw==last_return[2] and len(raw)==128
   pending=struct.unpack("<16Q",raw)
   assert pending[0]==int.from_bytes(b"HIACDE01","little") and pending[1] in(1,2,3,4,5,6,14,19)
   if lease is None:lease=pending[2]
   assert pending[2]==lease and lease!=0 and pending[3]==commands+1
   commands+=1;last_ack=False;raw_call=None;payload_seen=False
  elif kind==9:
   assert pending is not None and pending[1]==19 and raw_call is None and len(raw)==64
   number,sequence,primitive,before,result,error,answer,after=struct.unpack("<8Q",raw)
   assert number==syscalls+1 and sequence==pending[3] and primitive==pending[4] and primitive in(1,2,3,4)
   assert signed(before)==owned and error<=4095
   actual=signed(result);next_owned=signed(after)
   if actual<0:
    assert actual==-1 and error>0 and answer==(-error)&MASK
   else:
    assert error==0 and answer==(1 if primitive==1 else actual)
   if primitive==1:
    assert owned==-1 and next_owned==(actual if actual>=0 else -1)
   elif primitive==3:
    assert owned>=0 and next_owned==-1 and actual in(-1,0)
   else:
    assert owned>=0 and next_owned==owned
    if primitive==2:assert actual==-1 or 0<=actual<=pending[8]
    else:assert actual in(-1,0)
   owned=next_owned;syscalls+=1;raw_call=(primitive,actual,error,answer);payload_seen=False
  elif kind==11:
   assert pending is not None and pending[1]==19 and raw_call is not None and not payload_seen
   primitive,actual,error,answer=raw_call
   if primitive==1:assert len(raw)==pending[7] and raw[-1:]==b"\0"
   elif primitive==2:assert len(raw)==max(0,actual)
   elif primitive==3:assert raw==b""
   else:assert len(raw)==144
   raw_call=raw_call+(raw,);payload_seen=True
  elif kind==6:
   assert pending is not None and len(raw)>=64
   a=struct.unpack_from("<8Q",raw)
   assert a[:5]==(int.from_bytes(b"HIACDA01","little"),pending[2],pending[3],pending[1],0)
   assert a[6]==len(raw)-64 and a[7]==0
   if pending[1]==1:
    assert last_return is not None and last_return[0]==2 and a[5]==last_return[1]
    if pending[12]==pending[10] and pending[13]==0 and pending[14]<=len(last_return[2]):
     assert raw[64:]==last_return[2][:pending[14]]
   elif pending[1]==19:
    assert raw_call is not None and payload_seen and a[5]==raw_call[3]
    assert raw[64:]==(raw_call[4] if raw_call[0]==4 else b"")
   else:assert a[5]==0
   pending=None;last_ack=True;raw_call=None
  elif kind==10:
   assert terminal is not None and terminal[0]==BAD and owned>=0 and not cleanup_seen and len(raw)==32
   one,fd,result,error=struct.unpack("<4Q",raw)
   assert one==1 and signed(fd)==owned and signed(result) in(-1,0)
   assert (error==0)==(signed(result)==0)
   owned=-1;cleanup_seen=True
  else:
   assert kind==7 and current is None and pending is None and last_return is not None and last_return[0]==1
   assert terminal is None and raw==last_return[2] and len(raw)==128
   terminal=(last_return[1],raw)
   if terminal[0]!=BAD:
    t=struct.unpack("<16Q",raw);assert t[:4]==(int.from_bytes(b"HIACDE01","little"),7,lease,commands)
    assert owned==-1
 assert limits is not None and image_seen==set(counts) and input_seen and terminal is not None
 assert current is None and pending is None and owned==-1
 return dict(native_entries=sum(counts.values()),by_role=counts,commands=commands,
             raw_syscalls=syscalls,private_abort_cleanup=cleanup_seen,returned=terminal[0],
             terminal_hex=terminal[1].hex(),full_images_input_events_ACKs=True,
             all_raw_syscall_payloads=True,all_intermediate_workspaces=False)

class NativeMechanical:
 def __init__(self,assets,carrier,out,initial,wall_seconds=180):
  self.out=Path(out);self.out.mkdir(parents=True,exist_ok=False)
  self.assets=json.loads(Path(assets).read_bytes());self.slots={};self.closed=False
  assert self.assets["schema"]=="hia-implementation-files-runtime-assets-v1"
  carrier=Path(carrier).resolve();self.carrier=carrier
  build=json.loads(carrier.with_suffix(".build.json").read_bytes())
  assert build["source_sha256"]==C_SOURCE_SHA and file_hash(carrier)==build["executable"]
  assert file_hash(Path(build["source"]))["sha256"]==C_SOURCE_SHA
  rows=[]
  for role in range(1,3):
   m=self.assets["roles"][str(role)]["manifest"]
   for typ in ("source","image"):
    path=Path(m[typ+"_path"]);raw=path.read_bytes()
    assert len(raw)==m[typ+"_bytes"] and digest(raw)==m[typ+"_sha256"]
    rows.append((path,raw,stat.S_IMODE(path.stat().st_mode)))
  self.pins=rows
  (self.out/"initial.bin").write_bytes(initial)
  self.trace=self.out/"trace.bin";self.final=self.out/"final-slots.bin"
  args=[str(carrier),str(self.out/"initial.bin"),str(self.trace),str(self.final)]
  args.extend(self.assets["roles"][str(i)]["manifest"]["image_path"] for i in range(1,3))
  args.append(str(os.getpid()))
  start=time.monotonic();process=None;status=None;usage=None;failure=None
  stdout=None;stderr=None
  try:
   stdout=(self.out/"stdout.bin").open("xb");stderr=(self.out/"stderr.bin").open("xb")
   process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
   while status is None:
    pid,got,ru=os.wait4(process.pid,os.WNOHANG)
    if pid:
     status=got;usage=ru;process.returncode=os.waitstatus_to_exitcode(got);break
    if time.monotonic()-start>wall_seconds:raise TimeoutError("fixed implementation-file original 180 wall group deadline")
    time.sleep(.02)
  except BaseException as exc:
   failure=exc
  finally:
   cleanup=[]
   if process is not None and status is None:
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    except BaseException as exc:cleanup.append(exc)
    try:
     _,status,usage=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
    except BaseException as exc:cleanup.append(exc)
   for stream in(stdout,stderr):
    if stream is None:continue
    try:stream.close()
    except BaseException as exc:cleanup.append(exc)
   receipt=dict(args=args,wall_seconds=time.monotonic()-start,status=status,
        exit_code=None if status is None else os.waitstatus_to_exitcode(status),
        pid=None if process is None else process.pid,timeout=isinstance(failure,TimeoutError),
        child_reaped=status is not None,limits=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180),
        user_seconds=None if usage is None else usage.ru_utime,
        system_seconds=None if usage is None else usage.ru_stime,
        maximum_rss_kib=None if usage is None else usage.ru_maxrss,
        error=None if failure is None else repr(failure),cleanup_errors=list(map(repr,cleanup)))
   try:save(self.out/"process.json",receipt)
   except BaseException as exc:cleanup.append(exc)
   if failure is not None:
    for exc in cleanup:failure.add_note(repr(exc))
    raise failure
   if cleanup:raise cleanup[0]
  assert receipt["exit_code"] in(0,2),receipt
  assert (self.out/"stdout.bin").read_bytes()==b"" and (self.out/"stderr.bin").read_bytes()==b""
  self.trace_summary=validate_trace(self.trace,self.assets,initial)
  self.entries=self.trace_summary["native_entries"];self.calls=self.trace_summary["by_role"];self.commands=self.trace_summary["commands"];self.syscalls=self.trace_summary["raw_syscalls"]
  self._parse_final()
  assert self.returned==self.trace_summary["returned"] and self.event.hex()==self.trace_summary["terminal_hex"]
  assert (receipt["exit_code"]==2)==(self.returned==BAD)
  self.status="PRIVATE_BAD" if self.returned==BAD else "TERMINAL"
  self.payload=b"" if self.status=="PRIVATE_BAD" else self.read(*struct.unpack("<16Q",self.event)[6:9])
  for path,raw,mode in rows:assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
  assert file_hash(carrier)==build["executable"] and file_hash(Path(build["source"]))["sha256"]==C_SOURCE_SHA
  self.result=dict(status=self.status,returned=self.returned,event=self.event,payload=self.payload,
       entries=self.entries,mechanical_steps=self.commands)
  save(self.out/"trace-summary.json",self.trace_summary)
  save(self.out/"full-files.json",{p.name:file_hash(p) for p in(self.trace,self.final,self.out/"initial.bin",self.out/"stdout.bin",self.out/"stderr.bin")})
 def _parse_final(self):
  with self.final.open("rb") as f:
   h=struct.unpack("<8Q",read_exact(f,64))
   assert h[:2]==(int.from_bytes(b"HIAEMXS1","little"),1) and h[2:4]==(self.entries,self.commands) and h[6:]==(128,0)
   self.returned=h[4];self.event=read_exact(f,128);last=-1;total=os.fstat(f.fileno()).st_size
   for _ in range(h[5]):
    slot,n,ro,owned,*reserved=struct.unpack("<8Q",read_exact(f,64))
    assert last<slot<64 and ro in(0,1) and owned==1 and reserved==[0]*4
    at=f.tell();assert n<=total-at
    self.slots[slot]=dict(size=n,readonly=bool(ro),file_offset=at);f.seek(n,1);last=slot
   assert f.tell()==total
 def read(self,slot,at,count):
  b=self.slots[slot];assert 0<=at<=b["size"] and 0<=count<=b["size"]-at
  with self.final.open("rb") as f:f.seek(b["file_offset"]+at);return read_exact(f,count)
 def compare_python(self,python):
  assert self.entries==python.entries and self.calls==python.calls and self.commands==python.commands
  assert set(self.slots)==set(python.slots)
  for slot,b in self.slots.items():
   p=python.slots[slot];assert (b["size"],b["readonly"])==(p["size"],p["readonly"])
   for at in range(0,b["size"],4096):
    n=min(4096,b["size"]-at);assert self.read(slot,at,n)==python.read(slot,at,n),(slot,at)
  actual_returns=[];actual_acks=[]
  for kind,raw in trace_records(self.trace):
   if kind==4:
    serial,role,returned,n=struct.unpack_from("<4Q",raw)
    actual_returns.append((serial-1,role,returned,raw[32:].hex()))
   elif kind==5:command=raw
   elif kind==6:actual_acks.append((command.hex(),raw))
  original_returns=[];original_acks=[]
  import zlib
  def raw_value(d):
   raw=b"".join(zlib.decompress((python.evidence.directory/(h+".zlib")).read_bytes()) for h in d["pages"])
   assert len(raw)==d["bytes"] and digest(raw)==d["sha256"];return raw
  python.evidence.entries.flush()
  with (python.out/"entries.jsonl").open() as f:
   for line in f:
    row=json.loads(line)
    if row["status"]=="RETURNED":original_returns.append((row["number"],row["role"],row["returned"],row["event_hex"]))
    elif row["status"]=="MECHANICAL_ACK":original_acks.append((row["event_hex"],raw_value(row["ack"])))
  assert actual_returns==original_returns and actual_acks==original_acks
  actual_sys=[];current_sys=None
  for kind,raw in trace_records(self.trace):
   if kind==9:
    number,sequence,primitive,before,result,error,answer,after=struct.unpack("<8Q",raw)
    # Real OS descriptor numbers are process-local, never copied into HIA ACKs.
    # Each trace validates their exact lifecycle; compare the logical result.
    current_sys=(number,primitive,0 if primitive==1 and signed(result)>=0 else signed(result),
                 error,answer,signed(before)>=0,signed(after)>=0)
   elif kind==11:
    assert current_sys is not None;actual_sys.append((current_sys,raw));current_sys=None
  original_sys=[]
  with (python.out/"entries.jsonl").open() as f:
   for line in f:
    row=json.loads(line)
    if row["status"]=="RAW_SYSCALL":
     original_sys.append(((row["number"],row["primitive"],
        0 if row["primitive"]==1 and row["raw_result"]>=0 else row["raw_result"],
        row["errno"],row["returned"],row["fd_before"]>=0,row["fd_after"]>=0),
        raw_value(row["full_payload"])))
  assert actual_sys==original_sys and self.syscalls==python.syscalls
  return dict(all_native_header_returns_equal=True,all_command_ACK_bytes_equal=True,all_final_slot_bytes_permissions_equal=True,
              all_raw_syscall_payloads_logical_results_errno_equal=True,actual_FD_numbers_each_validated_in_own_process=True,
              python_full_intermediate_workspace_CAS_retained=True,native_runner_intermediate_workspaces_recorded=False)
 def close(self,encode=True):
  if self.closed:return
  self.closed=True
  for path,raw,mode in self.pins:assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
  hashes=dict(trace=file_hash(self.trace),all_final_slots=file_hash(self.final))
  result=dict(source_image_before_after_exact=True,**hashes,
              all_intermediate_workspaces=False,complete_event_ACK_trace=True)
  if encode:result["lossless_original_encoding"]=encode_closed_evidence((self.trace,self.final),self.out)
  else:result["raw_retained_after_failed_comparison"]=True
  save(self.out/"closed-evidence.json",result)
  return result
