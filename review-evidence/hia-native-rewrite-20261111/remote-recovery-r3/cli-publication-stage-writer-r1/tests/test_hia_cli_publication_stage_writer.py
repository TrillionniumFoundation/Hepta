"""Fresh staging write owner against CPython 3.12.14 and actual Linux files.
Scripted raw outcomes exercise real io.BufferedWriter; they are not filesystem
authority. The separate real-files panel calls only issued Linux primitives.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,importlib.util,io,json,os,resource,stat,struct,sys,traceback,zlib
M=(1<<64)-1
_LIBC=ctypes.CDLL(None)
_LIBC.__errno_location.restype=ctypes.POINTER(ctypes.c_int)
_ERRNO=_LIBC.__errno_location()
def magic(s):return int.from_bytes(s,"little")
def digest(raw):return sha256(raw).hexdigest()
def save(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2,sort_keys=True)+"\n")
def module(name,path):
 sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def command(path,data,lease=71):
 return struct.pack("<8Q",magic(b"HIASWC01"),1,lease,1,len(path),len(data),65+len(path)+len(data),0)+path+b"\0"+data
def guard(raw,size=None):
 size=len(raw) if size is None else size;assert len(raw)<=size
 b=ctypes.create_string_buffer(max(size,1)+64);at=ctypes.addressof(b)+32
 ctypes.memset(at-32,0xa9,32);ctypes.memmove(at,raw,len(raw));ctypes.memset(at+max(size,1),0xa9,32)
 return b,at,size
def check(b):
 assert ctypes.string_at(b[1]-32,32)==bytes([0xa9])*32
 assert ctypes.string_at(b[1]+max(1,b[2]),32)==bytes([0xa9])*32
def exception(e):
 if e is None:return None
 return dict(type=type(e).__name__,text=str(e),errno=getattr(e,"errno",None),
  characters=getattr(e,"characters_written",None),filename=None if getattr(e,"filename",None) is None else os.fsencode(e.filename).hex())
class Evidence:
 def __init__(self,out):self.out=out;self.cas_index={};self.entries=0
 def cas(self,raw):
  raw=bytes(raw);h=digest(raw);p=self.out/"cas"/(h+".zlib");p.parent.mkdir(exist_ok=True)
  if not p.exists():p.write_bytes(zlib.compress(raw,6))
  assert zlib.decompress(p.read_bytes())==raw;self.cas_index[h]=len(raw)
  return dict(path="cas/"+p.name,bytes=len(raw),sha256=h,compression="zlib")
 def entry(self,label,s,r,before,after,ret):
  row=dict(label=label,first=self.cas(s),reply=self.cas(r),workspace_before=self.cas(before),workspace_after=self.cas(after),return_value=ret)
  with (self.out/"entries.jsonl").open("a") as f:f.write(json.dumps(row,sort_keys=True)+"\n")
  self.entries+=1
class Native:
 def __init__(self,image,evidence):self.image=image;self.e=evidence
 def call(self,s,r,w,label):
  a=guard(s);b=guard(r);before=ctypes.string_at(w[1],w[2])
  ret=int(self.image._entry(a[1],a[2],b[1],b[2],w[1],w[2]))
  for x in (a,b,w):check(x)
  assert ctypes.string_at(a[1],a[2])==s and ctypes.string_at(b[1],b[2])==r
  after=ctypes.string_at(w[1],w[2]);self.e.entry(label,s,r,before,after,ret)
  return ret
 def run(self,s,peer,label,mutator=None):
  w=guard(b"",1024);reply=b""
  for index in range(10000):
   ret=self.call(s,reply,w,label)
   event=struct.unpack_from("<16Q",ctypes.string_at(w[1],w[2]),256)
   assert ret==128 and event[0]==magic(b"HIASWE01") and event[2]==71,(ret,event)
   if event[1]==2:
    reply=peer(event,s)
    if mutator:
     bad=mutator(reply)
     assert self.call(s,bad,w,label+"/bad")==0xfffffffd
     assert self.call(s,reply,w,label+"/valid-after-bad")==0xfffffffd
     return dict(private_BAD=True)
    continue
   assert event[1]==0 and event[14]==0 and event[15]==99,event
   if event[5]==0:e=None
   elif event[5]==1:
    name=s[event[9]:event[9]+event[10]] if event[10] else None
    e=OSError(event[6],os.strerror(event[6]),os.fsdecode(name)) if name is not None else OSError(event[6],os.strerror(event[6]))
   elif event[5]==2:e=BlockingIOError(event[6],"write could not complete without blocking",event[7])
   else:assert event[5]==3;e=ValueError("invalid buffering size")
   result=dict(event=list(event),exception=exception(e))
   assert self.call(s,reply,w,label+"/terminal-reentry")==0xfffffffd
   return result
  raise AssertionError("finite test iteration guard; not a production quota")
def ack(event,result=0,err=0,payload=b""):
 return struct.pack("<8Q",magic(b"HIASWA01"),event[2],event[3],event[4],int(bool(err)),result if not err else 0,err,len(payload))+payload
class Script:
 def __init__(self,plan):self.plan={k:list(v) for k,v in plan.items()};self.rows=[];self.data=bytearray();self.live=True
 def call(self,op,data=b""):
  rows=self.plan.get(op,[]);choice=rows.pop(0) if rows else None
  err=choice[1] if choice and choice[0]=="error" else 0
  n=min(len(data),choice[1]) if choice and choice[0]=="count" else len(data) if op==5 else 0
  if err:n=0
  self.rows.append(dict(op=op,asked=len(data),data=bytes(data).hex(),returned=n,errno=err))
  if op==5 and not err:self.data.extend(data[:n])
  return n,err
class Raw(io.RawIOBase):
 def __init__(self,script):self.script=script;self.closed_here=False
 @property
 def closed(self):return self.closed_here
 def writable(self):return True
 def readable(self):return False
 def seekable(self):return True
 def tell(self):return len(self.script.data)
 def write(self,data):
  while True:
   n,err=self.script.call(5,bytes(data))
   if err==4:continue
   if err==11:
    _ERRNO[0]=11
    return None
   if err:raise OSError(err,os.strerror(err))
   return n
 def close(self):
  if self.closed_here:return
  self.closed_here=True
  _,err=self.script.call(2)
  if err:raise OSError(err,os.strerror(err))
def reference_buffered(payload,block,plan):
 script=Script(plan);raw=Raw(script);result=None
 try:
  with io.BufferedWriter(raw,buffer_size=block) as stream:
   stream.write(payload);stream.flush()
   while True:
    _,err=script.call(6)
    if err==4:continue
    if err:raise OSError(err,os.strerror(err))
    break
 except BaseException as e:result=exception(e)
 assert raw.closed
 return dict(exception=result,data=bytes(script.data),trace=script.rows)
def script_peer(script,block):
 def peer(event,source):
  op=event[4]
  if op==1:return ack(event,1)
  if op==3:
   raw=bytearray(144);struct.pack_into("<I",raw,24,stat.S_IFREG|0o600);struct.pack_into("<q",raw,56,block)
   return ack(event,payload=bytes(raw))
  assert op in (2,5,6),op
  at,n=event[9:11];assert at<=len(source) and n<=len(source)-at
  data=source[at:at+n] if op==5 else b""
  result,err=script.call(op,data)
  return ack(event,result,err)
 return peer
def scripted_cases():
 scenarios=[
 ("normal",{}),("write-zero",{5:[("count",0)]}),("partial",{5:[("count",1)]}),
 ("eintr",{5:[("error",4)]}),("eagain",{5:[("error",11)]}),
 ("eagain-close-eagain",{5:[("error",11),("error",11)]}),
 ("eio",{5:[("error",5)]}),("eio-close-enospc",{5:[("error",5),("error",28)]}),
 ("partial-eagain",{5:[("count",1),("error",11)]}),
 ("partial-eagain-enospc",{5:[("count",1),("error",11),("error",28)]}),
 ("partial-eintr-zero",{5:[("count",1),("error",4),("count",0)]}),
 ("fsync-eintr",{6:[("error",4)]}),("fsync-enospc",{6:[("error",28)]}),
 ("close-error",{2:[("error",5)]}),
 ("fsync-and-close",{6:[("error",28)],2:[("error",5)]}),
 ("write-and-close",{5:[("error",11)],2:[("error",5)]})]
 answer=[]
 for block in (2,8,4096):
  for n in (block-1,block,block+1,2*block+3):
   for label,plan in scenarios:answer.append((str(block)+"/"+str(n)+"/"+label,block,n,plan))
 return answer
class Physical:
 def __init__(self):
  self.libc=ctypes.CDLL(None,use_errno=True);self.libc.syscall.restype=ctypes.c_long
  self.fd=None;self.rows=[]
 def syscall(self,n,*args):
  ctypes.set_errno(0);ret=int(self.libc.syscall(ctypes.c_long(n),*(ctypes.c_long(x) for x in args)))
  return ret,ctypes.get_errno() if ret<0 else 0
 def __call__(self,event,source):
  op=event[4];data=b"";result=0
  if op==1:
   at,n=event[9:11];path=source[at:at+n];assert len(path)==n and path[-1]==0 and b"\0" not in path[:-1]
   buf=guard(path);ret,err=self.syscall(2,buf[1],event[11],event[12]);check(buf)
   if not err:assert self.fd is None;self.fd=ret;result=1
  elif op==3:
   assert self.fd is not None and event[10]==144
   buf=guard(b"",144);ret,err=self.syscall(5,self.fd,buf[1]);check(buf)
   if not err:data=ctypes.string_at(buf[1],144)
  elif op==5:
   assert self.fd is not None;at,n=event[9:11];raw=source[at:at+n];assert len(raw)==n
   buf=guard(raw);ret,err=self.syscall(1,self.fd,buf[1],n);check(buf)
   if not err:result=ret
  elif op==6:
   assert self.fd is not None;ret,err=self.syscall(74,self.fd)
  else:
   assert op==2 and self.fd is not None
   fd=self.fd;self.fd=None;ret,err=self.syscall(3,fd)
  self.rows.append(dict(op=op,event=list(event),raw_return=ret,errno=err))
  return ack(event,result,err,data)
 def cleanup(self):
  if self.fd is not None:
   fd=self.fd;self.fd=None;os.close(fd)
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--compiler",type=Path,required=True);p.add_argument("--out",type=Path,required=True);a=p.parse_args()
 assert sys.version_info[:3]==(3,12,14)
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 root=Path(__file__).resolve().parents[1];out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
 pins={};result=dict(status="FAIL",scope="NEW_NATIVE_STAGING_WRITE_STATE_MACHINE",whole_cli_publication_closed=False,scripted_cases=0,physical_cases=0,private_controls=0)
 def pin(path):
  path=path.resolve();raw=path.read_bytes();pins[str(path)]=dict(bytes=len(raw),sha256=digest(raw));return raw
 evidence=Evidence(out);physical=None
 try:
  sys.path[:0]=[str(root/"tools"),str(a.source.resolve()),str(root.parent/"Hepta-agent-edit-native")]
  import cli_authoring,cli_publication_stage_writer as owner
  from hepta.hia_agent_assembly import render_assembly,assemble_program
  from hepta.hia_json_preflight_native import NativeHiaJsonImage
  from tools.qualify_hia_selfhost import compile_stage
  for path in (root/"tools").glob("*.py"):pin(path)
  pin(Path(__file__));pin(root.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py")
  compiler=pin(a.compiler);assert(len(compiler),digest(compiler))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
  body=cli_authoring.expanded(owner.BODY,owner.CONSTANTS);doc=cli_authoring.document(body,"hia_cli_publication_stage_writer")
  profile=cli_authoring.profile(doc);assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192 and profile["max_params"]<=16
  raw=render_assembly(doc).encode();assemble_program(raw);(out/"source.hiaasm").write_bytes(raw);(out/"authoring-expanded.py").write_text(body)
  where=out/"compile";where.mkdir();image,receipt=compile_stage(where,"cli-publication-stage-writer",a.compiler,raw);ir=pin(image)
  assert receipt["source_sha256"]==receipt["input_sha256"]==digest(raw)
  assert receipt["image_sha256"]==receipt["artifact_sha256"]==digest(compiler)
  assert receipt["produced_sha256"]==digest(ir) and receipt["produced_bytes"]==len(ir)
  assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
  save(where/"manifest.json",dict(source_sha256=digest(raw),image_sha256=digest(ir),profile=profile,receipt=receipt))
  native=Native(NativeHiaJsonImage(ir,expected_sha256=digest(ir)),evidence)
  for i,(label,block,n,plan) in enumerate(scripted_cases()):
   payload=(b"\0HIA staging\xff"* ((n+12)//13))[:n];assert len(payload)==n
   expected=reference_buffered(payload,block,plan);script=Script(plan)
   observed=native.run(command(b"/private-issued-stage/program.hia",payload),script_peer(script,block),label)
   assert observed["exception"]==expected["exception"],(label,observed,expected)
   assert bytes(script.data)==expected["data"] and script.rows==expected["trace"],(label,script.rows,expected)
   save(out/"scripted"/(str(i).zfill(4)+".json"),dict(label=label,block=block,payload=evidence.cas(payload),plan=plan,actual=observed,expected_exception=expected["exception"],written=evidence.cas(expected["data"]),actual_trace=script.rows,reference_trace=expected["trace"]))
   result["scripted_cases"]+=1
  fixtures=out/"physical";fixtures.mkdir()
  cases=[("success-"+str(n),n,"plain") for n in (0,1,4096,4097,8193,65537)]+[("existing",71,"existing"),("parent-file",71,"parent-file"),("missing-parent",71,"missing-parent"),("dangling",71,"dangling"),("surrogateescape",71,"surrogateescape")]
  for i,(label,n,mode) in enumerate(cases):
   payload=(b"real\0stage\xff"* ((n+10)//11))[:n];assert len(payload)==n;answers=[];final=[]
   for variant in ("reference","native"):
    folder=fixtures/str(i)/variant;folder.mkdir(parents=True);stage=folder/"program.hia"
    if mode=="existing":stage.write_bytes(b"winner")
    if mode=="parent-file":(folder/"a").write_bytes(b"parent");stage=folder/"a/program.hia"
    if mode=="missing-parent":stage=folder/"absent/program.hia"
    if mode=="dangling":stage.symlink_to("absent")
    if mode=="surrogateescape":stage=folder/os.fsdecode(b"program-\xff.hia")
    if variant=="reference":
     error=None
     try:
      with stage.open("xb") as f:f.write(payload);f.flush();os.fsync(f.fileno())
     except BaseException as e:error=exception(e)
     answers.append(error)
    else:
     physical=Physical()
     try:
      got=native.run(command(os.fsencode(stage),payload),physical,label);answers.append(got["exception"])
      assert physical.fd is None
      save(out/"physical-results"/(str(i)+".json"),dict(label=label,result=got,syscalls=physical.rows))
     finally:physical.cleanup()
    if answers[-1] and answers[-1]["filename"] is not None:
     name=bytes.fromhex(answers[-1]["filename"]);assert name==os.fsencode(stage)
     answers[-1]=dict(answers[-1],filename="<stage>",text=answers[-1]["text"].replace(repr(str(stage)),repr("<stage>")))
    content=stage.read_bytes() if stage.is_file() else None
    final.append(content)
   assert answers[0]==answers[1] and final[0]==final[1],(label,answers,final)
   save(out/"physical-comparisons"/(str(i)+".json"),dict(label=label,reference=answers[0],actual=answers[1],contents=None if final[0] is None else evidence.cas(final[0])))
   result["physical_cases"]+=1
  def field(i,n):
   def change(raw):b=bytearray(raw);struct.pack_into("<Q",b,i*8,n);return bytes(b)
   return change
  controls=[("magic",field(0,0)),("lease",field(1,72)),("sequence",field(2,99)),("op",field(3,3)),("status",field(4,2)),("open-result",field(5,2)),("errno-on-success",field(6,5)),("extent",field(7,1)),("truncated",lambda r:r[:-1]),("extra",lambda r:r+b"\0")]
  for label,change in controls:
   native.run(command(b"/private-issued-stage/program.hia",b"x"),script_peer(Script({}),4096),"private/"+label,change);result["private_controls"]+=1
  assert result["scripted_cases"]==192 and result["physical_cases"]==11 and result["private_controls"]==10
  result.update(status="PASS",profile=profile,source_sha256=digest(raw),image_sha256=digest(ir))
 except BaseException as e:
  result.update(error_class=type(e).__name__,error=str(e),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  if physical is not None:physical.cleanup()
  unchanged=all(Path(p).stat().st_size==v["bytes"] and digest(Path(p).read_bytes())==v["sha256"] for p,v in pins.items())
  save(out/"source-pins.json",pins);result.update(source_pins_unchanged=unchanged,native_entries=evidence.entries)
  for h,n in evidence.cas_index.items():content=zlib.decompress((out/"cas"/(h+".zlib")).read_bytes());assert len(content)==n and digest(content)==h
  result["cas_readback"]=dict(status="PASS",objects=len(evidence.cas_index),logical_bytes=sum(evidence.cas_index.values()))
  save(out/"summary.json",result);print(json.dumps(result,sort_keys=True),flush=True)
 if result["status"]!="PASS" or not result["source_pins_unchanged"]:raise SystemExit(1)
if __name__=="__main__":main()
