"""Unified current type/late-Core/P16 modes -> actual integer Core Graph qualification.

The native fixed ELF owns program admission and Graph issuance. The separate
native GraphWire scan/emit pair reads the actual returned Graph; Python does
not construct Graph nodes or reconstruct errors. Private continuation tests
are explicitly synthetic issued-state fixtures, separate from the ELF cases.
"""
from __future__ import annotations
import argparse,ctypes,importlib.util,json,os,resource,signal,stat,struct,subprocess,sys,time,traceback,zlib
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
for name in ("bundle","reference","out"):p.add_argument("--"+name,type=Path,required=True)
GROUPS={"semantic":26,"raw-boundary":1,"functions":1,"private":60,
 "fixed-errors":34,"type-context":4,"type-names":24,"type-shapes":9,"type-order":17,
 "helper-budget":1,"late-inventory":1,
 "compat-semantic":23,"compat-assembly":22,"compat-object":6,
 "late-node-below":1,"late-node-equal":1,"late-node-over":1,
 "late-byte-below":1,"late-byte-equal":1,"late-byte-over":1,
 "late-depth-and-order":6,"late-private-protocol":38}
p.add_argument("--group",choices=tuple(GROUPS),required=True)
p.add_argument("--variant",type=int,default=0)
p.add_argument("--issued-sample",type=Path)
p.add_argument("--predecessor-control",action="store_true")
p.add_argument("--control-results",type=Path)
a=p.parse_args();OUT=a.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
REF=a.reference.resolve();PROJECT=Path(__file__).resolve().parents[1];START=time.monotonic_ns()
INITIAL_SELF=resource.getrusage(resource.RUSAGE_SELF);INITIAL_CHILD=resource.getrusage(resource.RUSAGE_CHILDREN)
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def deadline(signum,frame):raise TimeoutError("actual admission Graph group 180 wall seconds")
signal.signal(signal.SIGALRM,deadline);signal.setitimer(signal.ITIMER_REAL,180)
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
libc.mmap.restype=ctypes.c_void_p
libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
SELF_PID=os.getpid();PINS={};ROWS=[];PLAN=[];STATUS="FAIL";FAILURE=None
ELF_PROCESSES=0;ORIGINAL_ELF_PROCESSES=0;WIRE_ENTRIES=0;PRIVATE_ENTRIES=0;PRIVATE_CASES=0
PREDECESSOR_PRIVATE_ENTRIES=0;PRIVATE_RECORDS=0;RUN_EXECUTABLE=None;RUN_EXECUTABLE_SHA=None
EXTRAS=None;P16=None
MAX=(1<<64)-1;ABI=0xfffffffd;IMAGES={};BUNDLE=None;CONSTANTS=None
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def magic(value):return int.from_bytes(value.encode("ascii"),"little")
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def pin(path):
 path=Path(path).resolve();info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not path.is_symlink()
 raw=path.read_bytes();mode=stat.S_IMODE(info.st_mode)
 if path in PINS:assert PINS[path]==(raw,mode),str(path)
 else:PINS[path]=(raw,mode)
 return raw
def after_inputs():
 rows=[]
 for path,(raw,mode) in PINS.items():
  same=False;error=None
  try:
   info=path.lstat()
   same=stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not path.is_symlink()
   same=same and stat.S_IMODE(info.st_mode)==mode and path.read_bytes()==raw
  except BaseException as exc:error=repr(exc)
  rows.append(dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=mode,same=same,error=error))
 return rows
def cas(raw):
 raw=bytes(raw);h=digest(raw);dest=OUT/"cas"/(h+".zlib");dest.parent.mkdir(exist_ok=True)
 if not dest.exists():
  with dest.open("xb") as f:f.write(zlib.compress(raw,1))
 assert zlib.decompress(dest.read_bytes())==raw
 return dict(bytes=len(raw),sha256=h,path="cas/"+dest.name,compression="zlib")
def canonical(value):
 return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def transport(value):
 return json.dumps(value,sort_keys=False,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()
def packet(raw,lease,request,digits=4300,mode=1,tree=0):
 return struct.pack("<8Q",magic("HIAWPI01"),lease,request,digits,len(raw),mode,tree,0)+raw
def primitive(version=6,functions=1):
 result={"schema":"hepta.hia.program.v"+str(version),"module":"native_backend_prefix","functions":[]}
 for index in range(functions):
  params=[{"name":"value","type":"u8"}]
  result["functions"].append({"name":"identity" if functions==1 else "f"+str(index),
    "params":params,"returns":["u8"],"effects":[],"entry":"entry",
    "blocks":[{"id":"entry","params":params,"ops":[],"term":{"op":"ret","values":["value"]}}]})
 return result
def composite(version):
 result=primitive();result["schema"]="hepta.hia.composite.v"+str(version);result["types"]=[]
 return result
def expected(raw,digits):
 previous=sys.get_int_max_str_digits();sys.set_int_max_str_digits(digits)
 try:
  try:
   checked=verify_program(raw)
   core=checked.canonical_bytes
   original=checked.structured_bytes if checked.structured_bytes is not None else core
   return dict(kind=1,core=core,input_sha256=checked.input_sha256,core_sha256=checked.sha256,
     input_bytes=len(original),structured=int(checked.structured_bytes is not None),
     version=int(json.loads(original)["schema"].rsplit("v",1)[1]),
     core_version=int(json.loads(core)["schema"].rsplit("v",1)[1]))
  except HIAProgramRejected as exc:
   return dict(kind=4,error_class=type(exc).__name__,code=exc.code,text=str(exc).encode("utf-8"))
 finally:sys.set_int_max_str_digits(previous)
def add(label,value,accepted,raw=False,digits=4300):
 source=bytes(value) if raw else transport(value);ref=expected(source,digits)
 assert (ref["kind"]==1)==accepted,(label,ref)
 PLAN.append(dict(label=label,raw=source,digits=digits,expected=ref))
def plan():
 if a.group=="semantic":
  for version in range(1,9):add("verify-v"+str(version),primitive(version),True)
  for version in range(1,5):add("verify-composite-v"+str(version),composite(version),True)
  from tests.test_hia_program_composite import stored_loan_program,task_program
  add("stored-loans",stored_loan_program(),True)
  add("structured-task-helpers",task_program(),True)
  add("digits-disabled",primitive(),True,digits=0)
  add("digits-minimum",primitive(),True,digits=640)
  raw=transport(primitive()).replace(b"identity",b"\\u0069dentity")
  add("escaped-identifier",raw,True,raw=True)
  add("raw-whitespace",b"\n\t "+transport(primitive())+b" \r\n",True,raw=True)
  for label,raw in (("empty",b""),("invalid-UTF8",b"\xff"),
       ("duplicate",b'{"schema":1,"schema":2}'),("float",b'{"v":1.5}'),
       ("nonfinite",b'{"v":NaN}'),("trailing",b'{} {}')):
   add("raw-"+label,raw,False,raw=True)
  bad=primitive();bad["functions"][0]["blocks"][0]["term"]["values"]=["missing"]
  add("core-undefined-value",bad,False)
  bad=primitive();bad["functions"][0]["blocks"][0]["ops"]=[
   {"op":"bad_"+("λ"*60000),"args":[],"out":[],"attrs":{}}]
  add("core-entire-Unicode-error",bad,False)
  assert len(PLAN)==26
 elif a.group=="raw-boundary":
  assert a.variant in (0,1)
  n=8388608+a.variant;base=transport(primitive())
  add("raw-byte-"+str(n),base+b" "*(n-len(base)),a.variant==0,raw=True)
 elif a.group=="functions":
  n=(128,129,1024,1025)[a.variant]
  add("Core-functions-"+str(n),primitive(functions=n),n<=1024)
 elif a.group in ("fixed-errors","type-context","type-names","type-shapes","type-order","helper-budget","late-inventory"):
  path=PROJECT/"development/current_type_prefix_cases.py";raw=pin(path)
  assert (len(raw),digest(raw))==(6069,"f881b1408cb659a4a031aa15f16cee2ceeb45ba1b31ac9e391971b35eda108f3")
  spec=importlib.util.spec_from_file_location("backend_current_prefix_exact_fixtures",path)
  module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  rows=module.raw_cases(PROJECT,a.group,BUNDLE,pin,cas,save,OUT/"current-public-oracle")
  for original in rows:
   add(original["label"],original["source"],original["expected"]["kind"]!=4,raw=True)
   new=PLAN[-1]["expected"];old=original["expected"]
   assert new["kind"]==old["kind"]
   if new["kind"]==4:
    assert new["text"]==old["payload"] and new["code"]==old["code"]
   else:assert new["core"]==old["payload"]
  assert len(PLAN)==GROUPS[a.group]
 else:raise AssertionError(a.group)
def child_setup():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 if libc.prctl(4,0,0,0,0)!=0 or libc.prctl(3,0,0,0,0)!=0:os._exit(125)
 if libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=SELF_PID:os._exit(125)
def actual(label,data,args=()):
 global ELF_PROCESSES,ORIGINAL_ELF_PROCESSES
 where=OUT/"cases"/label;where.mkdir(parents=True,exist_ok=False)
 (where/"input.bin").write_bytes(data)
 save(OUT/"pending-process.json",dict(label=label,input=cas(data),executable_sha256=RUN_EXECUTABLE_SHA,predecessor_control=a.predecessor_control))
 before=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.monotonic_ns()
 process=None;timed=False;returncode=None;cleanup=[]
 try:
  with (where/"input.bin").open("rb") as fi,(where/"stdout.bin").open("wb") as fo,(where/"stderr.bin").open("wb") as fe:
   env={"PATH":"/nonexistent","HOME":"/nonexistent","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"}
   process=subprocess.Popen([RUN_EXECUTABLE,*args],stdin=fi,stdout=fo,stderr=fe,env=env,
      close_fds=True,start_new_session=True,preexec_fn=child_setup)
   if a.predecessor_control:ORIGINAL_ELF_PROCESSES+=1
   else:ELF_PROCESSES+=1
   remaining=180-(time.monotonic_ns()-START)/1e9
   if remaining<=0:raise TimeoutError("group wall exhausted")
   try:returncode=process.wait(timeout=remaining)
   except subprocess.TimeoutExpired:
    timed=True;os.killpg(process.pid,signal.SIGKILL);returncode=process.wait()
 finally:
  primary=sys.exception()
  if process is not None and process.poll() is None:
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   except BaseException as exc:cleanup.append(repr(exc))
   try:returncode=process.wait()
   except BaseException as exc:cleanup.append(repr(exc))
  if cleanup:
   if primary is not None:
    for detail in cleanup:primary.add_note("child cleanup: "+detail)
   else:raise AssertionError(cleanup)
 after=resource.getrusage(resource.RUSAGE_CHILDREN)
 stdout=(where/"stdout.bin").read_bytes();stderr=(where/"stderr.bin").read_bytes()
 row=dict(label=label,returncode=returncode,timed_out=timed,wall_ns=time.monotonic_ns()-start,
   user_cpu=after.ru_utime-before.ru_utime,system_cpu=after.ru_stime-before.ru_stime,
   input=cas(data),stdout=cas(stdout),stderr=cas(stderr),executable_sha256=RUN_EXECUTABLE_SHA,
   predecessor_control=a.predecessor_control,
   closed_all_streams=True,child_reaped=True,empty_PATH_and_HOME=True)
 save(where/"process.json",row)
 assert not timed,row
 return row,stdout,stderr,where
class Guard:
 def __init__(self,raw,size=None,fill=0,readonly=False):
  self.size=len(raw) if size is None else size
  assert 0<=len(raw)<=self.size
  self.total=((self.size+128+4095)//4096)*4096
  self.addr=int(libc.mmap(None,self.total,3,0x22,-1,0))
  assert self.addr!=ctypes.c_void_p(-1).value
  self.ptr=self.addr+64;ctypes.memset(self.addr,0x69,self.total)
  if self.size:ctypes.memset(self.ptr,fill,self.size)
  if raw:ctypes.memmove(self.ptr,raw,len(raw))
  if readonly:assert libc.mprotect(self.addr,self.total,1)==0
 def bytes(self):return ctypes.string_at(self.ptr,self.size)
 def check(self):
  assert ctypes.string_at(self.addr,64)==bytes([0x69])*64
  assert ctypes.string_at(self.ptr+self.size,self.total-self.size-64)==bytes([0x69])*(self.total-self.size-64)
 def close(self):
  if self.addr is not None:
   at=self.addr;self.addr=None
   assert libc.munmap(at,self.total)==0
def close_guards(values):
 errors=[];primary=sys.exception()
 for value in values:
  if value is not None:
   try:value.close()
   except BaseException as exc:errors.append(repr(exc))
 if errors:
  if primary is not None:
   for detail in errors:primary.add_note("guard cleanup: "+detail)
  else:raise AssertionError(errors)
def native_entry(image,first,second,workspace,label):
 global WIRE_ENTRIES
 s=c=w=None
 try:
  s=Guard(first,readonly=True);c=Guard(second,readonly=True);w=Guard(workspace)
  before=dict(source=cas(first),command=cas(second),workspace=cas(workspace))
  save(OUT/"pending-wire.json",dict(label=label,before=before,source_and_command_hardware_readonly=True))
  returned=int(image._entry(s.ptr,s.size,c.ptr,c.size,w.ptr,w.size));WIRE_ENTRIES+=1
  for value in (s,c,w):value.check()
  result=w.bytes()
  save(OUT/"wire-entries"/(str(WIRE_ENTRIES).zfill(5)+".json"),
   dict(label=label,entry=WIRE_ENTRIES,returned=returned,before=before,workspace_after=cas(result),
     source_after=cas(s.bytes()),command_after=cas(c.bytes()),all_canaries_unchanged=True))
  assert s.bytes()==first and c.bytes()==second
  return returned,result
 finally:close_guards((s,c,w))
def graph_wire(graph,core,digits,label):
 h=struct.unpack_from("<8Q",graph)
 assert h[0]==magic("HIAGRF01") and h[1]==41 and h[6]==len(graph) and h[7]==0
 assert 1<=h[3]<=h[2]
 command=struct.pack("<8Q",magic("HIAGWC01"),41,1,h[3],len(core),2,digits,0)
 workspace=bytes(32768);role="scan";events=[]
 while True:
  returned,workspace=native_entry(IMAGES[role],graph,command,workspace,label+"-"+role)
  assert returned==128,(returned,role)
  event=struct.unpack_from("<16Q",workspace);events.append(event)
  assert event[0]==magic("HIAGWE01") and event[2:4]==(41,1)
  assert event[8]==0 and event[15]==0,event
  if event[1]==1:
   need=event[10];assert len(workspace)<need<1<<30
   workspace+=bytes(need-len(workspace))
  elif event[1]==2:
   assert role=="scan";role="emit"
  elif event[1]==0:
   at,n=event[11:13];assert at<=len(workspace) and n<=len(workspace)-at
   assert workspace[at:at+n]==core,(label,len(core),n)
   return dict(entries=len(events),full_canonical_Core_bytes_equal=True,
      original_Graph=cas(graph),wire_output=cas(workspace[at:at+n]),events=[list(x) for x in events])
  else:raise AssertionError(event)
def parse_result(row,stdout,stderr,planned,lease,request,where):
 ref=planned["expected"];assert len(stderr)>=128
 terminal=struct.unpack_from("<16Q",stderr)
 assert terminal[:3]==(magic("HIACDE01"),7,lease) and terminal[3]>0
 if ref["kind"]==4:
  assert row["returncode"]==2 and stdout==b""
  result=stderr[128:];assert terminal[4:7]==(1,1,30)
 else:
  assert row["returncode"]==0 and len(stderr)==128
  result=stdout;assert terminal[4:7]==(0,0,30)
 assert len(result)>=256 and terminal[7:12]==(0,len(result),ref["kind"],0 if ref["kind"]==1 else 1,len(result))
 assert terminal[12:]==(0,0,0,0)
 q=struct.unpack_from("<32Q",result)
 assert q[1:6]==(1,lease,request,1,ref["kind"])
 assert q[6:10]==((0,0,0,len(result)) if ref["kind"]==1 else (1,0,0,len(result)))
 ra,rn,ca,cn,pa,pn,ea,en=q[10:18]
 for at,n in ((ra,rn),(ca,cn),(pa,pn),(ea,en)):
  assert at<=len(result) and n<=len(result)-at
 if ref["kind"]==4:
  assert q[0]==magic("HIAWPE01") and q[18:]==(0,)*14
  assert (ra,rn,ca,cn)==(0,0,0,0) and pa==ea==256
  assert result[pa:pa+pn]==ref["text"] and len(result)==pa+pn
  assert result[ea:ea+en]==ref["code"].encode("ascii")
  return dict(kind=4,complete_reference_error_equal=True)
 assert q[0]==magic("HIAWGE01") and q[23:]==(0,)*9
 assert (ra,rn,ca,cn,pa,pn,ea,en)==(256,256,512,len(ref["core"]),512,len(ref["core"]),0,0)
 assert result[ca:ca+cn]==ref["core"]
 receipt=struct.unpack_from("<32Q",result,ra)
 assert receipt[:3]==(magic("HIAPRV01"),1,lease+2) and receipt[3]>0
 assert receipt[4:9]==(ref["structured"],ref["version"],ref["core_version"],ref["input_bytes"],cn)
 assert receipt[9]==(ref["input_bytes"] if ref["structured"] else 0)
 assert result[ra+80:ra+112].hex()==ref["input_sha256"]
 assert result[ra+112:ra+144].hex()==ref["core_sha256"]
 assert receipt[18:24]==(45,52 if ref["structured"] else 0,56,256,1,ref["structured"])
 assert receipt[24:]==(0,)*8
 ga,gn,gl,gr,gc=q[18:23]
 assert ga==512+cn and len(result)==ga+gn and gl==41 and 1<=gr<=gc
 graph=result[ga:]
 gh=struct.unpack_from("<8Q",graph)
 assert gh[:4]==(magic("HIAGRF01"),41,gc,gr) and gh[6:]==(gn,0)
 assert 64+gc*64+gh[4]*8+gh[5]==gn
 wire=graph_wire(graph,ref["core"],planned["digits"],planned["label"])
 (where/"issued-Graph.bin").write_bytes(graph)
 (where/"actual-Core.bin").write_bytes(ref["core"])
 save(where/"issued-sample.json",dict(schema="hia-actual-program-Graph-sample-v1",
  source_head="new source-bound prefix build; no prior result inherited",
  executable_sha256=BUNDLE["executable_sha256"],raw_input=cas(planned["raw"]),
  actual_full_result=cas(result),actual_Graph=cas(graph),actual_Core=cas(ref["core"]),
  actual_process_returncode=row["returncode"],actual_receipt=cas(result[256:512]),
  graph_wire=wire,header=list(q),parent_request=request,service_lease=lease))
 return dict(kind=1,complete_actual_receipt_and_Core_verified=True,Graph_wire=wire)
def pin_reference_modules():
 for mod in tuple(sys.modules.values()):
  filename=getattr(mod,"__file__",None)
  if filename:
   path=Path(filename).resolve()
   if path.suffix==".py" and path.is_relative_to(REF):pin(path)
def evidence_value(value):
 if type(value) is bytes:return cas(value)
 if type(value) is dict:return {key:evidence_value(item) for key,item in value.items()}
 if type(value) is list:return [evidence_value(item) for item in value]
 return value
def control_original(label):
 assert a.control_results is not None
 root=a.control_results.resolve()
 summary=json.loads(pin(root/"summary.json"))
 assert summary["schema"]=="hia-unified-program-Graph-actual-v1" and summary["status"]=="PASS"
 assert summary["predecessor_control_only"] and summary["group"]==a.group
 assert summary["completed_cases"]==GROUPS[a.group] and summary["actual_ELF_processes"]==0
 assert summary["actual_predecessor_ELF_processes"]==GROUPS[a.group]
 assert summary["source_image_inputs_before_after_equal"] and not summary["finalization_errors"]
 assert summary["limits"]==dict(cpu=90,wall=180,address=1<<30,core=0)
 assert summary["parent_plus_children_CPU_seconds"]<90 and summary["elapsed_seconds"]<180
 where=root/"cases"/label;process=json.loads(pin(where/"process.json"))
 assert process["predecessor_control"] and not process["timed_out"]
 assert process["executable_sha256"]==BUNDLE["original_executable_identity"]["sha256"]
 values={field:pin(where/(field+".bin")) for field in ("input","stdout","stderr")}
 for field,raw in values.items():
  assert (len(raw),digest(raw))==(process[field]["bytes"],process[field]["sha256"])
 return process,values
def retained_late_original(label):
 value=BUNDLE["original_six_public_cases"][label]
 result={}
 for field in ("input","stdout","stderr"):
  item=value[field];raw=pin(item["path"])
  assert (len(raw),digest(raw),gitsha(raw))==(item["bytes"],item["sha256"],item["gitsha"])
  result[field]=raw
 process=json.loads(pin(value["process_path"]))
 assert process["returncode"]==value["returncode"]==2 and not process["timed_out"]
 return process,result
def semantic():
 compatibility=a.group.startswith("compat-")
 if a.group in EXTRAS.COUNTS:EXTRAS.plan(globals(),a.group)
 else:plan()
 assert len(PLAN)==GROUPS[a.group]
 if a.predecessor_control:
  assert compatibility and a.control_results is None
 elif compatibility:
  assert a.control_results is not None
 pin_reference_modules()
 saved=[]
 for row in PLAN:
  saved.append(dict(label=row["label"],mode=row.get("mode",1),tree=row.get("tree",0),
   digits=row["digits"],input=cas(row["raw"]),expected=evidence_value(row["expected"])))
 save(OUT/"planned-corpus.json",saved)
 # Every original public oracle finishes before any target invocation.
 for index,row in enumerate(PLAN):
  mode,tree=row.get("mode",1),row.get("tree",0)
  lease=0x42504701+index*4;request=index+1
  original=None
  if a.group in BUNDLE["original_six_public_cases"]:
   old_process,original=retained_late_original(row["label"])
   header=struct.unpack_from("<8Q",original["input"])
   assert header[0]==magic("HIAWPI01") and header[3]==row["digits"]
   assert header[4]==len(row["raw"]) and header[5:]==(mode,tree,0)
   lease,request=header[1:3]
  data=packet(row["raw"],lease,request,row["digits"],mode,tree)
  if original is not None:assert data==original["input"]
  if compatibility and not a.predecessor_control:
   old_process,original=control_original(row["label"])
   assert data==original["input"]
  process,stdout,stderr,where=actual(row["label"],data)
  if mode==1 and tree==0:
   assert not a.predecessor_control
   result=parse_result(process,stdout,stderr,row,lease,request,where)
  else:
   original_planned=dict(row,expected=row["p16_expected"])
   complete=P16["parse_result"](process,stdout,stderr,original_planned,lease,request)
   result=dict(kind=row["expected"]["kind"],original_HIAWPE01=True,
     complete_original_payload_receipt_Core_and_error_equal=True,full_result=cas(complete))
  if original is not None:
   assert process["returncode"]==old_process["returncode"]
   assert stdout==original["stdout"] and stderr==original["stderr"]
   result["complete_predecessor_input_stdout_stderr_exit_equal"]=True
   result["predecessor_control"]=a.group.startswith("compat-")
   result["prior_six_original_case_readback"]=a.group in BUNDLE["original_six_public_cases"]
  ROWS.append(dict(label=row["label"],status="PASS",mode=mode,tree=tree,process=process,result=result))
  save(OUT/"cases-completed.json",ROWS)
def private_entry(command,workspace,label,output_size=128,advertised_work=None,predecessor=False):
 global PRIVATE_ENTRIES,PREDECESSOR_PRIVATE_ENTRIES,PRIVATE_RECORDS
 s=o=w=None
 try:
  s=Guard(command,readonly=True);o=Guard(b"",128,fill=0xa3);w=Guard(workspace)
  before=dict(command=cas(command),workspace=cas(workspace),output=cas(o.bytes()),
    advertised_output=output_size,advertised_work=len(workspace) if advertised_work is None else advertised_work)
  save(OUT/"pending-private.json",dict(label=label,before=before,source_hardware_readonly=True))
  image=IMAGES["predecessor-root" if predecessor else "root"]
  returned=int(image._entry(s.ptr,s.size,o.ptr,output_size,w.ptr,
    len(workspace) if advertised_work is None else advertised_work))
  if predecessor:PREDECESSOR_PRIVATE_ENTRIES+=1
  else:PRIVATE_ENTRIES+=1
  PRIVATE_RECORDS+=1
  for value in (s,o,w):value.check()
  result=w.bytes();output=o.bytes()
  save(OUT/"private-entries"/(str(PRIVATE_RECORDS).zfill(5)+".json"),
   dict(label=label,entry=PRIVATE_RECORDS,target_entry=PRIVATE_ENTRIES,
     predecessor_entry=PREDECESSOR_PRIVATE_ENTRIES,predecessor_control=predecessor,
     returned=returned,before=before,
     output_after=cas(output),workspace_after=cas(result),source_after=cas(s.bytes()),all_canaries_unchanged=True))
  assert s.bytes()==command
  return returned,result,output
 finally:close_guards((s,o,w))
def put(w,name,value,delta=0):struct.pack_into("<Q",w,CONSTANTS[name]+delta,value)
def get(w,name,delta=0):return struct.unpack_from("<Q",w,CONSTANTS[name]+delta)[0]
def state_initial():
 w=bytearray(CONSTANTS["MIN_WORK"])
 put(w,"CAPS",1);put(w,"CAPS",2,8);put(w,"CAPS",len(w),16)
 return w
def ack(w,payload=b""):
 return struct.pack("<8Q",magic("HIACDA01"),get(w,"C_LEASE"),get(w,"C_SEQUENCE"),
   get(w,"C_PENDING"),0,0,len(payload),0)+payload
def private_case(label,cmd,w,poison=True,output_size=128,advertised_work=None):
 global PRIVATE_CASES
 first=PRIVATE_ENTRIES+1
 returned,after,out=private_entry(cmd,bytes(w),label,output_size,advertised_work)
 assert returned==ABI,(label,returned)
 if poison:
  retry,unused,output=private_entry(cmd,after,label+"-permanent")
  assert retry==ABI,label
 PRIVATE_CASES+=1;ROWS.append(dict(label=label,status="PASS",private_synthetic_context=True,
  first_entry=first,last_entry=PRIVATE_ENTRIES,permanent_refusal_checked=poison))
def private_mode_compatibility(label,command,initial):
 global PRIVATE_CASES
 old=private_entry(command,bytes(initial),label+"-original",predecessor=True)
 new=private_entry(command,bytes(initial),label+"-unified")
 assert old==new and old[0]==128,(label,old[0],new[0])
 PRIVATE_CASES+=1
 ROWS.append(dict(label=label,status="PASS",private_synthetic_context=True,
  valid_original_mode_tree_preserved=True,complete_return_output_workspace_equal=True,
  predecessor_entries=1,new_entries=1))
def private():
 global PRIVATE_CASES
 assert a.issued_sample is not None
 sample_path=a.issued_sample.resolve();sample=json.loads(pin(sample_path))
 assert sample["schema"]=="hia-actual-program-Graph-sample-v1"
 assert sample["executable_sha256"]==BUNDLE["executable_sha256"] and sample["actual_process_returncode"]==0
 graph=pin(sample_path.parent/"issued-Graph.bin");core=pin(sample_path.parent/"actual-Core.bin")
 assert (len(graph),digest(graph))==(sample["actual_Graph"]["bytes"],sample["actual_Graph"]["sha256"])
 assert (len(core),digest(core))==(sample["actual_Core"]["bytes"],sample["actual_Core"]["sha256"])
 process=json.loads(pin(sample_path.parent/"process.json"))
 assert process["returncode"]==0 and process["executable_sha256"]==BUNDLE["executable_sha256"]
 full=pin(sample_path.parent/"stdout.bin");terminal=pin(sample_path.parent/"stderr.bin")
 assert len(terminal)==128 and digest(full)==sample["actual_full_result"]["sha256"]
 q=struct.unpack_from("<32Q",full)
 assert q[0]==magic("HIAWGE01") and full[q[18]:q[18]+q[19]]==graph
 assert full[q[12]:q[12]+q[13]]==core and full[368:400].hex()==digest(core)
 command=packet(b"{}",19,37)[:64];initial=state_initial()
 for at,value in ((0,0),(8,0),(8,MAX),(16,0),(24,639),(24,1<<32),(32,1),(40,0),(40,2),(48,1),(56,1)):
  raw=bytearray(command);struct.pack_into("<Q",raw,at,value)
  label="initial-header-"+str(at)+"-"+str(value)
  if (at,value) in ((40,2),(48,1)):
   private_mode_compatibility(label,bytes(raw),initial)
  else:private_case(label,bytes(raw),initial)
 for at,value in ((40,5),(48,2)):
  raw=bytearray(command);struct.pack_into("<Q",raw,at,value)
  private_case("new-invalid-header-"+str(at)+"-"+str(value),bytes(raw),initial)
 for n in (0,63,65):
  private_case("initial-extent-"+str(n),(command+b"\0")[:n],initial)
 for at in (CONSTANTS["CAPS"],CONSTANTS["CAPS"]+16,CONSTANTS["WP_MAGIC"],1048575):
  w=bytearray(initial);w[at]^=1
  private_case("initial-state-"+str(at),command,w)
 private_case("short-output",command,initial,output_size=127)
 private_case("short-workspace",command,initial,poison=False,advertised_work=len(initial)-1)
 returned,waiting,event=private_entry(command,bytes(initial),"actual-initial-event")
 assert returned==128 and struct.unpack_from("<Q",event,8)[0]==15
 valid=ack(waiting,bytes(160))
 # RUN_CHILD has returned=128; malformed header examples fail before any payload validation.
 valid=bytearray(valid);struct.pack_into("<Q",valid,40,128);valid=bytes(valid)
 for at,value in ((0,0),(8,20),(16,get(waiting,"C_SEQUENCE")+1),(24,1),(32,1),(48,159),(56,1)):
  raw=bytearray(valid);struct.pack_into("<Q",raw,at,value)
  private_case("initial-ACK-"+str(at),bytes(raw),waiting)
 def finished_state(phase):
  w=state_initial()
  for name,value in (("C_MAGIC",CONSTANTS["EDIT_STATE"]),("A_MAGIC",CONSTANTS["A_STATE_MAGIC"]),
   ("WP_MAGIC",CONSTANTS["WP_STATE"]),("WP_MODE",1),("WP_TREE",0),("WP_HAS_RECEIPT",1),
   ("L_MAGIC",CONSTANTS["LOWER_MAGIC"]),("L_STATUS",1),("L_DRIVER",56),
   ("C_LEASE",19),("C_SEQUENCE",11),("C_PENDING",14),("C_NEXT",phase),
   ("C_OBSERVE",64 if phase==91005 else 0),("BG_MAGIC",CONSTANTS["BG_STATE"]),
   ("E_REQUEST",37),("E_DIGITS",4300),("E_CORE_BYTES",len(core)),
   ("WP_CORE_SLOT",CONSTANTS["B_CORE"]),("WP_CORE_BYTES",len(core)),
   ("S_STATE",2),("S_KIND",2),("S_RESULT_CODE",128),("S_RESULT_EVENT_BYTES",128),
   ("S_RESULT_SLOT",32),("S_RESULT_BYTES",256+len(graph)),("BG_GRAPH_BYTES",len(graph))):
   put(w,name,value)
  put(w,"CAPS",len(core),CONSTANTS["B_CORE"]*8)
  for slot in range(32,50):put(w,"CAPS",256+len(graph) if slot==32 else 128,slot*8)
  event=[magic("HIAJDE01"),0,41,37,1,0,0,0,0,0,0,0,0,0,256,len(graph)]
  struct.pack_into("<16Q",w,CONSTANTS["S_RESULT_EVENT"],*event)
  if phase==91005:put(w,"CAPS",len(graph),CONSTANTS["B_GRAPH"]*8)
  return w
 waiting=finished_state(91001)
 # Positive private continuation observes exact operation sequence but supplies no fake
 # claim of public issuance. The Graph bytes themselves are from the preceding real ELF.
 expected_ops=[2,4,6,14]+[5]*18
 current=bytes(waiting);cmd=ack(current);events=[]
 for index,operation in enumerate(expected_ops):
  returned,current,event=private_entry(cmd,current,"private-complete-copy-release-"+str(index))
  assert returned==128
  words=struct.unpack("<16Q",event);assert words[1]==operation,(index,words)
  if operation==2:assert words[4:6]==(CONSTANTS["B_GRAPH"],len(graph))
  elif operation==4:assert words[4:9]==(32,256,CONSTANTS["B_GRAPH"],0,len(graph))
  elif operation==6:assert words[4:6]==(CONSTANTS["B_GRAPH"],1)
  elif operation==14:assert words[4:7]==(CONSTANTS["B_GRAPH"],0,64)
  else:assert words[4]==32+index-4
  events.append(list(words));cmd=ack(current,graph[:64] if operation==14 else b"")
 PRIVATE_CASES+=1;ROWS.append(dict(label="private-complete-copy-protect-view-release",status="PASS",
   private_synthetic_context=True,events=events,stopped_before_last_release_ACK=True))
 for name,value in (("BG_MAGIC",0),("WP_HAS_RECEIPT",0),("WP_MODE",2),("WP_TREE",1),
   ("S_STATE",1),("S_KIND",1),("S_RESULT_CODE",127),("S_RESULT_EVENT_BYTES",127),
   ("S_RESULT_BYTES",255+len(graph))):
  w=finished_state(91001);put(w,name,value)
  private_case("finished-field-"+name,ack(w),w)
 for at,value in ((0,0),(8,1),(16,42),(24,38),(104,1),(112,MAX),(120,127),(120,MAX)):
  w=finished_state(91001);put(w,"S_RESULT_EVENT",value,at)
  private_case("decoder-event-"+str(at),ack(w),w)
 for at,value in ((0,0),(8,42),(16,0),(24,0),(24,MAX),(32,MAX),(40,MAX),(48,len(graph)+1),(56,1)):
  w=finished_state(91005);head=bytearray(graph[:64]);struct.pack_into("<Q",head,at,value)
  private_case("Graph-header-"+str(at)+"-"+str(value),ack(w,head),w)
 for name,value in (("WP_MODE",2),("WP_MODE",3),("WP_TREE",1),("WP_TREE",2)):
  w=finished_state(91005);put(w,name,value)
  private_case("active-Graph-view-mode-tree-"+name+"-"+str(value),ack(w,graph[:64]),w)
 save(OUT/"cases-completed.json",ROWS)
 assert (PRIVATE_CASES,PRIVATE_ENTRIES,PREDECESSOR_PRIVATE_ENTRIES,PRIVATE_RECORDS)==(60,138,2,140)

PRIMARY=None
FINALIZATION_ERRORS=[]
def _final_failure(phase,exc):
 global PRIMARY,STATUS
 STATUS="FAIL"
 FINALIZATION_ERRORS.append(dict(phase=phase,error_class=type(exc).__name__,error=str(exc)))
 if PRIMARY is None:PRIMARY=exc
 elif exc is not PRIMARY:PRIMARY.add_note(phase+": "+repr(exc))
 return None
def _final_attempt(phase,operation):
 try:return operation()
 except BaseException as exc:return _final_failure(phase,exc)
def _finish_receipt(report,success_status,marker):
 global STATUS
 if PRIMARY is not None:STATUS="FAIL"
 def sync():
  report["status"]=STATUS
  report["finalization_errors"]=list(FINALIZATION_ERRORS)
  report["first_failure"]=(None if PRIMARY is None else
    dict(error_class=type(PRIMARY).__name__,error=str(PRIMARY)))
  if "complete_inner_readback" in report:report["complete_inner_readback"]=STATUS==success_status
  if "partial" in report:report["partial"]=STATUS!=success_status
 def measure(phase):
  measured=_final_attempt(phase,_elapsed_budget)
  if measured is None:return
  cpu,wall=measured
  report[phase]=dict(parent_plus_children_CPU_seconds=cpu,elapsed_seconds=wall)
  if cpu>=90 or wall>=180:_final_failure(phase,TimeoutError("strict final 90 CPU / 180 wall gate"))
 measure("pre_receipt_budget")
 sync()
 _final_attempt("write_summary",lambda:save(OUT/"summary.json",report))
 sync()
 _final_attempt("print_summary",lambda:print(marker+" "+json.dumps(report,sort_keys=True),flush=True))
 measure("post_output_budget")
 # A post-output failure must replace any earlier provisional PASS receipt.
 # Every output attempt is independent; the first exception remains primary.
 if STATUS!=success_status or PRIMARY is not None:
  STATUS="FAIL";sync()
  _final_attempt("rewrite_failure_summary",lambda:save(OUT/"summary.json",report))
  sync()
  _final_attempt("print_failure_summary",lambda:print(marker+"_FINAL_FAILURE "+json.dumps(report,sort_keys=True),flush=True))
  sync()
  _final_attempt("save_final_failure_summary",lambda:save(OUT/"summary.json",report))
 _final_attempt("disable_alarm",lambda:signal.setitimer(signal.ITIMER_REAL,0))
 # Account for successful receipt output and alarm cancellation before return.
 measured=_final_attempt("return_budget_measure",_elapsed_budget)
 if measured is not None and (measured[0]>=90 or measured[1]>=180):
  _final_failure("return_budget",TimeoutError("strict return 90 CPU / 180 wall gate"))
 if STATUS!=success_status or PRIMARY is not None:
  STATUS="FAIL";sync()
  _final_attempt("save_return_failure_summary",lambda:save(OUT/"summary.json",report))
  if PRIMARY is not None:raise PRIMARY
  raise SystemExit(1)

def _elapsed_budget():
 end=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
 return (end.ru_utime+end.ru_stime-INITIAL_SELF.ru_utime-INITIAL_SELF.ru_stime+
   children.ru_utime+children.ru_stime-INITIAL_CHILD.ru_utime-INITIAL_CHILD.ru_stime,
   (time.monotonic_ns()-START)/1e9)

try:
 pin(__file__);BUNDLE=json.loads(pin(a.bundle))
 assert BUNDLE["schema"]=="hia-unified-program-Graph-fixed-v1" and BUNDLE["status"]=="BUILT_ONLY"
 assert BUNDLE["nonzero_images"]==47 and BUNDLE["table_rows"]==63
 assert BUNDLE["actual_current_P16_head"]=="8f27671ad748dc7c081a1eaad897b057d8d9f42e"
 assert BUNDLE["current_late_Core_group6_routes_preserved"] and BUNDLE["full_original_P16_modes_and_tree_preserved"]
 assert BUNDLE["Graph_only_on_mode1_tree0_success"] and BUNDLE["original_other_modes_use_HIAWPE01"]
 assert BUNDLE["current_root_HIA_reproduced_before_extension"] and BUNDLE["current_type_context_error_routes_preserved"]
 assert BUNDLE["current_type_context_roles"]==[8,40,41,43,46,50,56]
 assert BUNDLE["current_reader50_child_kind0_drivers41_43_preserved"] and BUNDLE["current_role51_RWW_preserved"]
 assert BUNDLE["actual_new_B3_compilations"]==1 and BUNDLE["actual_native_packer_entries"]==1
 assert BUNDLE["new_compiler_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
 assert BUNDLE["retained_peer_compiler_sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
 elf=pin(BUNDLE["executable_path"])
 assert (len(elf),digest(elf))==(BUNDLE["executable_bytes"],BUNDLE["executable_sha256"])
 for row in BUNDLE["role_bindings"].values():
  assert (len(pin(row["source_path"])),digest(pin(row["source_path"])))==(row["source_bytes"],row["source_sha256"])
  assert (len(pin(row["image_path"])),digest(pin(row["image_path"])))==(row["image_bytes"],row["image_sha256"])
 prior=BUNDLE["original_root_binding"]
 assert (prior["source_bytes"],prior["source_sha256"])==(293304,"42c09f173d185133de7c9a661c7798aa24c66a01583f0d36a777942ccdde0902")
 assert (prior["image_bytes"],prior["image_sha256"])==(381135,"0f3745a833a17bae7c42c9017f6b8f944f7069200db876119ba434f93cc06d9d")
 for kind in ("source","image"):
  raw=pin(prior[kind+"_path"])
  assert (len(raw),digest(raw))==(prior[kind+"_bytes"],prior[kind+"_sha256"])
 RUN_EXECUTABLE=BUNDLE["executable_path"];RUN_EXECUTABLE_SHA=BUNDLE["executable_sha256"]
 if a.predecessor_control:
  assert a.group.startswith("compat-") and a.control_results is None
  RUN_EXECUTABLE=BUNDLE["original_executable_path"]
  original=pin(RUN_EXECUTABLE);ident=BUNDLE["original_executable_identity"]
  assert (len(original),digest(original),gitsha(original))==(ident["bytes"],ident["sha256"],ident["gitsha"])
  RUN_EXECUTABLE_SHA=ident["sha256"]
 CONSTANTS=json.loads(pin(BUNDLE["constants_path"]))
 sys.path.insert(0,str(REF))
 from hepta.hia_program import verify_program,HIAProgramRejected
 from hepta.hia_agent_assembly import render_assembly,assemble_program,diagnose_assembly,HIAAssemblyRejected
 from hepta.hia_json_preflight_native import NativeHiaJsonImage
 helper=PROJECT/"tests/unified_program_graph_extra_cases.py";raw=pin(helper)
 assert (len(raw),digest(raw))==(5172,"40ed7084f37b32a7393359cbf82c3c572b4b70fc1a54ded7dc03407e0625ca7f")
 spec=importlib.util.spec_from_file_location("unified_program_exact_extra_fixtures",helper)
 EXTRAS=importlib.util.module_from_spec(spec);spec.loader.exec_module(EXTRAS)
 P16=EXTRAS.prepare(globals())
 pin_reference_modules()
 if a.group=="private":
  row=BUNDLE["role_bindings"]["56"]
  IMAGES["root"]=NativeHiaJsonImage(pin(row["image_path"]),expected_sha256=row["image_sha256"])
  IMAGES["predecessor-root"]=NativeHiaJsonImage(pin(prior["image_path"]),expected_sha256=prior["image_sha256"])
  private()
 elif a.group=="late-private-protocol":
  assert not a.predecessor_control and a.control_results is None
  original_private=EXTRAS.private(globals())
  save(OUT/"original-late-private-result.json",original_private)
 else:
  for name,role in (("scan","29"),("emit","30")):
   row=BUNDLE["test_only_wire"][role]
   pin(row["source_path"])
   IMAGES[name]=NativeHiaJsonImage(pin(row["image_path"]),expected_sha256=row["image_sha256"])
  semantic()
 pin_reference_modules()
 assert len({row["label"] for row in ROWS})==len(ROWS)==GROUPS[a.group]
 if a.group=="private":
  assert (PRIVATE_ENTRIES,PREDECESSOR_PRIVATE_ENTRIES,ELF_PROCESSES,ORIGINAL_ELF_PROCESSES)==(138,2,0,0)
 elif a.group=="late-private-protocol":
  assert (PRIVATE_CASES,PRIVATE_ENTRIES,PREDECESSOR_PRIVATE_ENTRIES,ELF_PROCESSES,ORIGINAL_ELF_PROCESSES)==(38,105,0,0,0)
 elif a.predecessor_control:
  assert (ELF_PROCESSES,ORIGINAL_ELF_PROCESSES,PRIVATE_ENTRIES)==(0,GROUPS[a.group],0)
 else:
  assert (ELF_PROCESSES,ORIGINAL_ELF_PROCESSES,PRIVATE_ENTRIES)==(GROUPS[a.group],0,0)
 STATUS="PASS"
except BaseException as exc:
 PRIMARY=exc;STATUS="FAIL"
 FAILURE=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
 _final_attempt("original_traceback",lambda:traceback.print_exc())
finally:
 cleanup=[]
 for image in IMAGES.values():
  try:image._mapping.close()
  except BaseException as exc:
   cleanup.append(repr(exc));_final_failure("image_cleanup",exc)
 observed_after=_final_attempt("source_after",after_inputs)
 source_after=[] if observed_after is None else observed_after
 if observed_after is None or not all(x["same"] for x in source_after):
  _final_failure("source_after_identity",AssertionError("source before/after identity mismatch"))
 _final_attempt("source_after_receipt",lambda:save(OUT/"source-after.json",source_after))
 frozen=[]
 for index,(path,(raw,mode)) in enumerate(PINS.items()):
  try:
   target=OUT/"frozen-inputs"/str(index)/path.name;target.parent.mkdir(parents=True,exist_ok=True)
   target.write_bytes(raw);target.chmod(mode)
   assert target.read_bytes()==raw and stat.S_IMODE(target.stat().st_mode)==mode
   frozen.append(dict(path=str(path),snapshot=str(target),bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=mode))
  except BaseException as exc:_final_failure("freeze_input:"+str(path),exc)
 _final_attempt("source_pins_receipt",lambda:save(OUT/"source-pins.json",frozen))
 measured=_final_attempt("initial_final_budget_measure",_elapsed_budget)
 cpu,wall=(None,None) if measured is None else measured
 if measured is not None and (cpu>=90 or wall>=180):_final_failure("initial_final_budget",TimeoutError("actual prefix final resource gate"))
 report=dict(schema="hia-unified-program-Graph-actual-v1",status=STATUS,error=FAILURE,cleanup_errors=cleanup,
  group=a.group,variant=a.variant,planned_cases=GROUPS[a.group],completed_cases=len(ROWS),actual_ELF_processes=ELF_PROCESSES,
  actual_wire_native_entries=WIRE_ENTRIES,actual_private_native_entries=PRIVATE_ENTRIES,
  actual_predecessor_ELF_processes=ORIGINAL_ELF_PROCESSES,predecessor_control_only=a.predecessor_control,
  actual_predecessor_private_entries=PREDECESSOR_PRIVATE_ENTRIES,complete_private_entry_records=PRIVATE_RECORDS,
  private_cases=PRIVATE_CASES,source_image_inputs_before_after_equal=observed_after is not None and all(x["same"] for x in source_after),
  parent_plus_children_CPU_seconds=cpu,elapsed_seconds=wall,limits=dict(cpu=90,wall=180,address=1<<30,core=0),
  actual_program_admission_and_integer_Graph_issuance=any("Graph_wire" in row.get("result",{}) for row in ROWS),
  current_P16_late_Core_HIA_source_binding_required=True,full_original_mode_tree_contract=True,
  retained_type_and_late_diagnostic_cases_not_inherited=True,
  all_current_33_type_context_message_shapes_planned=a.group in ("type-names","type-shapes","type-order"),
  private_fixtures_authenticate_external_Graph=False,whole_public_backend=False,installed=False,cold=False,
  prior_results_inherited=False,Python_authoring_test_TCB=True)
 _finish_receipt(report,"PASS","HIA_UNIFIED_PROGRAM_GRAPH_GROUP_ORIGINAL")
