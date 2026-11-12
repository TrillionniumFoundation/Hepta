"""Actual ordered implementation-file reads and native incremental SHA.
The exact original _implementation_hash function is an oracle only. Runtime
policy is HIA. Fixed C and ctypes mechanics select no path, filename or digest.
Error tests currently establish errno and filename bytes, not rendered Python
exception text or the complete public backend. Every new group is independent.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ast,ctypes,json,lzma,os,resource,signal,stat,struct,sys,time,traceback,types,zlib
from functools import lru_cache
sys.dont_write_bytecode=True
BAD=0xfffffffd
MASK=(1<<64)-1
OWNER_SHA="a7fc5e1f656fdf4bacc3e35b754cc6f113c0b257b49dcc13c9a03fa5a23fc871"
REFERENCE_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
PINS={
 "implementation_files_mechanical_harness.py":"9d57ba12ab5f8b648faae7bb370b6719d527a6197a2cecbe36802966c4d289f4",
 "implementation_files_native_adapter.py":"c9ebdb266cc3a4e1b9796bc79ae412cfd73fd966e41217b28f7d5ff6ef4ae441",
 "function_frame_test_reference.py":"b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"}
def digest(raw):return sha256(raw).hexdigest()
def q(raw,at=0):return struct.unpack_from("<Q",raw,at)[0]
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
def change(raw,at,value):
 out=bytearray(raw);struct.pack_into("<Q",out,at,value);return bytes(out)
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def file_identity(path):
 path=Path(path);st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and not path.is_symlink() and st.st_nlink==1
 h=sha256();n=0
 with path.open("rb") as f:
  while True:
   b=f.read(1<<18)
   if not b:break
   h.update(b);n+=len(b)
 assert n==st.st_size
 return dict(bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(st.st_mode))
def load(name,path,expected):
 raw=Path(path).read_bytes();assert digest(raw)==expected,(str(path),digest(raw),expected)
 mod=types.ModuleType(name);mod.__file__=str(path);sys.modules[name]=mod
 exec(compile(raw,str(path),"exec"),mod.__dict__);return mod
def initial(root,request=1):
 raw=os.fsencode(root)
 return struct.pack("<8Q",magic("HIAIFI01"),1,19,request,64,len(raw),64+len(raw),0)+raw
def group_cpu():
 a=resource.getrusage(resource.RUSAGE_SELF);b=resource.getrusage(resource.RUSAGE_CHILDREN)
 return a.ru_utime+a.ru_stime+b.ru_utime+b.ru_stime
def snapshot_layout(directory):
 result=[]
 for path in sorted(Path(directory).rglob("*"),key=lambda p:os.fsencode(str(p))):
  st=path.lstat();row=dict(path_hex=os.fsencode(str(path.relative_to(directory))).hex(),mode=stat.S_IMODE(st.st_mode))
  if stat.S_ISLNK(st.st_mode):row.update(kind="symlink",target_hex=os.fsencode(os.readlink(path)).hex())
  elif stat.S_ISREG(st.st_mode):row.update(kind="file",**file_identity(path))
  elif stat.S_ISDIR(st.st_mode):row.update(kind="directory")
  else:raise AssertionError(("unexpected fixture kind",str(path),st.st_mode))
  result.append(row)
 return result

class Suite:
 def __init__(self,args):
  self.args=args;self.out=args.out;self.root=Path(__file__).resolve().parent;self.pins={}
  self.cases=[];self.protocol=0;self.entries=0;self.by_role={"1":0,"2":0};self.syscalls=0
  self.started_processes=0;self.encoding_cpu=0;self.encoding_wall=0
  self.pin(__file__)
  for path,value in PINS.items():self.pin(self.root/path,value)
  self.owner=load("implementation_file_owner_constants",self.root.parent/"tools/hia_implementation_files.py",OWNER_SHA)
  self.pin(self.root.parent/"tools/hia_implementation_files.py",OWNER_SHA)
  common_path=self.root.parent/"tools/hia_composite_lowering_driver_common.py"
  self.pin(common_path,self.owner.COMMON_SHA)
  common=load("implementation_file_common_constants",common_path,self.owner.COMMON_SHA)
  self.constants={**common.CONSTANTS,**self.owner.CONSTANTS};self.names=self.owner.FILES
  self.H=load("implementation_file_full_operand_mechanics",self.root/"implementation_files_mechanical_harness.py",PINS["implementation_files_mechanical_harness.py"])
  self.N=load("implementation_file_fixed_mechanics",self.root/"implementation_files_native_adapter.py",PINS["implementation_files_native_adapter.py"])
  self.assets=json.loads(self.pin(args.assets))
  assert self.assets["schema"]=="hia-implementation-files-runtime-assets-v1" and set(self.assets["roles"])=={"1","2"}
  for row in self.assets["roles"].values():
   for kind in("source","image"):
    m=row["manifest"];assert len(self.pin(m[kind+"_path"],m[kind+"_sha256"]))==m[kind+"_bytes"]
  self.pin(args.carrier);self.pin(args.carrier.with_suffix(".build.json"))
  self.pin(args.reference/"hepta/hia_json_preflight_native.py")
  raw=self.pin(args.reference/"hepta/hia_program_native.py",REFERENCE_SHA)
  tree=ast.parse(raw);node=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=="_implementation_hash")
  original_names=ast.literal_eval(next(x.iter for x in ast.walk(node) if isinstance(x,ast.For)))
  assert tuple(original_names)==self.names
  self.oracle=types.ModuleType("exact_implementation_fingerprint_oracle")
  self.oracle.__dict__.update(Path=Path,sha256=sha256,__file__="")
  exec(compile(ast.Module(body=[node],type_ignores=[]),str(args.reference/"hepta/hia_program_native.py"),"exec"),self.oracle.__dict__)
  save(self.out/"oracle-extraction.json",dict(reference_sha256=REFERENCE_SHA,
      original_function_AST_unchanged=True,function="_implementation_hash",ordered_names=list(self.names),
      target_runtime_calls_reference=False,host_digest_is_oracle_or_evidence_only=True))
  for name in self.names:self.pin(args.reference/"hepta"/name,REFERENCE_SHA if name=="hia_program_native.py" else None)
 def pin(self,path,expected=None):
  path=Path(path).absolute();identity=file_identity(path);raw=path.read_bytes()
  assert digest(raw)==identity["sha256"] and len(raw)==identity["bytes"]
  if expected is not None:assert identity["sha256"]==expected,(str(path),identity,expected)
  if path in self.pins:assert self.pins[path]==(raw,identity["mode"])
  else:
   self.pins[path]=(raw,identity["mode"]);target=self.out/"sources"/str(len(self.pins))/path.name
   target.parent.mkdir(parents=True);target.write_bytes(raw);target.chmod(identity["mode"])
  return raw
 def forbid(self,*a,**k):raise AssertionError("original implementation fingerprint used as runtime fallback")
 def oracle_result(self,root):
  self.oracle.__file__=os.fsdecode(root)+"/private_module_location.py"
  try:return dict(kind="success",sha256=self.oracle._implementation_hash())
  except OSError as exc:
   return dict(kind="OSError",class_name=type(exc).__name__,errno=exc.errno,
      filename_hex=None if exc.filename is None else os.fsencode(exc.filename).hex(),message=str(exc))
 def fixture(self,case,kind="varied",index=0):
  base=case/"fixture";base.mkdir()
  for i,name in enumerate(self.names):
   if kind=="reference":raw=self.pins[self.args.reference/"hepta"/name][0]
   elif kind=="empty":raw=b""
   elif kind=="large_one" and i==0:raw=(bytes(range(256))*32769)[:(8<<20)+1]
   elif kind=="large_total":raw=(bytes(range(251))*1993)[:500001]
   elif kind.startswith("chunk") and i==0:
    n=int(kind[5:]);raw=(bytes(range(256))*257)[:n]
   else:raw=struct.pack("<Q",i)+bytes(range(256))+name.encode()+b"\0end"
   (base/name).write_bytes(raw)
  root=os.fsencode(base);expect_index=None
  if kind=="missing":
   (base/self.names[index]).unlink();expect_index=index
  elif kind=="directory":
   (base/self.names[index]).unlink();(base/self.names[index]).mkdir();expect_index=index
  elif kind=="longpath":
   root+=b"/"+b"x"*5000;expect_index=0
  elif kind=="filelink":
   p=base/self.names[7];target=case/"linked-payload.bin";p.rename(target);p.symlink_to(target)
  elif kind in("parentlink","unicode","undecodable"):
   alias=case/("alias" if kind=="parentlink" else "caf\u00e9-\u03bb" if kind=="unicode" else os.fsdecode(b"alias-\xff"))
   alias.symlink_to(base,target_is_directory=True);root=os.fsencode(alias)
  elif kind=="trailing":root+=b"/"
  elif kind=="relative":root=os.fsencode(os.path.relpath(base,Path.cwd()))
  # Prevent atime changes from making the two actual fstat payloads differ.
  # This is an explicit fixture property, not a production filesystem rule.
  future=time.time_ns()+2*86400*10**9
  for path in case.rglob("*"):
   if path.is_file() and not path.is_symlink():
    os.utime(path,ns=(future,path.stat().st_mtime_ns))
  return root,expect_index
 def layout_begin(self,case):
  raw=snapshot_layout(case)
  # Only caller-created fixture entries are present before original evidence.
  save(case/"fixture-layout-before.json",raw);return raw
 def retire_aliases(self,case):
  rows=[];errors=[]
  for path in sorted(case.rglob("*"),key=lambda p:len(str(p)),reverse=True):
   if path.is_symlink():
    try:
     target=os.fsencode(os.readlink(path));path.unlink()
     rows.append(dict(path_hex=os.fsencode(str(path.relative_to(case))).hex(),target_hex=target.hex(),removed_owned_temporary_symlink=True))
    except BaseException as exc:errors.append(exc)
  save(case/"fixture-alias-retirement.json",rows)
  if errors:
   for exc in errors[1:]:errors[0].add_note(repr(exc))
   raise errors[0]
 def fixture_after(self,case,before):
  expected_paths={row["path_hex"] for row in before}
  current=[row for row in snapshot_layout(case) if row["path_hex"] in expected_paths]
  save(case/"fixture-layout-after.json",current)
  assert current==before,"original filesystem fixture bytes/modes/links changed"
 def record_final(self,actual,case,label):
  rows=[]
  for slot,b in sorted(actual.slots.items()):
   h=sha256()
   for at in range(0,b["size"],65536):h.update(actual.read(slot,at,min(65536,b["size"]-at)))
   rows.append(dict(slot=slot,bytes=b["size"],readonly=b["readonly"],sha256=h.hexdigest()))
  save(case/(label+"-final-slots.json"),rows);return rows
 def validate(self,actual,result,wire,expected,expected_index,case):
  assert result["status"]=="TERMINAL" and result["returned"]==128
  event=struct.unpack("<16Q",result["event"])
  assert event[:3]==(magic("HIACDE01"),7,19) and event[6:9]==(9,0,128)
  assert actual.slots[9]["readonly"]
  raw=result["payload"];assert len(raw)==128
  d=struct.unpack("<16Q",raw)
  assert d[:4]==(magic("HIAIFR01"),1,19,q(wire,24)) and d[15]==0
  assert event[4:6]==(d[4],d[8]) and event[9:12]==d[5:8] and event[12:]==(0,)*4
  if expected["kind"]=="success":
   assert d[4]==0 and d[5]==20 and d[8:11]==(0,0,0)
   assert d[11:]==(7,32,0,0,0) and actual.slots[7]["readonly"]
   payload=actual.read(7,0,32);assert payload.hex()==expected["sha256"]
   # Name and payload lengths are independently issued fixture facts, not
   # values taken from a target header to decide the reference hash.
   prefix=os.fsdecode(wire[64:])
   total=sum((Path(prefix)/name).stat().st_size for name in self.names)
   assert d[6]==total and d[7]==total+sum(len(name.encode())+2 for name in self.names)
  else:
   assert d[4]==1 and d[9]==expected["errno"] and d[10]==expected_index
   assert d[5]==expected_index and d[11]==4 and d[13]==0
   assert actual.slots[4]["readonly"]
   payload=actual.read(4,0,d[12])
   assert bool(d[14])==(expected["filename_hex"] is not None)
   if d[14]:assert payload.hex()==expected["filename_hex"]
   assert d[8]==(5 if expected["errno"]==21 else 1)
  save(case/"native-result-descriptor.json",dict(words=list(d),hex=raw.hex(),
       error_text_renderer_present=False,complete_public_exception_equivalence=False))
  return d
 def _clean(self,case,python,native,success,primary):
  errors=[]
  if python is not None:
   try:
    closed=python.close();assert python.owned==-1
    save(case/"python-closed.json",closed)
   except BaseException as exc:errors.append(exc)
  if native is not None:
   try:
    closed=native.close(encode=success)
    if success:
     e=closed["lossless_original_encoding"]
     self.encoding_cpu+=e["cpu_seconds"];self.encoding_wall+=e["wall_seconds"]
   except BaseException as exc:errors.append(exc)
  try:self.retire_aliases(case)
  except BaseException as exc:errors.append(exc)
  if primary is not None:
   for exc in errors:primary.add_note(repr(exc))
  elif errors:
   for exc in errors[1:]:errors[0].add_note(repr(exc))
   raise errors[0]
 def exact(self,label,kind="varied",index=0,backend="c",close_stdin=False):
  case=self.out/"cases"/("%04d"%len(self.cases));case.mkdir(parents=True)
  root,expected_index=self.fixture(case,kind,index);before=self.layout_begin(case)
  wire=initial(root,len(self.cases)+1);(case/"initial.bin").write_bytes(wire)
  expected=self.oracle_result(root);save(case/"reference.json",expected)
  assert (expected["kind"]=="OSError")==(expected_index is not None)
  python=None;native=None;success=False;saved_fd=None;original=self.oracle._implementation_hash
  self.oracle._implementation_hash=self.forbid
  try:
   if backend in("python","cross"):
    python=self.H.Mechanical(self.args.assets,self.args.reference,case/"python-full-CAS")
    if close_stdin:
     saved_fd=os.dup(0);os.close(0)
    try:result=python.run(wire)
    finally:
     if saved_fd is not None:os.dup2(saved_fd,0);os.close(saved_fd);saved_fd=None
    self.validate(python,result,wire,expected,expected_index,case)
    self.record_final(python,case,"python")
    if close_stdin:
     python.evidence.entries.flush()
     events=[json.loads(line) for line in (python.out/"entries.jsonl").read_text().splitlines()]
     assert any(v["status"]=="RAW_SYSCALL" and v["primitive"]==1 and v["raw_result"]==0 for v in events)
   if backend in("c","cross"):
    self.started_processes+=1
    native=self.N.NativeMechanical(self.args.assets,self.args.carrier,case/"fixed-native",wire)
    self.validate(native,native.result,wire,expected,expected_index,case)
    self.record_final(native,case,"native")
   compare=None
   if backend=="cross":
    assert native.result["payload"]==result["payload"] and native.result["event"]==result["event"]
    compare=native.compare_python(python);save(case/"two-carrier-whole-comparison.json",compare)
   self.fixture_after(case,before)
   by_role={str(i):sum(a.calls.get(i,0) for a in(python,native) if a is not None) for i in(1,2)}
   entries=sum(by_role.values());syscalls=sum(a.syscalls for a in(python,native) if a is not None)
   row=dict(label=label,status="PASS",kind="ACTUAL_FILESYSTEM_AND_NATIVE_SHA",backend=backend,
      reference=expected,native_entries=entries,by_role=by_role,raw_syscalls=syscalls,
      private=False,FD0_actual=close_stdin,full_small_CAS_crosscheck=compare is not None,
      native_full_syscall_payloads=True,full_public_backend=False,
      evidence_scope="full-CAS-and-final-native" if backend=="cross" else "full-CAS" if backend=="python" else "full-raw-syscalls-and-final-native")
   self.cases.append(row);self.entries+=entries;self.syscalls+=syscalls
   for role,n in by_role.items():self.by_role[role]+=n
   save(case/"result.json",row);success=True;return row
  finally:
   self.oracle._implementation_hash=original
   if saved_fd is not None:
    try:os.dup2(saved_fd,0)
    finally:os.close(saved_fd)
   self._clean(case,python,native,success,sys.exception())
 def private_bad(self,label,wire=None,inject=None):
  case=self.out/"cases"/("%04d"%len(self.cases));case.mkdir(parents=True)
  root,_=self.fixture(case);before=self.layout_begin(case)
  if wire is None:wire=initial(root,len(self.cases)+1)
  elif callable(wire):wire=wire(initial(root,len(self.cases)+1))
  (case/"initial.bin").write_bytes(wire)
  actual=None;original=self.oracle._implementation_hash;self.oracle._implementation_hash=self.forbid
  try:
   actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"python-full-CAS")
   result=actual.run(wire,intercept=inject)
   assert result["status"]=="PRIVATE_BAD",result
   first=actual.buffers.allocate(len(actual.last_original_ack or wire),actual.last_original_ack or wire,True)
   before_syscalls=actual.syscalls
   try:
    returned=actual.native(1,(first,actual.slots[3],actual.slots[2]),
       (first,actual.slots[3],actual.slots[2]),("private-repeat","slot3","slot2"))
    assert returned==BAD and actual.syscalls==before_syscalls
   finally:actual.buffers.close(first)
   self.record_final(actual,case,"python");self.fixture_after(case,before)
   row=dict(label=label,status="PASS",kind="PRIVATE_PERMANENT_BAD",private=True,
      native_entries=actual.entries,by_role={str(i):actual.calls.get(i,0) for i in(1,2)},
      raw_syscalls=actual.syscalls,interceptions=actual.interceptions,
      first_bad_event_hex=result["event"].hex(),second_return=returned,
      no_new_io_on_original_ACK_after_poison=True,evidence_scope="full-CAS")
   self.cases.append(row);self.protocol+=1;self.entries+=actual.entries;self.syscalls+=actual.syscalls
   for role,n in row["by_role"].items():self.by_role[role]+=n
   save(case/"result.json",row)
  finally:
   self.oracle._implementation_hash=original
   self._clean(case,actual,None,False,sys.exception())
 def short_buffer(self,output,work):
  case=self.out/"cases"/("%04d"%len(self.cases));case.mkdir(parents=True)
  wire=initial(b"");(case/"initial.bin").write_bytes(wire);actual=None
  try:
   actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"python-full-CAS")
   a=actual.buffers.allocate(len(wire),wire,True);o=actual.buffers.allocate(output);w=actual.buffers.allocate(work)
   actual.slots={1:a,3:o,2:w}
   before=[ctypes.string_at(b["address"],b["size"]) for b in(o,w)]
   returned=actual.native(1,(a,o,w),(a,o,w),("short-input","short-output","short-work"))
   assert returned==BAD and [ctypes.string_at(b["address"],b["size"]) for b in(o,w)]==before
   assert actual.syscalls==0
   self.record_final(actual,case,"python")
   row=dict(label="short-output-%d-work-%d"%(output,work),status="PASS",kind="PRIVATE_SHORT_BUFFER",
       private=True,native_entries=1,by_role={"1":1,"2":0},raw_syscalls=0,evidence_scope="full-CAS",
       complete_output_workspace_unchanged=True,permanent_state_not_claimed_for_short_buffer=True)
   self.cases.append(row);self.protocol+=1;self.entries+=1;self.by_role["1"]+=1;save(case/"result.json",row)
  finally:self._clean(case,actual,None,False,sys.exception())
 def cross_group(self):
  for kind in("empty","varied"):self.exact("cross-"+kind,kind,backend="cross")
 def normal_group(self):
  for kind in("reference","empty","varied","unicode","undecodable","trailing","relative",
              "filelink","parentlink","chunk65535","chunk65536","chunk65537"):
   self.exact("normal-"+kind,kind)
 def errors_group(self):
  for i in range(20):self.exact("missing-%02d"%i,"missing",i)
  for i in(0,9,19):self.exact("directory-%02d"%i,"directory",i)
  self.exact("kernel-ENAMETOOLONG","longpath")
 def large_group(self,variant):
  self.exact("no-new-8MiB-budget-"+str(variant),"large_one" if variant==0 else "large_total")
 def fd0_group(self):self.exact("actual-owned-file-descriptor-zero",backend="python",close_stdin=True)
 def initial_group(self):
  for at,value in((0,0),(8,2),(16,0),(24,0),(32,0),(40,MASK),(48,0),(56,1)):
   self.private_bad("initial-field-"+str(at),lambda raw,at=at,value=value:change(raw,at,value))
  for label,fn in(("empty",lambda raw:b""),("short",lambda raw:raw[:63]),
       ("truncated",lambda raw:raw[:-1]),("extra",lambda raw:raw+b"x"),
       ("NUL",lambda raw:raw[:64]+b"\0"+raw[65:]),("wrong-total",lambda raw:change(raw,48,len(raw)+1))):
   self.private_bad("initial-"+label,fn)
  self.short_buffer(127,65536);self.short_buffer(128,65535)
 def ack_group(self):
  variants=[("q"+str(at),lambda raw,at=at,value=value:change(raw,at,value))
    for at,value in((0,0),(8,20),(16,0),(24,99),(32,1),(40,1),(48,1),(56,1))]
  variants +=[("short",lambda raw:raw[:-1]),("extra",lambda raw:raw+b"x")]
  for label,alter in variants:
   used=[False]
   def inject(actual,event,ack):
    if not used[0]:used[0]=True;return alter(ack)
    return ack
   self.private_bad("ACK-"+label,inject=inject);assert used[0]
 def state_group(self):
  for key in("C_PHASE","C_PENDING","C_NEXT","C_ALLOC_SLOT","C_ALLOC_BYTES","CAPS",
             "L_DRIVER","F_INDEX","F_HASH_BYTES","ARGS","NAME_AT","WIRE"):
   used=[False];at=self.constants[key]
   def inject(actual,event,ack):
    if not used[0]:
     used[0]=True;b=actual.slots[2];old=ctypes.string_at(b["address"]+at,1)
     new=bytes((old[0]^1,));ctypes.memmove(b["address"]+at,new,1)
     actual.evidence.entry(dict(status="PRIVATE_WORKSPACE_MUTATION",offset=at,before=old.hex(),after=new.hex()))
    return ack
   self.private_bad("issued-pin-"+key,inject=inject);assert used[0]
 def operation_group(self):
  for primitive,values in((1,(0,2)),(2,(65537,MASK-4095)),(3,(1,2)),(4,(1,2))):
   for bad in values:
    used=[False]
    def inject(actual,event,ack):
     fields=struct.unpack("<16Q",event)
     if not used[0] and fields[1]==19 and fields[4]==primitive:
      used[0]=True;return change(ack,40,bad)
     return ack
    self.private_bad("raw-result-%d-%d"%(primitive,bad),inject=inject);assert used[0]
 def hash_group(self):
  for action in(0,1,2):
   used=[False]
   def inject(actual,event,ack):
    fields=struct.unpack("<16Q",event)
    if not used[0] and fields[1]==1 and fields[4]==2:
     command=actual.read(fields[5],fields[6],fields[7])
     if command[0]==action:used[0]=True;return change(ack,40,q(ack,40)+1)
    return ack
   self.private_bad("actual-SHA-return-"+str(action),inject=inject);assert used[0]
 def finish(self):
  rows=[]
  for i,(path,(raw,mode)) in enumerate(self.pins.items(),1):
   now=file_identity(path);same=path.read_bytes()==raw and now["mode"]==mode
   rows.append(dict(path=str(path),snapshot=str(Path("sources")/str(i)/path.name),
       bytes=len(raw),sha256=digest(raw),mode=mode,same=same))
  save(self.out/"source-before-after.json",rows);assert all(row["same"] for row in rows)
  return dict(files=len(rows),all_bytes_and_modes_equal=True)

SCHEDULE=[["cross",0,2,0],["normal",0,12,0],["errors",0,24,0],
 ["large",0,1,0],["large",1,1,0],["fd0",0,1,0],["initial",0,16,16],
 ["ack",0,10,10],["state",0,12,12],["operation",0,8,8],["hash",0,3,3]]

def source_tree_identity(root,path):
 rows=0;total=0
 with Path(path).open("w",encoding="utf-8") as dst:
  for directory,dirs,files in os.walk(root,followlinks=False):
   dirs.sort();files.sort()
   for name in dirs:assert not (Path(directory)/name).is_symlink()
   for name in files:
    f=Path(directory)/name;row=dict(path=str(f.relative_to(root)),**file_identity(f))
    dst.write(json.dumps(row,sort_keys=True,ensure_ascii=True)+"\n");rows+=1;total+=row["bytes"]
 return dict(files=rows,raw_bytes=total,ledger=file_identity(path))

def readback_cas(directory):
 after=json.loads((directory/"source-after.json").read_bytes())
 assert after["status"]=="PASS" and after["source_pins_unchanged"]
 @lru_cache(maxsize=64)
 def page(h):
  raw=zlib.decompress((directory/"cas"/(h+".zlib")).read_bytes())
  assert len(raw)<=4096 and digest(raw)==h
  return raw
 all_pages=0;raw_pages=0
 for path in sorted((directory/"cas").glob("*.zlib")):
  raw=page(path.stem);all_pages+=1;raw_pages+=len(raw)
 assert (all_pages,raw_pages)==(after["cas_pages"],after["cas_raw_bytes"])
 previous={};snapshots={};logical=0
 with (directory/"snapshots.jsonl").open() as f:
  for line in f:
   row=json.loads(line);assert row["id"]==len(snapshots) and row["page_size"]==4096
   old=previous.get(row["key"]);assert row["base"]==(None if old is None else old[0])
   pages=[] if old is None else list(old[1][:row["page_count"]])
   pages.extend([None]*(row["page_count"]-len(pages)));seen=set()
   for index,h in row["changed"]:
    assert 0<=index<len(pages) and index not in seen;seen.add(index);pages[index]=h
   h=sha256();n=0
   for number,p in enumerate(pages):
    assert p is not None;raw=page(p)
    assert len(raw)==min(4096,row["bytes"]-number*4096);h.update(raw);n+=len(raw)
   assert n==row["bytes"] and h.hexdigest()==row["sha256"]
   snapshots[row["id"]]=(row["bytes"],row["sha256"]);previous[row["key"]]=(row["id"],pages)
   logical+=n
 assert logical==after["logical_buffer_bytes"] and len(snapshots)==after["complete_snapshot_descriptors"]
 def payload(value):
  if type(value) is dict:
   if set(("bytes","sha256","pages"))<=set(value):
    raw=b"".join(page(h) for h in value["pages"])
    assert len(raw)==value["bytes"] and digest(raw)==value["sha256"]
   elif set(("id","key","bytes","sha256"))<=set(value):
    assert snapshots[value["id"]]==(value["bytes"],value["sha256"])
   for x in value.values():payload(x)
  elif type(value) is list:
   for x in value:payload(x)
 entered={};returned={};commands=0;syscalls=0
 with (directory/"entries.jsonl").open() as f:
  for line in f:
   row=json.loads(line);payload(row)
   if row["status"]=="ENTERING":
    assert row["number"] not in entered;entered[row["number"]]=row
   elif row["status"]=="RETURNED":
    n=row["number"];assert n in entered and n not in returned
    assert row["role"]==entered[n]["role"] and row["before"]==entered[n]["before"]
    assert row["canaries_intact"]
    for i,ro in enumerate(row["readonly"]):
     if ro:assert row["before"][i]["sha256"]==row["after"][i]["sha256"]
    returned[n]=row
   elif row["status"]=="MECHANICAL_ACK":commands+=1
   elif row["status"]=="RAW_SYSCALL":syscalls+=1;assert row["number"]==syscalls
 assert set(entered)==set(returned)
 for number,row in enumerate(after["pins"],1):
  copy=directory/"sources"/str(number)/Path(row["path"]).name
  assert copy.read_bytes()==Path(row["path"]).read_bytes()
  assert file_identity(copy)["sha256"]==row["sha256"] and file_identity(copy)["bytes"]==row["bytes"]
 return dict(native_entries=len(returned),commands=commands,raw_syscalls=syscalls,
     snapshots=len(snapshots),logical_buffer_bytes=logical,CAS_pages=all_pages,all_complete_raw_bytes_checked=True)

def encoded_row(directory,name):
 doc=json.loads((directory/"exact-raw-encoding.json").read_bytes())
 rows=[r for r in doc["rows"] if Path(r["raw_path"]).name==name];assert len(rows)==1
 row=rows[0];path=Path(row["encoded_path"])
 assert path.parent==directory and path.name==name+".xz" and not Path(row["raw_path"]).exists()
 assert row["compression"]=="xz-crc64-preset3" and row["all_decoded_bytes_compared_to_actual_raw"]
 identity=file_identity(path)
 assert {k:identity[k] for k in("bytes","sha256")}==row["encoded"] and identity["mode"]==row["encoded_mode"]==row["raw_mode"]
 h=sha256();n=0
 with lzma.open(path,"rb") as stream:
  while True:
   b=stream.read(1<<18)
   if not b:break
   h.update(b);n+=len(b)
 assert dict(bytes=n,sha256=h.hexdigest())==row["raw"]==row["decoded"]
 return path,row["raw"]

def final_readback(path,identity,expected,adapter):
 total=0;whole=sha256()
 with lzma.open(path,"rb") as stream:
  def read(n):
   nonlocal total
   raw=adapter.read_exact(stream,n);whole.update(raw);total+=len(raw);return raw
  head=struct.unpack("<8Q",read(64));assert head[:2]==(magic("HIAEMXS1"),1) and head[5]==len(expected)
  event=read(128);assert head[6:]==(128,0)
  for row in expected:
   slot,n,ro,owned,*reserved=struct.unpack("<8Q",read(64))
   assert (slot,n,bool(ro),owned)==(row["slot"],row["bytes"],row["readonly"],1)
   assert ro in(0,1) and reserved==[0]*4
   h=sha256();left=n
   while left:
    b=read(min(1<<18,left));h.update(b);left-=len(b)
   assert h.hexdigest()==row["sha256"]
  assert stream.read(1)==b""
 assert dict(bytes=total,sha256=whole.hexdigest())==identity
 return dict(complete_slot_bytes=True,slots=len(expected),event_hex=event.hex(),returned=head[4],native_entries=head[2],commands=head[3])

def readback_group(args):
 root=args.readback_group.resolve();out=args.out;report=dict(status="INCOMPLETE",target_entries=0)
 assert out!=root and not out.is_relative_to(root),"readback output must not alter its original input"
 before=None;primary=None
 try:
  adapter=load("implementation_file_readback_adapter",Path(__file__).with_name("implementation_files_native_adapter.py"),PINS["implementation_files_native_adapter.py"])
  before=source_tree_identity(root,out/"inputs-before.jsonl")
  assets=json.loads(args.assets.read_bytes())
  summary=json.loads((root/"summary.json").read_bytes());assert summary["status"]=="PASS"
  cases=[];entries=0;syscalls=0;private=0
  for case in sorted((root/"cases").iterdir()):
   row=json.loads((case/"result.json").read_bytes());assert row["status"]=="PASS"
   actual_entries=0;actual_syscalls=0;observation=dict(case=case.name,label=row["label"])
   if (case/"python-full-CAS").is_dir():
    value=readback_cas(case/"python-full-CAS");actual_entries+=value["native_entries"];actual_syscalls+=value["raw_syscalls"]
    observation["full_CAS"]=value
   if (case/"fixed-native").is_dir():
    native=case/"fixed-native";trace,trace_id=encoded_row(native,"trace.bin")
    final,final_id=encoded_row(native,"final-slots.bin")
    initial_raw=(case/"initial.bin").read_bytes()
    assert (native/"initial.bin").read_bytes()==initial_raw
    value=adapter.validate_trace(trace,assets,initial_raw,trace_id["bytes"])
    assert value==json.loads((native/"trace-summary.json").read_bytes())
    slots=json.loads((case/"native-final-slots.json").read_bytes())
    final_value=final_readback(final,final_id,slots,adapter)
    assert (final_value["event_hex"],final_value["returned"],final_value["native_entries"],final_value["commands"])==(value["terminal_hex"],value["returned"],value["native_entries"],value["commands"])
    actual_entries+=value["native_entries"];actual_syscalls+=value["raw_syscalls"]
    observation["fixed_native"]=dict(trace=value,final=final_value)
   assert actual_entries==row["native_entries"] and actual_syscalls==row["raw_syscalls"]
   entries+=actual_entries;syscalls+=actual_syscalls;private+=int(row["private"]);cases.append(observation)
  assert (len(cases),entries,syscalls,private)==(summary["cases"],summary["native_entries"],summary["raw_syscalls"],summary["private_protocol_controls"])
  for row in json.loads((root/"source-before-after.json").read_bytes()):
   assert row["same"];copy=root/row["snapshot"]
   assert file_identity(copy)=={k:row[k] for k in("bytes","sha256","mode")}
   assert copy.read_bytes()==Path(row["path"]).read_bytes()
  report.update(status="PASS",cases=len(cases),source_execution_not_repeated=True,
     original_native_entries=entries,original_raw_syscalls=syscalls,original_private_controls=private,
     full_CAS_count=sum("full_CAS" in row for row in cases),
     fixed_native_processes=sum("fixed_native" in row for row in cases),details=cases)
 except BaseException as exc:
  primary=exc;report.update(status="FAIL",error=repr(exc),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  after_error=None
  try:
   after=source_tree_identity(root,out/"inputs-after.jsonl");report["inputs_after"]=after
   if before is not None:
    with (out/"inputs-before.jsonl").open("rb") as a,(out/"inputs-after.jsonl").open("rb") as b:
     while True:
      x=a.read(1<<18);y=b.read(1<<18);assert x==y
      if not x:break
    report["complete_input_bytes_modes_unchanged"]=True
  except BaseException as exc:
   after_error=exc;report.update(status="FAIL",after_check_error=repr(exc))
   if primary is not None:primary.add_note(repr(exc))
  report["inputs_before"]=before
  save_error=None
  try:save(out/"readback.json",report)
  except BaseException as exc:
   save_error=exc
   if primary is not None:primary.add_note("readback evidence save failed: "+repr(exc))
   elif after_error is not None:after_error.add_note("readback evidence save failed: "+repr(exc))
  if primary is not None:raise primary
  if after_error is not None:raise after_error
  if save_error is not None:raise save_error
 return report

def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def deadline(*unused):raise TimeoutError("implementation file group original 180 wall")
 signal.signal(signal.SIGALRM,deadline);signal.alarm(180)
 p=argparse.ArgumentParser()
 p.add_argument("--assets",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
 p.add_argument("--carrier",type=Path);p.add_argument("--reference",type=Path)
 p.add_argument("--group");p.add_argument("--variant",type=int,default=0)
 p.add_argument("--readback-group",type=Path)
 args=p.parse_args();args.out=args.out.resolve();args.out.mkdir(parents=True,exist_ok=False)
 args.assets=args.assets.resolve()
 started=time.monotonic();suite=None;summary=dict(status="INCOMPLETE",all_prior_results_inherited=False)
 try:
  assert sys.version_info[:3]==(3,12,14)
  if args.readback_group is not None:
   summary.update(readback_group(args));summary["scope"]="INDEPENDENT_ORIGINAL_BYTES_READBACK";summary["native_entries"]=0
  else:
   assert args.carrier is not None and args.reference is not None and args.group is not None
   args.carrier=args.carrier.resolve();args.reference=args.reference.resolve()
   selected=[r for r in SCHEDULE if r[:2]==[args.group,args.variant]];assert len(selected)==1
   suite=Suite(args)
   methods={"cross":suite.cross_group,"normal":suite.normal_group,"errors":suite.errors_group,
       "fd0":suite.fd0_group,"initial":suite.initial_group,"ack":suite.ack_group,
       "state":suite.state_group,"operation":suite.operation_group,"hash":suite.hash_group}
   if args.group=="large":suite.large_group(args.variant)
   else:methods[args.group]()
   assert (len(suite.cases),suite.protocol)==tuple(selected[0][2:])
   assert group_cpu()<=90
   summary.update(status="PASS",scope="ACTUAL_FILESYSTEM_PLUS_NATIVE_SHA_OR_PRIVATE_PROTOCOL")
 except BaseException as exc:
  summary.update(status="FAIL",error=repr(exc),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  if suite is not None:
   summary.update(group=args.group,variant=args.variant,cases=len(suite.cases),
       private_protocol_controls=suite.protocol,native_entries=suite.entries,by_role=suite.by_role,
       raw_syscalls=suite.syscalls,started_C_processes=suite.started_processes,
       evidence_encoding_cpu_seconds=suite.encoding_cpu,evidence_encoding_wall_seconds=suite.encoding_wall,
       original_group_limits_include_evidence_encoding=True,
       complete_exception_text=False,all_filenames_order_and_hash_decisions_native=True,
       actual_core_admission=False,complete_public_backend=False,
       development_C_and_Python_authoring_remain_TCB=True)
   try:summary["source_custody"]=suite.finish()
   except BaseException as exc:
    summary.update(status="FAIL",cleanup_error=repr(exc),cleanup_traceback=traceback.format_exc());traceback.print_exc()
  cpu=group_cpu();elapsed=time.monotonic()-started
  if cpu>90 or elapsed>=180:summary.update(status="FAIL",final_budget_exceeded=True)
  summary.update(parent_plus_children_CPU_seconds=cpu,elapsed_seconds=elapsed,
       limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),
       core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180),installed=False,cold=False)
  save(args.out/"summary.json",summary);print(json.dumps(summary,sort_keys=True),flush=True);signal.alarm(0)
 if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
