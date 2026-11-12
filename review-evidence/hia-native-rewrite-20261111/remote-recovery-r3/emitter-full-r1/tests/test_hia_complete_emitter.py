"""Whole original _Emitter differential across eleven actual HIA images.
The reference is used only to construct fixtures/admission and expected results.
No Python-generated instruction, symbol plan, Code command or ELF is supplied
to the native chain. Native-only boundary traces are explicitly separate from
the retained per-entry full-workspace Python-CAS crosschecks.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes,importlib.abc,importlib.util,json,os,resource,signal,stat,struct,sys,time,traceback,types
sys.dont_write_bytecode=True
BAD=0xfffffffd
MASK=(1<<64)-1
PINS={
 "emitter_mechanical_harness.py":"4f93c246c3ad4e4b83089821ed328ec6d52097be6994c17b36dfd2e2a7919f1a",
 "emitter_native_adapter.py":"6211db1e02e094e627e65601bb5c12bf5534400f9fabcc00ce0b8fa35af2d408",
 "function_frame_test_reference.py":"b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6",
 "function_code_test_reference.py":"61dbf40a99220f2f5b6db7950ee8e3a53299530d385fee70877ade6a0e387c11",
 "function_lowering_test_reference.py":"e08023ddab7501313a45825e5e2cdbba40d3524fee3e4a0f9ad33ba65335bc17",
 "wrapper_test_reference.py":"30950bd89da646f64061fc55bd0b855178c7e20fd214485b58b20ad86b4bd470"}
REF_PINS={
 "hepta/hia_program_native.py":"bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c",
 "hepta/hia_machine_x64.py":"8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9",
 "hepta/hia_machine_plan.py":"ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a",
 "hepta/hia_native_byte_abi.py":"0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6"}
def digest(raw):return sha256(raw).hexdigest()
def q(raw,at=0):return struct.unpack_from("<Q",raw,at)[0]
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
def changed(raw,at,value):
 out=bytearray(raw);struct.pack_into("<Q",out,at,value);return bytes(out)
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def load(name,path,expected):
 raw=Path(path).read_bytes();assert digest(raw)==expected,(path,digest(raw),expected)
 m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m
 exec(compile(raw,str(path),"exec"),m.__dict__);return m
def initial(graph,*,lease=19,request=1,graphlease=17,codelease=41,structured=False):
 return struct.pack("<16Q",magic("HIAEMB01"),1,lease,request,graphlease,codelease,q(graph,24),len(graph),int(structured),*([0]*7))+graph
class FrozenImports(importlib.abc.MetaPathFinder,importlib.abc.Loader):
    def __init__(self,root,files):self.root,self.files=root,files
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split(".")[0] not in ("hepta","tools"):return None
        base=self.root.joinpath(*fullname.split("."))
        for candidate,package in ((base.with_suffix(".py"),False),(base/"__init__.py",True)):
            if candidate in self.files:
                return importlib.util.spec_from_file_location(fullname,candidate,loader=self,
                    submodule_search_locations=[str(base)] if package else None)
        if any(p.is_relative_to(base) for p in self.files):
            spec=importlib.util.spec_from_loader(fullname,loader=None,is_package=True)
            spec.submodule_search_locations=[str(base)];return spec
        raise ModuleNotFoundError("file absent from immutable reference snapshot: "+fullname)
    def create_module(self,spec):return None
    def exec_module(self,module):
        path=Path(module.__spec__.origin)
        exec(compile(self.files[path],str(path),"exec"),module.__dict__)
class Suite:
 def __init__(self,args):
  self.args=args;self.root=Path(__file__).resolve().parent;self.out=args.out
  self.started=time.monotonic();self.cases=[];self.native_entries=0;self.by_role={i:0 for i in range(1,12)}
  self.protocol=0;self.admitted=0;self.private_profile=0;self.child_cpu=0
  self.encoding_cpu=0;self.encoding_wall=0
  self.pins={}
  for name,h in PINS.items():self.pin(self.root/name,h)
  self.pin(__file__)
  self.pin(self.root.parent/"tools/hia_emitter_controller.py","3d61004c26b89fdec53b4457659ae4eccd8f2fcd73b8f260fafa716d0af01665")
  self.H=load("whole_emitter_mechanics",self.root/"emitter_mechanical_harness.py",PINS["emitter_mechanical_harness.py"])
  self.N=load("whole_emitter_native",self.root/"emitter_native_adapter.py",PINS["emitter_native_adapter.py"])
  self.F=self.H.F
  self.M=load("whole_emitter_function_fixtures",self.root/"function_lowering_test_reference.py",PINS["function_lowering_test_reference.py"]);self.M.F=self.F
  self.W=load("whole_emitter_wrapper_fixtures",self.root/"wrapper_test_reference.py",PINS["wrapper_test_reference.py"]);self.W.F=self.F
  self.control=load("whole_emitter_control_source",self.root.parent/"tools/hia_emitter_controller.py","3d61004c26b89fdec53b4457659ae4eccd8f2fcd73b8f260fafa716d0af01665")
  for prefix in("hepta","tools"):
   for path in sorted((args.reference/prefix).rglob("*.py")):self.pin(path,REF_PINS.get(str(path.relative_to(args.reference))))
  for path,h in REF_PINS.items():self.pin(args.reference/path,h)
  frozen={p:raw for p,(raw,mode) in self.pins.items() if p.is_relative_to(args.reference) and p.suffix==".py"}
  assert not any(n.split(".")[0] in ("hepta","tools") for n in sys.modules)
  sys.meta_path.insert(0,FrozenImports(args.reference,frozen))
  sys.path.insert(0,str(args.reference))
  from hepta import hia_program_native,hia_native_byte_abi,hia_machine_x64
  from hepta.hia_program import verify_program
  from hepta.hia_machine_plan import validate_plan
  self.original=hia_program_native;self.byte=hia_native_byte_abi;self.code=hia_machine_x64
  self.verify=verify_program;self.validate_plan=validate_plan
  self.assets=json.loads(self.pin(args.assets));assert set(map(int,self.assets["roles"]))==set(range(1,12))
  for row in self.assets["roles"].values():
   m=row["manifest"]
   for typ in("source","image"):assert len(self.pin(m[typ+"_path"],m[typ+"_sha256"]))==m[typ+"_bytes"]
  self.pin(args.carrier);self.pin(args.carrier.with_suffix(".build.json"))
 def pin(self,path,expected=None):
  path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
  if expected is not None:assert digest(raw)==expected,(path,digest(raw),expected)
  if path in self.pins:assert self.pins[path]==(raw,mode)
  else:
   self.pins[path]=(raw,mode);target=self.out/"sources"/str(len(self.pins))/path.name
   target.parent.mkdir(parents=True);target.write_bytes(raw);target.chmod(mode)
  return raw
 def forbidden(self,*a,**k):raise AssertionError("old semantic backend runtime fallback")
 def guard(self):
  targets=[(self.original._Emitter,"render"),(self.original._Emitter,"wrapper"),
   (self.original._Function,"render"),(self.original._Function,"operation"),
   (self.original,"write_elf_object"),(self.byte,"emit_wrapper"),(self.byte,"normalize_exports")]
  for name in("emit","mov_imm","call","jmp","jcc","label","align","finalize"):
   targets.append((self.code.Code,name))
  saved=[(obj,name,getattr(obj,name)) for obj,name in targets]
  for obj,name,_ in saved:setattr(obj,name,self.forbidden)
  return saved
 @staticmethod
 def unguard(saved):
  for obj,name,value in saved:setattr(obj,name,value)
 def count(self,actual):
  self.native_entries+=actual.entries
  for role,n in actual.calls.items():self.by_role[int(role)]+=n
 def allowed(self,document):
  scalars={"i8","u8","i16","u16","i32","u32","i64","u64","isize","usize","bool","unit"}
  if "exports" in document:return frozenset(document["exports"])
  return frozenset(fn["name"] for fn in document["functions"] if all(p["type"] in scalars for p in fn["params"]) and all(t in scalars for t in fn["returns"]))
 def oracle(self,doc,plan,foreign,private=False,structured=False):
  if private:
   document=copy.deepcopy(doc)
   checked=types.SimpleNamespace(as_dict=lambda:copy.deepcopy(document),structured_bytes=b"private-issued-origin" if structured else None,scalar_entrypoints=self.allowed(document))
   self.private_profile+=1
  else:
   checked=self.verify(doc);document=checked.as_dict();self.admitted+=1
   assert not structured or checked.structured_bytes is not None
  emitter=None;error=None;normalized=None;result=None
  try:
   normalized=self.byte.normalize_exports(foreign,checked)
   if plan is not None:
    plan=copy.deepcopy(plan);plan["core_sha256"]=checked.sha256
    plan=self.validate_plan(checked,plan)
   emitter=self.original._Emitter(document,checked.scalar_entrypoints,
       None if plan is None else plan["block_order"],normalized,plan)
   result=emitter.render()
  except (self.original.HIAProgramNativeRejected,self.code.MachineEncodingError) as exc:
   error=exc
  return document,plan,emitter,normalized,result,error
 def code_state(self,actual,oracle):
  if oracle is None:
   assert actual.calls.get(7,0)==0 and 11 not in actual.slots and 12 not in actual.slots
   return dict(code_not_initialized=True)
  assert 11 in actual.slots and 12 in actual.slots
  meta=actual.read(12,0,actual.slots[12]["size"]);n=q(meta,176)
  assert n==len(oracle.data)
  for at in range(0,n,4096):
   assert actual.read(11,64+at,min(4096,n-at))==oracle.data[at:at+4096],("code bytes",at)
  def name(pointer):
   assert 4096<=pointer<=len(meta)-80
   at,size=q(meta,pointer),q(meta,pointer+8)
   assert at==pointer+80 and size<=len(meta)-at
   return meta[at:at+size].decode("utf-8","surrogatepass")
  labels={};pending=[q(meta,184)];seen=set()
  while pending:
   p=pending.pop()
   if not p:continue
   assert p not in seen;seen.add(p);key=name(p)
   if q(meta,p+32):labels[key]=q(meta,p+24)
   pending.extend((q(meta,p+40),q(meta,p+48)))
  assert len(seen)==q(meta,192) and labels==oracle.labels
  fix=[];p=q(meta,208)
  while p:
   assert len(fix)<q(meta,224);fix.append((q(meta,p+8),name(q(meta,p+16))));p=q(meta,p)
  rel=[];p=q(meta,232)
  while p:
   assert len(rel)<q(meta,248)
   rel.append(dict(offset=q(meta,p+8),symbol=name(q(meta,p+16)),type=4,addend=-4));p=q(meta,p)
  assert fix==oracle.fixups and rel==oracle.relocations
  return dict(code_bytes=n,code_sha256=digest(oracle.data),labels=len(labels),fixups=len(fix),relocations=len(rel),
              all_code_bytes_labels_fixups_relocations_equal=True)
 def registry_state(self,actual,document,emitter):
  raw=actual.read(2,0,1<<20);c=self.control.CONSTANTS
  n=q(raw,c["E_RECORD_N"]);serial=q(raw,c["E_SERIAL"]);global_n=q(raw,c["E_GLOBAL_N"])
  symbols=[];frames=[];exports=[]
  final_header=q(raw,c["REG_AT"])==magic("HIAEMR01")
  for i in range(n):
   idx,kind,name_at,name_n,begin,end,frame,reserved=struct.unpack_from("<8Q",raw,c["REG_AT"]+256+i*64)
   assert reserved==0 and 0<=idx<len(document["functions"]) and kind in(0,1,2)
   if final_header:
    assert 16 in actual.slots
    name=actual.read(16,name_at,name_n).decode("ascii")
   else:
    start=q(raw,c["E_NAME_START"])+name_at;assert start+name_n<=len(raw)
    name=raw[start:start+name_n].decode("ascii")
   symbols.append(dict(name=name,offset=begin,size=end-begin,**{"global":bool(kind)}))
   if kind:exports.append(name)
   else:frames.append((document["functions"][idx]["name"],frame))
  expected_symbols=[] if emitter is None else emitter.symbols
  expected_frames=[] if emitter is None else emitter.frames
  expected_exports=[] if emitter is None else emitter.exports
  expected_serial=0 if emitter is None else emitter.serial
  assert (symbols,frames,exports,serial)==(expected_symbols,expected_frames,expected_exports,expected_serial),(symbols,expected_symbols,frames,expected_frames,exports,expected_exports,serial,expected_serial)
  assert global_n==len(exports)
  return dict(symbols=symbols,frames=frames,exports=exports,serial=serial,complete_ordered_registry_equal=True)
 def exact(self,label,doc,plan=None,foreign=(),*,private=False,structured=False,backend="native",cross=False):
  case=self.out/"cases"/("%04d"%len(self.cases));case.mkdir(parents=True)
  document,checked_plan,emitter,normalized,expected,error=self.oracle(doc,plan,foreign,private,structured)
  graph=self.F.capture([document,checked_plan,foreign],17);wire=initial(graph,structured=structured)
  (case/"initial.bin").write_bytes(wire)
  expected_error=None if error is None else dict(type=type(error).__name__,text=str(error),
      domain=2 if isinstance(error,self.original.HIAProgramNativeRejected) else 1)
  save(case/"oracle.json",dict(label=label,error=expected_error,normalized=normalized,
       symbols=[] if emitter is None else emitter.symbols,frames=[] if emitter is None else emitter.frames,
       exports=[] if emitter is None else emitter.exports,serial=0 if emitter is None else emitter.serial,
       admitted=not private,private_profile_fixture=private))
  if expected is not None:
   (case/"reference.text.bin").write_bytes(expected[0]);(case/"reference.object.bin").write_bytes(expected[1])
  actual=None;other=None;row=None
  try:
   saved=self.guard()
   try:
    if backend=="python":
     actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"python-full-CAS")
     result=actual.run(wire)
    else:
     actual=self.N.NativeMechanical(self.args.assets,self.args.carrier,case/"native-trace",wire,
            wall_seconds=max(.001,180-(time.monotonic()-self.started)))
     result=actual.result
    if cross:
     assert backend=="python"
     other=self.N.NativeMechanical(self.args.assets,self.args.carrier,case/"native-trace",wire,
            wall_seconds=max(.001,180-(time.monotonic()-self.started)))
     assert other.event==result["event"] and other.payload==result["payload"] and other.returned==result["returned"]
     crosscheck=other.compare_python(actual)
    else:crosscheck=None
   finally:self.unguard(saved)
   assert result["status"]=="TERMINAL",result
   event=struct.unpack("<16Q",result["event"])
   assert event[:3]==(magic("HIACDE01"),7,19) and event[14:]==(1,0)
   if error is not None:
    assert event[4]==expected_error["domain"] and event[5]!=0 and result["payload"].decode("utf-8")==str(error),(label,event,str(error),result["payload"])
    assert event[6]==17 and event[7]==0 and actual.slots[17]["readonly"]
   else:
    assert event[4:6]==(0,0) and len(result["payload"])==256
    head=struct.unpack("<32Q",result["payload"])
    assert head[:4]==(magic("HIAMER01"),1,19,1) and head[30:]==(0,0)
    assert head[4:8]==(1,128,len(graph),17)
    for slotid in(head[8],head[16],head[19],head[22],head[25]):assert actual.slots[slotid]["readonly"]
    text=actual.read(head[16],head[17],head[18]);obj=actual.read(head[19],head[20],head[21])
    (case/"actual.text.bin").write_bytes(text);(case/"actual.object.bin").write_bytes(obj)
    assert (text,obj)==expected,(label,len(text),len(expected[0]),len(obj),len(expected[1]))
    assert head[11:16]==(41,event[9],emitter.serial,len(document["functions"]),len(emitter.exports))
    assert head[18]==len(expected[0]) and head[21]==len(expected[1])
   state=self.code_state(actual,None if emitter is None else emitter.c)
   registry=self.registry_state(actual,document,emitter)
   assert event[10]==(0 if emitter is None else len(emitter.c.data)) and event[11]==registry["serial"]
   assert event[12:14]==(len(registry["symbols"]),len(registry["exports"]))
   row=dict(label=label,status="PASS",kind="WHOLE_NATIVE_EMITTER" if not private else "PRIVATE_EMITTER_PROFILE",
       error=expected_error,code_state=state,registry=registry,native_entries=actual.entries,
       by_role=actual.calls,mechanical_commands=actual.commands,crosscheck=crosscheck,
       crosscheck_native_entries=0 if other is None else other.entries,
       crosscheck_by_role={} if other is None else other.calls,
       input_graph_bytes=len(graph),functions=len(document["functions"]),
       text_bytes=None if expected is None else len(expected[0]),object_bytes=None if expected is None else len(expected[1]),
       complete_text_and_ELF_equal=expected is not None,full_outer_backend=False,
       evidence_scope="per-entry-full-workspace-CAS" if backend=="python" else "full-events-ACKs-and-final-all-slots")
   self.cases.append(row);save(case/"result.json",row)
   return row
  finally:
   primary=sys.exception();cleanup=[]
   for item in(other,actual):
    if item is not None:
     try:self.count(item)
     except BaseException as exc:cleanup.append(exc)
     try:
      custody=item.close(encode=primary is None) if isinstance(item,self.N.NativeMechanical) else item.close()
      if custody and "lossless_original_encoding" in custody:
       self.encoding_cpu+=custody["lossless_original_encoding"]["cpu_seconds"]
       self.encoding_wall+=custody["lossless_original_encoding"]["wall_seconds"]
     except BaseException as exc:cleanup.append(exc)
   if other is not None or backend=="native":
    for path in case.rglob("process.json"):
     try:
      p=json.loads(path.read_bytes());self.child_cpu+=(p["user_seconds"] or 0)+(p["system_seconds"] or 0)
     except BaseException as exc:cleanup.append(exc)
   if cleanup:
    first=primary if primary is not None else cleanup.pop(0)
    for exc in cleanup:first.add_note("Emitter cleanup: "+repr(exc))
    if primary is None:raise first
 def collected(self,group,variant=0):
  result=types.SimpleNamespace(cases=[])
  def capture(actual,label,document,plan=None,**kw):
   row=dict(label=label,document=copy.deepcopy(document),plan=copy.deepcopy(plan),**kw);actual.cases.append(row);return row
  old=self.M.exact_function;self.M.exact_function=capture
  try:
   if group=="scalars":self.M.scalar_group(result,variant)
   elif group=="casts":self.M.cast_group(result,variant)
   elif group=="boolean":self.M.boolean_select_group(result)
   elif group=="resources":self.M.resource_group(result)
   elif group=="edges":self.M.edge_group(result)
   elif group=="calls":self.M.call_group(result)
   elif group=="selection":self.M.code_selection_group(result)
   else:self.M.inventory_group(result,variant)
  finally:self.M.exact_function=old
  return result.cases
 def lower_group(self,group,variant):
  rows=self.collected(group,variant)
  for row in rows:
   doc=row["document"];plan=row["plan"]
   if group in("resources","edges","calls"):
    extra=self.M.fn("whole_emitter_entry")
    doc["functions"].append(extra)
    if plan is not None:plan["function_order"].append(extra["name"])
   if group=="inventory" and variant==0:doc["exports"]=["f0"]
   self.exact(row["label"],doc,plan)
 def cross_group(self):
  doc=self.M.doc(self.M.fn("entry",params=[self.M.p("x","u64")],returns=["u64"],term=dict(op="ret",values=["x"])))
  self.exact("identity-cross-all-slots",doc,backend="python",cross=True)
  doc=self.M.doc(self.M.fn("inner",params=[self.M.p("x","u64")],returns=["u64"],term=dict(op="ret",values=["x"])),
       self.M.fn("outer",params=[self.M.p("x","u64")],ops=[self.M.ins("call",["x"],[self.M.p("y","u64")],{"function":"inner"})],
         returns=["u64"],term=dict(op="ret",values=["y"])))
  plan=self.F.machine_plan(doc);plan["function_order"].reverse();plan["function_alignment"]=32
  plan["scratch_registers"]={"r10":"r11","r11":"r10"}
  self.exact("call-reverse-align-cross-all-slots",doc,plan,backend="python",cross=True)
 def borrowed_group(self,variant):
  result=types.SimpleNamespace(cases=[])
  def capture(actual,label,document,**kw):
   actual.cases.append((label,copy.deepcopy(document),kw))
  old=self.W.exact;self.W.exact=capture
  try:self.W.borrowed_cases(result,variant)
  finally:self.W.exact=old
  for label,doc,kw in result.cases:
   self.exact(label,doc,foreign=((doc["functions"][0]["name"],kw["extent"]),))
 def manifest_group(self):
  doc=self.W.fixture(["readbuf"],["u32"],"loan")
  bad=[None,False,0,[],{},b"",self.F.InheritedStr(""),tuple(range(129)),
       (0,),([],),(("loan",),),(("loan",1,2),),(["loan",1],),
       (("loan",True),),(("loan",False),),(("loan",0),),(("loan",-1),),(("loan",1<<20|1),),
       (("loan",1<<64),),(("loan",1<<1000),),((self.F.InheritedStr("loan"),1),),
       (("loan",1.0),),(("loan",None),),(("missing",1),),(("é",1),),(("\ud800",1),),
       (("loan",1),("loan",2)),(("abort",1),),(("__hia_private",1),), (("_init",1),)]
  for i,value in enumerate(bad):self.exact("manifest-invalid-"+str(i),doc,foreign=value)
  scalar=self.W.fixture(["u64"],["u32"],"scalar")
  self.exact("manifest-scalar-signature",scalar,foreign=(("scalar",1),))
  wrong=self.W.fixture(["readbuf"],["u64"],"wrong")
  self.exact("manifest-wrong-result",wrong,foreign=(("wrong",1),))
  wide=self.W.fixture(["readbuf"]*9,["u32"],"wide")
  self.exact("manifest-nine-loans",wide,foreign=(("wide",1),))
  exported=copy.deepcopy(doc);exported["exports"]=[]
  self.exact("manifest-explicit-contract-first",exported,foreign=(("missing",1),))
  self.exact("manifest-structured-contract-first",doc,foreign=(("missing",1),),private=True,structured=True)
  doc=self.M.doc(self.W.fixture(["readbuf"],["u32"],"zeta")["functions"][0],
                self.W.fixture(["mutbuf"],["u32"],"alpha")["functions"][0])
  self.exact("manifest-sort-complete-native",doc,foreign=(("zeta",1<<20),("alpha",1)))
 def late_group(self,variant):
  if variant in(0,1,2,3):
   count=(128,129,1024,1024)[variant];doc=self.M.doc(*(self.M.fn("f"+str(i)) for i in range(count)))
   if variant==2:doc["exports"]=["f"+str(i) for i in range(128)]
   self.exact("late-entry-count-"+str(variant),doc)
  elif variant==4:
   doc=self.M.doc(self.W.fixture(["readbuf"],["u32"],"zz")["functions"][0],
                 self.W.fixture(["mutbuf"],["u32"],"aa")["functions"][0])
   doc["exports"]=["zz","aa"];self.exact("missing-exports-sort-first",doc)
  elif variant==5:
   doc=self.W.fixture(["readbuf"],["u32"],"skip");self.exact("zero-scalar-entry",doc)
  elif variant==6:
   doc=self.M.doc(self.M.fn("normal"),self.M.fn("abort"))
   self.exact("reserved-after-complete-function-loop",doc)
  else:
   doc=self.M.doc(self.M.fn("normal"),self.W.fixture(["readbuf"],["u32"],"_init")["functions"][0])
   plan=self.F.machine_plan(doc);plan["function_alignment"]=64
   self.exact("reserved-but-ineligible-wrapper-still-align",doc,plan)
 def profiles(self):
  base=self.M.doc(self.M.fn("f"))
  cases=[]
  d=copy.deepcopy(base);d["schema"]="hepta.hia.program.v999";cases.append(("future-schema",d))
  d=copy.deepcopy(base);d["functions"][0]["blocks"][0]["term"]["op"]="future";cases.append(("future-term",d))
  d=copy.deepcopy(base);d["functions"][0]["params"]=[{"name":"a","type":"future"}];cases.append(("future-type",d))
  d=copy.deepcopy(base);d["functions"][0]["blocks"][0]["ops"]=[self.M.ins("future",[],[])];cases.append(("future-op",d))
  d=copy.deepcopy(base);d["functions"][0]["params"]=[{"name":"a","type":"future"}];d["functions"][0]["blocks"][0]["term"]["op"]="future";cases.append(("term-before-type",d))
  d=copy.deepcopy(base);d["functions"][0]["params"]=[{"name":"a","type":"future"}];d["functions"][0]["blocks"][0]["ops"]=[self.M.ins("future",[],[])];cases.append(("op-before-type",d))
  d=copy.deepcopy(base);d["functions"][0]["blocks"][0]["ops"]=[self.M.ins("const",[],[{"name":"v","type":"future"}],{"value":0}),self.M.ins("future",[],[])];cases.append(("later-op-before-type",d))
  d=copy.deepcopy(base);d["functions"][0]["params"]=[{"name":"a","type":"future"}];other=self.M.fn("g");other["blocks"][0]["term"]["op"]="future";d["functions"].append(other);cases.append(("first-function-type-before-next-term",d))
  for label,doc in cases:self.exact(label,doc,private=True)
 def private_bad(self,label,wire,intercept=None):
  case=self.out/"cases"/("%04d"%len(self.cases));case.mkdir(parents=True)
  actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"python-full-CAS")
  try:
   saved=self.guard()
   try:result=actual.run(wire,intercept=intercept)
   finally:self.unguard(saved)
   assert result["status"]=="PRIVATE_BAD",result
   if intercept is not None:assert actual.interceptions==1
   repeat=actual.last_original_ack or wire
   a=actual.buffers.allocate(len(repeat),repeat,True)
   try:
    ret=actual.native(11,(a,actual.slots[3],actual.slots[2]),(a,actual.slots[3],actual.slots[2]),
        ("private-repeat","slot3","slot2"))
    assert ret==BAD
   finally:actual.buffers.close(a)
   row=dict(label=label,status="PASS",kind="PRIVATE_EMITTER_PERMANENT_BAD",native_entries=actual.entries,by_role=actual.calls,interceptions=actual.interceptions)
   self.cases.append(row);self.protocol+=1;save(case/"result.json",row)
  finally:self.count(actual);actual.close()
 def protocols(self,variant):
  doc=self.verify(self.M.doc(self.M.fn("f"))).as_dict()
  wire=initial(self.F.capture([doc,None,()],17))
  if variant==0:
   mutations=[(0,0),(8,2),(16,0),(24,0),(32,0),(40,0),(48,0),(56,len(wire)),(64,2)]
   mutations.extend((i,1) for i in range(72,128,8))
   mutations.extend(((128,0),(136,18),(152,2),(176,len(wire))))
   for i,(at,value) in enumerate(mutations):self.private_bad("initial-"+str(i),changed(wire,at,value))
   return
  if variant==1:
   changes=[(0,0),(8,20),(16,0),(24,99),(32,1),(40,MASK),(48,1),(56,1)]
   target=lambda event,ack:True
  else:
   role={2:1,3:7,4:2,5:9}[variant]
   changes=[(64,0),(72,2),(88,999),(96,999),(184,1)]
   if variant==2:changes.extend(((80,9),(160,MASK)))
   target=lambda event,ack:struct.unpack("<16Q",event)[1]==1 and struct.unpack("<16Q",event)[4]==role
  for i,(at,value) in enumerate(changes):
   used=[False]
   def inject(actual,event,ack):
    if not used[0] and target(event,ack):
     used[0]=True
     assert at+8<=len(ack)
     return changed(ack,at,value)
    return ack
   self.private_bad("ACK-"+str(variant)+"-"+str(i),wire,inject)
   assert used[0]
 def finish(self):
  rows=[]
  for path,(raw,mode) in self.pins.items():
   now=path.read_bytes();row=dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=mode,
       same=now==raw and stat.S_IMODE(path.stat().st_mode)==mode)
   rows.append(row)
  save(self.out/"source-before-after.json",rows);assert all(x["same"] for x in rows)
  return dict(files=len(rows),all_bytes_and_modes_equal=True)
EXPECTED={("cross",0):2,**{("scalars",i):24 for i in range(10)},**{("casts",i):20 for i in range(10)},
 ("boolean",0):32,("resources",0):30,("edges",0):21,("calls",0):12,("selection",0):16,
 **{("inventory",i):1 for i in range(5)},**{("borrowed",i):9 for i in range(8)},("manifest",0):36,
 **{("late",i):1 for i in range(8)},("profile",0):8,("protocol",0):20,("protocol",1):8,
 ("protocol",2):7,("protocol",3):5,("protocol",4):5,("protocol",5):5}
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def deadline(*args):raise TimeoutError("whole-Emitter original 180 wall")
 signal.signal(signal.SIGALRM,deadline);signal.alarm(180)
 p=argparse.ArgumentParser()
 for name in("assets","carrier","reference","out"):p.add_argument("--"+name,type=Path,required=True)
 p.add_argument("--group",required=True);p.add_argument("--variant",type=int,default=0);args=p.parse_args()
 args.out=args.out.resolve();args.out.mkdir(parents=True,exist_ok=False);args.reference=args.reference.resolve()
 args.assets=args.assets.resolve();args.carrier=args.carrier.resolve()
 start=time.monotonic();suite=None;summary=dict(status="INCOMPLETE",group=args.group,variant=args.variant,old_results_inherited=False)
 try:
  assert sys.version_info[:3]==(3,12,14) and (args.group,args.variant) in EXPECTED
  suite=Suite(args)
  if args.group=="cross":suite.cross_group()
  elif args.group in("scalars","casts","boolean","resources","edges","calls","selection","inventory"):suite.lower_group(args.group,args.variant)
  elif args.group=="borrowed":suite.borrowed_group(args.variant)
  elif args.group=="manifest":suite.manifest_group()
  elif args.group=="late":suite.late_group(args.variant)
  elif args.group=="profile":suite.profiles()
  else:suite.protocols(args.variant)
  assert len(suite.cases)==EXPECTED[(args.group,args.variant)],(len(suite.cases),EXPECTED[(args.group,args.variant)])
  parent_cpu=resource.getrusage(resource.RUSAGE_SELF).ru_utime+resource.getrusage(resource.RUSAGE_SELF).ru_stime
  assert parent_cpu+suite.child_cpu<=90,("aggregate original CPU budget",parent_cpu,suite.child_cpu)
  summary["status"]="PASS"
 except BaseException as error:
  summary.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  if suite is not None:
   summary.update(cases=len(suite.cases),native_entries=suite.native_entries,by_role=suite.by_role,
      private_protocol_controls=suite.protocol,actual_reference_admitted_fixtures=suite.admitted,
      private_profile_fixtures=suite.private_profile,child_cpu_seconds=suite.child_cpu,
      evidence_encoding_cpu_seconds=suite.encoding_cpu,evidence_encoding_wall_seconds=suite.encoding_wall,
      original_group_limits_include_evidence_encoding=True,
      case_categories={k:sum(row["kind"]==k for row in suite.cases) for k in sorted({row["kind"] for row in suite.cases})})
   try:summary["source_custody"]=suite.finish()
   except BaseException as error:summary.update(status="FAIL",cleanup_error=repr(error),cleanup_traceback=traceback.format_exc());traceback.print_exc()
  summary.update(elapsed_seconds=time.monotonic()-start,limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
     address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180),
     full_public_backend=False,installed=False,cold=False,host_instruction_or_ELF_generation=False,
     private_immutable_actual_Core_and_checked_plan_precondition=True)
  save(args.out/"summary.json",summary);print(json.dumps(summary,sort_keys=True),flush=True);signal.alarm(0)
 if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
