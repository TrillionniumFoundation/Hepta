"""Fresh post-Core backend join; no prior component result is inherited.
The complete original emit_program_machine oracle runs before native execution.
Private admitted-Core/hash input fixtures are explicit. This does not claim the
public object boundary or native implementation-file custody is already joined.
All target code, plan canonicalization, object inspection, names and metadata
come from actual HIA; reference semantic entrypoints are disabled during native.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes,dataclasses,importlib.abc,importlib.util,json,os,resource,signal,stat,struct,sys,time,traceback,types
sys.dont_write_bytecode=True
BAD=0xfffffffd
MASK=(1<<64)-1
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
PINS={
 "backend_mechanical_harness.py":"f481be27e3988e2f92a90c9dd34dea90958c60e1d9b29e52791217e3f890f198",
 "backend_native_adapter.py":"d5c2732735410dd02be8754ce16db0473bb51febf6b2dc8f11ffd897a42dc4b7",
 "function_frame_test_reference.py":"b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6",
 "function_lowering_test_reference.py":"e08023ddab7501313a45825e5e2cdbba40d3524fee3e4a0f9ad33ba65335bc17",
 "wrapper_test_reference.py":"30950bd89da646f64061fc55bd0b855178c7e20fd214485b58b20ad86b4bd470"}
CONTROL_SHA="35ce9e9fccfb0601d3d000834c241ae9140eb70449fabc2747ae19e84c1d2a05"
REF_PINS={
 "hepta/hia_program_native.py":"bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c",
 "hepta/hia_machine_x64.py":"8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9",
 "hepta/hia_machine_plan.py":"ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a",
 "hepta/hia_native_byte_abi.py":"0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6",
 "hepta/object_symbols.py":"aff81d724d08ed4a8c3189e3370f75e234daa010ec9e9855aedc1019d55a693f",
 "hepta/object_structure.py":"4fb0b3d962e4b7f6ba508257bf605f4403d402e4f3d7e05cffa084b91651f5a8"}
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
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
def initial(graph,checked,implementation_before,implementation_after,*,digits=4300):
 head=struct.pack("<12Q",magic("HIABBI01"),1,19,1,17,41,23,29,q(graph,24),len(graph),
                  int(checked.structured_bytes is not None),digits)+bytes(32)
 head+=bytes.fromhex(checked.sha256)+bytes.fromhex(checked.input_sha256)
 head+=bytes.fromhex(implementation_before)+bytes.fromhex(implementation_after)+bytes(64)
 assert len(head)==320
 return head+graph
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
  self.started=time.monotonic();self.cases=[];self.native_entries=0
  self.by_role={str(i):0 for i in range(1,22)};self.protocol=0;self.admitted=0
  self.child_cpu=0;self.encoding_cpu=0;self.encoding_wall=0;self.pins={}
  for name,h in PINS.items():self.pin(self.root/name,h)
  self.pin(__file__);self.pin(self.root.parent/"tools/hia_backend_controller.py",CONTROL_SHA)
  self.H=load("backend_full_operand_mechanics",self.root/"backend_mechanical_harness.py",PINS["backend_mechanical_harness.py"])
  self.N=load("backend_fixed_native_mechanics",self.root/"backend_native_adapter.py",PINS["backend_native_adapter.py"])
  self.F=self.H.F
  self.M=load("backend_reference_fixtures",self.root/"function_lowering_test_reference.py",PINS["function_lowering_test_reference.py"]);self.M.F=self.F
  self.W=load("backend_borrowed_fixtures",self.root/"wrapper_test_reference.py",PINS["wrapper_test_reference.py"]);self.W.F=self.F
  self.control=load("backend_control_constants",self.root.parent/"tools/hia_backend_controller.py",CONTROL_SHA)
  for prefix in("hepta","tools"):
   for path in sorted((args.reference/prefix).rglob("*.py")):self.pin(path,REF_PINS.get(str(path.relative_to(args.reference))))
  for path,h in REF_PINS.items():self.pin(args.reference/path,h)
  frozen={p:raw for p,(raw,mode) in self.pins.items() if p.is_relative_to(args.reference) and p.suffix==".py"}
  assert not any(n.split(".")[0] in("hepta","tools") for n in sys.modules)
  sys.meta_path.insert(0,FrozenImports(args.reference,frozen));sys.path.insert(0,str(args.reference))
  from hepta import hia_program_native,hia_native_byte_abi,hia_machine_x64,hia_program,hia_machine_plan,object_symbols
  self.original=hia_program_native;self.byte=hia_native_byte_abi;self.code=hia_machine_x64
  self.core=hia_program;self.plan=hia_machine_plan;self.symbols=object_symbols
  self.verify=hia_program.verify_program
  self.assets=json.loads(self.pin(args.assets))
  assert self.assets["schema"]=="hia-backend-join-runtime-assets-v1"
  assert set(map(int,self.assets["roles"]))==set(range(1,22))
  for row in self.assets["roles"].values():
   m=row["manifest"]
   for kind in("source","image"):assert len(self.pin(m[kind+"_path"],m[kind+"_sha256"]))==m[kind+"_bytes"]
  self.pin(args.carrier);self.pin(args.carrier.with_suffix(".build.json"))
 def pin(self,path,expected=None):
  path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
  if expected is not None:assert digest(raw)==expected,(path,digest(raw),expected)
  if path in self.pins:assert self.pins[path]==(raw,mode)
  else:
   self.pins[path]=(raw,mode);target=self.out/"sources"/str(len(self.pins))/path.name
   target.parent.mkdir(parents=True);target.write_bytes(raw);target.chmod(mode)
  return raw
 def forbidden(self,*a,**k):raise AssertionError("reference semantic runtime fallback")
 def guard(self):
  targets=[(self.original,"emit_program_machine"),(self.original,"_implementation_hash"),
   (self.original,"_inspect_object"),(self.original,"inspect_object_symbols"),
   (self.original,"write_elf_object"),(self.original,"validate_block_layout_plan"),
   (self.original._Emitter,"render"),(self.original._Emitter,"wrapper"),
   (self.original._Function,"render"),(self.original._Function,"operation"),
   (self.core,"verify_program"),(self.plan,"validate_plan"),(self.byte,"normalize_exports"),
   (self.byte,"emit_wrapper"),(self.symbols,"inspect_object_symbols")]
  for name in("emit","mov_imm","call","jmp","jcc","label","align","finalize"):targets.append((self.code.Code,name))
  saved=[(obj,name,getattr(obj,name)) for obj,name in targets]
  for obj,name,_ in saved:setattr(obj,name,self.forbidden)
  return saved
 @staticmethod
 def unguard(saved):
  for obj,name,value in saved:setattr(obj,name,value)
 def count(self,actual):
  self.native_entries+=actual.entries
  for role,n in actual.calls.items():self.by_role[str(role)]+=n
 def oracle(self,document,plan,foreign,*,bind_plan=True,stale=False,corrupt=None):
  checked=self.verify(document);self.admitted+=1;detached=checked.as_dict()
  plan=copy.deepcopy(plan)
  if bind_plan and type(plan) is dict and "core_sha256" in plan:plan["core_sha256"]=checked.sha256
  before=self.original._implementation_hash();after=before
  if stale:after=("0" if before[0]!="0" else "1")+before[1:]
  old=self.original._implementation_hash;calls=[]
  if stale:
   def hash_observer():
    value=before if not calls else after;calls.append(value);return value
   self.original._implementation_hash=hash_observer
  result=None;error=None;canonical_plan=None;expected_metadata=None
  try:
   result=self.original.emit_program_machine(checked,machine_plan=plan,foreign_buffer_exports=foreign)
  except (ValueError,TypeError,OverflowError) as exc:
   error=exc
  finally:self.original._implementation_hash=old
  if corrupt is not None:
   # A private corruption test starts with an actual, successful native-produced
   # object, then changes exactly the same bytes before independent inspection.
   clean=self.original.emit_program_machine(checked,machine_plan=plan,foreign_buffer_exports=foreign)
   damaged=bytearray(clean.object_bytes)
   for at,value in corrupt:damaged[at]=value
   try:self.original._inspect_object(bytes(damaged),clean.exports)
   except (ValueError,TypeError,OverflowError) as exc:error=exc
   else:raise AssertionError("private object corruption must reach the original inspector")
   result=None
  if error is None:
   assert result is not None
   if plan is not None:canonical_plan=canonical(self.plan.validate_plan(checked,plan))
   fields=dataclasses.asdict(result)
   assert fields.pop("object_bytes")==result.object_bytes and fields.pop("text_bytes")==result.text_bytes
   fields["machine_text_sha256"]=digest(result.text_bytes)
   expected_metadata=canonical(fields)
  domain=None
  if error is not None:
   if isinstance(error,self.plan.MachinePlanRejected):domain=3
   elif isinstance(error,self.original.HIAProgramNativeRejected):domain=2
   elif isinstance(error,self.code.MachineEncodingError):domain=1
   elif corrupt is not None:domain=4
   else:raise AssertionError(("unclassified original exception",type(error).__name__,str(error)))
  return checked,detached,plan,before,after,result,error,domain,canonical_plan,expected_metadata
 def _cleanup(self,actual,other,case,backend,primary):
  errors=[]
  for item in(other,actual):
   if item is None:continue
   try:self.count(item)
   except BaseException as exc:errors.append(exc)
   try:
    receipt=item.close(encode=primary is None) if isinstance(item,self.N.NativeMechanical) else item.close()
    if receipt and "lossless_original_encoding" in receipt:
     self.encoding_cpu+=receipt["lossless_original_encoding"]["cpu_seconds"]
     self.encoding_wall+=receipt["lossless_original_encoding"]["wall_seconds"]
   except BaseException as exc:errors.append(exc)
  if other is not None or backend=="native":
   for path in case.rglob("process.json"):
    try:
     value=json.loads(path.read_bytes());self.child_cpu+=(value["user_seconds"] or 0)+(value["system_seconds"] or 0)
    except BaseException as exc:errors.append(exc)
  if errors:
   first=primary if primary is not None else errors.pop(0)
   for exc in errors:first.add_note("backend evidence cleanup: "+repr(exc))
   if primary is None:raise first
 def exact(self,label,document,plan=None,foreign=(),*,bind_plan=True,stale=False,
           corrupt=None,backend="native",cross=False,expect_success=None,expect_rejection=None):
  case=self.out/"cases"/("%04d"%len(self.cases));case.mkdir(parents=True)
  checked,doc,plan,before,after,expected,error,domain,plan_bytes,metadata=self.oracle(
      document,plan,foreign,bind_plan=bind_plan,stale=stale,corrupt=corrupt)
  if expect_success is not None:assert (error is None)==expect_success,(label,type(error).__name__,str(error))
  if expect_rejection is not None:
   assert error is not None and (type(error).__name__,str(error))==expect_rejection,(label,error,expect_rejection)
  graph=self.F.capture([doc,plan,foreign],17);wire=initial(graph,checked,before,after,digits=sys.get_int_max_str_digits())
  (case/"initial.bin").write_bytes(wire)
  expected_error=None if error is None else dict(type=type(error).__name__,text=str(error),domain=domain)
  save(case/"oracle.json",dict(label=label,error=expected_error,actual_reference_admitted_Core=True,
       implementation_before=before,implementation_after=after,private_stale_hash_fixture=stale,
       private_actual_object_corruption=corrupt,core_sha256=checked.sha256,input_sha256=checked.input_sha256,
       raw_plan_supplied_to_native=True,canonical_plan_supplied_to_native=False))
  if error is not None:(case/"reference.error.bin").write_bytes(str(error).encode("utf-8"))
  if expected is not None:
   (case/"reference.object.bin").write_bytes(expected.object_bytes)
   (case/"reference.text.bin").write_bytes(expected.text_bytes)
   (case/"reference.metadata.json").write_bytes(metadata)
   if plan_bytes is not None:(case/"reference.plan.json").write_bytes(plan_bytes)
  actual=None;other=None;mutations=[0];last_phase=[0]
  def private_mutation(instance,event,ack):
   values=struct.unpack("<16Q",event)
   if corrupt is not None and mutations[0]==0 and values[1]==1 and values[4]==18 and q(ack,40)==128:
    state=instance.read(2,0,1<<20);const=self.control.CONSTANTS
    if q(state,const["O_POST_MODE"])==0:
     offset=q(state,const["O_OBJECT_AT"]);count=q(state,const["O_OBJECT_N"])
     old=instance.read(31,offset,count);damaged=bytearray(old)
     for at,value in corrupt:
      assert at<len(damaged);damaged[at]=value
     (case/"actual.original-before-private-corruption.bin").write_bytes(old)
     (case/"actual.private-corrupted-object.bin").write_bytes(damaged)
     instance.protect(31,False)
     try:ctypes.memmove(instance.slots[31]["address"]+offset,bytes(damaged),len(damaged))
     finally:instance.protect(31,True)
     mutations[0]+=1
   return ack
  try:
   saved=self.guard()
   try:
    if backend=="python":
     actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"python-full-CAS")
     result=actual.run(wire,intercept=private_mutation if corrupt is not None else None)
    else:
     assert corrupt is None
     actual=self.N.NativeMechanical(self.args.assets,self.args.carrier,case/"native-trace",wire,
          wall_seconds=max(.001,180-(time.monotonic()-self.started)));result=actual.result
    crosscheck=None
    if cross:
     assert backend=="python" and corrupt is None
     other=self.N.NativeMechanical(self.args.assets,self.args.carrier,case/"native-trace",wire,
          wall_seconds=max(.001,180-(time.monotonic()-self.started)))
     assert other.result["event"]==result["event"] and other.result["payload"]==result["payload"] and other.result["returned"]==result["returned"]
     crosscheck=other.compare_python(actual)
   finally:self.unguard(saved)
   assert result["status"]=="TERMINAL",result
   (case/"actual.terminal.bin").write_bytes(result["event"])
   (case/"actual.result.bin").write_bytes(result["payload"])
   event=struct.unpack("<16Q",result["event"])
   assert event[:3]==(magic("HIACDE01"),7,19) and event[15]==1
   if corrupt is not None:assert mutations[0]==1
   if error is not None:
    assert event[4]==domain and event[5]>0 and event[6:9]==(36,0,len(result["payload"]))
    assert actual.slots[36]["readonly"] and result["payload"].decode("utf-8")==str(error),(label,event,str(error),result["payload"])
    assert 35 not in actual.slots
    if str(error).startswith("E_HIA_MACHINE_PLAN:"):assert domain==2 and actual.calls.get(7,0)==0 and actual.calls.get(11,0)==0
    if corrupt is not None:assert actual.calls.get(17,0)>0
    if stale and domain==2 and str(error).startswith("E_HIA_PROGRAM_STALE:"):assert actual.calls.get(17,0)>0
   else:
    assert event[4:9]==(0,0,35,0,512) and actual.slots[35]["readonly"]
    head=struct.unpack("<64Q",result["payload"])
    assert head[:8]==(magic("HIABMR01"),1,19,1,17,41,23,29) and head[60:]==(0,)*4
    assert head[8]==31 and head[11]==30 and head[14:16]==(19,0) and head[17:19]==(32,0)
    assert head[23]==int(plan is not None) and head[24] in((0,) if plan is None else(1,2,3,4))
    assert head[25]==len(expected.foreign_buffer_exports) and head[26]==len(doc["functions"])
    assert head[27]==len(expected.exports) and head[28]>0 and head[29]==int(checked.structured_bytes is not None)
    assert head[31]==head[26]+head[27]
    for slot in(31,30,19,32):assert actual.slots[slot]["readonly"]
    obj=actual.read(*head[8:11]);text=actual.read(*head[11:14]);meta=actual.read(*head[14:17])
    assert obj==expected.object_bytes and text==expected.text_bytes and meta==metadata,(label,digest(obj),digest(expected.object_bytes),meta,metadata)
    (case/"actual.object.bin").write_bytes(obj);(case/"actual.text.bin").write_bytes(text);(case/"actual.metadata.json").write_bytes(meta)
    if plan is None:assert head[20:23]==(0,0,0) and 11 not in actual.slots
    else:
     assert head[20:22]==(11,0) and head[22]==len(plan_bytes) and actual.slots[11]["readonly"]
     actual_plan=actual.read(*head[20:23]);assert actual_plan==plan_bytes
     (case/"actual.plan.json").write_bytes(actual_plan)
    hashes=b"".join(bytes.fromhex(v) for v in(checked.sha256,checked.input_sha256,before,after,
          digest(obj),digest(text)))+(bytes(32) if plan_bytes is None else sha256(plan_bytes).digest())
    assert result["payload"][256:480]==hashes
    assert event[9:15]==(len(meta),len(obj),len(text),0 if plan_bytes is None else len(plan_bytes),len(doc["functions"]),len(expected.exports))
    assert actual.calls.get(17,0)>0 and actual.calls.get(18,0)>=2 and actual.calls.get(19,0)>=6 and actual.calls.get(21,0)>0
    assert (actual.calls.get(16,0)>0)==(plan is not None)
   row=dict(label=label,status="PASS",kind="POST_CORE_COMPLETE_BACKEND_ORACLE",
       error=expected_error,native_entries=actual.entries,by_role=actual.calls,
       crosscheck_native_entries=0 if other is None else other.entries,
       crosscheck_by_role={} if other is None else other.calls,crosscheck=crosscheck,
       mechanical_commands=actual.commands,input_graph_bytes=len(graph),functions=len(doc["functions"]),
       complete_object_text_metadata_equal=error is None,canonical_plan_equal=error is None and plan is not None,
       original_error_full_text_equal=error is not None,private_stale_hash_fixture=stale,
       private_actual_object_corruption_count=mutations[0],
       evidence_scope="per-entry-full-workspace-CAS" if backend=="python" else "full-events-ACKs-and-final-all-slots",
       public_native_Core_admission=False,public_native_file_hash_custody=False)
   self.cases.append(row);save(case/"result.json",row)
   return row
  finally:self._cleanup(actual,other,case,backend,sys.exception())

 def simple(self,name="entry",typ="u64"):
  return self.M.doc(self.M.fn(name,params=[self.M.p("x",typ)],returns=[typ],term=dict(op="ret",values=["x"])))
 def plan_for(self,doc,version=3):
  if version==1:return dict(schema="hepta.hia.agent.block-layout.v1",core_sha256="",block_order={
      doc["functions"][0]["name"]:[b["id"] for b in doc["functions"][0]["blocks"]]})
  result=self.F.machine_plan(doc,leaf=version==4)
  if version==2:
   result["schema"]="hepta.hia.agent.machine-plan.v2";del result["value_registers"]
   del result["instruction_selection"]["scalar_select"]
  return result
 def cross_group(self):
  doc=self.simple()
  self.exact("complete-object-metadata-and-all-slots",doc,backend="python",cross=True,expect_success=True)
  doc=self.M.doc(self.M.fn("zeta"),self.M.fn("alpha"))
  plan=self.plan_for(doc);plan["function_order"].reverse();plan["function_alignment"]=64
  plan["scratch_registers"]={"r10":"r11","r11":"r10"}
  self.exact("checked-plan-retired-before-emitter-all-slots",doc,plan,backend="python",cross=True,expect_success=True)
 def scalar_group(self):
  for typ in("bool","i8","u8","i16","u16","i32","u32","i64","u64","isize","usize","unit"):
   doc=self.simple("scalar_"+typ,typ)
   if typ=="unit":
    # Core admits unit, but the original native C wrapper excludes unit parameters.
    # Preserve the identical valid Core fixture and require the original late
    # zero-entrypoint rejection before issuing any target command for this case.
    assert typ in self.core.SCALARS and typ not in set(self.original.WIDTHS)|{"bool"}
    assert "exports" not in doc and len(doc["functions"])==1
    assert doc["functions"][0]["params"]==[{"name":"x","type":"unit"}]
    assert doc["functions"][0]["returns"]==["unit"]
    self.exact("scalar-unit",doc,expect_success=False,expect_rejection=(
      "HIAProgramNativeRejected","E_HIA_PROGRAM_NATIVE: native profile requires between 1 and 128 admitted entrypoints"))
   else:self.exact("scalar-"+typ,doc,expect_success=True)
 def plan_group(self):
  doc=self.simple()
  for version in(1,2,3,4):
   plan=self.plan_for(doc,version)
   if version>=3:plan["value_registers"]={"entry":{"x":"r8" if version==4 else"r12"}}
   self.exact("plan-v"+str(version),doc,plan,expect_success=True)
  doc=self.F.edge_case()
  # The retained frame fixture has two scalar returns, so it has no native C
  # wrapper on its own. Keep its complete backedge/permutation body unchanged
  # and call it from a legal one-result public entrypoint.
  original_functions=copy.deepcopy(doc["functions"])
  assert len(original_functions)==1 and original_functions[0]["name"]=="f"
  assert original_functions[0]["returns"]==["u64","u64"] and "exports" not in doc
  doc["functions"].append(self.M.fn("edge_entry",
      params=[self.M.p("a","u64"),self.M.p("b","u64"),self.M.p("cond","bool")],
      ops=[self.M.ins("call",["a","b","cond"],
          [self.M.p("left","u64"),self.M.p("right","u64")],{"function":"f"})],
      returns=["u64"],term=dict(op="ret",values=["left"])))
  assert doc["functions"][:-1]==original_functions
  plan=self.plan_for(doc);plan["block_order"]={"f":["end","loop_block","entry"]}
  self.exact("closed-backedge-reordered",doc,plan,expect_success=True)
  doc=self.M.doc(self.M.fn("inside",params=[self.M.p("x","u64")],returns=["u64"],term=dict(op="ret",values=["x"])),
     self.M.fn("outside",params=[self.M.p("x","u64")],ops=[self.M.ins("call",["x"],[self.M.p("y","u64")],{"function":"inside"})],
       returns=["u64"],term=dict(op="ret",values=["y"])))
  plan=self.plan_for(doc);plan["function_order"].reverse();plan["function_alignment"]=32
  plan["instruction_selection"]={"move_immediate":"mov32_if_exact","alu_immediate":"imm8_if_exact","scalar_select":"cmov_scalar"}
  self.exact("call-relocation-reverse-layout",doc,plan,expect_success=True)
 def borrowed_group(self):
  for count in range(1,9):
   doc=self.W.fixture(["readbuf" if i%2==0 else"mutbuf" for i in range(count)],["u32"],"loan")
   self.exact("borrowed-arity-"+str(count),doc,foreign=(("loan",1 if count<8 else 1<<20),),expect_success=True)
  doc=self.M.doc(self.W.fixture(["readbuf"],["u32"],"zeta")["functions"][0],
       self.W.fixture(["mutbuf"],["u32"],"alpha")["functions"][0])
  plan=self.plan_for(doc);plan["function_order"].reverse();plan["function_alignment"]=64
  self.exact("borrowed-native-name-sort",doc,plan,foreign=(("zeta",97),("alpha",1)),expect_success=True)
  doc=self.M.doc(self.M.fn("scalar"),self.W.fixture(["readbuf"],["u32"],"borrowed")["functions"][0])
  self.exact("scalar-and-borrowed-complete-metadata",doc,foreign=(("borrowed",4096),),expect_success=True)
 def order_group(self):
  scalar=self.simple();loan=self.W.fixture(["readbuf"],["u32"],"loan")
  self.exact("foreign-shape-before-plan",scalar,False,foreign=None,expect_success=False)
  self.exact("foreign-extent-before-plan",loan,False,foreign=(("loan",0),),expect_success=False)
  self.exact("plan-before-zero-scalar-exports",loan,False,expect_success=False)
  loader=self.M.doc(self.M.fn("normal"),self.M.fn("_init"))
  self.exact("plan-before-loader-export",loader,False,expect_success=False)
  self.exact("plan-before-implementation-change",scalar,False,stale=True,expect_success=False)
  self.exact("foreign-before-implementation-change",scalar,False,foreign=None,stale=True,expect_success=False)
  self.exact("actual-inspection-before-stale",scalar,stale=True,expect_success=False)
  self.exact("borrowed-actual-inspection-before-stale",loan,foreign=(("loan",17),),stale=True,expect_success=False)
 def plan_error_group(self):
  doc=self.simple();good=self.plan_for(doc)
  values=[("boolean",False,False),("list",[],False),("empty",{},False)]
  p=copy.deepcopy(good);p["schema"]="unknown";values.append(("schema",p,True))
  p=copy.deepcopy(good);p["core_sha256"]="1"*64;values.append(("core",p,False))
  p=copy.deepcopy(good);p["block_order"]=[];values.append(("map",p,True))
  p=copy.deepcopy(good);p["function_order"]=["entry","entry"];values.append(("permutation",p,True))
  p=copy.deepcopy(good);p["function_alignment"]=True;values.append(("bool-alignment",p,True))
  p=copy.deepcopy(good);p["scratch_registers"]={"r10":"r10","r11":"r10"};values.append(("scratch",p,True))
  p=copy.deepcopy(good);p["instruction_selection"]["move_immediate"]="future";values.append(("choice",p,True))
  p=copy.deepcopy(good);p["value_registers"]=[];values.append(("register-map",p,True))
  p=copy.deepcopy(good);p["unreviewed"]=float("inf");values.append(("snapshot-before-field",p,True))
  assert len(values)==12
  for name,plan,bind in values:self.exact("plan-error-"+name,doc,plan,bind_plan=bind,expect_success=False)
 def late_group(self):
  self.exact("late-zero-exports",self.W.fixture(["readbuf"],["u32"],"skip"),expect_success=False)
  self.exact("late-loader-reserved",self.M.doc(self.M.fn("normal"),self.M.fn("_init")),expect_success=False)
  doc=self.M.doc(self.W.fixture(["u32"],["u32","u64"],"zz")["functions"][0],
       self.W.fixture(["u64"],["u64","u32"],"aa")["functions"][0]);doc["exports"]=["zz","aa"]
  row=self.exact("late-missing-explicit-sort",doc,expect_success=False)
  assert row["error"]["text"]=="E_HIA_PROGRAM_ABI: explicit exports have signatures outside the native C ABI: aa, zz"
  self.exact("late-129-exports",self.M.doc(*(self.M.fn("f"+str(i)) for i in range(129))),expect_success=False)
  doc=self.M.doc(self.M.fn("frame_boundary",ops=[self.M.ins("const",[],[self.M.p("v"+str(i),"u64")],{"value":i}) for i in range(8185)]))
  self.exact("late-frame-65536-plus8",doc,expect_success=False)
 def scale_group(self,variant):
  if variant<3:
   count=(128,129,1024)[variant];doc=self.M.doc(*(self.M.fn("f"+str(i)) for i in range(count)))
   if variant:doc["exports"]=["f"+str(i) for i in range(128)]
  else:
   doc=self.M.doc(self.M.fn("frame_boundary",ops=[self.M.ins("const",[],[self.M.p("v"+str(i),"u64")],{"value":i}) for i in range(8184)]))
  self.exact("actual-full-backend-boundary-"+str(variant),doc,expect_success=True)
 def inspect_group(self):
  self.exact("actual-object-magic-corruption",self.simple(),corrupt=((0,0),),backend="python",expect_success=False)
  self.exact("actual-object-machine-before-stale",self.simple(),corrupt=((18,0),(19,0)),stale=True,backend="python",expect_success=False)
 def private_bad(self,label,wire,intercept=None):
  case=self.out/"cases"/("%04d"%len(self.cases));case.mkdir(parents=True)
  (case/"initial.bin").write_bytes(wire)
  actual=None
  try:
   actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"python-full-CAS")
   saved=self.guard()
   try:result=actual.run(wire,intercept=intercept)
   finally:self.unguard(saved)
   assert result["status"]=="PRIVATE_BAD",result
   if intercept is not None:assert actual.interceptions==1
   repeat=actual.last_original_ack or wire
   a=actual.buffers.allocate(len(repeat),repeat,True)
   try:
    returned=actual.native(20,(a,actual.slots[3],actual.slots[2]),
       (a,actual.slots[3],actual.slots[2]),("private-repeat","slot3","slot2"))
    assert returned==BAD
   finally:actual.buffers.close(a)
   row=dict(label=label,status="PASS",kind="PRIVATE_BACKEND_PERMANENT_BAD",native_entries=actual.entries,
      by_role=actual.calls,crosscheck_native_entries=0,crosscheck_by_role={},interceptions=actual.interceptions,
      evidence_scope="per-entry-full-workspace-CAS",permanent_poison_on_original_ACK=True)
   self.cases.append(row);self.protocol+=1;save(case/"result.json",row)
  finally:self._cleanup(actual,None,case,"python",sys.exception())
 def private_input(self,plan=False):
  doc=self.simple();checked=self.verify(doc);value=self.plan_for(doc) if plan else None
  if value is not None:value["core_sha256"]=checked.sha256
  impl=self.original._implementation_hash()
  return initial(self.F.capture([checked.as_dict(),value,()],17),checked,impl,impl)
 def initial_group(self):
  wire=self.private_input()
  changes=[(0,0),(8,2),(16,0),(24,0),(32,0),(40,0),(48,0),(56,0),(64,0),(72,len(wire)),(80,2),
      (48,19),(56,19),(48,29)]
  changes.extend((at,1) for at in range(96,128,8))
  changes.extend((at,1) for at in range(256,320,8))
  changes.extend(((320,0),(328,18),(344,2),(368,len(wire)),(376,1),(384,6)))
  assert len(changes)==32
  for i,(at,value) in enumerate(changes):self.private_bad("initial-"+str(i),changed(wire,at,value))
 def ack_group(self):
  wire=self.private_input()
  for i,(at,value) in enumerate(((0,0),(8,20),(16,0),(24,99),(32,1),(40,MASK),(48,1),(56,1))):
   used=[False]
   def inject(actual,event,ack):
    if not used[0]:used[0]=True;return changed(ack,at,value)
    return ack
   self.private_bad("ACK-"+str(i),wire,inject);assert used[0]
 def peer_group(self,variant):
  role=(1,16,11,21,18,17,19)[variant];wire=self.private_input(plan=role in(16,19))
  if role in(11,16):changes=((64,0),(72,99),(80,0),(88,MASK))
  elif role==19:changes=((40,0),(8,20),(24,99),(56,1))
  else:changes=((64,0),(72,2),(88,999),(184,1))
  for i,(at,value) in enumerate(changes):
   used=[False]
   def inject(actual,event,ack):
    values=struct.unpack("<16Q",event)
    if not used[0] and values[1]==1 and values[4]==role and (role!=19 or q(ack,40)==32):
     assert at+8<=len(ack);used[0]=True;return changed(ack,at,value)
    return ack
   self.private_bad("peer-"+str(role)+"-"+str(i),wire,inject);assert used[0]
 def grow_group(self):
  wire=self.private_input()
  for role,needed_at in((1,48),(21,56),(18,56),(17,64)):
   used=[False]
   def inject(actual,event,ack):
    values=struct.unpack("<16Q",event)
    if not used[0] and values[1]==1 and values[4]==role and q(ack,40)==0xfffffffe:
     used[0]=True;return changed(ack,64+needed_at,0)
    return ack
   self.private_bad("nonincreasing-GROW-"+str(role),wire,inject);assert used[0]
 def finish(self):
  rows=[]
  for path,(raw,mode) in self.pins.items():
   now=path.read_bytes();rows.append(dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=mode,
       same=now==raw and stat.S_IMODE(path.stat().st_mode)==mode))
  save(self.out/"source-before-after.json",rows);assert all(row["same"] for row in rows)
  return dict(files=len(rows),all_bytes_and_modes_equal=True)

SCHEDULE=[
 ["cross",0,2,0],["scalar",0,12,0],["plan",0,6,0],["borrowed",0,10,0],
 ["order",0,8,0],["planerror",0,12,0],["late",0,5,0],
 ["scale",0,1,0],["scale",1,1,0],["scale",2,1,0],["scale",3,1,0],["inspect",0,2,0],
 ["initial",0,32,32],["ack",0,8,8],
 ["peer",0,4,4],["peer",1,4,4],["peer",2,4,4],["peer",3,4,4],
 ["peer",4,4,4],["peer",5,4,4],["peer",6,4,4],["grow",0,4,4]]
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def deadline(*args):raise TimeoutError("native backend join original 180 wall")
 signal.signal(signal.SIGALRM,deadline);signal.alarm(180)
 parser=argparse.ArgumentParser()
 for name in("assets","carrier","reference","out"):parser.add_argument("--"+name,type=Path,required=True)
 parser.add_argument("--group",required=True);parser.add_argument("--variant",type=int,default=0)
 args=parser.parse_args();args.out=args.out.resolve();args.out.mkdir(parents=True,exist_ok=False)
 args.reference=args.reference.resolve();args.assets=args.assets.resolve();args.carrier=args.carrier.resolve()
 started=time.monotonic();suite=None;summary=dict(status="INCOMPLETE",group=args.group,variant=args.variant,
       all_prior_results_inherited=False,full_public_backend=False)
 try:
  assert sys.version_info[:3]==(3,12,14)
  selected=[row for row in SCHEDULE if row[:2]==[args.group,args.variant]];assert len(selected)==1
  suite=Suite(args)
  methods={"cross":suite.cross_group,"scalar":suite.scalar_group,"plan":suite.plan_group,
     "borrowed":suite.borrowed_group,"order":suite.order_group,"planerror":suite.plan_error_group,
     "late":suite.late_group,"inspect":suite.inspect_group,"initial":suite.initial_group,
     "ack":suite.ack_group,"grow":suite.grow_group}
  if args.group=="scale":suite.scale_group(args.variant)
  elif args.group=="peer":suite.peer_group(args.variant)
  else:methods[args.group]()
  assert (len(suite.cases),suite.protocol)==tuple(selected[0][2:]),(len(suite.cases),suite.protocol,selected)
  usage=resource.getrusage(resource.RUSAGE_SELF);parent_cpu=usage.ru_utime+usage.ru_stime
  assert parent_cpu+suite.child_cpu<=90,("original aggregate CPU",parent_cpu,suite.child_cpu)
  summary["status"]="PASS"
 except BaseException as exc:
  summary.update(status="FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  if suite is not None:
   summary.update(cases=len(suite.cases),native_entries=suite.native_entries,by_role=suite.by_role,
      private_protocol_controls=suite.protocol,reference_admitted_fixtures=suite.admitted,
      child_cpu_seconds=suite.child_cpu,evidence_encoding_cpu_seconds=suite.encoding_cpu,
      evidence_encoding_wall_seconds=suite.encoding_wall,original_group_limits_include_evidence_encoding=True,
      evidence_scope_counts={k:sum(row["evidence_scope"]==k for row in suite.cases)
        for k in sorted({row["evidence_scope"] for row in suite.cases})},
      native_control_and_all_command_issuance_HIA=True,host_instruction_or_ELF_or_plan_generation_during_native=False,
      actual_native_Core_admission=False,public_foreign_capture=False,actual_native_implementation_file_hash_custody=False)
   try:summary["source_custody"]=suite.finish()
   except BaseException as exc:summary.update(status="FAIL",cleanup_error=repr(exc),cleanup_traceback=traceback.format_exc());traceback.print_exc()
  final_usage=resource.getrusage(resource.RUSAGE_SELF)
  final_CPU=final_usage.ru_utime+final_usage.ru_stime+(0 if suite is None else suite.child_cpu)
  final_elapsed=time.monotonic()-started
  if final_CPU>90 or final_elapsed>=180:summary.update(status="FAIL",final_budget_exceeded=True)
  summary.update(parent_plus_children_CPU_seconds=final_CPU,elapsed_seconds=final_elapsed,
     limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),
                 core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180),
     full_public_backend=False,compile_program_machine=False,installed=False,cold=False,
     development_C_mechanics_and_Python_authoring_TCB=True)
  save(args.out/"summary.json",summary);print(json.dumps(summary,sort_keys=True),flush=True);signal.alarm(0)
 if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
