"""Actual native snapshot -> GraphWire -> checked-plan continuation differential.

The reference runs first. During native execution its admission/plan functions
are disabled. Python captures exact object tags and transports only actual HIA
events; it never supplies a canonical plan, a semantic ACK or an expected result.
Every actual entry retains all three complete operands before and after in
losslessly verified page CAS, including actual readonly source and canaries.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes,itertools,json,resource,signal,stat,struct,sys,time,traceback,types
sys.dont_write_bytecode=True
BAD=0xfffffffd
GROW=0xfffffffe
MASK=(1<<64)-1
LIMIT=8<<20
PLAN_LEASE=17
CONTROL_LEASE=19
REQUEST=1
BUILD_SHA="3e4fc3fae2b8c382956328887eb0bc4fee61dac64c1f808294f7984ee950148b"
HARNESS_SHA="f4c0a87fc178b52b00afb25903ed597de4c886c6d295829b0b36160c7da4c515"
FRAME_SHA="b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
PLAN_SHA="ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a"
CORE_SHA="76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
SCHEMAS=("hepta.hia.agent.block-layout.v1","hepta.hia.agent.machine-plan.v2",
 "hepta.hia.agent.machine-plan.v3","hepta.hia.agent.machine-plan.v4")
REGISTERS=("rbx","r12","r13","r14","r15","r8","r9")
ERRORS=(
 "plan must be an object","plan requires bounded plain JSON data","unknown plan schema",
 "plan has missing or unreviewed fields","plan belongs to a different Core","invalid block order map",
 "unknown function in block order","block order must name every member exactly once",
 "function order must name every member exactly once","scratch assignment must bijectively rename only r10 and r11",
 "instruction choices must be explicit and complete","unreviewed immediate move encoding",
 "unreviewed immediate arithmetic encoding","unreviewed function alignment","unreviewed scalar select encoding",
 "value_registers must be a function map","unknown function in value register assignment",
 "value registers must be explicit assignments admitted by this plan version",
 "caller-clobbered value registers require a leaf opcode whitelist; no calls, swap or allocation/bulk helpers",
 "leaf registers require scalar/borrowed parameters and scalar returns",
 "register assignment requires an existing integer or boolean SSA value","interfering values ")
def magic(s):return int.from_bytes(s.encode("ascii"),"little")
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def q(raw,at=0):return struct.unpack_from("<Q",raw,at)[0]
def changed(raw,at,value):
 out=bytearray(raw);struct.pack_into("<Q",out,at,value);return bytes(out)
def loaded(name,path,expected):
 raw=Path(path).read_bytes();assert digest(raw)==expected,(str(path),digest(raw),expected)
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
 exec(compile(raw,str(path),"exec"),module.__dict__);return module
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode("utf-8")
def initial(graph,core_sha,digits,request=REQUEST):
 head=bytearray(struct.pack("<16Q",magic("HIAMPB01"),1,CONTROL_LEASE,request,
       PLAN_LEASE,q(graph,24),len(graph),digits,*([0]*8)))
 head[64:96]=bytes.fromhex(core_sha)
 return bytes(head)+graph
def parameter(name,typ):return dict(name=name,type=typ)
def operation(name,args=(),out=(),attrs=None):return dict(op=name,args=list(args),out=list(out),attrs={} if attrs is None else attrs)
def function(name="f",params=(),ops=(),returns=(),term=None,effects=(),blocks=None):
 params=list(params);ops=list(ops);term=dict(op="ret",values=[]) if term is None else term
 blocks=[dict(id="entry",params=params,ops=ops,term=term)] if blocks is None else blocks
 return dict(name=name,params=params,returns=list(returns),effects=list(effects),
             entry=blocks[0]["id"],blocks=blocks)
def program(*functions):return dict(schema="hepta.hia.program.v8",module="checked_plan",functions=list(functions))
def scalar_function(name="f"):
 p=parameter("x","u64")
 return function(name,[p],returns=["u64"],term=dict(op="ret",values=["x"]))
def plan_for(checked,version=3):
 d=checked.as_dict()
 result=dict(schema=SCHEMAS[version-1],core_sha256=checked.sha256,block_order={})
 if version==1:result["block_order"]={d["functions"][0]["name"]:[b["id"] for b in d["functions"][0]["blocks"]]}
 if version>=2:
  result.update(function_order=[f["name"] for f in d["functions"]],
   scratch_registers={"r10":"r10","r11":"r11"},
   instruction_selection={"move_immediate":"movabs","alu_immediate":"imm32"},function_alignment=1)
 if version>=3:
  result["instruction_selection"]["scalar_select"]="branch";result["value_registers"]={}
 return result
def error_code(text):
 prefix="E_HIA_MACHINE_PLAN: "
 assert text.startswith(prefix),text
 body=text[len(prefix):]
 for i,value in enumerate(ERRORS,1):
  if body==value or (i==22 and body.startswith(value)):return i
 raise AssertionError(("unmapped original error",text))
def visited(value):
 count=0;pending=[value]
 while pending:
  item=pending.pop();count+=1
  if type(item) is dict:pending.extend(item.values())
  elif type(item) is list:pending.extend(item)
 return count
class DictSubclass(dict):pass
class ListSubclass(list):pass
class IntSubclass(int):pass

class Suite:
 def __init__(self,args):
  self.args=args;self.root=Path(__file__).resolve().parents[1];self.out=args.out
  self.pins={};self.cases=[];self.calls={str(i):0 for i in range(1,6)}
  self.entries=0;self.admitted=0;self.protocol=0;self.grows={};self.covered_errors=set()
  self.pure_grows=0;self.wire_grows=0;self.closed=False
  self.pin(__file__)
  self.build=loaded("checked_plan_build_reference",self.root/"tools/build_hia_checked_plan.py",BUILD_SHA)
  self.pin(self.root/"tools/build_hia_checked_plan.py",BUILD_SHA)
  for name,h in self.build.PINS.items():self.pin(self.root/name,h)
  frozen={p.resolve():self.pin(p) for prefix in("hepta","tools")
    for p in sorted((args.reference/prefix).rglob("*.py"))}
  sys.meta_path.insert(0,self.build.FrozenImports(args.reference,frozen))
  from hepta import hia_program,hia_machine_plan
  assert digest(self.pin(Path(hia_program.__file__)))==CORE_SHA
  assert digest(self.pin(Path(hia_machine_plan.__file__)))==PLAN_SHA
  self.core=hia_program;self.plan=hia_machine_plan
  self.verify=hia_program.verify_program;self.validate=hia_machine_plan.validate_plan
  self.H=loaded("checked_plan_actual_mechanics",self.root/"tests/plan_mechanical_harness.py",HARNESS_SHA)
  self.F=self.H.F
  self.pin(self.root/"tests/plan_mechanical_harness.py",HARNESS_SHA)
  self.pin(self.root/"tests/function_frame_test_reference.py",FRAME_SHA)
  doc=json.loads(self.pin(args.assets))
  assert doc["schema"]=="hia-plan-development-runtime-assets-v1"
  assert set(doc["roles"])=={str(i) for i in range(1,6)}
  for number,row in doc["roles"].items():
   m=row["manifest"]
   assert m["schema"]=="hia-checked-machine-plan-development-component-v1" and m["status"]=="BUILT_ONLY"
   assert m["role"]==int(number)
   for kind in("source","image"):
    raw=self.pin(m[kind+"_path"],m[kind+"_sha256"]);assert len(raw)==m[kind+"_bytes"]
 def pin(self,path,expected=None):
  path=Path(path).absolute();info=path.lstat()
  assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
  raw=path.read_bytes()
  if expected is not None:assert digest(raw)==expected,(str(path),digest(raw),expected)
  if path in self.pins:assert self.pins[path]==(raw,stat.S_IMODE(info.st_mode))
  else:
   self.pins[path]=(raw,stat.S_IMODE(info.st_mode))
   target=self.out/"source"/str(len(self.pins))/path.name;target.parent.mkdir(parents=True)
   target.write_bytes(raw);target.chmod(stat.S_IMODE(info.st_mode))
  return raw
 def guard(self):
  def forbidden(*args,**kw):raise AssertionError("host plan/Core admission used during actual native continuation")
  saved=[]
  for module,name in((self.core,"verify_program"),(self.core,"_decode"),
      (self.plan,"validate_plan"),(self.plan,"register_assignment_witness")):
   saved.append((module,name,getattr(module,name)));setattr(module,name,forbidden)
  return saved
 def unguard(self,saved):
  for module,name,value in saved:setattr(module,name,value)
 def count(self,actual):
  self.entries+=actual.entries
  for role,count in actual.calls.items():self.calls[str(role)]+=count
 def exact(self,label,doc,make=None,expected_error=None,digits=None,expected_text=None):
  checked=self.verify(doc);self.admitted+=1
  submitted=plan_for(checked) if make is None else make(checked)
  digits=sys.get_int_max_str_digits() if digits is None else digits
  old_digits=sys.get_int_max_str_digits();sys.set_int_max_str_digits(digits)
  case=self.out/"cases"/("%04d"%len(self.cases));case.mkdir(parents=True)
  actual=None;observer=[]
  try:
   expected=None;error=None
   try:expected=self.validate(checked,submitted)
   except self.plan.MachinePlanRejected as exc:error=dict(type=type(exc).__name__,text=str(exc),code=error_code(str(exc)))
   if expected_error is None:assert error is None,(label,"expected valid original plan",error)
   else:assert error is not None and error["code"]==expected_error,(label,error,expected_error)
   if expected_text is not None:assert error is not None and error["text"]==expected_text
   expected_wire=None if error else canonical(expected)
   graph=self.F.capture([checked.as_dict(),submitted],PLAN_LEASE);wire=initial(graph,checked.sha256,digits)
   graph_view=self.F.Graph(graph);core_id,plan_id=graph_view.children(q(graph,24))
   save(case/"oracle.json",dict(label=label,core_sha256=checked.sha256,error=error,
      canonical_bytes=None if error else len(expected_wire),canonical_sha256=None if error else digest(expected_wire),
      integer_digits=digits,reference_before_native=True))
   (case/"input.graph").write_bytes(graph);(case/"input.begin").write_bytes(wire)
   (case/"admitted-core.json").write_bytes(checked.canonical_bytes)
   if expected_wire is not None:(case/"expected.canonical").write_bytes(expected_wire)
   actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"full-CAS")
   def observe(mechanic,event,ack):
    fields=struct.unpack("<16Q",event)
    if fields[1]==2:
     key=str(fields[4]);self.grows[key]=self.grows.get(key,0)+1
    if fields[1]==1:
     role=fields[4];reply=ack[64:]
     observer.append(dict(role=role,returned=q(ack,40),event=list(struct.unpack("<16Q",reply))))
     if role in(2,3):
      command=mechanic.read(fields[8],0,fields[9])
      assert len(command)==64 and q(command)==magic("HIAGWC01")
      assert tuple(q(command,i) for i in(8,16,24,32,40,48,56))==(PLAN_LEASE,REQUEST,plan_id,LIMIT,2,digits,0)
      if q(reply,8)==1:self.wire_grows+=1
     if role==4 and q(reply,16)==1:self.pure_grows+=1
    return ack
   saved=self.guard()
   try:result=actual.run(wire,intercept=observe)
   finally:self.unguard(saved)
   assert result["status"]=="TERMINAL",(label,result,observer)
   terminal=struct.unpack("<16Q",result["event"])
   assert terminal[:3]==(magic("HIACDE01"),7,CONTROL_LEASE)
   assert terminal[7]==0 and terminal[9:13]==(REQUEST,PLAN_LEASE,plan_id,core_id)
   assert actual.read(1,0,len(wire))==wire and actual.slots[1]["readonly"]
   if error is None:
    expected_version=SCHEMAS.index(expected["schema"])+1
    assert terminal[4:9]==(0,0,9,0,256)
    assert terminal[13:]==(expected_version,len(expected_wire),visited(expected))
    raw=result["payload"];assert len(raw)==256
    words=struct.unpack("<32Q",raw)
    assert words[:16]==(magic("HIAMPD01"),1,CONTROL_LEASE,REQUEST,PLAN_LEASE,1,128,len(graph),
         core_id,plan_id,expected_version,8,0,len(expected_wire),7,0)
    assert raw[128:160]==bytes.fromhex(checked.sha256)
    assert words[20:24]==(visited(expected),digits,2,LIMIT) and words[24:]==(0,)*8
    for slot in(7,8,9):assert actual.slots[slot]["readonly"]
    assert actual.read(8,0,len(expected_wire))==expected_wire
    peer=actual.read(7,1024,128)
    assert struct.unpack("<8Q",peer[:64])==(magic("HIAMPR01"),1,PLAN_LEASE,REQUEST,core_id,plan_id,expected_version,len(graph))
    assert peer[64:96]==bytes.fromhex(checked.sha256) and peer[96:]==bytes(32)
    (case/"actual.canonical").write_bytes(actual.read(8,0,len(expected_wire)))
    roles=[r["role"] for r in observer]
    assert roles[0]==1 and 2 in roles and 3 in roles and roles[-1]==4
    assert max(i for i,r in enumerate(roles) if r in(2,3))<min(i for i,r in enumerate(roles) if r==4)
   else:
    self.covered_errors.add(error["code"])
    raw=error["text"].encode("utf-8")
    assert terminal[4:9]==(3,error["code"],10,0,len(raw)),(label,terminal,error)
    assert result["payload"]==raw
    assert actual.slots[10]["readonly"]
    roles=[r["role"] for r in observer]
    assert roles[0]==1
    if error["code"]==1:assert roles==[1]
    if error["code"]<=2:assert 4 not in roles
    else:assert 2 in roles and 3 in roles and roles[-1]==4
   row=dict(label=label,status="PASS",kind="ACTUAL_REFERENCE_ADMITTED_CORE_AND_PLAN",
       error=error,native_entries=actual.entries,by_role=actual.calls,
       complete_canonical_equal=error is None,complete_original_error_equal=error is not None,
       integer_digits=digits,actual_peer_events=observer)
   actual.evidence.case(row);self.cases.append(row);save(case/"result.json",row)
  finally:
   sys.set_int_max_str_digits(old_digits)
   if actual is not None:
    self.count(actual);save(case/"evidence.json",actual.close())
 def private_bad(self,label,wire,intercept=None):
  case=self.out/"cases"/("%04d"%len(self.cases));case.mkdir(parents=True)
  actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"full-CAS")
  try:
   (case/"input.begin").write_bytes(wire)
   saved=self.guard()
   try:result=actual.run(wire,intercept=intercept)
   finally:self.unguard(saved)
   assert result["status"]=="PRIVATE_BAD",(label,result)
   if intercept is not None:assert actual.interceptions==1
   repeat=actual.last_original_ack or wire
   a=actual.buffers.allocate(len(repeat),repeat,True)
   try:
    returned=actual.native(5,(a,actual.slots[3],actual.slots[2]),(a,actual.slots[3],actual.slots[2]),
      ("private-repeat","slot3","slot2"))
    assert returned==BAD
   finally:actual.buffers.close(a)
   row=dict(label=label,status="PASS",kind="PRIVATE_PERMANENT_BAD",
      native_entries=actual.entries,by_role=actual.calls,interceptions=actual.interceptions)
   actual.evidence.case(row);self.cases.append(row);self.protocol+=1;save(case/"result.json",row)
  finally:self.count(actual);save(case/"evidence.json",actual.close())
 def finish(self):
  rows=[]
  for path,(raw,mode) in self.pins.items():
   now=path.read_bytes()
   rows.append(dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=mode,
      same=now==raw and stat.S_IMODE(path.stat().st_mode)==mode))
  save(self.out/"source-before-after.json",rows)
  assert all(r["same"] for r in rows)
  return dict(files=len(rows),all_bytes_and_modes_equal=True)

def amended(checked,version=3,**changes):
 result=plan_for(checked,version);result.update(changes);return result
def shape_group(s):
 doc=program(scalar_function())
 roots=[None,True,0,0.0,"{}",b"{}",[],(),DictSubclass()]
 for i,value in enumerate(roots):s.exact("top-exact-type-"+str(i),doc,lambda c,v=value:v,1)
 for i,value in enumerate((None,True,1,{},[],"","future","HEPTA.HIA.AGENT.MACHINE-PLAN.V3")):
  s.exact("unknown-schema-"+str(i),doc,lambda c,v=value:amended(c,schema=v),3)

def field_group(s):
 doc=program(scalar_function())
 for version in range(1,5):
  s.exact("version-"+str(version),doc,lambda c,v=version:plan_for(c,v))
  for key in (("schema","core_sha256","block_order") if version==1 else
      ("schema","core_sha256","block_order","function_order","scratch_registers","instruction_selection","function_alignment")
        +(("value_registers",) if version>=3 else ())):
   def missing(c,key=key,v=version):
    result=plan_for(c,v);del result[key];return result
   s.exact("v"+str(version)+"-missing-"+key,doc,missing,3 if key=="schema" else 4)
  s.exact("v"+str(version)+"-extra",doc,lambda c,v=version:amended(c,v,unreviewed=0),4)

def hash_group(s):
 doc=program(scalar_function())
 for i,value in enumerate((None,False,0,{},[],"","0"*64,"A"*64)):
  s.exact("different-Core-"+str(i),doc,lambda c,v=value:amended(c,core_sha256=v),5)

def choice_group(s,variant):
 doc=program(scalar_function("z"),function("a"));rows=[]
 for move,alu,align,swap,order in itertools.product(("movabs","mov32_if_exact"),
       ("imm32","imm8_if_exact"),(1,16,32,64),(False,True),(False,True)):
  rows.append((2,move,alu,align,swap,order,"branch"))
 for version in(3,4):
  for move,alu,align,swap,select in itertools.product(("movabs","mov32_if_exact"),
       ("imm32","imm8_if_exact"),(1,16,32,64),(False,True),("branch","cmov_scalar")):
   rows.append((version,move,alu,align,swap,False,select))
 assert len(rows)==192
 for index,row in list(enumerate(rows))[variant*16:(variant+1)*16]:
  def make(c,row=row):
   version,move,alu,align,swap,order,select=row;p=plan_for(c,version)
   p["instruction_selection"]={"move_immediate":move,"alu_immediate":alu}
   if version>=3:p["instruction_selection"]["scalar_select"]=select
   p["scratch_registers"]={"r10":"r11","r11":"r10"} if swap else {"r10":"r10","r11":"r11"}
   p["function_alignment"]=align
   if order:p["function_order"].reverse()
   return p
  s.exact("complete-reviewed-choice-"+str(index),doc,make)

def block_group(s):
 doc=program(scalar_function())
 for i,value in enumerate((None,True,[],"")):
  s.exact("block-map-kind-"+str(i),doc,lambda c,v=value:amended(c,block_order=v),6)
 s.exact("v1-empty-block-map",doc,lambda c:amended(c,1,block_order={}),6)
 s.exact("unknown-block-function",doc,lambda c:amended(c,block_order={"foreign":[]}),7)
 for i,value in enumerate(([],["entry","entry"],[0],["wrong"],[True])):
  s.exact("bad-block-permutation-"+str(i),doc,lambda c,v=value:amended(c,block_order={"f":v}),8)
 for version in range(1,5):s.exact("valid-layout-v"+str(version),doc,lambda c,v=version:plan_for(c,v))

def layout_group(s):
 doc=s.F.edge_case()
 for order in itertools.permutations(("entry","loop_block","end")):
  s.exact("three-block-order-"+"/".join(order),doc,lambda c,o=list(order):amended(c,block_order={"f":o}))
 for variant in(0,1):
  two=program(scalar_function("a"),function("z"))
  def make(c,variant=variant):
   p=plan_for(c);p["block_order"]={"foreign":[]} if variant==0 else {"a":["wrong"],"foreign":[]}
   p["function_order"].reverse();return p
  s.exact("sorted-block-map-first-"+str(variant),two,make,7 if variant==0 else 8)
 def reverse_insertion(c):
  p=plan_for(c);p["block_order"]={"z":["entry"],"a":["entry"]};p["function_order"].reverse()
  return dict(reversed(list(p.items())))
 s.exact("full-plan-and-block-dict-insertion-reversed",program(scalar_function("a"),function("z")),reverse_insertion)
 shared=["entry"]
 s.exact("immutable-alias-block-orders",program(scalar_function("a"),function("z")),
    lambda c:amended(c,block_order={"a":shared,"z":shared}))

def order_group(s):
 doc=program(scalar_function())
 for i,value in enumerate((None,0,{},[],["f","f"],["wrong"],[0],[True])):
  s.exact("bad-function-permutation-"+str(i),doc,lambda c,v=value:amended(c,function_order=v),9)
 for i,value in enumerate((None,0,[],{},{"r10":"r10"},{"r10":"r10","r11":"r10"},
        {"r10":"r11","r11":"rax"},{"r10":1,"r11":"r11"},{"r10":"r10","r11":"r11","rax":"rax"})):
  s.exact("scratch-not-bijection-"+str(i),doc,lambda c,v=value:amended(c,scratch_registers=v),10)

def invalid_choice_group(s,variant):
 doc=program(scalar_function());rows=[]
 for i,value in enumerate((None,{},[],{"move_immediate":"movabs"},
      {"move_immediate":"movabs","alu_immediate":"imm32"},
      {"move_immediate":"movabs","alu_immediate":"imm32","scalar_select":"branch","x":0})):
  rows.append(("shape-"+str(i),11,"instruction_selection",value))
 for field,code,values in(
   ("move_immediate",12,(None,True,0,{},[],"xor","MOVABS")),
   ("alu_immediate",13,(None,False,0,{},[],"truncate","IMM32")),
   ("function_alignment",14,(True,False,0,-1,2,8,65,4096,1<<100,"16",None)),
   ("scalar_select",15,(None,True,0,{},[],"cmov","BRANCH"))):
  for i,value in enumerate(values):rows.append((field+"-"+str(i),code,field,value))
 assert len(rows)==38
 for label,code,field,value in rows[variant*19:(variant+1)*19]:
  def make(c,field=field,value=value):
   p=plan_for(c)
   if field in("instruction_selection","function_alignment"):p[field]=value
   else:p["instruction_selection"][field]=value
   return p
  s.exact(label,doc,make,code)

def assignment_group(s):
 doc=program(scalar_function())
 for i,value in enumerate((None,True,[],0,"")):
  s.exact("assignment-map-kind-"+str(i),doc,lambda c,v=value:amended(c,value_registers=v),16)
 s.exact("all-unknown-keys-before-any-mapping",doc,
    lambda c:amended(c,value_registers={"f":0,"foreign":{}}),17)
 s.exact("unicode-unknown-function",doc,lambda c:amended(c,value_registers={"\u03bb":{}}),17)
 for i,value in enumerate((None,True,[],0,"")):
  s.exact("per-function-map-kind-"+str(i),doc,lambda c,v=value:amended(c,value_registers={"f":v}),18)
 for i,reg in enumerate((None,True,0,[],{},"rax","r10","r8","r9")):
  s.exact("v3-register-domain-"+str(i),doc,lambda c,r=reg:amended(c,value_registers={"f":{"x":r}}),18)
 s.exact("undefined-SSA",doc,lambda c:amended(c,value_registers={"f":{"missing":"rbx"}}),21)
 # All keys are checked before per-function mapping, after canonical key sorting.
 s.exact("unknown-z-before-invalid-known-a",program(scalar_function("a")),
    lambda c:amended(c,value_registers={"z":{},"a":{"x":"rax"}}),17)
 s.exact("empty-explicit-map",doc,lambda c:amended(c,value_registers={"f":{}}))

def interval_document():
 p=[parameter("b","u64"),parameter("a","u64")]
 ops=[operation("const",out=[parameter("z","u64")],attrs={"value":1}),
      operation("const",out=[parameter("c","u64")],attrs={"value":2}),
      operation("int.add.wrap",["z","c"],[parameter("v","u64")])]
 return program(function("f",p,ops,["u64"],dict(op="ret",values=["v"])))
def interval_group(s):
 doc=interval_document()
 for reg in REGISTERS:
  s.exact("noninterfering-dead-param-"+reg,doc,
   lambda c,r=reg:amended(c,4,value_registers={"f":{"a":r,"z":r}}))
 for label,mapping in(
   ("same-entry",{"a":"rbx","b":"rbx"}),
   ("dead-output-clobbers-live-input",{"z":"rbx","c":"rbx"}),
   ("input-output-inclusive",{"z":"rbx","v":"rbx"}),
   ("other-input-output-inclusive",{"c":"r15","v":"r15"}),
   ("register-order-before-name-order",{"a":"r12","b":"r12","z":"rbx","c":"rbx"}),
   ("reverse-map-insertion",{"v":"rbx","z":"rbx"})):
  s.exact(label,doc,lambda c,m=mapping:amended(c,4,value_registers={"f":m}),22)
 # Separate blocks have independent intervals, including branch and backedge arguments.
 edge=s.F.edge_case()
 for reg in REGISTERS:
  s.exact("staged-edges-"+reg,edge,lambda c,r=reg:amended(c,4,
     block_order={"f":["end","loop_block","entry"]},value_registers={"f":{"a":r,"x":r,"u":r}}))
 s.exact("original-Core-block-order-first",edge,lambda c:amended(c,4,
     block_order={"f":["end","loop_block","entry"]},value_registers={"f":{"a":"rbx","b":"rbx","u":"rbx","v":"rbx"}}),
     22,"E_HIA_MACHINE_PLAN: interfering values f/entry: a and b share rbx")
 def tie(c):
  p=plan_for(c,4);p["value_registers"]={"f":{"b":"rbx","a":"rbx"}};return p
 s.exact("same-start-lexicographic-tie",doc,tie,22,
     "E_HIA_MACHINE_PLAN: interfering values f/entry: a and b share rbx")

LEAF=(
 "const","int.add.wrap","int.add.checked","int.sub.wrap","int.sub.checked",
 "int.mul.wrap","int.mul.checked","int.div.checked","int.rem.checked",
 "int.shl.checked","int.shr.checked","int.neg.checked","int.cast",
 "bit.and","bit.or","bit.xor","bit.not","compare.eq","compare.ne","compare.lt","compare.le","compare.gt","compare.ge",
 "bool.and","bool.or","bool.not","select","buffer.len","buffer.load","buffer.store")
def leaf_document(op):
 attrs={};outs=["u64"];types_=["u64","u64"]
 if op=="const":types_=[];attrs={"value":7}
 elif op in("int.neg.checked","bit.not"):types_=["u64"]
 elif op=="int.cast":types_=["i64"];outs=["u32"];attrs={"mode":"wrap"}
 elif op.startswith("compare."):outs=["bool"]
 elif op.startswith("bool."):types_=["bool"] if op=="bool.not" else ["bool","bool"];outs=["bool"]
 elif op=="select":types_=["bool","u64","u64"]
 elif op=="buffer.len":types_=["readbuf"];outs=["usize"]
 elif op=="buffer.load":types_=["readbuf","usize"];outs=["u8"]
 elif op=="buffer.store":types_=["mutbuf","usize","u8"];outs=[]
 p=[parameter("p"+str(i),t) for i,t in enumerate(types_)]
 out=[parameter("v"+str(i),t) for i,t in enumerate(outs)]
 params=p+[parameter("marker","u64")]
 return program(function("f",params,[operation(op,[p["name"] for p in p],out,attrs)],outs,
   dict(op="ret",values=[x["name"] for x in out]),["alloc","read","trap","write"]))
def leaf_group(s,variant):
 assert set(LEAF)==s.plan.LEAF_VALUE_OPS and len(LEAF)==30
 for i,op in list(enumerate(LEAF))[variant*15:(variant+1)*15]:
  s.exact("leaf-op-"+str(i)+"-"+op,leaf_document(op),
    lambda c:amended(c,4,value_registers={"f":{"marker":"r8"}}))

RESOURCES=(
 ("buffer.new",["usize"],["buffer"]),("buffer.try_new",["usize"],["buffer","bool"]),
 ("buffer.len",["buffer"],["usize"]),("buffer.len",["readbuf"],["usize"]),("buffer.len",["mutbuf"],["usize"]),
 ("borrow.read",["buffer"],["readbuf"]),("borrow.read",["readbuf"],["readbuf"]),("borrow.read",["mutbuf"],["readbuf"]),
 ("borrow.mut",["buffer"],["mutbuf"]),("borrow.mut",["mutbuf"],["mutbuf"]),
 ("owner.move",["buffer"],["buffer"]),("owner.move",["chain"],["chain"]),
 ("owner.drop",["buffer"],[]),("owner.drop",["chain"],[]),
 ("buffer.load",["readbuf","usize"],["u8"]),("buffer.store",["mutbuf","usize","u8"],[]),
 ("buffer.fill",["mutbuf","u8"],[]),("buffer.copy",["mutbuf","readbuf","usize"],[]),
 ("buffer.move_within",["mutbuf","usize","usize","usize"],[]),("buffer.swap",["mutbuf","usize","usize"],[]),
 ("buffer.copy_range",["mutbuf","readbuf","usize","usize","usize"],[]),("buffer.fill_range",["mutbuf","usize","usize","u8"],[]),
 ("chain.empty",[],["chain"]),("chain.try_push",["chain","buffer"],["chain","buffer","bool"]),
 ("chain.pop",["chain"],["chain","buffer","bool"]),("chain.is_empty",["chain"],["bool"]),
 ("chain.head_read",["chain"],["readbuf"]),("chain.head_mut",["chain"],["mutbuf"]))
def resource_group(s,variant):
 rows=[]
 for i,(op,types_,outtypes) in enumerate(RESOURCES):
  p=[parameter("p"+str(i),t) for i,t in enumerate(types_)]
  out=[parameter("v"+str(i),t) for i,t in enumerate(outtypes)]
  d=program(function("f",p+[parameter("marker","u64")],
     [operation(op,[x["name"] for x in p],out)],term=dict(op="trap",code="user"),
     effects=["alloc","read","trap","write"]))
  expected=19 if op not in LEAF else (20 if "buffer" in types_ else None)
  rows.append(("resource-"+str(i)+"-"+op,d,expected))
 for borrow,typ in(("borrow.read","readbuf"),("borrow.mut","mutbuf")):
  d=program(function("f",[parameter("owner","buffer"),parameter("marker","u64")],
    [operation(borrow,["owner"],[parameter("view",typ)]),operation("loan.end",["view"])],
    term=dict(op="trap",code="user"),effects=["alloc","read","trap","write"]))
  rows.append(("loan-end-"+typ,d,19))
 assert len(rows)==30
 for label,d,expected in rows[variant*15:(variant+1)*15]:
  s.exact(label,d,lambda c:amended(c,4,value_registers={"f":{"marker":"r9"}}),expected)

def type_group(s):
 types_=("u8","u16","u32","u64","i8","i16","i32","i64","usize","isize","bool","unit","buffer","readbuf","mutbuf","chain")
 for typ in types_:
  d=program(function("f",[parameter("x",typ),parameter("marker","u64")],
       term=dict(op="trap",code="user"),effects=["trap"]))
  s.exact("assigned-definition-type-"+typ,d,
    lambda c:amended(c,value_registers={"f":{"x":"rbx"}}),None if typ in s.plan.VALUE_TYPES else 21)
  s.exact("leaf-parameter-type-"+typ,d,
    lambda c:amended(c,4,value_registers={"f":{"marker":"r8"}}),
    None if typ in s.plan.VALUE_TYPES|{"readbuf","mutbuf"} else 20)
 for typ in("u64","unit","buffer","readbuf","mutbuf","chain"):
  d=program(function("f",[parameter("marker","u64")],returns=[typ],
       term=dict(op="trap",code="user"),effects=["trap"]))
  # Borrowed return provenance is required even on a trapping function.
  if typ in("readbuf","mutbuf"):
   d["functions"][0]["params"].append(parameter("borrowed",typ))
   d["functions"][0]["blocks"][0]["params"]=d["functions"][0]["params"]
   d["functions"][0]["return_loans"]=["borrowed"]
  s.exact("leaf-return-type-"+typ,d,
    lambda c:amended(c,4,value_registers={"f":{"marker":"r8"}}),None if typ=="u64" else 20)

def first_error_group(s):
 d=program(scalar_function());rows=[]
 def add(label,error,edit):rows.append((label,error,edit))
 add("schema-before-fields",3,lambda p:p.update(schema="bad",extra=0))
 add("fields-before-hash",4,lambda p:p.update(core_sha256="",extra=0))
 add("hash-before-layout",5,lambda p:p.update(core_sha256="",block_order=None))
 add("layout-before-function",6,lambda p:p.update(block_order=None,function_order=[]))
 add("function-before-scratch",9,lambda p:p.update(function_order=[],scratch_registers=None))
 add("scratch-before-choices",10,lambda p:p.update(scratch_registers=None,instruction_selection=None))
 add("choices-before-alignment",11,lambda p:p.update(instruction_selection={},function_alignment=0))
 add("move-before-alu",12,lambda p:p["instruction_selection"].update(move_immediate="bad",alu_immediate="bad"))
 add("alu-before-alignment",13,lambda p:(p["instruction_selection"].update(alu_immediate="bad"),p.update(function_alignment=0)))
 add("alignment-before-select",14,lambda p:(p["instruction_selection"].update(scalar_select="bad"),p.update(function_alignment=0)))
 add("select-before-assignments",15,lambda p:(p["instruction_selection"].update(scalar_select="bad"),p.update(value_registers=None)))
 add("unknown-before-invalid-mapping",17,lambda p:p.update(value_registers={"f":None,"z":{}}))
 add("wire-before-schema-surrogate",2,lambda p:p.update(schema="bad",extra="\ud800"))
 add("snapshot-before-schema-float",2,lambda p:p.update(schema="bad",extra=0.0))
 add("snapshot-before-fields-tuple",2,lambda p:p.update(extra=()))
 add("snapshot-before-move-subclass",2,lambda p:p["instruction_selection"].update(move_immediate=s.F.InheritedStr("movabs")))
 for label,error,edit in rows:
  def make(c,edit=edit):
   p=plan_for(c);edit(p);return p
  s.exact(label,d,make,error)

def snapshot_group(s):
 d=program(scalar_function())
 samples=(0.0,-0.0,float("nan"),float("inf"),float("-inf"),b"x",bytearray(b"x"),
   memoryview(b"x"),(),(1,),set(),{1},DictSubclass(a=1),ListSubclass([1]),IntSubclass(1),
   s.F.InheritedStr("text"),object())
 for i,value in enumerate(samples):
  s.exact("nested-exact-tag-"+str(i),d,lambda c,v=value:amended(c,extra=v),2)
 for i,key in enumerate((None,True,1,1.0,b"a",(1,),s.F.InheritedStr("x"))):
  s.exact("non-exact-string-key-"+str(i),d,lambda c,k=key:amended(c,extra={k:None}),2)
 for i,kind in enumerate(("list","dict","mixed")):
  if kind=="list":
   value=[];value.append(value)
  elif kind=="dict":
   value={};value["self"]=value
  else:
   value=[];parent={"child":value};value.append(parent)
  s.exact("active-cycle-"+kind,d,lambda c,v=value:amended(c,extra=v),2)
 # Repeated containers outside the active path are permitted and copied twice.
 shared={"x":[1,True,None,"text"]}
 s.exact("repeated-off-path-alias",d,lambda c:{"extra":[shared,shared],"schema":"unknown"},3)
 for i,value in enumerate(("\ud800","\udfff","a\ud800b","\U0010ffff","\x00\n\t\"\\","\u00e9\U0001f642")):
  s.exact("scalar-Unicode-"+str(i),d,lambda c,v=value:{"schema":"unknown","extra":v},2 if i<3 else 3)

def depth_group(s):
 d=program(scalar_function())
 def nested(n,empty=False):
  value=[] if empty else None
  for unused in range(n):value=[value]
  return {"z":value}
 # Root depth is zero; an empty container does not visit an extra leaf.
 for n,empty,expected in((62,False,3),(63,False,3),(64,False,2),
                          (62,True,3),(63,True,3),(64,True,2)):
  s.exact("depth-"+str(n)+"-"+str(empty),d,lambda c,n=n,e=empty:nested(n,e),expected)

def digits_group(s,variant):
 d=program(scalar_function())
 rows=[]
 for limit,n in((640,639),(640,640),(640,641),(4300,4299),(4300,4300),(4300,4301),
                 (0,4301),(0,8192)):
  for sign in(1,-1):
   rows.append((limit,n,sign))
 assert len(rows)==16
 for limit,n,sign in rows[variant*8:(variant+1)*8]:
  value=sign*(10**(n-1))
  s.exact("integer-digits-"+str(limit)+"-"+str(n)+"-"+str(sign),d,
      lambda c,v=value:{"schema":"unknown","integer":v},3 if limit==0 or n<=limit else 2,digits=limit)

def node_budget_group(s,variant):
 count=262142+variant
 value={"z":[None]*count}
 assert visited(value)==262144+variant
 s.exact("exact-nodes-"+str(262144+variant),program(scalar_function()),
      lambda c:value,3 if variant==0 else 2)

def byte_budget_group(s,variant):
 value={"schema":"unknown","padding":""}
 value["padding"]="a"*(LIMIT+variant-len(canonical(value)))
 assert len(canonical(value))==LIMIT+variant
 s.exact("exact-wire-bytes-"+str(LIMIT+variant),program(scalar_function()),lambda c:value,3 if variant==0 else 2)

def integer_byte_group(s):
 value=1<<(LIMIT*4)
 assert value.bit_length()==LIMIT*4+1
 s.exact("integer-bitlength-before-decimal-allocation",program(scalar_function()),
    lambda c:{"schema":"unknown","integer":value},2,digits=0)

def scale_group(s,variant):
 if variant==0:
  d=program(*(function("f"+str(i)) for i in range(1024)))
  def make(c):
   p=plan_for(c,4);p["function_order"].reverse()
   p["block_order"]={"f1023":["entry"],"f0":["entry"]}
   p["value_registers"]={"f1023":{},"f0":{}}
   return p
  label="full-1024-function-domain"
 elif variant==1:
  blocks=[]
  for i in range(4096):
   term=dict(op="ret",values=[]) if i==4095 else dict(op="jump",target="b"+str(i+1),args=[])
   blocks.append(dict(id="b"+str(i),params=[],ops=[],term=term))
  d=program(function("f",blocks=blocks))
  def make(c):
   p=plan_for(c,4);p["block_order"]={"f":["b"+str(i) for i in reversed(range(4096))]}
   p["value_registers"]={"f":{}}
   return p
  label="full-4096-block-domain"
 elif variant==2:
  count=8192
  ops=[operation("const",out=[parameter("v"+str(i),"u64")],attrs={"value":i}) for i in range(count)]
  d=program(function("f",ops=ops))
  def make(c):
   p=plan_for(c,4);p["value_registers"]={"f":{"v"+str(i):"r8" for i in reversed(range(count))}}
   return p
  label="8192-definitions-same-register-dead-lifetimes"
 else:raise AssertionError(variant)
 s.exact(label,d,make)

def seed(s,document=None,make=None):
 checked=s.verify(program(scalar_function()) if document is None else document)
 s.admitted+=1
 plan=plan_for(checked) if make is None else make(checked)
 # The protocol seed is separately admitted by the unchanged original oracle.
 admitted=s.validate(checked,plan)
 graph=s.F.capture([checked.as_dict(),plan],PLAN_LEASE)
 return initial(graph,checked.sha256,sys.get_int_max_str_digits()),graph,admitted

def once(predicate,mutation):
 used=False
 def intercept(actual,event,ack):
  nonlocal used
  if not used and predicate(actual,struct.unpack("<16Q",event),ack):
   used=True
   result=mutation(actual,struct.unpack("<16Q",event),ack)
   assert type(result) is bytes and result!=ack
   return result
  return ack
 return intercept

def initial_protocol_group(s,variant):
 wire,graph,_=seed(s)
 nodes=q(graph,16);root=q(graph,24);edgebase=64+nodes*64
 root_at=128+64+(root-1)*64
 first=q(wire,root_at+24)
 first_edge=128+edgebase+first*8
 edits=[
  ("magic",0,0),("version",8,0),("controller-lease",16,0),
  ("logical-request",24,0),("Graph-lease",32,0),("root-zero",40,0),
  ("Graph-length",48,len(graph)-1),("reserved96",96,1),("reserved104",104,1),
  ("reserved112",112,1),("reserved120",120,1),("Graph-magic",128,0),
  ("Graph-lease-mismatch",136,PLAN_LEASE+1),("Graph-no-nodes",144,0),
  ("Graph-root",152,0),("Graph-edges-overflow",160,MASK),
  ("Graph-scalar-length",168,q(graph,40)+1),("Graph-extent",176,len(graph)+1),
  ("Graph-reserved",184,1),("root-kind",root_at,6),
  ("root-count",root_at+32,1),("root-identity",root_at+40,0),
  ("core-zero",first_edge,0),("plan-out-of-range",first_edge+8,nodes+1)]
 assert len(edits)==24
 for label,at,value in edits[variant*12:(variant+1)*12]:
  s.private_bad("initial-"+label,changed(wire,at,value))

def ack_protocol_group(s):
 wire,_,_=seed(s)
 edits=[("magic",0,0),("lease",8,CONTROL_LEASE+1),("sequence",16,0),
  ("operation",24,0),("status",32,1),("noncall-return",40,1),("length",48,1),("reserved",56,1)]
 for label,at,value in edits:
  s.private_bad("ACK-"+label,wire,once(lambda a,e,k:True,lambda a,e,k,at=at,v=value:changed(k,at,v)))
 for label,change in(("truncated",lambda raw:raw[:-1]),("trailing-byte",lambda raw:raw+b"\0")):
  s.private_bad("ACK-"+label,wire,once(lambda a,e,k:True,lambda a,e,k,f=change:f(k)))

def snapshot_protocol_group(s,variant):
 wire,_,_=seed(s)
 edits=[("magic",0,0),("version",8,0),("action",16,3),("lease",24,PLAN_LEASE+1),
  ("request",32,REQUEST+1),("mode",40,1),("error",48,1),("needed",56,32769),
  ("offset",64,1),("size",72,1),("version-result",80,1),("zero-visited",88,0),
  ("plan",96,0),("Core",104,0),("phase",112,0),("bad",120,1)]
 for label,at,value in edits[variant*8:(variant+1)*8]:
  s.private_bad("snapshot-"+label,wire,once(lambda a,e,k:e[1]==1 and e[4]==1,
     lambda a,e,k,at=at,v=value:changed(k,64+at,v)))

def wire_protocol_group(s,variant):
 wire,_,_=seed(s)
 edits=[
  ("magic",0,0),("lease",16,PLAN_LEASE+1),("request",24,REQUEST+1),("root",32,0),
  ("maximum",40,LIMIT+1),("flags",48,0),("digits",56,sys.get_int_max_str_digits()+1),("bad",120,1),
  ("code",64,1),("cause",72,1),("need-too-large",80,MASK),("offset",88,1),
  ("count",96,1),("next-image",104,0),("phase",112,1),("action",8,0)]
 for label,at,value in edits[variant*8:(variant+1)*8]:
  s.private_bad("wire-ready-"+label,wire,once(lambda a,e,k:e[1]==1 and e[4]==2 and q(k,72)==2,
     lambda a,e,k,at=at,v=value:changed(k,64+at,v)))

def grow_protocol_group(s,variant):
 wire,_,_=seed(s)
 if variant==0:
  edits=[("code",64,1),("cause",72,1),("offset",88,1),("count",96,1),
     ("next",104,1),("phase",112,2),("need-not-larger",80,None)]
  for label,at,value in edits:
   s.private_bad("wire-GROW-"+label,wire,
      once(lambda a,e,k:e[1]==1 and e[4]==2 and q(k,72)==1,
       lambda a,e,k,at=at,v=value:changed(k,64+at,a.slots[e[10]]["size"] if v is None else v)))
  s.private_bad("wire-GROW-return-marker",wire,
      once(lambda a,e,k:e[1]==1 and e[4]==2 and q(k,72)==1,lambda a,e,k:changed(k,40,GROW)))
 elif variant==1:
  edits=[("code",48,1),("offset",64,1),("count",72,1),("need-not-larger",56,None),
     ("early-phase",112,2),("terminal-phase",112,5),("action",16,0),("bad",120,1)]
  for label,at,value in edits:
   s.private_bad("semantic-GROW-"+label,wire,
     once(lambda a,e,k:e[1]==1 and e[4]==4 and q(k,80)==1,
       lambda a,e,k,at=at,v=value:changed(k,64+at,a.slots[e[10]]["size"] if v is None else v)))
 elif variant==2:
  for role in(2,4):
   saved=None;replayed=False
   def replay(a,event,ack,role=role):
    nonlocal saved,replayed
    e=struct.unpack("<16Q",event)
    if e[1]!=1 or e[4]!=role:return ack
    action=q(ack,72 if role==2 else 80)
    if saved is None and action==1:
     saved=ack
     return ack
    if saved is not None and not replayed:
     replayed=True
     # Keep the new outer lease/sequence while replaying an earlier actual peer
     # event and return value. This is an explicit private corruption control.
     return ack[:40]+saved[40:48]+ack[48:64]+saved[64:]
    return ack
   s.private_bad("stale-actual-GROW-role-"+str(role),wire,replay)
   assert saved is not None and replayed
 else:raise AssertionError(variant)

def semantic_protocol_group(s,variant):
 wire,_,_=seed(s)
 edits=[("magic",0,0),("version",8,0),("action",16,3),("lease",24,PLAN_LEASE+1),
   ("request",32,REQUEST+1),("mode",40,0),("error",48,3),("needed",56,0),
   ("offset",64,1025),("size",72,127),("version-result",80,0),("visited",88,1),
   ("plan",96,0),("Core",104,0),("phase",112,2),("bad",120,1)]
 for label,at,value in edits[variant*8:(variant+1)*8]:
  s.private_bad("semantic-success-"+label,wire,
    once(lambda a,e,k:e[1]==1 and e[4]==4 and q(k,80)==0,
     lambda a,e,k,at=at,v=value:changed(k,64+at,v)))

def descriptor_protocol_group(s):
 wire,_,_=seed(s)
 edits=[("magic",0,0),("version",8,0),("lease",16,PLAN_LEASE+1),("request",24,REQUEST+1),
  ("Core",32,0),("plan",40,0),("version-result",48,0),("Graph-length",56,0),
  ("actual-Core-SHA",64,None),("reserved96",96,1),("reserved104",104,1),("reserved112",112,1),("reserved120",120,1)]
 for label,at,value in edits:
  s.private_bad("descriptor-"+label,wire,once(lambda a,e,k:e[1]==14 and e[4:7]==(7,1024,128),
      lambda a,e,k,at=at,v=value:changed(k,64+at,q(k,64+at)^1 if v is None else v)))

def output_protocol_group(s):
 wire,_,_=seed(s)
 for label,at,value in(("zero-bytes",96,0),("too-many-bytes",96,LIMIT+1),
      ("out-of-span",88,MASK),("pending-next",104,2),("bad-phase",112,89)):
  s.private_bad("wire-output-"+label,wire,
     once(lambda a,e,k:e[1]==1 and e[4]==3 and q(k,72)==0,
          lambda a,e,k,at=at,v=value:changed(k,64+at,v)))
 # A genuinely completed controller cannot be resumed or initialized again.
 case=s.out/"cases"/("%04d"%len(s.cases));case.mkdir(parents=True)
 actual=s.H.Mechanical(s.args.assets,s.args.reference,case/"full-CAS")
 try:
  (case/"input.begin").write_bytes(wire)
  saved=s.guard()
  try:result=actual.run(wire)
  finally:s.unguard(saved)
  assert result["status"]=="TERMINAL" and q(result["event"],32)==0
  (case/"actual.terminal").write_bytes(result["event"]);(case/"actual.result").write_bytes(result["payload"])
  for label,raw in(("last-ACK",actual.last_original_ack),("initial-again",wire)):
   b=actual.buffers.allocate(len(raw),raw,True)
   try:
    returned=actual.native(5,(b,actual.slots[3],actual.slots[2]),(b,actual.slots[3],actual.slots[2]),
       ("post-terminal-"+label,"slot3","slot2"))
    assert returned==BAD
   finally:actual.buffers.close(b)
  row=dict(label="terminal-is-final",status="PASS",kind="PRIVATE_PERMANENT_BAD",
      native_entries=actual.entries,by_role=actual.calls,interceptions=0,
      original_completed_terminal_preserved=True,two_late_resumes_permanently_refused=True)
  s.cases.append(row);s.protocol+=1;actual.evidence.case(row);save(case/"result.json",row)
 finally:s.count(actual);save(case/"evidence.json",actual.close())

SCHEDULE=[["shape",0,17,0],["fields",0,34,0],["hash",0,8,0],["choices",0,16,0],["choices",1,16,0],["choices",2,16,0],["choices",3,16,0],["choices",4,16,0],["choices",5,16,0],["choices",6,16,0],["choices",7,16,0],["choices",8,16,0],["choices",9,16,0],["choices",10,16,0],["choices",11,16,0],["blocks",0,15,0],["layout",0,10,0],["order",0,17,0],["invalidchoices",0,19,0],["invalidchoices",1,19,0],["assignments",0,24,0],["intervals",0,22,0],["leaf",0,15,0],["leaf",1,15,0],["resources",0,15,0],["resources",1,15,0],["types",0,38,0],["firsterror",0,16,0],["snapshot",0,34,0],["depth",0,6,0],["digits",0,8,0],["digits",1,8,0],["nodes",0,1,0],["nodes",1,1,0],["bytes",0,1,0],["bytes",1,1,0],["integerbytes",0,1,0],["scale",0,1,0],["scale",1,1,0],["scale",2,1,0],["initial",0,12,12],["initial",1,12,12],["ack",0,10,10],["snapshotprotocol",0,8,8],["snapshotprotocol",1,8,8],["wireprotocol",0,8,8],["wireprotocol",1,8,8],["growprotocol",0,8,8],["growprotocol",1,8,8],["growprotocol",2,2,2],["semanticprotocol",0,8,8],["semanticprotocol",1,8,8],["descriptor",0,13,13],["outputprotocol",0,6,6]]
def deadline(signum,frame):raise TimeoutError("original checked-plan 180 second wall limit")
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 signal.signal(signal.SIGALRM,deadline);signal.setitimer(signal.ITIMER_REAL,180)
 p=argparse.ArgumentParser()
 for name in("reference","assets","out"):p.add_argument("--"+name,type=Path,required=True)
 p.add_argument("--group",choices=sorted({row[0] for row in SCHEDULE}),required=True)
 p.add_argument("--variant",type=int,required=True)
 args=p.parse_args();args.reference=args.reference.resolve();args.assets=args.assets.resolve();args.out=args.out.resolve()
 args.out.mkdir(parents=True,exist_ok=False)
 expected=next((r for r in SCHEDULE if r[:2]==[args.group,args.variant]),None)
 assert expected is not None
 start=time.monotonic();suite=None
 report=dict(status="INCOMPLETE",group=args.group,variant=args.variant,target_cases=expected[2],
    target_private_controls=expected[3],scope="FRESH_NATIVE_CHECKED_PLAN_FIVE_IMAGE_COMPONENT",
    native_entries=0,VM_entries=0,host_plan_or_canonical_generation_during_native=False,
    prior_reference_admission_fixture=True,actual_native_Core_admission_join=False,
    private_immutable_Graph_required=True,public_foreign_graph_capture=False,
    public_emitter_join=False,standalone_preservation_witness_JSON=False,installed=False,cold=False,
    all_prior_pass_counts_inherited=False)
 try:
  assert sys.version_info[:3]==(3,12,14)
  assert len(SCHEDULE)==54 and sum(r[2] for r in SCHEDULE)==674 and sum(r[3] for r in SCHEDULE)==119
  suite=Suite(args)
  simple={"shape":shape_group,"fields":field_group,"hash":hash_group,"blocks":block_group,
      "layout":layout_group,"order":order_group,"assignments":assignment_group,
      "intervals":interval_group,"types":type_group,"firsterror":first_error_group,
      "snapshot":snapshot_group,"depth":depth_group,"integerbytes":integer_byte_group,
      "ack":ack_protocol_group,"descriptor":descriptor_protocol_group,"outputprotocol":output_protocol_group}
  variants={"choices":choice_group,"invalidchoices":invalid_choice_group,
      "leaf":leaf_group,"resources":resource_group,"digits":digits_group,"nodes":node_budget_group,
      "bytes":byte_budget_group,"scale":scale_group,"initial":initial_protocol_group,
      "snapshotprotocol":snapshot_protocol_group,"wireprotocol":wire_protocol_group,
      "growprotocol":grow_protocol_group,"semanticprotocol":semantic_protocol_group}
  if args.group in simple:
   assert args.variant==0;simple[args.group](suite)
  else:variants[args.group](suite,args.variant)
  assert len(suite.cases)==expected[2] and suite.protocol==expected[3]
  assert suite.entries==sum(suite.calls.values())==sum(row["native_entries"] for row in suite.cases)
  assert suite.entries>0 and suite.calls["5"]>0
  if expected[3]==0:assert suite.admitted==len(suite.cases)
  if args.group in("fields","choices","intervals","leaf","resources","types","scale"):
   assert suite.calls["1"] and suite.calls["2"] and suite.calls["3"] and suite.calls["4"]
  if args.group in("choices","scale"):assert suite.pure_grows and suite.wire_grows
  report.update(status="PASS")
 except BaseException as error:
  report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  if suite is not None:
   report.update(cases=len(suite.cases),private_protocol_controls=suite.protocol,
      reference_Core_admissions=suite.admitted,native_entries=suite.entries,by_role=suite.calls,
      covered_public_error_codes=sorted(suite.covered_errors),mechanical_growth_by_slot=suite.grows,
      actual_semantic_GROW_events=suite.pure_grows,actual_wire_GROW_events=suite.wire_grows,
      results=suite.cases)
   try:report["source_custody"]=suite.finish()
   except BaseException as error:
    report["status"]="FAIL";report["source_custody_error"]=dict(type=type(error).__name__,text=str(error),traceback=traceback.format_exc())
    traceback.print_exc()
  report.update(elapsed_seconds=time.monotonic()-start,
      limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),
          core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180),
      original_group_limits_include_evidence_encoding=True,
      each_native_entry_complete_three_operands_before_after=True,
      actual_command_ACK_event_full_bytes_retained=True,
      guards_and_hardware_readonly_and_canaries=True)
  save(args.out/"summary.json",report)
  print("HIA_CHECKED_PLAN_GROUP_ORIGINAL "+json.dumps(report,sort_keys=True,ensure_ascii=True),flush=True)
  signal.setitimer(signal.ITIMER_REAL,0)
 if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
