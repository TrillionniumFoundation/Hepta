"""Source inverse, transitive read-only proof, exact original generation and fresh Core/profile gate."""
from __future__ import annotations
import ast,hashlib,importlib.util,json,resource,re,signal,sys,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
BASE=Path("/workspace/scratch/9acdfa9f5639/runtime-development/nine-role-local-r4")
REF=Path("/workspace/scratch/9acdfa9f5639/reference0ef")
def sha(b):return hashlib.sha256(b).hexdigest()
def ident(p):
 p=Path(p);b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=sha(b),mode=p.stat().st_mode&0o777,gitsha=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest())
def save(p,d):
 b=(json.dumps(d,sort_keys=True,indent=2)+"\n").encode();p.write_bytes(b);assert p.read_bytes()==b
def main():
 started=time.monotonic_ns();startcpu=time.process_time_ns();pins={};report=dict(status="INCOMPLETE",scope="NEW_ISSUER_HEADER_READ_HOIST_SOURCE_PROOF_ONLY",B3=0,VM=0,native=0);primary=None
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def alarm(*a):raise TimeoutError("180wall")
 signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,180)
 def pin(p):
  p=Path(p);pins[str(p)]=ident(p);return p.read_bytes()
 def load(name,p):
  b=pin(p);spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;exec(compile(b,str(p),"exec"),m.__dict__);return m
 try:
  pin(__file__);old=pin(ROOT/"old.py");new=pin(ROOT/"new.py")
  assert ident(ROOT/"old.py")["gitsha"]=="33c3bde4fdae6781ae33a20be776a22ea29222f8"
  assert ident(ROOT/"new.py")["gitsha"]=="dc45ba1fc5910be5d591b7433ce79cb814229e40"
  edits=json.loads(pin(ROOT/"exact-edits.json"));forward=old.decode()
  for e in edits:assert forward.count(e["before"])==1;forward=forward.replace(e["before"],e["after"])
  assert forward.encode()==new
  inverse=new.decode()
  for e in reversed(edits):assert inverse.count(e["after"])==1;inverse=inverse.replace(e["after"],e["before"])
  assert inverse.encode()==old
  sys.path[:0]=[str(BASE/"source"),str(REF)]
  from hepta.hia_agent_assembly import render_assembly,assemble_program
  a=load("old_issuer_readproof",ROOT/"old.py");b=load("new_issuer_readproof",ROOT/"new.py")
  original=a.source_program();candidate=b.source_program()
  af={n.name:n for n in ast.parse(original).body};bf={n.name:n for n in ast.parse(candidate).body}
  assert list(af)==list(bf) and a.CONSTANTS==b.CONSTANTS
  changed=[n for n in af if ast.dump(af[n],include_attributes=False)!=ast.dump(bf[n],include_attributes=False)]
  assert changed==["ui_child_shape"]
  builtin={"byte","length","choose"}
  seen=set();edges={}
  def visit(name,functions):
   if name in seen:return
   seen.add(name);node=functions[name]
   assert all(not isinstance(n,(ast.Attribute,ast.Subscript,ast.AugAssign,ast.Delete)) for n in ast.walk(node))
   calls=[]
   for n in ast.walk(node):
    if isinstance(n,ast.Call):
     assert isinstance(n.func,ast.Name);callee=n.func.id;calls.append(callee)
     assert callee in functions or callee in builtin,callee
     if callee in functions:visit(callee,functions)
   edges[name]=sorted(set(calls))
  visit("ui_child_shape",bf)
  assert seen=={"ui_child_shape","ui_capsule","ui_span","read64","get"}
  assert not any(x in {"store","put","copy_input","copy_workspace","buffer_copy_range"} for calls in edges.values() for x in calls)
  docs={"old":a.document(),"new":b.document()}
  olddoc=json.loads(pin(BASE/"evidence/actual-unixopen-build-r1/generation-frontier/role-9.document.json"))
  assert docs["old"]==olddoc
  ids={n:"f"+str(i) for i,n in enumerate(af)}
  differences=[x["name"] for x,y in zip(docs["old"]["functions"],docs["new"]["functions"],strict=True) if x!=y]
  assert differences==[ids["ui_child_shape"]]
  profiles={};gen=[]
  for label,d in docs.items():
   raw=(json.dumps(d,sort_keys=True,separators=(",",":"))+"\n").encode();(ROOT/(label+".document.json")).write_bytes(raw)
   source=render_assembly(d).encode();(ROOT/(label+".hiaasm")).write_bytes(source);assemble_program(source)
   funcs=d["functions"];names=[p["name"] for f in funcs for p in f["params"]]+[p["name"] for f in funcs for block in f["blocks"] for p in block["params"]]+[o["name"] for f in funcs for block in f["blocks"] for op in block["ops"] for o in op.get("out",[])]
   suffixes=[int(m.group(1)) for name in names if (m:=re.search(r"(\d+)$",name))]
   profile=dict(functions=len(funcs),blocks=sum(len(f["blocks"]) for f in funcs),ops=sum(len(block["ops"]) for f in funcs for block in f["blocks"]),max_blocks=max(len(f["blocks"]) for f in funcs),max_block_params=max(len(block["params"]) for f in funcs for block in f["blocks"]),max_ssa_numeric_suffix=max(suffixes,default=0),source_bytes=len(source))
   profiles[label]=profile;save(ROOT/(label+"-profile.json"),profile)
   assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
   assert profile["max_blocks"]<=256 and profile["max_block_params"]<=16 and profile["max_ssa_numeric_suffix"]<2048
   assert 0<len(source)<=1<<20
   allowed={"const","buffer.load","buffer.len","int.cast","int.add.wrap","int.sub.wrap","int.mul.wrap","int.shl.checked","int.shr.checked","bit.or","bit.and","compare.eq","compare.ne","compare.lt","compare.le","compare.gt","compare.ge","bool.not","bool.and","bool.or","select","call"}
   subset={f["name"]:f for f in funcs if f["name"] in {ids[n] for n in seen}}
   for f in subset.values():
    for block in f["blocks"]:
     for op in block["ops"]:
      assert op["op"] in allowed,(label,f["name"],op["op"])
      if op["op"]=="call":assert op["attrs"]["function"] in subset
   gen.append(dict(label=label,read_only_function_ids=sorted(subset),exact_ops=sorted({op["op"] for f in subset.values() for block in f["blocks"] for op in block["ops"]}),no_buffer_write_or_allocation_or_drop_or_syscall=True))
  asm=pin(BASE/"source/inputs/native_unixopen_issued_executor.S").decode()
  assert ident(BASE/"source/inputs/native_unixopen_issued_executor.S")["gitsha"]=="af439d426a8acb1a2bc114077185fc24ca42cc8a"
  allocation=asm[asm.index("allocate_descriptor:\n"):asm.index("protect_descriptor:\n")]
  invocation=asm[asm.index("invoke_image:\n"):asm.index("\nrun_map:")]
  assert "mov r10d,0x22" in allocation and "mov r8,-1" in allocation
  assert "call qword ptr [rax+r10*8]" in invocation and "mov r8,[r15+WORK+8]" in invocation and "mov r9,[r15+WORK+16]" in invocation
  report.update(status="PASS_SOURCE_PROFILE_CORE_ONLY",exact_two_source_edits=edits,full_author_forward_inverse=True,changed_DSL_function=changed,changed_generated_function_ids=differences,all_other_functions_exact=True,
   transitive_function_names=sorted(seen),call_edges=edges,generated_read_only_proof=gen,profiles=profiles,
   header_offsets=[224,232,240,248],header_read_bytes=8,guard_workspace_bytes=256,
   proof=["All hoisted fixed index+i accesses have 0<=index+i<=255 for i0..7; no u64 addition overflow and no bounds trap under W length>=256.",
    "ui_child_shape and the complete transitive five-function closure contain only scalar control, buffer.len/load and their read-only calls; no write to W or S occurs during either loop.",
    "In this fixed single-thread carrier each role9 workspace is a private anonymous mmap descriptor (flags0x22,fd-1). The image executes synchronously between before/after records; input/capsule records are copied bytes and no callback/syscall is invoked inside this read-only closure.",
    "For the fixed invocation, these four words remain constant. Cached unsigned values therefore equal every original repeated get. Original byte(s) then byte(w), addition expressions, loop increment and first mismatch return remain in order.",
    "The W length<256 branch is the exact original loop, including short-W traps. For W>=256 extra empty-loop reads are total, read-only and unobservable except costs.",
    "Same u64 arithmetic/wrap and first load/trap ordering are preserved in the byte comparisons; no full-span shortcut or wide load is introduced."],
   explicit_nonclaims=["No arbitrary concurrently rewritten workspace equivalence.","No arbitrary fuel-by-fuel or exact step-count equivalence.","No native success, full28 case qualification or budget relaxation."],
   fixed_executor_pin=ident(BASE/"source/inputs/native_unixopen_issued_executor.S"),
   actual_CI_or_qualification=False,planned_tests=["old/new/direct VM on empty/first inequality/all mismatch offsets/bad spans/u64wrap/short W","old/new actual native full buffers and traps under original profiles","original12+8+8 complete fresh gate without split or inherited cases"])
  for m in tuple(sys.modules.values()):
   p=getattr(m,"__file__",None)
   if p:
    p=Path(p).resolve()
    if p.suffix==".py" and (p.is_relative_to(BASE/"source") or p.is_relative_to(REF)):pin(p)
 except BaseException as exc:
  primary=exc;report.update(status="FAIL",error=repr(exc),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  after={};errors=[]
  for p,expected in pins.items():
   try:after[p]=ident(p);assert after[p]==expected
   except BaseException as exc:
    errors.append(dict(path=p,error=repr(exc)))
    if primary is None:primary=exc
    else:primary.add_note("after:"+repr(exc))
  report.update(source_before=pins,source_after=after,after_errors=errors)
  if primary is not None:report["status"]="FAIL"
  try:
   save(ROOT/"proof.json",report);print(json.dumps({k:report.get(k) for k in ["status","profiles","changed_generated_function_ids","B3","VM","native"]},sort_keys=True),flush=True)
   assert 0<=time.process_time_ns()-startcpu<90_000_000_000 and 0<=time.monotonic_ns()-started<180_000_000_000
  except BaseException as exc:
   if primary is None:primary=exc
   else:primary.add_note("final:"+repr(exc))
  if primary is not None:
   report.update(status="FAIL",final_error=repr(primary))
   try:save(ROOT/"proof.json",report)
   except BaseException as exc:primary.add_note("FAILreceipt:"+repr(exc))
  signal.setitimer(signal.ITIMER_REAL,0)
 if primary is not None:raise primary
if __name__=="__main__":main()
