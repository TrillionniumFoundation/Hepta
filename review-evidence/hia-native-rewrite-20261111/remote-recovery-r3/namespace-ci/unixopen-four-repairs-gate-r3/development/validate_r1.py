#!/usr/bin/env python3
"""New local DEVELOPMENT alpha-equivalence gate; no old CI count is inherited."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ast, copy, ctypes, hashlib, importlib.util, json, os, platform, resource, signal, stat, struct, time, traceback
from pathlib import Path
ROOT=Path("/workspace/scratch/9acdfa9f5639/runtime-development")
REF=Path("/workspace/scratch/9acdfa9f5639/reference0ef")
ORIGINAL=ROOT/"unix9-follow55B-original/inner-retained"
SOURCE=ROOT/"dms10-dense-ssa-r1/generate_hia_agent_namespace_dms_map_join_r10.py"
OUT=ROOT/"dms10-dense-ssa-development-r1"
OLD=ORIGINAL/"namespace-actual-unixopen-source/tools/generate_hia_agent_namespace_dms_map_join_r9.py"
DOC=ORIGINAL/"run/namespace-actual-unixopen-r1/actual-unixopen-build-r1/generation-frontier/role-4.document.json"
COMPILER=ORIGINAL/"run/namespace-actual-unixopen-r1/compiler/B3.image.bin"
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
NEW="7198fd77427b45fc5de80b06290de5cbd524bb9752ef9509241fd3095a4a1c33"
def sha(b):return hashlib.sha256(b).hexdigest()
def git(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def save(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+"\n")
def wire(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def q(b,a):return struct.unpack_from("<Q",b,a)[0]
def put(b,a,v):struct.pack_into("<Q",b,a,v)
def magic(b):return int.from_bytes(b,"little")
def info(p):
 b=p.read_bytes();return dict(bytes=len(b),sha256=sha(b),gitsha=git(b),mode=stat.S_IMODE(p.stat().st_mode))
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p)
 m=importlib.util.module_from_spec(spec);sys.modules[name]=m
 exec(compile(p.read_bytes(),str(p),"exec"),m.__dict__);return m
def main():
 assert sys.version_info[:3]==(3,12,14)
 assert not OUT.exists();OUT.mkdir()
 started=time.monotonic_ns();cpu0=time.process_time();child0=resource.getrusage(resource.RUSAGE_CHILDREN)
 def timeout(*_):raise TimeoutError("development original180wall")
 signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 report=dict(status="INCOMPLETE",scope="LOCAL_DEVELOPMENT_DMS10_ALPHA_EQUIVALENCE_NOT_CI_QUALIFICATION",
  environment=dict(python=sys.version,platform=platform.platform()),old_CI_preserved="FAIL",fresh_B3=0,
  old_VM=0,new_VM=0,new_native=0,direct_steady_VM_pairs=0,
  original_nine_role_28_process_gate_executed=False,physical_OS_syscalls=0,
  limits=dict(subject_CPU=90,subject_wall=180,address_bytes=1<<30,VM_steps=4000000,VM_arena=32<<20,VM_depth=64,
   B3_CPU=10,B3_wall=20,B3_address=256<<20,B3_output=1<<20,B3_workspace=1<<20))
 pins={};primary=None
 def pin(p,expected=None):
  r=info(p)
  if expected:assert r["sha256"]==expected,(str(p),r)
  pins[str(p)]=r;return p.read_bytes()
 cas=OUT/"cas";cas.mkdir()
 def kept(b):
  b=bytes(b);h=sha(b);p=cas/h
  if not p.exists():p.write_bytes(b)
  assert p.read_bytes()==b
  return dict(sha256=h,bytes=len(b),path="cas/"+h)
 try:
  index=Path("/workspace/scratch/9acdfa9f5639/reference0ef-local-copies.json")
  inventory=json.loads(pin(index))
  assert inventory["reference_commit"]=="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
  expected={r["path"]:r for r in inventory["matched"]}
  for r in inventory["matched"]:
   p=REF/r["path"];a=info(p)
   assert (a["bytes"],a["sha256"],a["gitsha"],a["mode"])==(r["bytes"],r["sha256"],r["gitsha"],int(r["mode"][-3:],8))
  pin(SOURCE,NEW);pin(OLD,"268a55deb3912d658b4fdb9952fbfeff8cedd168bcda18da611d4ae4d664567f")
  original_doc_raw=pin(DOC,"a6eca09e2a03e8cc606df7a1c95ef6519089ff6d3dba1052b9943ae8576b7df1")
  assert len(pin(COMPILER,B3))==669556
  sys.path.insert(0,str(REF))
  import tools
  for name in ("generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects","hia_namespace_dms_fixed_header_builder"):
   p=ORIGINAL/"namespace-actual-unixopen-source/tools"/(name+".py");pin(p);load("tools."+name,p)
  old=load("development_old_dms10",OLD);new=load("development_new_dms10",SOURCE)
  old_doc=old.document();new_doc=new.document()
  assert wire(old_doc)==original_doc_raw
  assert new.source_program()==old.source_program()
  changed=[a["name"] for a,b in zip(old_doc["functions"],new_doc["functions"]) if a!=b]
  assert changed==["f16"]
  # Independent explicit source-name inverse, including all use sites.
  old_fn=old_doc["functions"][16];new_fn=new_doc["functions"][16]
  names=sorted({v["name"] for b in old_fn["blocks"] for v in b["params"]+[v for op in b["ops"] for v in op["out"]]},key=lambda n:int(n[1:]))
  inverse={"v"+str(i):n for i,n in enumerate(names)}
  back=copy.deepcopy(new_doc)
  f=back["functions"][16]
  for v in f["params"]:v["name"]=inverse[v["name"]]
  for b in f["blocks"]:
   for v in b["params"]:v["name"]=inverse[v["name"]]
   for op in b["ops"]:
    op["args"]=[inverse[x] for x in op["args"]]
    for v in op["out"]:v["name"]=inverse[v["name"]]
   term=b["term"]
   if term["op"]=="ret":term["values"]=[inverse[x] for x in term["values"]]
   elif term["op"]=="jump":term["args"]=[inverse[x] for x in term["args"]]
   else:
    assert term["op"]=="branch"
    term["cond"]=inverse[term["cond"]]
    for edge in ("then","else"):term[edge]["args"]=[inverse[x] for x in term[edge]["args"]]
  assert wire(back)==original_doc_raw
  (OUT/"old.document.json").write_bytes(original_doc_raw)
  (OUT/"new.document.json").write_bytes(wire(new_doc))
  save(OUT/"name-bijection.json",dict(old_to_new={n:"v"+str(i) for i,n in enumerate(names)},inverse_exact_original_bytes=True))
  from hepta.hia_agent_assembly import render_assembly,assemble_program
  from hepta.hia_program_runtime import _Machine,_Owner,_View
  from hepta.hia_json_preflight_native import NativeHiaJsonImage
  from tools.qualify_hia_selfhost import compile_stage
  old_asm=render_assembly(old_doc).encode();new_asm=render_assembly(new_doc).encode()
  (OUT/"old.hiaasm").write_bytes(old_asm);(OUT/"new.hiaasm").write_bytes(new_asm)
  assert 0<len(new_asm)<=1<<20
  old_program=assemble_program(old_asm);new_program=assemble_program(new_asm)
  compile_dir=OUT/"compile";compile_dir.mkdir()
  image_path,receipt=compile_stage(compile_dir,"new-dms10",COMPILER,new_asm)
  assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
  assert receipt["output_capacity"]==1<<20 and receipt["workspace_bytes"]==1<<20
  report["fresh_B3"]=1
  image_raw=pin(image_path);image=NativeHiaJsonImage(image_raw,sha(image_raw))
  canary=bytes(range(160,176))
  def vm(program,src,output,workspace,entry="f0"):
   owners=[_Owner(-1,bytearray(src)),_Owner(-2,bytearray(output)),_Owner(-3,bytearray(workspace))]
   m=_Machine(program,4000000,32<<20,None,64);fn=m.functions[entry]
   args=[_View(owners[2],True)] if entry=="f16" else [_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)]
   status=m.invoke(fn,args)[0]
   assert bytes(owners[0].data)==src
   return status,bytes(owners[1].data),bytes(owners[2].data),m.steps,m.resources()
  def native(src,output,workspace):
   data=[src,output,workspace];bufs=[]
   for b in data:
    buf=ctypes.create_string_buffer(len(b)+32)
    ctypes.memmove(ctypes.addressof(buf),canary,16)
    if b:ctypes.memmove(ctypes.addressof(buf)+16,b,len(b))
    ctypes.memmove(ctypes.addressof(buf)+16+len(b),canary,16)
    bufs.append(buf)
   result=image._entry(*[x for buf,b in zip(bufs,data) for x in (ctypes.addressof(buf)+16,len(b))])
   allbytes=[]
   for buf,b in zip(bufs,data):
    raw=bytes(buf)
    assert raw[:16]==raw[len(b)+16:len(b)+32]==canary
    allbytes.append(raw[16:16+len(b)])
   assert allbytes[0]==src
   return result,allbytes[1],allbytes[2]
  ledger=[]
  def compare(label,src,output,workspace):
   pre=dict(input=kept(src),output=kept(output),workspace=kept(workspace))
   a=vm(old_program,src,output,workspace);report["old_VM"]+=1
   b=vm(new_program,src,output,workspace);report["new_VM"]+=1
   c=native(src,output,workspace);report["new_native"]+=1
   assert a==b,(label,"old/new full VM or steps/resources")
   assert a[:3]==c,(label,"new native complete bytes/return")
   row=dict(label=label,pre=pre,returned=a[0],steps=a[3],resources=a[4],output=kept(a[1]),workspace=kept(a[2]),
    old_new_VM_equal=True,new_native_equal=True,canaries_equal=True)
   ledger.append(row);save(OUT/"entries.json",ledger)
   return a
  # Private protocol frames are explicit controls, not issued OS/Store authority.
  init=bytearray(320)
  for at,v in ((0,magic(b"HIANDX03")),(8,1),(32,256),(48,4096),(64,magic(b"HIANDM03")),(72,1),
    (80,11),(88,13),(128,17),(136,19),(168,3),(176,420),(184,3)):put(init,at,v)
  init=bytes(init)
  initialized=compare("complete-init-request",init,bytes([0xa5])*1280,bytes(8192))
  assert initialized[0]==1
  state=initialized[2]
  ack=bytearray(1344)
  for at,v in ((0,magic(b"HIANDX03")),(8,2),(16,1),(32,1280),(40,1),(48,4096),(64,magic(b"HIANDM03")),
    (72,8),(80,11),(88,13),(104,1),(120,1),(128,256),(136,256),(144,512),(160,1),(192,1024)):put(ack,at,v)
  ack[320:576]=state[768:1024]
  for at,v in ((0,magic(b"HIANFR03")),(16,17),(24,19),(120,1),(168,1),(176,3)):put(ack,576+at,v)
  for at,v in ((0,magic(b"HIANFR03")),(8,1),(16,17),(24,19),(64,1),(248,3)):put(ack,832+at,v)
  steady=compare("explicit-private-FS-init-completion",bytes(ack),initialized[1],state)
  assert steady[0]==0
  state=steady[2]
  probe=bytearray(init);put(probe,72,2);put(probe,96,1)
  for at in range(128,208,8):put(probe,at,0)
  for at in (0,8,32,40,48,56,72,80,112,120,136,144,152,160,176,200,208,232,248,416,424,464,472,1280,1288,1296,1304,1312,1320,1336,1344,1352):
   mutated=bytearray(state);put(mutated,at,q(mutated,at)^1)
   compare("mutated-steady-field-"+str(at),bytes(probe),bytes([0x3c])*1280,bytes(mutated))
  compare("unchanged-steady-refuses-bad-open-shape",bytes(probe),bytes([0x3c])*1280,state)
  for n in (0,7,8,8191):
   compare("short-workspace-"+str(n),init,bytes([0x55])*1280,bytes(n))
  for n in (0,255,1279):
   compare("short-output-"+str(n),init,bytes([0x66])*n,bytes(8192))
  for n in (0,63,64,319):
   compare("short-source-"+str(n),init[:n],bytes([0x77])*1280,bytes(8192))
  # Additional direct old/new f16 scope checks do not claim native entry.
  direct=[]
  for label,work in (("phase6",initialized[2]),("phase1",state),("allzero",bytes(8192))):
   a=vm(old_program,b"",b"",work,"f16");b=vm(new_program,b"",b"",work,"f16")
   assert a==b;report["direct_steady_VM_pairs"]+=1
   direct.append(dict(label=label,returned=a[0],steps=a[3],resources=a[4],pre=kept(work),post=kept(a[2])))
  save(OUT/"direct-steady.json",direct)
  for module in list(sys.modules.values()):
   path=getattr(module,"__file__",None)
   if not path:continue
   p=Path(path).resolve()
   if p.is_relative_to(REF):
    rel=p.relative_to(REF).as_posix();r=expected[rel]
    pin(p,r["sha256"]);assert info(p)["gitsha"]==r["gitsha"]
  report.update(status="PASS",controls=len(ledger),direct_scope_controls=len(direct),
   source_DSL_exact=True,old_generation_exact_original_failure_document=True,one_function_alpha_inverse_exact=True,
   all_full_return_output_workspace_steps_resources_equal=True,new_document=info(OUT/"new.document.json"),
   new_hiaasm=info(OUT/"new.hiaasm"),new_image=info(image_path),compile_receipt=receipt,
   subject_CI_rerun=False,ordinary_Store_SQL31_closed=False)
 except BaseException as error:
  primary=error;report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  errors=[]
  for name,before in pins.items():
   try:assert info(Path(name))==before,name
   except BaseException as error:
    errors.append(dict(path=name,error=repr(error)))
    if primary is None:primary=error
    else:primary.add_note("after:"+repr(error))
  report["source_before"]=pins;report["after_errors"]=errors
  save(OUT/"summary.json",report)
  usage=resource.getrusage(resource.RUSAGE_CHILDREN)
  total_cpu=time.process_time()-cpu0+usage.ru_utime+usage.ru_stime-child0.ru_utime-child0.ru_stime
  wall=time.monotonic_ns()-started
  budget=dict(cpu_seconds=total_cpu,wall_ns=wall,CPU_limit=90,wall_limit_ns=180000000000)
  if not (0<=total_cpu<90 and 0<=wall<180000000000):
   if primary is None:primary=AssertionError("final original90CPU180wall")
  if primary is not None:report["status"]="FAIL"
  report["post_readback_budget"]=budget;save(OUT/"summary.json",report)
  print(json.dumps({k:v for k,v in report.items() if k not in ("source_before","compile_receipt")},sort_keys=True),flush=True)
  signal.setitimer(signal.ITIMER_REAL,0)
 if primary:raise primary
if __name__=="__main__":main()
