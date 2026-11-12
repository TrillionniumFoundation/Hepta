"""Build one unified P16 type/group6/Core Graph root in a 47-image ELF.

The complete actual FOLLOW53 role56 is reconstructed before extension. One new
combined root is compiled with35ee B3; the other42 actual peer source/image
pairs and historical native HIA packer remain exact. Four actual integer Core
decoder/service images are explicitly added to formerly empty rows.

All original P16 modes/private tree input and error paths are retained. Only
mode1/tree0 success gains the actual issued Graph. This is new development
source; no prior case count or unexecuted combined qualification is inherited.
"""
from __future__ import annotations
import argparse,ast,ctypes,importlib.util,json,os,resource,signal,stat,struct,sys,time,traceback,zlib
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
for name in ("project","reference","compiler","assets","out"):
 p.add_argument("--"+name,type=Path,required=True)
a=p.parse_args()
PROJECT=a.project.resolve();REF=a.reference.resolve();OUT=a.out.resolve()
COMPILER=a.compiler.resolve();ASSET_PATH=a.assets.resolve()
OUT.mkdir(parents=True,exist_ok=False)
NEW_COMPILER="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
OLD_COMPILER="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
OWNER="5812129aebea5e0ef2e972cc43b2e8c3db2f7b6b6b0f63d53fe1f7d6c0f1a33e"
GENERATOR="f73573a25b040920ff2f9b006a0fbc92e5e63616e64b550db92b4574b375a7b9"
SOURCE_OWNER="c7575f39085d09c05df5999087657f2825d9219e6d1512beba21d77c3551a3e4"
CHILD_SHA="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
LIVE_OLD=set(range(1,29))|set(range(40,47))|{50,51,55,56,59,61,62,63}
LIVE=LIVE_OLD|{31,32,33,58}
START=time.monotonic_ns()
START_SELF=resource.getrusage(resource.RUSAGE_SELF);START_CHILD=resource.getrusage(resource.RUSAGE_CHILDREN)
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def deadline(signum,frame):raise TimeoutError("program Graph prefix builder 180 wall seconds")
signal.signal(signal.SIGALRM,deadline);signal.setitimer(signal.ITIMER_REAL,180)
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
libc.mmap.restype=ctypes.c_void_p
libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
PINS={};COMPILED=[];ATTEMPTS=[];PACKER_ENTRIES=0;STATUS="FAIL";FAILURE=None;AFTER=[]
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def read(path):
 path=Path(path).resolve();st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not path.is_symlink()
 raw=path.read_bytes();mode=stat.S_IMODE(st.st_mode)
 if path in PINS:assert PINS[path]==(raw,mode),str(path)
 else:PINS[path]=(raw,mode)
 return raw
def load(name,path,expected=None):
 raw=read(path)
 if expected is not None:assert digest(raw)==expected
 ast.parse(raw,filename=str(path))
 spec=importlib.util.spec_from_file_location(name,path)
 module=importlib.util.module_from_spec(spec);sys.modules[name]=module
 spec.loader.exec_module(module)
 return module
def cas(raw):
 raw=bytes(raw);h=digest(raw);dest=OUT/"cas"/(h+".zlib");dest.parent.mkdir(exist_ok=True)
 if not dest.exists():
  with dest.open("xb") as f:f.write(zlib.compress(raw,1))
 assert zlib.decompress(dest.read_bytes())==raw
 return dict(bytes=len(raw),sha256=h,path="cas/"+dest.name,compression="zlib")
def before_after():
 rows=[]
 for path,(raw,mode) in PINS.items():
  ok=False;error=None
  try:
   info=path.lstat()
   ok=stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink==1
   ok=ok and stat.S_IMODE(info.st_mode)==mode and path.read_bytes()==raw
  except BaseException as exc:error=repr(exc)
  rows.append(dict(path=str(path),bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=mode,same=ok,error=error))
 return rows
class Guard:
 def __init__(self,raw,size=None,fill=0,readonly=False):
  self.size=len(raw) if size is None else size
  assert 0<=len(raw)<=self.size
  self.total=((self.size+128+4095)//4096)*4096
  self.addr=int(libc.mmap(None,self.total,3,0x22,-1,0))
  assert self.addr!=ctypes.c_void_p(-1).value
  self.ptr=self.addr+64;ctypes.memset(self.addr,0x5d,self.total)
  if self.size:ctypes.memset(self.ptr,fill,self.size)
  if raw:ctypes.memmove(self.ptr,raw,len(raw))
  self.readonly=readonly
  if readonly:assert libc.mprotect(self.addr,self.total,1)==0
 def value(self):return ctypes.string_at(self.ptr,self.size)
 def check(self):
  assert ctypes.string_at(self.addr,64)==bytes([0x5d])*64
  assert ctypes.string_at(self.ptr+self.size,self.total-self.size-64)==bytes([0x5d])*(self.total-self.size-64)
 def close(self):
  if self.addr is not None:
   addr=self.addr;self.addr=None
   assert libc.munmap(addr,self.total)==0
def expected_elf(prefix,tables,roles):
 out=bytearray(prefix);assert len(tables)==1
 for role in range(1,64):
  raw=roles[role]
  assert len(raw)<=1048576
  if raw:
   out+=bytes((-len(out))&15)
   struct.pack_into("<Q",out,tables[0]+role*8,4194304+len(out));out+=raw
  else:assert struct.unpack_from("<Q",out,tables[0]+role*8)[0]==0
 struct.pack_into("<Q",out,96,len(out));struct.pack_into("<Q",out,104,len(out))
 return bytes(out)

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
 return (end.ru_utime+end.ru_stime-START_SELF.ru_utime-START_SELF.ru_stime+
   children.ru_utime+children.ru_stime-START_CHILD.ru_utime-START_CHILD.ru_stime,
   (time.monotonic_ns()-START)/1e9)

try:
 read(__file__)
 source_index=json.loads(read(PROJECT/"sources.json"))
 assert source_index["schema"]=="hia-unified-program-Graph-source-index-v1"
 for row in source_index["files"]:
  raw=read(PROJECT/row["path"])
  assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"])
  assert stat.S_IMODE((PROJECT/row["path"]).stat().st_mode)==int(row["mode"],8)&0o777
  if row["path"].endswith(".py"):ast.parse(raw,filename=row["path"])
 assets=json.loads(read(ASSET_PATH))
 assert assets["status"]=="READBACK_ONLY" and assets["target_executions"]==0
 assert assets["schema"]=="hia-unified-program-Graph-retained-assets-v1"
 assert assets["complete_inner_archive_and_members_read"] and assets["original_members"]==756
 assert assets["original_member_bytes"]==195136808
 assert assets["outer_ZIP_body_independently_read_by_prior_reader"]
 assert assets["late_Core_group6_in_same_original_root"]
 assert assets["source_bound_prior_reader_gitsha"]=="a58f3d2a06263fe5bc25d71047d20b8a0ac70ede"
 assert assets["actual_current_P16_head"]=="8f27671ad748dc7c081a1eaad897b057d8d9f42e"
 assert set(map(int,assets["roles"]))==LIVE and set(assets["original_actual_table_roles"])==LIVE_OLD
 assert assets["new_actual_table_roles"]==sorted(LIVE) and len(LIVE)==47
 raw=read(COMPILER);assert (len(raw),digest(raw))==(669556,NEW_COMPILER)
 sys.path[:0]=[str(PROJECT/"tools"),str(REF)]
 import tools
 overlay=PROJECT/"reference_helpers/tools";overlay.mkdir(parents=True,exist_ok=True)
 copy_source=PROJECT/"tools/hia_agent_edit_source_views.py"
 helper_raw=read(copy_source)
 assert (len(helper_raw),digest(helper_raw))==(23950,"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c")
 target=overlay/"hia_agent_edit_source_views.py";target.write_bytes(helper_raw);read(target)
 tools.__path__=[str(overlay),*list(tools.__path__)]
 assert digest(read(REF/"tools/hia_selfhost_child.py"))==CHILD_SHA
 assert digest(read(REF/"tools/qualify_hia_selfhost.py"))=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
 from hepta.hia_agent_assembly import render_assembly,assemble_program
 from hepta.hia_program import verify_program
 from hepta.hia_json_preflight_native import NativeHiaJsonImage
 from tools.qualify_hia_selfhost import compile_stage
 # Recreate the current root's exact authoring composition. The six actual
 # type-context peers themselves are retained from the fully checked artifact;
 # no pipeline recompile or historical case count is credited as new work.
 author=load("tools.cli_authoring",PROJECT/"tools/cli_authoring.py",
   "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b")
 generator_path=PROJECT/"tools/generate_hia_worker_program_service.py"
 generator=load("prefix_exact_worker_generator",generator_path,GENERATOR)
 catalog=load("prefix_current_fixed_catalog",PROJECT/"tools/generate_fixed_diagnostic_catalog_r1.py",
   "4c576e05b0c310d6f30858b5d983e4ba720503c91ae8750ff9591f9b6fbb74a0")
 diagnostic=load("prefix_current_fixed_diagnostics",PROJECT/"tools/extend_worker_program_diagnostics_r1.py",
   "39294aefd5501f513bc1676500fcf2fcb9c4cd374bf179944871bc85e182564c")
 for filename in [row[1] for row in catalog.TABLES]+[catalog.OUTER[0]]:
  read(PROJECT/"diagnostic_reference"/filename)
 save(OUT/"current-fixed-diagnostic-adaptation.json",
      diagnostic.attach(generator,catalog,PROJECT/"diagnostic_reference"))
 load("tools.extend_native_type_context_r1",PROJECT/"tools/extend_native_type_context_r1.py",
   "1d1903e98de38bbf8ea5be3303fdaa788a0eb8c9c03c53b4a57baf9f4502f30e")
 reader=load("prefix_current_type_reader",PROJECT/"tools/generate_type_context_reader_r1.py",
   "dbaed6abdce53a86b0af8e07e6c6e75fd1523846b82ceaa7771f4661fe50b0c2")
 load("tools.type_context_routes_common_r1",PROJECT/"tools/type_context_routes_common_r1.py",
   "51624c0f7dc00feac6781283adda9742f925ea13a2cdd6466174b451e5185dee")
 context=load("prefix_current_type_context",PROJECT/"tools/extend_worker_type_context_r1.py",
   "845c9f494f359d22b6afc6a2eb0c607b787015f602a5d917de0647f518c812fa")
 save(OUT/"current-type-context-adaptation.json",context.attach(generator,reader))
 late_path=PROJECT/"tools/extend_worker_late_core_r1.py"
 late_raw=read(late_path)
 late=load("prefix_current_late_Core",late_path,
   "2c7ae73cf067397e7245cd52713e4c13ede0a108376a1697d40b2c6f1e580906")
 save(OUT/"current-late-Core-adaptation.json",late.attach(generator,REF))
 prior_body,prior_live=generator.expanded("worker_program_service")
 prior_doc=generator.base.document(prior_body);prior_doc["module"]="worker_program_root"
 prior_source=render_assembly(prior_doc).encode("utf-8")
 prior=assets["roles"]["56"]
 assert (len(prior_source),digest(prior_source))==(293304,"42c09f173d185133de7c9a661c7798aa24c66a01583f0d36a777942ccdde0902")
 assert prior_source==read(prior["source_path"])
 assert (prior["image_bytes"],prior["image_sha256"])==(381135,"0f3745a833a17bae7c42c9017f6b8f944f7069200db876119ba434f93cc06d9d")
 prior_dir=OUT/"exact-current-root";prior_dir.mkdir()
 (prior_dir/"authoring.py").write_text(prior_body)
 (prior_dir/"source.hiaasm").write_bytes(prior_source);save(prior_dir/"document.json",prior_doc)
 save(prior_dir/"proof.json",dict(status="EXACT_CURRENT_HIA_REPRODUCED_NOT_RECOMPILED",
   actual_head=assets["actual_current_P16_head"],source_bytes=len(prior_source),
   source_sha256=digest(prior_source),retained_image_sha256=prior["image_sha256"],
   direct_reader_catalog_has_no_pipeline_mutable_state=True,reachable=prior_live))
 extension=load("prefix_unified_program_Graph",PROJECT/"tools/hia_unified_program_graph.py",OWNER)
 owner_raw=read(PROJECT/"tools/worker_program_service.py");assert digest(owner_raw)==SOURCE_OWNER
 body,proof=extension.extend(generator,owner_raw,read(generator_path),late_raw,read(prior["source_path"]))
 where=OUT/"compiled/root56";where.mkdir(parents=True)
 (where/"authoring.py").write_text(body)
 save(where/"extension-proof.json",proof)
 document=generator.base.document(body);document["module"]="unified_program_graph_root"
 save(where/"document.json",document)
 # Record all profile fields before enforcing the unchanged compiler profile.
 functions=document["functions"];blocks=[block for fn in functions for block in fn["blocks"]]
 names=[v["name"] for fn in functions for v in fn["params"]]
 names += [v["name"] for block in blocks for v in block["params"]]
 names += [v["name"] for block in blocks for op in block["ops"] for v in op.get("out",[])]
 import re
 nums=[int(m.group(1)) for n in names if (m:=re.search(r"(\d+)$",n))]
 observed=dict(functions=len(functions),blocks=len(blocks),operations=sum(len(b["ops"]) for b in blocks),
   max_function_blocks=max(len(f["blocks"]) for f in functions),
   max_block_parameters=max(len(b["params"]) for b in blocks),
   max_ssa_numeric_suffix=max(nums,default=0),max_block_operations=max(len(b["ops"]) for b in blocks))
 save(where/"profile-before-gates.json",observed)
 profile=generator.measured(document)
 assert all(observed[k]==v for k,v in profile.items())
 source=render_assembly(document).encode("utf-8")
 assert assemble_program(source).canonical_bytes==verify_program(document).canonical_bytes
 assert 0<len(source)<=1048576
 source_path=where/"source.hiaasm";source_path.write_bytes(source);read(source_path)
 ATTEMPTS.append(dict(label="backend-program-Graph-root56",source_bytes=len(source),source_sha256=digest(source),
   compiler_sha256=NEW_COMPILER,profile=observed))
 save(OUT/"compile-attempts.json",ATTEMPTS)
 image_path,receipt=compile_stage(where,"backend-program-Graph-root56",COMPILER,source)
 image=read(image_path)
 assert receipt["status"]=="returned" and receipt["abi_status"]==0
 assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
 assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
 assert receipt["input_bytes"]==len(source)
 assert receipt["artifact_sha256"]==receipt["image_sha256"]==NEW_COMPILER
 assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==receipt["core_u32"]==len(image)
 assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
 assert 0<len(image)<=1048576
 root=dict(role=56,source_path=str(source_path),source_bytes=len(source),source_sha256=digest(source),
   image_path=str(image_path),image_bytes=len(image),image_sha256=digest(image),compiler_sha256=NEW_COMPILER,
   profile=observed,receipt=receipt,origin="FRESH_35EE_B3_NEW_PROGRAM_GRAPH_ROOT")
 COMPILED.append(root);save(where/"manifest.json",root)
 print("HIA_BACKEND_PREFIX_ROOT_COMPILE "+json.dumps(root,sort_keys=True),flush=True)
 bindings={};images={i:b"" for i in range(1,64)}
 for key,row in assets["roles"].items():
  role=int(key)
  sr=read(row["source_path"]);im=read(row["image_path"])
  assert (len(sr),digest(sr))==(row["source_bytes"],row["source_sha256"])
  assert (len(im),digest(im))==(row["image_bytes"],row["image_sha256"])
  bindings[key]=dict(row);images[role]=im
 old_images={role:(images[role] if role in LIVE_OLD else b"") for role in range(1,64)}
 prefix=read(assets["prefix_path"]);layout=json.loads(read(assets["layout_path"]))
 tables=layout["tables"];original_elf=read(assets["original_executable"])
 assert expected_elf(prefix,tables,old_images)==original_elf
 compose=load("prefix_exact_p16_composer",PROJECT/"tools/compose_worker_program_executor.py",
   "0992b14a1c1bef977a4eefd777dd7e3bbb1104f56d2d318624ae1bfcc3b77e6c")
 original_asm=read(PROJECT/"tools/worker_program_executor_reference.S")
 composed,mechanical_proof=context.compose_executor(diagnostic,compose,original_asm)
 assert composed==read(assets["assembly_path"])
 save(OUT/"exact-current-mechanical-proof.json",mechanical_proof)
 assembly=read(assets["assembly_path"])
 # Keep the actual latest child reader50 scope and role51 RWW policy.
 # The new success path uses the original service58/decoder31/32/33 gates.
 mask=next(line for line in assembly.decode().splitlines() if line.startswith(".equ TWO_READ_MASK,"))
 expected_mask=0x60bf80bee2ac0462&~(1<<51)
 assert mask==".equ TWO_READ_MASK,"+hex(expected_mask)
 assert expected_mask&(1<<50) and not(expected_mask&(1<<51))
 for role in (31,32,33):
  expected_second_ro=bool((expected_mask>>role)&1)
  assert expected_second_ro==bool((0xe0bf80bee2ac0462>>role)&1)
 assert mechanical_proof["allowed_reader_calling_drivers"]==[41,43]
 assert mechanical_proof["allowed_child_kind"]==0
 assert mechanical_proof["original_program_kind1_reader50_refusal_preserved"]
 images[56]=image;bindings["56"]=root
 assert {role for role,value in images.items() if value}==LIVE
 assert all(images[i]==old_images[i] for i in LIVE_OLD-{56})
 packer_row=assets["retained_packer"]
 packer_source=read(packer_row["source_path"]);packer_image=read(packer_row["image_path"])
 assert (len(packer_source),digest(packer_source))==(packer_row["source_bytes"],packer_row["source_sha256"])
 assert (len(packer_image),digest(packer_image))==(packer_row["image_bytes"],packer_row["image_sha256"])
 packer=load("prefix_exact_p16_packer",PROJECT/"tools/generate_hia_worker_program_packer.py",
   "c9765cc9a1ca146184ada2e6cded5a99ecf2792c7d52a687f4c8c78cc9b4d3c4")
 packer_body=packer.source(prefix,tables)
 packer_doc=author.document(packer_body,"worker_program_packer")
 assert render_assembly(packer_doc).encode("utf-8")==packer_source
 parts=[images[i] for i in range(1,64)]
 packet=struct.pack("<8Q",int.from_bytes(b"HIAPPK01","little"),1,1,63,568+sum(map(len,parts)),568,64,0)
 packet+=struct.pack("<63Q",*map(len,parts))+b"".join(parts)
 expected=expected_elf(prefix,tables,images)
 native_packer=NativeHiaJsonImage(packer_image,expected_sha256=digest(packer_image))
 src=dst=work=None
 try:
  src=Guard(packet,readonly=True);dst=Guard(b"",len(expected),0x91);work=Guard(b"",64,0x37)
  before=dict(source=cas(packet),output=cas(dst.value()),workspace=cas(work.value()),hardware_source_readonly=True)
  save(OUT/"packer-pending.json",before)
  returned=int(native_packer._entry(src.ptr,src.size,dst.ptr,dst.size,work.ptr,work.size));PACKER_ENTRIES+=1
  for value in (src,dst,work):value.check()
  output=dst.value()
  save(OUT/"packer-result.json",dict(before=before,returned=returned,output=cas(output),
    workspace=cas(work.value()),source_after=cas(src.value()),expected=cas(expected),all_canaries_unchanged=True))
  assert returned==len(expected) and output==expected and src.value()==packet
  assert work.value()==bytes([0x37])*64
 finally:
  errors=[]
  for value in (src,dst,work):
   if value is not None:
    try:value.close()
    except BaseException as exc:errors.append(repr(exc))
  try:native_packer._mapping.close()
  except BaseException as exc:errors.append(repr(exc))
  if errors:
   primary=sys.exception()
   if primary is not None:
    for detail in errors:primary.add_note("native packer cleanup: "+detail)
   else:raise AssertionError(errors)
 elf=OUT/"hia-unified-program-Graph";elf.write_bytes(output);elf.chmod(0o700);read(elf)
 for mod in tuple(sys.modules.values()):
  filename=getattr(mod,"__file__",None)
  if filename:
   path=Path(filename).resolve()
   if path.suffix==".py" and (path.is_relative_to(REF) or path.is_relative_to(PROJECT)):read(path)
 for path,raw in {**generator.base.RAW,**generator.INPUTS}.items():assert read(path)==raw
 constants={k:v for k,v in generator.CONSTANTS.items()}
 constants.update(extension.CONSTANTS)
 save(OUT/"controller-constants.json",constants)
 save(OUT/"bundle.json",dict(schema="hia-unified-program-Graph-fixed-v1",status="BUILT_ONLY",
   executable_path=str(elf),executable_bytes=len(output),executable_sha256=digest(output),
   role_bindings=bindings,table_rows=63,nonzero_images=47,root_role=56,
   original_other_42_images_byte_identical=True,added_roles=[31,32,33,58],
   actual_new_B3_compilations=1,actual_native_packer_entries=1,new_compiler_sha256=NEW_COMPILER,
   retained_peer_compiler_sha256=OLD_COMPILER,retained_packer=packer_row,
   original_mechanical_source_path=assets["assembly_path"],original_mechanical_source_unchanged=True,
   constants_path=str(OUT/"controller-constants.json"),test_only_wire=assets["test_only_wire"],
   input_frame="HIAWPI01_original_modes1_2_3_4_tree_contract",success_frame="HIAWGE01_only_mode1_tree0",
   original_non_target_success_frame="HIAWPE01",error_frame="HIAWPE01",
   original_root_binding=prior,original_executable_path=assets["original_executable"],
   original_executable_identity=assets["original_executable_identity"],
   original_six_public_cases=assets["original_public_cases"],
   diagnostic_adaptation=str(OUT/"current-fixed-diagnostic-adaptation.json"),
   native_type_context_adaptation=str(OUT/"current-type-context-adaptation.json"),
   native_late_Core_adaptation=str(OUT/"current-late-Core-adaptation.json"),
   diagnostic_mask_proof=str(OUT/"exact-current-mechanical-proof.json"),
   actual_current_P16_head=assets["actual_current_P16_head"],
   current_root_HIA_reproduced_before_extension=True,
   current_late_Core_group6_routes_preserved=True,full_original_P16_modes_and_tree_preserved=True,
   Graph_only_on_mode1_tree0_success=True,original_other_modes_use_HIAWPE01=True,current_fixed_diagnostic_groups=[1,2,3,4,5],
   current_type_context_roles=[8,40,41,43,46,50,56],current_type_context_error_routes_preserved=True,
   current_reader50_child_kind0_drivers41_43_preserved=True,current_role51_RWW_preserved=True,
   current_diagnostic_catalog=assets["current_diagnostic_catalog"],
   current_type_context_inventory=assets["current_type_context_inventory"],
   original_group9_open=True,prior_group6_results_not_inherited=True,
   actual_P16_to_actual_integer_Core_Graph=True,private_immutable_capture_required=True,
   generic_plan_or_foreign_JSON_admitted=False,implementation_file_custody_joined=False,
   complete_public_backend=False,installed=False,cold=False))
 assert len(COMPILED)==1 and PACKER_ENTRIES==1
 STATUS="PASS_BUILD_ONLY"
except BaseException as exc:
 PRIMARY=exc;STATUS="FAIL"
 FAILURE=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
 _final_attempt("original_traceback",lambda:traceback.print_exc())
finally:
 observed_after=_final_attempt("source_after",before_after)
 AFTER=[] if observed_after is None else observed_after
 if observed_after is None or not all(row["same"] for row in AFTER):
  _final_failure("source_after_identity",AssertionError("source before/after identity mismatch"))
 frozen=[]
 for index,(path,(raw,mode)) in enumerate(PINS.items()):
  try:
   target=OUT/"frozen-inputs"/str(index)/path.name;target.parent.mkdir(parents=True,exist_ok=True)
   target.write_bytes(raw);target.chmod(mode)
   assert target.read_bytes()==raw and stat.S_IMODE(target.stat().st_mode)==mode
   frozen.append(dict(path=str(path),snapshot=str(target),bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=mode))
  except BaseException as exc:_final_failure("freeze_input:"+str(path),exc)
 _final_attempt("source_pins_receipt",lambda:save(OUT/"source-pins.json",frozen))
 _final_attempt("source_after_receipt",lambda:save(OUT/"source-after.json",AFTER))
 measured=_final_attempt("initial_final_budget_measure",_elapsed_budget)
 cpu,wall=(None,None) if measured is None else measured
 if measured is not None and (cpu>=90 or wall>=180):_final_failure("initial_final_budget",TimeoutError("program Graph prefix builder final resource gate"))
 report=dict(schema="hia-unified-program-Graph-build-v1",status=STATUS,failure=FAILURE,
   actual_new_B3_compilations=len(COMPILED),actual_compile_attempts=len(ATTEMPTS),
   actual_native_packer_entries=PACKER_ENTRIES,actual_semantic_ELF_processes=0,
   compiled=COMPILED,source_image_before_after_equal=observed_after is not None and all(r["same"] for r in AFTER),
   new_compiler_sha256=NEW_COMPILER,retained_compiler_sha256=OLD_COMPILER,
   actual_limits=dict(cpu=90,wall=180,address=1<<30,core=0),
   original_compile_limits=dict(cpu=10,wall=20,address=256<<20),
   parent_plus_children_CPU_seconds=cpu,elapsed_seconds=wall,
   old_results_counted_as_new=False,complete_public_backend=False,installed=False,cold=False)
 _finish_receipt(report,"PASS_BUILD_ONLY","HIA_BACKEND_PREFIX_BUILD_ORIGINAL")
