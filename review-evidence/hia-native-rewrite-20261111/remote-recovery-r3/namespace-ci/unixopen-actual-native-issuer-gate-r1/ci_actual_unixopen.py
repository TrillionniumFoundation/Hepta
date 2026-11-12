"""First executable gate for the actual native UnixOpen issuance chain.

The parent, issuer, framer and shared FS are real freshly compiled HIA images.
This gate covers the raw getpid prefix and exact refusal/continuation boundaries.
Ten nonraw UnixOpen peers remain pending. It does not rerun original42, inherit
old component counts, or claim ordinary Store/SQL/migration completion.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,gzip,hashlib,importlib.util,json,os,resource,stat,time,traceback
from pathlib import Path

COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
COMMON_SHA="3f18cec28f522722ae11216a9a94c6752d67d29120da2be9525db40ef31f8ae0"
INPUT_GIT="fc4ff42997e672fd6df2675545c9e9bd998505c4"
INPUT_SHA="d51e50345b557b66def979cb93300162cc5b4afc315d4c55d6c5a6a769134d78"
COMPILER="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
COMPILER_BYTES=669556
REFERENCE="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
SEAL_GIT="084a98a1d42e3081612b817e909eb50443d8a924"
SEAL_SHA="e74aaa4648fc406628e3dc0530e20b28c2da65a8ff304e9fa90ec85568208724"
GROUPS={"raw-prefix":12,"parent-refusal":8,"transport":8}
SCOPE="ACTUAL_NATIVE_UNIXOPEN_ISSUER_RAW_PREFIX_AND_FULL_WINDOW_REPLAY"
CONSOLE_GZIP_BYTES=700000

def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 raw=(json.dumps(value,sort_keys=True,indent=2)+"\n").encode("utf-8")
 path.write_bytes(raw);assert path.read_bytes()==raw
def identity(path):
 path=Path(path).absolute();st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and not path.is_symlink(),str(path)
 raw=path.read_bytes()
 return dict(path=str(path),bytes=len(raw),sha256=sha(raw),gitsha=git(raw),
  mode=stat.S_IMODE(st.st_mode)),raw
def load(name,path,raw):
 spec=importlib.util.spec_from_file_location(name,path)
 module=importlib.util.module_from_spec(spec);sys.modules[name]=module
 exec(compile(raw,str(path),"exec"),module.__dict__)
 return module

class Evidence:
 def __init__(self):
  self.primary=None;self.errors=[];self.pins={};self.copies=[]
  self.exports=[];self.emitted=set();self.gzip_bytes=0
 def fail(self,label,error):
  item=dict(scope=label,error_class=type(error).__name__,error=str(error))
  self.errors.append(item)
  if self.primary is None:self.primary=error
  elif error is not self.primary:self.primary.add_note(label+": "+repr(error))
 def attempt(self,label,operation):
  try:return operation()
  except BaseException as error:self.fail(label,error);return None
 def pin(self,path,expected=None):
  row,raw=identity(path)
  if expected is not None:
   assert (row["bytes"],row["sha256"],row["gitsha"],row["mode"])==(
    expected["bytes"],expected["sha256"],expected["blob"],int(expected["mode"][-3:],8)),str(path)
  old=self.pins.get(row["path"])
  assert old is None or old==row
  self.pins[row["path"]]=row
  return raw
 def copied(self,path,raw,mode):
  path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
  assert not path.exists() and not path.is_symlink()
  with path.open("xb") as stream:stream.write(raw)
  path.chmod(mode)
  observed,actual=identity(path);assert actual==raw and observed["mode"]==mode
  self.pins[observed["path"]]=observed;self.copies.append(observed)
  return path
 def original(self,path):
  row,raw=identity(path)
  key=(row["path"],row["sha256"])
  if key in self.emitted:return raw
  self.emitted.add(key);self.exports.append(row)
  # Complete original bytes precede any optional JSON interpretation.
  # Console omission is explicit; the unmodified original remains in the seal.
  compressed=gzip.compress(raw,compresslevel=1,mtime=0)
  if self.gzip_bytes+len(compressed)<=CONSOLE_GZIP_BYTES:
   encoded=base64.b64encode(compressed).decode("ascii")
   print("HIA_ACTUAL_UI_ORIGINAL_BEGIN "+json.dumps(dict(
    **row,encoding="gzip-base64",gzip_bytes=len(compressed),
    gzip_sha256=sha(compressed),chunks=(len(encoded)+4095)//4096),sort_keys=True),flush=True)
   for index in range(0,len(encoded),4096):
    print("HIA_ACTUAL_UI_ORIGINAL_CHUNK "+str(index//4096)+" "+encoded[index:index+4096],flush=True)
   print("HIA_ACTUAL_UI_ORIGINAL_END "+row["sha256"],flush=True)
   self.gzip_bytes+=len(compressed)
  else:
   print("HIA_ACTUAL_UI_ORIGINAL_RETAINED_NO_CONSOLE_BODY "+json.dumps(row,sort_keys=True),flush=True)
  return raw
 def after(self):
  observed={}
  for path,before in self.pins.items():
   try:
    row,_=identity(path);observed[path]=row
    assert row==before,(path,"source or frozen evidence changed")
   except BaseException as error:
    observed[path]=dict(error_class=type(error).__name__,error=str(error))
    self.fail("independent-after:"+path,error)
  return observed

def main():
 assert sys.version_info[:3]==(3,12,14)
 ev=Evidence();context=None;working=None;evidence=None;common=None;seal=None
 phase_start=None;details=dict(schema="hia.namespace.actual-unixopen-native-issuer.ci.v1",
  status="INCOMPLETE",scope=SCOPE,actual_counts="UNKNOWN_UNTIL_COMPLETED_REPORTS",
  planned_groups=GROUPS,planned_cases=28,new_packer_controls=45,
  inherited_test_counts=False,original42_reexecuted=False,
  fixed_native_issuer_implemented_in_new_source=True,actual_native_raw_prefix_subject_pass=False,
  nonraw_peers_completed=False,unresolved_nonraw_UnixOpen_peers=10,
  ordinary_unixOpen_closed=False,ordinary_Store_SQL31_closed=False,
  raw_syscall_semantic_coverage=["getpid"],other_raw_effects_not_claimed_by_this_gate=True,
  namespace_source_branch="FS9/DMS10; independent from original42 DMS9",
  original_parent_BEGIN_is_private_predecessor=True,
  no_host_Provider_ACK_or_completion_capsule_route=True,
  subject_wall_seconds=900,
  runtime_process_tree_limits=dict(CPU_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0),
  B3_limits=dict(CPU_seconds=10,wall_seconds=20,address_bytes=256<<20,output_bytes=1<<20,workspace_bytes=1<<20),
  VM_limits=dict(steps=4000000,arena_bytes=32<<20,depth=64),
  process_receipts=[],original_report_pins=[])
 common_path=Path(os.environ["HIA_CI_COMMON"]).resolve(strict=True)
 common_raw=ev.pin(common_path)
 assert sha(common_raw)==COMMON_SHA and git(common_raw)==COMMON_GIT
 common=load("actual_unixopen_common",common_path,common_raw)
 # Never modify an existing run's output, even when recovery preparation fails.
 assert not common.OUTPUT.exists()
 here=Path(__file__).resolve().parent
 own=ev.pin(__file__)
 index_path=here/"inputs.json";index_raw=ev.pin(index_path)
 assert sha(index_raw)==INPUT_SHA and git(index_raw)==INPUT_GIT
 manifest=json.loads(index_raw)
 assert manifest["schema"]=="hia.namespace.actual-unixopen-native-issuer.inputs.v1"
 assert len(manifest["inputs"])==28 and manifest["groups"]==GROUPS
 assert manifest["planned_fresh_process_cases"]==28 and manifest["new_packer_native_controls"]==45
 assert manifest["reference_commit"]==REFERENCE
 assert manifest["compiler_sha256"]==COMPILER and manifest["compiler_bytes"]==COMPILER_BYTES
 assert manifest["fixed_roles"]==list(range(1,10))
 assert manifest["fresh_role_B3"]==9 and manifest["fresh_packer_B3"]==1
 assert manifest["pure_DMS10_source_proof_controls"]==10
 assert manifest["original42_rerun"] is False and manifest["old_case_counts_inherited"] is False
 assert manifest["budgets"]["subject_wall_seconds"]==900
 assert manifest["budgets"]["VM"]==dict(steps=4000000,arena_bytes=32<<20,depth=64)
 sources={}
 for row in manifest["inputs"]:
  assert Path(row["path"]).name==row["path"] and row["path"] not in sources
  path=here/row["path"];raw=ev.pin(path,row);sources[row["path"]]=(row,raw)
  common.PINS[path]=raw
 common.PINS[Path(__file__).resolve()]=own
 common.PINS[index_path]=index_raw
 common.PINS[common_path]=common_raw
 seal_path=here/"stream_seal_bounded.py"
 seal_raw=sources[seal_path.name][1]
 assert sha(seal_raw)==SEAL_SHA and git(seal_raw)==SEAL_GIT
 seal=load("actual_unixopen_bounded_seal",seal_path,seal_raw)
 try:
  context=common.prepare()
  compiler_pin,compiler_raw=identity(context["compiler"])
  assert (compiler_pin["bytes"],compiler_pin["sha256"])==(COMPILER_BYTES,COMPILER)
  ev.pins[compiler_pin["path"]]=compiler_pin
  prlimit=Path("/usr/bin/prlimit")
  prlimit_raw=ev.pin(prlimit)
  assert prlimit.stat().st_mode&0o111 and prlimit_raw[:4]==b"\x7fELF"
  working=Path(context["base"])/"namespace-actual-unixopen-r1-source";working.mkdir()
  (working/"inputs").mkdir();(working/"tools").mkdir()
  paths={}
  for name,(row,raw) in sources.items():
   target=ev.copied(working/"inputs"/name,raw,int(row["mode"][-3:],8))
   paths[name]=str(target)
   if row["working_alias"] is not None:
    alias=Path(row["working_alias"])
    assert not alias.is_absolute() and ".." not in alias.parts
    assert len(alias.parts)==2 and alias.parts[0]=="tools" and alias.suffix==".py"
    ev.copied(working/alias,raw,int(row["mode"][-3:],8))
  evidence=Path(context["output"])/"namespace-actual-unixopen-r1";evidence.mkdir()
  (evidence/"compiler").mkdir()
  compiler_copy=ev.copied(evidence/"compiler/B3.image.bin",compiler_raw,compiler_pin["mode"])
  context=dict(context,namespace_working=str(working),namespace_evidence=str(evidence),
   namespace_input_paths=paths,namespace_predecessor=None)
  context_path=evidence/"context.json";save(context_path,context);ev.pin(context_path)
  save(evidence/"source-before.json",ev.pins)
  env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
  phase_start=time.monotonic_ns()
  details["subject_phase"]=dict(started_monotonic_ns=phase_start,limit_ns=900_000_000_000,
   end_boundary="after every group, original report export and complete subject source-after checks; before independent seal")
  save(evidence/"subject-phase.json",details["subject_phase"])
  def remaining():
   value=900-(time.monotonic_ns()-phase_start)/1_000_000_000
   if value<=0:raise TimeoutError("actual UnixOpen original900 aggregate")
   return value
  def run(label,argv,relative=None,*,cpu=90,wall=180,address=1<<30):
   failure=None;receipt=None
   command=[str(prlimit),"--cpu="+str(cpu)+":"+str(cpu),
    "--as="+str(address)+":"+str(address),"--core=0:0","--",*map(str,argv)]
   try:
    receipt=common.run(label,command,cwd=context["reference"],
     timeout=min(wall,remaining()),env=env)
    details["process_receipts"].append(dict(label=label,receipt=receipt,
     enforced_parent_kernel_limit=dict(CPU_seconds=cpu,address_bytes=address,core_bytes=0)))
    used=receipt["child_cpu_seconds"];elapsed=receipt["elapsed_ns"]
    assert type(used) in (int,float) and 0<=used<cpu,(label,"complete process tree CPU",used,cpu)
    assert type(elapsed) is int and 0<=elapsed<wall*1_000_000_000,(label,"complete process wall",elapsed,wall)
   except BaseException as error:failure=error
   finally:
    output_paths=[common.OUTPUT/"steps"/label/name for name in ("process.json","stdout.log","stderr.log")]
    if relative is not None:output_paths.append(evidence/relative)
    for path in output_paths:
     if path.is_file():
      try:ev.original(path)
      except BaseException as error:
       if failure is None:failure=error
       else:failure.add_note("raw original export "+str(path)+": "+repr(error))
   if failure is not None:raise failure
   return receipt
  def report(relative,status):
   path=evidence/relative;raw=ev.original(path)
   row,_=identity(path);details["original_report_pins"].append(row)
   value=json.loads(raw)
   assert value["status"]==status,(relative,value)
   return value
  run("actual-ui-original-ten-DMS10-source-proofs",
   [context["python"],"-B",paths["validate-dms10-header-proof.py"],
    "--directory",working/"inputs","--output",evidence/"dms10-source-proof"],
   "dms10-source-proof/summary.json",cpu=10,wall=30,address=256<<20)
  proof=report("dms10-source-proof/summary.json","PASS_SOURCE_PROOF_ONLY")
  assert len(proof["controls"])==10 and proof["source_unchanged"]
  for flag in ("one_literal_delta_reversed_byte_identically","origin_bindings_equal",
    "original_builder_class_byte_identical","original_origin_propagation_byte_identical"):
   assert proof[flag] is True
  assert proof["new_HIA_generation"]==proof["new_B3_compiles"]==proof["new_VM_entries"]==proof["new_native_entries"]==0
  assert proof["actual_limits"]==dict(cpu=[10,10],address=[256<<20,256<<20],core=[0,0])
  composed=evidence/"composed-executor.S";composition_report=evidence/"composition.json"
  run("actual-ui-exact-fixed-source-composition",
   [context["python"],"-B",paths["compose_executor.py"],
    "--base",paths["namespace-fixed-fs9.S"],"--capsule",paths["capsules.S"],
    "--dispatch",paths["dispatcher.S"],"--output",composed,"--manifest",composition_report],
   "composition.json")
  composition=json.loads(ev.original(composition_report))
  assert composition["exact_old_source_inverse"] is True and composition["unique_edits"]==5
  assert composition["new_context_metadata_disjoint"] is True
  assert composition["fixed_runtime_roles"]==list(range(1,10))
  assert composed.read_bytes()==sources["native_unixopen_issued_executor.S"][1]
  ev.pin(composed)
  run("actual-ui-nine-fresh-roles-and-native-packer",
   [context["python"],"-B",paths["build_actual_unixopen.py"],"--context",context_path,
    "--executor",composed,"--packer",paths["generate_native_packer.py"]],
   "actual-unixopen-build-r1/summary.json")
  built=report("actual-unixopen-build-r1/summary.json","PASS_BUILD_ONLY")
  assert built["fresh_role_compiles"]==9 and built["packer_entries"]==45
  assert built["actual_carrier_processes"]==0 and built["source_pins_unchanged"] is True
  assert built["actual_process_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
  assert set(built["exact_roles"])==set(map(str,range(1,10)))
  assert built["executable"]["layout"]["relocation_count"]==0
  def compile_receipt(receipt,source,image):
   assert receipt["status"]=="returned" and receipt["abi_status"]==0
   assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER
   assert receipt["source_sha256"]==receipt["input_sha256"]==source["sha256"]
   assert receipt["input_bytes"]==source["bytes"]
   assert receipt["produced_sha256"]==image["sha256"] and receipt["produced_bytes"]==image["bytes"]
   assert receipt["core_u32"]==receipt["result_u64"]==image["bytes"]
   assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
   assert receipt["source_unchanged"] is True and not receipt["forbidden_compiler_modules_loaded"]
  for number,row in built["exact_roles"].items():
   for field in ("source","image"):
    observed,raw=identity(row[field]["path"])
    assert (observed["bytes"],observed["sha256"])==(row[field]["bytes"],row[field]["sha256"])
    ev.pins[observed["path"]]=observed
   compile_receipt(row["compile_receipt"],row["source"],row["image"])
   profile=row["profile"]
   assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
   assert profile["max_blocks"]<=256 and profile["max_block_params"]<=16
   assert profile["max_ssa_numeric_suffix"]<2048
  packer_source=evidence/"actual-unixopen-build-r1/packer.hiaasm"
  packer_source_pin,_=identity(packer_source)
  packer_receipt=built["compile_receipt"]
  assert packer_receipt["source_sha256"]==packer_receipt["input_sha256"]==packer_source_pin["sha256"]
  assert packer_receipt["input_bytes"]==packer_source_pin["bytes"]
  assert packer_receipt["produced_sha256"]==built["packer_image_sha256"]
  assert packer_receipt["status"]=="returned" and packer_receipt["abi_status"]==0
  assert packer_receipt["artifact_sha256"]==packer_receipt["image_sha256"]==COMPILER
  assert packer_receipt["limits"]["cpu_seconds"]==10 and packer_receipt["limits"]["address_bytes"]==256<<20
  assert packer_receipt["source_unchanged"] and not packer_receipt["forbidden_compiler_modules_loaded"]
  ev.pins[packer_source_pin["path"]]=packer_source_pin
  packer_images=sorted((evidence/"actual-unixopen-build-r1/compile/namespace-unixopen-issued-packer").glob("*.image.bin"))
  assert len(packer_images)==1
  packer_image_pin,_=identity(packer_images[0])
  assert (packer_image_pin["bytes"],packer_image_pin["sha256"])==(packer_receipt["produced_bytes"],packer_receipt["produced_sha256"])
  ev.pins[packer_image_pin["path"]]=packer_image_pin
  pp=built["profile"]
  assert pp["functions"]<=128 and pp["blocks"]<=1536 and pp["ops"]<=8192
  assert pp["max_blocks"]<=256 and pp["max_block_params"]<=16 and pp["max_ssa_numeric_suffix"]<2048
  executable_pin,executable_raw=identity(built["executable"]["path"])
  assert (executable_pin["bytes"],executable_pin["sha256"])==(built["executable"]["bytes"],built["executable"]["sha256"])
  assert executable_pin["mode"]==0o755 and executable_raw[:4]==b"\x7fELF"
  ev.pins[executable_pin["path"]]=executable_pin
  # Every complete original generated source/image/document/receipt remains in
  # the evidence tree. Neither a frozen image nor an old case outcome is reused.
  completed=[]
  for group,count in GROUPS.items():
   relative="actual-unixopen-"+group+"-r1/summary.json"
   run("actual-ui-native-"+group,[context["python"],"-B",paths["test-actual-unixopen.py"],
    "--context",context_path,"--group",group],relative)
   value=report(relative,"PASS")
   assert value["group"]==group
   assert value["planned_cases"]==value["completed_cases"]==value["actual_ELF_processes"]==value["process_launch_attempts"]==count
   assert value["actual_process_count_complete"] and value["actual_entry_counts_complete"]
   assert len(value["case_results"])==count
   assert value["actual_native_entries"]==value["full_VM_entries"]>0
   assert value["source_inputs_unchanged"] is True
   assert value["limits"]==dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0)
   assert value["VM_limits"]==dict(steps=4000000,arena_bytes=32<<20,depth=64)
   for flag in ("ordinary_unixOpen_closed","ordinary_Store_closed","non_raw_peer_callbacks_used",
    "host_completion_capsules_supplied","original42_rerun","prior_results_inherited"):
    assert value[flag] is False
   for case in value["case_results"]:
    assert case["status"]=="PASS"
    replay=case["replay"];proc=case["actual_process"]
    assert replay["native_entries"]==replay["VM_entries"]>0
    assert replay["all_native_return_output_workspace_bytes_equal"] and replay["no_field_mask"]
    assert replay["no_cached_VM_results"] and replay["no_native_or_syscall_execution_in_replayer"]
    assert replay["private_issued_capsules_bound_to_actual_begin_and_completed_windows"]
    assert proc["returncode"]==case["expected_exit"] and proc["source_unchanged"]
    assert not proc["wall_watchdog_fired"] and not proc["wall_kill_sent"]
    assert 0<=proc["usage"]["user"]+proc["usage"]["system"]<90
    assert 0<=proc["elapsed_ns"]<180_000_000_000
   completed.append(value)
  cases=[item for group in completed for item in group["case_results"]]
  assert len(cases)==28 and len({case["label"] for case in cases})==28
  assert sum(group["actual_ELF_processes"] for group in completed)==28
  assert sum(group["actual_parent_raw_ACKs"] for group in completed)==14
  assert sum(group["actual_getpid_syscalls"] for group in completed)==15
  # 12 prefix cases produce 13 ACKs (one PID-reset pair); the explicit
  # no-reentry control first produces one real prefix. One direct prior FS
  # getpid in the shared-session case adds the fifteenth actual syscall.
  counts=dict(pure_DMS10_source_proof_controls=10,fresh_role_B3=9,fresh_packer_B3=1,
   new_nine_image_native_packer_controls=45,completed_cases=28,actual_fixed_processes=28,
   actual_native_entries=sum(row["actual_native_entries"] for row in completed),
   full_VM_entries=sum(row["full_VM_entries"] for row in completed),
   actual_native_parent_ACKs=sum(row["actual_parent_raw_ACKs"] for row in completed),
   actual_getpid_syscalls=sum(row["actual_getpid_syscalls"] for row in completed),
   actual_getpid_counter_scope="Role1 primitive trace only; bootstrap/fixture OS getpid calls are not semantic peer entries.",
   inherited_counts=False,old_original42_reexecuted=False)
  assert counts["actual_native_entries"]==counts["full_VM_entries"]
  details.update(status="PASS_RAW_PREFIX_COMPONENT_ONLY",actual_counts=counts,
   actual_native_raw_prefix_subject_pass=True,complete_nine_role_source_and_image_pins=True,
   all_native_windows_return_output_workspace_equal=True,
   actual_private_capsules_bound_to_real_call_source_and_completed_image=True)
 except BaseException as error:
  ev.fail("subject-primary",error)
  details.update(status="FAIL",error_class=type(error).__name__,error=str(error),
   traceback=traceback.format_exc())
  ev.attempt("print-primary",lambda:traceback.print_exception(error))
 finally:
  # Do not let a malformed partial summary replace the original target error.
  # Export complete bytes first, then attempt optional field interpretation.
  if evidence is not None:
   for path in sorted(evidence.rglob("summary.json")):
    if path==evidence/"summary.json":continue
    ev.attempt("partial-original:"+str(path),lambda path=path:ev.original(path))
  details["source_after"]=ev.after()
  details["source_before"]=ev.pins
  details["all_pinned_inputs_copies_and_generated_outputs_unchanged"]=not any(
   row["scope"].startswith("independent-after:") for row in ev.errors)
  details["original_exports"]=ev.exports
  details["errors"]=ev.errors
  if ev.primary is not None:
   details["status"]="FAIL";details["actual_native_raw_prefix_subject_pass"]=False
  if evidence is not None:
   ev.attempt("source-after-receipt",lambda:save(evidence/"source-after.json",details["source_after"]))
   ev.attempt("subject-summary",lambda:save(evidence/"summary.json",details))
   if phase_start is not None:
    end=time.monotonic_ns();elapsed=end-phase_start
    phase=details["subject_phase"]
    phase.update(ended_monotonic_ns=end,elapsed_ns=elapsed,
     source_after_checks_attempted_for_all_pins=True,
     final_subject_summary_write_readback_pass=not any(row["scope"]=="subject-summary" for row in ev.errors),
     within_original900=0<=elapsed<900_000_000_000)
    if not phase["within_original900"]:
     ev.fail("strict-final-subject900",TimeoutError("complete actual UnixOpen subject exceeded original900"))
    ev.attempt("subject-phase-receipt",lambda:save(evidence/"subject-phase.json",phase))
    # Measure again after writing/reading the phase receipt itself.
    if time.monotonic_ns()-phase_start>=900_000_000_000:
     ev.fail("subject900-after-phase-receipt",TimeoutError("actual UnixOpen final phase receipt exceeded original900"))
   if ev.primary is not None:
    details["status"]="FAIL";details["actual_native_raw_prefix_subject_pass"]=False
    ev.attempt("rewrite-FAIL-subject",lambda:save(evidence/"summary.json",details))
  status="PASS" if ev.primary is None and details["status"]=="PASS_RAW_PREFIX_COMPONENT_ONLY" else "FAIL"
  if common.OUTPUT.exists():
   # The independent seal has zero target entries and its own fresh
   # 90CPU/180wall/1GiB child. Include complete source/reference after checks.
   seal_started=time.monotonic_ns()
   before_self=time.process_time();before_child=resource.getrusage(resource.RUSAGE_CHILDREN)
   if common.PREPARED:
    ev.attempt("independent-full-byte-seal",lambda:seal.finish(common,SCOPE,status,details,
     roots={"namespace-actual-unixopen-source":str(working)} if working is not None else {}))
   else:
    # A failed preparation has original raw logs, but no complete source
    # inventory qualification. Keep those bytes in the always-uploaded output.
    details["complete_seal_not_attempted"]="PREPARATION_INCOMPLETE; all existing raw output is retained"
    ev.attempt("incomplete-preparation-raw-summary",lambda:save(common.OUTPUT/"summary.json",
     dict(status="FAIL",scope=SCOPE,details=details,prepared=False,
      complete_source_inventory_verified=False,complete_member_seal=False)))
   final=dict(schema="hia-actual-unixopen-final-v1",status=status if ev.primary is None else "FAIL",
    subject_status=details["status"],actual_counts=details["actual_counts"],
    subject_phase=details.get("subject_phase"),errors=ev.errors,
    ordinary_Store_SQL31_closed=False,original42_reexecuted=False,
    original_subject_budget_unchanged=True,independent_seal_target_entries=0)
   final_path=common.OUTPUT/"actual-unixopen-final.json"
   ev.attempt("write-final-caller-receipt",lambda:save(final_path,final))
   ev.attempt("print-final-caller-receipt",lambda:print("HIA_ACTUAL_UNIXOPEN_FINAL "+json.dumps(final,sort_keys=True),flush=True))
   after_child=resource.getrusage(resource.RUSAGE_CHILDREN)
   seal_cpu=time.process_time()-before_self+after_child.ru_utime+after_child.ru_stime-before_child.ru_utime-before_child.ru_stime
   seal_elapsed=time.monotonic_ns()-seal_started
   if not (0<=seal_cpu<90 and 0<=seal_elapsed<180_000_000_000):
    ev.fail("strict-whole-seal-post-caller-output",AssertionError(
     ("independent seal aggregate90CPU180wall",seal_cpu,seal_elapsed)))
   if ev.primary is not None:
    final.update(status="FAIL",errors=ev.errors,seal_post_caller_CPU_seconds=seal_cpu,
     seal_post_caller_elapsed_ns=seal_elapsed)
    ev.attempt("rewrite-FAIL-final",lambda:save(final_path,final))
 if ev.primary is not None:raise ev.primary
 assert details["status"]=="PASS_RAW_PREFIX_COMPONENT_ONLY"
 return 0

if __name__=="__main__":raise SystemExit(main())
