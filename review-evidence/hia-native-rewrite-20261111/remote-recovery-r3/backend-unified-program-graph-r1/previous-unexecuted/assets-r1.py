"""Bind the fully checked FOLLOW53 root and real Core decoder assets.

No target, compiler, VM, ELF or image is invoked. The preceding exact reader
must already have retained and verified the full original ZIP and all756
members. This adapter independently rechecks every retained member's complete
bytes/mode and binds the exact43 old roles plus four actual decoder/service
roles. A private JSON receipt is not external provenance authentication.
"""
from __future__ import annotations
import argparse,ctypes,json,os,resource,signal,stat,sys,time,traceback
from hashlib import sha1,sha256
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
MAP_GIT="35202c1c5961923b60f6100e07fa696e2c8f84a0"
PANELS_GIT="c579ec40c94aef1fa5488e7a3c83ed18db8bb66e"
READER_GIT="a58f3d2a06263fe5bc25d71047d20b8a0ac70ede"
OLD_COMPILER="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
HEAD="8f27671ad748dc7c081a1eaad897b057d8d9f42e"
OLD_PROJECT="/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-late-Core-native-r1/"
ROOT="worker-late-Core/"
BUILD=ROOT+"development/build-r1/"
OLD_ROLES=set(range(1,29))|set(range(40,47))|{50,51,55,56,59,61,62,63}
RETAINED_MAP_ROLES=(set(range(1,29))-{8})|{42,44,45,55}
NEW_DECODER_ROLES={31,32,33,58}
TEST_ONLY_WIRE_ROLES={29,30}
assert len(OLD_ROLES)==43 and len(RETAINED_MAP_ROLES)==31
p=argparse.ArgumentParser()
for name in ("readback","out","reader","role-map","observation"):
 p.add_argument("--"+name,type=Path,required=True)
a=p.parse_args()
OUT=a.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
READBACK=a.readback.resolve()
START=time.monotonic_ns()
START_SELF=resource.getrusage(resource.RUSAGE_SELF);START_CHILD=resource.getrusage(resource.RUSAGE_CHILDREN)
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
def timeout(signum,frame):raise TimeoutError("unified program asset binding 180 wall seconds")
signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
INPUTS={};COPIES={};STATUS="FAIL";FAILURE=None;ERRORS=[];ASSETS=None;MEMBERS=[]
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("w",encoding="utf-8",newline="\n") as f:
  json.dump(value,f,sort_keys=True,indent=2,ensure_ascii=True);f.write("\n")
def identity(path):
 path=Path(path);st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not path.is_symlink(),str(path)
 h=sha256();g=sha1(b"blob "+str(st.st_size).encode()+b"\0");n=0
 with path.open("rb") as src:
  while True:
   raw=src.read(1<<18)
   if not raw:break
   n+=len(raw);h.update(raw);g.update(raw)
 assert n==st.st_size
 return dict(bytes=n,sha256=h.hexdigest(),gitsha=g.hexdigest(),mode=stat.S_IMODE(st.st_mode))
def track(path):
 path=Path(path).resolve();info=identity(path)
 if path in INPUTS:assert INPUTS[path]==info,str(path)
 else:INPUTS[path]=info
 return info
def data(path,expected_git=None):
 before=track(path);raw=Path(path).read_bytes()
 assert len(raw)==before["bytes"] and sha256(raw).hexdigest()==before["sha256"]
 assert sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==before["gitsha"]
 if expected_git is not None:assert before["gitsha"]==expected_git
 return raw
def copy_original(path,target,expected_git=None):
 raw=data(path,expected_git);before=INPUTS[Path(path).resolve()]
 target.parent.mkdir(parents=True,exist_ok=True)
 with target.open("xb") as out:out.write(raw)
 target.chmod(before["mode"])
 assert target.read_bytes()==raw and identity(target)==before
 assert identity(path)==before
 COPIES[target.resolve()]=before
 return raw
def safe(name):
 assert type(name) is str and name and "\\" not in name and "\0" not in name
 p=PurePosixPath(name)
 assert not p.is_absolute() and all(part not in ("",".","..") for part in name.split("/"))
 assert p.as_posix()==name
 return name
def member(name):
 return READBACK/"members"/safe(name)
def pair(row,sp,ip,origin):
 source=track(sp);image=track(ip)
 assert (source["bytes"],source["sha256"])==(row["source_bytes"],row["source_sha256"])
 assert (image["bytes"],image["sha256"])==(row["image_bytes"],row["image_sha256"])
 receipt=row.get("receipt")
 if receipt is not None:
  assert receipt["status"]=="returned" and receipt["abi_status"]==0
  assert receipt["artifact_sha256"]==receipt["image_sha256"]==OLD_COMPILER
  assert receipt["source_sha256"]==receipt["input_sha256"]==source["sha256"]
  assert receipt["input_bytes"]==source["bytes"]
  assert receipt["produced_sha256"]==image["sha256"]
  assert receipt["produced_bytes"]==receipt["core_u32"]==image["bytes"]
  assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
  assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
  assert receipt["wall_elapsed_ns"]<20_000_000_000
 return dict(row,source_path=str(Path(sp).resolve()),image_path=str(Path(ip).resolve()),
  source_identity=source,image_identity=image,origin=origin)
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
 track(__file__)
 reader_raw=copy_original(a.reader,OUT/"originals/exact-reader.py",READER_GIT)
 summary_raw=copy_original(READBACK/"summary.json",OUT/"originals/readback-summary.json")
 post_budget_raw=copy_original(READBACK/"post-output-budget.json",OUT/"originals/readback-post-output-budget.json")
 proof_raw=copy_original(READBACK/"verified-original-build.json",OUT/"originals/verified-build.json")
 pins_raw=copy_original(READBACK/"verified-original-source-pins.json",OUT/"originals/verified-source-pins.json")
 members_raw=copy_original(READBACK/"inner-members-readback.json",OUT/"originals/inner-members-readback.json")
 cases_raw=copy_original(READBACK/"six-original-public-cases.json",OUT/"originals/six-public-cases.json")
 failures_raw=copy_original(READBACK/"original-two-fixture-failures.json",OUT/"originals/original-fixture-failures.json")
 after_raw=copy_original(READBACK/"input-and-materialized-aftercheck.json",OUT/"originals/reader-aftercheck.json")
 map_raw=copy_original(a.role_map,OUT/"originals/original-role-map.json",MAP_GIT)
 panels_raw=copy_original(a.observation,OUT/"originals/original-follow53-panels.jsonl",PANELS_GIT)
 summary=json.loads(summary_raw);proof=json.loads(proof_raw);pins=json.loads(pins_raw)
 assert summary["schema"]=="hia-follow53-late-Core-complete-original-readback-r1"
 assert summary["status"]=="PASS" and summary["original_target_status"]=="FAIL"
 assert (summary["source_head"],summary["run"],summary["job"],summary["artifact"])==(
  HEAD,43237029243,131248772749,13952974167)
 assert summary["complete_original_ZIP_retained_and_after_verified"] is True
 assert summary["all_756_original_members_retained_and_after_verified"] is True
 assert summary["original_inputs_and_self_unchanged"] and not summary["after_errors"]
 assert not summary["finalization_errors"] and summary["primary_failure"] is None
 assert summary["new_target_entries"]==summary["new_compiler_entries"]==summary["original_project_imports"]==0
 assert summary["facts"]["status"]=="PASS" and summary["facts"]["completed_original_public_cases"]==6
 assert summary["facts"]["all_43_source_image_bytes_bound"]
 assert summary["facts"]["complete_original_ELF_and_13_compiler_outputs_bound"]
 assert summary["inner"]["members"]==756 and summary["inner"]["original_bytes"]==195136808
 assert summary["original_runtime_budget"]==dict(cpu=90,wall=180,address=1<<30)
 post_budget=json.loads(post_budget_raw);assert post_budget["status"]=="PASS"
 for value in (summary["budget"],post_budget):
  assert 0<=value["aggregate_cpu_seconds"]<90 and 0<=value["elapsed_ns"]<180_000_000_000
 # The exact reader records its own after identity. Recheck it against the
 # pinned full source, not merely a self-asserted status in a foreign document.
 after=json.loads(after_raw)
 own=[r for r in after if r["kind"]=="input" and r["before"]["path"]==str(a.reader.resolve())]
 assert len(own)==1 and own[0]["status"]=="PASS" and own[0]["before"]==own[0]["after"]
 assert (own[0]["before"]["bytes"],own[0]["before"]["sha256"])==(
  len(reader_raw),sha256(reader_raw).hexdigest())
 rows=json.loads(members_raw);seen=set()
 assert len(rows)==756
 for row in rows:
  name=safe(row["name"]);assert name not in seen;seen.add(name)
  actual=track(member(name))
  assert (actual["bytes"],actual["sha256"],actual["mode"])==(row["bytes"],row["sha256"],row["mode"])
  MEMBERS.append(dict(name=name,**actual))
 assert sum(row["bytes"] for row in MEMBERS)==195136808
 original_map=json.loads(map_raw)
 assert set(original_map["components"])=={str(i) for i in range(1,64)}
 bundle_path=member(BUILD+"bundle.json");bundle=json.loads(data(bundle_path))
 old_report=json.loads(data(member(BUILD+"summary.json")))
 assert bundle["schema"]=="hia-worker-program-assembly-native-fixed-v1"
 assert bundle["status"]=="BUILT_ONLY" and bundle["compiler_sha256"]==OLD_COMPILER
 assert (bundle["fresh_compiles"],bundle["nonzero_images"],bundle["table_rows"])==(13,43,63)
 assert bundle["actual_native_packer_entries"]==1
 assert set(map(int,bundle["role_bindings"]))==OLD_ROLES
 assert set(bundle["unused_rows"])==set(range(1,64))-OLD_ROLES
 panels=[json.loads(line) for line in panels_raw.splitlines()]
 assert len(panels)==9
 observed=panels[0]["original_summary"]
 assert panels[0]["actual_successful_process"] and observed["status"]=="PASS"
 assert observed==old_report and observed["compiled"]==bundle["compiled"]
 assert sha256(data(bundle_path)).hexdigest()==proof["bundle_sha256"]
 assert observed["actual_compiles"]==observed["actual_compile_attempts"]==13
 assert observed["actual_packer_entries"]==1 and observed["actual_semantic_processes"]==0
 assert observed["source_and_image_before_after_equal"] is True
 assert proof["status"]=="PASS" and proof["original_build_pass"]
 assert proof["compiler_sha256"]==OLD_COMPILER and set(proof["role_bindings"])==set(bundle["role_bindings"])
 by_original={}
 for row in pins:
  assert row["original_path"] not in by_original
  raw=data(member(row["member"]))
  info=track(member(row["member"]))
  assert (len(raw),info["sha256"],info["gitsha"],info["mode"])==(
   row["bytes"],row["sha256"],row["gitsha"],row["mode"])
  by_original[row["original_path"]]=row
 def frozen(path,n,h):
  assert path in by_original,("source not bound by complete original pins",path)
  row=by_original[path]
  assert (row["bytes"],row["sha256"])==(n,h)
  return member(row["member"])
 roles={}
 for role in sorted(OLD_ROLES):
  row=bundle["role_bindings"][str(role)]
  sp=frozen(row["source_path"],row["source_bytes"],row["source_sha256"])
  ip=frozen(row["image_path"],row["image_bytes"],row["image_sha256"])
  roles[str(role)]=pair(row,sp,ip,"EXACT_ACTUAL_GROUP6_TYPE_P16_53_RETAINED_NO_INHERITED_QUALIFICATION")
  before=proof["role_bindings"][str(role)]
  assert (str(sp),str(ip))==(str(member(before["source"]["frozen_member"])),str(member(before["image"]["frozen_member"])))
  if role in RETAINED_MAP_ROLES:
   old=original_map["components"][str(role)]
   assert all(row[k]==old[k] for k in ("source_bytes","source_sha256","image_bytes","image_sha256"))
 for role in sorted(NEW_DECODER_ROLES):
  assert role not in OLD_ROLES
  row=original_map["components"][str(role)]
  assert row["compiler_sha256"]==OLD_COMPILER
  roles[str(role)]=pair(row,row["source_path"],row["image_path"],
   "ACTUAL_RETAINED_DECODER_SOURCE_IMAGE_NEW_COMBINATION_UNQUALIFIED")
 assert len(roles)==47 and set(map(int,roles))==OLD_ROLES|NEW_DECODER_ROLES
 assert (roles["56"]["source_bytes"],roles["56"]["source_sha256"])==(
  293304,"42c09f173d185133de7c9a661c7798aa24c66a01583f0d36a777942ccdde0902")
 assert (roles["56"]["image_bytes"],roles["56"]["image_sha256"])==(
  381135,"0f3745a833a17bae7c42c9017f6b8f944f7069200db876119ba434f93cc06d9d")
 test_wire={}
 for role in sorted(TEST_ONLY_WIRE_ROLES):
  row=original_map["components"][str(role)]
  test_wire[str(role)]=pair(row,row["source_path"],row["image_path"],
   "TEST_ONLY_ACTUAL_NATIVE_WIRE_NOT_A_PRODUCTION_ROLE")
 compiled=bundle["compiled"];assert len(compiled)==13
 for row in compiled:
  pair(row,frozen(row["source_path"],row["source_bytes"],row["source_sha256"]),
   frozen(row["image_path"],row["image_bytes"],row["image_sha256"]),"EXACT_ORIGINAL_COMPILER_OUTPUT")
 packers=[r for r in compiled if r["label"]=="worker-program-ELF-packer"];assert len(packers)==1
 row=packers[0]
 packer=pair(row,frozen(row["source_path"],row["source_bytes"],row["source_sha256"]),
  frozen(row["image_path"],row["image_bytes"],row["image_sha256"]),"ACTUAL_RETAINED_NATIVE_HIA_PACKER")
 carrier=member(BUILD+"carrier/prefix.bin").parent
 prefix=carrier/"prefix.bin";layout=carrier/"layout.json";assembly=carrier/"worker_program_executor.S"
 info=track(prefix);layout_value=json.loads(data(layout));track(assembly)
 assert layout_value["prefix_bytes"]==info["bytes"] and layout_value["prefix_sha256"]==info["sha256"]
 assert layout_value["rows"]==63 and set(layout_value["nonzero_roles"])==OLD_ROLES
 assert len(layout_value["tables"])==1
 original_elf=frozen(bundle["executable_path"],bundle["executable_bytes"],bundle["executable_sha256"])
 assert track(original_elf)["mode"]==0o700
 catalog=member(BUILD+"diagnostic-catalog.json");inventory=member(BUILD+"context-authoring/reader-inventory.json")
 track(catalog);track(inventory)
 ASSETS=dict(schema="hia-unified-program-Graph-retained-assets-v1",status="READBACK_ONLY",
  actual_original_archive=[28834052,"0ac66c2a6be8b599368294a017becc2b39fe4a9f0276e86a38bba0ed07666ea7"],
  actual_original_ledger=[292041,"24e653fd7dd2d8edf319d75abd7dce47a6f589deacf70ab0ea1394be9239f6e8"],
  original_members=756,original_member_bytes=195136808,roles=roles,test_only_wire=test_wire,
  retained_packer=packer,original_bundle=str(bundle_path),original_executable=str(original_elf),
  prefix_path=str(prefix),prefix_identity=info,layout_path=str(layout),assembly_path=str(assembly),
  original_actual_table_roles=sorted(OLD_ROLES),new_actual_table_roles=sorted(OLD_ROLES|NEW_DECODER_ROLES),
  root_to_replace=56,actual_current_P16_head=HEAD,
  actual_current_P16_build_json=panels[0]["label"],
  fixed_diagnostic_groups=[1,2,3,4,5],dynamic_type_context_roles=[8,40,41,43,46,50,56],
  late_Core_group6_in_same_original_root=True,
  current_diagnostic_catalog=str(catalog),current_type_context_inventory=str(inventory),
  complete_inner_archive_and_members_read=True,outer_ZIP_body_independently_read_by_prior_reader=True,
  source_bound_prior_reader_gitsha=READER_GIT,
  historical_six_cases_only_read_back_not_inherited=True,original_target_status="FAIL",
  target_executions=0,old_cases_rerun=0,new_combination_qualified=False)
 save(OUT/"assets.json",ASSETS);STATUS="PASS"
except BaseException as exc:
 FAILURE=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
 _final_failure("subject",exc)
 _final_attempt("original_traceback",lambda:traceback.print_exc())
finally:
 for path,before in {**INPUTS,**COPIES}.items():
  try:
   after=identity(path);assert after==before
  except BaseException as exc:
   ERRORS.append(dict(path=str(path),error_class=type(exc).__name__,error=str(exc)))
   _final_failure("source_after:"+str(path),exc)
 _final_attempt("before_identity_receipt",
  lambda:save(OUT/"before-identities.json",[{**r,"path":str(p)} for p,r in INPUTS.items()]))
 _final_attempt("member_identity_receipt",lambda:save(OUT/"complete-member-identities.json",MEMBERS))
 cpu,wall=(None,None)
 measured=_final_attempt("initial_final_budget_measure",_elapsed_budget)
 if measured is not None:
  cpu,wall=measured
  if cpu>=90 or wall>=180:_final_failure("initial_final_budget",TimeoutError("strict asset90CPU180wall"))
 report=dict(schema="hia-unified-program-Graph-asset-binding-v1",status=STATUS,failure=FAILURE,
  complete_inner_readback=STATUS=="PASS",partial=STATUS!="PASS",original_member_count=len(MEMBERS),
  original_member_bytes=sum(r["bytes"] for r in MEMBERS),after_check_errors=ERRORS,
  original_target_status="FAIL",original_completed_public_cases=6,
  old_case_results_inherited=False,source_bound_prior_reader_gitsha=READER_GIT,
  target_executions=0,compiler_executions=0,VM_entries=0,HIA_entries=0,
  actual_limits=dict(cpu=90,wall=180,address=1<<30,core=0),
  parent_plus_children_CPU_seconds=cpu,elapsed_seconds=wall,
  new_combination_qualified=False,whole_public_backend=False,installed=False)
 _finish_receipt(report,"PASS","HIA_UNIFIED_PREFIX_ASSET_ORIGINAL")
