"""One complete type/late-Core/P16 role56 with actual Core Graph: new qualification.

This driver never credits previous public or private results to the new table.
The original43 table is fully read back, rebuilt byte-exactly and used for three
separately bounded non-Graph-mode controls. All new26 groups execute one47 table.
"""
from pathlib import Path
from hashlib import sha1,sha256
import ast,base64,json,os,re,stat,sys,traceback,types
sys.dont_write_bytecode=True
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
SEAL_GIT="084a98a1d42e3081612b817e909eb50443d8a924"
INDEX_GIT="d634984f9109877bcf7d756ab420a30527b1bbac"
INDEX_SHA="c3ee635e5c46258bd528f1c205e66f1750e00744d77ba7fae247682f39c57259"
INDEX_BYTES=24829
NEW_COMPILER="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
OLD_COMPILER="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
PREDECESSOR_HEAD="8f27671ad748dc7c081a1eaad897b057d8d9f42e"
TRANSPORT_SHA="d01d7ad501180abc9311075f6e1868567cde852dd629de124d5fbf1c23a82960"
SCHEDULE=[["semantic",0,26],["private",0,60],["fixed-errors",0,34],["type-context",0,4],["type-names",0,24],["type-shapes",0,9],["type-order",0,17],["helper-budget",0,1],["late-inventory",0,1],["raw-boundary",0,1],["raw-boundary",1,1],["functions",0,1],["functions",1,1],["functions",2,1],["functions",3,1],["compat-semantic",0,23],["compat-assembly",0,22],["compat-object",0,6],["late-node-below",0,1],["late-node-equal",0,1],["late-node-over",0,1],["late-byte-below",0,1],["late-byte-equal",0,1],["late-byte-over",0,1],["late-depth-and-order",0,6],["late-private-protocol",0,38]]
CONTROL_GROUPS={"compat-semantic":23,"compat-assembly":22,"compat-object":6}
EXPECTED_LIMITS=dict(cpu=90,wall=180,address=1<<30,core=0)
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def regular(path):
 path=Path(path);info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not path.is_symlink(),str(path)
 return info
def raw_file(path):
 info=regular(path);raw=Path(path).read_bytes()
 assert len(raw)==info.st_size
 return raw
def load(name,path,expected):
 raw=raw_file(path);assert gitsha(raw)==expected,(str(path),gitsha(raw),expected)
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
 exec(compile(raw,str(path),"exec"),module.__dict__)
 return module,raw
def file_identity(path):
 info=regular(path);h=sha256();n=0
 with Path(path).open("rb") as stream:
  while True:
   part=stream.read(1<<18)
   if not part:break
   h.update(part);n+=len(part)
 assert n==info.st_size
 return dict(bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(info.st_mode))
def original_bytes(raw,path,label):
 for at in range(0,max(1,len(raw)),18000):
  part=raw[at:at+18000]
  print(label+" "+json.dumps(dict(path=str(path),bytes=len(raw),sha256=digest(raw),
    offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode("ascii")),sort_keys=True),flush=True)
def original(path,label):original_bytes(raw_file(path),path,label)
def original_summary(path,label):
 if not path.is_file():return None
 raw=raw_file(path)
 # Preserve every original byte even if JSON decoding then fails.
 original_bytes(raw,path,label+"_BYTES")
 value=json.loads(raw)
 print(label+" "+raw.decode("utf-8").strip(),flush=True)
 return value
class Evidence:
 def __init__(self):self.primary=None;self.errors=[]
 def record(self,phase,exc):
  self.errors.append(dict(phase=phase,error_class=type(exc).__name__,error=str(exc)))
  if self.primary is None:self.primary=exc
  elif self.primary is not exc:self.primary.add_note(phase+": "+repr(exc))
 def attempt(self,phase,operation):
  try:return operation()
  except BaseException as exc:self.record(phase,exc);return None
 def raise_if_failed(self):
  if self.primary is not None:raise self.primary
def closure(root,rows):
 for row in rows:
  path=root/row["path"];raw=raw_file(path)
  assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"]),row["path"]
  assert stat.S_IMODE(path.stat().st_mode)==int(row["mode"],8)&0o777
 return dict(files=len(rows),all_bytes_modes_SHA_Git_equal=True)
def receipt_gate(row):
 receipt=row["receipt"]
 assert receipt["status"]=="returned" and receipt["abi_status"]==0
 assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
 assert receipt["wall_elapsed_ns"]<=20_000_000_000
 assert receipt["limits"]["output_capacity"]==receipt["limits"]["workspace_bytes"]==1048576
 assert receipt["runner_sha256"]=="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
 assert receipt["source_sha256"]==receipt["input_sha256"]==row["source_sha256"]
 assert receipt["input_bytes"]==row["source_bytes"]
 assert receipt["artifact_sha256"]==receipt["image_sha256"]==NEW_COMPILER
 assert receipt["produced_sha256"]==row["image_sha256"]
 assert receipt["produced_bytes"]==receipt["core_u32"]==row["image_bytes"]
 assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
 for name in ("source","image"):
  info=file_identity(row[name+"_path"])
  assert (info["bytes"],info["sha256"])==(row[name+"_bytes"],row[name+"_sha256"])
 profile=row["profile"]
 assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["operations"]<=8192
 assert profile["max_function_blocks"]<=256 and profile["max_block_parameters"]<=16
 assert profile["max_ssa_numeric_suffix"]<2048
 document=json.loads(raw_file(Path(row["source_path"]).with_name("document.json")))
 functions=document["functions"];blocks=[b for f in functions for b in f["blocks"]]
 names=[v["name"] for f in functions for v in f["params"]]
 names += [v["name"] for b in blocks for v in b["params"]]
 names += [v["name"] for b in blocks for op in b["ops"] for v in op.get("out",[])]
 suffixes=[int(m.group(1)) for name in names if (m:=re.search(r"(\d+)$",name))]
 observed=dict(functions=len(functions),blocks=len(blocks),operations=sum(len(b["ops"]) for b in blocks),
   max_function_blocks=max(len(f["blocks"]) for f in functions),
   max_block_parameters=max(len(b["params"]) for b in blocks),
   max_ssa_numeric_suffix=max(suffixes,default=0),max_block_operations=max(len(b["ops"]) for b in blocks))
 assert observed==profile
 return dict(full_source_image_receipt_binding=True,document_profile_recomputed=True,
   max_block_operations_recorded_not_gated=True,original_compiler_limits=True)
def run_gate(common,label,args,cwd,env,summary_path,marker):
 evidence=Evidence()
 evidence.attempt("subject",lambda:common.run(label,args,cwd=cwd,timeout=180,env=env))
 value=evidence.attempt("original_summary",lambda:original_summary(summary_path,marker))
 step=common.OUTPUT/"steps"/label
 for filename in ("stderr.log","process.json"):
  evidence.attempt("original_"+filename,
   lambda filename=filename:original(step/filename,"HIA_UNIFIED_PREFIX_STEP_ORIGINAL")
    if (step/filename).is_file() else None)
 evidence.raise_if_failed()
 process=json.loads(raw_file(step/"process.json"))
 assert process["status"]=="PASS" and process["returncode"]==0 and not process["timed_out"]
 assert process["timeout_seconds"]==180 and process["child_cpu_seconds"]<90
 assert process["elapsed_ns"]<180*10**9
 assert value is not None
 return value,process

def final_subject_gate(value):
 assert value["source_image_inputs_before_after_equal"] and value["limits"]==EXPECTED_LIMITS
 assert value["parent_plus_children_CPU_seconds"]<90 and value["elapsed_seconds"]<180
 assert not value["finalization_errors"] and value["first_failure"] is None
 for phase in ("pre_receipt_budget","post_output_budget"):
  assert value[phase]["parent_plus_children_CPU_seconds"]<90
  assert value[phase]["elapsed_seconds"]<180
 assert not value["prior_results_inherited"] and not value["whole_public_backend"]
 assert value["current_P16_late_Core_HIA_source_binding_required"] and value["full_original_mode_tree_contract"]
def main():
 common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
 common,common_raw=load("backend_unified_prefix_common",common_path,COMMON_GIT)
 source=Path(__file__).resolve().parents[1]
 seal,seal_raw=load("backend_unified_prefix_bounded_seal",source/"ci/bounded_streamed_finish.py",SEAL_GIT)
 common.PINS[common_path]=common_raw;common.PINS[source/"ci/bounded_streamed_finish.py"]=seal_raw
 common.PINS[Path(__file__).resolve()]=raw_file(__file__)
 index_raw=raw_file(source/"sources.json")
 assert (len(index_raw),digest(index_raw),gitsha(index_raw))==(INDEX_BYTES,INDEX_SHA,INDEX_GIT)
 common.PINS[source/"sources.json"]=index_raw
 index=json.loads(index_raw);rows=index["files"]
 assert index["schema"]=="hia-unified-program-Graph-source-index-v1"
 assert len(rows)==43 and len({r["path"] for r in rows})==43
 assert [r["path"] for r in rows]==sorted(r["path"] for r in rows)
 assert SCHEDULE==[[r["group"],r["variant"],r["cases"]] for r in index["schedule"]]
 closure(source,rows)
 project=assets_root=reader_root=None;status="FAIL";groups={};controls={};actual_pairs={}
 executable=before_executable=original_executable=original_identity=None
 transport_pins={};retained_extra={};main_evidence=Evidence()
 report=dict(schema="hia-unified-P16-late-Core-Graph-independent-CI-v1",status="INCOMPLETE",
  current_predecessor_head=PREDECESSOR_HEAD,original_table_images=43,new_table_images=47,
  changed_roles=[56],added_roles=[31,32,33,58],retained_current_images=42,
  planned_fresh_B3=1,planned_native_packer_entries=1,planned_new_groups=26,planned_new_cases=283,
  planned_new_ELF=185,planned_new_private_cases=98,planned_new_private_entries=243,
  planned_predecessor_control_groups=3,planned_predecessor_ELF_processes=51,
  planned_predecessor_private_entries=2,planned_total_group_invocations=29,
  actual_new_B3=0,actual_new_HIA_packer_entries=0,actual_completed_cases=0,
  actual_ELF=0,actual_private_cases=0,actual_private_entries=0,actual_wire_entries=0,
  actual_predecessor_ELF=0,actual_predecessor_private_entries=0,
  original_six_read_back_and_rerun_not_inherited=True,original_follow54_group6_not_inherited=True,
  prior_413_type_and_90_implementation_cases_not_inherited=True,
  implementation_fingerprints_joined=False,full_public_backend=False,group9_open=True,
  installed=False,cold=False,Python_authoring_test_and_fixed_executor_TCB=True)
 def update_group_counts(evidence):
  for name,field in (("actual_completed_cases","completed_cases"),("actual_ELF","actual_ELF_processes"),
    ("actual_private_cases","private_cases"),("actual_private_entries","actual_private_native_entries"),
    ("actual_wire_entries","actual_wire_native_entries"),
    ("actual_predecessor_private_entries","actual_predecessor_private_entries")):
   evidence.attempt("count_"+name,
    lambda name=name,field=field:report.__setitem__(name,sum(r.get(field,0) for r in groups.values())))
  evidence.attempt("count_predecessor_ELF",lambda:report.__setitem__("actual_predecessor_ELF",
   sum(r.get("actual_predecessor_ELF_processes",0) for r in controls.values())))
 def execute_group(context,env,bundle_path,group,variant,count,sample,control_only=False,control_results=None):
  label=group+"-"+str(variant)
  if control_only:label="predecessor-"+label
  out=project/"development"/("native-"+label+"-r1")
  args=[context["python"],"-B",project/"development/test_unified_program_graph.py",
    "--bundle",bundle_path,"--reference",context["reference"],"--out",out,
    "--group",group,"--variant",str(variant)]
  if control_only:args+=["--predecessor-control"]
  if control_results is not None:args+=["--control-results",control_results]
  if group=="private":
   assert not control_only and sample is not None and sample.is_file()
   args+=["--issued-sample",sample]
  evidence=Evidence();value=None
  try:
   value,process=run_gate(common,"unified-program-Graph-"+label,args,project,env,
    out/"summary.json","HIA_UNIFIED_PREFIX_GROUP_ORIGINAL")
  except BaseException as exc:evidence.record("group_subject",exc)
  finally:
   current=evidence.attempt("group_final_summary",
    lambda:original_summary(out/"summary.json","HIA_UNIFIED_PREFIX_GROUP_FINAL_ORIGINAL"))
   if current is not None:
    if control_only:controls[label]=current
    else:groups[label]=current
   report["new_groups"]=groups;report["predecessor_control_groups"]=controls
   update_group_counts(evidence)
  evidence.raise_if_failed()
  assert value is not None and value["schema"]=="hia-unified-program-Graph-actual-v1"
  assert value["status"]=="PASS" and value["group"]==group and value["variant"]==variant
  assert value["planned_cases"]==value["completed_cases"]==count
  final_subject_gate(value)
  after=json.loads(raw_file(out/"source-after.json"))
  assert after and all(r["same"] and r["error"] is None for r in after)
  if control_only:
   assert group in CONTROL_GROUPS and count==CONTROL_GROUPS[group]
   assert value["predecessor_control_only"]
   assert value["actual_predecessor_ELF_processes"]==count
   assert value["actual_ELF_processes"]==value["actual_private_native_entries"]==0
   assert value["actual_predecessor_private_entries"]==value["actual_wire_native_entries"]==0
  else:
   assert not value["predecessor_control_only"] and value["actual_predecessor_ELF_processes"]==0
   if group=="private":
    assert value["private_cases"]==60 and value["actual_private_native_entries"]==138
    assert value["actual_predecessor_private_entries"]==2 and value["complete_private_entry_records"]==140
    assert value["actual_ELF_processes"]==value["actual_wire_native_entries"]==0
   elif group=="late-private-protocol":
    assert value["private_cases"]==38 and value["actual_private_native_entries"]==105
    assert value["actual_predecessor_private_entries"]==value["actual_ELF_processes"]==value["actual_wire_native_entries"]==0
   else:
    assert value["actual_ELF_processes"]==count
    assert value["private_cases"]==value["actual_private_native_entries"]==value["actual_predecessor_private_entries"]==0
  closure(project,rows)
  assert file_identity(executable)==before_executable
  assert file_identity(original_executable)==original_identity
  return out,value
 try:
  context=common.prepare()
  project=Path(context["base"])/"backend-unified-program-Graph-native-r1";project.mkdir()
  for row in rows:
   raw=raw_file(source/row["path"])
   assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"])
   common.PINS[source/row["path"]]=raw
   target=project/row["path"];target.parent.mkdir(parents=True,exist_ok=True)
   with target.open("xb") as out:out.write(raw)
   target.chmod(int(row["mode"],8)&0o777)
   if target.suffix==".py":ast.parse(raw,filename=str(target))
  (project/"sources.json").write_bytes(index_raw)
  (project/"ci-driver-original.py").write_bytes(raw_file(__file__))
  assert closure(project,rows)["all_bytes_modes_SHA_Git_equal"]
  assert len(SCHEDULE)==26 and sum(r[2] for r in SCHEDULE)==283
  assert sum(r[2] for r in SCHEDULE if r[0] not in ("private","late-private-protocol"))==185
  assert len(CONTROL_GROUPS)==3 and sum(CONTROL_GROUPS.values())==51
  compiler=Path(context["compiler"])
  assert file_identity(compiler)["bytes"]==669556 and file_identity(compiler)["sha256"]==NEW_COMPILER
  env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8")
  archive=Path(os.environ["HIA_UNIFIED53_ZIP"]).resolve()
  transport_dir=project/"original53-transport";transport_dir.mkdir()
  for suffix in (".metadata.json",".receipt.json"):
   path=archive.with_name(archive.name+suffix);raw=raw_file(path)
   transport_pins[path]=file_identity(path)
   target=transport_dir/path.name;target.write_bytes(raw);target.chmod(transport_pins[path]["mode"])
   assert raw_file(target)==raw and file_identity(target)==transport_pins[path]
   transport_pins[target]=file_identity(target)
  tr=json.loads(raw_file(archive.with_name(archive.name+".receipt.json")))
  assert tr["status"]=="PASS" and not tr["finalization_errors"] and tr["error"] is None
  assert (tr["run"],tr["artifact"],tr["head"])==(43237029243,13952974167,PREDECESSOR_HEAD)
  assert tr["self_sha256"]==TRANSPORT_SHA and tr["self_unchanged"]
  assert tr["bytes"]==tr["expected_bytes"]==100633717
  assert tr["expected_sha256"]=="36f8063dd97c8fffeed958797a22d38e091d9185ef1c90604c75ff509b70093d"
  assert tr["CPU_seconds"]<90 and int(tr["elapsed_ns"])<180_000_000_000
  assert tr["project_imports"]==tr["native_entries"]==0 and not tr["repository_token_forwarded_to_storage"]
  report["complete_transport_receipt"]=tr
  reader_root=Path(context["base"])/"unified-group6-follow53-complete-originals-r1"
  value,process=run_gate(common,"unified-P16-complete-original53-readback",
   [context["python"],"-B",project/"ci/read_follow53_late_core_originals.py",
    "--zip",archive,"--out",reader_root,"--repo",context["source"]],
   project,env,reader_root/"summary.json","HIA_UNIFIED_PREFIX_PREDECESSOR_READBACK_ORIGINAL")
  report["predecessor_readback"]=value
  assert value["status"]=="PASS" and value["original_target_status"]=="FAIL"
  assert value["complete_original_ZIP_retained_and_after_verified"]
  assert value["all_756_original_members_retained_and_after_verified"]
  assert value["new_target_entries"]==value["new_compiler_entries"]==value["original_project_imports"]==0
  assert value["facts"]["completed_original_public_cases"]==6
  assert value["facts"]["all_43_source_image_bytes_bound"] and value["facts"]["complete_original_ELF_and_13_compiler_outputs_bound"]
  assert value["budget"]["aggregate_cpu_seconds"]<90 and value["budget"]["elapsed_ns"]<180_000_000_000
  assert not value["after_errors"] and not value["finalization_errors"] and value["primary_failure"] is None
  post=json.loads(raw_file(reader_root/"post-output-budget.json"))
  assert post["status"]=="PASS" and post["aggregate_cpu_seconds"]<90 and post["elapsed_ns"]<180_000_000_000
  assets_root=Path(context["base"])/"unified-current-P16-assets-r1"
  value,process=run_gate(common,"unified-P16-retained-asset-binding",
   [context["python"],"-B",project/"ci/bind_unified_program_graph_assets.py",
    "--readback",reader_root,"--out",assets_root,
    "--reader",project/"ci/read_follow53_late_core_originals.py",
    "--role-map",project/"resources/original-role-map.json",
    "--observation",project/"resources/follow53-original-panels.jsonl"],
   project,env,assets_root/"summary.json","HIA_UNIFIED_PREFIX_ASSET_ORIGINAL")
  report["retained_asset_binding"]=value
  assert value["status"]=="PASS" and value["complete_inner_readback"] and not value["partial"]
  assert value["original_member_count"]==756 and value["original_member_bytes"]==195136808
  assert value["target_executions"]==value["compiler_executions"]==value["VM_entries"]==value["HIA_entries"]==0
  assert value["actual_limits"]==EXPECTED_LIMITS
  assert value["parent_plus_children_CPU_seconds"]<90 and value["elapsed_seconds"]<180
  assert not value["after_check_errors"] and not value["finalization_errors"]
  assets=assets_root/"assets.json";build=project/"development/build-r1"
  build_evidence=Evidence()
  try:
   value,process=run_gate(common,"unified-program-Graph-root-and-native-packer",
    [context["python"],"-B",project/"development/build_unified_program_graph.py",
     "--project",project,"--reference",context["reference"],"--compiler",compiler,
     "--assets",assets,"--out",build],
    project,env,build/"summary.json","HIA_UNIFIED_PREFIX_BUILD_ORIGINAL")
  except BaseException as exc:build_evidence.record("build_subject",exc)
  finally:
   report["build"]=build_evidence.attempt("build_final_summary",
    lambda:original_summary(build/"summary.json","HIA_UNIFIED_PREFIX_BUILD_FINAL_ORIGINAL"))
   if report["build"] is not None:
    def build_counts():
     report["actual_new_B3"]=report["build"]["actual_new_B3_compilations"]
     report["actual_new_HIA_packer_entries"]=report["build"]["actual_native_packer_entries"]
    build_evidence.attempt("build_counts",build_counts)
   for pattern,marker in (("*.stderr","HIA_UNIFIED_PREFIX_NESTED_STDERR_ORIGINAL"),
     ("*.stderr.log","HIA_UNIFIED_PREFIX_NESTED_STDERR_ORIGINAL"),
     ("profile-before-gates.json","HIA_UNIFIED_PREFIX_PROFILE_ORIGINAL")):
    paths=build_evidence.attempt("list_"+pattern,lambda pattern=pattern:sorted(build.rglob(pattern)))
    for path in paths or []:
     build_evidence.attempt("original_"+str(path),lambda path=path,marker=marker:original(path,marker))
  build_evidence.raise_if_failed()
  assert value["status"]=="PASS_BUILD_ONLY" and value["actual_limits"]==EXPECTED_LIMITS
  assert value["actual_new_B3_compilations"]==value["actual_compile_attempts"]==value["actual_native_packer_entries"]==1
  assert value["actual_semantic_ELF_processes"]==0 and value["source_image_before_after_equal"]
  assert value["parent_plus_children_CPU_seconds"]<90 and value["elapsed_seconds"]<180
  assert not value["finalization_errors"] and value["first_failure"] is None
  assert len(value["compiled"])==1
  report["fresh_root_independent_profile_and_receipt"]=receipt_gate(value["compiled"][0])
  bundle_path=build/"bundle.json";bundle=json.loads(raw_file(bundle_path))
  assert bundle["schema"]=="hia-unified-program-Graph-fixed-v1" and bundle["status"]=="BUILT_ONLY"
  assert bundle["nonzero_images"]==47 and bundle["table_rows"]==63
  assert bundle["original_other_42_images_byte_identical"] and bundle["added_roles"]==[31,32,33,58]
  assert bundle["current_root_HIA_reproduced_before_extension"] and bundle["current_type_context_error_routes_preserved"]
  assert bundle["current_reader50_child_kind0_drivers41_43_preserved"] and bundle["current_role51_RWW_preserved"]
  assert bundle["current_late_Core_group6_routes_preserved"] and bundle["full_original_P16_modes_and_tree_preserved"]
  assert bundle["Graph_only_on_mode1_tree0_success"] and bundle["original_other_modes_use_HIAWPE01"]
  assert bundle["actual_current_P16_head"]==PREDECESSOR_HEAD
  assert set(map(int,bundle["role_bindings"]))==set(range(1,29))|set(range(40,47))|{31,32,33,50,51,55,56,58,59,61,62,63}
  for role,row in bundle["role_bindings"].items():
   actual_pairs[role]={}
   for kind in ("source","image"):
    info=file_identity(row[kind+"_path"])
    assert (info["bytes"],info["sha256"])==(row[kind+"_bytes"],row[kind+"_sha256"])
    actual_pairs[role][kind]=dict(path=row[kind+"_path"],**info)
  for row in [bundle["original_root_binding"],bundle["retained_packer"],*bundle["test_only_wire"].values()]:
   for kind in ("source","image"):
    path=Path(row[kind+"_path"]);info=file_identity(path)
    assert (info["bytes"],info["sha256"])==(row[kind+"_bytes"],row[kind+"_sha256"])
    retained_extra[path]=info
  executable=Path(bundle["executable_path"]);before_executable=file_identity(executable)
  assert (before_executable["bytes"],before_executable["sha256"])==(bundle["executable_bytes"],bundle["executable_sha256"])
  original_executable=Path(bundle["original_executable_path"])
  original_identity=file_identity(original_executable)
  assert all(original_identity[k]==bundle["original_executable_identity"][k] for k in original_identity)
  sample=None
  for group,variant,count in SCHEDULE:
   control_out=None
   if group in CONTROL_GROUPS:
    control_out,control_value=execute_group(context,env,bundle_path,group,variant,count,sample,True)
   out,value=execute_group(context,env,bundle_path,group,variant,count,sample,False,control_out)
   if group=="semantic":
    sample=out/"cases/verify-v6/issued-sample.json";assert sample.is_file()
  assert len(groups)==26 and len(controls)==3
  assert (report["actual_completed_cases"],report["actual_ELF"],
    report["actual_private_cases"],report["actual_private_entries"],
    report["actual_predecessor_ELF"],report["actual_predecessor_private_entries"])==(283,185,98,243,51,2)
  report.update(status="PASS",actual_source_image_pairs=actual_pairs,
   actual_predecessor_ELF_identity=original_identity,
   type_context_late_Core_and_original_full_modes_executed_on_same_role56=True,
   original_non_Graph_inputs_stdout_stderr_exit_equal=True,
   original_six_late_inputs_and_complete_streams_equal=True,
   actual_complete_receipt_Core_Graph_and_wire_bytes_compared=True,
   all_canonical_HIA_documents_profiles_images_receipts_preserved=True,
   full_source_mode_SHA_Git_inputs_read_back=True,
   original_complete_ZIP_body_and_756_members_read=True,
   native_GraphWire_entries_are_measured_not_process_inference=True)
  status="PASS"
 except BaseException as exc:
  main_evidence.record("CI_subject",exc)
  report.update(status="FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
  main_evidence.attempt("original_CI_traceback",lambda:traceback.print_exc())
 finally:
  errors=[]
  for label,root in (("submitted",source),("materialized",project)):
   if root is not None:
    try:report[label+"_source_after"]=closure(root,rows)
    except BaseException as exc:
     errors.append(dict(scope=label,error=repr(exc)));main_evidence.record("closure_"+label,exc)
  for role,kinds in actual_pairs.items():
   for kind,row in kinds.items():
    try:assert file_identity(row["path"])=={k:row[k] for k in ("bytes","sha256","mode")}
    except BaseException as exc:
     errors.append(dict(role=role,kind=kind,error=repr(exc)));main_evidence.record("role_"+role+"_"+kind,exc)
  for path,before in {**retained_extra,**transport_pins}.items():
   try:assert file_identity(path)==before
   except BaseException as exc:
    errors.append(dict(path=str(path),error=repr(exc)));main_evidence.record("retained_after:"+str(path),exc)
  for label,path,before in (("new_ELF",executable,before_executable),("old_ELF",original_executable,original_identity)):
   if before is not None:
    try:assert file_identity(path)==before
    except BaseException as exc:
     errors.append(dict(scope=label,error=repr(exc)));main_evidence.record(label+"_after",exc)
  if errors or main_evidence.primary is not None:status="FAIL";report["status"]="FAIL"
  report["CI_evidence_errors"]=main_evidence.errors
  report["final_source_image_after_check_errors"]=errors
  report["all_observed_source_image_pairs_before_after_equal"]=not errors
  roots={}
  if project is not None:roots["unified-program-Graph"]=project
  if assets_root is not None and assets_root.exists():roots["unified-P16-assets"]=assets_root
  if reader_root is not None and reader_root.exists():roots["unified-follow53-originals"]=reader_root
  main_evidence.attempt("bounded_seal",
   lambda:seal.finish(common,"unified-full-P16-late-Core-Graph-r1",status,report,roots=roots))
 main_evidence.raise_if_failed()
 if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
