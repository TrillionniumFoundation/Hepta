"""Current type-context P16 -> actual admitted Core Graph, first independent CI.

Source-only development driver. The current predecessor is fully read back;
only a new root is compiled, and all new cases execute the current 47-image
combination. Historical component counts are never inherited.
"""
from pathlib import Path
from hashlib import sha1,sha256
import ast,base64,json,os,re,stat,sys,traceback,types
sys.dont_write_bytecode=True
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
SEAL_GIT="084a98a1d42e3081612b817e909eb50443d8a924"
INDEX_GIT="a53cae2f921ee96de1a1d963357d854197038215"
INDEX_SHA="b5e79b874203add6c0760c4e34d1270f98d767f3c6425741b49472a77f01eda3"
INDEX_BYTES=19000
NEW_COMPILER="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
OLD_COMPILER="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
SCHEDULE=[["semantic",0,26],["private",0,54],["fixed-errors",0,34],["type-context",0,4],["type-names",0,24],["type-shapes",0,9],["type-order",0,17],["helper-budget",0,1],["late-inventory",0,1],["raw-boundary",0,1],["raw-boundary",1,1],["functions",0,1],["functions",1,1],["functions",2,1],["functions",3,1]]
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
def original(path,label):
 raw=raw_file(path)
 for at in range(0,len(raw),18000):
  part=raw[at:at+18000]
  print(label+" "+json.dumps(dict(path=str(path),bytes=len(raw),sha256=digest(raw),
    offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode("ascii")),sort_keys=True),flush=True)
def original_summary(path,label):
 if not path.is_file():return None
 raw=raw_file(path);value=json.loads(raw)
 print(label+" "+raw.decode("utf-8").strip(),flush=True)
 return value
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
 try:
  common.run(label,args,cwd=cwd,timeout=180,env=env)
 finally:
  value=original_summary(summary_path,marker)
  step=common.OUTPUT/"steps"/label
  for filename in ("stderr.log","process.json"):
   if (step/filename).is_file():original(step/filename,"HIA_CURRENT_PREFIX_STEP_ORIGINAL")
 process=json.loads(raw_file(step/"process.json"))
 assert process["status"]=="PASS" and process["returncode"]==0 and not process["timed_out"]
 assert process["timeout_seconds"]==180 and process["child_cpu_seconds"]<90
 assert process["elapsed_ns"]<180*10**9
 assert value is not None
 return value,process
def main():
 common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
 common,common_raw=load("backend_current_prefix_common",common_path,COMMON_GIT)
 source=Path(__file__).resolve().parents[1]
 seal,seal_raw=load("backend_current_prefix_bounded_seal",source/"ci/bounded_streamed_finish.py",SEAL_GIT)
 common.PINS[common_path]=common_raw;common.PINS[source/"ci/bounded_streamed_finish.py"]=seal_raw
 common.PINS[Path(__file__).resolve()]=raw_file(__file__)
 index_raw=raw_file(source/"sources.json")
 assert (len(index_raw),digest(index_raw),gitsha(index_raw))==(INDEX_BYTES,INDEX_SHA,INDEX_GIT)
 common.PINS[source/"sources.json"]=index_raw
 index=json.loads(index_raw);rows=index["files"]
 assert index["schema"]=="hia-backend-current-program-Graph-source-index-v2"
 assert len(rows)==37 and len({r["path"] for r in rows})==37
 assert [r["path"] for r in rows]==sorted(r["path"] for r in rows)
 closure(source,rows)
 project=assets_root=None;status="FAIL";groups={};actual_pairs={};executable=None;before_executable=None
 report=dict(schema="hia-current-P16-Core-Graph-independent-CI-v1",status="INCOMPLETE",
  current_predecessor_head="122a6640aee2666d23563910578ef66858c01d88",
  original_current_table_images=43,new_current_table_images=47,
  changed_roles=[56],added_roles=[31,32,33,58],retained_current_images=42,
  planned_fresh_B3=1,planned_native_packer_entries=1,planned_groups=15,planned_cases=176,
  planned_actual_ELF=122,planned_private_cases=54,planned_private_entries=128,
  actual_new_B3=0,actual_new_HIA_packer_entries=0,actual_completed_cases=0,
  actual_ELF=0,actual_private_cases=0,actual_private_entries=0,actual_wire_entries=0,
  prior_413_cases_inherited=False,prior_90_file_cases_inherited=False,
  implementation_fingerprints_joined=False,full_public_backend=False,
  current_group6_follow53_inherited=False,whole_public_diagnostics=False,
  installed=False,cold=False,Python_authoring_test_and_fixed_executor_TCB=True)
 try:
  context=common.prepare()
  project=Path(context["base"])/"backend-current-program-Graph-native-r1";project.mkdir()
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
  assert len(SCHEDULE)==15 and sum(r[2] for r in SCHEDULE)==176
  assert sum(r[2] for r in SCHEDULE if r[0]!="private")==122
  compiler=Path(context["compiler"])
  assert file_identity(compiler)["bytes"]==669556 and file_identity(compiler)["sha256"]==NEW_COMPILER
  env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8")
  assets_root=Path(context["base"])/"backend-current-P16-originals-r1"
  value,process=run_gate(common,"current-P16-complete-original-assets",
   [context["python"],"-B",project/"ci/read_backend_program_graph_assets.py",
    "--input",Path(os.environ["HIA_CURRENT_P16_ORIGINALS"]).resolve(),"--out",assets_root,
    "--role-map",project/"resources/original-role-map.json",
    "--observation",project/"resources/follow52a-original-panels.jsonl"],
   project,env,assets_root/"summary.json","HIA_CURRENT_PREFIX_ASSET_ORIGINAL")
  report["predecessor_readback"]=value
  assert value["status"]=="PASS" and value["complete_inner_readback"] and not value["partial"]
  assert value["archive_members_read"]==4783 and value["original_member_bytes_read"]==190964237
  assert value["target_executions"]==value["compiler_executions"]==value["VM_entries"]==value["HIA_entries"]==0
  assert value["actual_limits"]==EXPECTED_LIMITS
  assert value["parent_plus_children_CPU_seconds"]<90 and value["elapsed_seconds"]<180
  assert not value["outer_ZIP_body_independently_read"] and not value["after_check_errors"]
  assets=assets_root/"assets.json";build=project/"development/build-r1"
  try:
   value,process=run_gate(common,"current-program-Graph-root-and-native-packer",
    [context["python"],"-B",project/"development/build_backend_program_graph.py",
     "--project",project,"--reference",context["reference"],"--compiler",compiler,
     "--assets",assets,"--out",build],
    project,env,build/"summary.json","HIA_CURRENT_PREFIX_BUILD_ORIGINAL")
  finally:
   report["build"]=original_summary(build/"summary.json","HIA_CURRENT_PREFIX_BUILD_FINAL_ORIGINAL")
   if report["build"] is not None:
    report["actual_new_B3"]=report["build"]["actual_new_B3_compilations"]
    report["actual_new_HIA_packer_entries"]=report["build"]["actual_native_packer_entries"]
   if build.exists():
    for path in sorted(set(build.rglob("*.stderr"))|set(build.rglob("*.stderr.log"))):
     original(path,"HIA_CURRENT_PREFIX_NESTED_STDERR_ORIGINAL")
    for path in sorted(build.rglob("profile-before-gates.json")):
     original(path,"HIA_CURRENT_PREFIX_PROFILE_ORIGINAL")
  assert value["status"]=="PASS_BUILD_ONLY" and value["actual_limits"]==EXPECTED_LIMITS
  assert value["actual_new_B3_compilations"]==value["actual_compile_attempts"]==value["actual_native_packer_entries"]==1
  assert value["actual_semantic_ELF_processes"]==0 and value["source_image_before_after_equal"]
  assert value["parent_plus_children_CPU_seconds"]<90 and value["elapsed_seconds"]<180
  assert len(value["compiled"])==1
  report["fresh_root_independent_profile_and_receipt"]=receipt_gate(value["compiled"][0])
  bundle_path=build/"bundle.json";bundle=json.loads(raw_file(bundle_path))
  assert bundle["schema"]=="hia-backend-current-program-Graph-fixed-v2" and bundle["status"]=="BUILT_ONLY"
  assert bundle["nonzero_images"]==47 and bundle["table_rows"]==63
  assert bundle["original_other_42_images_byte_identical"] and bundle["added_roles"]==[31,32,33,58]
  assert bundle["current_root_HIA_reproduced_before_extension"] and bundle["current_type_context_error_routes_preserved"]
  assert bundle["current_reader50_child_kind0_drivers41_43_preserved"] and bundle["current_role51_RWW_preserved"]
  assert bundle["actual_current_P16_head"]==report["current_predecessor_head"]
  assert set(map(int,bundle["role_bindings"]))==set(range(1,29))|set(range(40,47))|{31,32,33,50,51,55,56,58,59,61,62,63}
  for role,row in bundle["role_bindings"].items():
   actual_pairs[role]={}
   for kind in ("source","image"):
    info=file_identity(row[kind+"_path"])
    assert (info["bytes"],info["sha256"])==(row[kind+"_bytes"],row[kind+"_sha256"])
    actual_pairs[role][kind]=dict(path=row[kind+"_path"],**info)
  executable=Path(bundle["executable_path"]);before_executable=file_identity(executable)
  assert (before_executable["bytes"],before_executable["sha256"])==(bundle["executable_bytes"],bundle["executable_sha256"])
  sample=None
  for group,variant,count in SCHEDULE:
   label=group+"-"+str(variant);out=project/"development"/("native-"+label+"-r1")
   args=[context["python"],"-B",project/"development/test_backend_program_graph.py",
       "--bundle",bundle_path,"--reference",context["reference"],"--out",out,
       "--group",group,"--variant",str(variant)]
   if group=="private":
    assert sample is not None and sample.is_file()
    args+=["--issued-sample",sample]
   try:
    value,process=run_gate(common,"current-program-Graph-"+label,args,project,env,
     out/"summary.json","HIA_CURRENT_PREFIX_GROUP_ORIGINAL")
   finally:
    current=original_summary(out/"summary.json","HIA_CURRENT_PREFIX_GROUP_FINAL_ORIGINAL")
    if current is not None:groups[label]=current
    report["groups"]=groups
    for name,field in (("actual_completed_cases","completed_cases"),("actual_ELF","actual_ELF_processes"),
      ("actual_private_cases","private_cases"),("actual_private_entries","actual_private_native_entries"),
      ("actual_wire_entries","actual_wire_native_entries")):
     report[name]=sum(r.get(field,0) for r in groups.values())
   assert value["status"]=="PASS" and value["group"]==group and value["variant"]==variant
   assert value["planned_cases"]==value["completed_cases"]==count
   assert value["source_image_inputs_before_after_equal"] and value["limits"]==EXPECTED_LIMITS
   assert value["parent_plus_children_CPU_seconds"]<90 and value["elapsed_seconds"]<180
   assert not value["prior_results_inherited"] and not value["whole_public_backend"]
   if group=="private":
    assert value["private_cases"]==54 and value["actual_private_native_entries"]==128
    assert value["actual_ELF_processes"]==value["actual_wire_native_entries"]==0
   else:
    assert value["actual_ELF_processes"]==count
    assert value["private_cases"]==value["actual_private_native_entries"]==0
   if group=="semantic":
    sample=out/"cases/verify-v6/issued-sample.json";assert sample.is_file()
   closure(project,rows);assert file_identity(executable)==before_executable
  assert len(groups)==15
  assert (report["actual_completed_cases"],report["actual_ELF"],
          report["actual_private_cases"],report["actual_private_entries"])==(176,122,54,128)
  report.update(status="PASS",actual_source_image_pairs=actual_pairs,
    current_public_context_and_error_tests_executed_again=True,
    actual_complete_receipt_Core_Graph_and_wire_bytes_compared=True,
    actual_33_type_message_shapes_and_error_order_covered=True,
    all_canonical_HIA_documents_profiles_images_receipts_preserved=True,
    full_source_mode_SHA_Git_inputs_read_back=True,
    outer_ZIP_body_independently_read=False)
  status="PASS"
 except BaseException as exc:
  report.update(status="FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  errors=[]
  for label,root in (("submitted",source),("materialized",project)):
   if root is not None:
    try:report[label+"_source_after"]=closure(root,rows)
    except BaseException as exc:errors.append(dict(scope=label,error=repr(exc)))
  for role,kinds in actual_pairs.items():
   for kind,row in kinds.items():
    try:assert file_identity(row["path"])=={k:row[k] for k in ("bytes","sha256","mode")}
    except BaseException as exc:errors.append(dict(role=role,kind=kind,error=repr(exc)))
  if before_executable is not None:
   try:assert file_identity(executable)==before_executable
   except BaseException as exc:errors.append(dict(scope="fixed_ELF",error=repr(exc)))
  if errors:status="FAIL";report["status"]="FAIL"
  report["final_source_image_after_check_errors"]=errors
  report["all_observed_source_image_pairs_before_after_equal"]=not errors
  roots={}
  if project is not None:roots["current-program-Graph"]=project
  if assets_root is not None and assets_root.exists():roots["current-P16-originals"]=assets_root
  seal.finish(common,"current-program-Core-Graph-r2",status,report,roots=roots)
 if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
