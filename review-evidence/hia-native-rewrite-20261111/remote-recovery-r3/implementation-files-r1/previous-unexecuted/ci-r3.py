"""First independent actual implementation-file and native SHA qualification.
No prior Emitter, compiler-component or private-header result is inherited.
Only the operator's common output/source inputs are used; no external artifact
input or host semantic filesystem policy is supplied to the target.
"""
from pathlib import Path
from hashlib import sha256,sha1
import ast,base64,json,os,re,stat,sys,traceback,types
sys.dont_write_bytecode=True
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
SEAL_GIT="7d014167dc69e800f1546ff111a416a6cbab1639"
SOURCE_PREFIX="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/implementation-files-r1/"
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
CHILD_SHA="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
SCHEDULE=[["cross",0,2,0],["normal",0,12,0],["errors",0,24,0],
 ["large",0,1,0],["large",1,1,0],["fd0",0,1,0],["initial",0,16,16],
 ["ack",0,10,10],["state",0,12,12],["operation",0,8,8],["hash",0,3,3]]
FILES=[
  {
    "path": "ci/implementation_files_streamed_finish.py",
    "mode": "100644",
    "bytes": 11768,
    "sha256": "503fabaee5d2b0bdd8a1f3b8e513efce35d69a647f91c58ba2a8ec7214d3d840",
    "gitsha": "7d014167dc69e800f1546ff111a416a6cbab1639"
  },
  {
    "path": "docs/HIA_IMPLEMENTATION_FILES_NATIVE.md",
    "mode": "100644",
    "bytes": 11649,
    "sha256": "8ba7b6a11fe031797b3f991c9c95ebfcd57c828de02653414b8200b0b03065f7",
    "gitsha": "c8e94b350b3d976131b10e3db748cc90ea11e743"
  },
  {
    "path": "reference/cpython-3.12.14-fileio.c",
    "mode": "100644",
    "bytes": 31814,
    "sha256": "b2266a58fd78f856f0b8b47ff34b3b166bd4cf4ca80adaaacaa271417fbe9f23",
    "gitsha": "bab68077a2144aa6fe7f66100a3f22f923abc8be"
  },
  {
    "path": "reference/hia_program_native.py",
    "mode": "100644",
    "gitsha": "1d0e0344f8300b11b5dd505cbea655170aba5be1",
    "bytes": 46917,
    "sha256": "bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
  },
  {
    "path": "reference/hia_selfhost_child.py",
    "mode": "100644",
    "gitsha": "2ecbf3a04680eceee0537cb3d621073bac9c52f4",
    "bytes": 6791,
    "sha256": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
  },
  {
    "path": "tests/function_frame_test_reference.py",
    "mode": "100644",
    "gitsha": "a7d64f7804753398df08e69158bcebb7afc54747",
    "bytes": 42184,
    "sha256": "b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
  },
  {
    "path": "tests/implementation_files_mechanical_harness.py",
    "mode": "100644",
    "bytes": 11927,
    "sha256": "9d57ba12ab5f8b648faae7bb370b6719d527a6197a2cecbe36802966c4d289f4",
    "gitsha": "f3743e4f91832b6ca6455ae9fe76a7528752c6ec"
  },
  {
    "path": "tests/implementation_files_native_adapter.py",
    "mode": "100644",
    "bytes": 18747,
    "sha256": "c9ebdb266cc3a4e1b9796bc79ae412cfd73fd966e41217b28f7d5ff6ef4ae441",
    "gitsha": "5dad74e5f95bbad171ea33b0de410f76e75069f0"
  },
  {
    "path": "tests/test_hia_implementation_files.py",
    "mode": "100644",
    "bytes": 35226,
    "sha256": "b4636bc61da70a2fd9a8a6a8bfde6da9fe6a78f6ae82ee3e011028d03ac7fe64",
    "gitsha": "42fad7af4318694b8f1d1c0e3572656a8f455213"
  },
  {
    "path": "tools/build_hia_implementation_files.py",
    "mode": "100644",
    "bytes": 11839,
    "sha256": "a867ac39fd1084d9ac14c0a2010c5ad138b4ff622a3e681b3bb95e5c403b1b97",
    "gitsha": "0281283470dbae7dd87f99296edccbed1685e26f"
  },
  {
    "path": "tools/build_implementation_files_native_mechanics.py",
    "mode": "100644",
    "bytes": 4371,
    "sha256": "f1836bc480e9a594932718a000ebc1f8b7f1ada036ca4b0166fc450e566c57a8",
    "gitsha": "7f01e8d2fa101a4c8d7410becb0b6123b6f31f0d"
  },
  {
    "path": "tools/function_authoring_reference.py",
    "mode": "100644",
    "gitsha": "6f1bffe8bd815a068f9834489960006cbaad6fac",
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
  },
  {
    "path": "tools/generate_hia_sha256.py",
    "mode": "100644",
    "bytes": 5474,
    "sha256": "4114a26ff0ea47229bccbedadcb40efdd9715a8dd0739d2fcb55c98f8ddbdf97",
    "gitsha": "b59c2259f038eab830c16bf498b14a5d15556ee4"
  },
  {
    "path": "tools/generate_hia_sha256_stream.py",
    "mode": "100644",
    "bytes": 4420,
    "sha256": "247816be2a50d384a6dd86a1d8cad909a48fbcdef54444f2394a7789fb137238",
    "gitsha": "80167acbcc4c4f162deaf436aab95fffefb9947a"
  },
  {
    "path": "tools/hia_agent_edit_source_views.py",
    "mode": "100644",
    "gitsha": "f7d123bdb2bf65b25182b571f024299cb0342828",
    "bytes": 23950,
    "sha256": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
  },
  {
    "path": "tools/hia_composite_lowering_driver_common.py",
    "mode": "100644",
    "gitsha": "e56539a9cb76f95010ea6ca995737f40ab6e1850",
    "bytes": 17781,
    "sha256": "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
  },
  {
    "path": "tools/hia_implementation_files.py",
    "mode": "100644",
    "bytes": 17161,
    "sha256": "a7fc5e1f656fdf4bacc3e35b754cc6f113c0b257b49dcc13c9a03fa5a23fc871",
    "gitsha": "964c46106607ae8bef292ce81b1e97ad8206e882"
  },
  {
    "path": "tools/implementation_files_native_mechanics.c",
    "mode": "100644",
    "bytes": 12516,
    "sha256": "0886ad565d13beb22e62e81652ba98b68e83bf841d4f9f8048c1f27d77de533b",
    "gitsha": "294fe43871dd11c06e6f01c7d21caf4b976b04e2"
  }
]

def digest(raw):return sha256(raw).hexdigest()
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def hash_stream(stream):
 h=sha256();n=0
 while True:
  raw=stream.read(1<<18)
  if not raw:break
  h.update(raw);n+=len(raw)
 return dict(bytes=n,sha256=h.hexdigest())
def identity(path):
 with Path(path).open("rb") as stream:return hash_stream(stream)
file_hash=identity
def loaded(name,path,expected):
 raw=Path(path).read_bytes()
 assert git_blob(raw)==expected,(str(path),git_blob(raw),expected)
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
 exec(compile(raw,str(path),"exec"),module.__dict__)
 return module,raw
def original(path,label):
 raw=path.read_bytes()
 for at in range(0,len(raw),18000):
  part=raw[at:at+18000]
  print(label+" "+json.dumps(dict(path=str(path),bytes=len(raw),sha256=digest(raw),
   offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
def summary(directory,label):
 path=directory/"summary.json"
 if not path.exists():return None
 raw=path.read_bytes();value=json.loads(raw)
 print(label+" "+raw.decode().strip(),flush=True)
 return value
def file_closure(project):
 for row in FILES:
  path=project/row["path"];info=path.lstat()
  assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not path.is_symlink()
  raw=path.read_bytes()
  assert (len(raw),digest(raw),git_blob(raw))==(row["bytes"],row["sha256"],row["gitsha"])
  assert stat.S_IMODE(info.st_mode)==int(row["mode"],8)&0o777
 return dict(files=len(FILES),all_complete_source_bytes_modes_equal=True)
def named_pin(name):
 rows=[r for r in FILES if r["path"]==name];assert len(rows)==1
 return rows[0]["sha256"]
def gates(build,manifest,document_dir):
 before=json.loads((build/"source-before.json").read_bytes())
 after=json.loads((build/"source-after.json").read_bytes())
 assert before and len(before)==len(after)
 for a,b in zip(before,after):
  assert a["path"]==b["path"] and a["bytes"]==b["bytes"] and a["sha256"]==b["sha256"] and b["same"]
  source=Path(a["path"]);snapshot=build/a["snapshot"]
  assert source.read_bytes()==snapshot.read_bytes()
  assert identity(source)=={k:a[k] for k in("bytes","sha256")}
  assert stat.S_IMODE(source.stat().st_mode)==stat.S_IMODE(snapshot.stat().st_mode)==a["mode"]
 p=manifest["profile"];r=manifest["compile_receipt"]
 document=json.loads((document_dir/"document.json").read_bytes());functions=document["functions"]
 blocks=[b for f in functions for b in f["blocks"]]
 names=[v["name"] for b in blocks for v in b["params"]+[v for op in b["ops"] for v in op["out"]]]
 assert names and all(re.fullmatch(r"v[0-9]+",name) for name in names)
 observed=dict(functions=len(functions),blocks=len(blocks),ops=sum(len(b["ops"]) for b in blocks),
  max_blocks=max(len(f["blocks"]) for f in functions),
  max_params=max(len(b["params"]) for b in blocks),max_block_ops=max(len(b["ops"]) for b in blocks),
  max_ssa_index=max(int(name[1:]) for name in names))
 assert all(p[k]==v for k,v in observed.items()),(p,observed)
 if "max_function_values" in p:assert p["max_function_values"]==p["max_ssa_index"]+1
 assert p["functions"]<=128 and p["blocks"]<=1536 and p["ops"]<=8192
 assert p["max_blocks"]<=256 and p["max_params"]<=16 and p["max_ssa_index"]<2048
 assert r["limits"]["cpu_seconds"]==10 and r["limits"]["address_bytes"]==256<<20
 assert r["runner_sha256"]==CHILD_SHA
 assert r["source_sha256"]==r["input_sha256"]==manifest["source_sha256"]
 assert r["artifact_sha256"]==r["image_sha256"]==COMPILER_SHA
 assert r["produced_sha256"]==manifest["image_sha256"] and r["produced_bytes"]==manifest["image_bytes"]
 assert r["source_unchanged"] and not r["forbidden_compiler_modules_loaded"]
 for kind in("source","image"):
  assert identity(manifest[kind+"_path"])==dict(bytes=manifest[kind+"_bytes"],sha256=manifest[kind+"_sha256"])
  assert 0<manifest[kind+"_bytes"]<=1<<20
 assert manifest["status"]=="BUILT_ONLY" and manifest["compiler_sha256"]==COMPILER_SHA
 return dict(complete_source_mode_snapshots_equal=True,snapshots=len(before),
  complete_document_profile_independently_recomputed=True,original_B3_limits=True,
  original_profile_gates=True,max_block_ops_recorded_not_gated=True)

def main():
 common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
 common,common_raw=loaded("implementation_files_ci_common",common_path,COMMON_GIT)
 seal_path=Path(__file__).resolve().with_name("implementation_files_streamed_finish.py")
 seal,seal_raw=loaded("implementation_files_stream_seal",seal_path,SEAL_GIT)
 common.PINS[common_path]=common_raw;common.PINS[seal_path]=seal_raw
 common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
 project=None;status="FAIL";roles={};pairs={};carrier_before=None;carrier=None
 report=dict(scope="FRESH_ACTUAL_IMPLEMENTATION_FILES_AND_NATIVE_SHA",status="INCOMPLETE",
    expected_fresh_B3=2,expected_groups=11,expected_cases=90,expected_private_controls=49,
    expected_full_CAS_cases=52,expected_C_processes=40,expected_small_crosschecks=2,
    builds={},groups={},readbacks={},actual_compilations=0,actual_cases=0,actual_native_entries=0,
    actual_private_controls=0,actual_raw_syscalls=0,old_results_inherited=False,
    new_native_installed_inventory=False,actual_public_Core_admission=False,
    complete_public_exception_text=False,full_public_backend=False,installed=False,cold=False,
    development_C_mechanics_and_Python_authoring_TCB=True)
 try:
  context=common.prepare()
  mine=Path(context["base"])/"implementation-files-recovery-r1";mine.mkdir()
  project=mine/"native-implementation-files-next";project.mkdir()
  for row in FILES:
   source=common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
   raw=source.read_bytes()
   assert (len(raw),digest(raw),git_blob(raw))==(row["bytes"],row["sha256"],row["gitsha"])
   source.chmod(int(row["mode"],8)&0o777)
  (project/"ci-driver-original.py").write_bytes(Path(__file__).read_bytes())
  file_closure(project)
  parsed=ast.parse((project/"tests/test_hia_implementation_files.py").read_bytes())
  assignments=[n for n in parsed.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="SCHEDULE" for t in n.targets)]
  assert len(assignments)==1 and ast.literal_eval(assignments[0].value)==SCHEDULE
  assert len(SCHEDULE)==11 and sum(r[2] for r in SCHEDULE)==90 and sum(r[3] for r in SCHEDULE)==49
  env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8")
  for role,component,owner in((1,"controller","hia_implementation_files.py"),(2,"hash","generate_hia_sha256_stream.py")):
   build=project/"development"/("build-"+component+"-r1");step="implementation-files-build-"+component
   try:
    common.run(step,[context["python"],"-B",project/"tools/build_hia_implementation_files.py",
       "--reference",context["reference"],"--compiler",context["compiler"],"--out",build,
       "--component",component],cwd=project,timeout=180,env=env)
   finally:
    value=summary(build,"HIA_IMPLEMENTATION_FILES_BUILD_ORIGINAL")
    if value is not None:
     report["builds"][component]=value
     report["actual_compilations"]=sum(v.get("compilations",0) for v in report["builds"].values())
    if build.exists():
     for path in sorted(set(build.rglob("*.stderr"))|set(build.rglob("*.stderr.log"))):original(path,"HIA_IMPLEMENTATION_FILES_NESTED_STDERR")
     for path in sorted(build.rglob("profile-before-gates.json")):original(path,"HIA_IMPLEMENTATION_FILES_PROFILE_ORIGINAL")
     for path in sorted(build.rglob("profile-functions-before-gates.json")):original(path,"HIA_IMPLEMENTATION_FILES_FUNCTION_PROFILE_ORIGINAL")
   value=report["builds"][component]
   assert value["status"]=="PASS_BUILD_ONLY" and value["compilations"]==1 and value["native_semantic_entries"]==0
   assert value["actual_limits"]==LIMITS and value["source_pins_unchanged"]
   process=json.loads((common.OUTPUT/"steps"/step/"process.json").read_bytes())
   assert process["status"]=="PASS" and process["returncode"]==0 and not process["timed_out"]
   assert process["timeout_seconds"]==180 and process["child_cpu_seconds"]<=90
   manifest=value["manifest"]
   assert manifest["schema"]=="hia-implementation-files-development-component-v1"
   assert manifest["component"]==component and manifest["role"]==role and not manifest["abi_second_readonly"]
   assert manifest["author_sha256"]==named_pin("tools/"+owner)
   report["builds"][component]["independent_gate_readback"]=gates(build,manifest,build)
   roles[str(role)]=dict(name=component,manifest=manifest,actual_role=role,second_readonly=False)
   pairs[str(role)]={kind:dict(path=manifest[kind+"_path"],bytes=manifest[kind+"_bytes"],sha256=manifest[kind+"_sha256"],
       mode=stat.S_IMODE(Path(manifest[kind+"_path"]).stat().st_mode)) for kind in("source","image")}
  assert report["actual_compilations"]==2
  assets=project/"development/runtime-assets.json"
  save(assets,dict(schema="hia-implementation-files-runtime-assets-v1",roles=roles,root_role=1,
     actual_fresh_B3_compilations=2,old_results_inherited=False,
     private_actual_installation_directory_issuer_required=True,header_is_authentication=False))
  save(project/"development/source-image-pairs.json",pairs)
  nativebuild=project/"development/native-mechanics-build-r1"
  c_step="implementation-files-development-C-build"
  try:
   common.run(c_step,[context["python"],"-B",project/"tools/build_implementation_files_native_mechanics.py",
       "--stage","build","--source",project/"tools/implementation_files_native_mechanics.c","--out",nativebuild],
       cwd=project,timeout=180,env=env)
   common.run("implementation-files-development-C-seal",
       [context["python"],"-B",project/"tools/build_implementation_files_native_mechanics.py",
        "--stage","seal","--source",project/"tools/implementation_files_native_mechanics.c","--out",nativebuild,
        "--receipt",common.OUTPUT/"steps"/c_step/"process.json"],cwd=project,timeout=180,env=env)
  finally:report["C_mechanics_build"]=summary(nativebuild,"HIA_IMPLEMENTATION_FILES_C_BUILD_ORIGINAL")
  c=report["C_mechanics_build"];assert c["status"]=="PASS_BUILD_ONLY"
  assert c["source_sha256"]==named_pin("tools/implementation_files_native_mechanics.c")
  carrier=nativebuild/"implementation-files-native-mechanics";carrier_before=identity(carrier)
  assert carrier_before==c["executable"] and c["source_before_after_exact"] and not c["installed"]
  for group,variant,count,private in SCHEDULE:
   label=group+"-"+str(variant);out=project/"development"/("native-"+label+"-r1")
   step="implementation-files-native-"+label
   try:
    common.run(step,[context["python"],"-B",project/"tests/test_hia_implementation_files.py",
       "--assets",assets,"--carrier",carrier,"--reference",context["reference"],"--out",out,
       "--group",group,"--variant",str(variant)],cwd=project,timeout=180,env=env)
   finally:
    value=summary(out,"HIA_IMPLEMENTATION_FILES_GROUP_ORIGINAL")
    if value is not None:
     report["groups"][label]=value
     for target,field in(("actual_cases","cases"),("actual_native_entries","native_entries"),
         ("actual_private_controls","private_protocol_controls"),("actual_raw_syscalls","raw_syscalls")):
      report[target]=sum(v.get(field,0) for v in report["groups"].values())
    else:report.setdefault("missing_group_summaries",[]).append(label)
   value=report["groups"][label]
   assert value["status"]=="PASS" and (value["group"],value["variant"])==(group,variant)
   assert (value["cases"],value["private_protocol_controls"])==(count,private)
   assert value["limits"]==dict(**LIMITS,wall=180) and value["source_custody"]["all_bytes_and_modes_equal"]
   assert value["parent_plus_children_CPU_seconds"]<=90 and value["elapsed_seconds"]<180
   assert value["native_entries"]==sum(value["by_role"].values()) and value["all_filenames_order_and_hash_decisions_native"]
   assert value["original_group_limits_include_evidence_encoding"] and not value["all_prior_results_inherited"]
   assert not any(value[k] for k in("complete_exception_text","actual_core_admission","complete_public_backend","installed","cold"))
   process=json.loads((common.OUTPUT/"steps"/step/"process.json").read_bytes())
   assert process["status"]=="PASS" and process["returncode"]==0 and not process["timed_out"]
   assert process["timeout_seconds"]==180 and process["child_cpu_seconds"]<=90
   readback=project/"development"/("readback-"+label+"-r1")
   try:
    common.run("implementation-files-originals-"+label,
       [context["python"],"-B",project/"tests/test_hia_implementation_files.py",
        "--readback-group",out,"--assets",assets,"--out",readback],cwd=project,timeout=180,env=env)
   finally:
    observation=summary(readback,"HIA_IMPLEMENTATION_FILES_READBACK_ORIGINAL")
    if observation is not None:report["readbacks"][label]=observation
   observation=report["readbacks"][label]
   assert observation["status"]=="PASS" and observation["limits"]==dict(**LIMITS,wall=180)
   assert observation["target_entries"]==observation["native_entries"]==0
   assert observation["source_execution_not_repeated"] and observation["complete_input_bytes_modes_unchanged"]
   assert (observation["cases"],observation["original_private_controls"])==(count,private)
   assert observation["original_native_entries"]==value["native_entries"] and observation["original_raw_syscalls"]==value["raw_syscalls"]
   assert observation["parent_plus_children_CPU_seconds"]<=90 and observation["elapsed_seconds"]<180
   file_closure(project);assert identity(carrier)==carrier_before
  assert len(report["groups"])==len(report["readbacks"])==11
  assert (report["actual_cases"],report["actual_private_controls"])==(90,49)
  assert sum(v["full_CAS_count"] for v in report["readbacks"].values())==52
  assert sum(v["fixed_native_processes"] for v in report["readbacks"].values())==40
  assert report["groups"]["cross-0"]["cases"]==2
  assert sum(v["original_native_entries"] for v in report["readbacks"].values())==report["actual_native_entries"]
  assert sum(v["original_raw_syscalls"] for v in report["readbacks"].values())==report["actual_raw_syscalls"]
  report.update(status="PASS",actual_by_role={str(i):sum(v["by_role"][str(i)] for v in report["groups"].values()) for i in(1,2)},
      exact_original_success_digest_and_physical_error_fields_compared=True,
      all_actual_canonical_HIA_sources_documents_images_receipts_retained=True,
      full_CAS_cases=52,fixed_native_processes=40,full_crosschecks=2,
      no_eight_MiB_file_or_inventory_gate_added=True)
  status="PASS"
 except BaseException as exc:
  report.update(status="FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  errors=[]
  if project is not None:
   try:report["submitted_source_after"]=file_closure(project)
   except BaseException as exc:errors.append(dict(scope="source",error=repr(exc)))
  for role,pair in pairs.items():
   for kind,row in pair.items():
    try:
     assert identity(row["path"])=={k:row[k] for k in("bytes","sha256")}
     assert stat.S_IMODE(Path(row["path"]).stat().st_mode)==row["mode"]
    except BaseException as exc:errors.append(dict(role=role,kind=kind,error=repr(exc)))
  if carrier_before is not None:
   try:assert identity(carrier)==carrier_before
   except BaseException as exc:errors.append(dict(scope="C_mechanics",error=repr(exc)))
  if errors:status="FAIL";report["status"]="FAIL"
  report["final_source_image_after_check_errors"]=errors;report["actual_source_image_pairs"]=pairs
  report["all_completed_source_image_pairs_before_after_equal"]=not errors
  roots={} if project is None else {"implementation-files":project}
  seal.finish(common,"implementation-files-r1",status,report,roots=roots)
 if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
