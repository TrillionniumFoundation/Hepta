"""Fresh five-image checked-machine-plan CI. No earlier component result is inherited."""
from pathlib import Path
from hashlib import sha1,sha256
import ast,base64,json,os,stat,struct,sys,traceback,types
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
SOURCE_PREFIX=R3+"checked-machine-plan-r1/"
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
SEAL_GIT="2576c7fcec392d71ca57ba9ad3241eb9fccf9aba"
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
COMPONENTS=("snapshot","wire_scan","wire_emit","semantics","controller")
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
WIRE={
 "wire_scan":dict(path="native-edit-candidate-next/development/build-r1/source/59/graph_json_wire_scan.hiaasm",
     bytes=147822,sha256="c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3"),
 "wire_emit":dict(path="native-edit-candidate-next/development/build-r1/source/61/graph_json_wire_emit.hiaasm",
     bytes=173680,sha256="9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2")}
FILES=[
  {
    "path": "tools/hia_checked_machine_plan.py",
    "mode": "100644",
    "bytes": 40924,
    "sha256": "8fd64a521afb771255d112e40fe7586b1c46c69f343fe5bdd6d42e643d205336",
    "gitsha": "f7eac3d992da5855174845e6861f19fa5d115631"
  },
  {
    "path": "tools/hia_checked_plan_controller.py",
    "mode": "100644",
    "bytes": 18316,
    "sha256": "d15c8141db699d1f6df0e6753f6220905903911cf6bd1a01accc41fbbf5103f6",
    "gitsha": "a21bf7ae8f3cc4f3d551fe0ab827f3229c716dda"
  },
  {
    "path": "tools/build_hia_checked_plan.py",
    "mode": "100644",
    "bytes": 11868,
    "sha256": "e834443162d08ef5e29e47bbc9c04f0410b289ffce13fff20f08e35279028fe1",
    "gitsha": "a50b1741eef85ba8416dbc307e345f40bb739f5d"
  },
  {
    "path": "tests/plan_mechanical_harness.py",
    "mode": "100644",
    "bytes": 8732,
    "sha256": "f4c0a87fc178b52b00afb25903ed597de4c886c6d295829b0b36160c7da4c515",
    "gitsha": "bbcab1dd9086bbe83152e7e3a1e3f2dcbc491f32"
  },
  {
    "path": "tests/test_hia_checked_plan.py",
    "mode": "100644",
    "bytes": 49766,
    "sha256": "26c2ccc3f7d6da64934eaeb0547b84df10a515790f404e103e59777d2402b2d2",
    "gitsha": "f0abb87090dd2d24b73e4e760a483622dac589a7"
  },
  {
    "path": "docs/HIA_CHECKED_MACHINE_PLAN_NATIVE.md",
    "mode": "100644",
    "bytes": 19365,
    "sha256": "0e4f6d098f5db7445997202c22c88bc485d0ba97d944a9a57675da0036c3f0bd",
    "gitsha": "e5585a6831e2a84e4dbc7ec99579555ff951a2da"
  },
  {
    "path": "ci/streamed_checked_plan_finish.py",
    "mode": "100644",
    "bytes": 6129,
    "sha256": "eb728a36be4c1e4505337f99b3286bb40747497001d12c035abdf3178c430ad8",
    "gitsha": "2576c7fcec392d71ca57ba9ad3241eb9fccf9aba"
  },
  {
    "path": "evidence/semantic-narrow-static-review.json",
    "mode": "100644",
    "bytes": 5298,
    "sha256": "68fbc9d209a5e9cac6946d7abf7d576ab90fdcc54204e02897db642220fbdfc8",
    "gitsha": "01596fa961251c632d53a6860fffad1f07b77c67"
  },
  {
    "path": "reference/hia_machine_plan.py",
    "mode": "100644",
    "bytes": 13270,
    "sha256": "ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a",
    "gitsha": "61833e8bf8497089461bad9eb2347c82a233e8b2"
  },
  {
    "path": "reference/hia_program.py",
    "mode": "100644",
    "bytes": 45247,
    "sha256": "76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92",
    "gitsha": "5d0027f4453759e4156a3496e64215c441a727e4"
  },
  {
    "path": "reference/hia_selfhost_child.py",
    "mode": "100644",
    "bytes": 6791,
    "sha256": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29",
    "gitsha": "2ecbf3a04680eceee0537cb3d621073bac9c52f4"
  },
  {
    "path": "reference/generate_hia_graph_wire_common.py",
    "mode": "100644",
    "bytes": 13815,
    "sha256": "32ceeceb285f9d3d3250a920c40ebd7bac8e1a44460c5321d714f6f5a0da2b3c",
    "gitsha": "0711ccf18b3838e53b47821c464c3492b802eff6"
  },
  {
    "path": "tests/function_frame_test_reference.py",
    "mode": "100644",
    "bytes": 42184,
    "sha256": "b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6",
    "gitsha": "a7d64f7804753398df08e69158bcebb7afc54747"
  },
  {
    "path": "tools/function_authoring_reference.py",
    "mode": "100644",
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b",
    "gitsha": "6f1bffe8bd815a068f9834489960006cbaad6fac"
  },
  {
    "path": "tools/hia_agent_edit_source_views.py",
    "mode": "100644",
    "bytes": 23950,
    "sha256": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c",
    "gitsha": "f7d123bdb2bf65b25182b571f024299cb0342828"
  },
  {
    "path": "tools/hia_composite_lowering_driver_common.py",
    "mode": "100644",
    "bytes": 17781,
    "sha256": "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1",
    "gitsha": "e56539a9cb76f95010ea6ca995737f40ab6e1850"
  },
  {
    "path": "tools/hia_frozen_ssa_rename.py",
    "mode": "100644",
    "bytes": 2791,
    "sha256": "ceafde9ccf11f5d58de8519821e8b29061de9c967c636a63901735c93f3f419b",
    "gitsha": "13174e28113ed390ba0522e4d39096764fe6cce1"
  }
]
SCHEDULE=[["shape",0,17,0],["fields",0,34,0],["hash",0,8,0],["choices",0,16,0],["choices",1,16,0],["choices",2,16,0],["choices",3,16,0],["choices",4,16,0],["choices",5,16,0],["choices",6,16,0],["choices",7,16,0],["choices",8,16,0],["choices",9,16,0],["choices",10,16,0],["choices",11,16,0],["blocks",0,15,0],["layout",0,10,0],["order",0,17,0],["invalidchoices",0,19,0],["invalidchoices",1,19,0],["assignments",0,24,0],["intervals",0,23,0],["leaf",0,15,0],["leaf",1,15,0],["resources",0,15,0],["resources",1,15,0],["calls",0,4,0],["types",0,38,0],["firsterror",0,16,0],["snapshot",0,34,0],["depth",0,6,0],["digits",0,8,0],["digits",1,8,0],["nodes",0,1,0],["nodes",1,1,0],["bytes",0,1,0],["bytes",1,1,0],["integerbytes",0,1,0],["scale",0,1,0],["scale",1,1,0],["scale",2,1,0],["initial",0,12,12],["initial",1,12,12],["ack",0,10,10],["snapshotprotocol",0,8,8],["snapshotprotocol",1,8,8],["wireprotocol",0,8,8],["wireprotocol",1,8,8],["growprotocol",0,8,8],["growprotocol",1,8,8],["growprotocol",2,2,2],["semanticprotocol",0,8,8],["semanticprotocol",1,8,8],["descriptor",0,13,13],["outputprotocol",0,6,6]]
def digest(raw):return sha256(raw).hexdigest()
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def identity(path):
 h=sha256();n=0
 with Path(path).open("rb") as f:
  while True:
   raw=f.read(1<<18)
   if not raw:break
   h.update(raw);n+=len(raw)
 return dict(bytes=n,sha256=h.hexdigest())
def loaded(name,path,expected):
 raw=Path(path).read_bytes();assert git_blob(raw)==expected,(str(path),git_blob(raw),expected)
 m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m
 exec(compile(raw,str(path),"exec"),m.__dict__);return m,raw
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
 print(label+" "+raw.decode().strip(),flush=True);return value
def gates(build,manifest):
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
 assert p["functions"]<=128 and p["blocks"]<=1536 and p["ops"]<=8192
 assert p["max_blocks"]<=256 and p["max_params"]<=16 and p["max_ssa_index"]<2048
 assert p["max_ssa_index"]+1==p["max_function_values"] and p["max_block_ops"]>=0
 assert r["limits"]["cpu_seconds"]==10 and r["limits"]["address_bytes"]==256<<20
 assert r["runner_sha256"]=="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
 assert r["source_sha256"]==r["input_sha256"]==manifest["source_sha256"]
 assert r["artifact_sha256"]==r["image_sha256"]==COMPILER_SHA
 assert r["produced_sha256"]==manifest["image_sha256"] and r["produced_bytes"]==manifest["image_bytes"]
 assert r["source_unchanged"] and not r["forbidden_compiler_modules_loaded"]
 for kind in("source","image"):
  path=Path(manifest[kind+"_path"])
  assert identity(path)==dict(bytes=manifest[kind+"_bytes"],sha256=manifest[kind+"_sha256"])
  assert 0<manifest[kind+"_bytes"]<=1<<20
 return dict(complete_source_and_mode_snapshots_equal=True,snapshots=len(before),
      original_B3_limits=True,original_profile_gates=True,max_block_ops_recorded_not_gated=True)

def alpha_readback(build,manifest):
 proof=json.loads((build/"full-SSA-alpha-proof.json").read_bytes())
 original=json.loads((build/"original-frozen.document.json").read_bytes())
 revised=json.loads((build/"document.json").read_bytes())
 restored=json.loads(json.dumps(revised))
 assert proof["schema"]=="hia-frozen-HIA-bijective-SSA-rename-v1"
 assert all(proof[k] for k in("original_entire_document_restored_by_inverse","input_document_unmodified",
     "only_SSA_definition_and_use_spellings_changed","operations_types_literals_attributes_labels_and_order_unchanged",
     "original_limits_unchanged","actual_B3_compilation_required","actual_semantic_validation_required"))
 assert identity(build/"original-frozen.hiaasm")==dict(bytes=proof["original_source_bytes"],sha256=proof["original_source_sha256"])
 assert identity(manifest["source_path"])==dict(bytes=proof["revised_source_bytes"],sha256=proof["revised_source_sha256"])
 assert identity(build/"original-frozen.hiaasm")=={k:WIRE[manifest["component"]][k] for k in("bytes","sha256")}
 assert len(proof["functions"])==len(original["functions"])==len(revised["functions"])
 for old,new,restore,row in zip(original["functions"],revised["functions"],restored["functions"],proof["functions"]):
  def defs(fn):
   return [v for b in fn["blocks"] for v in b["params"]+[v for op in b["ops"] for v in op["out"]]]
  old_names=[v["name"] for v in defs(old)];new_names=[v["name"] for v in defs(new)]
  pairs=row["old_to_new"]
  assert [p[0] for p in pairs]==old_names and [p[1] for p in pairs]==new_names
  assert new_names==["v"+str(i) for i in range(len(new_names))]
  assert len(set(old_names))==len(old_names)==row["distinct_definitions"]
  assert row["function"]==old["name"]==new["name"]
  assert row["original_max_numeric_suffix"]==max(int(n[1:]) for n in old_names)
  assert row["revised_max_numeric_suffix"]==len(new_names)-1<2048
  reverse={b:a for a,b in pairs}
  for param in restore["params"]:param["name"]=reverse[param["name"]]
  for block in restore["blocks"]:
   for param in block["params"]:param["name"]=reverse[param["name"]]
   for op in block["ops"]:
    op["args"]=[reverse[n] for n in op["args"]]
    for output in op["out"]:output["name"]=reverse[output["name"]]
   term=block["term"];kind=term["op"]
   if kind=="ret":term["values"]=[reverse[n] for n in term["values"]]
   elif kind=="jump":term["args"]=[reverse[n] for n in term["args"]]
   elif kind=="branch":
    term["cond"]=reverse[term["cond"]]
    for side in("then","else"):term[side]["args"]=[reverse[n] for n in term[side]["args"]]
   else:assert kind=="trap"
 assert restored==original
 return dict(complete_inverse_original_document_equal=True,functions=len(proof["functions"]),
   changed_fields_only_SSA_spelling=True,original_and_revised_sources_retained=True,
   original_profile_limit_retained=True,proof=identity(build/"full-SSA-alpha-proof.json"))

def case_rows(directory,value):
 paths=sorted((directory/"cases").glob("*/result.json"))
 rows=[json.loads(path.read_bytes()) for path in paths]
 assert len(rows)==value["cases"] and all(r["status"]=="PASS" for r in rows)
 assert len({r["label"] for r in rows})==len(rows)
 by_role={str(i):0 for i in range(1,6)};entries=0;private=0;snapshots=0;logical=0
 for path,row in zip(paths,rows):
  count=row["native_entries"];entries+=count
  for role,n in row["by_role"].items():by_role[str(role)]+=n
  if row["kind"]=="PRIVATE_PERMANENT_BAD":
   private+=1;assert row["interceptions"] in(0,1)
  else:
   assert row["kind"]=="ACTUAL_REFERENCE_ADMITTED_CORE_AND_PLAN"
   oracle=json.loads((path.parent/"oracle.json").read_bytes())
   assert oracle["reference_before_native"] and oracle["error"]==row["error"]
   if row["error"] is None:
    raw=(path.parent/"actual.canonical").read_bytes()
    assert raw==(path.parent/"expected.canonical").read_bytes()
    assert (len(raw),digest(raw))==(oracle["canonical_bytes"],oracle["canonical_sha256"])
    assert row["complete_canonical_equal"] and not row["complete_original_error_equal"]
   else:assert row["complete_original_error_equal"] and not row["complete_canonical_equal"]
  evidence=json.loads((path.parent/"evidence.json").read_bytes())
  assert evidence==json.loads((path.parent/"full-CAS/source-after.json").read_bytes())
  assert evidence["status"]=="PASS" and evidence["source_pins_unchanged"] and not evidence["changed"]
  for name in("all_new_pages_decompressed_equal","all_final_pages_rehashed",
          "full_memory_read_before_after_each_entry","delta_pages_reconstruct_identically"):
   assert evidence[name]
  assert evidence["complete_snapshot_descriptors"]==count*6
  snapshots+=evidence["complete_snapshot_descriptors"];logical+=evidence["logical_buffer_bytes"]
  entered=returned=0;pending=None;trace_roles={str(i):0 for i in range(1,6)}
  descriptors={}
  with (path.parent/"full-CAS/snapshots.jsonl").open() as stream:
   for number,line in enumerate(stream):
    d=json.loads(line);assert d["id"]==number and d["page_size"]==4096
    assert d["page_count"]==(d["bytes"]+4095)//4096
    assert d["base"] is None or 0<=d["base"]<number
    descriptors[number]={k:d[k] for k in("id","key","bytes","sha256")}
  assert len(descriptors)==count*6
  with (path.parent/"full-CAS/entries.jsonl").open() as stream:
   for line in stream:
    record=json.loads(line)
    if record["status"]=="MECHANICAL_ACK":
     assert pending is None and len(bytes.fromhex(record["event_hex"]))==128
     assert record["ack"]["bytes"]>=64
     continue
    assert record["status"] in("ENTERING","RETURNED")
    if record["status"]=="ENTERING":
     assert pending is None and record["number"]==entered
     assert len(record["before"])==len(record["capacities"])==len(record["readonly"])==3
     for view,cap in zip(record["before"],record["capacities"]):
      assert view==descriptors[view["id"]] and view["bytes"]==cap
     pending=record;entered+=1
    else:
     assert pending is not None and record["number"]==pending["number"]
     assert record["role"]==pending["role"] and record["before"]==pending["before"]
     assert record["capacities"]==pending["capacities"] and record["readonly"]==pending["readonly"]
     assert record["canaries_intact"] and len(record["after"])==3
     for i,(view,cap) in enumerate(zip(record["after"],record["capacities"])):
      assert view==descriptors[view["id"]] and view["bytes"]==cap
      if record["readonly"][i]:assert view["sha256"]==record["before"][i]["sha256"]
     assert len(bytes.fromhex(record["event_hex"]))==128
     trace_roles[str(record["role"])]+=1;returned+=1;pending=None
  assert pending is None and entered==returned==count and trace_roles=={str(k):v for k,v in row["by_role"].items()}|{str(i):0 for i in range(1,6) if str(i) not in row["by_role"]}
 assert entries==value["native_entries"] and by_role==value["by_role"] and private==value["private_protocol_controls"]
 return dict(cases=len(rows),native_entries=entries,by_role=by_role,private_controls=private,
      complete_before_after_snapshot_descriptors=snapshots,logical_buffer_bytes=logical,
      trace_records_and_originals_correlated=True,all_cases_full_intermediate_CAS=True,
      encoded_CAS_pages_retained_for_complete_archive_readback=True)

def main():
 common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
 common,common_raw=loaded("checked_plan_ci_common",common_path,COMMON_GIT)
 seal_path=Path(__file__).resolve().with_name("streamed_checked_plan_finish.py")
 seal,seal_raw=loaded("checked_plan_stream_seal",seal_path,SEAL_GIT)
 common.PINS[common_path]=common_raw;common.PINS[seal_path]=seal_raw
 common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
 project=None;status="FAIL"
 report=dict(scope="FRESH_CHECKED_MACHINE_PLAN_FIVE_IMAGE_NATIVE_COMPONENT",status="INCOMPLETE",
     planned_groups=55,planned_cases=679,planned_private_controls=119,
     builds={},groups={},actual_compilations=0,actual_cases=0,actual_native_entries=0,actual_private_controls=0,
     old_results_inherited=False,full_public_backend=False,actual_Core_admission_join=False,
     public_foreign_Graph_capture=False,public_Emitter_join=False,
     standalone_preservation_witness_JSON=False,installed=False,cold=False)
 try:
  context=common.prepare()
  mine=Path(context["base"])/"checked-machine-plan-recovery-r2";mine.mkdir()
  project=mine/"native-checked-plan-next";project.mkdir()
  for row in FILES:
   source=common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
   raw=source.read_bytes()
   assert (len(raw),digest(raw),git_blob(raw))==(row["bytes"],row["sha256"],row["gitsha"])
   source.chmod(int(row["mode"],8)&0o777)
  (project/"ci-driver-original.py").write_bytes(Path(__file__).read_bytes())
  assert len(SCHEDULE)==55 and sum(r[2] for r in SCHEDULE)==679 and sum(r[3] for r in SCHEDULE)==119
  tree=ast.parse((project/"tests/test_hia_checked_plan.py").read_bytes())
  schedule_assign=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="SCHEDULE" for t in n.targets))
  assert ast.literal_eval(schedule_assign.value)==SCHEDULE
  env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8")
  roles={};pairs={}
  for i,component in enumerate(COMPONENTS,1):
   build=project/"development"/("build-"+component+"-r2")
   args=[context["python"],"-B",project/"tools/build_hia_checked_plan.py",
     "--reference",context["reference"],"--compiler",context["compiler"],"--out",build,"--component",component]
   if component in WIRE:
    wire=Path(context["workspace"])/WIRE[component]["path"]
    assert identity(wire)=={k:WIRE[component][k] for k in("bytes","sha256")}
    args.extend(["--wire-source",wire])
   try:
    common.run("checked-plan-build-"+component,args,cwd=project,timeout=180,env=env)
   finally:
    value=summary(build,"HIA_CHECKED_PLAN_BUILD_ORIGINAL")
    if value is not None:
     report["builds"][component]=value
     report["actual_compilations"]=sum(x.get("compilations",0) for x in report["builds"].values())
    if build.exists():
     for path in sorted(set(build.rglob("*.stderr"))|set(build.rglob("*.stderr.log"))):
      original(path,"HIA_CHECKED_PLAN_BUILD_STDERR")
     for path in sorted(build.glob("profile-before-gates.json")):
      original(path,"HIA_CHECKED_PLAN_PROFILE_ORIGINAL")
     for path in sorted(build.glob("full-SSA-alpha-proof.json")):
      original(path,"HIA_CHECKED_PLAN_SSA_ALPHA_ORIGINAL")
   value=report["builds"][component]
   assert value["status"]=="PASS_BUILD_ONLY" and value["compilations"]==1
   assert value["actual_limits"]==LIMITS and value["native_semantic_entries"]==0
   assert value["source_pins_unchanged"] and value["original_limits_unchanged"]
   m=value["manifest"]
   assert m["schema"]=="hia-checked-machine-plan-development-component-v1" and m["status"]=="BUILT_ONLY"
   assert m["component"]==component and m["role"]==i and m["compiler_sha256"]==COMPILER_SHA
   assert m["abi_second_readonly"]==(i!=5)
   expected_author=next(r["sha256"] for r in FILES if r["path"]=="tools/"+(
       "hia_checked_plan_controller.py" if component=="controller" else "hia_checked_machine_plan.py"))
   if component in WIRE:expected_author=WIRE[component]["sha256"]
   assert m["author_sha256"]==expected_author
   report["builds"][component]["independent_gate_readback"]=gates(build,m)
   if component in WIRE:
    report["builds"][component]["independent_SSA_inverse_readback"]=alpha_readback(build,m)
   roles[str(i)]=dict(name=component,manifest=m)
   pairs[component]={kind:dict(path=m[kind+"_path"],bytes=m[kind+"_bytes"],sha256=m[kind+"_sha256"],
         mode=stat.S_IMODE(Path(m[kind+"_path"]).stat().st_mode)) for kind in("source","image")}
  assert report["actual_compilations"]==5
  assets=project/"development/runtime-assets.json"
  save(assets,dict(schema="hia-plan-development-runtime-assets-v1",roles=roles,
       actual_fresh_B3_compilations=5,old_results_inherited=False))
  for group,variant,count,private in SCHEDULE:
   label=group+"-"+str(variant);out=project/"development"/("native-"+label+"-r2")
   try:
    common.run("checked-plan-native-"+label,[context["python"],"-B",project/"tests/test_hia_checked_plan.py",
       "--assets",assets,"--reference",context["reference"],"--out",out,"--group",group,"--variant",str(variant)],
       cwd=project,timeout=180,env=env)
   finally:
    value=summary(out,"HIA_CHECKED_PLAN_GROUP_ORIGINAL")
    if value is not None:
     report["groups"][label]=value
     for target,field in(("actual_cases","cases"),("actual_native_entries","native_entries"),("actual_private_controls","private_protocol_controls")):
      report[target]=sum(v.get(field,0) for v in report["groups"].values())
    else:report.setdefault("missing_group_summaries",[]).append(label)
   value=report["groups"][label]
   assert value["status"]=="PASS" and (value["group"],value["variant"])==(group,variant)
   assert (value["cases"],value["private_protocol_controls"])==(count,private)
   assert value["limits"]==dict(**LIMITS,wall=180)
   assert value["source_custody"]["all_bytes_and_modes_equal"] and value["VM_entries"]==0
   assert value["original_group_limits_include_evidence_encoding"]
   assert all(value[k] for k in("each_native_entry_complete_three_operands_before_after",
      "actual_command_ACK_event_full_bytes_retained","guards_and_hardware_readonly_and_canaries"))
   assert not any(value[k] for k in("host_plan_or_canonical_generation_during_native",
       "actual_native_Core_admission_join","public_foreign_graph_capture",
       "public_emitter_join","standalone_preservation_witness_JSON","installed","cold","all_prior_pass_counts_inherited"))
   report["groups"][label]["independent_case_readback"]=case_rows(out,value)
  assert (len(report["groups"]),report["actual_cases"],report["actual_private_controls"])==(55,679,119)
  error_codes=sorted({x for group in report["groups"].values() for x in group["covered_public_error_codes"]})
  assert error_codes==list(range(1,23))
  for component,pair in pairs.items():
   for kind,row in pair.items():
    assert identity(row["path"])=={k:row[k] for k in("bytes","sha256")}
    assert stat.S_IMODE(Path(row["path"]).stat().st_mode)==row["mode"]
  for row in FILES:
   raw=(project/row["path"]).read_bytes()
   assert (len(raw),digest(raw),git_blob(raw))==(row["bytes"],row["sha256"],row["gitsha"])
   assert stat.S_IMODE((project/row["path"]).stat().st_mode)==(int(row["mode"],8)&0o777)
  report.update(status="PASS",all_original_22_error_texts_exercised=True,
      all_five_production_sources_images_before_after_equal=True,actual_source_image_pairs=pairs,
      actual_by_role={str(i):sum(v["by_role"][str(i)] for v in report["groups"].values()) for i in range(1,6)},
      canonical_HIA_document_profile_image_and_receipts_retained=True,
      complete_actual_GraphWire_then_semantics_not_host_forwarding=True,
      all_actual_entry_operands_before_after_full_CAS=True,
      full_original_canonical_and_error_oracle_before_native=True)
  status="PASS"
 except BaseException as error:
  report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  roots={}
  if project is not None and project.exists():roots["checked-plan"]=project
  seal.finish(common,"checked-machine-plan-r2",status,report,roots=roots)
 if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
