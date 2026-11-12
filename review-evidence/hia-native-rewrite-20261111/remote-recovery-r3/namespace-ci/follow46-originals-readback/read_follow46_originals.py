"""Read complete FOLLOW46 cost and unixOpen originals; zero target execution."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,collections,gzip,hashlib,importlib.util,json,os,resource,signal,traceback
from pathlib import Path
HELPER="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/namespace-ci/issued-fs-follow42-readback/read_issued_fs_follow42.py"
HELPER_SHA="a2d0b36d9c739afc202785b2fc3acc488c55c126dac53b78e0a9f41c998b9866"
PINS={
 "cost":dict(artifact=13937805819,run=43204248178,job=131135272544,
  ZIP_bytes=118588521,ZIP_SHA256="54e0cb85babe9313e426ffb836bbb1a7d30497d06622260f08210ce49202ce98",
  archive_bytes=29997720,archive_sha256="84fdcc244bc7067b0f0c5da0f6be03970ddedc8005f8a0d6d3ebf1370d0baaed",
  index_bytes=68196,index_sha256="6e2769197596f4485335140e90222c10f07ddf4e5608040150a189b8efb72a20",
  members=204,raw_bytes=73764799),
 "unixopen":dict(artifact=13937242217,run=43204248178,job=131135272610,
  ZIP_bytes=63067636,ZIP_SHA256="ee8fd8ba0f6bf1fa34eab51ab631b100f2f9f208b1c15283403c7959e8a299ea",
  archive_bytes=5939840,archive_sha256="554b963520fd95c0298b6229cdf45b3b33f8de68af45d44d374dbc13c8cb4450",
  index_bytes=51148,index_sha256="e66ac3cef256ef4ed8d511f22b84ba4e434d725f08ce628de0c580468c4e64b6",
  members=151,raw_bytes=42784321)}
CONSOLE_CAP=1<<20
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def alarm(*_):raise TimeoutError("FOLLOW46 exact original readback wall180")
 signal.signal(signal.SIGALRM,alarm);signal.alarm(180)
 repo=Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
 helper_path=repo/HELPER;helper_raw=helper_path.read_bytes()
 assert sha(helper_raw)==HELPER_SHA
 spec=importlib.util.spec_from_file_location("namespace46_readonly_helpers",helper_path)
 helper=importlib.util.module_from_spec(spec);sys.modules[spec.name]=helper
 exec(compile(helper_raw,str(helper_path),"exec"),helper.__dict__)
 out=Path(os.environ["HIA_NAMESPACE_FOLLOW46_READBACK_OUTPUT"]).absolute()
 out.mkdir(parents=True,exist_ok=False);payload=out/"payload";payload.mkdir()
 work=out.parent/(out.name+"-expanded-355");work.mkdir(exist_ok=False)
 report=dict(schema="hia.namespace.follow46.exact-original-readback.v1",status="INCOMPLETE",
  targets=PINS,new_B3_entries=0,new_VM_entries=0,new_native_entries=0,
  new_target_executions=0,original_900_qualification_results_unchanged=True,
  whole_namespace_closed=False,ordinary_Store_closed=False,
  ZIP_scope="Provider declared digest plus actions/download-artifact transport; only inner archives and members independently byte/mode/SHA/Git verified here.",
  complete_original_copies={},member_readback={},raw_exports=[],after_check_errors=[])
 before=[(helper_path,helper.pin(helper_path)),(Path(__file__).resolve(),helper.pin(Path(__file__).resolve()))]
 primary=None;forests={};raw_to_emit=[];console_bytes=0
 def export(label,row,root,emit=False):
  source=root/row["name"];dest=payload/"exports"/label/row["name"]
  p=helper.copy(source,dest,helper.pin(source))
  entry=dict(target=label,member=row["name"],**p)
  report["raw_exports"].append(entry)
  if emit:raw_to_emit.append((entry,dest))
  return dest
 def one(rows,suffix):
  found=[row for row in rows if row["name"].endswith(suffix)]
  assert len(found)==1,(suffix,[row["name"] for row in found])
  return found[0]
 try:
  for label,p in PINS.items():
   root=Path(os.environ["HIA_NAMESPACE_"+label.upper()+"46_ORIGINALS"]).resolve(strict=True)
   archive,ap=helper.locate(root,"evidence.tar.xz",p["archive_bytes"],p["archive_sha256"])
   index,ip=helper.locate(root,"evidence-members.json",p["index_bytes"],p["index_sha256"])
   before.extend(((archive,ap),(index,ip)))
   helper.copy(archive,payload/"originals"/label/"evidence.tar.xz",ap)
   helper.copy(index,payload/"originals"/label/"evidence-members.json",ip)
   report["complete_original_copies"][label]=dict(archive=ap,index=ip)
   helper.save(out/"summary.json",report)
  # All original archives are retained before any tar or semantic parsing.
  for label,p in PINS.items():
   original=payload/"originals"/label
   helper.PIN=p
   root=work/label;root.mkdir()
   rows=helper.extract(original/"evidence.tar.xz",original/"evidence-members.json",root)
   assert len(rows)==p["members"] and sum(row["bytes"] for row in rows)==p["raw_bytes"]
   helper.save(payload/(label+"-all-members-readback.json"),rows)
   report["member_readback"][label]=dict(members=len(rows),bytes=sum(row["bytes"] for row in rows),
     all_bytes_modes_SHA256_Git_verified=True)
   forests[label]=(root,rows)
   for row in rows:
    name=row["name"]
    if label=="cost":
     selected=("/namespace-reference-cost/" in name and
       (name.endswith(".json") or name.endswith("/full.prof") or "/selected-sources/" in name))
     emit=(name.endswith("/summary.json") or name.endswith("/selection.json")
       or name.endswith("/profile-all-functions.json") or name.endswith("/timed.json")
       or name.endswith("/profiled.json") or name.endswith("/actual-reference-module-pins.json"))
     selected=selected or ("recorded-reference-cost" in name and
       (name.endswith(".log") or name.endswith(".json")))
     emit=emit or ("recorded-reference-cost" in name and name.endswith(".log"))
    else:
     selected="/unixopen-native-parent-r2/" in name and (
       name.endswith("/summary.json") or "/build/" in name or name.endswith("/source-before.json")
       or name.endswith("/source-after.json"))
     emit=name.endswith("/summary.json") and "/unixopen-native-parent-r2/" in name
    if selected:export(label,row,root,emit)
  # Prepare all lossless console chunks before semantic assertions. No truncation.
  emissions=[]
  for entry,path in raw_to_emit:
   raw=path.read_bytes();assert (len(raw),sha(raw))==(entry["bytes"],entry["sha256"])
   compressed=gzip.compress(raw,compresslevel=9,mtime=0)
   assert gzip.decompress(compressed)==raw
   meta=dict(**entry,encoding="gzip+base64",compressed_bytes=len(compressed),
    compressed_sha256=sha(compressed),chunks=(len(compressed)+24575)//24576)
   lines=["HIA_NAMESPACE46_RAW_BEGIN "+json.dumps(meta,sort_keys=True)]
   for offset in range(0,len(compressed),24576):
    lines.append("HIA_NAMESPACE46_RAW_CHUNK "+json.dumps(dict(target=entry["target"],
     member=entry["member"],offset=offset,base64=base64.b64encode(compressed[offset:offset+24576]).decode("ascii")),sort_keys=True))
   lines.append("HIA_NAMESPACE46_RAW_END "+json.dumps(dict(target=entry["target"],member=entry["member"],
    bytes=len(raw),sha256=sha(raw),git_blob_sha1=helper.git(raw)),sort_keys=True))
   emissions.extend(lines)
  console_bytes=sum(len((line+"\n").encode()) for line in emissions)
  assert console_bytes<CONSOLE_CAP-196608,("exact original console payload too large",console_bytes)
  for line in emissions:print(line,flush=True)
  report["complete_raw_console_bytes_before_semantic_parse"]=console_bytes
  helper.save(out/"summary.json",report)
  cost_root,cost_rows=forests["cost"]
  row=one(cost_rows,"/namespace-reference-cost/summary.json")
  raw=(cost_root/row["name"]).read_bytes();cost=json.loads(raw)
  assert cost["status"]=="PASS_COST_DIAGNOSTIC_ONLY"
  assert cost["new_VM_entries"]==36 and len(cost["cases"])==18
  assert cost["new_native_entries"]==cost["new_B3_compiles"]==cost["original_tests_rerun"]==0
  assert cost["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall_seconds=180)
  assert cost["original_members_verified"]==4272 and cost["original_raw_bytes_verified"]==323619640
  assert cost["all_selected_full_outputs_workspaces_and_steps_equal"] and cost["no_mutation_of_reference_VM_methods"]
  assert cost["after_check_errors"]==[]
  report["cost_original_complete_summary_pin"]=dict(member=row["name"],**helper.pin(cost_root/row["name"]))
  stage_totals={};roles={};profiles=[];seen=set()
  for case in cost["cases"]:
   number=case["index"];role=case["role"];assert role in range(1,7) and number not in seen;seen.add(number)
   base="/namespace-reference-cost/cases/"+str(number)+"/"
   timed_row=one(cost_rows,base+"timed.json")
   profiled_row=one(cost_rows,base+"profiled.json")
   stats_row=one(cost_rows,base+"profile-all-functions.json")
   timed=json.loads((cost_root/timed_row["name"]).read_bytes())
   profiled=json.loads((cost_root/profiled_row["name"]).read_bytes())
   functions=json.loads((cost_root/stats_row["name"]).read_bytes())
   assert isinstance(functions,list) and functions
   assert timed==case["timed"]
   for key in ("returned","output_sha256","workspace_sha256","steps","resources","ledger_uncompressed_bytes","ledger_uncompressed_sha256"):
    assert timed[key]==profiled[key],(number,key)
   assert timed["exact_source_unchanged"] and profiled["exact_source_unchanged"]
   rr=roles.setdefault(str(role),dict(windows=0,VM_entries=0,steps=0,unprofiled_stages={},profile_function_totals={}))
   rr["windows"]+=1;rr["VM_entries"]+=2;rr["steps"]+=timed["steps"]
   for name,times in timed["stages"].items():
    for dest in (stage_totals,rr["unprofiled_stages"]):
     total=dest.setdefault(name,dict(cpu_ns=0,wall_ns=0))
     for key in ("cpu_ns","wall_ns"):total[key]+=times[key]
   for function in functions:
    key=json.dumps([function["file"],function["line"],function["function"]],separators=(",",":"))
    aggregate=rr["profile_function_totals"].setdefault(key,dict(file=function["file"],
     line=function["line"],function=function["function"],primitive_calls=0,total_calls=0,self_seconds=0.0,cumulative_seconds=0.0))
    for field in ("primitive_calls","total_calls","self_seconds","cumulative_seconds"):aggregate[field]+=function[field]
   ordered=sorted(functions,key=lambda f:(-f["self_seconds"],f["file"],f["line"],f["function"]))
   profiles.append(dict(index=number,role=role,trace=case["trace"],offset=case["offset"],
    timed=timed,profile_function_count=len(functions),profile_by_self_top=ordered[:12],
    profile_by_cumulative_top=functions[:12],original_profile_json=dict(member=stats_row["name"],**helper.pin(cost_root/stats_row["name"]))))
  assert seen==set(range(18)) and set(roles)==set(map(str,range(1,7)))
  assert stage_totals==cost["stage_totals"]
  for rr in roles.values():
   functions=list(rr.pop("profile_function_totals").values())
   rr["profile_by_self_top"]=sorted(functions,key=lambda f:(-f["self_seconds"],f["file"],f["line"],f["function"]))[:15]
   rr["profile_by_cumulative_top"]=sorted(functions,key=lambda f:(-f["cumulative_seconds"],f["file"],f["line"],f["function"]))[:15]
  report["cost"]=dict(new_VM_entries=36,new_native_entries=0,new_B3_compiles=0,
   selected_windows=18,roles=roles,unprofiled_stage_totals=stage_totals,
   interpretation="These are selected recorded windows only. Profiled cumulative times overlap caller/callee; gzip subtimes overlap their total. No whole-suite attribution or performance extrapolation.")
  helper.save(payload/"cost-all-window-analysis.json",profiles)
  unix_root,unix_rows=forests["unixopen"]
  top_row=one(unix_rows,"/unixopen-native-parent-r2/summary.json")
  top=json.loads((unix_root/top_row["name"]).read_bytes())
  assert top["status"]=="PASS_COMPONENT_ONLY" and top["inputs_unchanged"] is True
  assert top["source_changes"]==[]
  assert top["actual_counts"]==dict(fresh_HIA_B3_compiles=1,fresh_original_C_library_builds=1,
   complete_semantic_cases=85,original_C_returned_calls=88,protocol_setup_original_C_call=1,
   additional_protocol_full_semantic_cases=2,protocol_controls=42,fresh_VM_entries=833,
   fresh_native_entries=833,namespace_syscalls=0)
  report["unixopen_original_complete_summary_pin"]=dict(member=top_row["name"],**helper.pin(unix_root/top_row["name"]))
  build_row=one(unix_rows,"/unixopen-native-parent-r2/build/summary.json")
  built=json.loads((unix_root/build_row["name"]).read_bytes())
  assert built["status"]=="PASS_BUILD_ONLY" and built["fresh_B3_compiles"]==1
  assert built["profile"]==dict(functions=33,blocks=578,ops=2419,max_blocks=93,max_block_params=13)
  canonical=[]
  for kind,item in (("document",built["document"]),("canonical_source",built["canonical_source"]),
    ("native_image",dict(bytes=built["compile_receipt"]["produced_bytes"],sha256=built["compile_receipt"]["produced_sha256"]))):
   found=[r for r in unix_rows if (r["bytes"],r["sha256"])==(item["bytes"],item["sha256"])]
   assert found,(kind,item)
   for member in found:
    src=unix_root/member["name"]
    helper.copy(src,payload/"canonical-unixopen"/kind/member["name"],helper.pin(src))
   canonical.append(dict(kind=kind,pin=dict(bytes=item["bytes"],sha256=item["sha256"]),members=found))
  totals=dict(C_cases=0,VM_entries=0,native_entries=0,protocol_controls=0)
  names=[]
  rows=[r for r in unix_rows if "/unixopen-native-parent-r2/" in r["name"] and r["name"].endswith("/summary.json")
   and any(("/"+part+"/") in r["name"] for part in ("protocol","build"))]
  semantic=[r for r in unix_rows if "/unixopen-native-parent-r2/semantic-" in r["name"] and r["name"].endswith("/summary.json")]
  assert len(semantic)==9
  protocol_row=one(unix_rows,"/unixopen-native-parent-r2/protocol/summary.json")
  for r in [*semantic,protocol_row]:
   body=json.loads((unix_root/r["name"]).read_bytes())
   assert body["status"]=="PASS" and body["source_pins_unchanged"]
   assert body["all_complete_return_output_workspace_bytes_equal"] and body["all_native_source_readonly_and_canaries"]
   assert body["actual_namespace_syscalls"]==body["actual_issued_namespace_authorities"]==0
   assert body["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
   assert not body["native_VM_byte_masking"] and not body["inherited_counts"]
   if body["mode"]=="semantic":names.extend(body["cases_completed"])
   for key in totals:totals[key]+=body[key]
  assert len(names)==len(set(names))==85
  assert totals==dict(C_cases=88,VM_entries=833,native_entries=833,protocol_controls=42)
  report["unixopen"]=dict(counts=top["actual_counts"],canonical=canonical,semantic_names=names,
   all_complete_original_component_reports_verified=True,
   foreign_effects=18,ordinary_Store_closed=False,actual_namespace_syscalls=0)
  report["status"]="PASS_READBACK_ONLY"
 except BaseException as error:
  primary=error;report.update(status="FAIL_READBACK",error=repr(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  for path,pin in before:
   try:assert helper.pin(path)==pin
   except BaseException as error:report["after_check_errors"].append(dict(path=str(path),error=repr(error)))
  if report["after_check_errors"]:report["status"]="FAIL_READBACK"
  report["all_inputs_unchanged"]=bool(before) and not report["after_check_errors"]
  helper.save(out/"summary.json",report);helper.save(payload/"readback-summary.json",report)
  try:
   seal=helper.seal(out);report["new_readonly_seal"]=seal;helper.save(out/"summary.json",report)
  except BaseException as error:
   report.update(status="FAIL_READBACK",seal_error=repr(error))
   helper.save(out/"summary.json",report)
   if primary is not None:primary.add_note("seal: "+repr(error))
   else:traceback.print_exc()
  console=json.dumps(report,sort_keys=True)
  if console_bytes+len(console.encode())+64<CONSOLE_CAP:
   print("HIA_NAMESPACE46_READBACK "+console,flush=True)
  else:
   compact={key:report.get(key) for key in ("status","error","traceback","member_readback","after_check_errors","all_inputs_unchanged","new_readonly_seal")}
   raw=(out/"summary.json").read_bytes();compact["complete_summary_pin"]=dict(bytes=len(raw),sha256=sha(raw),git_blob_sha1=helper.git(raw))
   print("HIA_NAMESPACE46_READBACK_CONSOLE_ONLY_SUMMARY "+json.dumps(compact,sort_keys=True),flush=True)
  signal.alarm(0)
 return 0 if report["status"]=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
