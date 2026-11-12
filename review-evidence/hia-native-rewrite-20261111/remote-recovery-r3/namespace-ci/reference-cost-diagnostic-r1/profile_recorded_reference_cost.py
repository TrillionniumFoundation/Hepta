"""Bounded cost diagnosis of exact recorded FOLLOW42 VM windows.
No native image is entered and no qualification/test-suite result is produced.
Every original member is verified before selecting at most three recorded
windows per role: first, last, and largest total logical input/output/workspace.
The retained CoreVM, instruction budget and full-byte checks are unchanged.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,cProfile,ctypes,gzip,hashlib,importlib.util,json,os,pstats,resource,signal,stat,struct,time,traceback
from pathlib import Path
REF_COMMIT="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
READER_SHA="a2d0b36d9c739afc202785b2fc3acc488c55c126dac53b78e0a9f41c998b9866"
def sha(b):return hashlib.sha256(b).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def load(name,path,expected):
 raw=path.read_bytes();assert sha(raw)==expected
 spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec)
 sys.modules[name]=mod;exec(compile(raw,str(path),"exec"),mod.__dict__);return mod
def limits():
 parent=os.getppid();libc=ctypes.CDLL(None,use_errno=True)
 assert libc.prctl(1,9,0,0,0)==0
 if os.getppid()!=parent:os._exit(112)
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("diagnostic wall180")))
 signal.alarm(180)
 return dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall_seconds=180)
def clock():return time.process_time_ns(),time.monotonic_ns()
def elapsed(start):
 cpu,wall=clock();return dict(cpu_ns=cpu-start[0],wall_ns=wall-start[1])
def scan(path,relative,magic):
 before=path.stat().st_size;waiting={};items=[];offset=0
 with path.open("rb") as stream:
  while offset<before:
   header=stream.read(96);assert len(header)==96
   h=struct.unpack("<12Q",header);role=magic.get(h[0])
   assert role in range(1,7) and h[10]==role and h[11]==0
   kind=h[1];assert kind in (1,2,3,4)
   lengths=([h[3],h[4],h[5]] if kind==1 else [h[4],h[5]] if kind==2 else [h[3]] if kind==3 else [])
   size=sum(lengths);assert size<=before-offset-96
   row=dict(trace=relative,offset=offset,header=list(h),bytes=size+96,role=role)
   key=(role,h[8],h[9],h[2])
   if kind==1:
    assert key not in waiting;waiting[key]=row
   elif kind==2:
    assert key in waiting
    pre=waiting.pop(key);pre["post"]=row;items.append(pre)
   stream.seek(size,1);offset+=96+size
 assert offset==before
 return items
def select(candidates):
 chosen={}
 for role in range(1,7):
  rows=[r for r in candidates if r["role"]==role];assert rows
  groups=(("first",rows[0]),("last",rows[-1]),("largest-logical-bytes",max(rows,key=lambda x:sum(x["header"][3:6]))))
  for why,row in groups:
   key=(row["trace"],row["offset"])
   if key not in chosen:chosen[key]=dict(row,reasons=[])
   chosen[key]["reasons"].append(why)
 return sorted(chosen.values(),key=lambda r:(r["role"],r["trace"],r["offset"]))
def read_record(trace,row):
 with trace.open("rb") as stream:
  stream.seek(row["offset"]);data=stream.read(row["bytes"])
 assert len(data)==row["bytes"] and struct.unpack_from("<12Q",data)==tuple(row["header"])
 lengths=row["header"][3:6] if row["header"][1]==1 else row["header"][4:6]
 parts=[];at=96
 for n in lengths:parts.append(data[at:at+n]);at+=n
 assert at==len(data)
 return data,parts
def one(program,case,folder,Machine,Owner,View,profile):
 stages={};start=clock()
 original,preout,prework=case["parts"];expected_output,expected_work=case["postparts"]
 owners=[Owner(-1,bytearray(original)),Owner(-2,bytearray(preout)),Owner(-3,bytearray(prework))]
 views=[View(owners[0],False),View(owners[1],True),View(owners[2],True)]
 stages["owners_views_full_copy"]=elapsed(start)
 start=clock();machine=Machine(program,4_000_000,32<<20,None,64)
 stages["fresh_Machine_including_first_as_dict"]=elapsed(start)
 start=clock();entry=program.as_dict()["functions"][0]
 stages["second_as_dict_select_entry"]=elapsed(start)
 start=clock();actual=machine.invoke(entry,views)[0]
 stages["retained_VM_invoke"]=elapsed(start)
 start=clock();out=bytes(owners[1].data);work=bytes(owners[2].data)
 assert bytes(owners[0].data)==original
 assert actual==case["post"]["header"][6],(actual,case["post"]["header"])
 assert out==expected_output and work==expected_work
 stages["full_input_output_workspace_compare"]=elapsed(start)
 start=clock()
 result=dict(role=case["role"],trace=case["trace"],offset=case["offset"],returned=actual,
  input_hex=original.hex(),pre_output_hex=preout.hex(),pre_workspace_hex=prework.hex(),
  output_hex=out.hex(),post_workspace_hex=work.hex())
 wire=(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n").encode()
 stages["full_hex_and_JSON_encode"]=elapsed(start)
 output=folder/("profile-ledger.jsonl.gz" if profile else "timed-ledger.jsonl.gz")
 start=clock()
 with gzip.open(output,"wb",compresslevel=9) as stream:
  stream.write(wire);after_write=elapsed(start)
  flush_start=clock();stream.flush();flush_cost=elapsed(flush_start)
 stages["gzip_open_write_before_flush"]=after_write
 stages["gzip_explicit_flush"]=flush_cost
 stages["gzip_full_open_write_flush_close"]=elapsed(start)
 assert gzip.decompress(output.read_bytes())==wire
 observation=dict(stages=stages,steps=machine.steps,resources=machine.resources(),
  exact_source_unchanged=program.canonical_bytes==case["canonical_bytes"],
  returned=actual,output_sha256=sha(out),workspace_sha256=sha(work),
  ledger_uncompressed_bytes=len(wire),ledger_uncompressed_sha256=sha(wire),
  ledger_bytes=output.stat().st_size,ledger_sha256=sha(output.read_bytes()),
  gzip_scope="Per-window level9 write/explicit flush/close; original42 shared stream does not flush per entry. Not extrapolated as whole-run gzip timing.")
 assert observation["exact_source_unchanged"]
 return observation
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--context",required=True);ap.add_argument("--reader",required=True);args=ap.parse_args()
 context_path=Path(args.context).resolve();context_raw=context_path.read_bytes();c=json.loads(context_raw)
 assert sys.version_info[:3]==(3,12,14) and os.environ.get("GITHUB_ACTIONS")=="true"
 actual_limits=limits()
 reader_path=Path(args.reader).resolve();helper=load("namespace_cost_original_reader",reader_path,READER_SHA)
 ref=Path(c["reference"]).resolve();out=Path(c["cost_output"]);out.mkdir(mode=0o700,parents=True,exist_ok=False)
 work=Path(c["cost_work"]);work.mkdir(mode=0o700,parents=True,exist_ok=False)
 root=Path(os.environ["HIA_NAMESPACE_COST_ORIGINALS"]).resolve(strict=True)
 report=dict(status="INCOMPLETE",scope="RECORDED_REFERENCE_COST_DIAGNOSTIC_NOT_QUALIFICATION",
  original_qualifications_unchanged=True,actual_limits=actual_limits,reference=REF_COMMIT,
  new_B3_compiles=0,new_native_entries=0,new_VM_entries=0,
  original_budget_replacements=0,original_tests_rerun=0,cases=[],sources={})
 controls=[];after_errors=[]
 helper.copy(context_path,out/"context-original.json")
 helper.copy(Path(__file__).resolve(),out/"diagnostic-source.py")
 helper.copy(reader_path,out/"reader-source.py")
 save(out/"summary.json",report)
 try:
  archive,archive_pin=helper.locate(root,"evidence.tar.xz",helper.PIN["archive_bytes"],helper.PIN["archive_sha256"])
  index,index_pin=helper.locate(root,"evidence-members.json",helper.PIN["index_bytes"],helper.PIN["index_sha256"])
  controls.extend([(archive,archive_pin),(index,index_pin),(reader_path,helper.pin(reader_path)),(Path(__file__).resolve(),helper.pin(Path(__file__).resolve()))])
  helper.copy(archive,out/"original-evidence.tar.xz",archive_pin)
  helper.copy(index,out/"original-evidence-members.json",index_pin)
  report["complete_original_archive_preserved_before_parse"]=True;save(out/"summary.json",report)
  members=work/"members";checked=helper.extract(archive,index,members)
  save(out/"complete-original-member-readback.json",checked)
  report["original_members_verified"]=len(checked)
  report["original_raw_bytes_verified"]=sum(r["bytes"] for r in checked)
  assert len(checked)==4272 and report["original_raw_bytes_verified"]==323619640
  by_name={row["name"]:row for row in checked}
  build_name="run/namespace-db-physical-join-r1/db-join-build-r1/summary.json"
  build_raw=(members/build_name).read_bytes()
  assert (len(build_raw),sha(build_raw))==helper.REPORTS[build_name]
  built=json.loads(build_raw);assert built["status"]=="PASS_BUILD_ONLY" and built["fresh_role_compiles"]==6
  (out/"original-build-summary.json").write_bytes(build_raw)
  sys.path.insert(0,str(ref))
  from hepta.hia_agent_assembly import assemble_program
  import hepta.hia_program_runtime as runtime
  import hepta.hia_program as program_module
  assert Path(runtime.__file__).resolve()==ref/"hepta/hia_program_runtime.py"
  programs={};documents={}
  for role in range(1,7):
   row=built["exact_roles"][str(role)]
   for label in ("source","image"):
    item=row[label]
    names=[name for name,p in by_name.items() if p["bytes"]==item["bytes"] and p["sha256"]==item["sha256"]]
    assert names,(role,label,item)
    values=[(members/name).read_bytes() for name in names]
    assert all(value==values[0] for value in values)
    target=out/"selected-sources"/("role-"+str(role)+(".hiaasm" if label=="source" else ".image.bin"))
    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(values[0])
    report["sources"][str(role)+"-"+label]=dict(original_members=names,pin=helper.pin(target))
    controls.append((target,helper.pin(target)))
    if label=="source":source=values[0]
   start=clock();programs[role]=assemble_program(source)
   report["sources"][str(role)+"-assembly"]=elapsed(start)
   documents[role]=programs[role].as_dict()
   (out/"selected-sources"/("role-"+str(role)+".canonical.json")).write_bytes(programs[role].canonical_bytes)
  runtime_pins=[]
  for module in tuple(sys.modules.values()):
   filename=getattr(module,"__file__",None)
   if filename:
    path=Path(filename).resolve()
    if path.is_relative_to(ref) and path.suffix==".py":
     row=helper.pin(path);controls.append((path,row));runtime_pins.append(dict(path=path.relative_to(ref).as_posix(),**row))
  save(out/"actual-reference-module-pins.json",runtime_pins)
  base=members/"run/namespace-db-physical-join-r1/db-join-native-r1"
  candidates=[]
  for path in sorted(base.glob("test_*/native-*/trace.bin")):
   candidates.extend(scan(path,path.relative_to(base).as_posix(),helper.MAGICS))
  selected=select(candidates)
  assert 6<=len(selected)<=18
  report["candidate_complete_native_windows"]=len(candidates)
  report["selection"]="Deterministic first/last/largest logical window per role, deduplicated; completed original native windows only."
  save(out/"selection.json",selected)
  for number,case in enumerate(selected):
   folder=out/"cases"/str(number);folder.mkdir(parents=True)
   pre,parts=read_record(base/case["trace"],case)
   post,postparts=read_record(base/case["trace"],case["post"])
   (folder/"original-pre-record.bin").write_bytes(pre);(folder/"original-post-record.bin").write_bytes(post)
   complete=dict(case,parts=parts,postparts=postparts,canonical_bytes=programs[case["role"]].canonical_bytes)
   progress=dict(index=number,selection=case,status="ABOUT_TO_INVOKE_UNPROFILED",new_VM_entries=report["new_VM_entries"])
   save(out/"frontier.json",progress)
   timed=one(programs[case["role"]],complete,folder,runtime._Machine,runtime._Owner,runtime._View,False)
   report["new_VM_entries"]+=1;save(folder/"timed.json",timed)
   progress.update(status="ABOUT_TO_INVOKE_CPROFILE",new_VM_entries=report["new_VM_entries"]);save(out/"frontier.json",progress)
   profiler=cProfile.Profile();profiler.enable()
   profiled=one(programs[case["role"]],complete,folder,runtime._Machine,runtime._Owner,runtime._View,True)
   profiler.disable();profiler.dump_stats(str(folder/"full.prof"))
   report["new_VM_entries"]+=1;save(folder/"profiled.json",profiled)
   for key in ("returned","output_sha256","workspace_sha256","steps","resources","ledger_uncompressed_bytes","ledger_uncompressed_sha256"):
    assert timed[key]==profiled[key],(number,key)
   stats=pstats.Stats(profiler)
   all_stats=[dict(file=k[0],line=k[1],function=k[2],primitive_calls=v[0],total_calls=v[1],self_seconds=v[2],cumulative_seconds=v[3]) for k,v in stats.stats.items()]
   all_stats.sort(key=lambda r:(-r["cumulative_seconds"],r["file"],r["line"],r["function"]))
   save(folder/"profile-all-functions.json",all_stats)
   report["cases"].append(dict(index=number,role=case["role"],trace=case["trace"],offset=case["offset"],reasons=case["reasons"],
    original_record_sha256=sha(pre),original_post_sha256=sha(post),timed=timed,profile_top=all_stats[:25]))
   save(out/"summary.json",report)
  assert report["new_VM_entries"]==2*len(selected)
  assert all(programs[role].as_dict()==documents[role] for role in range(1,7))
  stage_totals={}
  for case in report["cases"]:
   for key,v in case["timed"]["stages"].items():
    totals=stage_totals.setdefault(key,dict(cpu_ns=0,wall_ns=0))
    for which in totals:totals[which]+=v[which]
  report.update(status="PASS_COST_DIAGNOSTIC_ONLY",stage_totals=stage_totals,
   all_selected_full_outputs_workspaces_and_steps_equal=True,
   no_mutation_of_reference_VM_methods=True,
   measured_limits="All selected diagnostic windows share one90CPU/180wall/1GiB process. Existing900 aggregate suites were not executed or replaced.",
   inference_scope="Selected recorded windows only. No attribution of unobserved in-flight operation and no whole-run performance extrapolation.")
 except BaseException as error:
  report.update(status="FAIL_DIAGNOSTIC",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  for path,before in controls:
   try:
    after=helper.pin(path);assert before==after
   except BaseException as error:after_errors.append(dict(path=str(path),error=repr(error)))
  if context_path.read_bytes()!=context_raw:after_errors.append(dict(path=str(context_path),error="changed"))
  report["after_check_errors"]=after_errors
  if after_errors:report["status"]="FAIL_DIAGNOSTIC"
  save(out/"summary.json",report)
  console={k:report[k] for k in ("status","scope","actual_limits","original_qualifications_unchanged","new_B3_compiles","new_native_entries","new_VM_entries","original_tests_rerun","after_check_errors")}
  console.update(stage_totals=report.get("stage_totals"),cases=len(report["cases"]),
   summary_sha256=sha((out/"summary.json").read_bytes()),error=report.get("error"),traceback=report.get("traceback"))
  print("HIA_NAMESPACE_REFERENCE_COST "+json.dumps(console,sort_keys=True),flush=True)
  signal.alarm(0)
 return 0 if report["status"]=="PASS_COST_DIAGNOSTIC_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
