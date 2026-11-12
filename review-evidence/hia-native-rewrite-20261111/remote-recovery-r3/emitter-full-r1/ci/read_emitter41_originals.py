"""Zero-target-execution, exact FOLLOW41 Emitter archive/readback.

This reader never imports a product module, loads native images or runs a child.
It validates every archived byte/mode, then retains the complete original group
summaries, case results and exact eleven source/image pairs for the new tail CI.
Compressed evidence members are preserved by their exact bytes; their original
logical-buffer decoding checks remain the original run's checks, not a new claim.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha256
import argparse,json,os,resource,signal,stat,sys,tarfile,time,traceback
BASELINE_SHA="7484b1d6640dde68f748beb928574d601dbce3c3a352465e95b3f5d9bc8cfe26"
OLD_PREFIX="/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/complete-emitter-recovery-r3/native-emitter-next/"
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def identity(path):
 path=Path(path);info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
 h=sha256();size=0
 with path.open("rb") as f:
  while True:
   block=f.read(1<<18)
   if not block:break
   h.update(block);size+=len(block)
 after=path.lstat()
 assert (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==(
     after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
 return dict(bytes=size,sha256=h.hexdigest(),mode=stat.S_IMODE(info.st_mode))
def archive_name(path):
 assert type(path) is str and path.startswith(OLD_PREFIX)
 return "emitter-full/"+path[len(OLD_PREFIX):]
def safe(name):
 p=PurePosixPath(name)
 assert name and not p.is_absolute() and all(x not in("","..",".") for x in p.parts)
 assert p.as_posix()==name
 return p
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def expired(*args):raise TimeoutError("original-emitter exact readback exceeded 180 wall seconds")
 signal.signal(signal.SIGALRM,expired);signal.alarm(180)
 parser=argparse.ArgumentParser()
 for name in("artifact-directory","baseline","out"):parser.add_argument("--"+name,type=Path,required=True)
 args=parser.parse_args();args.out=args.out.resolve();args.out.mkdir(parents=True,exist_ok=False)
 started=time.monotonic();report=dict(status="INCOMPLETE",scope="EXACT_FOLLOW41_READONLY_ALL_MEMBER_READBACK",
     native_entries=0,VM_entries=0,product_imports=0,subprocesses=0,compressed_logical_buffers_replayed=False,
     original_failed_run_remains_failed=True,old_test_results_inherited=False,
     complete_original_encoded_inputs_preserved=False,full_tar_readback_completed=False)
 inputs={}
 try:
  assert sys.version_info[:3]==(3,12,14)
  baseline_raw=args.baseline.read_bytes();assert digest(baseline_raw)==BASELINE_SHA
  baseline=json.loads(baseline_raw);inputs[str(args.baseline.resolve())]=identity(args.baseline)
  meta=baseline["artifact"]
  artifact_root=args.artifact_directory.resolve()
  assert artifact_root.is_dir()
  # download-artifact may add its artifact-name directory. Content pins, not
  # that packaging directory, identify the unique exact original input.
  def locate(relative):
   candidates=[p for p in artifact_root.rglob(Path(relative).name) if p.is_file()]
   assert len(candidates)==1,(relative,[str(p) for p in candidates])
   return candidates[0]
  archive=locate(meta["archive"]);ledger=locate(meta["ledger"])
  inputs[str(archive.resolve())]=identity(archive);inputs[str(ledger.resolve())]=identity(ledger)
  assert (inputs[str(archive.resolve())]["bytes"],inputs[str(archive.resolve())]["sha256"])==(meta["archive_bytes"],meta["archive_sha256"])
  assert (inputs[str(ledger.resolve())]["bytes"],inputs[str(ledger.resolve())]["sha256"])==(meta["ledger_bytes"],meta["ledger_sha256"])
  encoded_originals=[]
  report["full_original_archive_and_ledger_copies"]=encoded_originals
  original_dir=args.out/"complete-original-archive";original_dir.mkdir()
  for source in(archive,ledger):
   target=original_dir/source.name
   with source.open("rb") as src,target.open("xb") as dst:
    while True:
     block=src.read(1<<18)
     if not block:break
     dst.write(block)
   target.chmod(inputs[str(source.resolve())]["mode"])
   assert identity(target)==inputs[str(source.resolve())]
   with source.open("rb") as src,target.open("rb") as dst:
    while True:
     block=src.read(1<<18)
     assert dst.read(len(block))==block
     if not block:break
    assert not dst.read(1)
   encoded_originals.append(dict(source=str(source),copy=str(target),**identity(target)))
  report["complete_original_encoded_inputs_preserved"]=True
  expected_source_images={}
  for component,m in baseline["actual_manifests"].items():
   for kind in("source","image"):
    name=archive_name(m[kind+"_path"])
    expected_source_images[name]=(component,kind,{"bytes":m[kind+"_bytes"],"sha256":m[kind+"_sha256"]})
  assert len(expected_source_images)==22
  c_name=archive_name(baseline["actual_C_build"]["full_executable"]["path"])
  selected={};infos={};seen=set();members=0;total=0;preserved=[]
  prefix="emitter-full/development/"
  with ledger.open("r",encoding="utf-8") as index,tarfile.open(archive,"r|xz") as tf:
   for item in tf:
    line=index.readline();assert line
    row=json.loads(line);name=item.name;safe(name)
    assert name==row["name"] and name not in seen and item.isfile() and not item.issym() and not item.islnk()
    seen.add(name)
    assert item.size==row["bytes"] and item.mode==row["mode"]
    is_build=name.startswith(prefix+"build-")
    is_native=name.startswith(prefix+"native-")
    keep=name in expected_source_images or name in(c_name,"run/summary.json",c_name+".build.json")
    keep=keep or (name.startswith(prefix) and name.endswith("/summary.json") and "/cases/" not in name)
    keep=keep or (is_build and name.endswith(("/emitter.manifest.json","/bundle.json","/source-before.json","/source-after.json")))
    keep=keep or (is_native and name.endswith("/source-before-after.json"))
    keep=keep or (is_native and "/cases/" in name and name.endswith("/result.json"))
    keep=keep or (is_native and "/sources/" in name and name.endswith("/runtime-assets.json"))
    keep=keep or name==archive_name(baseline["actual_C_build"]["source"])
    if keep:
     target=args.out/"preserved"/safe(name);target.parent.mkdir(parents=True,exist_ok=True)
     output=target.open("xb")
    else:target=None;output=None
    h=sha256();size=0
    try:
     with tf.extractfile(item) as stream:
      while True:
       block=stream.read(1<<18)
       if not block:break
       h.update(block);size+=len(block)
       if output is not None:output.write(block)
    finally:
     if output is not None:output.close()
    assert size==row["bytes"] and h.hexdigest()==row["sha256"],name
    info=dict(bytes=size,sha256=h.hexdigest(),mode=item.mode)
    if is_build or (is_native and "/sources/" in name):infos[name]=info
    if target is not None:
     target.chmod(item.mode);assert identity(target)==info
     preserved.append(dict(name=name,path=str(target),**info))
     if name.endswith(".json"):
      selected[name]=json.loads(target.read_bytes())
    if name in expected_source_images:
     assert {k:info[k] for k in("bytes","sha256")}==expected_source_images[name][2]
    if name==c_name:
     assert {k:info[k] for k in("bytes","sha256")}==baseline["actual_C_build"]["executable"]
    members+=1;total+=size;tf.members.clear()
   assert not index.readline()
  assert members==meta["members"] and total==meta["original_bytes"]
  report["full_tar_readback_completed"]=True
  assert set(expected_source_images)<=seen and c_name in seen
  old=selected["run/summary.json"]
  assert old["status"]=="FAIL" and old["scope"]=="emitter-full-r3-tail11"
  assert old["frozen_source_and_reference_before_after_equal"] and old["submitted_script_pins_before_after_equal"]
  actual_groups={};all_results={};actual_roles={str(i):0 for i in range(1,12)}
  for row in baseline["planned_all_55"]:
   group,variant,count,private=row;label=group+"-"+str(variant)
   root=prefix+"native-"+label+"-r3"
   summary_name=root+"/summary.json"
   if summary_name not in selected:continue
   value=selected[summary_name]
   assert value==next(x for x in baseline["actual_groups"] if (x["group"],x["variant"])==(group,variant))
   actual_groups[label]=value
   results={name:item for name,item in selected.items() if name.startswith(root+"/cases/") and name.endswith("/result.json")}
   assert len(results)==value["cases"] and all(x["status"]=="PASS" for x in results.values())
   assert len({x["label"] for x in results.values()})==len(results)
   assert sum(x["native_entries"]+x.get("crosscheck_native_entries",0) for x in results.values())==value["native_entries"]
   cats={}
   for r in results.values():cats[r["kind"]]=cats.get(r["kind"],0)+1
   assert cats==value["case_categories"]
   roles={str(i):0 for i in range(1,12)}
   for result in results.values():
    for field in("by_role","crosscheck_by_role"):
     for role,n in result.get(field,{}).items():roles[str(role)]+=n
   assert roles==value["by_role"]
   for role,n in roles.items():actual_roles[role]+=n
   assert value["limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
   assert value["source_custody"]["all_bytes_and_modes_equal"]
   if value["status"]=="PASS":
    assert (value["cases"],value["private_protocol_controls"])==(count,private)
   run_value=old["details"]["groups"][label]
   assert all(run_value[k]==v for k,v in value.items())
   custody=selected[root+"/source-before-after.json"]
   assert len(custody)==value["source_custody"]["files"] and all(x["same"] for x in custody)
   for i,item in enumerate(custody,1):
    name=root+"/sources/"+str(i)+"/"+Path(item["path"]).name
    assert infos[name]=={k:item[k] for k in("bytes","sha256","mode")},name
   by_path={item["path"]:(i,item) for i,item in enumerate(custody,1)}
   assert len(by_path)==len(custody)
   old_test=by_path[OLD_PREFIX+"tests/test_hia_complete_emitter.py"][1]
   assert {k:old_test[k] for k in("bytes","sha256")}=={
       k:baseline["first_failure"]["old_test_source"][k] for k in("bytes","sha256")}
   for component,manifest in baseline["actual_manifests"].items():
    for kind in("source","image"):
     issued=by_path[manifest[kind+"_path"]][1]
     assert (issued["bytes"],issued["sha256"])==(manifest[kind+"_bytes"],manifest[kind+"_sha256"])
   at,asset_pin=by_path[OLD_PREFIX+"development/runtime-assets.json"]
   issued_assets=selected[root+"/sources/"+str(at)+"/runtime-assets.json"]
   assert set(issued_assets["roles"])=={str(i) for i in range(1,12)}
   assert issued_assets["actual_fresh_B3_compilations"]==11 and not issued_assets["old_results_inherited"]
   for component,manifest in baseline["actual_manifests"].items():
    assert issued_assets["roles"][str(manifest["role"])]==dict(name=component,manifest=manifest)
   all_results[label]=results
  assert len(actual_groups)==3
  failed=actual_groups["late-6"]
  assert (failed["status"],failed["cases"],failed["native_entries"],failed["error_class"],failed["error"])==(
      "FAIL",0,0,"HIAProgramRejected","E_HIA_NAME: function collides with native runtime symbol")
  passed=[row for row in baseline["planned_all_55"] if actual_groups.get(row[0]+"-"+str(row[1]),{}).get("status")=="PASS"]
  assert passed==baseline["passed_before_failure"] and len(passed)==2
  assert sum(actual_groups[g+"-"+str(v)]["cases"] for g,v,_,_ in passed)==2
  assert sum(x["native_entries"] for x in actual_groups.values())==731
  assert actual_roles==baseline["counts"]["roles"]
  assert len(old["details"]["groups"])==3 and old["details"]["actual_cases"]==2
  assert old["details"]["actual_native_entries"]==731
  pairs={}
  for component,m in baseline["actual_manifests"].items():
   root=prefix+"build-"+component+"-r3"
   value=selected[root+"/summary.json"]
   assert value["status"]=="PASS_BUILD_ONLY" and value["compilations"]==1 and value["source_pins_unchanged"]
   assert value["components"]=={component:m}
   assert selected[root+"/"+component+"/emitter.manifest.json"]==m
   before=selected[root+"/source-before.json"];after=selected[root+"/source-after.json"]
   assert len(before)==len(after) and all(x["same"] for x in after)
   for a,b in zip(before,after):
    assert a["path"]==b["path"] and a["bytes"]==b["bytes"] and a["sha256"]==b["sha256"]
    info=infos[root+"/"+a["snapshot"]]
    assert info=={k:a[k] for k in("bytes","sha256","mode")}
   paths={kind:str(args.out/"preserved"/archive_name(m[kind+"_path"])) for kind in("source","image")}
   pairs[component]=dict(manifest=m,paths=paths,full_original_source_and_image_verified=True,
       source_gate_before_after_all_equal=True)
  assert len(pairs)==11
  c_summary=selected[prefix+"native-mechanics-build-r3/summary.json"]
  assert c_summary==baseline["actual_C_build"] and c_summary["source_before_after_exact"]
  assert selected[c_name+".build.json"]=={k:v for k,v in c_summary.items() if k!="status"}
  save(args.out/"preserved-members.json",preserved)
  save(args.out/"actual-source-image-pairs.json",pairs)
  save(args.out/"original-groups-and-cases.json",dict(groups=actual_groups,cases=all_results))
  report.update(status="PASS",all_members=members,all_member_bytes=total,
      full_tar_bytes_modes_and_SHA256_equal=True,inputs_before_after=inputs,
      full_original_archive_and_ledger_copies=encoded_originals,original_by_role=actual_roles,
      outer_ZIP_independently_read=False,
      actual_source_image_pairs=pairs,old_C_executable=str(args.out/"preserved"/c_name),
      preserved_members=len(preserved),original_failed_group=failed,
      actual_original_passed_groups=passed,actual_original_passed_cases=2,
      actual_original_native_entries=731,all_original_gate_source_snapshots_verified=True,
      all_3_original_groups_bound_to_the_same_eleven_actual_images=True,
      original_late6_fixture_source_git="28152bad4ec34225f76ff852d0e24fad876087d2",
      union_claim_requires_new_9_groups_and_exact_same_production_bytes=True)
 except BaseException as error:
  report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  report["inputs_before"]=inputs
  after=[]
  for path,before in inputs.items():
   try:
    current=identity(path);same=current==before
    after.append(dict(path=path,before=before,after=current,same=same))
    if not same:
     report.setdefault("after_check_errors",[]).append("input changed: "+path)
     report["status"]="FAIL"
   except BaseException as error:
    after.append(dict(path=path,before=before,same=False,error_class=type(error).__name__,error=str(error)))
    report.setdefault("after_check_errors",[]).append("input after-check failed: "+path+": "+repr(error))
    report["status"]="FAIL"
  report["inputs_after_checks"]=after
  report["all_recorded_inputs_after_checked_equal"]=all(row["same"] for row in after)
  report["failure_preservation_scope"]=(
      "complete original archive and ledger plus selected originals available so far"
      if report["complete_original_encoded_inputs_preserved"] else
      "partial: expected original archive/ledger copies did not both complete")
  report["elapsed_seconds"]=time.monotonic()-started
  report["limits"]=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
      address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180)
  save(args.out/"summary.json",report);print(json.dumps(report,sort_keys=True),flush=True)
  signal.alarm(0)
 if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
