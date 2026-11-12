"""Complete immutable FOLLOW50 artifact readback, with zero target execution.
The input is the extraction of the exact GitHub artifact ID 13946102285.
All inner archive and ledger bytes, then all 19,329 member bytes and modes,
are verified. ZIP download metadata is stated separately from this readback.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
import argparse,base64,json,os,resource,signal,stat,sys,tarfile,time,traceback,types
ARCHIVE_BYTES=50284504
ARCHIVE_SHA="a8ff3c81f0eed557feefcb5c68dd14ad24bd98a008d36b1e72d3303d44989cb1"
LEDGER_BYTES=8492520
LEDGER_SHA="bed648fae4f20571901fedb0a57db7010e28dd61ba3eea2f98a083b1f751f400"
MEMBERS=19329
ORIGINAL_BYTES=322056528
HELPER_GIT="e6faa70b24b432c07dbf0347ccf0afad10ff5373"
HELPER_SHA="0e47d970d5faa73884a74165625119ffd562224e28ad652f693f0b61dfa7c380"
OBSERVATION_GIT="5544db958ae58c389f6aabfd8595d586a9525667"
OBSERVATION_SHA="12f45c736d4f74fbf221f05e12f87d45268bf57f5bcbe558acbf78762ba94016"
REPAIRED_GIT="d255ffd8147d4658ed555c54ac5c79ccf8779973"
REPAIRED_SHA="f481be27e3988e2f92a90c9dd34dea90958c60e1d9b29e52791217e3f890f198"
def git(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
 path.write_bytes(raw);assert path.read_bytes()==raw
def identity(path):
 info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not path.is_symlink(),str(path)
 h=sha256();n=0
 with path.open("rb") as stream:
  while True:
   raw=stream.read(1<<18)
   if not raw:break
   h.update(raw);n+=len(raw)
 after=path.lstat()
 assert (after.st_dev,after.st_ino,after.st_mode,after.st_size)==(info.st_dev,info.st_ino,info.st_mode,info.st_size)
 assert n==info.st_size
 return dict(bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(info.st_mode))
def copied(original,destination,pins):
 before=identity(original);pins[str(original)]=before
 with original.open("rb") as src,destination.open("xb") as dst:
  while True:
   raw=src.read(1<<18)
   if not raw:break
   dst.write(raw)
  dst.flush();os.fsync(dst.fileno())
 destination.chmod(before["mode"])
 assert identity(destination)==before and identity(original)==before
 # Hash equality above is accompanied by a second, complete byte comparison.
 with original.open("rb") as a,destination.open("rb") as b:
  while True:
   raw=a.read(1<<18);assert b.read(len(raw))==raw
   if not raw:break
  assert b.read(1)==b""
 return before
def unique(root,name):
 matches=list(root.rglob(name))
 assert len(matches)==1,(name,len(matches))
 path=matches[0]
 assert not any(p.is_symlink() for p in(path,*path.parents)) and path.is_file()
 return path
def safe_name(name):
 p=PurePosixPath(name)
 assert not p.is_absolute() and p.parts and all(part not in("",".","..") for part in p.parts)
 assert p.as_posix()==name and "\\" not in name
 return p
def printed_original(path,label):
 raw=path.read_bytes()
 for at in range(0,len(raw),18000):
  part=raw[at:at+18000]
  print(label+" "+json.dumps(dict(file=path.name,bytes=len(raw),sha256=digest(raw),
        offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)

def extract_all(archive,index,destination):
 rows={};original_paths=set();count=0;total=0
 with index.open("r",encoding="utf-8") as ledger,tarfile.open(archive,"r|xz") as tf:
  for item in tf:
   line=ledger.readline();assert line
   row=json.loads(line);name=row["name"];safe_name(name)
   assert name not in rows and row["path"] not in original_paths
   assert type(row["path"]) is str and row["path"].startswith("/")
   assert item.isfile() and not item.issym() and not item.islnk()
   assert item.name==name and item.size==row["bytes"] and item.mode==row["mode"]
   assert type(row["bytes"]) is int and row["bytes"]>=0 and type(row["mode"]) is int
   assert row["mode"]&~0o777==0
   path=destination/name;path.parent.mkdir(parents=True,exist_ok=True)
   h=sha256();n=0
   with tf.extractfile(item) as stream,path.open("xb") as out:
    while True:
     block=stream.read(1<<18)
     if not block:break
     out.write(block);h.update(block);n+=len(block)
   path.chmod(row["mode"])
   assert n==row["bytes"] and h.hexdigest()==row["sha256"]
   assert identity(path)=={k:row[k] for k in("bytes","sha256","mode")}
   rows[name]=row;original_paths.add(row["path"]);count+=1;total+=n
   tf.members.clear()
  assert not ledger.readline()
 assert count==MEMBERS and total==ORIGINAL_BYTES
 return rows

def main():
 started=time.monotonic()
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 if hasattr(os,"sched_getaffinity"):
  mask=os.sched_getaffinity(0);assert mask
  if len(mask)!=1:os.sched_setaffinity(0,{min(mask)})
  assert len(os.sched_getaffinity(0))==1
 def expired(*unused):raise TimeoutError("backend50 originals reader original 180 wall limit")
 signal.signal(signal.SIGALRM,expired);signal.alarm(180)
 parser=argparse.ArgumentParser()
 parser.add_argument("--input",required=True,type=Path)
 parser.add_argument("--out",required=True,type=Path)
 parser.add_argument("--observations",required=True,type=Path)
 parser.add_argument("--helper",required=True,type=Path)
 parser.add_argument("--repaired-harness",required=True,type=Path)
 args=parser.parse_args()
 source_path=Path(__file__).resolve()
 incoming=args.input.resolve();out=args.out.resolve()
 assert incoming.is_dir() and out!=incoming and not out.is_relative_to(incoming) and not incoming.is_relative_to(out)
 out.mkdir(parents=True,exist_ok=False)
 retained=out/"original-inputs";retained.mkdir()
 expanded=out/"original-members";expanded.mkdir()
 pins={};rows={};primary=None;after_errors=[];copy_rows=[];report=dict(
  schema="hia-backend50-complete-artifact-readback-v1",status="INCOMPLETE",
  target_native_entries_executed=0,VM_entries_executed=0,B3_calls_executed=0,
  source_generation_calls=0,product_imports=0,original_job_status="FAIL",
  original_completed_cases=0,new_qualified_cases=0,read_only_originals=True,
  full_public_backend_qualified=False,whole_stack_closed=False,
  artifact_id=13946102285,run_id=43220473879,job_id=131190424091,
  original_artifact_ZIP_metadata=dict(bytes=115405158,sha256="944561d46d4899cea7317631056210fa41fdeac7b4bd5c9163de060274b44169"),
  ZIP_bytes_independently_read_in_this_script=False,
  independently_verified_transport="Complete exact inner evidence.tar.xz and evidence-members.jsonl, then every member byte/mode.")
 try:
  sources=[(source_path,"reader.py"),(args.helper.resolve(),"helper.py"),
           (args.observations.resolve(),"observations.json"),(args.repaired_harness.resolve(),"repaired-harness.py")]
  # Preserve complete compressed originals before parsing any artifact JSON.
  originals=[(unique(incoming,"evidence.tar.xz"),"evidence.tar.xz"),
             (unique(incoming,"evidence-members.jsonl"),"evidence-members.jsonl")]
  assert originals[0][0].parent==originals[1][0].parent
  custody_source=originals[0][0].parent/"custody.json"
  originals.append((custody_source,"custody.json"))
  for path,name in originals+sources:
   row=copied(path,retained/name,pins)
   copy_rows.append(dict(original=str(path),retained=str(retained/name),**row))
   save(out/"input-copies.json",copy_rows)
  archive=retained/"evidence.tar.xz";index=retained/"evidence-members.jsonl"
  ai=identity(archive);ii=identity(index)
  assert (ai["bytes"],ai["sha256"])==(ARCHIVE_BYTES,ARCHIVE_SHA)
  assert (ii["bytes"],ii["sha256"])==(LEDGER_BYTES,LEDGER_SHA)
  helper_raw=(retained/"helper.py").read_bytes()
  observed_raw=(retained/"observations.json").read_bytes()
  assert (git(helper_raw),digest(helper_raw))==(HELPER_GIT,HELPER_SHA)
  assert (git(observed_raw),digest(observed_raw))==(OBSERVATION_GIT,OBSERVATION_SHA)
  custody=json.loads((retained/"custody.json").read_bytes())
  assert custody["schema"]=="hia-independent-ci-streamed-artifact-custody-v1"
  assert custody["status"]=="FAIL" and custody["scope"]=="backend-join-r1"
  assert custody["members"]==MEMBERS and custody["original_bytes"]==ORIGINAL_BYTES
  assert (custody["bytes"],custody["sha256"])==(ARCHIVE_BYTES,ARCHIVE_SHA)
  assert (custody["member_index_bytes"],custody["member_index_sha256"])==(LEDGER_BYTES,LEDGER_SHA)
  assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"]
  assert custody["complete_source_inventory_before_after_equal"] and custody["no_target_execution_in_seal"]
  report["original_custody"]=custody
  observation=json.loads(observed_raw)
  assert observation["head"]=="49e5cd97f11b3fb35d8a390e7ad4ed0c5b2fe030"
  assert observation["run_id"]==43220473879 and observation["job_id"]==131190424091
  rows=extract_all(archive,index,expanded)
  report.update(all_original_member_bytes_sha256_modes_verified=True,
      original_members=len(rows),original_bytes=sum(r["bytes"] for r in rows.values()))
  save(out/"member-readback.json",{k:report[k] for k in(
      "all_original_member_bytes_sha256_modes_verified","original_members","original_bytes")})
  prefix="backend-join/development/native-cross-0-r1/"
  selected=[("summary.json","HIA_BACKEND50_ORIGINAL_GROUP"),
    ("cases/0000/oracle.json","HIA_BACKEND50_ORIGINAL_ORACLE"),
    ("cases/0000/native-trace/process.json","HIA_BACKEND50_ORIGINAL_PROCESS"),
    ("cases/0000/native-trace/trace-summary.json","HIA_BACKEND50_ORIGINAL_TRACE_SUMMARY"),
    ("cases/0000/native-trace/closed-evidence.json","HIA_BACKEND50_ORIGINAL_CLOSED"),
    ("cases/0000/python-full-CAS/source-after.json","HIA_BACKEND50_ORIGINAL_PYTHON_CUSTODY")]
  for name,label in selected:
   assert prefix+name in rows
   printed_original(expanded/(prefix+name),label)
  helper=types.ModuleType("backend50_readonly_mechanical_replay")
  helper.__file__=str(retained/"helper.py")
  exec(compile(helper_raw,helper.__file__,"exec"),helper.__dict__)
  old_harness=(expanded/"backend-join/tests/backend_mechanical_harness.py").read_bytes()
  repaired=(retained/"repaired-harness.py").read_bytes()
  old_fragment=b"self.slots={};self.entries=0;self.calls={};self.commands=0;self.closed=False"
  new_fragment=b"self.slots={};self.entries=0;self.calls={i:0 for i in range(1,22)};self.commands=0;self.closed=False"
  assert old_harness.count(old_fragment)==repaired.count(new_fragment)==1
  assert repaired==old_harness.replace(old_fragment,new_fragment)
  assert repaired.replace(new_fragment,old_fragment)==old_harness
  assert (git(old_harness),len(old_harness))==("f4f8b88d9b77e19ea53d81527d1a6fc0fe9d758c",8829)
  assert (git(repaired),digest(repaired),len(repaired))==(REPAIRED_GIT,REPAIRED_SHA,8853)
  report["repair_inverse"]=dict(old_git=git(old_harness),new_git=git(repaired),
      exactly_one_counter_initialization_changed=True,complete_reverse_equal=True,
      original_strict_compare_unchanged=True,production_HIA_and_C_unchanged=True,
      new_source_not_executed_by_reader=True)
  replay=helper.audit(expanded,rows,observation)
  save(out/"first-cross-readback.json",replay)
  report["first_cross"]=replay
  assert replay["status"]=="PASS_READBACK_ONLY"
  assert replay["new_qualified_cases"]==replay["native_entries_executed"]==replay["VM_entries_executed"]==0
  report["status"]="PASS_READBACK_ONLY"
 except BaseException as exc:
  primary=exc
  report.update(status="FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  # Every after-check is independent; a missing source must not replace the
  # original exception or prevent the remaining original checks being tried.
  for path,want in pins.items():
   try:assert identity(Path(path))==want,path
   except BaseException as exc:after_errors.append(dict(path=path,error=repr(exc)))
  for row in copy_rows:
   try:assert identity(Path(row["retained"]))=={k:row[k] for k in("bytes","sha256","mode")}
   except BaseException as exc:after_errors.append(dict(path=row["retained"],error=repr(exc)))
  for name,row in rows.items():
   try:assert identity(expanded/name)=={k:row[k] for k in("bytes","sha256","mode")}
   except BaseException as exc:after_errors.append(dict(path=name,error=repr(exc)))
  usage=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
  cpu=usage.ru_utime+usage.ru_stime+children.ru_utime+children.ru_stime
  wall=time.monotonic()-started
  if after_errors or cpu>=90 or wall>=180:report["status"]="FAIL"
  report.update(source_and_original_inputs_before_after_equal=not after_errors,after_errors=after_errors,
      preserved_compressed_originals=len(copy_rows)>=2,complete_extracted_after_checks=len(rows),
      CPU_seconds=cpu,elapsed_seconds=wall,reader_limits=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180),
      seal_phase_not_run=True,source_before=pins.get(str(source_path)),
      full_original_member_readback_completed=report.get("all_original_member_bytes_sha256_modes_verified",False),
      new_subject_results_inherited=False)
  try:
   save(out/"readback.json",report)
   print("HIA_BACKEND50_READBACK "+json.dumps(report,sort_keys=True),flush=True)
  except BaseException as exc:
   if primary is not None:primary.add_note("readback evidence write failed: "+repr(exc))
   else:primary=exc
  # Includes final report construction and writes in the resource assertion.
  usage=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
  final_cpu=usage.ru_utime+usage.ru_stime+children.ru_utime+children.ru_stime
  final_wall=time.monotonic()-started
  if final_cpu>=90 or final_wall>=180:
   exc=AssertionError(("complete readback resource bound",final_cpu,final_wall))
   if primary is not None:primary.add_note(repr(exc))
   else:primary=exc
   report.update(status="FAIL",complete_final_budget_error=repr(exc),CPU_seconds=final_cpu,elapsed_seconds=final_wall)
   try:
    save(out/"readback.json",report)
    print("HIA_BACKEND50_READBACK_FINAL_BUDGET_FAILURE "+json.dumps(report,sort_keys=True),flush=True)
   except BaseException as write_error:primary.add_note("final budget evidence failed: "+repr(write_error))
  signal.alarm(0)
 if primary is not None:raise primary
 if report["status"]!="PASS_READBACK_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
