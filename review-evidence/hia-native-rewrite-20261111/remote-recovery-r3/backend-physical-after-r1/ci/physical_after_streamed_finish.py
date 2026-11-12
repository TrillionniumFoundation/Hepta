"""Streaming evidence closure for this new implementation-file custody CI.
Preserves common's source checks and every file byte/mode. JSONL replaces the
unbounded in-memory member list, and tarfile.members is cleared after each row.
It performs zero target executions. Existing component evidence is untouched.
"""
from pathlib import Path
from hashlib import sha256
import json,os,stat,tarfile,time
def file_hash(path):
 h=sha256();n=0
 with Path(path).open("rb") as f:
  while True:
   raw=f.read(1<<18)
   if not raw:break
   n+=len(raw);h.update(raw)
 return dict(bytes=n,sha256=h.hexdigest())
def files(root):
 info=root.lstat()
 assert not stat.S_ISLNK(info.st_mode)
 if stat.S_ISREG(info.st_mode):
  yield root
 elif stat.S_ISDIR(info.st_mode):
  for child in sorted(root.iterdir(),key=lambda p:p.name):
   yield from files(child)
 else:raise AssertionError(("unsupported evidence object",str(root),info.st_mode))
def rows_for(mapping,excluded):
 for label,root in sorted(mapping.items()):
  root=Path(root).resolve()
  one=root.is_file()
  for path in files(root):
   if path in excluded:continue
   info=path.lstat()
   assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
   rel=path.name if one else path.relative_to(root).as_posix()
   yield label+"/"+rel,path,info
def compare_stream(item_stream,path,expected):
 actual=sha256();n=0
 with path.open("rb") as original:
  while True:
   raw=item_stream.read(1<<18)
   if not raw:break
   assert original.read(len(raw))==raw,(str(path),"tar differs from complete actual file")
   actual.update(raw);n+=len(raw)
  assert original.read(1)==b""
 info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
 assert (n,actual.hexdigest(),stat.S_IMODE(info.st_mode))==(expected["bytes"],expected["sha256"],expected["mode"])
def _finish_streamed(common,scope,status,details,roots=None):
 assert status in("PASS","FAIL")
 output=common.OUTPUT;output.mkdir(parents=True,exist_ok=True)
 exact=common.PREPARED and common.unchanged(common.SOURCE_INDEX) and common.unchanged(common.REFERENCE_INDEX)
 scripts=all(path.read_bytes()==raw for path,raw in common.PINS.items())
 if status=="PASS":assert exact and scripts
 summary=dict(schema="hia-independent-ci-qualification-v1",scope=scope,status=status,
    details=details,steps=common.STEPS,prepared=common.PREPARED,
    frozen_source_and_reference_before_after_equal=exact,
    submitted_script_pins_before_after_equal=scripts,
    whole_stack_closed=False,production_activated=False,inherited_test_counts=False,
    original_ROG_launches_not_resolved_by_this_run=True,
    evidence_format="streamed-tar-xz-with-complete-JSONL-member-ledger-v1")
 common.save(output/"summary.json",summary)
 mapping={"run":output}
 mapping.update({name:Path(path) for name,path in(roots or {}).items() if Path(path).exists()})
 for name,root in mapping.items():
  assert name and "/" not in name and name not in(".","..")
  real=root.resolve();assert real==output or real.is_relative_to(common.BASE)
 archive=output/"evidence.tar.xz";index=output/"evidence-members.jsonl";custody_path=output/"custody.json"
 excluded={archive,index,custody_path}
 assert all(not path.exists() for path in excluded)
 started=time.monotonic();cpu=time.process_time();count=0;total=0
 with index.open("x",encoding="utf-8") as ledger,tarfile.open(archive,"w:xz",preset=1) as tf:
  for name,path,info in rows_for(mapping,excluded):
   identity=file_hash(path)
   row=dict(name=name,path=str(path),bytes=identity["bytes"],mode=stat.S_IMODE(info.st_mode),sha256=identity["sha256"])
   current=path.lstat()
   assert (current.st_dev,current.st_ino,current.st_mode,current.st_size)==(info.st_dev,info.st_ino,info.st_mode,info.st_size)
   member=tarfile.TarInfo(name);member.size=row["bytes"];member.mode=row["mode"]
   member.mtime=0;member.uid=member.gid=0;member.uname=member.gname=""
   with path.open("rb") as raw:tf.addfile(member,raw)
   tf.members.clear()
   ledger.write(json.dumps(row,sort_keys=True)+"\n")
   count+=1;total+=row["bytes"]
  ledger.flush();os.fsync(ledger.fileno())
 checked=0
 with index.open("r",encoding="utf-8") as ledger,tarfile.open(archive,"r|xz") as tf:
  for item in tf:
   line=ledger.readline();assert line
   row=json.loads(line);assert item.isfile() and item.name==row["name"]
   assert (item.size,item.mode)==(row["bytes"],row["mode"])
   with tf.extractfile(item) as raw:compare_stream(raw,Path(row["path"]),row)
   checked+=1;tf.members.clear()
  assert not ledger.readline() and checked==count
 # A second traversal detects omitted/added/reordered filesystem entries.
 with index.open("r",encoding="utf-8") as ledger:
  for name,path,info in rows_for(mapping,excluded):
   line=ledger.readline();assert line;row=json.loads(line)
   assert row["name"]==name and row["path"]==str(path)
   assert stat.S_IMODE(info.st_mode)==row["mode"]
   assert file_hash(path)=={k:row[k] for k in("bytes","sha256")}
  assert not ledger.readline()
 assert all(path.read_bytes()==raw for path,raw in common.PINS.items())
 ah=file_hash(archive);ih=file_hash(index)
 custody=dict(schema="hia-independent-ci-streamed-artifact-custody-v1",scope=scope,status=status,
    archive=str(archive),bytes=ah["bytes"],sha256=ah["sha256"],members=count,original_bytes=total,
    member_index=str(index),member_index_format="JSONL",member_index_bytes=ih["bytes"],member_index_sha256=ih["sha256"],
    all_original_and_tar_member_bytes_sha256_modes_readback=True,
    complete_source_inventory_before_after_equal=True,tar_member_cache_cleared_after_each_member=True,
    no_target_execution_in_seal=True,seal_wall_seconds=time.monotonic()-started,seal_cpu_seconds=time.process_time()-cpu,
    whole_stack_closed=False)
 common.save(custody_path,custody)
 print(json.dumps(custody,sort_keys=True),flush=True)
 if os.environ.get("GITHUB_STEP_SUMMARY"):
  with open(os.environ["GITHUB_STEP_SUMMARY"],"a") as f:
   f.write("## Implementation-file custody independent development\n\nStatus: **"+status+"**. Public backend / native installed inventory remain open.\n\n")
   f.write("Archive: "+ah["sha256"]+"; "+str(count)+" complete member bytes/modes verified.\n\n")
 return summary,custody

def finish(common,scope,status,details,roots=None):
 """New independent seal process: original target budgets are unchanged."""
 import ctypes,errno,resource,signal,sys,traceback
 parent=os.getpid();started=time.monotonic();parent_cpu=time.process_time()
 process_path=common.OUTPUT/"evidence-seal-process.json"
 limits_path=common.OUTPUT/"evidence-seal-limits.json"
 assert not process_path.exists() and not limits_path.exists()
 sys.stdout.flush();sys.stderr.flush()
 pid=os.fork()
 if pid==0:
  code=1
  try:
   os.setsid()
   libc=ctypes.CDLL(None,use_errno=True)
   libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
   libc.prctl.restype=ctypes.c_int
   if libc.prctl(1,signal.SIGKILL,0,0,0)!=0:
    number=ctypes.get_errno();raise OSError(number,os.strerror(number))
   if os.getppid()!=parent:raise RuntimeError("seal parent changed during startup")
   resource.setrlimit(resource.RLIMIT_CPU,(90,90))
   resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
   resource.setrlimit(resource.RLIMIT_CORE,(0,0))
   def expired(signum,frame):raise TimeoutError("independent evidence seal exceeded 180 wall seconds")
   signal.signal(signal.SIGALRM,expired);signal.alarm(180)
   observed=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
       address=list(resource.getrlimit(resource.RLIMIT_AS)),
       core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180)
   assert observed==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
   assert len(os.sched_getaffinity(0))==1
   common.OUTPUT.mkdir(parents=True,exist_ok=True)
   common.save(limits_path,dict(schema="hia-independent-evidence-seal-limits-v1",
       limits=observed,pid=os.getpid(),parent_pid=parent,setsid=True,
       parent_death_signal=signal.SIGKILL,one_CPU_affinity=True,
       actual_target_executions=0,qualification_scope="evidence creation and full readback only"))
   _finish_streamed(common,scope,status,details,roots)
   assert time.monotonic()-started<180
   assert time.process_time()<90
   code=0
  except BaseException:
   traceback.print_exc()
  finally:
   for stream in(sys.stdout,sys.stderr):
    try:stream.flush()
    except BaseException:code=1
   os._exit(code)
 primary=None;cleanup_errors=[];wait_status=None;usage=None;timed_out=False;result=None
 def consume_wait(blocking):
  nonlocal wait_status,usage
  if wait_status is not None:return True
  while True:
   try:got,observed_status,observed_usage=os.wait4(pid,0 if blocking else os.WNOHANG)
   except InterruptedError:continue
   if got:
    assert got==pid
    wait_status=observed_status;usage=observed_usage;return True
   return False
 def kill_owned():
  if wait_status is not None:return
  try:os.killpg(pid,signal.SIGKILL)
  except ProcessLookupError:
   try:os.kill(pid,signal.SIGKILL)
   except ProcessLookupError:pass
 try:
  while not consume_wait(False):
   if time.monotonic()-started>=180:
    timed_out=True;raise TimeoutError("independent evidence seal parent deadline")
   time.sleep(0.025)
  assert os.waitstatus_to_exitcode(wait_status)==0,("evidence seal child exit",wait_status)
  actual=json.loads(limits_path.read_bytes())
  assert actual["limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
  assert actual["pid"]==pid and actual["parent_pid"]==parent and actual["actual_target_executions"]==0
  result=(json.loads((common.OUTPUT/"summary.json").read_bytes()),
          json.loads((common.OUTPUT/"custody.json").read_bytes()))
 except BaseException as error:
  primary=error
 finally:
  if wait_status is None:
   try:kill_owned()
   except BaseException as error:cleanup_errors.append("kill: "+repr(error))
   try:consume_wait(True)
   except BaseException as error:cleanup_errors.append("reap: "+repr(error))
  child_cpu=None if usage is None else usage.ru_utime+usage.ru_stime
  parent_used=time.process_time()-parent_cpu
  elapsed=time.monotonic()-started
  within=(child_cpu is not None and child_cpu+parent_used<90 and elapsed<180)
  if not within:cleanup_errors.append("independent seal aggregate 90CPU/180wall gate failed")
  record=dict(schema="hia-independent-evidence-seal-process-v1",scope=scope,
      subject_status=status,status="PASS" if primary is None and not cleanup_errors else "FAIL",
      actual_target_executions=0,method="fresh fork with inherited immutable evidence paths",
      pid=pid,wait_status=wait_status,
      exit_code=None if wait_status is None else os.waitstatus_to_exitcode(wait_status),
      timed_out=timed_out,limits=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180),
      child_cpu_seconds=child_cpu,parent_CPU_seconds=parent_used,
      whole_seal_parent_child_CPU_seconds=None if child_cpu is None else child_cpu+parent_used,
      elapsed_wall_seconds=elapsed,aggregate_limits_pass=within,cleanup_errors=cleanup_errors,
      error_class=None if primary is None else type(primary).__name__,
      error=None if primary is None else str(primary),
      outer_metadata_note="This post-wait receipt is outside evidence.tar.xz and is retained in the outer CI artifact beside custody.json.")
  try:common.save(process_path,record)
  except BaseException as error:
   cleanup_errors.append("save process receipt: "+repr(error))
  if cleanup_errors:
   if primary is None:primary=AssertionError("independent evidence seal cleanup or budget failure")
   for note in cleanup_errors:primary.add_note(note)
 if primary is not None:raise primary
 print("HIA_EVIDENCE_SEAL_PROCESS "+json.dumps(record,sort_keys=True),flush=True)
 final_wall=time.monotonic()-started;final_cpu=child_cpu+time.process_time()-parent_cpu
 if final_wall>=180 or final_cpu>=90:
  failure=AssertionError("independent seal final parent postcheck 90CPU/180wall gate failed")
  record.update(status="FAIL",final_parent_postcheck_CPU_seconds=final_cpu,
      final_parent_postcheck_wall_seconds=final_wall,aggregate_limits_pass=False,
      error_class=type(failure).__name__,error=str(failure))
  try:common.save(process_path,record)
  except BaseException as error:failure.add_note("save final budget failure: "+repr(error))
  raise failure
 return result
