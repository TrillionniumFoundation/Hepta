"""First real fixed UnixOpen -> native issuer -> framer -> shared FS gate.

Twenty-eight fresh fixed-process cases. These exercise actual raw getpid
continuations and permanent/transport refusals, followed by complete fresh
CoreVM replay of every native window. The remaining ten UnixOpen effects
stay unresolved; no Python provider completes them and no Store success is
claimed. This is not a rerun or replacement of the separate original42 gate.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,resource,signal,stat,struct,sys,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
GROUPS={"raw-prefix":12,"parent-refusal":8,"transport":8}
CLIENT_SHA="e6a82d6236729b439786c8da1434174ff259562fe5484a5b235c47fbb08c80ce"
REPLAY_SHA="d91c2b292e7df6494f0c9cd84553b35f8c5e19293be767ba78f5640b99f8977b"
FIXTURE_GIT="feb06cbec0b1acf43ddbd43863cbf74a4bd55d28"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def q(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def put(raw,at,value):struct.pack_into("<Q",raw,at,value)
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
 started=time.monotonic_ns()
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def expired(*unused):raise TimeoutError("actual UnixOpen complete process group original180wall")
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,180)
 p=argparse.ArgumentParser()
 p.add_argument("--context",type=Path,required=True)
 p.add_argument("--group",choices=sorted(GROUPS),required=True)
 args=p.parse_args()
 assert sys.version_info[:3]==(3,12,14)
 context=json.loads(args.context.read_bytes());evidence=Path(context["namespace_evidence"])
 out=evidence/("actual-unixopen-"+args.group+"-r1");out.mkdir()
 pins={};before_raw={}
 def pin(path,expected=None):
  path=Path(path).absolute();st=path.lstat()
  assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
  raw=path.read_bytes();info=dict(bytes=len(raw),sha256=sha(raw),gitsha=git(raw),mode=stat.S_IMODE(st.st_mode))
  if expected is not None:assert info["sha256"]==expected
  key=str(path.resolve())
  if key in pins:assert info==pins[key]
  else:pins[key]=info;before_raw[key]=raw
  return raw
 def load(name,path,expected=None):
  raw=pin(path,expected)
  spec=importlib.util.spec_from_file_location(name,path)
  module=importlib.util.module_from_spec(spec);sys.modules[name]=module
  exec(compile(raw,str(path),"exec"),module.__dict__)
  return module
 report=dict(status="INCOMPLETE",group=args.group,planned_cases=GROUPS[args.group],
  completed_cases=0,actual_ELF_processes=0,actual_native_entries=0,full_VM_entries=0,
  actual_parent_raw_ACKs=0,actual_getpid_syscalls=0,case_results=[],
  ordinary_unixOpen_closed=False,ordinary_Store_closed=False,
  non_raw_peer_callbacks_used=False,host_completion_capsules_supplied=False,
  original42_rerun=False,prior_results_inherited=False,
  limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0),
  VM_limits=dict(steps=4000000,arena_bytes=32<<20,depth=64))
 failure=None
 try:
  pin(__file__);pin(args.context)
  here=Path(__file__).resolve().parent
  pin(here/"namespace-db-join-r1-client.py",
   "e5cad29b23957856c3a3ae08645eb7a14a62f6b0263fe67720a9560b88e58270")
  client=load("actual_unixopen_client",here/"actual-unixopen-client.py",CLIENT_SHA)
  replay=load("actual_unixopen_replay",here/"actual-unixopen-replay.py",REPLAY_SHA)
  fixture_path=here/"namespace-unixopen-fixtures.py"
  assert git(pin(fixture_path))==FIXTURE_GIT
  fixture=load("original_unixopen_input_fixture_only",fixture_path)
  ref=Path(context["reference"]);sys.path.insert(0,str(ref))
  from hepta.hia_agent_assembly import assemble_program
  build=json.loads(pin(evidence/"actual-unixopen-build-r1/summary.json"))
  assert build["status"]=="PASS_BUILD_ONLY" and build["fresh_role_compiles"]==9
  assert build["packer_entries"]==45 and build["source_pins_unchanged"]
  assert set(build["exact_roles"])=={str(r) for r in range(1,10)}
  assert build["executable"]["layout"]["relocation_count"]==0
  programs={}
  for role_text,row in sorted(build["exact_roles"].items(),key=lambda item:int(item[0])):
   role=int(role_text)
   source=pin(row["source"]["path"],row["source"]["sha256"])
   image=pin(row["image"]["path"],row["image"]["sha256"])
   assert (len(source),len(image))==(row["source"]["bytes"],row["image"]["bytes"])
   receipt=row["compile_receipt"]
   assert receipt["source_sha256"]==receipt["input_sha256"]==sha(source)
   assert receipt["produced_sha256"]==sha(image) and receipt["produced_bytes"]==len(image)
   assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
   assert receipt["artifact_sha256"]==receipt["image_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
   assert receipt["status"]=="returned" and receipt["abi_status"]==0
   programs[role]=assemble_program(source)
  executable=Path(build["executable"]["path"]);actual=pin(executable,build["executable"]["sha256"])
  assert len(actual)==build["executable"]["bytes"] and executable.stat().st_mode&0o111
  for module in tuple(sys.modules.values()):
   filename=getattr(module,"__file__",None)
   if filename:
    path=Path(filename).resolve()
    if path.is_relative_to(ref) and path.suffix==".py":pin(path)
  for index,(name,raw) in enumerate(before_raw.items()):
   target=out/"source-before"/str(index)/Path(name).name;target.parent.mkdir(parents=True)
   target.write_bytes(raw);target.chmod(pins[name]["mode"]);assert target.read_bytes()==raw
  save(out/"source-before.json",pins)
  def begin(c,case=None):
   case={} if case is None else dict(case)
   row=replay.latest_shared_FS(c.output/"trace.bin");w=row["workspace"]
   wire=bytearray(fixture.begin(case,random_pid=c.boot["actual_process"],
    counter=7,fsseq=q(w,216),sysseq=q(w,224)))
   put(wire,152,q(w,80));put(wire,160,q(w,88));put(wire,184,0)
   return bytes(wire)
  def full_case(label,run,expected_exit=0):
   directory=out/"cases"/label;directory.parent.mkdir(exist_ok=True)
   item=dict(label=label,status="INCOMPLETE",expected_exit=expected_exit)
   report["case_results"].append(item);save(out/"summary.json",report)
   c=client.Carrier(executable,directory,out)
   report["actual_ELF_processes"]+=1
   try:
    with c:
     c.expected_exit=expected_exit
     observations=run(c)
   except BaseException:
    save(out/"summary.json",report)
    raise
   actual_process=json.loads((directory/"actual-issuer-process.json").read_bytes())
   assert actual_process["returncode"]==expected_exit and actual_process["source_unchanged"]
   assert not actual_process["wall_watchdog_fired"] and not actual_process["wall_kill_sent"]
   assert 0<=actual_process["usage"]["user"]+actual_process["usage"]["system"]<90
   assert 0<=actual_process["elapsed_ns"]<180_000_000_000
   complete=replay.replay(directory,programs,expected_fatal=expected_exit)
   assert complete["native_entries"]==complete["VM_entries"]
   assert complete["all_native_return_output_workspace_bytes_equal"]
   item.update(status="PASS",observations=observations,actual_process=actual_process,replay=complete)
   report["completed_cases"]+=1
   report["actual_native_entries"]+=complete["native_entries"]
   report["full_VM_entries"]+=complete["VM_entries"]
   report["actual_parent_raw_ACKs"]+=complete["actual_native_parent_ACKs"]
   report["actual_getpid_syscalls"]+=complete["primitive_counts"].get("1:26",0)
   save(out/"summary.json",report)
   return item
  if args.group=="raw-prefix":
   rows=[
    ("main_PID_match",{},False,False,3,20,1),
    ("PID_mismatch_two_actual_getpid",{},True,False,2,12,2),
    ("wal_create_pending",dict(flags=524288|2|4),False,False,6,30,1),
    ("temporary_name_pending",dict(flags=512|2|4|8,path=None),False,False,5,22,1),
    ("readonly_main_pending",dict(flags=256|1),False,False,3,20,1),
    ("long_original_path_GROW",dict(path=b"/"+b"x"*8192+b"\0\0"),False,False,3,20,1),
    ("empty_C_string_preserved",dict(path=b"\0\0"),False,False,3,20,1),
    ("raw_non_UTF8_path_preserved",dict(path=b"\xff\x80\0\0"),False,False,3,20,1),
    ("original_filename_offset",dict(path=b"x\0db\0\0",path_offset=2),False,False,3,20,1),
    ("zero_errno_preserved",dict(initial_errno=0),False,False,3,20,1),
    ("nonzero_errno_preserved",dict(initial_errno=13),False,False,3,20,1),
    ("same_shared_FS_prior_call",{},False,True,3,20,1)]
   assert len(rows)==GROUPS[args.group]
   for label,case,mismatch,prior,expected_op,expected_stage,acks in rows:
    def run(c,case=case,mismatch=mismatch,prior=prior,expected_op=expected_op,expected_stage=expected_stage):
     if prior:
      fs,_=c.filesystem(26);assert fs[8]==c.boot["actual_process"]
     wire=bytearray(begin(c,case))
     if mismatch:put(wire,120,0)
     h,payload=c.parent_begin(wire)
     assert h[1]==1 and (h[6],h[7])==(expected_op,expected_stage),h
     assert h[9]==case.get("initial_errno",28)
     assert len(payload)>=256 and q(payload,48)==expected_op and q(payload,56)==expected_stage
     return dict(status="ACTUAL_RAW_PREFIX_COMPLETE_NONRAW_PENDING",
      pending_operation=expected_op,pending_stage=expected_stage,
      original_parent_output_sha256=sha((c.output/"requests"/str(len(c.requests)-1)/"output.bin").read_bytes()),
      expected_native_raw_ACKs=2 if mismatch else 1,nonraw_completed=False)
    result=full_case(label,run)
    assert result["replay"]["actual_native_parent_ACKs"]==acks
    assert result["replay"]["primitive_counts"]["1:26"]==acks+int(prior)
    assert result["replay"]["entries_by_role"]["7"]>0 and result["replay"]["entries_by_role"]["8"]>0
    assert result["replay"]["entries_by_role"]["9"]>0
    if label=="long_original_path_GROW":assert result["replay"]["growth_by_role"]["7"]>0
  elif args.group=="parent-refusal":
   rows=[("zero_call",32,0),("zero_source_lease",40,0),("bad_access",48,256),
    ("no_original_vfs",80,0),("invalid_boolean",72,2),("bad_reserved",208,1),
    ("path_offset_at_end",192,None),("missing_NUL",None,None)]
   assert len(rows)==GROUPS[args.group]
   for label,offset,value in rows:
    def run(c,offset=offset,value=value,label=label):
     wire=bytearray(begin(c))
     if label=="missing_NUL":wire[512:]=b"x"*len(wire[512:])
     else:put(wire,offset,len(wire)-512 if value is None else value)
     h,_=c.parent_begin(wire,label=label)
     assert h[1]==client.BAD,h
     valid=bytearray(begin(c));put(valid,32,2)
     again,_=c.parent_begin(valid,label="same-live-parent-remains-poisoned")
     assert again[1]==client.BAD
     return dict(first_refusal=list(h),persistent_refusal=list(again),
      native_parent_calls=2,host_reset=False)
    result=full_case(label,run)
    assert result["replay"]["actual_native_parent_ACKs"]==0
    assert result["replay"]["entries_by_role"]["9"]==0
    assert result["replay"]["primitive_counts"].get("1:26",0)==0
  else:
   rows=["bad_magic","bad_kind","declared_extent","nonzero_transport_reserved",
    "external_parent_ACK","external_process_identity","external_capsule","pending_parent_no_reentry"]
   assert len(rows)==GROUPS[args.group]
   for label in rows:
    def run(c,label=label):
     wire=bytearray(begin(c))
     packet=bytearray(client.envelope(2,wire))
     if label=="bad_magic":put(packet,0,0)
     elif label=="bad_kind":put(packet,8,9)
     elif label=="declared_extent":put(packet,16,len(wire)+1)
     elif label=="nonzero_transport_reserved":put(packet,24,1)
     elif label=="external_parent_ACK":put(packet,72,2)
     elif label=="external_process_identity":put(packet,64+184,c.boot["actual_process"])
     elif label=="external_capsule":
      packet=bytearray(client.envelope(2,bytes(512)));put(packet,64,int.from_bytes(b"HIAUIC01","little"))
     elif label=="pending_parent_no_reentry":
      h,_=c.parent_begin(wire);assert h[1]==1 and h[6]==3
     else:raise AssertionError(label)
     result=c.invalid_transport(packet,label=label,expected_exit=110)
     assert result["returncode"]==110
     return dict(actual_transport_exit=110,original_invalid_frame_sha256=sha(packet),
      no_external_completion_route=True)
    result=full_case(label,run,expected_exit=110)
    if label!="pending_parent_no_reentry":
     assert result["replay"]["entries_by_role"]["7"]==0
     assert result["replay"]["entries_by_role"]["8"]==0
     assert result["replay"]["entries_by_role"]["9"]==0
  assert report["completed_cases"]==report["planned_cases"]==len(report["case_results"])
  assert report["actual_ELF_processes"]==report["planned_cases"]
  assert report["actual_native_entries"]==report["full_VM_entries"]>0
  report["status"]="PASS"
 except BaseException as error:
  failure=error;report.update(status="FAIL",error_class=type(error).__name__,error=str(error),
   traceback=traceback.format_exc())
  try:traceback.print_exc()
  except BaseException as secondary:error.add_note("traceback output: "+repr(secondary))
 finally:
  after={};errors=[]
  for path,expected in pins.items():
   try:
    p=Path(path);st=p.lstat();assert stat.S_ISREG(st.st_mode) and not p.is_symlink()
    raw=p.read_bytes();observed=dict(bytes=len(raw),sha256=sha(raw),gitsha=git(raw),mode=stat.S_IMODE(st.st_mode))
    after[path]=observed;assert observed==expected
   except BaseException as error:
    after[path]=dict(error=repr(error));errors.append(dict(path=path,error=repr(error)))
    if failure is None:failure=error
    else:failure.add_note("source after: "+repr(error))
  report["source_before"]=pins;report["source_after"]=after
  report["source_inputs_unchanged"]=not errors
  if failure is not None:report["status"]="FAIL"
  try:
   save(out/"summary.json",report)
   print("HIA_UNIXOPEN_ACTUAL_GROUP "+json.dumps({k:report[k] for k in
    ("status","group","planned_cases","completed_cases","actual_ELF_processes",
     "actual_native_entries","full_VM_entries","actual_parent_raw_ACKs","actual_getpid_syscalls")},sort_keys=True),flush=True)
  except BaseException as error:
   if failure is None:failure=error
   else:failure.add_note("final output: "+repr(error))
  try:
   own=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
   budget=dict(whole_tree_CPU=own.ru_utime+own.ru_stime+child.ru_utime+child.ru_stime,
    elapsed_ns=time.monotonic_ns()-started)
   save(out/"post-output-budget.json",budget)
   own=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
   assert 0<=own.ru_utime+own.ru_stime+child.ru_utime+child.ru_stime<90
   assert 0<=time.monotonic_ns()-started<180_000_000_000
  except BaseException as error:
   if failure is None:failure=error
   else:failure.add_note("strict final budget: "+repr(error))
  if failure is not None:
   report.update(status="FAIL",final_error_class=type(failure).__name__,final_error=str(failure))
   try:save(out/"summary.json",report)
   except BaseException as error:failure.add_note("FAIL receipt: "+repr(error))
  signal.setitimer(signal.ITIMER_REAL,0)
 if failure is not None:raise failure
if __name__=="__main__":main()
