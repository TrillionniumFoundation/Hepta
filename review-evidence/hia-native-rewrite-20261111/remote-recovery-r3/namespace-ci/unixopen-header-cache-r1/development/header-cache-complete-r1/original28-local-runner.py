"""Local development execution of the exact candidate CI subject body.
The original subject, 28 cases and all assertions are byte-identical. This
harness only supplies an already copied, independently pinned local context.
It does not call or claim CI prepare(), Ubuntu qualification, or cold success.
"""
from __future__ import annotations
import hashlib,importlib.util,json,os,platform,resource,signal,sys,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def git(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def save(p,v):
 raw=(json.dumps(v,sort_keys=True,indent=2)+"\n").encode();p.write_bytes(raw);assert p.read_bytes()==raw
def load(name,p):
 raw=p.read_bytes();spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;exec(compile(raw,str(p),"exec"),m.__dict__);return m
def main():
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 os.environ["HIA_CI_OUTPUT"]=str(ROOT/"process-output");os.environ["PYTHONDONTWRITEBYTECODE"]="1"
 common=load("local_exact_common_run",ROOT/"ci_common.py")
 assert git((ROOT/"ci_common.py").read_bytes())=="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
 common.OUTPUT.mkdir()
 candidate=(ROOT/"ci_actual_candidate.py").read_bytes()
 assert git(candidate)=="723a40e7a299db9ed97f7515d6d39a2a06f1e3ad"
 ci=load("exact_candidate_subject_for_local_development",ROOT/"ci_actual_candidate.py")
 ev=ci.Evidence();context=json.loads((ROOT/"context.json").read_bytes())
 context_path=ROOT/"context.json";working=Path(context["namespace_working"]);evidence=Path(context["namespace_evidence"])
 manifest=json.loads((ROOT/"inputs.json").read_bytes());sources={};paths={}
 assert git((ROOT/"inputs.json").read_bytes())==ci.INPUT_GIT
 for row in manifest["inputs"]:
  path=working/"inputs"/row["path"];raw=ev.pin(path,row);sources[row["path"]]=(row,raw);paths[row["path"]]=str(path)
  if row["working_alias"] is not None:
   assert ev.pin(working/row["working_alias"])==raw
 for path in (ROOT/"ci_common.py",ROOT/"ci_actual_candidate.py",ROOT/"inputs.json",context_path,Path(context["compiler"]),Path(__file__)):ev.pin(path)
 assert ci.sha(Path(context["compiler"]).read_bytes())==ci.COMPILER and len(Path(context["compiler"]).read_bytes())==ci.COMPILER_BYTES
 details=dict(status="INCOMPLETE",scope="LOCAL_DEVELOPMENT_EXACT_SUBJECT_ONLY_NOT_UBUNTU_CI",
  actual_counts="UNKNOWN_UNTIL_COMPLETED_REPORTS",process_receipts=[],original_report_pins=[],
  ordinary_unixOpen_closed=False,ordinary_Store_SQL31_closed=False,original42_reexecuted=False,
  actual_native_raw_prefix_subject_pass=False)
 src=candidate.decode()
 start=src.index("  phase_start=time.monotonic_ns()\n")
 end=src.index('  status="PASS" if ev.primary is None',start)
 body=src[start:end]
 assert body.count('for group,count in GROUPS.items():')==1 and 'assert len(cases)==28' in body
 executable="def local_exact_subject():\n phase_start=None\n try:\n"+body+"\n if ev.primary is not None:raise ev.primary\n assert details['status']=='PASS_RAW_PREFIX_COMPONENT_ONLY'\n return details\n"
 (ROOT/"exact-subject-body.py").write_text(executable)
 save(ROOT/"extraction-proof.json",dict(candidate_git=git(candidate),candidate_sha256=sha(candidate),original_exact_subject_slice_sha256=sha(body.encode()),
  original_start_offset=start,original_end_offset=end,exact_original_body=True,only_local_context_and_original_common_run_supplied=True,
  CI_prepare_not_called=True,Ubuntu_qualification=False,compiler=ci.COMPILER,
  original_groups=ci.GROUPS,original_runtime_CPU90_wall180_and_900_subject_preserved=True))
 ci.__dict__.update(dict(ev=ev,context=context,context_path=context_path,working=working,evidence=evidence,common=common,details=details,
  paths=paths,sources=sources,prlimit=Path("/usr/bin/prlimit"),env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")))
 ev.pin(ROOT/"exact-subject-body.py");ev.pin(ROOT/"extraction-proof.json")
 compile_started=time.monotonic_ns()
 primary=None;result=None
 try:
  exec(compile(executable,str(ROOT/"exact-subject-body.py"),"exec"),ci.__dict__)
  result=ci.local_exact_subject()
 except BaseException as exc:primary=exc;traceback.print_exc()
 finally:
  receipt=dict(status="PASS" if primary is None else "FAIL",scope="LOCAL_DEVELOPMENT_NOT_UBUNTU_CI",
   original_subject=details,elapsed_ns=time.monotonic_ns()-compile_started,platform=platform.platform(),python=sys.version,
   CI_prepare_executed=False,CI_independent_seal_executed=False,complete_context_input_hash_check=True)
  if primary is not None:receipt.update(error=repr(primary))
  save(ROOT/"local-final.json",receipt);print("LOCAL_EXACT_SUBJECT_FINAL "+json.dumps({k:v for k,v in receipt.items() if k!="original_subject"},sort_keys=True),flush=True)
  if time.monotonic_ns()-compile_started>=900_000_000_000:
   if primary is None:primary=TimeoutError("local final caller after900")
   else:primary.add_note("local final caller after900")
   receipt.update(status="FAIL",error=repr(primary));save(ROOT/"local-final.json",receipt)
 if primary is not None:raise primary
if __name__=="__main__":main()
