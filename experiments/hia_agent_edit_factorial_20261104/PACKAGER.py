#!/usr/bin/env python3
"""Post-terminal observer and lossless packager: never runs models or evaluators."""
from collections import Counter
import hashlib, json, lzma, os, re, shutil, stat, subprocess, sys, tarfile, time
from pathlib import Path, PurePosixPath
B=Path("/home/qian-qi/work/hia-seven-evidence-20261104")
S=Path("/home/qian-qi/work/hia-ci-receipt-profile-20261104")
P=B/"publication-agent-edit-factorial-20261104-v1"
HEAD="3707b871ecbe563233ee9a3b69299fc627408936"
TREE="9530e9feccf0077696d2e94746fda6bfb6854417"
PROJECTION="e3b380bdb4d52e3d65c77356a3c09a4c6e3cfbf4"
ARMS=[("assembly","full"),("rust","full"),("assembly","patch"),("rust","patch")]
def read(p): return json.loads(Path(p).read_text())
def identity(p):
 p=Path(p)
 with p.open("rb") as f: return {"path":str(p),"bytes":p.stat().st_size,"sha256":hashlib.file_digest(f,"sha256").hexdigest()}
def write(p,v):
 with Path(p).open("xb") as f:f.write(json.dumps(v,sort_keys=True,indent=2,allow_nan=False).encode()+b"\n")
def git(*args): return subprocess.check_output(["git","-C",str(S),*args],text=True).strip()
def costs(v,p=""):
 out={}
 if isinstance(v,dict):
  for k,x in v.items():
   q=p+"."+k if p else k
   if k.endswith(("_ns","_seconds","_ms")) and (x is None or type(x) in (int,float)):out[q]=x
   elif isinstance(x,(list,dict)):out.update(costs(x,q))
 elif isinstance(v,list):
  for i,x in enumerate(v):out.update(costs(x,p+"["+str(i)+"]"))
 return out
def stage(a,c,i):
 if a.get("status")=="budget_timeout":return "timeout"
 if a.get("status") in ("generation_error","infrastructure_failure") or a.get("infrastructure_error"):return "infrastructure"
 e=a.get("edit_error")
 if e is not None:
  if any(x in e for x in ("E_FACTORIAL_PATCH_BUDGET","E_FACTORIAL_EDIT_FIELDS","E_FACTORIAL_EXACT_EDIT","E_FACTORIAL_FILE_BUDGET")):return "patch_admission"
  return "json_or_protocol"
 b=a.get("build")
 if b is not None and not b.get("native_built",False):return "infrastructure" if b.get("status")=="infrastructure_failure" else "source_or_compile"
 p=a.get("public")
 if p is not None and p.get("status")!="correct":return "public_tests"
 if a.get("status")=="public_passed" and i==len(c.get("attempts",[]))-1:
  if c.get("status")=="hidden_validation_failed":return "hidden_oracle"
  if c.get("correct") is True:return "correct"
 return "unclassified_retained_status"
def tokens(rows,n):
 ic=len(rows)==n and all(r.get("input_tokens_complete") is True for r in rows)
 oc=len(rows)==n and all(r.get("output_tokens_complete") is True for r in rows)
 ki=sum(r.get("known_input_tokens",0) for r in rows);ko=sum(r.get("known_output_tokens",0) for r in rows)
 return {"known_input_tokens":ki,"known_output_tokens":ko,"total_input_tokens":ki if ic else None,"total_output_tokens":ko if oc else None,"input_tokens_complete":ic,"output_tokens_complete":oc}
def main():
 started=time.monotonic_ns();os.sched_setaffinity(0,{12})
 outer=B/"factorial-driver-r3";terminal=read(outer/"MAIN_RUNTIME_TERMINAL.json")
 assert terminal["job_id"]=="1a1a5341ebd-fc05-1abf"
 assert terminal["output_complete"] is True and terminal["output_durable"] is True
 assert terminal["state"] in ("succeeded","failed","cancelled","timed_out")
 assert git("rev-parse","HEAD")==HEAD and git("rev-parse","HEAD^{tree}")==TREE and git("status","--porcelain","--untracked-files=all")==""
 P.mkdir(exist_ok=False);pub=P/"public";pub.mkdir()
 resultpath=B/"factorial-r3/RESULT.json"
 result=read(resultpath) if resultpath.exists() else None
 reg=read(B/"factorial-r3/REGISTRATION.json")
 wrapper=read(outer/"run.RESULT.json") if (outer/"run.RESULT.json").exists() else None
 issues=[];cells=[];attempts=[];disk={}
 for p in sorted((B/"factorial-r3/cells").rglob("CELL.json")):
  r=read(p)
  if r["id"] in disk:issues.append("duplicate CELL: "+r["id"])
  disk[r["id"]]=r
 rows=result.get("cells",[]) if result else []
 if result is None:issues.append("official RESULT absent; raw terminal evidence retained without rerun")
 if wrapper is None:issues.append("outer RESULT absent; main outer wall unknown")
 for r in rows:
  if disk.get(r["id"])!=r:issues.append("RESULT/CELL mismatch: "+r["id"])
 if set(disk)!={r["id"] for r in rows}:issues.append("CELL inventory differs from RESULT")
 for d in reg["schedule"]:
  r=disk.get(d["id"])
  if r is None:
   cells.append({**d,"observed":False,"correct":False,"stage":"missing","attempts":0,"cell_wall_ns":None});continue
  classified=[]
  for i,a in enumerate(r.get("attempts",[])):
   p=B/"factorial-r3/cells"/d["id"]/("attempt-"+str(i)+".json")
   same=p.exists() and read(p)==a
   if not same:issues.append("attempt mismatch: "+str(p))
   classified.append(stage(a,r,i))
   attempts.append({**d,"index":i,"stage":classified[-1],"original_status":a.get("status"),"input_tokens":a.get("input_tokens"),"output_tokens":a.get("output_tokens"),"request_wall_ns":a.get("request_wall_ns"),"full_attempt_wall_ns":None,"full_attempt_wall_scope":"Not measured separately by the frozen runner. Cell wall and raw nested costs are retained.","recorded_cost_fields":costs(a),"edit_error":a.get("edit_error"),"generation_error":a.get("error"),"infrastructure_error":a.get("infrastructure_error"),"build_status":(a.get("build") or {}).get("status"),"public_status":(a.get("public") or {}).get("status"),"receipt":str(p.relative_to(B)),"matches_cell_attempt":same})
  final="correct" if r.get("correct") is True else "infrastructure" if r.get("fatal_error") else classified[-1] if classified else "unclassified_retained_status"
  cells.append({**d,"observed":True,"correct":r.get("correct") is True,"stage":final,"original_status":r.get("status"),"attempts":len(r.get("attempts",[])),"cell_wall_ns":r.get("cell_wall_ns"),"input_tokens_complete":r.get("input_tokens_complete"),"output_tokens_complete":r.get("output_tokens_complete"),"known_input_tokens":r.get("known_input_tokens"),"known_output_tokens":r.get("known_output_tokens"),"total_input_tokens":r.get("total_input_tokens"),"total_output_tokens":r.get("total_output_tokens"),"fatal_error":r.get("fatal_error"),"hidden_status":(r.get("hidden") or {}).get("status")})
 groups=[]
 for m in reg["models"]:
  for l,i in ARMS:
   chosen=[r for r in rows if (r["model_id"],r["language"],r["interface"])==(m,l,i)]
   cs=[r for r in cells if (r["model_id"],r["language"],r["interface"])==(m,l,i)]
   ats=[r for r in attempts if (r["model_id"],r["language"],r["interface"])==(m,l,i)]
   groups.append({"model_id":m,"language":l,"interface":i,"expected_cells":4,"observed_cells":len(chosen),"correct":sum(r["correct"] for r in chosen),"attempts":sum(len(r["attempts"]) for r in chosen),"cell_failure_stages":dict(sorted(Counter(r["stage"] for r in cs).items())),"attempt_stages":dict(sorted(Counter(r["stage"] for r in ats).items())),"attributable_cell_wall_ns":sum(r["cell_wall_ns"] for r in chosen),"cost_scope":"Only these four cells; common costs reported separately and not assigned again.",**tokens(chosen,4)})
 preps=[]
 for revision in (1,2,3):
  name="factorial-r"+str(revision);rp=B/name/"REGISTRATION.json";rr=read(rp)
  o=read(B/("factorial-driver-r"+str(revision))/"prepare.RESULT.json")
  sessions=[{"path":str(p.relative_to(B)),"lifecycle":read(p)} for p in sorted((B/name).glob("capacity-*/lifecycle.json"))]
  zero=rr.get("model_requests")==0 and all(x["lifecycle"].get("completion_requests_started")==0 and x["lifecycle"].get("completion_responses_received")==0 for x in sessions)
  if not zero:issues.append(name+" zero-generation receipt mismatch")
  preps.append({"revision":revision,"source_commit":rr["source_commit"],"source_tree":rr["source_tree"],"registration":identity(rp),"inner_wall_ns":rr["observed_preparation_wall_ns"],"command_wall_ns":o["command_wall_ns"],"outer_wall_ns":o["driver_wall_ns"],"zero_generation":zero,"sessions":sessions,"role":"final preparation" if revision==3 else "superseded zero-generation preparation; retained cost"})
 gate=read(outer/"PRELAUNCH_GATE.json");release=read(outer/"COMPOSITION_RELEASE_CHECK.json")
 preparation=sum(p["outer_wall_ns"] for p in preps)
 assert preparation==520706534029 and gate["wall_ns"]==41202167756 and release["wall_ns"]==63260537
 mainwall=wrapper["driver_wall_ns"] if wrapper else None
 total=preparation+mainwall+gate["wall_ns"]+release["wall_ns"] if mainwall is not None else None
 cost={"schema":"hepta.agent.edit-factorial.observed-costs.v1","preparations":preps,"all_preparation_outer_wall_ns":preparation,"main_outer_wall_ns":mainwall,"main_command_wall_ns":wrapper.get("command_wall_ns") if wrapper else None,"main_internal_cohort_wall_ns":result.get("cohort_wall_ns") if result else None,"final_prelaunch_gate_wall_ns":gate["wall_ns"],"desktop_release_check_wall_ns":release["wall_ns"],"actual_observed_prepare_main_and_release_wall_sum_ns":total,"source_footprint_materialization_setup_ns":8618618349,"actual_observed_sum_with_recorded_footprint_setup_ns":total+8618618349 if total is not None else None,"common_main_overhead_ns":result.get("common_observed_runner_and_model_overhead_ns") if result else None,"cost_allocation_rule":result.get("cost_allocation") if result else None,"warning":"Four solo-arm allocations overlap. Never sum them as actual campaign cost. Nested clocks are not added to outer clocks.","waiting_ci_and_coordination_wall_ns":None,"waiting_scope":"Waiting is separate and no complete waiting clock was measured.","historical_download_wall_ns":None,"human_labor_wall_ns":None,"energy_joules":None,"scope":"Observed process walls on a shared nonexclusive host. Outerdriver excludes final receipt publication and interpreter startup; not complete economic cost.","concurrent_evidence_io":{p.name:read(p) for p in sorted(outer.glob("CONCURRENT_EVIDENCE_IO_*.json"))},"footprint_receipt":identity(B/"factorial-r3-footprint.json")}
 summary={"schema":"hepta.agent.edit-factorial.observation.v1","source_commit":HEAD,"source_tree":TREE,"api_publication_projection":PROJECTION,"one_actual_cohort":True,"no_reruns_or_repairs":True,"expected_cells":32,"observed_cells":result.get("observed_cells") if result else len(disk),"completed":result.get("completed",False) if result else False,"correct":sum(r.get("correct") is True for r in rows),"official_result":identity(resultpath) if result else None,"source_unchanged":result.get("source_unchanged") if result else None,"runtime_unchanged":result.get("runtime_unchanged") if result else None,"registration_unchanged":result.get("registration_unchanged") if result else None,"cleanup":result.get("session_cleanup") if result else None,"errors":result.get("errors") if result else None,"official_arms":result.get("arms") if result else None,"groups_by_model_language_interface":groups,"cells":cells,"attempts":attempts,"integrity_issues":issues,"receipt_accounting_consistent":not issues,"token_totals":tokens(rows,32),"attempt_count":sum(len(r["attempts"]) for r in rows),"real_external_maintenance_corpus":False,"stable_productivity_advantage":False,"scope":"One preregistered authored four-task, two-model, language x edit-interface pilot; not real external maintenance or population productivity evidence."}
 write(pub/"OBSERVATION.json",summary);write(pub/"COSTS.json",cost)
 if result:shutil.copyfile(resultpath,pub/"RESULT.json")
 shutil.copyfile(B/"factorial-r3-preparation-ledger.json",pub/"PREPARATION_LEDGER.json")
 shutil.copyfile(__file__,pub/"PACKAGER.py")
 sources={}
 for rev in (1,2,3):
  for name in ("factorial-r"+str(rev),"factorial-driver-r"+str(rev)):
   root=B/name;sources["retained/"+name]=root
   for p in sorted(root.rglob("*")):sources["retained/"+str(p.relative_to(B))]=p
 for p in sorted(B.glob("factorial-*")):
  if p.is_file():sources["retained/"+p.name]=p
 for rel,wanted in reg["source_bindings"].items():
  p=S/rel;assert identity(p)["sha256"]==wanted
  sources["registered-source/"+rel]=p
 sources["packaging/PACKAGER.py"]=Path(__file__)
 patterns=[("github_token",re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),("aws_access_key",re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),("openai_secret",re.compile(rb"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}")),("private_key",re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"))]
 members=[];findings=[];scanned=0;archive=P/"agent-edit-factorial-all-raw.tar"
 with tarfile.open(archive,"w",format=tarfile.PAX_FORMAT,dereference=False) as tar:
  for name,p in sorted(sources.items()):
   assert not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
   st=p.lstat()
   if p.suffix.lower()==".gguf":raise RuntimeError("model weight in evidence root")
   r={"path":name,"original_path":str(p),"mode":stat.S_IMODE(st.st_mode),"mtime_ns":st.st_mtime_ns}
   if p.is_symlink():r.update(type="symlink",target=os.readlink(p))
   elif p.is_dir():r.update(type="directory")
   elif p.is_file():
    r.update(type="file",bytes=st.st_size,sha256=identity(p)["sha256"])
    with p.open("rb") as f:
     offset=0;prev=b""
     while chunk:=f.read(1024*1024):
      block=prev+chunk;scanned+=len(chunk)
      for label,pattern in patterns:
       for match in pattern.finditer(block):findings.append({"path":name,"pattern":label,"offset":max(0,offset-len(prev)+match.start())})
      offset+=len(chunk);prev=block[-256:]
   else:raise RuntimeError("unsupported evidence type: "+str(p))
   members.append(r)
   info=tar.gettarinfo(str(p),arcname=name)
   if r["type"]=="file":
    info.type=tarfile.REGTYPE;info.linkname="";info.size=st.st_size
    with p.open("rb") as stream:tar.addfile(info,stream)
   else:tar.addfile(info)
 write(pub/"MEMBERS.json",{"schema":"hepta.agent.raw-members.v1","members":members,"all_selected_roots_retained":True,"model_weights_added":False,"selected_roots":["factorial-r1","factorial-r2","factorial-r3","factorial-driver-r1","factorial-driver-r2","factorial-driver-r3"],"scope":"Every member of these roots plus original top-level factorial metadata/drivers and final registered source; no evaluator rerun."})
 raw=identity(archive);encoded=P/"agent-edit-factorial-all-raw.tar.xz"
 with archive.open("rb") as src,lzma.open(encoded,"wb",preset=6) as dst:shutil.copyfileobj(src,dst)
 packed=identity(encoded);parts=[]
 with encoded.open("rb") as f:
  i=0
  while chunk:=f.read(768*1024):
   name="agent-edit-factorial-all-raw.tar.xz.part-"+str(i).zfill(3);(pub/name).write_bytes(chunk)
   parts.append({"name":name,"bytes":len(chunk),"sha256":hashlib.sha256(chunk).hexdigest()});i+=1
 write(pub/"MANIFEST.json",{"schema":"hepta.lossless.agent-factorial-package.v1","encoding":"xz","parts":parts,"encoded_bytes":packed["bytes"],"encoded_sha256":packed["sha256"],"restored_name":archive.name,"restored_bytes":raw["bytes"],"restored_sha256":raw["sha256"],"member_count":len(members),"member_manifest":"MEMBERS.json","maximum_part_bytes":768*1024,"source_commit":HEAD,"source_tree":TREE,"model_weights_added":False})
 write(pub/"PUBLIC_SAFETY_SCREEN.json",{"patterns":[n for n,_ in patterns],"scanned_bytes":scanned,"findings":findings,"candidate_count":len(findings),"scope":"Bounded high-confidence patterns over original bytes; not universal secrecy or recursive compressed-payload audit.","pattern_screen_passed":not findings})
 restore=r'''#!/usr/bin/env python3
import argparse,hashlib,json,lzma,shutil,tarfile
from pathlib import Path,PurePosixPath
p=argparse.ArgumentParser();p.add_argument("--out",required=True);a=p.parse_args()
root=Path(__file__).resolve().parent;m=json.loads((root/"MANIFEST.json").read_text())
out=Path(a.out);out.mkdir(exist_ok=False);encoded=out/"joined.tar.xz";digest=hashlib.sha256()
with encoded.open("xb") as f:
 for part in m["parts"]:
  data=(root/part["name"]).read_bytes()
  assert len(data)==part["bytes"] and hashlib.sha256(data).hexdigest()==part["sha256"]
  digest.update(data);f.write(data)
assert encoded.stat().st_size==m["encoded_bytes"] and digest.hexdigest()==m["encoded_sha256"]
raw=out/m["restored_name"]
with lzma.open(encoded,"rb") as src,raw.open("xb") as dst:shutil.copyfileobj(src,dst)
with raw.open("rb") as f:digest=hashlib.file_digest(f,"sha256").hexdigest()
assert raw.stat().st_size==m["restored_bytes"] and digest==m["restored_sha256"]
expected={r["path"]:r for r in json.loads((root/"MEMBERS.json").read_text())["members"]};seen=set()
with tarfile.open(raw,"r:") as archive:
 for member in archive:
  assert member.name in expected and member.name not in seen
  assert not PurePosixPath(member.name).is_absolute() and ".." not in PurePosixPath(member.name).parts
  seen.add(member.name);r=expected[member.name]
  if r["type"]=="file":
   assert member.isfile()
   with archive.extractfile(member) as f:observed=hashlib.file_digest(f,"sha256").hexdigest()
   assert member.size==r["bytes"] and observed==r["sha256"]
  elif r["type"]=="directory":assert member.isdir()
  elif r["type"]=="symlink":assert member.issym() and member.linkname==r["target"]
assert seen==set(expected)
print(json.dumps({"restored":str(raw),"bytes":raw.stat().st_size,"sha256":digest,"members_verified":len(seen),"no_archived_code_executed":True},sort_keys=True))
'''
 (pub/"RESTORE.py").write_text(restore)
 argv=[sys.executable,str(pub/"RESTORE.py"),"--out",str(P/"restore-check")]
 done=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 write(P/"RESTORE_COMMAND.json",{"argv":argv,"returncode":done.returncode,"stdout":done.stdout,"stderr":done.stderr})
 if done.returncode:raise RuntimeError("lossless restore failed")
 write(pub/"RESTORATION_CHECK.json",json.loads(done.stdout))
 lines=["# Agent language x edit-interface pilot","", "Measured original source: "+HEAD+"; tree: "+TREE+".",
 "GitHub App projection: "+PROJECTION+". Distinct commit identities are not relabeled.","",
 "One actual 32-cell cohort; four authored two-file math tasks; two local quantized models; assembly/Rust x full/patch.",
 "R1 and r2 preparations generated zero answers and were superseded after source integration corrections. Their costs and original bytes remain retained.",
 "This descriptive pilot does not establish real external maintenance or stable productivity advantage.","",
 "| Model | Language | Interface | Correct / expected | Attempts | Known input | Known output |","|---|---|---|---:|---:|---:|---:|"]
 for r in groups:lines.append("| "+" | ".join(map(str,[r["model_id"],r["language"],r["interface"],str(r["correct"])+" / 4",r["attempts"],r["known_input_tokens"],r["known_output_tokens"]]))+" |")
 lines+=["","OBSERVATION.json retains receipt-derived failure stages, original statuses, token completeness/nulls, all recorded attempt costs, and unchanged official arm allocations.",
 "Full attempt walls were not separately measured. Request and nested build/validation clocks are retained without adding overlapping timers.","",
 "Actual observed cost is three preparation outer walls + one main outer wall + final release/source/runtime gate + desktop release check = "+str(total)+" ns.",
 "The separately recorded source-footprint setup is 8618618349 ns. Four descriptive solo-arm allocations overlap and must never be summed as four actual campaigns.",
 "CPUs 8-11 were selected, not reserved; host was shared/nonexclusive, with bounded concurrent evidence IO disclosed in COSTS.json.",
 "CI/coordination waiting is separate; human labor, historical downloads, energy and unmeasured waiting remain unknown.","",
 "Every file in all three output and outerdriver roots is retained: requests/responses, attempted edits, native candidates, compile/public/hidden-oracle receipts, engines, identities, cleanup, failures and original drivers.",
 "Final registered source files are included. No GGUF model weights were added, and originals were not rewritten.",
 "Restore with python3 RESTORE.py --out /absolute/new/directory. It verifies parts, the exact TAR and every member without executing archived code.",
 "MEMBERS.json records every path and hash; PUBLIC_SAFETY_SCREEN.json states the bounded publication-screen scope.","",
 "Reporting performs no new response decoding, repair, compilation, evaluator/hidden-oracle run or same-cell rerun.",""]
 (pub/"README.md").write_text("\n".join(lines))
 assert git("rev-parse","HEAD")==HEAD and git("status","--porcelain","--untracked-files=all")==""
 unchanged=True
 for r in members:
  if r["type"]=="file" and identity(r["original_path"])["sha256"]!=r["sha256"]:
   unchanged=False;issues.append("original changed during packaging: "+r["original_path"])
 output={"schema":"hepta.agent.factorial.packaging-result.v1","public_directory":str(pub),"public_files":[identity(p) for p in sorted(pub.iterdir())],"public_bytes":sum(p.stat().st_size for p in pub.iterdir()),"raw_archive":raw,"encoded_archive":packed,"member_count":len(members),"part_count":len(parts),"restoration_verified":True,"originals_unchanged":unchanged,"source_clean_and_unchanged":True,"integrity_issues":issues,"public_release_ready":not findings and unchanged and not issues,"packaging_wall_ns":time.monotonic_ns()-started,"packaging_cpu_affinity":sorted(os.sched_getaffinity(0)),"packaging_scope":"Post-terminal evidence work outside experiment; not a benchmark.","finished_unix_ns":time.time_ns()}
 write(P/"PACKAGING_RESULT.json",output);print(json.dumps(output,sort_keys=True),flush=True)
if __name__=="__main__":main()
