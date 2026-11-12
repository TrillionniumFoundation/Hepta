from pathlib import Path
import ast,hashlib,json,re,stat,subprocess,sys,yaml
base=Path("/workspace/scratch/9acdfa9f5639");stage=base/"follow57-source-stage";prior=base/"follow56-source-stage/exact-source"
def identity(raw):
 return {"bytes":len(raw),"gitsha":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),"sha256":hashlib.sha256(raw).hexdigest()}
def check(path,row):
 assert path.is_file() and not path.is_symlink(),str(path)
 raw=path.read_bytes();pin=identity(raw)
 assert all(pin[k]==row[k] for k in pin),row["path"]
 assert stat.S_IMODE(path.stat().st_mode)==int(row["mode"][-3:],8)
 return raw
old=json.loads((stage/"old-active.json").read_bytes());current=json.loads((stage/"active.json").read_bytes())
assert len(old)==1110 and len(current)==1128
assert len({r["path"] for r in current})==1128 and {r["path"] for r in old}<={r["path"] for r in current}
for row in old:check(prior/row["path"],row)
records=[];paths={}
for row in current:
 p=stage/"overlay"/row["path"]
 if not p.exists():p=prior/row["path"]
 raw=check(p,row);ast.parse(raw,filename=row["path"]);paths[row["path"]]=p;records.append({**row,"status":"PASS_AST_ONLY"})
route=json.loads((stage/"route.json").read_bytes());carrier=paths[route["caller_path"]].read_text()
original=(stage/"carrier-before.py").read_text();insertion=(stage/"carrier-insert.py.txt").read_text()
assert carrier.count(insertion)==1 and carrier.replace(insertion,"",1)==original
target=route["target"];check(paths[target["path"]],target)
index=json.loads((stage/"source-index-r2.json").read_bytes())
assert len(index["source_files"])==17 and len({x["repository_path"] for x in index["source_files"]})==17
for row in index["source_files"]:
 if row["repository_path"].endswith(".py"):
  p=paths[row["repository_path"]];b=p.read_bytes()
  assert all(identity(b)[k]==row[k] for k in ("bytes","gitsha","sha256"))
  assert stat.S_IMODE(p.stat().st_mode)==row["mode"]
before_raw=(stage/"workflow-before.yml").read_text();after_raw=(stage/"workflow-after.yml").read_text()
before=yaml.load(before_raw,Loader=yaml.BaseLoader);after=yaml.load(after_raw,Loader=yaml.BaseLoader)
assert set(before)==set(after)
for key in before:
 if key!="jobs":assert before[key]==after[key]
assert len(before["jobs"])==len(after["jobs"])==155 and set(before["jobs"])==set(after["jobs"])
changed=[key for key in before["jobs"] if before["jobs"][key]!=after["jobs"][key]]
assert changed==["namespace_engine_original_sources_r1"],changed
b=before["jobs"][changed[0]];a=after["jobs"][changed[0]];delta=json.loads((stage/"workflow-delta.json").read_bytes())
for key in b:
 if key not in ("steps","timeout-minutes"):assert b[key]==a[key],key
assert b["timeout-minutes"]=="25" and a["timeout-minutes"]==delta["timeoutExpr"]
assert a["permissions"]=={"contents":"read","actions":"read"} and len(a["steps"])==len(b["steps"])
diff=[]
for bs,ns in zip(b["steps"],a["steps"]):
 if bs!=ns:
  diff.append(bs["name"]);assert bs["name"]=="Execute bounded independent evidence task"
  assert {k:v for k,v in ns.items() if k not in ("run","env")}=={k:v for k,v in bs.items() if k not in ("run","env")}
  assert {k:v for k,v in ns["env"].items() if k!="HIA_TRUE_SELF_REBUILD_SELECTED"}==bs["env"]
  assert ns["env"]["HIA_TRUE_SELF_REBUILD_SELECTED"]==delta["expr"]
  assert 'timeout --signal=TERM --kill-after=5s 180s ' in ns["run"]
  assert 'timeout --signal=TERM --kill-after=5s 2800s ' in ns["run"]
  assert bs["run"] in ns["run"]
  subprocess.run(["bash","-n"],input=ns["run"].encode(),check=True)
assert diff==["Execute bounded independent evidence task"]
assert before_raw.count(delta["before"])==1 and before_raw.replace(delta["before"],delta["after"],1)==after_raw
inverse=delta["after"].replace("    timeout-minutes: "+delta["timeoutExpr"]+"\n","    timeout-minutes: 25\n").replace("          HIA_TRUE_SELF_REBUILD_SELECTED: "+delta["expr"]+"\n","").replace(delta["newRun"],delta["oldRun"])
assert inverse==delta["before"]
report={"schema":"hia-follow57-root-source-workflow-check-r1","status":"PASS_SOURCE_ONLY","python":sys.version,"old_active":1110,"new_active":1128,"old_paths_preserved":True,"updated_active_sources":1,"added_active_sources":18,"all_size_mode_sha_git_AST_checked":True,"workflow_jobs":155,"changed_workflow_jobs":changed,"other154_jobs_text_exact":True,"old_fallback_source_exact":True,"old_job_minutes":25,"old_outer_wall_seconds":180,"new_selected_job_minutes":55,"new_selected_outer_wall_failsafe_seconds":2800,"new_driver_outer_wall_seconds":2700,"new_driver_stage_limits_unchanged":True,"source_index_python_inputs_checked":16,"target_executions":0,"production_activation":False,"whole_stack_closed":False,"files":records}
out=stage/"source-and-workflow-check.json";out.write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({k:v for k,v in report.items() if k!="files"},sort_keys=True))
