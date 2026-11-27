import hashlib,json,os,pathlib,resource,signal,stat,subprocess,time
BASE=pathlib.Path("/tmp/hia-progress-v147-20261114-dda7")
plan_raw=(BASE/"RUNTIME-READINESS-PLAN.json").read_bytes()
PLAN=json.loads(plan_raw)
OUT=pathlib.Path(PLAN["output"])
assert not OUT.exists()
OUT.mkdir(mode=0o700)
def pin(raw):
 return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def seven(s):
 return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def guard():
 mapraw=pathlib.Path(PLAN["runtime_file_map"]).read_bytes()
 assert pin(mapraw)["git_blob"]==PLAN["runtime_file_map_git"]
 m=json.loads(mapraw);root=pathlib.Path(PLAN["runtime_root"])
 assert m["root"]==str(root) and m["original_identity_claimed"] is False
 total=0
 for row in m["files"]:
  p=root/row["path"];before=p.lstat()
  assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
  raw=p.read_bytes()
  assert seven(before)==seven(p.lstat())==row["new_file_seven_stat"]
  assert pin(raw)==row["pin"] and stat.S_IMODE(before.st_mode)==row["mode"]
  total+=len(raw)
 assert len(m["files"])==PLAN["runtime_files"] and total==PLAN["runtime_bytes"]
 for path,sha in [("bin/python3.14",PLAN["executable_sha256"]),("lib/libpython3.14.so.1.0",PLAN["library_sha256"])]:
  assert hashlib.sha256((root/path).read_bytes()).hexdigest()==sha
 payload=pathlib.Path(PLAN["payload_path"]).read_bytes()
 assert pin(payload)["git_blob"]==PLAN["payload_git"]
 return {"files":len(m["files"]),"bytes":total,"map":pin(mapraw),"payload":pin(payload)}
def dump(name,value):
 (OUT/name).write_bytes((json.dumps(value,sort_keys=True,indent=2)+"\n").encode())
def limits():
 resource.setrlimit(resource.RLIMIT_CPU,(PLAN["CPU_seconds"],PLAN["CPU_seconds"]))
before=guard();dump("BEFORE.json",before)
started=time.monotonic_ns();timedout=False
p=subprocess.Popen(PLAN["command"],cwd=OUT,env=PLAN["environment"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=limits)
try:
 stdout,stderr=p.communicate(timeout=PLAN["timeout_seconds"])
except subprocess.TimeoutExpired:
 timedout=True
 os.killpg(p.pid,signal.SIGTERM)
 try:stdout,stderr=p.communicate(timeout=PLAN["cleanup_seconds"])
 except subprocess.TimeoutExpired:
  os.killpg(p.pid,signal.SIGKILL)
  stdout,stderr=p.communicate(timeout=PLAN["cleanup_seconds"])
(OUT/"stdout.bin").write_bytes(stdout);(OUT/"stderr.bin").write_bytes(stderr)
try:os.killpg(p.pid,0);group_absent=False
except ProcessLookupError:group_absent=True
try:
 child=os.waitpid(-1,os.WNOHANG);echild=False
except ChildProcessError:echild=True
after=guard();dump("AFTER.json",after)
assert before==after
result={"schema":"hepta.runtime-post-reset-readiness-result.v1","status":"PASS_STDLIB_READINESS_ONLY" if p.returncode==0 and not timedout and group_absent and echild else "FAIL",
 "plan":pin(plan_raw),"returncode":p.returncode,"timed_out":timedout,"elapsed_ns":time.monotonic_ns()-started,
 "stdout":pin(stdout),"stderr":pin(stderr),"process_group_absent":group_absent,"observed_ECHILD":echild,
 "all2496_runtime_files_full_read_before_after":True,"runtime_unchanged":True,
 "recovered_binary_executions":1,"project_imports":0,"product_calls":0,"CI":0,"current_full_product_qualification":False,
 "old_venv_or_dynamic_mapping_qualification_inherited":False,"whole_native":False,"production_legacy_retired":False}
if p.returncode==0:
 result["observed"]=json.loads(stdout)
dump("RESULT.json",result)
print(json.dumps({k:result[k] for k in ("status","returncode","timed_out","elapsed_ns","stdout","stderr","process_group_absent","observed_ECHILD","product_calls")},sort_keys=True))
raise SystemExit(0 if result["status"].startswith("PASS_") else 1)
