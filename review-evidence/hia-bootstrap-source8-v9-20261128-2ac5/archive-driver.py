from pathlib import Path
import os,json,time,hashlib,stat,tarfile,traceback
R=Path("/home/qian-qi/hia-bootstrap-vm-dispatch-v9-20261128-2ac5")
E=Path("/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-vm-dispatch-v9-20261128-2ac5/source8-complete-original-v1")
E.mkdir(mode=0o700,parents=True,exist_ok=False)
def emit(name,value):
 p=E/name;p.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n");return p
def digest(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def stamp(s):return [s.st_dev,s.st_ino,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
start=time.monotonic()
try:
 Q=R/"source8-v9-v1";terminal=json.loads((Q/"source8.terminal.json").read_bytes())
 tree=json.loads((Q/"source8/suite.tree-terminal.json").read_bytes())
 assert terminal["source"]=="175ac187d63bc67f77c4e40a366e6dd5d2416e49" and terminal["source_unchanged"] and terminal["returncode"]==1
 assert tree["all_captured_reaped"] and not tree["unattributed_children"]
 pids=[2202654,2202689,2219617,2306557]
 states={str(pid):(Path("/proc")/str(pid)/"stat").exists() for pid in pids}
 assert not any(states.values()),states
 emit("archive.start.json",{"time_ns":time.time_ns(),"root":str(R),"source_scope":"All non-source task materials including original full gate, 1024 diagnostic and complete physical source manifest; exact published Git source excluded","terminal":terminal,"tree":tree,"original_pid_paths_absent":states,"storage_free":os.statvfs(E).f_bavail*os.statvfs(E).f_frsize})
 records=[]
 def collect(p,arc):
  s=p.lstat();row={"path":str(arc),"source_path":str(p),"mode":stat.S_IMODE(s.st_mode)}
  if stat.S_ISDIR(s.st_mode):
   row["type"]="directory";records.append(row)
   for ch in sorted(p.iterdir()):collect(ch,arc/ch.name)
  else:
   assert stat.S_ISREG(s.st_mode),(str(p),s.st_mode)
   row.update(type="file",bytes=s.st_size,sha256=digest(p),stamp=stamp(s))
   assert stamp(p.lstat())==row["stamp"];records.append(row)
 for p in sorted(R.iterdir()):
  if p.name!="source":collect(p,Path("original")/p.name)
 index=emit("members.json",{"schema":"hia.complete-original-evidence.v1","root":str(R),"source_head":terminal["source"],"files":sum(x["type"]=="file" for x in records),"directories":sum(x["type"]=="directory" for x in records),"raw_bytes":sum(x.get("bytes",0) for x in records),"members":records})
 archive=E/"source8-v9-complete-failure.tar.gz"
 with tarfile.open(archive,"w:gz",compresslevel=1,dereference=False) as tf:
  for r in records:tf.add(r["source_path"],arcname=r["path"],recursive=False)
 expected={r["path"]:r for r in records};seen=set()
 with tarfile.open(archive,"r:gz") as tf:
  for m in tf:
   assert m.name in expected and m.name not in seen;seen.add(m.name);r=expected[m.name]
   assert m.mode==r["mode"]
   if r["type"]=="directory":assert m.isdir()
   else:
    assert m.isfile() and m.size==r["bytes"];h=hashlib.sha256()
    with tf.extractfile(m) as f:
     for b in iter(lambda:f.read(1048576),b""):h.update(b)
    assert h.hexdigest()==r["sha256"],m.name
 assert seen==set(expected)
 for r in records:
  p=Path(r["source_path"]);s=p.lstat();assert stat.S_IMODE(s.st_mode)==r["mode"]
  if r["type"]=="file":assert stamp(s)==r["stamp"] and digest(p)==r["sha256"],str(p)
 report={"status":"PASS_COMPLETE_ORIGINAL_ARCHIVE","source8_status":"FAIL_TIMEOUT","method7":"ERROR_TERMINAL_LATE_DIFFERENCES_7_AFTER_COMPLETE_VM_15830","method8":"INTERRUPTED_AFTER_5892","archive":str(archive),"archive_bytes":archive.stat().st_size,"archive_sha256":digest(archive),"index":str(index),"index_sha256":digest(index),"files":sum(r["type"]=="file" for r in records),"directories":sum(r["type"]=="directory" for r in records),"raw_bytes":sum(r.get("bytes",0) for r in records),"all_members_verified":True,"source_files_terminal_same":True,"deleted_original_files":0,"elapsed_seconds":time.monotonic()-start}
 emit("archive.terminal.json",report);print(json.dumps(report),flush=True)
except BaseException:
 emit("archive.failure.json",{"error":traceback.format_exc(),"elapsed_seconds":time.monotonic()-start});raise
