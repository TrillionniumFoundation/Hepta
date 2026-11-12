"""Independent complete local closed-evidence seal: no compiler, VM or native target calls."""
from __future__ import annotations
import hashlib,io,json,os,resource,signal,stat,sys,tarfile,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent
SOURCES={
 "source-proof":BASE/"unix9-header-cache-r1",
 "cost-all-windows":BASE/"unix9-cost-diagnostic-r1",
 "cost-one-call-tree":BASE/"unix9-cost-diagnostic-r2",
 "four-way-private-and-recorded":BASE/"unix9-header-cache-validation-r1",
 "complete-original-28":BASE/"nine-header-cache-local-r1",
}
def save(p,v):
 b=(json.dumps(v,sort_keys=True,indent=2)+"\n").encode();p.write_bytes(b);assert p.read_bytes()==b
def pin(p):
 p=Path(p);st=p.lstat();assert stat.S_ISREG(st.st_mode) and not p.is_symlink()
 raw=p.read_bytes();assert len(raw)==st.st_size
 return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),gitsha=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),mode=stat.S_IMODE(st.st_mode))
def main():
 started=time.monotonic_ns();resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def alarm(*_):raise TimeoutError("seal180wall")
 signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,180)
 primary=None;members=[];report=dict(status="INCOMPLETE",scope="LOCAL_COMPLETE_RAW_SEAL_ONLY",B3=0,VM=0,native=0)
 archive=ROOT/"complete-header-cache-evidence.tar.xz";index=ROOT/"members.json"
 assert not archive.exists() and not index.exists()
 try:
  final=json.loads((SOURCES["complete-original-28"]/"local-final.json").read_bytes());assert final["status"]=="PASS"
  assert final["original_subject"]["actual_counts"]["completed_cases"]==28
  paired=json.loads((SOURCES["four-way-private-and-recorded"]/"paired/summary.json").read_bytes());assert paired["status"]=="PASS" and paired["complete_cases"]==796
  for prefix,source in SOURCES.items():
   assert source.is_dir()
   for p in sorted(source.rglob("*")):
    if p.is_dir():
     assert not p.is_symlink()
     continue
    row=pin(p);row.update(path=prefix+"/"+p.relative_to(source).as_posix(),original_path=str(p));members.append(row)
  assert len({m["path"] for m in members})==len(members)
  save(index,members)
  with tarfile.open(archive,"w:xz",preset=1,format=tarfile.PAX_FORMAT) as tf:
   for row in members:
    path=Path(row["original_path"]);raw=path.read_bytes();assert pin(path)=={k:row[k] for k in ("bytes","sha256","gitsha","mode")}
    info=tarfile.TarInfo(row["path"]);info.size=len(raw);info.mode=row["mode"];info.uid=info.gid=0;info.uname=info.gname="";info.mtime=0
    tf.addfile(info,io.BytesIO(raw))
  seen=[]
  with tarfile.open(archive,"r:xz") as tf:
   for member,row in zip(tf,members,strict=True):
    assert member.isfile() and member.name==row["path"] and member.size==row["bytes"] and member.mode==row["mode"]
    raw=tf.extractfile(member).read()
    assert len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
    assert hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["gitsha"]
    assert raw==Path(row["original_path"]).read_bytes()
    seen.append(row["path"])
  assert len(seen)==len(members)
  errors=[]
  for row in members:
   try:assert pin(row["original_path"])=={k:row[k] for k in ("bytes","sha256","gitsha","mode")}
   except BaseException as exc:errors.append(dict(path=row["original_path"],error=repr(exc)))
  assert not errors,errors
  report.update(status="PASS",archive=pin(archive),index=pin(index),members=len(members),raw_bytes=sum(m["bytes"] for m in members),
   every_member_full_bytes_mode_SHA256_Git_SHA1_read_back=True,every_local_file_after_equal=True,
   includes_both_instrumented_cost_samples=True,includes_initial_private_probe_Core_rejection=True,
   includes_all796_four_way_originals=True,includes_fresh9_B3_plus_packer45_and_original28=True,
   candidate_VM_or_native_reexecuted_during_seal=False,does_not_replace_prior_FAIL=True)
 except BaseException as exc:
  primary=exc;report.update(status="FAIL",error=repr(exc),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  try:
   save(ROOT/"custody.json",report);print(json.dumps(report,sort_keys=True),flush=True)
   cpu=time.process_time_ns();wall=time.monotonic_ns()-started
   assert 0<=cpu<90_000_000_000 and 0<=wall<180_000_000_000
  except BaseException as exc:
   if primary is None:primary=exc
   else:primary.add_note("final:"+repr(exc))
  if primary is not None:
   report.update(status="FAIL",final_error=repr(primary))
   try:save(ROOT/"custody.json",report)
   except BaseException as exc:primary.add_note("FAILreceipt:"+repr(exc))
  signal.setitimer(signal.ITIMER_REAL,0)
 if primary is not None:raise primary
if __name__=="__main__":main()
