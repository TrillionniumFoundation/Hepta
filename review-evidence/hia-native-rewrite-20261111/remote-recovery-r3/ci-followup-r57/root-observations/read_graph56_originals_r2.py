from pathlib import Path,PurePosixPath
import hashlib,json,zipfile,tarfile,resource,time,signal
base=Path("/workspace/scratch/9acdfa9f5639");folder=base/"follow57-root-originals/graph56-r2";zip_path=base/"artifacts/follow56-unified-Graph-original.zip"
started=time.monotonic_ns();resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0));signal.alarm(180)
def budget():assert time.monotonic_ns()-started<180000000000
def file_pin(path):
 n=path.stat().st_size;h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(n).encode()+b"\0")
 with path.open("rb") as f:
  while b:=f.read(1<<20):h.update(b);g.update(b);budget()
 return {"bytes":n,"sha256":h.hexdigest(),"gitsha":g.hexdigest()}
before=file_pin(zip_path);assert before["bytes"]==414178682 and before["sha256"]=="1499b70f25000c5778d29cf49bb7fb61f1c278b21d685457f01437129dfe6f4d"
prefix="hia-backend-current-program-graph-recovery/";outer=[];seen=set();archive=folder/"evidence.tar.xz"
with zipfile.ZipFile(zip_path) as z:
 for m in z.infolist():
  assert m.filename not in seen and not m.is_dir();seen.add(m.filename)
  h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(m.file_size).encode()+b"\0");n=0
  target=archive.open("xb") if m.filename==prefix+"evidence.tar.xz" else None
  try:
   with z.open(m) as s:
    while b:=s.read(1<<20):
     h.update(b);g.update(b);n+=len(b)
     if target:target.write(b)
     budget()
  finally:
   if target:target.close()
  assert n==m.file_size
  outer.append({"path":m.filename,"bytes":n,"sha256":h.hexdigest(),"gitsha":g.hexdigest(),"mode":m.external_attr>>16,"zip_crc":m.CRC})
assert len(outer)==1246 and sum(r["bytes"] for r in outer)==413662904
custody=json.loads((folder/"custody.json").read_bytes());ap=file_pin(archive)
assert ap["bytes"]==custody["bytes"] and ap["sha256"]==custody["sha256"]
ledger=folder/"evidence-members.jsonl";assert file_pin(ledger)["sha256"]==custody["member_index_sha256"]
expected={}
for line in ledger.read_bytes().splitlines():
 row=json.loads(line);assert row["name"] not in expected;expected[row["name"]]=row
assert len(expected)==8600
members=0;total=0;observed=set();selected=[]
with tarfile.open(archive,"r:xz") as t:
 for m in t:
  assert m.name in expected and m.name not in observed and m.isfile() and not m.issym() and not m.islnk(),m.name
  observed.add(m.name);r=expected[m.name];assert m.mode==r["mode"] and m.size==r["bytes"],m.name
  p=PurePosixPath(m.name);assert not p.is_absolute() and ".." not in p.parts
  export=("backend-unified-program-Graph-native-r1/" in m.name and (m.name.endswith("summary.json") or m.name.endswith("post-output-budget.json") or m.name.endswith(".receipt.json")))
  dest=folder/"originals"/p if export else None
  if dest:dest.parent.mkdir(parents=True,exist_ok=True)
  writer=dest.open("xb") if dest else None
  h=hashlib.sha256();n=0
  try:
   with t.extractfile(m) as s:
    while b:=s.read(1<<20):
     h.update(b);n+=len(b)
     if writer:writer.write(b)
     budget()
  finally:
   if writer:writer.close()
  assert n==m.size and h.hexdigest()==r["sha256"],m.name
  if dest:selected.append({"archive_path":m.name,"local":str(dest),**file_pin(dest)})
  members+=1;total+=n;t.members.clear()
assert observed==set(expected) and total==1456783421
assert file_pin(zip_path)==before and file_pin(archive)==ap
u=resource.getrusage(resource.RUSAGE_SELF);cpu=u.ru_utime+u.ru_stime;wall=time.monotonic_ns()-started;assert cpu<90 and wall<180000000000
report={"schema":"hia-root-follow56-unified-Graph-full-original-readback-r1","status":"PASS","job":131386199220,"run":43276498118,"artifact":13970413635,"outer_archive":before,"outer_members":1246,"outer_raw_bytes":413662904,"inner_archive":ap,"inner_members":members,"inner_raw_bytes":total,"all_member_bytes_mode_SHA_checked":True,"all_originals_after_checked":True,"aggregate_CPU_seconds":cpu,"elapsed_ns":wall,"target_executions":0,"scope":"Full original evidence byte readback only; fresh target execution is the separately recorded Ubuntu job"}
(folder/"outer-members.json").write_text(json.dumps(outer,indent=2)+"\n");(folder/"selected-originals.json").write_text(json.dumps(selected,indent=2)+"\n");(folder/"root-full-readback.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report,sort_keys=True));print("selected raw originals",len(selected))
