"""Exact readonly FOLLOW36 composition artifact recovery; no subject execution."""
from pathlib import Path, PurePosixPath
import hashlib,json,zipfile,tarfile,signal,resource,os,time
os.sched_setaffinity(0,{4})
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
signal.alarm(180)
ROOT=Path("/workspace/scratch/9acdfa9f5639/hia-work37/worker/composition36-original")
ZIP=ROOT/"artifact13922316358.zip";OUT=ROOT/"readback-r1";OUT.mkdir(exist_ok=False)
started=time.monotonic_ns()
def sha(b):return hashlib.sha256(b).hexdigest()
def fs(path):
 with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def safe(n):
 p=PurePosixPath(n);assert n and not p.is_absolute() and ".." not in p.parts and "\\" not in n
def save(path,b,mode=420):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("xb") as f:f.write(b)
 path.chmod(mode);assert path.read_bytes()==b and path.stat().st_mode&4095==mode
assert ZIP.stat().st_size==407227860 and fs(ZIP)=="bdea2a680c2c715e946553f89c3a4224bdbda5f21f68acf65ec7ac1208bdf362"
ziprows=[];saved=[];verified={}
with zipfile.ZipFile(ZIP) as z:
 names=[i.filename for i in z.infolist()];assert len(names)==len(set(names))
 for i in z.infolist():
  safe(i.filename)
  if i.is_dir():continue
  assert (i.external_attr>>16)&0o170000!=0o120000
  with z.open(i) as f:
   h=hashlib.sha256();n=0
   while True:
    b=f.read(1<<20)
    if not b:break
    n+=len(b);h.update(b)
  assert n==i.file_size
  ziprows.append(dict(name=i.filename,bytes=n,sha256=h.hexdigest()))
 n=next(n for n in names if n.endswith("/evidence.tar.xz"));prefix=n.rsplit("/",1)[0]
 idx=z.read(prefix+"/evidence-members.json");cust=z.read(prefix+"/custody.json")
 assert len(idx)==18856776 and sha(idx)=="be202ec4f7e5a76a048f4c6a697669a243d47c1d1b0e508207489ee8016718e2"
 rows=json.loads(idx);assert len(rows)==35112
 expected={}
 for r in rows:
  safe(r["name"]);assert r["name"] not in expected
  expected[r["name"]]=r
 assert sum(r["bytes"] for r in rows)==509705277
 c=json.loads(cust);assert c["status"]=="FAIL" and c["members"]==35112 and c["original_bytes"]==509705277
 assert c["sha256"]=="4457ec3724251644ffc454a8acbcd99fc9684e92f3b3dbd4baa28280123c7291" and c["bytes"]==326118620
 save(OUT/"original-index.json",idx);save(OUT/"original-custody.json",cust)
 arc=OUT/"evidence.tar.xz"
 with z.open(n) as f,arc.open("xb") as o:
  while True:
   b=f.read(1<<20)
   if not b:break
   o.write(b)
 assert arc.stat().st_size==326118620 and fs(arc)==c["sha256"]
def selected(n):
 if n.startswith("run/steps/"):return True
 if n.endswith(("/cases.jsonl","/entries.jsonl","/pending.json","/pending-native-entry.json","/source-before.json","/source-after.json","/summary.json","/bundle.json","/source.json")):return True
 if "/cas/" in n:return False
 return n.endswith((".py",".hiaasm",".image.bin",".input.bin",".receipt.json",".manifest.json",".md")) and not n.startswith("run/worker-restore/")
with tarfile.open(arc,"r|xz") as tf:
 for m in tf:
  assert m.isfile() and m.name in expected and m.name not in verified
  r=expected[m.name];assert (m.size,m.mode,m.uid,m.gid,m.mtime)==(r["bytes"],r["mode"],0,0,0)
  h=hashlib.sha256();n=0;parts=[] if selected(m.name) else None
  f=tf.extractfile(m)
  while True:
   b=f.read(1<<20)
   if not b:break
   h.update(b);n+=len(b)
   if parts is not None:parts.append(b)
  assert (n,h.hexdigest())==(r["bytes"],r["sha256"]),m.name
  verified[m.name]=r
  if parts is not None:
   save(OUT/"files"/m.name,b"".join(parts),m.mode);saved.append(m.name)
assert set(verified)==set(expected)
sem=OUT/"files/store-values-composition/development/ci-composition-store-semantic-r1"
def lines(p):
 data=p.read_bytes();rows=[];tail=b""
 for i,b in enumerate(data.splitlines(keepends=True)):
  try:rows.append(json.loads(b))
  except json.JSONDecodeError:
   assert i==len(data.splitlines(keepends=True))-1 and not b.endswith(b"\n");tail=b
 return rows,tail
cases,ctail=lines(sem/"cases.jsonl");assert not ctail
frontiers={}
for label,pending,ledger in [("initializer",sem/"pending-native-entry.json",sem/"entries.jsonl"),("wire-methods",sem/"native-wire-methods/pending.json",sem/"native-wire-methods/entries.jsonl")]:
 rows,tail=lines(ledger);p=json.loads(pending.read_bytes());counts={}
 for x in rows:counts[x["role"]]=counts.get(x["role"],0)+1
 frontiers[label]=dict(pending=p,complete_records=len(rows),trailing_incomplete_bytes=len(tail),last=rows[-1],counts=counts,last_eight=rows[-8:])
process=json.loads((OUT/"files/run/steps/worker-store-composition-store-semantic/process.json").read_bytes())
stdout=(OUT/"files/run/steps/worker-store-composition-store-semantic/stdout.log").read_text()
result=dict(status="PASS_READONLY_ORIGINAL_FAILURE_PRESERVED",original_artifact=13922316358,all_zip=ziprows,
 all_tar_members=len(verified),all_original_bytes=509705277,all_members_bytes_sha256_modes_verified=True,
 saved_members=len(saved),completed_semantic_cases=cases,frontiers=frontiers,semantic_process=process,
 semantic_stdout=stdout,subject_executed=False,new_native_entries=0,elapsed_ns=time.monotonic_ns()-started)
assert fs(ZIP)=="bdea2a680c2c715e946553f89c3a4224bdbda5f21f68acf65ec7ac1208bdf362"
save(OUT/"report.json",(json.dumps(result,sort_keys=True,indent=2)+"\n").encode())
compact=dict(status=result["status"],all_members=len(verified),completed_cases=len(cases),stdout=stdout,
 frontiers={k:dict(complete_records=v["complete_records"],counts=v["counts"],pending=v["pending"],
 last={x:v["last"].get(x) for x in ("role","entry","label","result","status")},
 trailing_incomplete_bytes=v["trailing_incomplete_bytes"]) for k,v in frontiers.items()},
 elapsed_s=result["elapsed_ns"]/1e9)
print(json.dumps(compact,sort_keys=True))
