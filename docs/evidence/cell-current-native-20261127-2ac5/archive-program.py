from pathlib import Path
import sys,tarfile,json,hashlib,stat,io
base=Path("/home/qian-qi/hia-cell-current-native-20261127-2ac5")
roots=[base/("native-component-v"+str(i)) for i in range(1,5)]+[base/"mount-preparation-probe-v1"]
manifest=[]
paths=[]
for root in roots:
 assert root.is_dir(),root
 for p in sorted(root.rglob("*")):
  rel=p.relative_to(root)
  if any(part in ("current-source","legacy-f33-source",".git","__pycache__") for part in rel.parts):continue
  st=p.lstat()
  if stat.S_ISREG(st.st_mode):
   raw=p.read_bytes()
   row={"path":p.relative_to(base).as_posix(),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"mode":stat.S_IMODE(st.st_mode)}
   manifest.append(row);paths.append((p,row))
  elif stat.S_ISLNK(st.st_mode):
   raise ValueError("unexpected evidence symlink: "+str(p))
with tarfile.open(fileobj=sys.stdout.buffer,mode="w|gz",format=tarfile.PAX_FORMAT) as archive:
 for p,row in paths:
  raw=p.read_bytes()
  assert len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
  info=tarfile.TarInfo(row["path"]);info.size=len(raw);info.mode=row["mode"];info.mtime=0
  archive.addfile(info,io.BytesIO(raw))
 raw=(json.dumps({"schema":"cell-native-four-attempts-evidence-v1","files":manifest,"source_trees_retained_in_original_roots":True},indent=2,sort_keys=True)+"\n").encode()
 info=tarfile.TarInfo("manifest.json");info.size=len(raw);info.mode=0o600;info.mtime=0;archive.addfile(info,io.BytesIO(raw))
