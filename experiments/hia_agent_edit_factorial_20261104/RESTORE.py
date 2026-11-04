#!/usr/bin/env python3
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
