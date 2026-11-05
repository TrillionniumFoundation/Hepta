#!/usr/bin/env python3
from pathlib import Path, PurePosixPath
import argparse,hashlib,json,tarfile,tempfile
parser=argparse.ArgumentParser(description="Restore and hash-check the original evidence bytes; does not execute experiments.")
parser.add_argument("--package",type=Path,required=True)
parser.add_argument("--output",type=Path,required=True)
args=parser.parse_args()
package=args.package.resolve()
manifest=json.loads((package/"MANIFEST.json").read_text())
inventory=json.loads((package/manifest["included_inventory"]).read_text())
expected={r["path"]:r for r in inventory["files"]}
assert len(expected)==inventory["count"]
args.output.mkdir(parents=True,exist_ok=False)
target=args.output.resolve()
whole=hashlib.sha256()
count=0
with tempfile.TemporaryFile() as stream:
 for part in manifest["archive"]["parts"]:
  name=PurePosixPath(part["path"])
  assert not name.is_absolute() and ".." not in name.parts and len(name.parts)==1
  path=package/part["path"]
  assert not path.is_symlink()
  data=path.read_bytes()
  assert len(data)==part["bytes"] and hashlib.sha256(data).hexdigest()==part["sha256"]
  stream.write(data);whole.update(data);count+=len(data)
 assert count==manifest["archive"]["whole_bytes"] and whole.hexdigest()==manifest["archive"]["whole_sha256"]
 stream.seek(0)
 seen=set()
 with tarfile.open(fileobj=stream,mode="r:gz") as tar:
  for item in tar:
   name=PurePosixPath(item.name)
   assert item.isreg() and not name.is_absolute() and ".." not in name.parts
   assert item.name in expected and item.name not in seen
   record=expected[item.name]
   assert item.size==record["bytes"] and item.mode==record["mode"]
   path=target.joinpath(*name.parts);path.parent.mkdir(parents=True,exist_ok=True)
   h=hashlib.sha256();size=0
   with tar.extractfile(item) as source,path.open("xb") as output:
    while data:=source.read(1024*1024):output.write(data);h.update(data);size+=len(data)
   assert size==record["bytes"] and h.hexdigest()==record["sha256"]
   path.chmod(record["mode"])
   seen.add(item.name)
 assert seen==set(expected)
print(json.dumps({"restored_files":len(seen),"restored_bytes":inventory["bytes"],"archive_sha256":whole.hexdigest(),"all_file_hashes_verified":True},sort_keys=True))
