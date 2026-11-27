import gzip, hashlib, io, json, os, pathlib, stat, tarfile, time, zipfile

BASE = pathlib.Path("/tmp/hia-runtime-artifact-recovery-20261114-dda7")
ROOT = BASE / "runtime-data"
OUT = pathlib.Path("/tmp/hia-recovery-v146-20261114-dda7/runtime-static-root-readback.json")
ZIP_PIN = {"bytes":39213243,"sha256":"0d5d5ec2672ab066ba1e79ab93d61c206757ebe14ab8b41d26a9b92750c03aad"}
TAR_PIN = {"bytes":39297176,"sha256":"9fa03e3c319052efa21665e1c67c73e68ba47d3b5a265295a39a144086dfd702","git_blob":"2a8887abffd70fd7bafb841b4906150652c9ca12"}
EXPORT_PIN = {"bytes":1163361,"sha256":"3d6f4fbf1bba10ee73df47f2de729fcbda6d23c4272d59f068853ef1b8e82a19","git_blob":"9a76e1bb69cdd79a14444374bc461166488955f2"}
MAP_PIN = {"bytes":1143020,"sha256":"8d2b62ff99c668b453d8f622c7558a7ea693517aedfb342327c57b6febcd31c3","git_blob":"a8412acd5198b474000742cdf69bcbbd108dfc4e"}
CRITICAL = {
 "bin/python3.14":{"bytes":17752,"sha256":"b135f1ae69c99912bc4b035f60255094103c7ee1c4659491ae61385ad5dd09a5","git_blob":"f28f1bc924160c54582e268d794ecd46cf3455c0"},
 "lib/libpython3.14.so.1.0":{"bytes":32366232,"sha256":"0cceb109e9b44702a0b5ab3b822c110e8d1c112fdb69ef97f1fef633f37850e0","git_blob":"5f60ccb1a0e628084a9f151f3af4f40d2c8623d2"}
}
def pin(raw):
 return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def match(raw, expected):
 actual=pin(raw)
 assert all(actual[k]==v for k,v in expected.items()), (actual, expected)
 return actual
def seven(s):
 return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read_regular(path):
 before=path.lstat()
 assert stat.S_ISREG(before.st_mode) and before.st_nlink==1, str(path)
 raw=path.read_bytes()
 assert seven(before)==seven(path.lstat()), str(path)
 return raw,seven(before)
def safe(name):
 p=pathlib.PurePosixPath(name)
 assert not p.is_absolute() and name and all(x not in ("",".","..") for x in name.split("/")),name
 return p
started=time.monotonic_ns()
assert not OUT.exists()
zip_raw,zip_stat=read_regular(BASE/"ORIGINAL.zip")
zip_pin=match(zip_raw,ZIP_PIN)
map_raw,map_stat=read_regular(BASE/"CURRENT-FILE-MAP.json")
match(map_raw,MAP_PIN)
current=json.loads(map_raw)
assert current["root"]==str(ROOT) and current["original_identity_claimed"] is False
cur={row["path"]:row for row in current["files"]}
assert len(cur)==len(current["files"])==2496
with zipfile.ZipFile(io.BytesIO(zip_raw)) as z:
 infos=z.infolist()
 assert len(infos)==12 and len({i.filename for i in infos})==12
 assert all(not i.is_dir() for i in infos)
 manifest_raw=z.read("MANIFEST.json")
 manifest=json.loads(manifest_raw)
 assert len(manifest)==11
 assert set(z.namelist())=={"MANIFEST.json"}|{x["path"] for x in manifest}
 for row in manifest:
  safe(row["path"])
  payload=z.read(row["path"])
  match(payload,{k:row[k] for k in ("bytes","sha256","git_blob")})
  assert stat.S_IMODE(z.getinfo(row["path"]).external_attr>>16)==row["mode"]
  disk_raw,_=read_regular(BASE/"zip-members"/row["path"])
  assert disk_raw==payload,row["path"]
 export_raw=z.read("INTERPRETER-EXPORT.json")
 match(export_raw,EXPORT_PIN)
 export=json.loads(export_raw)
 archive=z.read("cpython3144-tool.tar.gz")
 match(archive,TAR_PIN)
assert export["archive"]==TAR_PIN
assert len(export["omitted_tool_paths"])==6487
expected={row["path"]:row for row in export["files"]}
assert len(expected)==len(export["files"])==2496 and set(expected)==set(cur)
for name,p in CRITICAL.items():
 assert {k:expected[name][k] for k in p}==p
 assert expected[name]["mode"]==0o755
expanded=gzip.decompress(archive)
assert len(expanded)==110151680
observed=set()
total=0
with tarfile.open(fileobj=io.BytesIO(expanded),mode="r:") as t:
 for member in t:
  rel=safe(member.name)
  assert member.isfile(),member.name
  name=str(rel)
  assert name in expected and name not in observed,name
  observed.add(name)
  row=expected[name]
  assert member.size==row["bytes"] and stat.S_IMODE(member.mode)==row["mode"],name
  archived=t.extractfile(member).read()
  match(archived,{k:row[k] for k in ("bytes","sha256","git_blob")})
  path=ROOT.joinpath(*rel.parts)
  actual,new_stat=read_regular(path)
  assert actual==archived,name
  assert new_stat==cur[name]["new_file_seven_stat"],name
  assert stat.S_IMODE(new_stat[2])==row["mode"]==cur[name]["mode"],name
  assert pin(actual)==cur[name]["pin"],name
  total+=len(actual)
assert observed==set(expected) and total==108197034
actual_paths=set()
for d,dirs,files in os.walk(ROOT,followlinks=False):
 for n in dirs:
  assert stat.S_ISDIR((pathlib.Path(d)/n).lstat().st_mode)
 for n in files:
  p=pathlib.Path(d)/n
  assert stat.S_ISREG(p.lstat().st_mode)
  actual_paths.add(p.relative_to(ROOT).as_posix())
assert actual_paths==set(expected)
for name,row in cur.items():
 assert seven((ROOT/name).lstat())==row["new_file_seven_stat"],name
assert seven((BASE/"ORIGINAL.zip").lstat())==zip_stat
assert seven((BASE/"CURRENT-FILE-MAP.json").lstat())==map_stat
result={
 "schema":"hepta.root-runtime-static-recovery-readback.v1",
 "status":"PASS_STATIC_BYTES_ONLY",
 "root":str(ROOT),"zip_pin":zip_pin,"tar_pin":TAR_PIN,"export_manifest_pin":EXPORT_PIN,
 "new_current_map_pin":MAP_PIN,"zip_members":12,"zip_each_CRC_read":True,
 "gzip_final_crc_read":True,"tar_regular_members":2496,"runtime_files":2496,
 "runtime_bytes":total,"all_original_bytes_modes_and_new_seven_stats_exact":True,
 "fresh_full_tar_and_runtime_bytes_each_compared":True,"critical_files":CRITICAL,
 "omitted_tool_paths":6487,"old_path_recreated":False,"old_inode_identity_inherited":False,
 "restored_binary_executions":0,"binders":0,"products":0,"CI":0,
 "dynamic_runtime_qualified":False,"whole_native":False,"production_legacy_retired":False,
 "elapsed_ns":time.monotonic_ns()-started
}
raw=(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+"\n").encode()
with OUT.open("xb") as f:
 f.write(raw)
print(json.dumps({"proof":str(OUT),"pin":pin(raw),"status":result["status"],"files":2496,"bytes":total,"elapsed_ns":result["elapsed_ns"]},sort_keys=True))
