import hashlib, importlib.util, json, os, pathlib, sys
import ctypes, gzip, lzma, struct, tarfile, traceback, unittest, zipfile, zlib
assert sys.version_info[:3] == (3,14,4), sys.version
rows=[]
seen=set()
for line in pathlib.Path("/proc/self/maps").read_text().splitlines():
 parts=line.split()
 if len(parts)<6 or "x" not in parts[1] or not parts[-1].startswith("/"): continue
 p=pathlib.Path(parts[-1])
 if str(p) in seen: continue
 seen.add(str(p))
 before=p.stat();raw=p.read_bytes();after=p.stat()
 fields=("st_dev","st_ino","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
 assert [getattr(before,k) for k in fields]==[getattr(after,k) for k in fields]
 rows.append({"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
 "git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),
 "current_seven_stat":{k:getattr(after,k) for k in fields}})
print(json.dumps({"version":sys.version,"version_info":list(sys.version_info),"executable":sys.executable,
 "prefix":sys.prefix,"base_prefix":sys.base_prefix,"sys_path":sys.path,
 "stdlib_modules_imported":["ctypes","gzip","lzma","struct","tarfile","traceback","unittest","zipfile","zlib"],
 "z3_available":importlib.util.find_spec("z3") is not None,"pytest_available":importlib.util.find_spec("pytest") is not None,
 "mapped_executable_files":rows,"project_imports":0,"product_calls":0,"qualification":"DEVELOPMENT_TOOL_STDLIB_READINESS_ONLY"},
 sort_keys=True))
