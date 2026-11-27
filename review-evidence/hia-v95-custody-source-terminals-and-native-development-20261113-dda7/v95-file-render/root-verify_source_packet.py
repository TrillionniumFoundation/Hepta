from pathlib import Path
import hashlib,json,stat
root=Path("/workspace/scratch/dda74a4fae35")
p=root/"v95-file-render-root-readback"
v=json.loads((p/"SOURCE-PACKET-DECODED.json").read_text())
base=root/"v94-union-r12/source"
def pin(raw,mode):
 return {"bytes":len(raw),"git_blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),"mode":mode,"sha256":hashlib.sha256(raw).hexdigest()}
def tree(rows):
 direct=[];groups={}
 for path,mode,sha in rows:
  name,sep,rest=path.partition("/")
  if sep:groups.setdefault(name,[]).append((rest,mode,sha))
  else:direct.append((name,mode,sha,False))
 for name,children in groups.items():direct.append((name,"40000",tree(children),True))
 direct.sort(key=lambda r:r[0].encode()+(b"/" if r[3] else b""))
 raw=b"".join(m.lstrip("0").encode()+b" "+n.encode()+b"\0"+bytes.fromhex(s) for n,m,s,_ in direct)
 return hashlib.sha1(b"tree "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
base_map=v["base"]["source_manifest"]
assert len(base_map)==v["base"]["files"]==3108
assert tree([(k,x["mode"],x["git_blob"]) for k,x in base_map.items()])==v["base"]["tree"]=="06524acb76047fc271ab6b6597362fd5f3499d00"
for name,expected in base_map.items():
 f=base/name
 assert f.is_file() and not f.is_symlink()
 mode="100"+format(stat.S_IMODE(f.stat().st_mode),"03o")
 assert pin(f.read_bytes(),mode)==expected,name
target=dict(base_map);new=shared=0
for name,row in v["files"].items():
 after=pin(row["text"].encode(),row["mode"])
 assert after=={k:row[k] for k in ("bytes","git_blob","mode","sha256")}
 if row["before"] is None:
  assert name not in target;new+=1
 else:
  before=row["before"];assert pin(before["text"].encode(),before["mode"])=={k:before[k] for k in ("bytes","git_blob","mode","sha256")}
  assert target[name]=={k:before[k] for k in ("bytes","git_blob","mode","sha256")}
  assert (base/name).read_bytes()==before["text"].encode();shared+=1
 target[name]=after
assert target==v["source_manifest"] and len(target)==3117
assert tree([(k,x["mode"],x["git_blob"]) for k,x in target.items()])==v["source_tree"]=="a3b97f233d4c26e0017f06fc80e3b3935c4fa6e1"
assert new==9 and shared==3
report={"schema":"hia.native-file-render.root-exact-source-readback.v1","status":"PASS","source_packet":"755d605716229672444546d56891fa1b6eb17b0e","decoded_packet":"d11888e31af2bef0e5c67d5ad2274a72f40c9adb","base_files":3108,"base_tree":v["base"]["tree"],"base_all_bytes_modes_checked":True,"source_files":len(target),"source_tree":v["source_tree"],"full_after_files":12,"new_files":new,"full_shared_before_files":shared,"all_unchanged_base_paths_exact":True,"source_generation_executed":0,"product_tests_executed":0,"matching_current_cold":False,"whole_native":False}
out=p/"SOURCE-READBACK.json";assert not out.exists();out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
print(json.dumps(report,sort_keys=True))
