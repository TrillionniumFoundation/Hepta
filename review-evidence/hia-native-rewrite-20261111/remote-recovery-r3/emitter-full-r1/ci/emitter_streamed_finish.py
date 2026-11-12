"""Streaming evidence closure for this new Emitter CI only.
Preserves common's source checks and every file byte/mode. JSONL replaces the
unbounded in-memory member list, and tarfile.members is cleared after each row.
It performs zero target executions. Existing component evidence is untouched.
"""
from pathlib import Path
from hashlib import sha256
import json,os,stat,tarfile,time
def file_hash(path):
 h=sha256();n=0
 with Path(path).open("rb") as f:
  while True:
   raw=f.read(1<<18)
   if not raw:break
   n+=len(raw);h.update(raw)
 return dict(bytes=n,sha256=h.hexdigest())
def files(root):
 info=root.lstat()
 assert not stat.S_ISLNK(info.st_mode)
 if stat.S_ISREG(info.st_mode):
  yield root
 elif stat.S_ISDIR(info.st_mode):
  for child in sorted(root.iterdir(),key=lambda p:p.name):
   yield from files(child)
 else:raise AssertionError(("unsupported evidence object",str(root),info.st_mode))
def rows_for(mapping,excluded):
 for label,root in sorted(mapping.items()):
  root=Path(root).resolve()
  one=root.is_file()
  for path in files(root):
   if path in excluded:continue
   info=path.lstat()
   assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
   rel=path.name if one else path.relative_to(root).as_posix()
   yield label+"/"+rel,path,info
def compare_stream(item_stream,path,expected):
 actual=sha256();n=0
 with path.open("rb") as original:
  while True:
   raw=item_stream.read(1<<18)
   if not raw:break
   assert original.read(len(raw))==raw,(str(path),"tar differs from complete actual file")
   actual.update(raw);n+=len(raw)
  assert original.read(1)==b""
 info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_nlink==1
 assert (n,actual.hexdigest(),stat.S_IMODE(info.st_mode))==(expected["bytes"],expected["sha256"],expected["mode"])
def finish(common,scope,status,details,roots=None):
 assert status in("PASS","FAIL")
 output=common.OUTPUT;output.mkdir(parents=True,exist_ok=True)
 exact=common.PREPARED and common.unchanged(common.SOURCE_INDEX) and common.unchanged(common.REFERENCE_INDEX)
 scripts=all(path.read_bytes()==raw for path,raw in common.PINS.items())
 if status=="PASS":assert exact and scripts
 summary=dict(schema="hia-independent-ci-qualification-v1",scope=scope,status=status,
    details=details,steps=common.STEPS,prepared=common.PREPARED,
    frozen_source_and_reference_before_after_equal=exact,
    submitted_script_pins_before_after_equal=scripts,
    whole_stack_closed=False,production_activated=False,inherited_test_counts=False,
    original_ROG_launches_not_resolved_by_this_run=True,
    evidence_format="streamed-tar-xz-with-complete-JSONL-member-ledger-v1")
 common.save(output/"summary.json",summary)
 mapping={"run":output}
 mapping.update({name:Path(path) for name,path in(roots or {}).items() if Path(path).exists()})
 for name,root in mapping.items():
  assert name and "/" not in name and name not in(".","..")
  real=root.resolve();assert real==output or real.is_relative_to(common.BASE)
 archive=output/"evidence.tar.xz";index=output/"evidence-members.jsonl";custody_path=output/"custody.json"
 excluded={archive,index,custody_path}
 assert all(not path.exists() for path in excluded)
 started=time.monotonic();cpu=time.process_time();count=0;total=0
 with index.open("x",encoding="utf-8") as ledger,tarfile.open(archive,"w:xz",preset=1) as tf:
  for name,path,info in rows_for(mapping,excluded):
   identity=file_hash(path)
   row=dict(name=name,path=str(path),bytes=identity["bytes"],mode=stat.S_IMODE(info.st_mode),sha256=identity["sha256"])
   current=path.lstat()
   assert (current.st_dev,current.st_ino,current.st_mode,current.st_size)==(info.st_dev,info.st_ino,info.st_mode,info.st_size)
   member=tarfile.TarInfo(name);member.size=row["bytes"];member.mode=row["mode"]
   member.mtime=0;member.uid=member.gid=0;member.uname=member.gname=""
   with path.open("rb") as raw:tf.addfile(member,raw)
   tf.members.clear()
   ledger.write(json.dumps(row,sort_keys=True)+"\n")
   count+=1;total+=row["bytes"]
  ledger.flush();os.fsync(ledger.fileno())
 checked=0
 with index.open("r",encoding="utf-8") as ledger,tarfile.open(archive,"r|xz") as tf:
  for item in tf:
   line=ledger.readline();assert line
   row=json.loads(line);assert item.isfile() and item.name==row["name"]
   assert (item.size,item.mode)==(row["bytes"],row["mode"])
   with tf.extractfile(item) as raw:compare_stream(raw,Path(row["path"]),row)
   checked+=1;tf.members.clear()
  assert not ledger.readline() and checked==count
 # A second traversal detects omitted/added/reordered filesystem entries.
 with index.open("r",encoding="utf-8") as ledger:
  for name,path,info in rows_for(mapping,excluded):
   line=ledger.readline();assert line;row=json.loads(line)
   assert row["name"]==name and row["path"]==str(path)
   assert stat.S_IMODE(info.st_mode)==row["mode"]
   assert file_hash(path)=={k:row[k] for k in("bytes","sha256")}
  assert not ledger.readline()
 assert all(path.read_bytes()==raw for path,raw in common.PINS.items())
 ah=file_hash(archive);ih=file_hash(index)
 custody=dict(schema="hia-independent-ci-streamed-artifact-custody-v1",scope=scope,status=status,
    archive=str(archive),bytes=ah["bytes"],sha256=ah["sha256"],members=count,original_bytes=total,
    member_index=str(index),member_index_format="JSONL",member_index_bytes=ih["bytes"],member_index_sha256=ih["sha256"],
    all_original_and_tar_member_bytes_sha256_modes_readback=True,
    complete_source_inventory_before_after_equal=True,tar_member_cache_cleared_after_each_member=True,
    no_target_execution_in_seal=True,seal_wall_seconds=time.monotonic()-started,seal_cpu_seconds=time.process_time()-cpu,
    whole_stack_closed=False)
 common.save(custody_path,custody)
 print(json.dumps(custody,sort_keys=True),flush=True)
 if os.environ.get("GITHUB_STEP_SUMMARY"):
  with open(os.environ["GITHUB_STEP_SUMMARY"],"a") as f:
   f.write("## Complete Emitter independent development\n\nStatus: **"+status+"**. Whole backend / installed closure remains open.\n\n")
   f.write("Archive: "+ah["sha256"]+"; "+str(count)+" complete member bytes/modes verified.\n\n")
 return summary,custody
