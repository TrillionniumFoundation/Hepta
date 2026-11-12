"""Read exact failed FOLLOW42 artifact; never execute HIA, VM, compiler or ELF."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,collections,gzip,hashlib,json,os,resource,signal,stat,struct,tarfile,traceback,zlib
from pathlib import Path,PurePosixPath
PIN=dict(artifact=13932591885,run=43192344684,job=131094562125,
 ZIP_bytes=363402316,ZIP_SHA256="74d207123cf5cf5643784192300de8dc0228d0c604cacde8ec779a1bea387b26",
 archive_bytes=23456180,archive_sha256="0c24cff97138fbf22a213c756b93c930292d18aed23779df6a3c049bab28ef23",
 index_bytes=2173406,index_sha256="f83ed843f1a852683969b8b7b139387c257b43f29e20f64a5b05c0b407dbd441",
 members=4272,raw_bytes=323619640)
REPORTS={
 "run/namespace-db-physical-join-r1/db-join-build-r1/summary.json":(130942,"6b12787d087d39ddd4ce8f3f7d0c1b8a959c096cbb9f14b66edf212ce309fe52"),
 "run/namespace-db-physical-join-r1/db-join-native-r1/summary.json":(1238299,"9db923245d693437fc1717b04f6d859c5148a277d31632f3fb0278244c356934"),
 "run/namespace-db-physical-join-r1/packer-differential-r1/summary.json":(22052,"2edab014beb3cb213dc0a2efe561c9cfb0447e98d304b7d2bd2384b08a4edc9c")}
MAGICS={int.from_bytes(v,"little"):i for i,v in enumerate(
 [b"",b"HIANFT03",b"HIASMT01",b"HIANMT01",b"HIANDT03",b"HIADBT01",b"HIADJT01"]) if i}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def pin(path):
 path=Path(path);info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
 h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(info.st_size).encode()+b"\0");n=0
 with path.open("rb") as stream:
  for block in iter(lambda:stream.read(1<<20),b""):n+=len(block);h.update(block);g.update(block)
 assert n==info.st_size
 return dict(bytes=n,mode=stat.S_IMODE(info.st_mode),sha256=h.hexdigest(),git_blob_sha1=g.hexdigest())
def copy(source,target,expected=None):
 before=pin(source)
 if expected is not None:assert before==expected
 target.parent.mkdir(parents=True,exist_ok=True)
 with source.open("rb") as src,target.open("xb") as dst:
  for block in iter(lambda:src.read(1<<20),b""):dst.write(block)
 target.chmod(before["mode"])
 assert pin(target)==before and pin(source)==before
 return before
def locate(root,name,n,digest):
 matches=[]
 for directory,dirs,names in os.walk(root,followlinks=False):
  for item in dirs:assert not (Path(directory)/item).is_symlink()
  if name in names:
   path=Path(directory)/name;info=pin(path)
   if (info["bytes"],info["sha256"])==(n,digest):matches.append((path,info))
 assert len(matches)==1,(name,len(matches))
 return matches[0]
def extract(archive,index,out):
 rows=json.loads(index.read_bytes());assert isinstance(rows,list) and len(rows)==PIN["members"]
 expected={}
 for row in rows:
  p=PurePosixPath(row["name"])
  assert not p.is_absolute() and p.parts and all(x not in ("",".","..") for x in p.parts)
  assert p.as_posix()==row["name"] and row["name"] not in expected
  expected[row["name"]]=row
 assert sum(r["bytes"] for r in rows)==PIN["raw_bytes"]
 seen=set();checked=[]
 with tarfile.open(archive,"r|xz") as tf:
  for member in tf:
   assert member.isfile() and member.name in expected and member.name not in seen
   row=expected[member.name]
   assert (member.size,member.mode)==(row["bytes"],row["mode"])
   assert member.uid==member.gid==member.mtime==0
   target=out/member.name;target.parent.mkdir(parents=True,exist_ok=True)
   h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(member.size).encode()+b"\0");n=0
   with target.open("xb") as dest:
    src=tf.extractfile(member)
    for block in iter(lambda:src.read(1<<20),b""):n+=len(block);h.update(block);g.update(block);dest.write(block)
   target.chmod(member.mode)
   assert (n,h.hexdigest())==(row["bytes"],row["sha256"])
   observed=pin(target)
   assert observed==dict(bytes=n,mode=member.mode,sha256=h.hexdigest(),git_blob_sha1=g.hexdigest())
   seen.add(member.name);checked.append(dict(name=member.name,**observed))
 assert seen==set(expected)
 return checked
def cas(raw,out):
 digest=sha(raw);p=out/"CAS"/digest;p.parent.mkdir(parents=True,exist_ok=True)
 if p.exists():assert p.read_bytes()==raw
 else:p.write_bytes(raw)
 assert p.read_bytes()==raw
 return dict(bytes=len(raw),sha256=digest,git_blob_sha1=git(raw),path=p.relative_to(out).as_posix())
def record_cas(value,out):
 found=[]
 def walk(x,place):
  if isinstance(x,dict):
   for key,v in x.items():
    where=place+"/"+key
    if key.endswith("_hex") and isinstance(v,str):
     data=bytes.fromhex(v);assert data.hex()==v.lower()
     found.append(dict(JSON_pointer=where,**cas(data,out)))
    else:walk(v,where)
  elif isinstance(x,list):
   for i,v in enumerate(x):walk(v,place+"/"+str(i))
 walk(value,"")
 return found
def trace_read(path,dest,payload):
 before=pin(path);dest.mkdir(parents=True,exist_ok=True)
 records=[];by_offset={};waiting={};counts=collections.Counter();incomplete=None
 with path.open("rb") as stream:
  offset=0
  while offset<before["bytes"]:
   raw=stream.read(96)
   if len(raw)<96:
    incomplete=dict(offset=offset,stage="partial_header",raw=cas(raw,payload));break
   h=struct.unpack("<12Q",raw);role=MAGICS.get(h[0]);kind=h[1]
   if role is None or kind not in (1,2,3,4) or h[10]!=role or h[11]!=0:
    incomplete=dict(offset=offset,stage="unrecognized_original_header",header=list(h),raw=cas(raw,payload));break
   sizes=([h[3],h[4],h[5]] if kind==1 else [h[4],h[5]] if kind==2 else [h[3]] if kind==3 else [])
   amount=sum(sizes)
   if amount>before["bytes"]-offset-96:
    tail=stream.read()
    incomplete=dict(offset=offset,stage="partial_payload",header=list(h),raw=cas(raw+tail,payload));break
   parts=[];cursor=offset+96;record_hash=hashlib.sha256(raw)
   for size in sizes:
    d=hashlib.sha256();remaining=size
    while remaining:
     block=stream.read(min(remaining,1<<20));assert block
     remaining-=len(block);d.update(block);record_hash.update(block)
    parts.append(dict(offset=cursor,bytes=size,sha256=d.hexdigest()));cursor+=size
   row=dict(offset=offset,bytes=96+amount,sha256=record_hash.hexdigest(),
    role=role,kind=kind,header=list(h),parts=parts)
   key=(role,h[8],h[9],h[2])
   if kind==1:
    assert key not in waiting
    waiting[key]=row
   elif kind==2:
    if key in waiting:
     parent=waiting.pop(key);parent["post_offset"]=offset;row["pre_offset"]=parent["offset"]
   records.append(row);by_offset[offset]=row;counts[str(role)+":"+str(kind)]+=1
   offset=cursor
 assert pin(path)==before
 first=records[:3];last=records[-3:]
 with path.open("rb") as stream:
  for label,selected in (("first",first),("last",last)):
   for i,row in enumerate(selected):
    stream.seek(row["offset"]);raw=stream.read(row["bytes"]);assert sha(raw)==row["sha256"]
    save(dest/(label+"-"+str(i)+".json"),dict(record=row,complete_raw_record=cas(raw,payload)))
 save(dest/"all-record-headers.json",records)
 result=dict(source=before,records=len(records),entries=sum(v for k,v in counts.items() if k.endswith(":1")),
  by_role_kind=dict(counts),first=first,last=last,incomplete=incomplete,
  open_record_keys=[list(k) for k in waiting],interpretation="Only recorded original bytes; no native rerun")
 save(dest/"trace-prefix.json",result)
 return result,by_offset
def ledger_read(path,trace,records,dest,payload):
 dest.mkdir(parents=True,exist_ok=True);before=pin(path)
 decoder=zlib.decompressobj(16+zlib.MAX_WBITS);pending=b"";digest=hashlib.sha256();raw_n=0
 count=0;first=[];last=[];roles=collections.Counter();errors=[];matched_offsets=set();decomp_error=None
 def feed(data):
  nonlocal pending,count,raw_n
  digest.update(data);raw_n+=len(data);pending+=data
  while b"\n" in pending:
   line,pending=pending.split(b"\n",1)
   value=json.loads(line);assert isinstance(value,dict)
   offset=value.get("original_offset",value.get("trace_offset"))
   assert isinstance(offset,int) and offset in records and offset not in matched_offsets
   pre=records[offset];assert pre["kind"]==1
   h=pre["header"]
   assert (value["role"],value["node"],value["context"],value["serial"])==(pre["role"],h[8],h[9],h[2])
   assert value["vm_step_budget"]==4000000
   post=records.get(pre.get("post_offset"))
   verified=[]
   pairs=[("input_hex",pre["parts"][0]),("pre_output_hex",pre["parts"][1]),("pre_workspace_hex",pre["parts"][2])]
   if post is not None:
    assert value["expected_return"]==post["header"][6]
    pairs.extend([("expected_output_hex",post["parts"][0]),("expected_workspace_hex",post["parts"][1])])
   else:errors.append(dict(line=count+1,offset=offset,reason="native post-record absent from original trace"))
   for field,part in pairs:
    data=bytes.fromhex(value[field]);assert data.hex()==value[field].lower()
    assert len(data)==part["bytes"] and sha(data)==part["sha256"],(path.name,count+1,field)
    verified.append(field)
   count+=1;roles[str(pre["role"])]+=1;matched_offsets.add(offset)
   item=dict(line=count,bytes=len(line)+1,sha256=sha(line+b"\n"),role=pre["role"],offset=offset,
    header=h,expected_return=value["expected_return"],verified_original_buffers=verified,raw=line+b"\n",value=value)
   if len(first)<3:first.append(item)
   last.append(item)
   if len(last)>3:del last[0]
 with path.open("rb") as stream:
  for block in iter(lambda:stream.read(65536),b""):
   try:feed(decoder.decompress(block))
   except zlib.error as e:decomp_error=repr(e);break
 if decomp_error is None:
  try:feed(decoder.flush())
  except zlib.error as e:decomp_error=repr(e)
 exported=[]
 for label,items in (("first",first),("last",last)):
  for i,row in enumerate(items):
   file=dest/(label+"-complete-"+str(i)+".jsonl");file.write_bytes(row["raw"])
   assert file.read_bytes()==row["raw"]
   exported.append(dict(position=label,**{k:v for k,v in row.items() if k not in ("raw","value")},
    complete_record=pin(file),complete_buffers=record_cas(row["value"],payload)))
 if pending:cas(pending,payload)
 relevant=(5,6) if path.name.startswith("outer-") else (1,2,3,4)
 unseen=[r for r in records.values() if r["kind"]==1 and r["role"] in relevant and r["offset"] not in matched_offsets]
 candidates=[]
 with trace.open("rb") as stream:
  for row in unseen[:3]:
   stream.seek(row["offset"]);raw=stream.read(row["bytes"]);assert sha(raw)==row["sha256"]
   candidates.append(dict(record=row,complete_record=cas(raw,payload)))
 result=dict(source=before,complete_returned_VM_records=count,roles=dict(roles),first_last=exported,
  prefix_bytes=raw_n,prefix_sha256=digest.hexdigest(),gzip_footer_completed=decoder.eof,
  gzip_error=decomp_error,unused_compressed_bytes=len(decoder.unused_data),
  partial_last_line_bytes=len(pending),partial_last_line_sha256=sha(pending),
  expected_buffers_match_available_actual_native_records=True,every_record_has_original_post=not errors,
  recorded_native_post_absent=errors,
  trace_entries_without_a_recorded_returned_VM_line=len(unseen),first_unrecorded_candidates=candidates,
  inflight_identification="UNKNOWN: gzip/Python buffering may hide complete but unflushed records; candidates are not asserted in-flight calls",
  no_VM_native_or_HIA_execution=True)
 assert pin(path)==before
 save(dest/"ledger-prefix.json",result)
 return result
def decimal(value):
 if value is None or isinstance(value,bool):return value
 if isinstance(value,int):return str(value)
 if isinstance(value,list):return [decimal(x) for x in value]
 if isinstance(value,dict):return {k:decimal(v) for k,v in value.items()}
 return value
def seal(out):
 root=out/"payload";rows=[]
 for directory,dirs,names in os.walk(root,followlinks=False):
  for d in dirs:assert not (Path(directory)/d).is_symlink()
  for n in names:
   path=Path(directory)/n;rows.append(dict(name=path.relative_to(root).as_posix(),**pin(path)))
 rows.sort(key=lambda x:x["name"]);save(out/"evidence-members.json",rows)
 archive=out/"evidence.tar.gz"
 with archive.open("xb") as raw,gzip.GzipFile(filename="",fileobj=raw,mode="wb",mtime=0,compresslevel=1) as gz,tarfile.open(fileobj=gz,mode="w|") as tf:
  for row in rows:
   info=tarfile.TarInfo(row["name"]);info.size=row["bytes"];info.mode=row["mode"]
   info.uid=info.gid=info.mtime=0;info.uname=info.gname=""
   with (root/row["name"]).open("rb") as stream:tf.addfile(info,stream)
 expected={r["name"]:r for r in rows};seen=set()
 with tarfile.open(archive,"r|gz") as tf:
  for member in tf:
   assert member.isfile() and member.name in expected and member.name not in seen
   row=expected[member.name];assert (member.size,member.mode)==(row["bytes"],row["mode"])
   h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(member.size).encode()+b"\0");n=0
   src=tf.extractfile(member)
   for block in iter(lambda:src.read(1<<20),b""):n+=len(block);h.update(block);g.update(block)
   assert (n,h.hexdigest(),g.hexdigest())==(row["bytes"],row["sha256"],row["git_blob_sha1"])
   assert pin(root/member.name)=={k:row[k] for k in ("bytes","mode","sha256","git_blob_sha1")}
   seen.add(member.name)
 assert seen==set(expected)
 result=dict(archive=pin(archive),index=pin(out/"evidence-members.json"),members=len(rows),
  raw_bytes=sum(r["bytes"] for r in rows),all_members_full_bytes_modes_SHA256_Git_readback=True)
 save(out/"custody.json",result);return result
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("original reader wall180")))
 signal.alarm(180);assert sys.version_info[:3]==(3,12,14)
 root=Path(os.environ["HIA_NAMESPACE_FOLLOW42_DIR"]).resolve(strict=True)
 out=Path(os.environ["HIA_CI_OUTPUT"]).absolute();assert not out.is_relative_to(root)
 out.mkdir(parents=True,exist_ok=False);payload=out/"payload";payload.mkdir()
 before=pin(Path(__file__).resolve());copy(Path(__file__).resolve(),payload/"reader-source.py",before)
 controls=[];result=dict(status="FAIL_READBACK",original_qualification="FAIL_UNCHANGED",
  original900limits_unchanged=True,new_HIA=0,new_B3=0,new_VM=0,new_native=0,
  ZIP_digest_scope="GitHub declaration only; downloaded directory does not expose original ZIP bytes",
  input_artifact=PIN,performance_root_cause="NOT_INFERRED")
 console={};after_errors=[]
 try:
  archive,ap=locate(root,"evidence.tar.xz",PIN["archive_bytes"],PIN["archive_sha256"])
  index,ip=locate(root,"evidence-members.json",PIN["index_bytes"],PIN["index_sha256"])
  controls=[(archive,ap),(index,ip)]
  copy(archive,payload/"original-evidence.tar.xz",ap);copy(index,payload/"original-evidence-members.json",ip)
  result["complete_pinned_archive_and_index_saved_before_semantic_parse"]=True
  members=payload/"original-members";checked=extract(archive,index,members)
  save(payload/"verified-original-members.json",checked)
  result.update(full_original_members_verified=len(checked),full_original_raw_bytes=sum(r["bytes"] for r in checked))
  reports={}
  for name,(size,digest) in REPORTS.items():
   raw=(members/name).read_bytes();assert (len(raw),sha(raw))==(size,digest)
   reports[name]=json.loads(raw)
  root_report=json.loads((members/"run/summary.json").read_bytes())
  assert root_report["status"]=="FAIL" and not root_report["whole_stack_closed"]
  build=reports[next(k for k in REPORTS if "/db-join-build-" in k)]
  packer=reports[next(k for k in REPORTS if "/packer-differential-" in k)]
  physical=reports[next(k for k in REPORTS if "/db-join-native-" in k)]
  assert build["status"]=="PASS_BUILD_ONLY" and build["fresh_role_compiles"]==6 and build["packer_entries"]==33
  assert packer["status"]=="PASS" and packer["cases"]==84 and packer["counts"]==dict(old_VM=84,new_VM=84,new_native=84)
  assert physical["status"]=="INCOMPLETE"
  base=members/"run/namespace-db-physical-join-r1/db-join-native-r1"
  traces={};ledger_results=[];processes=[]
  for path in sorted(base.rglob("trace.bin")):
   rel=path.relative_to(base).as_posix();dest=payload/"frontier"/path.parent.relative_to(base)
   t,records=trace_read(path,dest/"native-trace",payload);traces[rel]=t
   for label in ("outer-db-full-vm-replay.jsonl.gz","four-role-vm-replay.jsonl.gz"):
    ledger=path.parent/label
    if ledger.exists():
     item=ledger_read(ledger,path,records,dest/label,payload)
     ledger_results.append(dict(path=ledger.relative_to(base).as_posix(),**item))
  for directory in sorted(base.glob("test_*/native-*")):
   if not directory.is_dir():continue
   row=dict(path=directory.relative_to(base).as_posix())
   for filename in ("process.json","abort.json","requests.json","six-role-replay.json"):
    path=directory/filename
    if path.exists():
     value=json.loads(path.read_bytes())
     row[filename]=dict(pin=pin(path),value=value if filename!="six-role-replay.json" else
      {k:value[k] for k in ("status","native_entries","vm_entries","entries_by_role","original_trace_before","original_trace_after") if k in value})
   processes.append(row)
  stderr=base/"tests.stderr.log";stderr_raw=stderr.read_bytes() if stderr.exists() else b""
  result.update(status="PASS_READBACK_ONLY",original_reports={name:pin(members/name) for name in REPORTS},
   original_root_summary=pin(members/"run/summary.json"),native_trace_prefixes=traces,
   replay_prefixes=ledger_results,processes=processes,
   completed_replays_in_original_physical_summary=len(physical["replay"]),
   physical_summary_keys=sorted(physical),tests_stderr=dict(bytes=len(stderr_raw),sha256=sha(stderr_raw),base64=base64.b64encode(stderr_raw).decode()),
   recorded_state_only=True,unrecorded_inflight_call="UNKNOWN")
  save(payload/"full-frontier-result.json",result)
  console=dict(status=result["status"],members=len(checked),raw_bytes=result["full_original_raw_bytes"],
   original_report_pins=result["original_reports"],tests_stderr=result["tests_stderr"],
   original_physical_status=physical["status"],original_physical_summary_keys=sorted(physical),
   completed_replays_in_original_summary=len(physical["replay"]),physical_step=[x for x in root_report["steps"] if x["label"]=="six-role-actual-physical-and-complete-original-trace-replay"],
   process_frontiers=[],replay_frontiers=[])
  for item in processes:
   p=item.get("process.json",{}).get("value")
   req=item.get("requests.json",{}).get("value")
   console["process_frontiers"].append(dict(path=item["path"],process=p,abort_present="abort.json" in item,
    requests_count=len(req) if isinstance(req,list) else None,first_request=req[0] if req else None,last_request=req[-1] if req else None,
    completed_six_role_replay=item.get("six-role-replay.json")))
  for x in ledger_results:
   console["replay_frontiers"].append({k:x[k] for k in ("path","source","complete_returned_VM_records","roles","prefix_bytes","prefix_sha256","gzip_footer_completed","gzip_error","partial_last_line_bytes","partial_last_line_sha256","trace_entries_without_a_recorded_returned_VM_line","first_unrecorded_candidates","inflight_identification")})
   console["replay_frontiers"][-1]["first_last"]=[{k:r[k] for k in ("position","line","bytes","sha256","role","offset","header","expected_return","verified_original_buffers","complete_record")} for r in x["first_last"]]
 except BaseException as e:
  result.update(status="FAIL_READBACK",error_class=type(e).__name__,error=str(e),traceback=traceback.format_exc())
  save(payload/"failure.json",result)
  console=dict(status="FAIL_READBACK",error_class=type(e).__name__,error=str(e),traceback=traceback.format_exc())
 finally:
  for path,old in [(Path(__file__).resolve(),before),*controls]:
   try:
    new=pin(path);assert new==old
    save(payload/("after-"+sha(str(path).encode())+".json"),dict(path=str(path),before=old,after=new))
   except BaseException as e:after_errors.append(dict(path=str(path),error=repr(e)))
  if after_errors:result["status"]="FAIL_READBACK";console["status"]="FAIL_READBACK"
  result["after_check_errors"]=after_errors;save(payload/"result.json",result)
  try:console["custody"]=seal(out)
  except BaseException as e:
   result["status"]="FAIL_READBACK";console.update(status="FAIL_READBACK",seal_error=repr(e),seal_traceback=traceback.format_exc())
   save(out/"seal-failure.json",console)
  console.update(after_check_errors=after_errors,original_qualification="FAIL_UNCHANGED",new_HIA=0,new_B3=0,new_VM=0,new_native=0,
   integer_presentation="Decimal strings only in this readable projection; all original JSON/u64/trace bytes sealed unchanged.",
   performance_root_cause="NOT_INFERRED",unrecorded_inflight_call="UNKNOWN")
  raw=(json.dumps(decimal(console),sort_keys=True,separators=(",",":"))+"\n").encode()
  (out/"console-summary.json").write_bytes(raw)
  if len(raw)>=900000:
   result["status"]="FAIL_READBACK"
   print(json.dumps(dict(status="FAIL_CONSOLE_BOUND",bytes=len(raw),sha256=sha(raw),complete_file_saved=True,new_target_executions=0)),flush=True)
  else:print("HIA_NAMESPACE_FOLLOW42_RECORDED_FRONTIER "+raw.decode(),end="",flush=True)
  signal.alarm(0)
 return 0 if result["status"]=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
