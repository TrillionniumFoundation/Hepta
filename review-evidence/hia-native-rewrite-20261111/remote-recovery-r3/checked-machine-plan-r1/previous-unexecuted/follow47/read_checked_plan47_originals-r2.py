"""Read every original FOLLOW47 byte; execute no compiler, VM, HIA, or oracle.

Only complete original groups may be reused. The failed interval group, including
its 20 successful observations, remains failed and contributes zero union cases.
This standalone reader is limited to 90 CPU seconds / 180 wall / 1 GiB.
"""
from pathlib import Path,PurePosixPath
from hashlib import sha1,sha256
from functools import lru_cache
import argparse,json,os,resource,signal,stat,struct,sys,tarfile,time,traceback,zlib
sys.dont_write_bytecode=True
MANIFEST_GIT="f975f03dcabc67e684630e66c0c519d2279d5a31"
OLD_DRIVER_GIT="399dcb1d23b4331d3269cfa72fe060228a2f6288"
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
C_MAGIC=int.from_bytes(b"HIACDE01","little")
A_MAGIC=int.from_bytes(b"HIACDA01","little")
CHUNK=1<<18
def digest(raw):return sha256(raw).hexdigest()
def git(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def identity(path):
 path=Path(path);before=path.lstat()
 assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not path.is_symlink(),str(path)
 h=sha256();g=sha1(b"blob "+str(before.st_size).encode()+b"\0");n=0
 with path.open("rb") as stream:
  while True:
   raw=stream.read(CHUNK)
   if not raw:break
   n+=len(raw);h.update(raw);g.update(raw)
 after=path.lstat()
 assert (before.st_dev,before.st_ino,before.st_size,before.st_mode)==(after.st_dev,after.st_ino,after.st_size,after.st_mode)
 assert n==before.st_size
 return dict(bytes=n,sha256=h.hexdigest(),gitsha=g.hexdigest(),mode=stat.S_IMODE(before.st_mode))
def equal_file(a,b):
 assert identity(a)==identity(b),(str(a),str(b))
 with Path(a).open("rb") as x,Path(b).open("rb") as y:
  while True:
   raw=x.read(CHUNK);assert y.read(len(raw) if raw else 1)==raw
   if not raw:break
def copy_original(source,target):
 before=identity(source);target.parent.mkdir(parents=True,exist_ok=True)
 with Path(source).open("rb") as incoming,target.open("xb") as outgoing:
  while True:
   raw=incoming.read(CHUNK)
   if not raw:break
   outgoing.write(raw)
  outgoing.flush();os.fsync(outgoing.fileno())
 target.chmod(before["mode"]);equal_file(source,target)
 return before
def safe_name(name):
 p=PurePosixPath(name)
 assert name and not p.is_absolute() and p.as_posix()==name
 assert all(part not in("","..",".") for part in name.split("/"))
 return name
def unique(root,name,expected):
 found=[p for p in root.rglob(name) if p.is_file() and not p.is_symlink()]
 assert len(found)==1,(name,len(found),[str(p) for p in found])
 row=identity(found[0])
 assert all(row[k]==expected[k] for k in("bytes","sha256")),(name,row,expected)
 return found[0]
def bounded_page(raw,expected_hash):
 assert 0<len(raw)<=8192
 decoder=zlib.decompressobj();data=decoder.decompress(raw,4097)
 assert len(data)<=4096 and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data
 assert digest(data)==expected_hash
 return data
def json_file(path):return json.loads(Path(path).read_bytes())
def mode(row):return int(row["mode"],8)&0o777
class Reader:
 def __init__(self,args,manifest,report):
  self.args=args;self.manifest=manifest;self.report=report
  self.root=args.out/"selected";self.root.mkdir()
  self.cas=args.out/"decoded-page-encodings";self.cas.mkdir()
  self.rows={};self.page_info={};self.case_pages={}
  self.restored={};self.cases=[];self.snapshot_count=0;self.logical=0;self.acks=0
  self.hashes_recomputed=0;self.hashes_reused=0;self.hash_bytes=0
  self.original_group_summaries=[];self.original_build_summaries=[]
 def want(self,name):
  if name=="run/summary.json" or name=="checked-plan/development/runtime-assets.json":return True
  if name.startswith("checked-plan/development/build-"):
   parts=PurePosixPath(name).parts
   if "source" in parts[3:] and parts[-1] not in("source-before.json","source-after.json"):return False
   return name.endswith((".json",".hiaasm",".image.bin"))
  if name.startswith("checked-plan/development/native-"):
   if "/cases/" in name:
    return "/full-CAS/sources/" not in name and "/full-CAS/cas/" not in name
   return name.endswith(("/summary.json","/source-before-after.json"))
  return name=="checked-plan/ci-driver-original.py" or any(name=="checked-plan/"+r["path"] for r in self.manifest["source_files"])
 def scan(self,archive,ledger):
  count=total=0
  with ledger.open("r",encoding="utf-8") as index,tarfile.open(archive,"r|xz") as tf:
   for member in tf:
    line=index.readline();assert line
    row=json.loads(line);name=safe_name(row["name"])
    assert name not in self.rows and member.name==name and member.isfile()
    assert member.size==row["bytes"] and member.mode==row["mode"]
    assert member.mode>=0 and member.mode&~0o777==0
    assert member.uid==member.gid==member.mtime==0 and member.uname==member.gname==""
    assert type(row["bytes"]) is int and row["bytes"]>=0
    is_page="/full-CAS/cas/" in name and name.endswith(".zlib")
    target=self.root/name if self.want(name) else None
    if target:target.parent.mkdir(parents=True,exist_ok=True)
    output=target.open("xb") if target else None
    page=bytearray() if is_page else None
    h=sha256();g=sha1(b"blob "+str(member.size).encode()+b"\0");size=0
    try:
     with tf.extractfile(member) as incoming:
      while True:
       raw=incoming.read(CHUNK)
       if not raw:break
       size+=len(raw);h.update(raw);g.update(raw)
       if output:output.write(raw)
       if page is not None:
        assert size<=8192;page.extend(raw)
     assert (size,h.hexdigest())==(row["bytes"],row["sha256"]),name
    finally:
     if output:output.close()
    actual=dict(bytes=size,sha256=h.hexdigest(),gitsha=g.hexdigest(),mode=member.mode)
    self.rows[name]=actual
    if target:
     target.chmod(member.mode);assert identity(target)==actual
     self.restored[name]=target
    if is_page:
     key=PurePosixPath(name).name[:-5];assert len(key)==64 and set(key)<=set("0123456789abcdef")
     data=bounded_page(bytes(page),key)
     value=(len(data),len(page),h.hexdigest())
     if key in self.page_info:assert self.page_info[key]==value
     else:
      self.page_info[key]=value;path=self.cas/(key+".zlib")
      path.write_bytes(page);path.chmod(0o644)
      assert bounded_page(path.read_bytes(),key)==data
     case=name.split("/full-CAS/cas/")[0]
     self.case_pages.setdefault(case,set()).add(key)
    count+=1;total+=size;tf.members.clear()
   assert not index.readline()
  assert (count,total)==(self.manifest["members"],self.manifest["original_bytes"])
  self.report.update(all_tar_members_bytes_modes_SHA256_readback=True,members=count,original_bytes=total,
     full_original_copied_before_semantic_assertions=True,unique_CAS_pages=len(self.page_info),
     all_encoded_CAS_pages_bounded_decoded_and_hashed=True,tarinfo_cache_cleared=True)
 @lru_cache(maxsize=4096)
 def page(self,key):
  value=bounded_page((self.cas/(key+".zlib")).read_bytes(),key)
  assert len(value)==self.page_info[key][0];return value
 def full_hash(self,size,pages,cache):
  key=(size,tuple(pages))
  if key in cache:
   self.hashes_reused+=1;return cache[key]
  h=sha256();n=0
  for i,p in enumerate(pages):
   raw=self.page(p);assert len(raw)==min(4096,size-i*4096)
   n+=len(raw);h.update(raw)
  assert n==size
  value=h.hexdigest();cache[key]=value
  self.hashes_recomputed+=1;self.hash_bytes+=size
  return value
 def snapshot_table(self,case):
  previous={};descriptors={};cache={};logical=0
  with (self.root/case/"full-CAS/snapshots.jsonl").open() as stream:
   for number,line in enumerate(stream):
    d=json.loads(line);assert d["id"]==number and d["page_size"]==4096
    size=d["bytes"];assert type(size) is int and size>=0
    assert d["page_count"]==(size+4095)//4096
    old=previous.get(d["key"]);assert d["base"]==(None if old is None else old[0])
    before=() if old is None else old[1]
    pages=list(before[:d["page_count"]])+[None]*max(0,d["page_count"]-len(before))
    changed=d["changed"]
    assert [x[0] for x in changed]==sorted({x[0] for x in changed})
    for index,key in changed:
     assert type(index) is int and 0<=index<len(pages) and key in self.case_pages.get(case,set())
     assert index>=len(before) or before[index]!=key
     pages[index]=key
    assert all(type(key) is str and key in self.case_pages.get(case,set()) for key in pages)
    assert self.full_hash(size,pages,cache)==d["sha256"]
    frozen=tuple(pages);previous[d["key"]]=(number,frozen)
    descriptors[number]=dict(view={k:d[k] for k in("id","key","bytes","sha256")},pages=frozen)
    logical+=size
  self.snapshot_count+=len(descriptors);self.logical+=logical
  return descriptors,logical
 def span(self,descriptors,view,at,count):
  d=descriptors[view["id"]];assert view==d["view"]
  assert 0<=at<=view["bytes"] and 0<=count<=view["bytes"]-at
  result=bytearray()
  while count:
   i,offset=divmod(at,4096);raw=self.page(d["pages"][i]);n=min(count,len(raw)-offset)
   assert n>0;result.extend(raw[offset:offset+n]);at+=n;count-=n
  return bytes(result)
 def raw_descriptor(self,d,case):
  assert d["page_size"]==4096 and type(d["bytes"]) is int and 0<=d["bytes"]<=320
  assert len(d["pages"])==(d["bytes"]+4095)//4096
  assert all(key in self.case_pages[case] for key in d["pages"])
  raw=b"".join(self.page(key) for key in d["pages"])
  assert len(raw)==d["bytes"] and digest(raw)==d["sha256"]
  return raw
 def source_copies(self,pins,prefix,with_mode):
  for index,row in enumerate(pins,1):
   name=prefix+"/"+str(index)+"/"+PurePosixPath(row["path"]).name
   actual=self.rows[name]
   assert all(actual[k]==row[k] for k in("bytes","sha256")),(name,row,actual)
   if with_mode:assert actual["mode"]==row["mode"] and row["same"]
 def check_case(self,name,row,assets):
  path=self.root/name
  result=json_file(path/"result.json");assert result==row and row["status"]=="PASS"
  assert row["kind"]=="ACTUAL_REFERENCE_ADMITTED_CORE_AND_PLAN"
  oracle=json_file(path/"oracle.json")
  assert oracle["reference_before_native"] and oracle["label"]==row["label"] and oracle["error"]==row["error"]
  assert oracle["integer_digits"]==row["integer_digits"]
  core=path/"admitted-core.json";assert identity(core)["sha256"]==oracle["core_sha256"]
  if row["error"] is None:
   equal_file(path/"actual.canonical",path/"expected.canonical")
   assert identity(path/"actual.canonical")["sha256"]==oracle["canonical_sha256"]
   assert identity(path/"actual.canonical")["bytes"]==oracle["canonical_bytes"]
   assert row["complete_canonical_equal"] and not row["complete_original_error_equal"]
  else:
   assert row["complete_original_error_equal"] and not row["complete_canonical_equal"]
  evidence=json_file(path/"evidence.json")
  assert evidence==json_file(path/"full-CAS/source-after.json") and evidence["status"]=="PASS"
  assert evidence["source_pins_unchanged"] and not evidence["changed"]
  for key in("all_new_pages_decompressed_equal","all_final_pages_rehashed","full_memory_read_before_after_each_entry","delta_pages_reconstruct_identically"):
   assert evidence[key]
  self.source_copies(evidence["pins"],name+"/full-CAS/sources",False)
  pins={r["path"]:r for r in evidence["pins"]}
  for item in self.manifest["pairs"]:
   for kind in("source","image"):
    expected=item[kind];actual=pins[expected["path"]]
    assert all(actual[k]==expected[k] for k in("bytes","sha256"))
  asset_path=self.manifest["old_project"]+"/development/runtime-assets.json"
  assert all(pins[asset_path][k]==self.rows["checked-plan/development/runtime-assets.json"][k] for k in("bytes","sha256"))
  page_names=self.case_pages.get(name,set())
  assert evidence["cas_pages"]==len(page_names)
  assert evidence["cas_raw_bytes"]==sum(self.page_info[key][0] for key in page_names)
  table,logical=self.snapshot_table(name)
  count=row["native_entries"];assert len(table)==evidence["complete_snapshot_descriptors"]==count*6
  assert logical==evidence["logical_buffer_bytes"]
  actual_cases=[json.loads(line) for line in (path/"full-CAS/cases.jsonl").read_text().splitlines()]
  assert actual_cases==[row]
  entered=returned=0;pending=None;controller=None;reply=None;next_input=None;first=True;seq=0;peer_rows=[]
  calls={str(i):0 for i in range(1,6)};seen_snapshots=[];terminal=None
  with (path/"full-CAS/entries.jsonl").open() as stream:
   for line in stream:
    record=json.loads(line);state=record["status"]
    if state=="MECHANICAL_ACK":
     assert pending is None and controller is not None and record["event_hex"]==controller.hex()
     event=struct.unpack("<16Q",controller);assert event[0]==C_MAGIC and event[1]!=7
     assert event[3]==seq+1;seq=event[3]
     ack=self.raw_descriptor(record["ack"],name);words=struct.unpack("<8Q",ack[:64])
     assert words[:5]==(A_MAGIC,event[2],seq,event[1],0) and words[6]==len(ack)-64 and words[7]==0
     if event[1]==1:
      assert reply is not None and reply["role"]==event[4] and words[5]==reply["returned"]
      assert len(ack)==192
      peer_rows.append(dict(role=event[4],returned=words[5],event=list(struct.unpack("<16Q",ack[64:]))))
     else:assert words[5]==0
     next_input=(len(ack),digest(ack));reply=None;self.acks+=1
     continue
    assert state in("ENTERING","RETURNED")
    if state=="ENTERING":
     assert pending is None and record["number"]==entered
     assert len(record["before"])==len(record["capacities"])==len(record["readonly"])==3
     for view,cap in zip(record["before"],record["capacities"]):
      assert view==table[view["id"]]["view"] and view["bytes"]==cap;seen_snapshots.append(view["id"])
     role=record["role"];assert role in range(1,6)
     if role==5:
      expected=identity(path/"input.begin") if first else dict(bytes=next_input[0],sha256=next_input[1])
      assert all(record["before"][0][k]==expected[k] for k in("bytes","sha256"))
      assert record["readonly"]==[True,False,False]
      first=False;next_input=None
     else:
      assert controller is not None and struct.unpack("<16Q",controller)[4]==role
      assert record["readonly"]==[True,True,False]
     pending=record;entered+=1
    else:
     assert pending is not None and record["number"]==pending["number"] and record["role"]==pending["role"]
     for key in("before","capacities","readonly"):assert record[key]==pending[key]
     assert record["canaries_intact"] and len(record["after"])==3
     for i,(view,cap) in enumerate(zip(record["after"],record["capacities"])):
      assert view==table[view["id"]]["view"] and view["bytes"]==cap;seen_snapshots.append(view["id"])
      if record["readonly"][i]:assert view["sha256"]==record["before"][i]["sha256"]
     role=record["role"];event=bytes.fromhex(record["event_hex"])
     assert len(event)==128 and self.span(table,record["after"][1 if role==5 else 2],0,128)==event
     if role==5:
      assert record["returned"]==128
      controller=event;fields=struct.unpack("<16Q",event);assert fields[0]==C_MAGIC
      if fields[1]==7:
       assert fields[3]==seq;terminal=fields
     else:reply=dict(role=role,returned=record["returned"])
     calls[str(role)]+=1;returned+=1;pending=None
  assert pending is None and terminal is not None and next_input is None
  assert entered==returned==count and seen_snapshots==list(range(count*6))
  assert calls=={str(i):row["by_role"].get(str(i),0) for i in range(1,6)}
  assert peer_rows==row["actual_peer_events"]
  assert terminal[0:2]==(C_MAGIC,7) and terminal[7]==0
  if row["error"] is None:assert terminal[4:9]==(0,0,9,0,256)
  else:assert terminal[4:9]==(3,row["error"]["code"],10,0,len(row["error"]["text"].encode()))
  return dict(label=row["label"],native_entries=count,by_role=calls,snapshots=len(table),logical_bytes=logical)
 def semantics(self):
  manifest=self.manifest
  for row in manifest["source_files"]:
   actual=self.rows["checked-plan/"+row["path"]]
   assert all(actual[k]==row[k] for k in("bytes","sha256","gitsha")) and actual["mode"]==mode(row)
  row=manifest["driver"];actual=self.rows[row["name"]]
  assert actual["gitsha"]==OLD_DRIVER_GIT==row["gitsha"]
  assert all(actual[k]==row[k] for k in("bytes","sha256"))
  for row in manifest["original_summary_markers"]:
   actual=self.rows[row["name"]]
   assert all(actual[k]==row[k] for k in("bytes","sha256","gitsha"))
  assets=json_file(self.root/"checked-plan/development/runtime-assets.json")
  assert assets["schema"]=="hia-plan-development-runtime-assets-v1" and set(assets["roles"])=={str(i) for i in range(1,6)}
  pairs={}
  for role,expected in enumerate(manifest["pairs"],1):
   component=expected["component"];name="checked-plan/development/build-"+component+"-r2"
   summary=json_file(self.root/name/"summary.json");self.original_build_summaries.append(summary)
   assert summary["status"]=="PASS_BUILD_ONLY" and summary["compilations"]==1
   assert summary["native_semantic_entries"]==0 and summary["source_pins_unchanged"] and summary["original_limits_unchanged"]
   assert summary["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
   m=summary["manifest"];assert m==assets["roles"][str(role)]["manifest"]
   assert m["role"]==role and m["component"]==component and m["profile"]==expected["profile"]
   r=m["compile_receipt"]
   assert m["compiler_sha256"]==r["artifact_sha256"]==r["image_sha256"]==COMPILER_SHA
   assert r["status"]=="returned" and r["source_unchanged"] and not r["forbidden_compiler_modules_loaded"]
   assert r["limits"]["cpu_seconds"]==10 and r["limits"]["address_bytes"]==256<<20
   assert r["runner_sha256"]=="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
   for kind in("source","image"):
    target=expected[kind];actual=self.rows[target["name"]]
    assert all(actual[k]==target[k] for k in("bytes","sha256"))
    assert m[kind+"_path"]==target["path"] and m[kind+"_sha256"]==target["sha256"] and m[kind+"_bytes"]==target["bytes"]
   assert r["source_sha256"]==r["input_sha256"]==m["source_sha256"]
   assert r["produced_sha256"]==m["image_sha256"] and r["produced_bytes"]==m["image_bytes"]
   before=json_file(self.root/name/"source-before.json");after=json_file(self.root/name/"source-after.json")
   assert len(before)==len(after)>0
   for a,b in zip(before,after):
    for k in("path","bytes","sha256"):assert a[k]==b[k]
    assert b["same"]
    frozen=name+"/"+a["snapshot"];actual=self.rows[frozen]
    assert all(actual[k]==a[k] for k in("bytes","sha256","mode"))
   p=m["profile"]
   assert p["functions"]<=128 and p["blocks"]<=1536 and p["ops"]<=8192 and p["max_blocks"]<=256 and p["max_params"]<=16
   assert p["max_ssa_index"]<2048 and p["max_function_values"]==p["max_ssa_index"]+1
   pairs[component]={kind:dict(path=str(self.root/expected[kind]["name"]),**self.rows[expected[kind]["name"]]) for kind in("source","image")}
  full_run=json_file(self.root/"run/summary.json")
  assert full_run["status"]=="FAIL" and full_run["details"]["status"]=="FAIL"
  assert full_run["frozen_source_and_reference_before_after_equal"] and full_run["submitted_script_pins_before_after_equal"]
  assert full_run["details"]["actual_compilations"]==5
  assert full_run["details"]["actual_cases"]==375 and full_run["details"]["actual_native_entries"]==16814
  assert full_run["details"]["actual_private_controls"]==0
  complete=[];partial=None
  for index,expected in enumerate(manifest["groups"]):
   label=expected["group"]+"-"+str(expected["variant"]);name="checked-plan/development/native-"+label+"-r2"
   summary=json_file(self.root/name/"summary.json");self.original_group_summaries.append(summary)
   for k in("group","variant","status","cases","native_entries","by_role","covered_public_error_codes"):assert summary[k]==expected[k]
   assert summary["private_protocol_controls"]==0 and summary["VM_entries"]==0
   assert summary["limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
   for key in("original_group_limits_include_evidence_encoding","each_native_entry_complete_three_operands_before_after",
               "actual_command_ACK_event_full_bytes_retained","guards_and_hardware_readonly_and_canaries"):
    assert summary[key]
   for key in("host_plan_or_canonical_generation_during_native","actual_native_Core_admission_join",
               "public_foreign_graph_capture","public_emitter_join","standalone_preservation_witness_JSON","installed","cold","all_prior_pass_counts_inherited"):
    assert not summary[key]
   assert summary["source_custody"]["all_bytes_and_modes_equal"]
   pins=json_file(self.root/name/"source-before-after.json")
   assert len(pins)==summary["source_custody"]["files"]
   self.source_copies(pins,name+"/source",True)
   assert [r["label"] for r in summary["results"]]==expected["labels"]
   assert len(set(expected["labels"]))==len(expected["labels"])==expected["cases"]
   paths=sorted((self.root/name/"cases").glob("*/result.json"))
   assert len(paths)==expected["cases"]
   actual=[]
   for case_index,(path,row) in enumerate(zip(paths,summary["results"])):
    assert path.parent.name=="%04d"%case_index
    actual.append(self.check_case(path.parent.relative_to(self.root).as_posix(),row,assets))
   assert sum(r["native_entries"] for r in actual)==summary["native_entries"]
   calls={str(i):sum(r["by_role"][str(i)] for r in actual) for i in range(1,6)}
   assert calls==summary["by_role"]
   result=dict(group=expected["group"],variant=expected["variant"],cases=expected["cases"],native_entries=expected["native_entries"],
      by_role=calls,private_controls=0,covered_public_error_codes=summary["covered_public_error_codes"],
      complete_case_labels=expected["labels"],source_summary_path=str(self.root/name/"summary.json"),
      source_summary_identity=self.rows[name+"/summary.json"],full_CASE_CAS_readback=True)
   if index<21:
    assert summary["status"]=="PASS"
    assert manifest["full_schedule"][index]==[expected["group"],expected["variant"],expected["cases"],0]
    complete.append(result)
   else:
    assert index==21 and summary["status"]=="FAIL" and summary["group"]=="intervals"
    assert summary["error_class"]=="TypeError" and summary["error"]=="'str' object cannot be interpreted as an integer"
    assert "sys.set_int_max_str_digits(digits)" in summary["traceback"]
    result.update(status="ORIGINAL_FAIL_PRESERVED",credited_complete_groups=0,credited_union_cases=0,
       error_class=summary["error_class"],error=summary["error"])
    partial=result
   print("HIA_CHECKED_PLAN47_GROUP_READBACK "+json.dumps(result,sort_keys=True),flush=True)
  assert len(complete)==21 and sum(r["cases"] for r in complete)==355 and sum(r["native_entries"] for r in complete)==15886
  assert partial["cases"]==20 and partial["native_entries"]==928
  self.report.update(complete_groups=complete,incomplete_group=partial,actual_source_image_pairs=pairs,
    complete_group_count=21,credited_prior_cases=355,credited_prior_native_entries=15886,credited_prior_private_controls=0,
    all_observed_cases_readback=375,all_observed_native_entries_readback=16814,
    full_snapshot_descriptors_readback=self.snapshot_count,logical_buffer_bytes_readback=self.logical,
    recomputed_complete_buffer_hashes=self.hashes_recomputed,identical_page_vectors_hash_reused=self.hashes_reused,
    recomputed_complete_buffer_bytes=self.hash_bytes,complete_mechanical_ACKs_readback=self.acks,
    every_actual_operand_complete_bytes_reconstructed_and_SHA256_checked=True,
    original_image_source_copies_bound_to_all_cases=True,
    original_case_oracle_and_canonical_assertions_read_and_bound=True,
    original_failure_preserved=True,partial_20_not_counted_as_completed_group=True,
    old_runtime_assets_path=str(self.root/"checked-plan/development/runtime-assets.json"),
    original_full_schedule=manifest["full_schedule"],remaining_full_schedule=manifest["rerun_schedule"])
def timeout(signum,frame):raise TimeoutError("checked-plan47 readonly 180 second wall limit")
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
 started=time.monotonic();cpu=time.process_time()
 parser=argparse.ArgumentParser()
 for name in("input","out","manifest"):parser.add_argument("--"+name,type=Path,required=True)
 args=parser.parse_args();args.input=args.input.resolve();args.out=args.out.absolute();args.manifest=args.manifest.resolve()
 assert args.input.is_dir() and not args.out.exists() and not args.out.is_relative_to(args.input)
 args.out.mkdir(parents=True)
 report=dict(schema="hia-checked-plan47-independent-complete-original-readback-v1",status="INCOMPLETE",
   target_executions=0,VM_entries=0,native_entries=0,compiler_executions=0,
   original_failed_run_not_relabelled=True,new_tail_results_inherited=False,
   whole_public_backend=False,installed=False,cold=False)
 before={};primary=None;reader=None
 try:
  raw=args.manifest.read_bytes();assert git(raw)==MANIFEST_GIT
  manifest=json.loads(raw)
  assert (manifest["members"],manifest["original_bytes"],manifest["complete_groups"],manifest["complete_cases"])==(83803,1350967814,21,355)
  before[args.manifest]=identity(args.manifest);before[Path(__file__).resolve()]=identity(__file__)
  archive=unique(args.input,manifest["archive"]["basename"],manifest["archive"])
  ledger=unique(args.input,manifest["ledger"]["basename"],manifest["ledger"])
  before[archive]=identity(archive);before[ledger]=identity(ledger)
  originals=args.out/"complete-original";originals.mkdir()
  copy_original(archive,originals/"evidence.tar.xz")
  copy_original(ledger,originals/"evidence-members.jsonl")
  copy_original(args.manifest,originals/"input-manifest.json")
  report["complete_original_copy_identity"]={p.name:identity(p) for p in sorted(originals.iterdir())}
  report["full_original_archive_and_ledger_copied_and_readback_before_semantic_checks"]=True
  reader=Reader(args,manifest,report)
  reader.scan(originals/"evidence.tar.xz",originals/"evidence-members.jsonl")
  reader.semantics()
  report["status"]="PASS"
 except BaseException as error:
  primary=error;report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  after=[];failures=[]
  for path,expected in before.items():
   try:
    now=identity(path);same=now==expected
    after.append(dict(path=str(path),before=expected,after=now,same=same))
    if not same:raise AssertionError(("original input changed",str(path)))
   except BaseException as error:
    failures.append(dict(path=str(path),error_class=type(error).__name__,error=str(error)))
    if primary is not None:primary.add_note("after-check: "+repr(error))
  cpu_used=time.process_time()-cpu;wall=time.monotonic()-started
  if cpu_used>=90 or wall>=180:
   failures.append(dict(path="<reader budget>",error_class="AssertionError",error=str((cpu_used,wall))))
  if failures:
   report["status"]="FAIL";report["after_check_or_budget_failures"]=failures
  report.update(input_after_checks=after,all_inputs_after_equal=len(after)==len(before) and not failures,
     elapsed_wall_seconds=wall,elapsed_CPU_seconds=cpu_used,
     limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),
                 core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180),
     partial_readback=report["status"]!="PASS",reader_source=identity(__file__))
  save(args.out/"readback.json",report)
  print("HIA_CHECKED_PLAN47_ORIGINAL_READBACK "+json.dumps(report,sort_keys=True),flush=True)
  signal.setitimer(signal.ITIMER_REAL,0)
 if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
