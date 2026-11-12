"""Read-only replay of the exact failed FOLLOW50 first backend cross case.
No product imports, source generation, VM, B3, native entry or child process.
The byte replay below follows only already-recorded fixed mechanical events.
It does not create a new qualified target execution or turn the old case PASS.
"""
from pathlib import Path
from hashlib import sha256
import json,struct,zlib
MAGIC=int.from_bytes(b"HIACDE01","little")
ACK=int.from_bytes(b"HIACDA01","little")
READ_TWO=frozenset((1,2,3,4,5,6,8,9,10,12,13,14,15,17,18,21))
CONTROLLERS=frozenset((11,16,20))
ROLES=set(range(1,22))
def digest(raw):return sha256(raw).hexdigest()
def exact(stream,n):
 parts=[];left=n
 while left:
  block=stream.read(min(left,1<<18))
  assert block,"truncated original"
  parts.append(block);left-=len(block)
 return b"".join(parts)
def records(path):
 with path.open("rb") as stream:
  while True:
   header=stream.read(16)
   if not header:return
   assert len(header)==16
   kind,n=struct.unpack("<2Q",header)
   assert kind in range(1,9) and n<=path.stat().st_size-stream.tell()
   yield kind,exact(stream,n)
def read_json(path):return json.loads(path.read_bytes())
class SnapshotReader:
 def __init__(self,root):
  self.root=root;self.pages={};self.descriptors=[];self.logical=0
  for path in sorted((root/"cas").glob("*.zlib")):
   assert len(path.stem)==64 and path.stem not in self.pages
   raw=zlib.decompress(path.read_bytes())
   assert 0<len(raw)<=4096 and digest(raw)==path.stem
   self.pages[path.stem]=raw
  previous={}
  with (root/"snapshots.jsonl").open("r",encoding="utf-8") as stream:
   for identifier,line in enumerate(stream):
    d=json.loads(line);n=d["bytes"];key=d["key"]
    assert d["id"]==identifier and type(n) is int and n>=0
    assert d["page_size"]==4096 and d["page_count"]==(n+4095)//4096
    assert d["base"]==previous.get(key)
    old=[] if d["base"] is None else self.descriptors[d["base"]]["pages"]
    pages=list(old[:d["page_count"]])+[None]*max(0,d["page_count"]-len(old))
    last=-1
    for at,h in d["changed"]:
     assert type(at) is int and last<at<len(pages) and h in self.pages
     pages[at]=h;last=at
    assert all(h is not None for h in pages)
    state=sha256()
    for at,h in enumerate(pages):
     raw=self.pages[h];assert len(raw)==min(4096,n-at*4096)
     state.update(raw)
    assert state.hexdigest()==d["sha256"]
    self.descriptors.append(dict(id=identifier,key=key,bytes=n,sha256=d["sha256"],pages=pages))
    self.logical+=n;previous[key]=identifier
  custody=read_json(root/"source-after.json")
  assert custody["status"]=="PASS" and custody["source_pins_unchanged"] and not custody["changed"]
  for name in("all_new_pages_decompressed_equal","all_final_pages_rehashed",
      "full_memory_read_before_after_each_entry","delta_pages_reconstruct_identically"):
   assert custody[name]
  assert custody["cas_pages"]==len(self.pages)
  assert custody["cas_raw_bytes"]==sum(map(len,self.pages.values()))
  assert custody["complete_snapshot_descriptors"]==len(self.descriptors)
  assert custody["logical_buffer_bytes"]==self.logical
  self.custody=custody
 def descriptor(self,view):
  d=self.descriptors[view["id"]]
  assert view=={k:d[k] for k in("id","key","bytes","sha256")}
  return d
 def data(self,view):
  d=self.descriptor(view);raw=b"".join(self.pages[h] for h in d["pages"])
  assert len(raw)==d["bytes"] and digest(raw)==d["sha256"]
  return raw
 def raw(self,d):
  assert d["page_size"]==4096 and len(d["pages"])==(d["bytes"]+4095)//4096
  raw=b"".join(self.pages[h] for h in d["pages"])
  assert len(raw)==d["bytes"] and digest(raw)==d["sha256"]
  return raw

def native_trace(path,assets,initial,original_path):
 counts={i:0 for i in range(1,22)};images=set();limits=None;input_seen=False
 current=None;last_return=None;pending=None;last_ack=True;commands=0;terminal=None
 entries=[];returns=[];acks=[];command_bytes=[]
 for kind,raw in records(path):
  if kind==8:
   assert limits is None and not images and len(raw)==64
   limits=struct.unpack("<8Q",raw);assert limits==(90,90,1<<30,1<<30,0,0,180,4096)
  elif kind==1:
   assert limits is not None and not input_seen and len(raw)>=16
   role,n=struct.unpack_from("<2Q",raw)
   assert role in ROLES and role not in images and n==len(raw)-16
   m=assets["roles"][str(role)]["manifest"]
   assert n==m["image_bytes"] and digest(raw[16:])==m["image_sha256"]
   assert raw[16:]==original_path(m["image_path"]).read_bytes()
   images.add(role)
  elif kind==2:
   assert images==ROLES and not input_seen and raw==initial;input_seen=True
  elif kind==3:
   assert input_seen and terminal is None and current is None and len(raw)==128
   v=struct.unpack("<16Q",raw);serial,role=v[:2]
   assert role in ROLES and serial==sum(counts.values())+1
   assert v[9]==1 and v[11]==0 and v[12:]==(0,)*4
   if role==20:
    assert pending is None and last_ack and v[5:9]==(3,128,2,1<<20) and v[10]==0
   else:
    assert pending is not None and pending[1]==1 and role==pending[4]
    assert v[2:9]==(pending[5],pending[6],pending[7],pending[8],pending[9],pending[10],pending[11])
    assert v[10]==(0 if role in(7,11,16,19) else 1)
   current=v;counts[role]+=1;entries.append(v)
  elif kind==4:
   assert current is not None and len(raw)>=32
   serial,role,returned,n=struct.unpack_from("<4Q",raw)
   assert (serial,role)==current[:2] and n==len(raw)-32 and n<=128
   last_return=(role,returned,raw[32:]);current=None
   returns.append((serial-1,role,returned,raw[32:].hex()))
  elif kind==5:
   assert current is None and pending is None and last_return is not None
   assert last_return[0:2]==(20,128) and raw==last_return[2] and len(raw)==128
   pending=struct.unpack("<16Q",raw)
   assert pending[0]==MAGIC and pending[1] in(1,2,3,4,5,6,14) and pending[3]==commands+1
   commands+=1;last_ack=False;command_bytes.append(raw)
  elif kind==6:
   assert pending is not None and len(raw)>=64
   a=struct.unpack_from("<8Q",raw)
   assert a[:5]==(ACK,pending[2],pending[3],pending[1],0) and a[6]==len(raw)-64 and a[7]==0
   if pending[1]==1:
    assert last_return is not None and last_return[0]==pending[4] and a[5]==last_return[1]
    if pending[12]==pending[10] and pending[13]==0 and pending[14]<=len(last_return[2]):
     assert raw[64:]==last_return[2][:pending[14]]
   else:assert a[5]==0
   acks.append((command_bytes[-1].hex(),raw));pending=None;last_ack=True
  else:
   assert kind==7 and current is None and pending is None and last_return is not None
   assert last_return[0]==20 and terminal is None and raw==last_return[2] and len(raw)==128
   terminal=(last_return[1],raw)
 assert limits is not None and images==ROLES and input_seen and terminal is not None
 assert current is None and pending is None and len(entries)==len(returns)==sum(counts.values())
 return dict(counts=counts,entries=entries,returns=returns,acks=acks,
             commands=commands,terminal=terminal,limits=limits)

def python_replay(directory,initial,native):
 snapshots=SnapshotReader(directory)
 slots={0:dict(data=bytearray(),readonly=True),1:dict(data=bytearray(initial),readonly=True),
        2:dict(data=bytearray(1<<20),readonly=False),3:dict(data=bytearray(128),readonly=False)}
 def span(slot,at,n):
  assert type(slot) is int and 0<=slot<64 and slot in slots
  raw=slots[slot]["data"];assert 0<=at<=len(raw) and 0<=n<=len(raw)-at
  return raw[at:at+n]
 def put(slot,at,raw):
  span(slot,at,len(raw));assert not slots[slot]["readonly"]
  slots[slot]["data"][at:at+len(raw)]=raw
 counts={};entry=None;pending=None;sequence=0;lease=None;last_peer=None
 input_bytes=initial;returns=[];acks=[];entries=0;commands=0;terminal=None
 descriptor_cursor=0
 with (directory/"entries.jsonl").open("r",encoding="utf-8") as stream:
  for line in stream:
   row=json.loads(line);status=row["status"]
   if status=="ENTERING":
    assert entry is None and terminal is None and row["number"]==entries
    role=row["role"];assert role in ROLES and len(row["before"])==3
    assert [v["id"] for v in row["before"]]==list(range(descriptor_cursor,descriptor_cursor+3))
    descriptor_cursor+=3;v=native["entries"][entries]
    assert v[:2]==(entries+1,role)
    if role==20:
     assert pending is None
     operands=[input_bytes,bytes(span(3,0,128)),bytes(span(2,0,1<<20))]
     views=[None,(3,0,128),(2,0,1<<20)];readonly=[True,False,False]
     assert v[4]==len(input_bytes)
    else:
     assert pending is not None and pending[1]==1 and pending[4]==role
     a=pending[4:];src,at,n,second,second_n,work,work_n=a[1:8]
     assert len({src,second,work})==3 and work>=4 and not slots[work]["readonly"]
     if role not in READ_TWO:assert second>=4 and not slots[second]["readonly"]
     operands=[bytes(span(src,at,n)),bytes(span(second,0,second_n)),bytes(span(work,0,work_n))]
     views=[(src,at,n),(second,0,second_n),(work,0,work_n)]
     readonly=[True,role in READ_TWO,False]
    assert row["capacities"]==list(map(len,operands)) and row["readonly"]==readonly
    for before,raw in zip(row["before"],operands):assert snapshots.data(before)==raw
    counts[role]=counts.get(role,0)+1;entries+=1
    entry=(row,views,readonly)
   elif status=="RETURNED":
    assert entry is not None
    original,views,readonly=entry;role=row["role"]
    for key in("number","role","before","capacities","readonly"):assert row[key]==original[key]
    assert row["canaries_intact"] and len(row["after"])==3
    assert [v["id"] for v in row["after"]]==list(range(descriptor_cursor,descriptor_cursor+3))
    descriptor_cursor+=3
    after=[snapshots.data(view) for view in row["after"]]
    for i,(view,raw) in enumerate(zip(views,after)):
     assert len(raw)==row["capacities"][i]
     if readonly[i]:assert raw==snapshots.data(row["before"][i])
     else:
      assert view is not None;slot,at,n=view;assert len(raw)==n;put(slot,at,raw)
    event=after[1 if role in CONTROLLERS else 2][:128]
    assert event.hex()==row["event_hex"]
    result=(row["number"],role,row["returned"],row["event_hex"])
    assert result==native["returns"][row["number"]];returns.append(result)
    entry=None
    if role==20:
     assert row["returned"]==128 and len(event)==128
     v=struct.unpack("<16Q",event);assert v[0]==MAGIC and v[2]!=0
     if lease is None:lease=v[2]
     assert v[2]==lease
     if v[1]==7:
      assert v[3]==sequence and slots[v[6]]["readonly"]
      span(v[6],v[7],v[8]);terminal=(row["returned"],event)
     else:
      assert v[1] in(1,2,3,4,5,6,14) and v[3]==sequence+1
      sequence=v[3];pending=v;last_peer=None
    else:
     assert pending is not None and pending[1]==1 and role==pending[4]
     last_peer=(role,row["returned"])
   elif status=="MECHANICAL_ACK":
    assert entry is None and pending is not None and terminal is None
    event=bytes.fromhex(row["event_hex"]);assert event==struct.pack("<16Q",*pending)
    op=pending[1];a=pending[4:];observed=b"";returned=0
    if op==1:
     role,src,at,n,second,second_n,work,work_n,observe,observe_at,observe_n,reserved=a
     assert reserved==0 and observe_n<=256 and last_peer is not None and last_peer[0]==role
     observed=bytes(span(observe,observe_at,observe_n));returned=last_peer[1]
    elif op==2:
     target,size=a[:2];assert 3<=target<64 and size>0 and a[2:]==(0,)*10
     old=slots.get(target);raw=bytearray() if old is None else old["data"]
     assert size>len(raw);slots[target]=dict(data=raw+bytearray(size-len(raw)),readonly=False)
    elif op==3:
     target,at,n=a[:3];assert target>=4 and a[3:]==(0,)*9
     put(target,at,bytes(n))
    elif op==4:
     src,at,target,to,n=a[:5];assert target>=4 and src!=target and a[5:]==(0,)*7
     raw=bytes(span(src,at,n));put(target,to,raw)
    elif op==5:
     target=a[0];assert 4<=target<64 and a[1:]==(0,)*11 and target in slots;del slots[target]
    elif op==6:
     target,ro=a[:2];assert 4<=target<64 and ro in(0,1) and a[2:]==(0,)*10
     assert target in slots;slots[target]["readonly"]=bool(ro)
    else:
     assert op==14
     src,at,n=a[:3];assert n<=256 and a[3:]==(0,)*9;observed=bytes(span(src,at,n))
    ack=struct.pack("<8Q",ACK,lease,sequence,op,0,returned,len(observed),0)+observed
    assert snapshots.raw(row["ack"])==ack
    assert native["acks"][commands]==(event.hex(),ack)
    commands+=1;acks.append((event.hex(),ack));input_bytes=ack;pending=None;last_peer=None
   else:raise AssertionError(("unexpected original status",status))
 assert entry is None and pending is None and terminal is not None
 assert descriptor_cursor==len(snapshots.descriptors)==entries*6
 assert returns==native["returns"] and acks==native["acks"] and terminal==native["terminal"]
 dense={i:counts.get(i,0) for i in range(1,22)}
 assert entries==sum(native["counts"].values()) and commands==native["commands"]
 assert dense==native["counts"]
 # This exact old assertion failed because absent zero keys are significant.
 assert counts!=native["counts"]
 missing=sorted(ROLES-set(counts))
 assert missing==[12,13,14,15,16] and all(native["counts"][i]==0 for i in missing)
 return dict(slots=slots,counts=counts,dense_counts=dense,entries=entries,commands=commands,
             terminal=terminal,snapshot_count=descriptor_cursor,logical_bytes=snapshots.logical,
             CAS_pages=len(snapshots.pages),CAS_raw_bytes=sum(map(len,snapshots.pages.values())),
             missing_zero_keys=missing)

def final_slots(path,replayed,native):
 seen=set();last=-1;summary={}
 with path.open("rb") as stream:
  h=struct.unpack("<8Q",exact(stream,64))
  assert h[:2]==(int.from_bytes(b"HIAEMXS1","little"),1)
  assert h[2:4]==(replayed["entries"],replayed["commands"])
  assert h[4]==native["terminal"][0] and h[5]==len(replayed["slots"]) and h[6:]==(128,0)
  assert exact(stream,128)==native["terminal"][1]
  for _ in range(h[5]):
   slot,n,ro,owned,*reserved=struct.unpack("<8Q",exact(stream,64))
   assert last<slot<64 and ro in(0,1) and owned==1 and reserved==[0]*4
   b=replayed["slots"][slot];assert len(b["data"])==n and b["readonly"]==bool(ro)
   state=sha256()
   for at in range(0,n,1<<18):
    block=exact(stream,min(n-at,1<<18));assert block==b["data"][at:at+len(block)]
    state.update(block)
   summary[str(slot)]=dict(bytes=n,readonly=bool(ro),sha256=state.hexdigest())
   last=slot;seen.add(slot)
  assert stream.read(1)==b"" and seen==set(replayed["slots"])
 return summary

def audit(root,ledger,observation):
 root=Path(root);by_original={}
 for name,row in ledger.items():
  assert row["path"] not in by_original
  by_original[row["path"]]=name
 def member(name):
  assert name in ledger;return root/name
 def original_path(path):
  assert path in by_original,path
  return member(by_original[path])
 project="backend-join/"
 fixed_sources={
  "tests/backend_mechanical_harness.py":"68e884ce901c2c5611ca72309513ba3b6e605c5338246fd3a4123e12e0a351eb",
  "tests/backend_native_adapter.py":"d5c2732735410dd02be8754ce16db0473bb51febf6b2dc8f11ffd897a42dc4b7",
  "tests/function_frame_test_reference.py":"b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6",
  "tests/test_hia_backend_join.py":"7f3062a520bc546258f3bf4d715025a63a657d14232d3fc9cbed0c62f8a17095",
  "tools/backend_native_mechanics.c":"dae66f88b96826384c6c278e4f391754acdd43c51c989f963bd90e6bc83d764c"}
 for name,want in fixed_sources.items():assert digest(member(project+name).read_bytes())==want
 assets=read_json(member(project+"development/runtime-assets.json"))
 assert assets["schema"]=="hia-backend-join-runtime-assets-v1"
 assert set(map(int,assets["roles"]))==ROLES and assets["root_role"]==20
 assert assets["actual_fresh_B3_compilations"]==21 and not assets["old_results_inherited"]
 assert len(observation["observed_build"]["roles"])==21
 assert {row["runtime_role"] for row in observation["observed_build"]["roles"]}==ROLES
 bindings=[]
 for row in observation["observed_build"]["roles"]:
  role=row["runtime_role"];m=assets["roles"][str(role)]["manifest"]
  for kind in("source","image"):
   expected=row[kind];path=original_path(m[kind+"_path"]);raw=path.read_bytes()
   assert m[kind+"_path"]==expected["path"]
   assert len(raw)==m[kind+"_bytes"]==expected["bytes"]
   assert digest(raw)==m[kind+"_sha256"]==expected["sha256"]
  receipt=m["compile_receipt"]
  assert receipt["status"]=="returned" and receipt["abi_status"]==0 and receipt["source_unchanged"]
  assert receipt["source_sha256"]==receipt["input_sha256"]==m["source_sha256"]
  assert receipt["input_bytes"]==m["source_bytes"]
  assert receipt["artifact_sha256"]==m["compiler_sha256"]==row["compiler_sha256"]
  assert receipt["produced_sha256"]==m["image_sha256"] and receipt["produced_bytes"]==m["image_bytes"]
  assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
  assert receipt["wall_elapsed_ns"]<=20000000000
  bindings.append(dict(role=role,source_sha256=m["source_sha256"],image_sha256=m["image_sha256"]))
 run=read_json(member("run/summary.json"))
 assert run["status"]=="FAIL" and run["details"]["actual_compilations"]==21
 assert set(run["details"]["groups"])=={"cross-0"}
 group_name=project+"development/native-cross-0-r1/"
 group=read_json(member(group_name+"summary.json"))
 assert group["status"]=="FAIL" and group["group"]=="cross" and group["variant"]==0
 assert group["cases"]==0 and group["reference_admitted_fixtures"]==1
 assert group["error_class"]=="AssertionError" and 'self.calls==python.calls' in group["traceback"]
 assert group["source_custody"]==dict(all_bytes_and_modes_equal=True,files=510)
 case_name=group_name+"cases/0000/";case=root/case_name
 assert {name[len(group_name+"cases/"):].split("/")[0] for name in ledger if name.startswith(group_name+"cases/")}=={"0000"}
 assert case_name+"result.json" not in ledger
 assert case_name+"actual.terminal.bin" not in ledger and case_name+"actual.result.bin" not in ledger
 initial=member(case_name+"initial.bin").read_bytes()
 assert member(case_name+"native-trace/initial.bin").read_bytes()==initial
 oracle=read_json(member(case_name+"oracle.json"))
 assert oracle["label"]=="complete-object-metadata-and-all-slots"
 assert oracle["error"] is None and oracle["actual_reference_admitted_Core"]
 assert oracle["raw_plan_supplied_to_native"] and not oracle["canonical_plan_supplied_to_native"]
 assert not oracle["private_stale_hash_fixture"] and oracle["private_actual_object_corruption"] is None
 trace_root=case/"native-trace"
 process=read_json(member(case_name+"native-trace/process.json"))
 assert process["exit_code"]==0 and not process["timeout"] and process["child_reaped"] and not process["cleanup_errors"]
 assert process["limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
 assert member(case_name+"native-trace/stdout.bin").read_bytes()==member(case_name+"native-trace/stderr.bin").read_bytes()==b""
 closed=read_json(member(case_name+"native-trace/closed-evidence.json"))
 assert closed["source_image_before_after_exact"] and closed["complete_event_ACK_trace"]
 assert closed["raw_retained_after_failed_comparison"] and not closed["all_intermediate_workspaces"]
 files=read_json(member(case_name+"native-trace/full-files.json"))
 for name,want in files.items():
  assert "/" not in name and name in("trace.bin","final-slots.bin","initial.bin","stdout.bin","stderr.bin")
  row=ledger[case_name+"native-trace/"+name]
  assert want=={k:row[k] for k in("bytes","sha256")}
 for name,key in(("trace.bin","trace"),("final-slots.bin","all_final_slots")):
  row=ledger[case_name+"native-trace/"+name]
  assert closed[key]=={k:row[k] for k in("bytes","sha256")}
 native=native_trace(trace_root/"trace.bin",assets,initial,original_path)
 old_trace=read_json(member(case_name+"native-trace/trace-summary.json"))
 assert old_trace["native_entries"]==sum(native["counts"].values())
 assert old_trace["by_role"]=={str(k):v for k,v in native["counts"].items()}
 assert old_trace["commands"]==native["commands"] and old_trace["returned"]==native["terminal"][0]
 assert old_trace["terminal_hex"]==native["terminal"][1].hex()
 replayed=python_replay(case/"python-full-CAS",initial,native)
 final=final_slots(trace_root/"final-slots.bin",replayed,native)
 assert group["native_entries"]==replayed["entries"]+sum(native["counts"].values())
 assert group["by_role"]=={str(i):replayed["dense_counts"][i]+native["counts"][i] for i in range(1,22)}
 def view(slot,at,n):
  b=replayed["slots"][slot];assert b["readonly"]
  assert 0<=at<=len(b["data"]) and 0<=n<=len(b["data"])-at
  return bytes(b["data"][at:at+n])
 event=struct.unpack("<16Q",native["terminal"][1])
 assert event[:3]==(MAGIC,7,19) and event[4:9]==(0,0,35,0,512) and event[15]==1
 payload=view(*event[6:9]);head=struct.unpack("<64Q",payload)
 assert head[:8]==(int.from_bytes(b"HIABMR01","little"),1,19,1,17,41,23,29)
 assert head[60:]==(0,)*4 and head[8]==31 and head[11]==30 and head[14:16]==(19,0) and head[17:19]==(32,0)
 assert head[20:25]==(0,0,0,0,0) and 11 not in replayed["slots"]
 comparisons={}
 for start,name in((8,"object.bin"),(11,"text.bin"),(14,"metadata.json")):
  raw=view(*head[start:start+3]);reference=member(case_name+"reference."+name).read_bytes()
  assert raw==reference
  comparisons[name]=dict(bytes=len(raw),sha256=digest(raw))
 assert payload[256:480]==b"".join(bytes.fromhex(h) for h in(
  oracle["core_sha256"],oracle["input_sha256"],oracle["implementation_before"],oracle["implementation_after"],
  comparisons["object.bin"]["sha256"],comparisons["text.bin"]["sha256"]))+bytes(32)
 assert event[9:15]==(head[16],head[10],head[13],0,head[26],head[27])
 return dict(schema="hia-backend50-read-only-first-cross-replay-v1",status="PASS_READBACK_ONLY",
  original_job_status="FAIL",original_completed_cases=0,new_qualified_cases=0,
  native_entries_executed=0,VM_entries_executed=0,B3_calls_executed=0,product_imports=0,
  original_C_entries=sum(native["counts"].values()),original_Python_carrier_entries=replayed["entries"],
  original_aggregate_entries=group["native_entries"],mechanical_commands_each=native["commands"],
  dense_role_counts_equal=True,sparse_Python_counts_equal_to_C=False,missing_zero_keys=replayed["missing_zero_keys"],
  original_C_dense_counts={str(k):v for k,v in native["counts"].items()},
  original_Python_sparse_counts={str(k):v for k,v in replayed["counts"].items()},
  all_native_entry_roles_return_values_event_bytes_equal=True,
  all_mechanical_command_ACK_bytes_equal=True,all_final_slot_bytes_and_permissions_equal=True,
  full_Python_intermediate_snapshots_verified=replayed["snapshot_count"],
  full_Python_logical_buffer_bytes_verified=replayed["logical_bytes"],
  full_Python_CAS_pages_verified=replayed["CAS_pages"],full_Python_CAS_raw_bytes=replayed["CAS_raw_bytes"],
  complete_source_image_bindings=bindings,complete_final_slots=final,
  read_only_actual_outputs_equal_original_reference_files=comparisons,
  compound_counter_assertion_failure_explained_by_absent_zero_keys=True,
  native_intermediate_workspace_bytes_exist=False,
  first_case_not_reclassified_as_original_PASS=True,complete_backend_or_public_build_qualified=False)
