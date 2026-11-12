"""Complete recorded nine-role native windows and issued-capsule replay.

Every actual BEFORE window is executed in a fresh original CoreVM with
4,000,000 steps / 32 MiB / depth64. Complete return/output/workspace bytes
are compared without masks or cached results. The replayer issues no syscall
or native image call. Live provenance still belongs to the fixed executable;
these recorded bytes are evidence, never accepted runtime capabilities.
"""
from __future__ import annotations
import gzip,hashlib,json,stat,struct
from pathlib import Path
MASK=(1<<64)-1
BAD=0xfffffffd
def magic(raw):return int.from_bytes(raw,"little")
MAGICS={magic(b"HIANFT03"):1,magic(b"HIASMT01"):2,magic(b"HIANMT01"):3,
 magic(b"HIANDT03"):4,magic(b"HIADBT01"):5,magic(b"HIADJT01"):6,
 magic(b"HIAUPT01"):7,magic(b"HIAUFT01"):8,magic(b"HIAUJT01"):9}
CAPTRACE=magic(b"HIAUIT01")
CAPSULE=magic(b"HIAUIC01")
ISSUER_CHANNEL=magic(b"HIAUIX01")
ISSUER_EVENT=magic(b"HIAUIE01")
JOIN_CHANNEL=magic(b"HIANDJX1")
PARENT=magic(b"HIANUO01")
FS=magic(b"HIANFR03")
MEM=magic(b"HIANML01")
MEM_CHANNEL=magic(b"HIANMX01")
SYSCALLS={1:257,2:17,3:18,4:5,5:77,6:74,7:264,8:3,9:263,10:258,11:73,
 12:228,13:35,14:318,15:5,16:107,17:72,18:262,19:267,20:79,21:91,
 22:268,23:72,24:93,25:257,26:39,27:21,28:257,29:262,30:21,31:263}
def q(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def identity(path):
 path=Path(path);st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
 h=hashlib.sha256();n=0
 with path.open("rb") as f:
  while b:=f.read(1<<18):n+=len(b);h.update(b)
 assert n==st.st_size
 return dict(bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(st.st_mode))
class CAS:
 def __init__(self,path):
  self.path=Path(path);self.path.mkdir(parents=True,exist_ok=False)
  self.rows={}
 def put(self,raw):
  raw=bytes(raw);h=sha(raw);path=self.path/h
  if h not in self.rows:
   with path.open("xb") as f:f.write(raw)
   assert path.read_bytes()==raw
   self.rows[h]=dict(bytes=len(raw),sha256=h,path=str(path),mode=0o644)
  else:assert self.rows[h]["bytes"]==len(raw)
  return self.rows[h]
 def readback(self):
  for row in self.rows.values():
   assert identity(row["path"])=={k:row[k] for k in("bytes","sha256","mode")}

def records(path):
 """Streaming decoder of actual traces; no project or target code executed."""
 path=Path(path);size=path.stat().st_size;offset=0
 with path.open("rb") as stream:
  def take(n):
   nonlocal offset
   assert 0<=n<=size-offset,(offset,n,size)
   raw=stream.read(n);assert len(raw)==n;offset+=n;return raw
  while offset<size:
   start=offset;h=struct.unpack("<12Q",take(96))
   assert h[11]==0
   if h[0]==CAPTRACE:
    assert h[1] in (5,6) and h[4] in (6,7,8)
    payload=take(h[3])
    yield dict(offset=start,header=h,kind=h[1],role=h[4],payload=payload)
    continue
   assert h[0] in MAGICS
   role=MAGICS[h[0]];kind=h[1]
   assert h[10]==role and h[9]>0
   row=dict(offset=start,header=h,kind=kind,role=role)
   if kind==1:
    row.update(input=take(h[3]),output=take(h[4]),workspace=take(h[5]))
   elif kind==2:
    row.update(output=take(h[4]),workspace=take(h[5]))
   elif kind==3:
    assert role in (1,3);row["ack"]=take(h[3])
   elif kind==4:
    assert h[3:6]==(0,0,0) and offset==size
   else:raise AssertionError(("unknown trace kind",kind,role))
   yield row
 assert offset==size

def latest_shared_FS(path):
 last=None
 for row in records(path):
  if row["role"]==6 and row["kind"]==2:last=row
 assert last is not None and last["header"][6]==0
 w=last["workspace"];assert q(w,0)==magic(b"HIANDJ01") and q(w,8)==1
 return last

def replay(directory,programs,*,expected_fatal=0):
 from hepta.hia_program_runtime import _Machine,_Owner,_View
 directory=Path(directory);trace=directory/"trace.bin";before=identity(trace)
 requests=json.loads((directory/"requests.json").read_bytes())
 boot=json.loads((directory/"boot.json").read_bytes());pid=boot["actual_process"]
 assert set(programs)==set(range(1,10))
 output=directory/"full-native-VM-replay";output.mkdir()
 cas=CAS(output/"cas");ledger_path=output/"entries.jsonl.gz"
 states={};begins={};caps={};last_input_lease=0;transport_index=0
 entries={r:0 for r in programs};vm_counts={r:0 for r in programs}
 grows={r:0 for r in programs};primitive_counts={};capsule_count=0
 pending_child=None;pending_ack=None;active_VM=None;fatals=[];links=[]
 root_calls=0;root_actions=0;parent_raw_acks=0
 def state_for(role,node,generation):
  key=(role,node,generation)
  if key not in states:
   states[key]=dict(serial=0,last=None,waiting=None,ack=None,sysseq=0)
  return key,states[key]
 def span(raw,at,n):
  assert 0<=at<=len(raw) and 0<=n<=len(raw)-at
  return raw[at:at+n]
 def log(row):
  ledger.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");ledger.flush()
 def check_external(role,raw,action):
  nonlocal transport_index
  if action:return
  assert role in (6,7) and transport_index<len(requests)
  req=requests[transport_index];transport_index+=1
  assert req["transport_kind"]==(1 if role==6 else 2)
  original=(directory/"requests"/str(req["index"])/"input.bin").read_bytes()
  assert (len(original),sha(original))==(req["input_bytes"],req["input_sha256"])
  wire=(directory/"requests"/str(req["index"])/"transport.bin").read_bytes()
  assert (len(wire),sha(wire))==(req["transport_bytes"],req["transport_sha256"])
  assert wire==struct.pack("<8Q",magic(b"HIAUIP01"),req["transport_kind"],len(original),0,0,0,0,0)+original
  if role==6:
   header=bytearray(128)
   for at,value in ((0,JOIN_CHANNEL),(8,1),(32,len(original)),(88,4096)):
    struct.pack_into("<Q",header,at,value)
   assert raw==bytes(header)+original
  else:
   assert len(original)>=512 and q(original,184)==0
   expected=bytearray(original);struct.pack_into("<Q",expected,184,pid)
   assert raw==bytes(expected)
 def capsule(row):
  nonlocal capsule_count
  h=row["header"];raw=row["payload"];role=row["role"]
  assert len(raw)>=128
  c=struct.unpack_from("<16Q",raw)
  assert c[:6]==(CAPSULE,role,h[5],h[10],h[2],h[6])
  assert c[9:]==(h[7],1,int(role==8),0,pid,h[8],h[9])
  assert 128+c[6]+c[7]+c[8]==len(raw)
  key=(role,0,h[10]);assert key in states and h[5]==role
  state=states[key];begin=begins[role]
  assert begin["lease"]==h[7] and begin["call"]==h[9] and begin["action"]==h[8]
  assert h[2]>begin["serial"] and state["serial"]==h[2] and state["waiting"] is None
  original=span(raw,128,c[6]);out=span(raw,128+c[6],c[7]);work=span(raw,128+c[6]+c[7],c[8])
  assert original==begin["input"]
  assert (h[6],out,work)==(state["last"]["returncode"],state["last"]["output"],state["last"]["workspace"])
  assert begin["first_seen"]
  caps[role]=raw;capsule_count+=1
  log(dict(kind="actual-complete-capsule",offset=row["offset"],role=role,context=h[5],
   generation=h[10],entry_serial=h[2],lease=h[7],call=h[9],action=h[8],raw=cas.put(raw)))
 def check_root_before(raw,state):
  nonlocal pending_child,root_calls,root_actions
  assert len(raw)>=256 and q(raw,0)==ISSUER_CHANNEL
  assert (q(raw,16),q(raw,24),q(raw,40),q(raw,48),q(raw,56))==(pid,9,9,1,pid)
  command=q(raw,8)
  if state["last"] is not None and state["last"]["returncode"]==2:
   assert raw==state["last"]["input"]
   return
  if command==1:
   assert pending_child is None and pending_ack is None
   assert q(raw,32)==root_calls+1
   root_calls+=1;root_actions=0
   parent_size=q(raw,88);fs_size=q(raw,96)
   assert 256+parent_size+fs_size==len(raw)
   assert span(raw,256,parent_size)==caps[7]
   assert span(raw,256+parent_size,fs_size)==caps[6]
  else:
   assert command==2 and q(raw,32)==root_calls and pending_child is not None
   assert q(raw,64)==root_actions==pending_child["action"]
   assert q(raw,72)==len(raw)-256
   assert raw[256:]==caps[pending_child["role"]]
   c=struct.unpack_from("<16Q",raw,256)
   assert c[14:]==(pending_child["action"],root_calls)
   assert pending_child["begun"]
   links.append(dict(role=pending_child["role"],call=root_calls,action=root_actions,
    capsule_sha256=sha(raw[256:]),input_sha256=sha(pending_child["input"]),
    second_sha256=sha(pending_child["second"])))
   pending_child=None
 failure=None
 try:
  with gzip.open(ledger_path,"wt",encoding="utf-8") as ledger:
   for row in records(trace):
    h=row["header"];role=row["role"];kind=row["kind"]
    if kind==6:
     assert role in (6,7,8) and h[5]==role and h[6]==0 and h[10]==1
     key,state=state_for(role,0,h[10])
     assert state["waiting"] is None and h[2]==state["serial"]
     assert h[7]==last_input_lease+1;last_input_lease=h[7]
     raw=row["payload"];assert len(raw)==h[3]
     if role in begins:
      old=begins[role]
      assert old["first_seen"] and state["serial"]>old["serial"]
     if h[8]==0:
      check_external(role,raw,h[8])
     elif role in (6,8):
      assert pending_child is not None and pending_child["role"]==role
      assert (h[8],h[9])==(pending_child["action"],root_calls)
      assert not pending_child["begun"] and raw==pending_child["input"]
      pending_child["begun"]=True
     else:
      assert pending_ack is not None and role==7
      assert (h[8],h[9])==(root_actions,root_calls)
      assert raw==pending_ack
      pending_ack=None;parent_raw_acks+=1
     begins[role]=dict(serial=h[2],lease=h[7],call=h[9],action=h[8],
      input=raw,first_seen=False)
     log(dict(kind="actual-begin-source",offset=row["offset"],role=role,header=list(h),raw=cas.put(raw)))
     continue
    if kind==5:
     capsule(row);continue
    key,state=state_for(role,h[8],h[9])
    if kind==1:
     assert active_VM is None and state["waiting"] is None
     assert h[2]==state["serial"]+1 and h[6:8]==(0,0)
     src,pre_o,pre_w=row["input"],row["output"],row["workspace"]
     last=state["last"]
     if last is None:
      assert pre_w==bytes(len(pre_w))
      if role!=8:assert pre_o==bytes(len(pre_o))
     else:
      assert len(pre_w)>=len(last["workspace"])
      assert pre_w[:len(last["workspace"])]==last["workspace"]
      assert pre_w[len(last["workspace"]):]==bytes(len(pre_w)-len(last["workspace"]))
      if role!=8:
       assert len(pre_o)>=len(last["output"])
       assert pre_o[:len(last["output"])]==last["output"]
       assert pre_o[len(last["output"]):]==bytes(len(pre_o)-len(last["output"]))
      if last["returncode"]==2 and src==last["input"]:
       assert len(pre_w)>len(last["workspace"]) or len(pre_o)>len(last["output"])
       grows[role]+=1
     if state["ack"] is not None:
      assert src==state["ack"];state["ack"]=None
     if role in (6,7,8) and role in begins and not begins[role]["first_seen"]:
      assert src==begins[role]["input"];begins[role]["first_seen"]=True
      if role==8:
       assert pending_child is not None and pre_o==pending_child["second"]
     if role==9:check_root_before(src,state)
     number=sum(vm_counts.values())+1
     initial=dict(kind="before-VM",index=number,offset=row["offset"],role=role,
      context=h[8],generation=h[9],entry_serial=h[2],header=list(h),
      input=cas.put(src),pre_output=cas.put(pre_o),pre_workspace=cas.put(pre_w),
      limits=dict(steps=4000000,arena_bytes=32<<20,depth=64))
     log(initial);save(output/"frontier.json",initial)
     owners=[_Owner(-1,bytearray(src)),_Owner(-2,bytearray(pre_o)),_Owner(-3,bytearray(pre_w))]
     program=programs[role];document=program.as_dict()
     machine=_Machine(program,4000000,32<<20,None,64)
     returned=machine.invoke(document["functions"][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
     assert bytes(owners[0].data)==src
     if role==8:assert bytes(owners[1].data)==pre_o
     expected=dict(input=src,output=bytes(owners[1].data),workspace=bytes(owners[2].data),
      returncode=returned,serial=h[2],steps=machine.steps,pre_output=pre_o)
     state["waiting"]=expected;state["serial"]=h[2];active_VM=key;vm_counts[role]+=1
     log(dict(kind="after-VM",index=number,role=role,entry_serial=h[2],
      returned=returned,steps=machine.steps,expected_output=cas.put(expected["output"]),
      expected_workspace=cas.put(expected["workspace"])))
    elif kind==2:
     assert active_VM==key
     expected=state["waiting"];assert expected is not None
     assert h[2]==expected["serial"] and h[3]==len(expected["input"])
     assert h[6]==expected["returncode"] and h[7]==0
     assert row["output"]==expected["output"] and row["workspace"]==expected["workspace"]
     state["last"]=expected;state["waiting"]=None;active_VM=None;entries[role]+=1
     log(dict(kind="native-VM-full-equality",role=role,entry_serial=h[2],
      returned=h[6],actual_output=cas.put(row["output"]),actual_workspace=cas.put(row["workspace"]),
      all_bytes_equal=True,no_field_mask=True))
     if role==9:
      event=row["output"];work=row["workspace"]
      assert len(event)==256 and q(event,0)==ISSUER_EVENT and q(event,8)==h[6]
      if h[6]==1:
       assert pending_child is None and pending_ack is None
       assert q(event,64)==root_actions+1;root_actions+=1
       selected=q(event,80);assert selected in (6,8)
       first=span(work,q(event,88),q(event,96))
       second=span(work,q(event,104),q(event,112))
       assert q(event,120)==selected and q(event,128)==1
       existing=states.get((selected,0,1))
       assert q(event,136)==(0 if existing is None else existing["serial"])
       pending_child=dict(role=selected,action=root_actions,input=first,second=second,begun=False)
      elif h[6]==0:
       assert pending_child is None and pending_ack is None
       assert q(event,72)==5 and q(event,184)==512
       pending_ack=span(work,q(event,176),512)
      else:assert h[6] in (2,3,BAD)
    elif kind==3:
     assert active_VM is None and state["waiting"] is None and state["ack"] is None
     last=state["last"];assert last is not None and last["returncode"]==1 and h[2]==state["serial"]
     event=last["output"][:256];ack=row["ack"]
     if role==1:
      op=q(event,48);assert op in SYSCALLS and h[4]==SYSCALLS[op] and h[5]==op
      assert h[7]==q(event,40)>state["sysseq"]
      a=struct.unpack_from("<32Q",ack)
      assert a[0]==FS and a[1]==3 and a[2:7]==struct.unpack_from("<32Q",event)[2:7]
      assert a[7]==h[6] and a[12]==len(ack)-256 and a[13]==q(event,112)
      assert not any(a[8:12]) and not any(a[14:])
     else:
      assert role==3;op=q(event,64);assert op in (1,2,3,4)
      assert h[5]==op and h[4]=={1:9,2:0,3:11,4:0}[op] and h[7]==state["sysseq"]+1
      actual=h[6];error=(-actual)&MASK if actual>=MASK-4094 else 0
      values=[0]*32
      values[:8]=[MEM,3,*[q(event,at) for at in range(16,64,8)]]
      values[8:14]=[op,error,0 if error else actual,0,h[7],256]
      expected=struct.pack("<8Q",MEM_CHANNEL,2,op,0,512,h[7],0,0)+struct.pack("<32Q",*values)+event
      assert ack==expected
     state["sysseq"]=h[7];state["ack"]=ack
     key_op=str(role)+":"+str(op);primitive_counts[key_op]=primitive_counts.get(key_op,0)+1
     log(dict(kind="actual-primitive-ACK",offset=row["offset"],role=role,
      header=list(h),event=cas.put(event),ack=cas.put(ack)))
    elif kind==4:
     assert expected_fatal and h[6]==expected_fatal and h[7]==0
     fatals.append(dict(offset=row["offset"],header=list(h)))
    else:raise AssertionError(("unsupported trace",kind,role))
  assert active_VM is None
  assert all(s["waiting"] is None and s["ack"] is None for s in states.values())
  assert entries==vm_counts
  if expected_fatal:assert len(fatals)==1
  else:
   assert not fatals and pending_child is None and pending_ack is None
  incomplete=requests[transport_index:]
  assert all(r["transport_kind"]=="EXPLICIT_INVALID" for r in incomplete)
  assert len(incomplete)==int(bool(expected_fatal))
  # Every complete pipe response is the exact real output of its role.
  for r in requests[:transport_index]:
   if r["status"]!="COMPLETE":
    assert expected_fatal;continue
   raw=(directory/"requests"/str(r["index"])/"output.bin").read_bytes()
   assert (len(raw),sha(raw))==(r["output_bytes"],r["output_sha256"])
   role=6 if r["transport_kind"]==1 else 7
   # Retain full response for an independent whole-record reconstruction.
   cas.put(raw)
   assert q(raw,0)==(magic(b"HIANDJ01") if role==6 else PARENT)
  cas.readback();assert identity(trace)==before
  result=dict(status="PASS",native_entries=sum(entries.values()),VM_entries=sum(vm_counts.values()),
   entries_by_role={str(k):v for k,v in entries.items()},growth_by_role={str(k):v for k,v in grows.items()},
   primitive_ACKs=sum(primitive_counts.values()),primitive_counts=primitive_counts,
   capsule_records=capsule_count,actual_input_leases=last_input_lease,
   actual_issuer_calls=root_calls,actual_child_links=links,actual_native_parent_ACKs=parent_raw_acks,
   external_original_users_consumed=transport_index,fatal_records=fatals,trace=before,
   all_native_return_output_workspace_bytes_equal=True,no_field_mask=True,
   no_cached_VM_results=True,no_native_or_syscall_execution_in_replayer=True,
   private_issued_capsules_bound_to_actual_begin_and_completed_windows=True,
   ordinary_Store_closed=False,other_UnixOpen_peers_closed=False)
  save(output/"summary.json",result)
  return result
 except BaseException as error:
  failure=error
  try:save(output/"summary.json",dict(status="FAIL",error_class=type(error).__name__,error=str(error),
   native_entries=sum(entries.values()),VM_entries=sum(vm_counts.values()),entries_by_role=entries,
   trace=before,ordinary_Store_closed=False))
  except BaseException as secondary:error.add_note("replay failure summary: "+repr(secondary))
  raise
 finally:
  checks=[]
  for label,operation in (("trace_after",lambda:identity(trace)==before),("CAS_after",lambda:cas.readback() is None)):
   try:
    assert operation(),label
   except BaseException as error:
    checks.append(dict(label=label,error=repr(error)))
    if failure is not None:failure.add_note(label+": "+repr(error))
    else:failure=error
  try:save(output/"after-checks.json",dict(status="PASS" if not checks else "FAIL",errors=checks))
  except BaseException as error:
   if failure is None:failure=error
   else:failure.add_note("after receipt: "+repr(error))
  if failure is not None:raise failure
