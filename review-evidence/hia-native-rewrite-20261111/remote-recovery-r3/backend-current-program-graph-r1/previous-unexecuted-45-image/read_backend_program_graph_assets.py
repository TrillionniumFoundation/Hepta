"""Read the complete frozen P16 artifact and bind actual program/Graph assets.

No compiler, VM, HIA image or target executable is invoked by this reader.
The downloaded outer ZIP identity is upload metadata only. Every byte/mode of
the pinned inner archive and all 1,114 ledger members is independently checked.
"""
from __future__ import annotations
import argparse,ctypes,json,os,resource,signal,stat,sys,tarfile,time,traceback
from hashlib import sha1,sha256
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
ARCHIVE=(15487440,"8b6f1aeab15a5c6a6b029e2c5216cec61bb02f7711aeddbd1ff41bf8566ba95e")
LEDGER=(454632,"81155ccbc336b6eda69399ae17dea8ee33d5ec58009cf846b350c18d4ee2b142")
EXPECTED_MEMBERS=1114
EXPECTED_BYTES=124530461
MAP_GIT="35202c1c5961923b60f6100e07fa696e2c8f84a0"
RESULT_GIT="84d559b4eb8e02a943c3e2e59b2dda43f9919d35"
OLD_COMPILER="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
OLD_PROJECT="/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-program-fixed-r1/"
OLD_ROLES=set(range(1,29))|set(range(40,47))|{55,56,59,61,62,63}
NEW_DECODER_ROLES={31,32,33,58}
TEST_ONLY_WIRE_ROLES={29,30}
p=argparse.ArgumentParser()
for name in ("input","out","role-map","observation"):
 p.add_argument("--"+name,type=Path,required=True)
a=p.parse_args()
OUT=a.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
START=time.monotonic_ns()
START_SELF=resource.getrusage(resource.RUSAGE_SELF)
START_CHILD=resource.getrusage(resource.RUSAGE_CHILDREN)
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
def timeout(signum,frame):raise TimeoutError("P16 original asset reader 180 wall seconds")
signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
INPUTS={};COPIES={};EXTRACTED=[];STATUS="FAIL";FAILURE=None;ERRORS=[];ASSETS=None
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("w",encoding="utf-8",newline="\n") as f:json.dump(value,f,sort_keys=True,indent=2,ensure_ascii=True);f.write("\n")
def identity(path):
 path=Path(path);st=path.lstat()
 assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not path.is_symlink(),str(path)
 h=sha256();g=sha1(b"blob "+str(st.st_size).encode()+b"\0");n=0
 with path.open("rb") as f:
  while True:
   b=f.read(1<<18)
   if not b:break
   n+=len(b);h.update(b);g.update(b)
 assert n==st.st_size
 return dict(bytes=n,sha256=h.hexdigest(),gitsha=g.hexdigest(),mode=stat.S_IMODE(st.st_mode))
def track(path):
 path=Path(path).resolve();info=identity(path)
 if path in INPUTS:assert info==INPUTS[path]
 else:INPUTS[path]=info
 return info
def copy_original(path,target):
 before=track(path);target.parent.mkdir(parents=True,exist_ok=True)
 with Path(path).open("rb") as src,target.open("xb") as dst:
  while True:
   part=src.read(1<<18)
   if not part:break
   dst.write(part)
 target.chmod(before["mode"])
 assert identity(target)==before and identity(path)==before
 COPIES[target.resolve()]=before
 return target
def locate(name,expected):
 matches=[]
 for path in sorted(a.input.resolve().rglob(name)):
  info=identity(path)
  if (info["bytes"],info["sha256"])==expected:matches.append(path)
 assert len(matches)==1,(name,[str(x) for x in matches])
 return matches[0]
def safe(name):
 assert isinstance(name,str) and name and "\\" not in name and "\0" not in name
 q=PurePosixPath(name)
 assert not q.is_absolute() and all(part not in ("",".","..") for part in name.split("/"))
 assert q.as_posix()==name
 return q
def data(path,expected_git=None):
 info=track(path);raw=Path(path).read_bytes()
 assert len(raw)==info["bytes"] and sha256(raw).hexdigest()==info["sha256"]
 if expected_git is not None:assert info["gitsha"]==expected_git
 return raw
def pair(row,source_path,image_path,origin):
 source=track(source_path);image=track(image_path)
 assert (source["bytes"],source["sha256"])==(row["source_bytes"],row["source_sha256"])
 assert (image["bytes"],image["sha256"])==(row["image_bytes"],row["image_sha256"])
 result=dict(row,source_path=str(Path(source_path).resolve()),image_path=str(Path(image_path).resolve()),
   origin=origin,source_identity=source,image_identity=image)
 receipt=row.get("receipt")
 if receipt is not None:
  assert receipt["status"]=="returned" and receipt["abi_status"]==0
  assert receipt["artifact_sha256"]==receipt["image_sha256"]==OLD_COMPILER
  assert receipt["source_sha256"]==receipt["input_sha256"]==source["sha256"]
  assert receipt["input_bytes"]==source["bytes"]
  assert receipt["produced_sha256"]==image["sha256"]
  assert receipt["produced_bytes"]==receipt["core_u32"]==image["bytes"]
  assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
  assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
 return result
try:
 track(__file__)
 # Full originals are preserved before parsing any semantic JSON.
 archive=copy_original(locate("evidence.tar.xz",ARCHIVE),OUT/"originals/evidence.tar.xz")
 ledger=copy_original(locate("evidence-members.json",LEDGER),OUT/"originals/evidence-members.json")
 role_path=copy_original(a.role_map.resolve(),OUT/"originals/original-role-map.json")
 result_path=copy_original(a.observation.resolve(),OUT/"originals/follow42-original-result.json")
 assert INPUTS[a.role_map.resolve()]["gitsha"]==MAP_GIT
 assert INPUTS[a.observation.resolve()]["gitsha"]==RESULT_GIT
 save(OUT/"early-original-copies.json",{str(k):v for k,v in COPIES.items()})
 rows=json.loads(data(ledger))
 assert type(rows) is list and len(rows)==EXPECTED_MEMBERS
 expected={}
 for row in rows:
  name=row["name"];safe(name)
  assert name not in expected and type(row["bytes"]) is int and row["bytes"]>=0
  assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
  assert type(row["sha256"]) is str and len(row["sha256"])==64
  expected[name]=row
 assert sum(r["bytes"] for r in rows)==EXPECTED_BYTES
 extracted=OUT/"extracted";extracted.mkdir()
 seen=set();count=0;total=0
 with tarfile.open(archive,mode="r|xz") as tar:
  for item in tar:
   assert item.isfile() and not item.issym() and not item.islnk()
   name=item.name;safe(name)
   assert name not in seen and name in expected
   row=expected[name]
   assert item.size==row["bytes"] and stat.S_IMODE(item.mode)==row["mode"]
   target=extracted/name;target.parent.mkdir(parents=True,exist_ok=True)
   h=sha256();g=sha1(b"blob "+str(item.size).encode()+b"\0");n=0
   with tar.extractfile(item) as src,target.open("xb") as dst:
    while True:
     part=src.read(1<<18)
     if not part:break
     n+=len(part);h.update(part);g.update(part);dst.write(part)
   target.chmod(row["mode"])
   assert n==row["bytes"] and h.hexdigest()==row["sha256"]
   item_info=dict(bytes=n,sha256=h.hexdigest(),gitsha=g.hexdigest(),mode=row["mode"])
   assert identity(target)==item_info
   EXTRACTED.append(dict(name=name,path=str(target),**item_info))
   seen.add(name);count+=1;total+=n
   tar.members.clear()
 assert seen==set(expected) and count==EXPECTED_MEMBERS and total==EXPECTED_BYTES
 save(OUT/"complete-member-readback.json",EXTRACTED)
 by_digest={}
 for row in EXTRACTED:by_digest.setdefault((row["bytes"],row["sha256"]),[]).append(row)
 def frozen_file(old_path,n,h):
  if old_path.startswith(OLD_PROJECT):
   direct=extracted/"worker-program-fixed"/old_path[len(OLD_PROJECT):]
   if direct.is_file():
    info=identity(direct);assert (info["bytes"],info["sha256"])==(n,h);return direct
  matches=by_digest.get((n,h),[])
  assert matches,(old_path,n,h)
  names=[row for row in matches if Path(row["name"]).name==Path(old_path).name]
  selected=sorted(names or matches,key=lambda row:row["name"])[0]
  return Path(selected["path"])
 bundle_path=extracted/"worker-program-fixed/development/build-r1/bundle.json"
 bundle=json.loads(data(bundle_path))
 assert bundle["schema"]=="hia-worker-program-assembly-native-fixed-v1"
 assert bundle["status"]=="BUILT_ONLY" and bundle["fresh_compiles"]==6
 assert bundle["nonzero_images"]==41 and bundle["table_rows"]==63
 assert bundle["compiler_sha256"]==OLD_COMPILER and bundle["actual_native_packer_entries"]==1
 assert set(map(int,bundle["role_bindings"]))==OLD_ROLES
 assert set(bundle["unused_rows"])==set(range(1,64))-OLD_ROLES
 observation=json.loads(data(result_path,RESULT_GIT))
 assert observation["status"]=="PASS_INDEPENDENT_COMPONENT_SCOPE"
 assert observation["counts"]==dict(fresh_B3=6,compile_attempts=6,actual_HIA_ELF_packer_entries=1,
   cases=113,full_payload_comparisons=78,private_controls=35,actual_ELF_processes=83,actual_private_kernel_entries=38)
 observed_build=observation["original_panels"][0]["original_summary"]
 assert observed_build["actual_compiles"]==6 and observed_build["actual_packer_entries"]==1
 assert bundle["compiled"]==observed_build["compiled"]
 original_map=json.loads(data(role_path,MAP_GIT));assert set(original_map["components"])=={str(i) for i in range(1,64)}
 roles={}
 for role in sorted(OLD_ROLES):
  row=bundle["role_bindings"][str(role)]
  sp=frozen_file(row["source_path"],row["source_bytes"],row["source_sha256"])
  ip=frozen_file(row["image_path"],row["image_bytes"],row["image_sha256"])
  roles[str(role)]=pair(row,sp,ip,"EXACT_ACTUAL_P16_42_RETAINED_NO_NEW_QUALIFICATION")
  if role in set(range(1,29))|set(range(40,47))|{55}:
   old=original_map["components"][str(role)]
   assert all(row[key]==old[key] for key in("source_bytes","source_sha256","image_bytes","image_sha256"))
 for role in sorted(NEW_DECODER_ROLES):
  assert role not in OLD_ROLES
  row=original_map["components"][str(role)]
  assert row["compiler_sha256"]==OLD_COMPILER
  roles[str(role)]=pair(row,row["source_path"],row["image_path"],
    "EXACT_RETAINED_DECODER_SOURCE_IMAGE_NEW_P16_COMBINATION_NOT_QUALIFIED")
 assert set(map(int,roles))==OLD_ROLES|NEW_DECODER_ROLES and len(roles)==45
 test_wire={}
 for role in sorted(TEST_ONLY_WIRE_ROLES):
  row=original_map["components"][str(role)]
  test_wire[str(role)]=pair(row,row["source_path"],row["image_path"],
    "TEST_ONLY_NATIVE_WIRE_NOT_IN_PRODUCTION_TABLE")
 packer_rows=[r for r in bundle["compiled"] if r["label"]=="worker-program-ELF-packer"]
 assert len(packer_rows)==1
 row=packer_rows[0]
 packer=pair(row,frozen_file(row["source_path"],row["source_bytes"],row["source_sha256"]),
   frozen_file(row["image_path"],row["image_bytes"],row["image_sha256"]),
   "EXACT_ACTUAL_P16_42_NATIVE_PACKER_NO_NEW_COMPILATION")
 carrier=extracted/"worker-program-fixed/development/build-r1/carrier"
 prefix=carrier/"prefix.bin";layout=carrier/"layout.json";assembly=carrier/"worker_program_executor.S"
 layout_value=json.loads(data(layout));prefix_info=track(prefix);track(assembly)
 assert layout_value["prefix_bytes"]==prefix_info["bytes"] and layout_value["prefix_sha256"]==prefix_info["sha256"]
 assert layout_value["rows"]==63 and set(layout_value["nonzero_roles"])==OLD_ROLES
 assert len(layout_value["tables"])==1
 original_elf=frozen_file(bundle["executable_path"],bundle["executable_bytes"],bundle["executable_sha256"])
 ASSETS=dict(schema="hia-backend-program-Graph-retained-assets-v1",status="READBACK_ONLY",
  actual_original_archive=ARCHIVE,actual_original_ledger=LEDGER,
  original_members=count,original_member_bytes=total,roles=roles,test_only_wire=test_wire,
  retained_packer=packer,original_bundle=str(bundle_path),original_executable=str(original_elf),
  prefix_path=str(prefix),prefix_identity=prefix_info,layout_path=str(layout),
  assembly_path=str(assembly),original_actual_table_roles=sorted(OLD_ROLES),
  new_actual_table_roles=sorted(OLD_ROLES|NEW_DECODER_ROLES),root_to_replace=56,
  complete_inner_archive_and_members_read=True,outer_ZIP_body_independently_read=False,
  target_executions=0,old_cases_rerun=0,new_combination_qualified=False)
 save(OUT/"assets.json",ASSETS)
 STATUS="PASS"
except BaseException as exc:
 FAILURE=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
 traceback.print_exc()
finally:
 for kind,items in (("input",INPUTS.items()),("copy",COPIES.items())):
  for path,before in items:
   try:assert identity(path)==before,(kind,str(path))
   except BaseException as exc:ERRORS.append(dict(kind=kind,path=str(path),error=repr(exc)))
 for row in EXTRACTED:
  try:assert identity(row["path"])=={k:row[k] for k in("bytes","sha256","gitsha","mode")}
  except BaseException as exc:ERRORS.append(dict(kind="extracted",path=row["path"],error=repr(exc)))
 end=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
 cpu=(end.ru_utime+end.ru_stime-START_SELF.ru_utime-START_SELF.ru_stime+
      children.ru_utime+children.ru_stime-START_CHILD.ru_utime-START_CHILD.ru_stime)
 wall=(time.monotonic_ns()-START)/1e9
 if cpu>=90 or wall>=180:ERRORS.append(dict(kind="budget",cpu=cpu,wall=wall))
 if ERRORS:STATUS="FAIL"
 report=dict(schema="hia-backend-program-Graph-original-assets-readback-v1",status=STATUS,
   failure=FAILURE,after_check_errors=ERRORS,archive_members_read=len(EXTRACTED),
   original_member_bytes_read=sum(r["bytes"] for r in EXTRACTED),
   target_executions=0,compiler_executions=0,VM_entries=0,HIA_entries=0,
   original_P16_cases_rerun=0,old_success_counts_inherited_as_new=False,
   original_inputs={str(k):v for k,v in INPUTS.items()},
   actual_limits=dict(cpu=90,wall=180,address=1<<30,core=0),
   parent_plus_children_CPU_seconds=cpu,elapsed_seconds=wall,
   complete_inner_readback=STATUS=="PASS",outer_ZIP_body_independently_read=False,
   partial=STATUS!="PASS",whole_public_backend=False,installed=False)
 save(OUT/"summary.json",report)
 print("HIA_BACKEND_PREFIX_ASSET_ORIGINAL "+json.dumps(report,sort_keys=True),flush=True)
 final_self=resource.getrusage(resource.RUSAGE_SELF);final_child=resource.getrusage(resource.RUSAGE_CHILDREN)
 final_cpu=(final_self.ru_utime+final_self.ru_stime-START_SELF.ru_utime-START_SELF.ru_stime+
      final_child.ru_utime+final_child.ru_stime-START_CHILD.ru_utime-START_CHILD.ru_stime)
 final_wall=(time.monotonic_ns()-START)/1e9
 signal.setitimer(signal.ITIMER_REAL,0)
 if final_cpu>=90 or final_wall>=180:raise TimeoutError("P16 asset reader final resource gate")
if STATUS!="PASS":raise SystemExit(1)
