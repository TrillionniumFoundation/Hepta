"""Independently read the existing successful FOLLOW52a original42 archive.
No project import, compiler, VM, native image, ELF, syscall fixture or test rerun.
The original downloaded directory is immutable. ZIP identity is an Actions
declaration; this program reads and verifies the complete pinned inner archive.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import base64,collections,gzip,hashlib,json,os,resource,signal,stat,struct,tarfile,time,traceback
from pathlib import Path,PurePosixPath
SPEC_GIT="a5cd324a4ddc6b496734fe3bda4365fc8f1cb231"
SPEC_SHA="ded138adb535944e1cf80223a9196878c351b7e867ecb6c273b5bc4ad86d9155"
SPEC_BYTES=22404
MAGICS={int.from_bytes(v,"little"):i for i,v in enumerate(
 (b"",b"HIANFT03",b"HIASMT01",b"HIANMT01",b"HIANDT03",b"HIADBT01",b"HIADJT01")) if i}
LIMITS=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
 raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
 path.write_bytes(raw);assert path.read_bytes()==raw
 return raw
def pin(path):
 path=Path(path);before=path.lstat()
 assert stat.S_ISREG(before.st_mode) and not path.is_symlink(),str(path)
 h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(before.st_size).encode()+b"\0");n=0
 with path.open("rb") as stream:
  for block in iter(lambda:stream.read(1<<20),b""):n+=len(block);h.update(block);g.update(block)
 after=path.lstat()
 assert (before.st_dev,before.st_ino,before.st_size,before.st_mode,before.st_mtime_ns)==(
  after.st_dev,after.st_ino,after.st_size,after.st_mode,after.st_mtime_ns)
 assert n==before.st_size
 return dict(bytes=n,mode=stat.S_IMODE(before.st_mode),sha256=h.hexdigest(),git_blob_sha1=g.hexdigest())
def same_pin(actual,expected):
 for key in ("bytes","mode","sha256","git_blob_sha1"):
  if key in expected:assert actual[key]==expected[key],(key,actual,expected)
def copy_exact(source,target,expected=None):
 source=Path(source);target=Path(target);before=pin(source)
 if expected is not None:same_pin(before,expected)
 target.parent.mkdir(parents=True,exist_ok=True)
 with source.open("rb") as src,target.open("xb") as dst:
  for block in iter(lambda:src.read(1<<20),b""):dst.write(block)
 target.chmod(before["mode"])
 assert pin(source)==pin(target)==before
 return before
def locate(root,name,n,digest):
 matches=[]
 for directory,dirs,names in os.walk(root,followlinks=False):
  for item in dirs:assert not (Path(directory)/item).is_symlink()
  if name in names:
   path=Path(directory)/name;got=pin(path)
   if (got["bytes"],got["sha256"])==(n,digest):matches.append((path,got))
 assert len(matches)==1,(name,len(matches))
 return matches[0]
def extract_exact(archive,index,out,spec):
 rows=json.loads(index.read_bytes())
 assert type(rows) is list and len(rows)==spec["members"]
 expected={}
 for row in rows:
  p=PurePosixPath(row["name"])
  assert not p.is_absolute() and p.parts and all(x not in ("",".","..") for x in p.parts)
  assert p.as_posix()==row["name"] and "\\" not in row["name"] and row["name"] not in expected
  assert type(row["bytes"]) is int and row["bytes"]>=0
  assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
  assert type(row["path"]) is str and Path(row["path"]).is_absolute()
  expected[row["name"]]=row
 assert sum(r["bytes"] for r in rows)==spec["raw_bytes"]
 seen=set();checked=[]
 with tarfile.open(archive,"r|xz") as tf:
  for member in tf:
   assert member.isfile() and member.name in expected and member.name not in seen
   row=expected[member.name]
   assert (member.size,member.mode)==(row["bytes"],row["mode"])
   assert member.uid==member.gid==member.mtime==0 and member.uname==member.gname==""
   target=out/member.name;target.parent.mkdir(parents=True,exist_ok=True)
   h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(member.size).encode()+b"\0");n=0
   source=tf.extractfile(member);assert source is not None
   with source,target.open("xb") as dest:
    for block in iter(lambda:source.read(1<<20),b""):
     n+=len(block);h.update(block);g.update(block);dest.write(block)
   target.chmod(member.mode)
   assert (n,h.hexdigest())==(row["bytes"],row["sha256"])
   got=pin(target)
   assert got==dict(bytes=n,mode=member.mode,sha256=h.hexdigest(),git_blob_sha1=g.hexdigest())
   checked.append(dict(name=member.name,original_path=row["path"],**got));seen.add(member.name)
 assert seen==set(expected)
 return checked
def exact_raw(path,expected=None):
 raw=Path(path).read_bytes()
 if expected is not None:same_pin(pin(path),expected)
 return raw
def equal_ranges(a,apos,b,bpos,n):
 a.seek(apos);b.seek(bpos);remaining=n
 while remaining:
  amount=min(remaining,1<<20);x=a.read(amount);y=b.read(amount)
  assert len(x)==len(y)==amount and x==y
  remaining-=amount
def equal_buffer(stream,part,raw):
 assert len(raw)==part["bytes"]
 stream.seek(part["offset"]);pos=0
 while pos<len(raw):
  amount=min(len(raw)-pos,1<<20);block=stream.read(amount)
  assert len(block)==amount and block==raw[pos:pos+amount]
  pos+=amount
 assert sha(raw)==part["sha256"]
def trace_index(path):
 before=pin(path);records=[];by_offset={};waiting={};serials={};counts=collections.Counter();offset=0
 with Path(path).open("rb") as stream:
  while offset<before["bytes"]:
   raw=stream.read(96);assert len(raw)==96
   h=struct.unpack("<12Q",raw);role=MAGICS.get(h[0]);kind=h[1]
   assert role is not None and kind in (1,2,3,4) and h[10]==role and h[11]==0
   assert h[9]>0
   sizes=([h[3],h[4],h[5]] if kind==1 else [h[4],h[5]] if kind==2 else [h[3]] if kind==3 else [])
   assert sum(sizes)<=before["bytes"]-offset-96
   parts=[];cursor=offset+96;digest=hashlib.sha256(raw)
   for size in sizes:
    ph=hashlib.sha256();remaining=size
    while remaining:
     block=stream.read(min(remaining,1<<20));assert block
     remaining-=len(block);ph.update(block);digest.update(block)
    parts.append(dict(offset=cursor,bytes=size,sha256=ph.hexdigest()));cursor+=size
   row=dict(offset=offset,bytes=cursor-offset,sha256=digest.hexdigest(),role=role,kind=kind,
    header=list(h),parts=parts)
   key=(role,h[8],h[9],h[2]);ctx=(role,h[8],h[9])
   if kind==1:
    assert key not in waiting and h[6:8]==(0,0)
    assert h[2]==serials.get(ctx,0)+1
    serials[ctx]=h[2];waiting[key]=row
   elif kind==2:
    assert key in waiting and h[7]==0
    pre=waiting.pop(key)
    assert h[3:6]==tuple(pre["header"][3:6])
    pre["post_offset"]=offset;row["pre_offset"]=pre["offset"]
   elif kind==3:
    assert role in (1,3)
   else:
    assert h[3:6]==(0,0,0) and h[7]==0
   records.append(row);by_offset[offset]=row;counts[(role,kind)]+=1;offset=cursor
 assert offset==before["bytes"] and not waiting
 assert pin(path)==before
 return dict(source=before,records=records,by_offset=by_offset,counts=counts)
def read_ledger(path,trace,index,roles,expected_pin):
 before=pin(path);same_pin(before,expected_pin)
 expected={x["offset"] for x in index["records"] if x["kind"]==1 and x["role"] in roles}
 seen=set();counts=collections.Counter();raw_hash=hashlib.sha256();raw_bytes=0;first=None;last=None
 with gzip.open(path,"rb") as ledger,Path(trace).open("rb") as actual:
  for line_number,line in enumerate(ledger,1):
   assert line.endswith(b"\n") and line.strip()
   raw_hash.update(line);raw_bytes+=len(line);r=json.loads(line)
   offset=r.get("original_offset",r.get("trace_offset"))
   assert type(offset) is int and offset in expected and offset not in seen
   pre=index["by_offset"][offset];post=index["by_offset"].get(pre.get("post_offset"))
   assert post is not None and post["kind"]==2
   h=pre["header"]
   assert (r["role"],r["node"],r["context"],r["serial"])==(pre["role"],h[8],h[9],h[2])
   assert r["vm_step_budget"]==4000000 and r["expected_return"]==post["header"][6]
   fields=(("input_hex",pre["parts"][0]),("pre_output_hex",pre["parts"][1]),
    ("pre_workspace_hex",pre["parts"][2]),("expected_output_hex",post["parts"][0]),
    ("expected_workspace_hex",post["parts"][1]))
   for key,part in fields:
    value=r[key];assert type(value) is str
    raw=bytes.fromhex(value);assert raw.hex()==value.lower()
    equal_buffer(actual,part,raw)
   item=dict(line=line_number,offset=offset,role=pre["role"],serial=h[2],
    bytes=len(line),sha256=sha(line),actual_original_full_buffers_equal=True)
   if first is None:first=item
   last=item;seen.add(offset);counts[pre["role"]]+=1
 assert seen==expected and pin(path)==before
 return dict(original_compressed_pin=before,complete_records=len(seen),
  complete_uncompressed_bytes=raw_bytes,complete_uncompressed_sha256=raw_hash.hexdigest(),
  counts={str(k):v for k,v in sorted(counts.items())},first=first,last=last,
  all_complete_native_pre_post_buffers_and_return_equal=True,gzip_eof_and_crc_checked=True)
def validate_partition(directory,outer):
 inner_path=directory/"four-role-original-partition/trace.bin"
 inner=trace_index(inner_path);parts=json.loads((directory/"original-trace-partition.json").read_bytes())
 assert len(parts)==len(outer["records"])
 inner_offset=0
 with (directory/"trace.bin").open("rb") as a,inner_path.open("rb") as b:
  for part,row in zip(parts,outer["records"]):
   assert (part["source_offset"],part["bytes"],part["sha256"],part["role"],part["kind"])==(
    row["offset"],row["bytes"],row["sha256"],row["role"],row["kind"])
   if row["role"]<=4:
    assert part["partition"]=="unchanged-four-role" and part["target_offset"]==inner_offset
    i=inner["by_offset"][inner_offset]
    assert (i["bytes"],i["sha256"],i["header"])==(row["bytes"],row["sha256"],row["header"])
    equal_ranges(a,row["offset"],b,inner_offset,row["bytes"]);inner_offset+=row["bytes"]
   else:
    assert part["partition"]=="outer-db" and "target_offset" not in part
 assert inner_offset==inner["source"]["bytes"]
 return inner
def member_for_original(checked,members,original,expected=None):
 found=[r for r in checked if r["original_path"]==original]
 assert len(found)==1,(original,len(found))
 row=found[0];path=members/row["name"]
 if expected is not None:same_pin(pin(path),expected)
 return path,row
def captured_pin_rows(rows,checked):
 signatures=collections.defaultdict(list)
 for r in checked:signatures[(r["bytes"],r["sha256"],r["mode"])].append(r["name"])
 result=[]
 for original,expected in rows.items():
  assert type(expected) is dict and "error" not in expected and "error_class" not in expected
  key=(expected["bytes"],expected["sha256"],expected["mode"])
  matches=signatures.get(key,[])
  assert matches,("original source capture absent",original,expected)
  result.append(dict(original_path=original,pin=expected,byte_identical_archive_members=matches))
 return result
def profile(document):
 f=document["functions"];assert f
 return dict(functions=len(f),blocks=sum(len(x["blocks"]) for x in f),
  max_blocks=max(len(x["blocks"]) for x in f),
  ops=sum(len(b["ops"]) for x in f for b in x["blocks"]),
  max_block_params=max(len(b["params"]) for x in f for b in x["blocks"]))
def compile_binding(receipt,source,image,spec):
 assert receipt["source_sha256"]==receipt["input_sha256"]==sha(source)
 assert receipt["input_bytes"]==len(source)
 assert receipt["artifact_sha256"]==receipt["image_sha256"]==spec["compiler"]["sha256"]
 assert receipt["produced_sha256"]==sha(image) and receipt["produced_bytes"]==len(image)
 assert 0<len(image)<=1<<20
 assert receipt["status"]=="returned" and receipt["abi_status"]==0
 assert receipt["result_u64"]==receipt["core_u32"]==receipt["produced_bytes"]
 assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
 assert receipt["limits"]["output_capacity"]==receipt["limits"]["workspace_bytes"]==1<<20
 assert 0<=receipt["wall_elapsed_ns"]<20_000_000_000
 child=next(x for x in spec["reference_compile_control_sources"] if x["path"]=="tools/hia_selfhost_child.py")
 assert receipt["runner_sha256"]==child["sha256"]
 assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
 return dict(source_bytes=len(source),source_sha256=sha(source),image_bytes=len(image),
  image_sha256=sha(image),receipt=receipt)
def original_exports(members,payload,names):
 exports=[]
 for name in names:
  path=members/name
  if not path.exists():continue
  target=payload/"exports"/name
  before=pin(path);copy_exact(path,target,before)
  exports.append(dict(name=name,pin=before,path=target.relative_to(payload).as_posix()))
 return exports

def verify_reports(spec,members,checked,payload):
 base=members/spec["base"];build_dir=base/"db-join-build-r1";physical_dir=base/"db-join-native-r1"
 root=json.loads((members/"run/summary.json").read_bytes())
 details=json.loads((base/"summary.json").read_bytes())
 assert root["schema"]=="hia-independent-ci-qualification-v1"
 assert root["scope"]=="NAMESPACE_ORIGINAL42_EXACT_BYTE_HELPERS" and root["status"]=="PASS"
 assert root["details"]==details and details["status"]=="PASS"
 assert root["prepared"] and root["frozen_source_and_reference_before_after_equal"]
 assert root["submitted_script_pins_before_after_equal"]
 assert not root["whole_stack_closed"] and not root["production_activated"] and not root["inherited_test_counts"]
 assert details["inputs_unchanged"] and details["working_source_unchanged"]
 assert details["execution_counts"]==spec["expected_counts"]
 phase=details["original42_phase"]
 assert phase["source_after_checks_finished"] and phase["within_original900"]
 assert 0<=phase["elapsed_ns"]<900_000_000_000
 assert phase["deadline_monotonic_ns"]==phase["started_monotonic_ns"]+900_000_000_000
 steps={r["label"]:r for r in root["steps"]}
 assert len(steps)==len(root["steps"]) and all(r["status"]=="PASS" and r["returncode"]==0 and not r["timed_out"] for r in steps.values())
 physical_step=steps["six-role-actual-physical-and-complete-original-trace-replay"]
 assert physical_step["elapsed_ns"]==spec["expected_physical_process_elapsed_ns"]
 assert physical_step["timeout_seconds"]==900
 assert 0<=physical_step["elapsed_ns"]<phase["elapsed_ns"]<900_000_000_000
 assert details["physical_process"]==physical_step
 for name in ("six-role-fresh-B3-and-actual-HIA-packer","six-role-packer-old-VM-new-VM-new-native-complete-differential"):
  p=steps[name];assert p["timeout_seconds"]==180 and 0<=p["child_cpu_seconds"]<90 and 0<=p["elapsed_ns"]<180_000_000_000
 for name in ("DMS9-exact-header-proof-transfer-source-controls","original42-six-authors-only-three-byte-helpers-source-proof"):
  p=steps[name];assert p["timeout_seconds"]==30 and 0<=p["child_cpu_seconds"]<10
 source_custody=[]
 for row in [spec["driver"],*spec["sources"]]:
  path=base/"source"/row["name"];got=pin(path)
  assert (got["bytes"],got["sha256"],got["git_blob_sha1"])==(row["bytes"],row["sha256"],row["blob"])
  source_custody.append(dict(name=row["name"],member=path.relative_to(members).as_posix(),**got))
 compiler=base/"compiler/B3.image.bin";same_pin(pin(compiler),spec["compiler"])
 reports={}
 for name,expected in spec["reports"].items():
  path=members/name;same_pin(pin(path),expected);reports[name]=json.loads(path.read_bytes())
 build=reports[spec["base"]+"/db-join-build-r1/summary.json"]
 physical=reports[spec["base"]+"/db-join-native-r1/summary.json"]
 packer=reports[spec["base"]+"/packer-differential-r1/summary.json"]
 assert details["build_original_report"]==details["build"]==build
 assert details["physical_original_report"]==details["physical"]==physical
 assert details["packer_differential_original_report"]==details["packer_differential"]==packer
 assert build["status"]=="PASS_BUILD_ONLY" and build["fresh_role_compiles"]==6
 assert set(build["exact_roles"])==set(build["generated_roles"])==set(build["compiled_roles"])==set(map(str,range(1,7)))
 assert build["source_pins_unchanged"] and build["source_before"]==build["source_after"]
 build_sources=captured_pin_rows(build["source_before"],checked)
 for control in spec["reference_compile_control_sources"]:
  original=[r for path,r in build["source_before"].items() if path.endswith("/"+control["path"])]
  assert len(original)==1 and (original[0]["bytes"],original[0]["sha256"],original[0]["mode"])==(control["bytes"],control["sha256"],0o644)
  captures=[r for r in checked if (r["bytes"],r["sha256"],r["mode"])==(control["bytes"],control["sha256"],0o644)]
  assert captures and all(r["git_blob_sha1"]==control["blob"] for r in captures)
 assert build["actual_process_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
 assert build["process_limits"]["wall_seconds"]==180
 canonical=[];images={};receipts=[];profiles={}
 def canonical_copy(name,original,expected=None):
  p,row=member_for_original(checked,members,original,expected)
  target=payload/"canonical"/name;copy_exact(p,target,pin(p))
  got=dict(name=name,original_member=row["name"],original_path=original,
   retained_path=target.relative_to(payload).as_posix(),**pin(target))
  canonical.append(got);return p.read_bytes(),got
 for role in map(str,range(1,7)):
  r=build["exact_roles"][role];assert build["compiled_roles"][role]==r
  source,sp=canonical_copy("role-"+role+".hiaasm",r["source"]["path"],r["source"])
  image,ip=canonical_copy("role-"+role+".image.bin",r["image"]["path"],r["image"])
  assert r["compile_receipt"]["produced_image"]==r["image"]["path"]
  receipts.append(dict(role=role,**compile_binding(r["compile_receipt"],source,image,spec)))
  images[role]=image
  front=build["profile_frontiers"]["role-"+role]
  document_path,_=member_for_original(checked,members,front["document"]["path"],front["document"])
  document=json.loads(document_path.read_bytes());got=profile(document)
  assert got==front["profile"]==r["profile"]==build["generated_roles"][role]["profile"]
  assert front["author_source_sha256"]==r["author_source_sha256"]==build["generated_roles"][role]["author_source_sha256"]
  assert front["original_profile_limits"]==dict(functions=128,blocks=1536,ops=8192,max_blocks=256,max_block_params=16)
  assert all(got[k]<=front["original_profile_limits"][k] for k in got)
  profiles["role-"+role]=got
 pack_source_path=build_dir/"packer.hiaasm";pack_source=pack_source_path.read_bytes()
 copy_exact(pack_source_path,payload/"canonical/packer.hiaasm",pin(pack_source_path))
 canonical.append(dict(name="packer.hiaasm",original_member=pack_source_path.relative_to(members).as_posix(),
  retained_path="canonical/packer.hiaasm",**pin(pack_source_path)))
 pack_receipt=build["compile_receipt"]
 pack_image,pack_ip=canonical_copy("packer.image.bin",pack_receipt["produced_image"],
  dict(bytes=pack_receipt["produced_bytes"],sha256=pack_receipt["produced_sha256"]))
 assert build["packer_image_sha256"]==sha(pack_image)
 receipts.append(dict(role="packer",**compile_binding(pack_receipt,pack_source,pack_image,spec)))
 front=build["profile_frontiers"]["packer"]
 document_path,_=member_for_original(checked,members,front["document"]["path"],front["document"])
 got=profile(json.loads(document_path.read_bytes()));assert got==front["profile"]==build["profile"]
 assert front["original_profile_limits"]==dict(functions=128,blocks=1536,ops=8192,max_blocks=256,max_block_params=16)
 assert all(got[k]<=front["original_profile_limits"][k] for k in got);profiles["packer"]=got
 executable,ep=canonical_copy("hia-namespace-db-join",build["executable"]["path"],build["executable"])
 assert ep["mode"]==0o755 and executable[:4]==b"\x7fELF"
 # Bind every archived image byte to the actual fixed ELF; do not regenerate a packer.
 template=build_dir/"executor.bin";template_raw=template.read_bytes()
 assert len(template_raw)==build["executable"]["template_bytes"]
 controls=build["packer_controls"];assert build["packer_entries"]==len(controls)==33
 assert len({r["label"] for r in controls})==33
 for row in controls:
  c=build_dir/"packer-controls"/row["label"];saved=json.loads((c/"result.json").read_bytes())
  assert saved==row and row["actual_return"]==row["expected_return"]
  assert row["guards"] and row["source_unchanged"] and row["workspace_unchanged"] and row["exact_output_equal"]
  assert sha((c/"input.bin").read_bytes())==row["input_sha256"]
  out=(c/"output.bin").read_bytes();assert (len(out),sha(out))==(row["output_bytes"],row["output_sha256"])
 assert executable==(build_dir/"packer-controls/normal/output.bin").read_bytes()
 for role in map(str,range(1,7)):
  at=build["executable"]["image_offsets"][role];n=build["executable"]["image_bytes"][role]
  assert n==len(images[role]) and executable[at:at+n]==images[role]
 # Packer source is retained verbatim; no packer or HIA code is interpreted here.
 assert packer["status"]=="PASS" and packer["cases"]==84
 assert packer["counts"]==dict(old_VM=84,new_VM=84,new_native=84)
 assert packer["source_before_after_equal"] and packer["no_masks"] and packer["complete_buffers_equal"]
 assert packer["old_profile_not_relaxed"] and packer["mapping_cleanup_error"] is None
 assert packer["old_native_compiles"]==packer["new_B3_compiles_in_this_process"]==packer["actual_physical_syscalls"]==0
 assert packer["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
 assert packer["limits"]==dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0,VM_steps=4000000,VM_arena_bytes=32<<20)
 pack_rows={r["name"]:r for r in packer["results"]};assert len(pack_rows)==len(packer["results"])==84
 observed_pack=[];pdir=base/"packer-differential-r1"
 with gzip.open(pdir/"complete-invocations.jsonl.gz","rb") as stream:
  for line in stream:
   assert line.endswith(b"\n");r=json.loads(line);assert r["name"] in pack_rows and r["name"] not in observed_pack
   assert r["equal"];orig=bytes.fromhex(r["workspace_before_hex"])
   values=[]
   for k in ("old_VM","new_VM","new_native"):
    t=r[k];o=bytes.fromhex(t["output_hex"]);w=bytes.fromhex(t["workspace_hex"])
    assert w==orig;values.append((t["result"],o,w))
   assert values[0]==values[1]==values[2]
   n=r["new_native"];assert n["canaries"] and n["readonly_source_unchanged"]
   s=pack_rows[r["name"]];assert s["result"]==values[2][0] and s["three_way_equal"] and s["workspace_unchanged"]
   assert (s["output_bytes"],s["output_sha256"])==(len(values[2][1]),sha(values[2][1]))
   observed_pack.append(r["name"])
 assert len(observed_pack)==84
 proof=json.loads((base/"dms9-header-source-proof/summary.json").read_bytes())
 exact=json.loads((base/"exact-byte-source-proof/summary.json").read_bytes())
 assert proof==details["DMS9_exact_header_proof_transfer"] and exact==details["exact_byte_source_proof"]
 assert proof["status"]=="PASS_SOURCE_PROOF_ONLY" and len(proof["controls"])==10 and proof["source_unchanged"]
 assert exact["status"]=="PASS_SOURCE_PROOF_ONLY" and exact["source_unchanged"]
 assert exact["original_ten_DMS9_proof_complete_before_transform"]
 assert len(exact["roles"])==6 and len(exact["negative_source_controls"])==8
 for r in exact["roles"]:
  assert r["changed_helper_names"]==["read64","get","put"]
  assert all(r[k] for k in ("all_other_HIA_functions_exact","exact_source_inverse","source_program_function_unmodified","function_names_order_and_signatures_exact","total_scalar_classification_exact"))
 assert all(r["refused"] for r in exact["negative_source_controls"])
 assert physical["status"]=="PASS" and physical["source_pins_unchanged"]
 assert physical["source_before"]==physical["source_after"]
 physical_sources=captured_pin_rows(physical["source_before"],checked)
 tests=physical["tests"];assert tests["test_ids"]==spec["expected_test_ids"]
 assert tests["tests_loaded"]==tests["tests_run"]==len(set(tests["test_ids"]))==42
 assert not any(tests[k] for k in ("errors","failures","skipped","expected_failures","unexpected_successes"))
 assert physical["native_entries"]==physical["vm_entries"]==5011 and physical["process_traces"]==60
 assert physical["entries_by_role"]==spec["expected_counts"]["entries_by_role"]
 assert physical["all_actual_trace_processes_fully_replayed"]
 assert physical["abort_cleanup_pure_control_count"]==len(physical["abort_cleanup_pure_controls"])==3
 assert physical["vm_steps_per_original_entry"]==4000000 and physical["vm_arena_bytes"]==32<<20
 assert not any(physical[k] for k in ("ordinary_store_closed","full_sql31_closed","root_policy_closed",
  "unixOpen_and_findReusableFd_closed","migration_closed","python_router_used","counts_inherited","legacy_sqlite3461_claimed"))
 result=dict(original42_phase=phase,original_steps=root["steps"],counts=spec["expected_counts"],
  canonical_inputs=canonical,compile_receipts=receipts,profiles=profiles,source_inputs=source_custody,
  captured_build_sources=build_sources,captured_physical_sources=physical_sources,
  exact_84_recorded_old_VM_new_VM_native_buffers_equal=True,sqlite=physical["sqlite"],
  original_scope=physical["scope"],whole_Store_closed=False)
 save(payload/"canonical-source-image-index.json",dict(canonical_inputs=canonical,compile_receipts=receipts,profiles=profiles))
 return result,physical,physical_dir
def verify_physical_traces(physical,physical_dir,checked,members,payload):
 rows=physical["process_limit_readbacks"];assert len(rows)==len(physical["replay"])==60
 seen=set();totals=collections.Counter();ack_count=0;db_retire=0;inner_retire=0;reports=[]
 for limit_row,expected_replay in zip(rows,physical["replay"]):
  process_path,m=member_for_original(checked,members,limit_row["path"],dict(sha256=limit_row["sha256"]))
  directory=process_path.parent;assert directory.is_relative_to(physical_dir) and directory not in seen
  seen.add(directory);process=json.loads(process_path.read_bytes())
  assert process["limits"]==physical["native_limits"]==limit_row["limits"]
  assert process["limits"]["cpu_seconds"]==90 and process["limits"]["wall_seconds"]==180
  assert process["limits"]["address_bytes"]==1<<30 and process["limits"]["core_bytes"]==0
  assert process["actual_native_identity"]["actual_limits"]==limit_row["actual"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
  assert process["actual_native_identity"]["pid"]==limit_row["native_pid"]
  assert process["wait_status"]==limit_row["wait_status"] and process["returncode"]==limit_row["returncode"]==0
  assert os.WIFEXITED(process["wait_status"]) and os.WEXITSTATUS(process["wait_status"])==0
  assert not process["wall_kill_sent"] and not process["wall_watchdog_fired"] and process["watchdog_error"] is None
  assert process["source_unchanged"] and process["unframed_stdout_bytes"]==0
  assert 0<=process["elapsed_ns"]<180_000_000_000
  cpu=process["usage"]["user"]+process["usage"]["system"];assert 0<=cpu<90
  replay=json.loads((directory/"six-role-replay.json").read_bytes());assert replay==expected_replay
  assert replay["status"]=="PASS" and replay["no_masks"] and replay["no_inherited_counts"]
  assert replay["all_original_records_partitioned_exactly_once"] and replay["all_input_output_workspace_return_bytes_equal"]
  assert replay["no_OS_primitive_executed_by_replayer"] and not replay["fatal_records"]
  outer=trace_index(directory/"trace.bin")
  assert replay["original_trace_before"]==replay["original_trace_after"]==dict(bytes=outer["source"]["bytes"],sha256=outer["source"]["sha256"])
  assert (process["trace_bytes"],process["trace_sha256"])==(outer["source"]["bytes"],outer["source"]["sha256"])
  inner=validate_partition(directory,outer)
  inner_dir=directory/"four-role-original-partition"
  inner_summary=json.loads((inner_dir/"four-role-replay.json").read_bytes())
  assert inner_summary==replay["unchanged_inner_replayer"] and inner_summary["status"]=="PASS"
  outer_ledger=read_ledger(directory/"outer-db-full-vm-replay.jsonl.gz",directory/"trace.bin",outer,{5,6},replay["outer_DB_ledger"])
  inner_ledger=read_ledger(inner_dir/"four-role-vm-replay.jsonl.gz",inner_dir/"trace.bin",inner,{1,2,3,4},
   dict(bytes=inner_summary["ledger_bytes"],sha256=inner_summary["ledger_sha256"]))
  actual={str(r):outer["counts"][(r,1)] for r in range(1,7)}
  assert actual==replay["entries_by_role"]
  assert sum(actual.values())==replay["native_entries"]==replay["vm_entries"]==outer_ledger["complete_records"]+inner_ledger["complete_records"]
  assert inner_summary["native_entries"]==inner_summary["vm_entries"]==inner_ledger["complete_records"]
  assert inner_summary["all_return_output_workspace_bytes_equal"] and inner_summary["no_field_masks"]
  assert inner_summary["all_child_replies_bound_to_actual_original_source_output_workspace"]
  assert not inner_summary["fatal_records"]
  acks=sum(outer["counts"][(r,3)] for r in (1,3))
  assert acks==inner_summary["actual_primitive_acks"]
  totals.update({int(k):v for k,v in actual.items()});ack_count+=acks
  db_retire+=len(replay["actual_DB_context_retirements"]);inner_retire+=len(inner_summary["exact_retirements"])
  reports.append(dict(directory=directory.relative_to(members).as_posix(),native_entries=sum(actual.values()),
   entries_by_role=actual,primitive_acks=acks,process=process,outer_ledger=outer_ledger,inner_ledger=inner_ledger,
   original_trace=outer["source"],original_partition_records=len(outer["records"]),
   DB_retirements=len(replay["actual_DB_context_retirements"]),inner_retirements=len(inner_summary["exact_retirements"])))
 expected_dirs={p.parent for p in physical_dir.glob("test_*/native-*/process.json")}
 assert seen==expected_dirs and len(seen)==60
 assert {str(k):v for k,v in sorted(totals.items())}==physical["entries_by_role"]
 assert sum(totals.values())==5011 and ack_count==physical["actual_primitive_acks"]==503
 assert db_retire==physical["actual_DB_retirements"]==39 and inner_retire==physical["actual_inner_retirements"]==2
 save(payload/"complete-recorded-trace-readback.json",dict(processes=reports,total_entries=sum(totals.values()),
  entries_by_role={str(k):v for k,v in sorted(totals.items())},primitive_acks=ack_count,
  DB_retirements=db_retire,inner_retirements=inner_retire,
  all_60_original_traces_partition_and_all_5011_recorded_VM_buffers_byte_equal=True,
  no_HIA_VM_native_execution=True))
 return dict(actual_fixed_processes=60,native_entries=5011,recorded_VM_entries=5011,primitive_ACKs=ack_count,
  DB_retirements=db_retire,inner_retirements=inner_retire,entries_by_role={str(k):v for k,v in sorted(totals.items())})

def emit_originals(payload,exports):
 budget=850000;used=0;emitted=[];omitted=[]
 for row in exports:
  raw=(payload/row["path"]).read_bytes();same_pin(pin(payload/row["path"]),row["pin"])
  compressed=gzip.compress(raw,compresslevel=6,mtime=0)
  chunks=[base64.b64encode(compressed[i:i+49152]).decode("ascii") for i in range(0,len(compressed),49152)]
  begin=dict(name=row["name"],raw=row["pin"],gzip_bytes=len(compressed),gzip_sha256=sha(compressed),
   chunks=len(chunks),encoding="base64(gzip(full unchanged original bytes))")
  lines=["HIA_NAMESPACE52_RAW_BEGIN "+json.dumps(begin,sort_keys=True,separators=(",",":"))]
  lines += ["HIA_NAMESPACE52_RAW_CHUNK "+json.dumps(dict(name=row["name"],index=i,data=data),sort_keys=True,separators=(",",":")) for i,data in enumerate(chunks)]
  lines += ["HIA_NAMESPACE52_RAW_END "+json.dumps(dict(name=row["name"],chunks=len(chunks),raw_sha256=row["pin"]["sha256"]),sort_keys=True,separators=(",",":"))]
  needed=sum(len(x.encode())+1 for x in lines)
  if used+needed>budget:
   omitted.append(dict(name=row["name"],pin=row["pin"],complete_original_saved_in_artifact=True,
    reason="Entire original export omitted from console to keep bounded output; never truncated"))
   continue
  for line in lines:print(line,flush=True)
  used+=needed;emitted.append(begin)
 result=dict(console_bytes=used,console_budget=budget,emitted=emitted,omitted=omitted,
  original_bytes_never_reserialized=True)
 save(payload/"console-original-export-index.json",result)
 return result
def seal_payload(out):
 payload=out/"payload";rows=[]
 for directory,dirs,names in os.walk(payload,followlinks=False):
  for d in dirs:assert not (Path(directory)/d).is_symlink()
  for name in names:
   p=Path(directory)/name;rows.append(dict(name=p.relative_to(payload).as_posix(),**pin(p)))
 rows.sort(key=lambda x:x["name"]);save(out/"readback-members.json",rows)
 archive=out/"readback-evidence.tar.gz"
 with archive.open("xb") as target,gzip.GzipFile(filename="",fileobj=target,mode="wb",mtime=0,compresslevel=1) as gz,tarfile.open(fileobj=gz,mode="w|") as tf:
  for row in rows:
   p=payload/row["name"];same_pin(pin(p),row)
   info=tarfile.TarInfo(row["name"]);info.size=row["bytes"];info.mode=row["mode"]
   info.uid=info.gid=info.mtime=0;info.uname=info.gname=""
   with p.open("rb") as f:tf.addfile(info,f)
 expected={r["name"]:r for r in rows};seen=set()
 with tarfile.open(archive,"r|gz") as tf:
  for member in tf:
   assert member.isfile() and member.name in expected and member.name not in seen
   row=expected[member.name]
   assert (member.size,member.mode)==(row["bytes"],row["mode"])
   assert member.uid==member.gid==member.mtime==0
   h=hashlib.sha256();g=hashlib.sha1(b"blob "+str(member.size).encode()+b"\0");n=0
   source=tf.extractfile(member);assert source is not None
   with source:
    for chunk in iter(lambda:source.read(1<<20),b""):n+=len(chunk);h.update(chunk);g.update(chunk)
   assert (n,h.hexdigest(),g.hexdigest())==(row["bytes"],row["sha256"],row["git_blob_sha1"])
   same_pin(pin(payload/member.name),row);seen.add(member.name)
 assert seen==set(expected)
 result=dict(archive=pin(archive),index=pin(out/"readback-members.json"),members=len(rows),
  raw_bytes=sum(r["bytes"] for r in rows),full_bytes_modes_SHA256_Git_readback=True,
  complete_original_4706_members_retained_inside_pinned_original_tar=True,
  original_expanded_files_are_redundant_readback_working_copies_not_new_target_evidence=True)
 save(out/"readback-custody.json",result)
 return result
def measure(start):
 own=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
 return dict(cpu_seconds=own.ru_utime+own.ru_stime+children.ru_utime+children.ru_stime,
  parent_cpu_seconds=own.ru_utime+own.ru_stime,child_cpu_seconds=children.ru_utime+children.ru_stime,
  elapsed_ns=time.monotonic_ns()-start,maxrss_kib=own.ru_maxrss)
def strict_budget(row):
 assert 0<=row["cpu_seconds"]<90,("whole reader CPU90",row)
 assert 0<=row["elapsed_ns"]<180_000_000_000,("whole reader wall180",row)
def main():
 started=time.monotonic_ns()
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def alarm(signum,frame):raise TimeoutError("Original52a readonly reader wall180")
 signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,180)
 cpus=os.sched_getaffinity(0);assert cpus
 os.sched_setaffinity(0,{min(cpus)})
 root=Path(os.environ["HIA_NAMESPACE_FOLLOW52A_DIR"]).resolve(strict=True)
 out=Path(os.environ["HIA_CI_OUTPUT"]).absolute()
 assert not out.exists() and not out.is_relative_to(root) and not root.is_relative_to(out)
 out.mkdir(parents=True,exist_ok=False);payload=out/"payload";payload.mkdir()
 members=out/"verified-originals";members.mkdir()
 controls=[];copies=[];pending=[];checked=[];exports=[];spec=None;console={};primary=None
 result=dict(status="FAIL_READBACK",scope="INDEPENDENT_EXISTING_ORIGINAL42_FOLLOW52A_BYTES_ONLY",
  new_HIA=0,new_B3=0,new_VM=0,new_native=0,new_target_tests=0,
  original_selected_target_status="PASS_UNCHANGED",whole_Store_closed=False,
  ZIP_identity_scope="Actions artifact declaration only. No original ZIP bytes or CRC are read here.",
  original_archive_verified=False,complete_original_source_and_image_custody_verified=False)
 def preserve(source,target,before):
  controls.append((source,before));pending.append(str(target))
  copy_exact(source,target,before);copies.append((target,before));pending.remove(str(target))
 try:
  assert sys.version_info[:3]==(3,12,14),sys.version
  assert os.uname().machine=="x86_64"
  self_path=Path(__file__).resolve();self_pin=pin(self_path)
  preserve(self_path,payload/"reader-source.py",self_pin)
  config=self_path.with_name("input-follow52a.json");config_pin=pin(config)
  preserve(config,payload/"input-follow52a.json",config_pin)
  assert (config_pin["bytes"],config_pin["sha256"],config_pin["git_blob_sha1"])==(SPEC_BYTES,SPEC_SHA,SPEC_GIT)
  spec=json.loads(config.read_bytes());result["original_artifact"]=spec
  archive,ap=locate(root,"evidence.tar.xz",spec["archive_bytes"],spec["archive_sha256"])
  preserve(archive,payload/"original-evidence.tar.xz",ap)
  result["complete_archive_saved_before_index_parse"]=True
  index,ip=locate(root,"evidence-members.json",spec["index_bytes"],spec["index_sha256"])
  preserve(index,payload/"original-evidence-members.json",ip)
  result["complete_index_saved_before_semantic_parse"]=True
  checked=extract_exact(archive,index,members,spec)
  save(payload/"complete-verified-original-members.json",checked)
  result.update(original_archive_verified=True,original_members=len(checked),
   original_raw_bytes=sum(r["bytes"] for r in checked))
  # Capture and emit the whole genuine originals before any schema or semantic
  # assertion can fail. These are raw file bytes, never a JSON reserialization.
  base=spec["base"]
  names=[base+"/db-join-native-r1/summary.json",base+"/db-join-build-r1/summary.json",
   base+"/packer-differential-r1/summary.json",base+"/summary.json","run/summary.json",
   base+"/dms9-header-source-proof/summary.json",base+"/exact-byte-source-proof/summary.json",
   base+"/db-join-native-r1/tests.stderr.log","run/steps.json"]
  exports=original_exports(members,payload,names)
  save(payload/"complete-original-export-index.json",exports)
  result["original_exports"]=exports
  result["console_exports"]=emit_originals(payload,exports)
  report,physical,physical_dir=verify_reports(spec,members,checked,payload)
  traces=verify_physical_traces(physical,physical_dir,checked,members,payload)
  result.update(status="PASS_READBACK_ONLY",original42=report,trace_readback=traces,
   complete_original_source_and_image_custody_verified=True,
   no_original_failed_run_reclassified=True,all_4706_original_files_modes_SHA256_and_Git_readback=True)
  save(payload/"complete-derived-readback.json",result)
  console=dict(status="PASS_READBACK_ONLY",scope=result["scope"],original_head=spec["original_head"],
   run=spec["run"],job=spec["job"],artifact=spec["artifact"],
   original_members=len(checked),original_raw_bytes=result["original_raw_bytes"],
   original42_phase=report["original42_phase"],execution_counts=report["counts"],trace_readback=traces,
   canonical_source_and_image_count=len(report["canonical_inputs"]),fresh_original_compile_receipts=len(report["compile_receipts"]),
   profiles=report["profiles"],sqlite=report["sqlite"],original_exports=exports,
   full_raw_export_console_index="payload/console-original-export-index.json",
   full_readback="payload/complete-derived-readback.json",
   full_trace_readback="payload/complete-recorded-trace-readback.json",
   original_source_and_image_index="payload/canonical-source-image-index.json",
   whole_Store_closed=False,new_HIA=0,new_B3=0,new_VM=0,new_native=0)
 except BaseException as error:
  primary=dict(type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
  result.update(status="FAIL_READBACK",primary_error=primary)
  console=dict(status="FAIL_READBACK",primary_error=primary,new_target_executions=0)
 finally:
  after_errors=[]
  for label,items in (("original-input-or-self",controls),("completed-early-copy",copies)):
   for path,before in items:
    try:
     after=pin(path);assert after==before
    except BaseException as error:
     after_errors.append(dict(scope=label,path=str(path),type=type(error).__name__,
      message=str(error),traceback=traceback.format_exc()))
  for row in checked:
   try:same_pin(pin(members/row["name"]),row)
   except BaseException as error:
    after_errors.append(dict(scope="expanded-original-member",path=row["name"],
     type=type(error).__name__,message=str(error),traceback=traceback.format_exc()))
  if after_errors or pending:
   result["status"]="FAIL_READBACK";console["status"]="FAIL_READBACK"
  result["after_check_errors"]=after_errors;result["unfinished_early_copies"]=pending
  result["all_available_original_after_checks_attempted"]=True
  try:
   save(payload/"final-readback-result.json",result)
   custody=seal_payload(out);console["readback_custody"]=custody
  except BaseException as error:
   result["status"]="FAIL_READBACK";console["status"]="FAIL_READBACK"
   console["seal_error"]=dict(type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
  # Seal work is included before this second full control/self/copy after-check.
  # A failed later check changes overall status even if the earlier seal is valid.
  for label,items in (("post-seal-original-input-or-self",controls),("post-seal-completed-copy",copies)):
   for path,before in items:
    try:assert pin(path)==before
    except BaseException as error:
     after_errors.append(dict(scope=label,path=str(path),type=type(error).__name__,
      message=str(error),traceback=traceback.format_exc()))
     result["status"]="FAIL_READBACK";console["status"]="FAIL_READBACK"
  try:
   console.update(after_check_errors=after_errors,unfinished_early_copies=pending,
    all_original_failures_preserved=True,original_target_rerun=False,
    limits=LIMITS,observed_before_output=measure(started))
   raw=save(out/"readback-summary.json",console)
   assert len(raw)<100000,("Complete derived console summary must be bounded",len(raw))
   print("HIA_NAMESPACE52_READBACK "+json.dumps(console,sort_keys=True,separators=(",",":")),flush=True)
  except BaseException as error:
   result["status"]="FAIL_READBACK";console["status"]="FAIL_READBACK"
   console["summary_output_error"]=dict(type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
  # The alarm remains active through every after-check, the archive seal,
  # metadata write/readback and stdout. Final success checks include those costs.
  try:
   post=measure(started);save(out/"post-output-budget.json",dict(limits=LIMITS,observed=post))
   # Include the budget metadata's own complete write/readback before the gate.
   final=measure(started);strict_budget(final)
   assert result["status"]=="PASS_READBACK_ONLY" and console["status"]=="PASS_READBACK_ONLY"
  except BaseException as error:
   result["status"]="FAIL_READBACK";console["status"]="FAIL_READBACK"
   console["final_gate_error"]=dict(type=type(error).__name__,message=str(error),traceback=traceback.format_exc())
   console["original_primary_error"]=primary
   try:save(out/"readback-summary.json",console)
   except BaseException as secondary:
    console["failed_final_receipt_write"]=dict(type=type(secondary).__name__,message=str(secondary))
   try:print("HIA_NAMESPACE52_READBACK_FINAL_FAILURE "+json.dumps(
    dict(status="FAIL_READBACK",primary=primary,final_gate_error=console["final_gate_error"],
     summary_output_error=console.get("summary_output_error"),seal_error=console.get("seal_error"),
     after_check_errors=after_errors,unfinished_early_copies=pending,new_target_executions=0),
    sort_keys=True,separators=(",",":")),flush=True)
   except BaseException:pass
  signal.setitimer(signal.ITIMER_REAL,0)
 return 0 if result["status"]=="PASS_READBACK_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
