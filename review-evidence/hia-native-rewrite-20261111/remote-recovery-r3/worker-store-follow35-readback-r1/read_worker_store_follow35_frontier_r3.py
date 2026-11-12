"""Read only the exact FOLLOW35 Store artifact; never execute its source/images.

Original two 90-CPU failures stay failures. This reader verifies every ZIP/tar
member, every ledger record and every referenced CAS membership, then expands
only pending/last native buffers to identify the recorded frontier. A pending
file equal to the last completed entry is not mislabeled an unfinished call.
A missing completed ledger row does not distinguish an in-flight native call
from after-return canary/input checks or snapshot recording in the harness.
"""
from __future__ import annotations
import base64,hashlib,json,os,resource,signal,stat,struct,sys,tarfile,time,traceback,zipfile,zlib
from pathlib import Path,PurePosixPath
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def wall(*_):raise TimeoutError("readonly Store artifact reader exceeded its 180-second bound")
signal.signal(signal.SIGALRM,wall);signal.alarm(180)
ZIP=Path(sys.argv[1]).resolve();OUT=Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True,exist_ok=False)
SELF=Path(__file__).read_bytes()
START=time.monotonic_ns()
ZIP_BYTES=85456843
ZIP_SHA="30bff4835fc1c24b948d1cb2cff67babdff2a2bd87edc2f31f4f5071ee2b7623"
INNER_BYTES=16607300
INNER_SHA="bbb9ca5956ffaf7dc4379e2640b87abaffdf864ff99a884c4117668b50b3f440"
INDEX_BYTES=7520401
INDEX_SHA="3055f8eeb02698c8180371a8a258b24a009973f6f5d05e69af4237fd7dc54ef7"
COMPILER="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
EXPECTED_COMPONENTS=json.loads(r'''{"emit":{"compiler_sha256":"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","counts":null,"exact_fixed_original_hia_source":true,"image_bytes":256019,"image_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/emit.image.bin","image_sha256":"9b69271adb5c3024842fc065e294b9a3550077801b76e43046c4eb09e3925a80","receipt_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/emit.receipt.json","role":"emit","source_bytes":173680,"source_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-edit-render-next/examples/hia_bootstrap/graph_json_wire_emit.hiaasm","source_sha256":"9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2"},"maps":{"compiler_sha256":"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","counts":{"blocks":352,"functions":29,"instructions":1615,"max_block_parameters":15,"max_function_blocks":39},"image_bytes":140591,"image_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/maps.image.bin","image_sha256":"fdf6ec06432682e02ea8c3380235aa6a4accdac1024c93e32ba8df3df80674e0","receipt_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/maps.receipt.json","role":"maps","source_bytes":95040,"source_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-initialization-registry-next/examples/hia_bootstrap/agent_worker_initialization_maps.hiaasm","source_sha256":"bc3faf33b6e946e943aea8a42503b633a77625eb037058c277422d07039d7f3b"},"merge":{"compiler_sha256":"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","counts":{"blocks":202,"functions":12,"instructions":878,"max_block_parameters":16,"max_function_blocks":77},"image_bytes":82828,"image_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/merge.image.bin","image_sha256":"e7915e121cd863dee54fc43ce03e219a4de7ca3ad5f8aa7a004dbef05fcb554a","receipt_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/merge.receipt.json","role":"merge","source_bytes":54648,"source_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-initialization-registry-next/examples/hia_bootstrap/graph_merge.hiaasm","source_sha256":"e2c9bc7fe841c628a9bcc492f48bed02e468ce699250c6d223f4eba0a894dbca"},"pure":{"compiler_sha256":"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","counts":{"blocks":768,"functions":40,"instructions":3555,"max_block_parameters":15,"max_function_blocks":92},"image_bytes":306738,"image_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/pure.image.bin","image_sha256":"d04f574ea2d180d0eedbb36404787772b57471999bd3451ab03435c8d6536eb8","receipt_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/pure.receipt.json","role":"pure","source_bytes":208134,"source_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-initialization-registry-next/examples/hia_bootstrap/agent_worker_initializer_pure_join.hiaasm","source_sha256":"593312105f58a26c50586da921425e958325c0b1df3988bc2c353dc733fdb75f"},"registry":{"compiler_sha256":"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","counts":{"blocks":410,"functions":33,"instructions":2285,"max_block_parameters":15,"max_function_blocks":39},"image_bytes":173954,"image_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/registry.image.bin","image_sha256":"481d2abd8bf44b8e25c97186f74e3bc769b6e5163ee3d5c6b6c5f01585df33a9","receipt_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/registry.receipt.json","role":"registry","source_bytes":124035,"source_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-initialization-registry-next/examples/hia_bootstrap/agent_worker_initializer_registry.hiaasm","source_sha256":"6249034eece44249dc0e5b747ce90a9c052e0e2461fd8a51297bfd8b57785ca2"},"scan":{"compiler_sha256":"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","counts":null,"exact_fixed_original_hia_source":true,"image_bytes":215282,"image_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/scan.image.bin","image_sha256":"3545a6c60334b5f7e92eda8df582472a2a493c74b814e5ac9158cdd2e866b026","receipt_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/scan.receipt.json","role":"scan","source_bytes":147822,"source_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-edit-render-next/examples/hia_bootstrap/graph_json_wire_scan.hiaasm","source_sha256":"c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3"},"sequence":{"compiler_sha256":"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","counts":{"blocks":545,"functions":32,"instructions":2947,"max_block_parameters":10,"max_function_blocks":93},"image_bytes":196611,"image_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/sequence.image.bin","image_sha256":"f6ffb339a75828c19feb59e306d0256a22b161711559677bd8d53f77538b194a","receipt_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/sequence.receipt.json","role":"sequence","source_bytes":154820,"source_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-initialization-registry-next/examples/hia_bootstrap/agent_worker_initialization_sequence.hiaasm","source_sha256":"fa460eaf5f5b5e35061211724b07698bb3ab4da965f1a56bf53611da0cd62663"},"values":{"compiler_sha256":"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","counts":{"blocks":316,"functions":23,"instructions":1513,"max_block_parameters":15,"max_function_blocks":50},"image_bytes":128975,"image_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/values.image.bin","image_sha256":"15cb7e589647fd22e2df9470004c7c64281f4ad9e9cb5dccb70c0cc191386297","receipt_path":"/home/runner/work/_temp/hia-worker-store-json-profile-recovery/store-values-registry-eight-compiles/values.receipt.json","role":"values","source_bytes":88015,"source_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-initialization-registry-next/examples/hia_bootstrap/agent_worker_initialization_values.hiaasm","source_sha256":"0d32720faeb22478b4163436a4586e6b140aac18628bf2a99b824f34e543a266"},"storevalues":{"compiler_sha256":"0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8","counts":{"blocks":927,"functions":36,"instructions":4231,"max_block_parameters":15,"max_function_blocks":89,"max_ssa_index":1207},"image_bytes":391846,"image_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-worker-store-values-next/development/compile-r1/worker-store-json-profile.image.bin","image_sha256":"2ef53e18e3680e868d5c3882697b30ffb1bdb01d3b16664a739a916444fe9a51","receipt_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-worker-store-values-next/development/compile-r1/worker-store-json-profile.receipt.json","role":"storevalues","source_bytes":259178,"source_path":"/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-recovery/work-r2/native-agent-worker-store-values-next/examples/hia_bootstrap/agent_worker_store_json_profile.hiaasm","source_sha256":"8f01df5f3db397294be700e99bca9fd86fea326a76331774557d27d22dc534de"}}''')
GROUPS=("large-value-8m","large-value-over")
PASS_GROUPS={"semantic":(27,6188),"errors":(14,2674),"protocol":(223,574),
             "growth":(4,708),"large-ref-8m":(1,124)}
report=dict(schema="hepta.hia.worker-store-follow35-frontier-readback.v1",
 status="FAIL_READER",original_run=43165373215,original_job=131005901440,
 original_head="2544ec88203992d5d8590b4ab09fb0231066be72",artifact_id=13919838606,
 original_qualification_status="FAIL",original_large_limits_unchanged=True,
 new_native_entries=0,new_compiles=0,new_vm_entries=0,subject_source_executed=False,
 all_logical_CAS_expanded=False,whole_worker_closed=False,frontiers={})
kept={};kept_paths={};verified={};referenced={};source_rows={};wanted_cas={}
def digest(raw):return hashlib.sha256(raw).hexdigest()
def gitsha(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def file_identity(path):
 h=hashlib.sha256();n=0
 with path.open("rb") as f:
  while True:
   raw=f.read(1<<20)
   if not raw:break
   n+=len(raw);h.update(raw)
 return n,h.hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def safe(name):
 p=PurePosixPath(name)
 assert name and not p.is_absolute() and ".." not in p.parts and "\\" not in name,name
 return p
def keep(name,raw,mode=420):
 safe(name);p=OUT/"originals"/name;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(raw)
 p.chmod(mode);assert (len(p.read_bytes()),digest(p.read_bytes()),stat.S_IMODE(p.stat().st_mode))==(len(raw),digest(raw),mode)
 kept[name]=raw;kept_paths[name]=p
def json_member(name):
 assert name in kept,name
 return json.loads(kept[name])
def jsonlines(raw,name):
 rows=[];tail=b""
 parts=raw.splitlines(keepends=True)
 for i,line in enumerate(parts):
  complete=line.endswith(b"\n")
  try:row=json.loads(line)
  except (UnicodeDecodeError,json.JSONDecodeError):
   if i==len(parts)-1 and not complete:tail=line;break
   raise
  assert isinstance(row,dict),(name,i)
  rows.append(row)
 return rows,tail
def ref_check(prefix,ref):
 assert isinstance(ref,dict) and type(ref.get("bytes")) is int and ref["bytes"]>=0,ref
 key=ref.get("sha256");assert type(key) is str and len(key)==64 and all(c in "0123456789abcdef" for c in key),ref
 name=prefix+"/cas/"+key+".zlib"
 assert name in verified,(name,"missing original compressed CAS")
 old=referenced.setdefault(name,ref)
 assert old==ref,(name,old,ref)
 return name
def frontier_ref(prefix,ref):
 name=ref_check(prefix,ref);wanted_cas[name]=ref;return name
try:
 zip_before=file_identity(ZIP)
 assert zip_before==(ZIP_BYTES,ZIP_SHA),zip_before
 save(OUT/"reader-source.json",dict(bytes=len(SELF),sha256=digest(SELF),gitsha=gitsha(SELF),
  original_zip_bytes=ZIP_BYTES,original_zip_sha256=ZIP_SHA))
 with zipfile.ZipFile(ZIP) as z:
  names=[i.filename for i in z.infolist()]
  assert len(names)==len(set(names))
  zip_files=[]
  for item in z.infolist():
   safe(item.filename)
   if item.is_dir():continue
   assert not stat.S_ISLNK(item.external_attr>>16),item.filename
   n=0;h=hashlib.sha256()
   with z.open(item) as f:
    while True:
     part=f.read(1<<20)
     if not part:break
     n+=len(part);h.update(part)
   assert n==item.file_size
   zip_files.append(dict(name=item.filename,bytes=n,sha256=h.hexdigest()))
  tar_names=[n for n in names if n.endswith("/evidence.tar.xz")]
  assert len(tar_names)==1,tar_names
  tar_name=tar_names[0];prefix=tar_name.rsplit("/",1)[0]
  custody_raw=z.read(prefix+"/custody.json")
  index_raw=z.read(prefix+"/evidence-members.json")
  assert (len(index_raw),digest(index_raw))==(INDEX_BYTES,INDEX_SHA)
  custody=json.loads(custody_raw);index=json.loads(index_raw)
  assert custody["status"]=="FAIL" and custody["scope"]=="worker-native-store-json-profile-initializer-continuations-r1"
  assert (custody["bytes"],custody["sha256"],custody["members"],custody["original_bytes"])==(INNER_BYTES,INNER_SHA,15676,112417463)
  assert custody["member_index_bytes"]==INDEX_BYTES and custody["member_index_sha256"]==INDEX_SHA
  assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
  assert isinstance(index,list) and len(index)==15676
  expected={}
  paths={}
  for row in index:
   safe(row["name"]);assert row["name"] not in expected
   assert type(row["bytes"]) is int and row["bytes"]>=0
   assert type(row["mode"]) is int and 0<=row["mode"]<=4095
   expected[row["name"]]=row;paths.setdefault(row["path"],[]).append(row["name"])
  assert sum(r["bytes"] for r in index)==112417463
  keep("custody.json",custody_raw);keep("evidence-members.json",index_raw)
  archive=OUT/"originals"/"evidence.tar.xz";h=hashlib.sha256();n=0
  with z.open(tar_name) as src,archive.open("xb") as dst:
   while True:
    part=src.read(1<<20)
    if not part:break
    dst.write(part);h.update(part);n+=len(part)
  assert (n,h.hexdigest())==(INNER_BYTES,INNER_SHA)
  report["zip_all_files"]=zip_files
  report["zip_all_CRC_and_member_bytes_verified"]=True
 component_names=set()
 for role,row in EXPECTED_COMPONENTS.items():
  assert row["compiler_sha256"]==COMPILER
  for field in ("source_path","image_path","receipt_path"):
   assert row[field] in paths,(role,field,row[field])
   component_names.update(paths[row[field]])
 def selected(name):
  if name in component_names or name in ("run/summary.json","run/steps.json"):return True
  if name.startswith("run/steps/worker-store-values-") and name.rsplit("/",1)[-1] in ("process.json","stdout.log","stderr.log"):return True
  if name.startswith("store-values/development/ci-") and name.rsplit("/",1)[-1] in (
    "summary.json","source-before.json","source-after.json","cases.json","pending.json","entries.jsonl"):return True
  return False
 with tarfile.open(archive,"r|xz") as tf:
  for item in tf:
   assert item.isfile() and item.name in expected and item.name not in verified,item.name
   row=expected[item.name];assert (item.size,item.mode)==(row["bytes"],row["mode"])
   assert item.uid==0 and item.gid==0 and item.mtime==0,item.name
   f=tf.extractfile(item);h=hashlib.sha256();n=0;parts=[] if selected(item.name) else None
   while True:
    part=f.read(1<<20)
    if not part:break
    h.update(part);n+=len(part)
    if parts is not None:parts.append(part)
   assert (n,h.hexdigest())==(row["bytes"],row["sha256"]),item.name
   verified[item.name]=row
   if parts is not None:keep(item.name,b"".join(parts),item.mode)
 assert set(verified)==set(expected)
 report["all_tar_members_sha256_bytes_modes_verified"]=True
 report["tar_members"]=len(verified);report["tar_original_bytes"]=sum(r["bytes"] for r in verified.values())
 def by_original_path(path):
  names=paths[path];assert names
  values=[kept[n] for n in names]
  assert all(raw==values[0] for raw in values)
  return values[0]
 identities={}
 for role,row in EXPECTED_COMPONENTS.items():
  s=by_original_path(row["source_path"]);i=by_original_path(row["image_path"])
  rc=json.loads(by_original_path(row["receipt_path"]))
  assert (len(s),digest(s))==(row["source_bytes"],row["source_sha256"])
  assert (len(i),digest(i))==(row["image_bytes"],row["image_sha256"])
  assert rc["input_sha256"]==row["source_sha256"] and rc["produced_sha256"]==row["image_sha256"]
  assert rc["image_sha256"]==COMPILER
  identities[role]=dict(source_bytes=len(s),source_sha256=digest(s),image_bytes=len(i),
   image_sha256=digest(i),compiler_sha256=COMPILER,actual_receipt=rc)
 report["fresh_original_nine_component_identities"]=identities
 summary=json_member("run/summary.json")
 assert summary["status"]=="FAIL" and summary["details"]["actual_physical_namespace_entries"]==0
 assert summary["frozen_source_and_reference_before_after_equal"] is True
 assert summary["submitted_script_pins_before_after_equal"] is True
 report["original_summary"]=summary
 ledger_summaries={}
 for name,raw in tuple(kept.items()):
  if not name.endswith("/entries.jsonl"):continue
  group_prefix=name.rsplit("/",1)[0];records,tail=jsonlines(raw,name)
  counts={}
  for row in records:
   role=row["role"];assert role in EXPECTED_COMPONENTS,role
   assert row["entry"]==counts.get(role,0)+1,(name,role,row["entry"],counts)
   counts[role]=row["entry"]
   assert type(row["result"]) is int and 0<=row["result"]<=0xffffffff
   assert row["same_inputs"] is True
   for field in ("s","r","w","after_r","after_w"):ref_check(group_prefix,row[field])
  ledger_summaries[name]=dict(complete_entries=len(records),counts=counts,
   trailing_incomplete_bytes=len(tail),trailing_incomplete_sha256=digest(tail),
   ledger_bytes=len(raw),ledger_sha256=digest(raw))
  if group_prefix.rsplit("/",1)[-1] not in tuple("ci-"+g+"-r1" for g in GROUPS):continue
  group=group_prefix.rsplit("/",1)[-1][3:-3]
  pending_name=group_prefix+"/pending.json"
  pending=json_member(pending_name) if pending_name in kept else None
  last=records[-1] if records else None
  outstanding=None
  if pending is not None:
   assert pending["role"] in EXPECTED_COMPONENTS
   complete=counts.get(pending["role"],0)
   assert pending["entry"] in (complete,complete+1),(pending,complete)
   outstanding=pending["entry"]==complete+1
   if not outstanding:
    assert last is not None
    assert all(pending[k]==last[k] for k in ("role","entry","label","s","r","w"))
   for field in ("s","r","w"):frontier_ref(group_prefix,pending[field])
  if last is not None:
   for field in ("s","r","w","after_r","after_w"):frontier_ref(group_prefix,last[field])
  process=json_member("run/steps/worker-store-values-"+group+"/process.json")
  assert process["returncode"]==-9 and process["timed_out"] is False and process["timeout_seconds"]==180
  assert group_prefix+"/summary.json" not in expected
  report["frontiers"][group]=dict(process=process,ledger=ledger_summaries[name],
   pending=pending,last_completed=last,last_eight_entries=records[-8:],
   entry_without_completed_ledger_record=outstanding,
   classification=("PENDING_ENTRY_WITHOUT_COMPLETION_RECORD" if outstanding else
     "NO_UNFINISHED_NATIVE_ENTRY_RECORDED" if outstanding is False else "PENDING_FILE_ABSENT"),
   pending_kernel_identity=identities[pending["role"]] if pending is not None else None)
 assert set(report["frontiers"])==set(GROUPS)
 for group,(count,entries) in PASS_GROUPS.items():
  prefix="store-values/development/ci-"+group+"-r1"
  terminal=json_member(prefix+"/summary.json")
  assert terminal["status"]=="PASS" and (terminal["cases"],terminal["total_actual_entries"])==(count,entries)
  assert ledger_summaries[prefix+"/entries.jsonl"]["complete_entries"]==entries
  assert ledger_summaries[prefix+"/entries.jsonl"]["trailing_incomplete_bytes"]==0
 runtime_sources={
  "store-values/development/digest_harness_r4.py":(12362,"9e04554a902050a97c9e0c9449735671d77dd02d8d2090972294b4a205ac7528"),
  "store-values/development/store_values_harness_r1.py":(15468,"ee46468c8c5f41a3f35668a4b17e75686599536554c5924e0629223917c805e7"),
  "store-values/development/test_worker_store_values_targets_r1.py":(10332,"5041539f518c3f61d8e19d5e9d3f2b400894e9506ce040d6da616d665e8992b2")}
 for name,identity in runtime_sources.items():
  assert name in verified
  assert (verified[name]["bytes"],verified[name]["sha256"])==identity,name
 report["actual_runtime_harness_source_identities"]=runtime_sources
 by_identity={}
 for row in verified.values():
  by_identity.setdefault((row["bytes"],row["sha256"],row["mode"]),[]).append(row["name"])
 before_checks={}
 for group in (*PASS_GROUPS,*GROUPS):
  name="store-values/development/ci-"+group+"-r1/source-before.json"
  inputs=json_member(name);assert isinstance(inputs,dict) and inputs
  matches=[]
  for original,row in inputs.items():
   identity=(row["bytes"],row["sha256"],row["mode"])
   direct=[n for n in paths.get(original,[]) if
    (verified[n]["bytes"],verified[n]["sha256"],verified[n]["mode"])==identity]
   copies=by_identity.get(identity,[])
   assert direct or copies,(name,original,row)
   matches.append(dict(original_path=original,identity=row,
    direct_path_members=direct,exact_content_mode_copy_members=copies if not direct else []))
  before_checks[group]=matches
 report["source_before_pins_matched_all_original_archive_bytes_and_modes"]=before_checks
 report["pending_completion_observation_limit"]=(
  "The harness writes pending before entry, but writes completed ledger only after "
  "native return, canary and readonly-input checks and complete buffer snapshot saving. "
  "A missing ledger row is not proof that CPU was spent inside the named image.")
 report["all_complete_ledger_records_and_CAS_memberships_verified"]=True
 report["ledger_summaries"]=ledger_summaries
 report["referenced_compressed_CAS_objects"]=len(referenced)
 expanded={}
 with tarfile.open(archive,"r|xz") as tf:
  for item in tf:
   if item.name not in wanted_cas:continue
   raw=tf.extractfile(item).read()
   assert (len(raw),digest(raw),item.mode)==(verified[item.name]["bytes"],verified[item.name]["sha256"],verified[item.name]["mode"])
   keep("frontier-cas/"+item.name,raw,item.mode)
   ref=wanted_cas[item.name];d=zlib.decompressobj();h=hashlib.sha256();n=0;first=bytearray()
   for at in range(0,len(raw),65536):
    part=raw[at:at+65536]
    while part:
     data=d.decompress(part,1<<20);part=d.unconsumed_tail
     n+=len(data);assert n<=ref["bytes"],item.name;h.update(data)
     if len(first)<4096:first.extend(data[:4096-len(first)])
   assert d.eof and not d.unused_data and not d.unconsumed_tail,item.name
   assert (n,h.hexdigest())==(ref["bytes"],ref["sha256"]),item.name
   prefix=bytes(first)
   expanded[item.name]=dict(bytes=n,sha256=h.hexdigest(),original_compressed_member=item.name,
    prefix_bytes=len(prefix),prefix_hex=prefix.hex(),
    first_32_le_u64=list(struct.unpack("<"+"Q"*min(32,len(prefix)//8),prefix[:min(32,len(prefix)//8)*8])))
 assert set(expanded)==set(wanted_cas)
 report["frontier_CAS_full_uncompressed_bytes_sha256_verified"]=expanded
 for group,row in report["frontiers"].items():
  prefix="store-values/development/ci-"+group+"-r1"
  p=row["pending"]
  row["pending_views"]={field:expanded[prefix+"/cas/"+p[field]["sha256"]+".zlib"]
    for field in ("s","r","w")} if p is not None else {}
  def brief_entry(entry):
   if entry is None:return None
   label=str(entry.get("label",""));label_raw=label.encode("utf-8")
   return dict(role=entry.get("role"),entry=entry.get("entry"),result=entry.get("result"),
    label_prefix=label[:256],label_bytes=len(label_raw),label_sha256=digest(label_raw),
    views={field:dict(bytes=entry[field]["bytes"],sha256=entry[field]["sha256"])
     for field in ("s","r","w","after_r","after_w") if field in entry})
  kernel=row["pending_kernel_identity"]
  compact=dict(group=group,classification=row["classification"],
   entry_without_completed_ledger_record=row["entry_without_completed_ledger_record"],
   process={key:row["process"].get(key) for key in ("returncode","timed_out","timeout_seconds",
    "elapsed_ns","child_cpu_seconds","children_cumulative_maxrss_kib")},
   ledger=row["ledger"],pending=brief_entry(row["pending"]),
   last_completed=brief_entry(row["last_completed"]),
   last_eight_entries=[brief_entry(entry) for entry in row["last_eight_entries"]],
   pending_kernel_identity={key:kernel[key] for key in ("source_bytes","source_sha256",
    "image_bytes","image_sha256","compiler_sha256")} if kernel is not None else None,
   pending_view_headers={field:{key:view[key] for key in ("bytes","sha256","first_32_le_u64")}
    for field,view in row["pending_views"].items()},
   complete_frontier_and_all_prefix_bytes_in_report=True)
  print("HIA_WORKER_STORE_FRONTIER "+json.dumps(compact,sort_keys=True),flush=True)
 assert file_identity(ZIP)==zip_before and Path(__file__).read_bytes()==SELF
 assert file_identity(archive)==(INNER_BYTES,INNER_SHA)
 report["source_and_original_zip_unchanged"]=True
 report["status"]="PASS_READONLY_ORIGINAL_FAILURE_PRESERVED"
except BaseException as exc:
 report["failure"]=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
 report["elapsed_ns"]=time.monotonic_ns()-START
 save(OUT/"report.json",report)
 save(OUT/"readback-output-index.json",[dict(path=str(p.relative_to(OUT)),bytes=p.stat().st_size,
  sha256=file_identity(p)[1],mode=stat.S_IMODE(p.stat().st_mode))
  for p in sorted(OUT.rglob("*")) if p.is_file()])
 report_bytes,report_sha=file_identity(OUT/"report.json")
 index_bytes,index_sha=file_identity(OUT/"readback-output-index.json")
 brief={key:report[key] for key in ("status","original_qualification_status",
  "original_large_limits_unchanged","new_native_entries","new_compiles","new_vm_entries",
  "subject_source_executed","whole_worker_closed","zip_all_CRC_and_member_bytes_verified",
  "all_tar_members_sha256_bytes_modes_verified","tar_members","tar_original_bytes",
  "all_complete_ledger_records_and_CAS_memberships_verified","referenced_compressed_CAS_objects",
  "source_and_original_zip_unchanged","pending_completion_observation_limit","elapsed_ns")
  if key in report}
 brief["verified_source_before_pin_counts"]={group:len(rows) for group,rows in
  report.get("source_before_pins_matched_all_original_archive_bytes_and_modes",{}).items()}
 brief["ledger_summaries"]=report.get("ledger_summaries",{})
 brief["frontier_groups"]=sorted(report["frontiers"])
 brief["report"]=dict(path="report.json",bytes=report_bytes,sha256=report_sha)
 brief["output_index"]=dict(path="readback-output-index.json",bytes=index_bytes,sha256=index_sha)
 if "failure" in report:
  failure=report["failure"];message=failure["error"];raw=message.encode("utf-8")
  brief["failure"]=dict(error_class=failure["error_class"],error_prefix=message[:2048],
   full_error_bytes=len(raw),full_error_sha256=digest(raw),full_error_in_report=True)
 print("HIA_WORKER_STORE_FRONTIER_READER "+json.dumps(brief,sort_keys=True),flush=True)
 signal.alarm(0)
if report["status"]!="PASS_READONLY_ORIGINAL_FAILURE_PRESERVED":raise SystemExit(1)
