"""Nine remaining original Emitter groups after exact FOLLOW39 and FOLLOW41 readbacks.
The preceding 44 and 2 groups remain separate observations of their failed runs.
All eleven production HIA source/image pairs must match BOTH prior runs before
this tail is executed. No production difference enables partial coverage.
"""
from pathlib import Path
from hashlib import sha1,sha256
import base64,importlib.util,json,lzma,os,stat,sys,traceback,types
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
SOURCE_PREFIX=R3+"emitter-full-r1/"
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
SEAL_GIT="ea7a0c34555fc75835c507dc13ffe9e071137dd9"
FILES=[
  {
    "path": "ci/emitter_streamed_finish.py",
    "mode": "100644",
    "bytes": 6120,
    "sha256": "6da813d4be8fd4f268f90ce063e3aadc011e0aae0832163d02f5b6640555e96e",
    "gitsha": "ea7a0c34555fc75835c507dc13ffe9e071137dd9"
  },
  {
    "path": "docs/HIA_COMPLETE_EMITTER_NATIVE.md",
    "mode": "100644",
    "bytes": 23661,
    "sha256": "bce568f9014d36a4682b505d15cc843e8f62c96dd241ee73b2c867803a2d754a",
    "gitsha": "208c093042aba6cbe61e53de1198ca60909cc767"
  },
  {
    "path": "reference/hia_machine_plan.py",
    "gitsha": "61833e8bf8497089461bad9eb2347c82a233e8b2",
    "bytes": 13270,
    "sha256": "ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a",
    "mode": "100644"
  },
  {
    "path": "reference/hia_machine_x64.py",
    "gitsha": "8e87bd317c5f61e00993bb0bf8d803c5385d6556",
    "bytes": 11057,
    "sha256": "8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9",
    "mode": "100644"
  },
  {
    "path": "reference/hia_native_byte_abi.py",
    "gitsha": "4412810e9e6dfba82879dbb9ae19c19ce2de178c",
    "bytes": 5825,
    "sha256": "0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6",
    "mode": "100644"
  },
  {
    "path": "reference/hia_program_native.py",
    "gitsha": "1d0e0344f8300b11b5dd505cbea655170aba5be1",
    "bytes": 46917,
    "sha256": "bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c",
    "mode": "100644"
  },
  {
    "path": "reference/hia_selfhost_child.py",
    "gitsha": "2ecbf3a04680eceee0537cb3d621073bac9c52f4",
    "bytes": 6791,
    "sha256": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29",
    "mode": "100644"
  },
  {
    "path": "tests/emitter_mechanical_harness.py",
    "mode": "100644",
    "bytes": 8753,
    "sha256": "4f93c246c3ad4e4b83089821ed328ec6d52097be6994c17b36dfd2e2a7919f1a",
    "gitsha": "0dfa2474834b12df5d0a94b35be57890a79a960f"
  },
  {
    "path": "tests/emitter_native_adapter.py",
    "mode": "100644",
    "bytes": 14766,
    "sha256": "6211db1e02e094e627e65601bb5c12bf5534400f9fabcc00ce0b8fa35af2d408",
    "gitsha": "d4064e20d867ae77d241b48d6552fa8e68cb566f"
  },
  {
    "path": "tests/function_code_test_reference.py",
    "gitsha": "18aa77e90c3047da6035e32f58725851286eca28",
    "bytes": 45704,
    "sha256": "61dbf40a99220f2f5b6db7950ee8e3a53299530d385fee70877ade6a0e387c11",
    "mode": "100644"
  },
  {
    "path": "tests/function_frame_test_reference.py",
    "gitsha": "a7d64f7804753398df08e69158bcebb7afc54747",
    "bytes": 42184,
    "sha256": "b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6",
    "mode": "100644"
  },
  {
    "path": "tests/function_lowering_test_reference.py",
    "gitsha": "cb42b8e725bc16471c1cd9fd965c0bdd7f704405",
    "bytes": 48120,
    "sha256": "e08023ddab7501313a45825e5e2cdbba40d3524fee3e4a0f9ad33ba65335bc17",
    "mode": "100644"
  },
  {
    "path": "tests/test_hia_complete_emitter.py",
    "mode": "100644",
    "bytes": 30508,
    "sha256": "cff0e69a89fcbeefbbbe69b522cf775fa0621cda65ab1dca49b1f90aab0bd716",
    "gitsha": "9609ecf8271ff49fcad1f5e8730bc2b2180f1ca4"
  },
  {
    "path": "tests/wrapper_test_reference.py",
    "gitsha": "b92c5ab3053e6661d564d13cb053c4d403a872c5",
    "bytes": 28437,
    "sha256": "30950bd89da646f64061fc55bd0b855178c7e20fd214485b58b20ad86b4bd470",
    "mode": "100644"
  },
  {
    "path": "tools/build_emitter_native_mechanics.py",
    "mode": "100644",
    "bytes": 4319,
    "sha256": "701737366d4536a46eab2e32894b57d6dc5728e52f913861754b84f308d24759",
    "gitsha": "696186611a301ca17d828b2d5085ec148cf211f1"
  },
  {
    "path": "tools/build_hia_complete_emitter.py",
    "mode": "100644",
    "bytes": 15496,
    "sha256": "7b6664186a423173487aa8a562cd043768e7fec3b71a4f1948005ec39915530a",
    "gitsha": "41d4a135744468845b6bc0fe79a3bf9ab3e5a227"
  },
  {
    "path": "tools/emitter_native_mechanics.c",
    "mode": "100644",
    "bytes": 10283,
    "sha256": "cfc106e6d312f3e63eab51f2b19aa4e04a8c141c3dd4456e7d225b5a7425678f",
    "gitsha": "25dc29835a2fb5380b3dbcd2077f7440ff03466c"
  },
  {
    "path": "tools/function_authoring_reference.py",
    "gitsha": "6f1bffe8bd815a068f9834489960006cbaad6fac",
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b",
    "mode": "100644"
  },
  {
    "path": "tools/hia_agent_edit_source_views.py",
    "gitsha": "f7d123bdb2bf65b25182b571f024299cb0342828",
    "bytes": 23950,
    "sha256": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c",
    "mode": "100644"
  },
  {
    "path": "tools/hia_composite_lowering_driver_common.py",
    "gitsha": "e56539a9cb76f95010ea6ca995737f40ab6e1850",
    "bytes": 17781,
    "sha256": "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1",
    "mode": "100644"
  },
  {
    "path": "tools/hia_emitter_controller.py",
    "mode": "100644",
    "bytes": 45316,
    "sha256": "7b706ef28c91d57a36d567ce701501dfa9ed025f4e27278cf629ace6bf011398",
    "gitsha": "fdbbeed9d5cf5798f3a7b42aa4299f0c57e37402"
  },
  {
    "path": "tools/hia_emitter_finish.py",
    "mode": "100644",
    "bytes": 25093,
    "sha256": "66b6480a3f6f37985fc4d97c4d54de848bb7fcd247591f04542df7e94570337c",
    "gitsha": "c3deb8a4c86c382b58e0897617770b8e2ac5ae45"
  },
  {
    "path": "tools/hia_emitter_prepare.py",
    "mode": "100644",
    "bytes": 26939,
    "sha256": "da2a957ed48c1fce78c7b931b6b6e3833522271d0fe0578b248e367820ebfb3f",
    "gitsha": "16e1786ece4aa71c0dac6d5a431288893c2829ad"
  },
  {
    "path": "tools/hia_emitter_wrapper_issuer.py",
    "bytes": 5548,
    "sha256": "5eb9752617afea5af7ceddfedb9c309fcf7d88fa3da5f3895e7e1a1aae1d7ff8",
    "gitsha": "fad97e3489b06f128270ccc662a9f001ef2aa3b7",
    "mode": "100644"
  },
  {
    "path": "tools/hia_emitter_wrapper_tape.py",
    "bytes": 20087,
    "sha256": "332a8633a13f09fcc6021ebdf1f916e97b65b93f4b875b57264abf7eb93b0287",
    "gitsha": "2f4253bd3c56bda55a5e7d36928c6b8f53ca355a",
    "mode": "100644"
  },
  {
    "path": "tools/hia_function_code_issuer.py",
    "gitsha": "0309b3f34843287552778eefda7962a7f95f4f02",
    "bytes": 21712,
    "sha256": "f126ef9f45988e4eb699e22cd965f3e6057fdcc969e590ebd8e266b520287219",
    "mode": "100644"
  },
  {
    "path": "tools/hia_function_frame_plan.py",
    "gitsha": "bb475cb50848f09dc4fda62ab1aa869bc0b9891d",
    "bytes": 32438,
    "sha256": "27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd",
    "mode": "100644"
  },
  {
    "path": "tools/hia_function_lowering_tape.py",
    "gitsha": "d5b590bb7c67c34e9f994ff550da99358371a281",
    "bytes": 54950,
    "sha256": "e61fcb540bbe51a0e85dc09cd9afa3813b6ba24d6739da2912269c10ce1522eb",
    "mode": "100644"
  },
  {
    "path": "tools/hia_machine_elf_writer.py",
    "gitsha": "3f92d9e185f17f6df8b45d91a4201ce968723073",
    "bytes": 28963,
    "sha256": "84bbd81168ca645807ce0095755bb6e74efb1ffd9419cec3473a439e34dca985",
    "mode": "100644"
  },
  {
    "path": "tools/hia_machine_x64_encoder.py",
    "gitsha": "817443cde4a81402e850086b80ac5de985b62183",
    "bytes": 51420,
    "sha256": "92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a",
    "mode": "100644"
  },
  {
    "path": "ci/read_emitter39_originals.py",
    "mode": "100644",
    "bytes": 15782,
    "sha256": "568fd5333fae984dcb95720eecb2b81019aa5ced1b3558e53f304984cbd4d75b",
    "gitsha": "3c521eafc2aea016e34e04168a7e9aff75f6ee03"
  },
  {
    "path": "evidence/follow39-baseline.json",
    "mode": "100644",
    "bytes": 117059,
    "sha256": "df09c61139a6b3a831c65f8dcf14685d0d2059eca6ecc8fc26077ec648d8ae69",
    "gitsha": "af1359f1485f8c051041136e4ea66653c3510983"
  },
  {
    "path": "evidence/follow39-test-original.py",
    "mode": "100644",
    "bytes": 29760,
    "sha256": "d44389458f0ead3f4b290bfd183a0e3158c73561344d9b3e909bafadd4a19722",
    "gitsha": "98a99f9ee214cb8cf70a402acf5f0167f8696a00"
  },
  {
    "path": "ci/read_emitter41_originals.py",
    "mode": "100644",
    "bytes": 15768,
    "sha256": "6241f504292c1fdd6a27daeade9b1271eec06e7cb305a97c2d94cf7caae7372b",
    "gitsha": "ea4084cc1d3e924ae0786d395c3de0bbd97641b1"
  },
  {
    "path": "evidence/follow41-baseline.json",
    "mode": "100644",
    "bytes": 57443,
    "sha256": "7484b1d6640dde68f748beb928574d601dbce3c3a352465e95b3f5d9bc8cfe26",
    "gitsha": "637c67cc6eb258114e7f4febbec09c3e96321c9a"
  },
  {
    "path": "evidence/follow41-test-original.py",
    "mode": "100644",
    "bytes": 29947,
    "sha256": "9715d73aa19b36acccf05404497010503c146a18137ccca75a8d11f0d804bc41",
    "gitsha": "28152bad4ec34225f76ff852d0e24fad876087d2"
  }
]
SCHEDULE=[["cross",0,2,0],["scalars",0,24,0],["scalars",1,24,0],["scalars",2,24,0],["scalars",3,24,0],["scalars",4,24,0],["scalars",5,24,0],["scalars",6,24,0],["scalars",7,24,0],["scalars",8,24,0],["scalars",9,24,0],["casts",0,20,0],["casts",1,20,0],["casts",2,20,0],["casts",3,20,0],["casts",4,20,0],["casts",5,20,0],["casts",6,20,0],["casts",7,20,0],["casts",8,20,0],["casts",9,20,0],["boolean",0,32,0],["resources",0,30,0],["edges",0,21,0],["calls",0,12,0],["selection",0,16,0],["inventory",0,1,0],["inventory",1,1,0],["inventory",2,1,0],["inventory",3,1,0],["inventory",4,1,0],["borrowed",0,9,0],["borrowed",1,9,0],["borrowed",2,9,0],["borrowed",3,9,0],["borrowed",4,9,0],["borrowed",5,9,0],["borrowed",6,9,0],["borrowed",7,9,0],["manifest",0,36,0],["late",0,1,0],["late",1,1,0],["late",2,1,0],["late",3,1,0],["late",4,1,0],["late",5,1,0],["late",6,1,0],["late",7,1,0],["profile",0,8,0],["protocol",0,20,20],["protocol",1,8,8],["protocol",2,7,7],["protocol",3,5,5],["protocol",4,5,5],["protocol",5,5,5]]
COMPONENTS=("prepare","frame","tape","issuer","wrap_tape","wrap_issuer","encoder","finalizer","finish","elf","controller")
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
OWNER_NAMES=("hia_emitter_prepare.py","hia_function_frame_plan.py","hia_function_lowering_tape.py",
 "hia_function_code_issuer.py","hia_emitter_wrapper_tape.py","hia_emitter_wrapper_issuer.py",
 "hia_machine_x64_encoder.py","hia_machine_x64_encoder.py","hia_emitter_finish.py",
 "hia_machine_elf_writer.py","hia_emitter_controller.py")

def digest(raw):return sha256(raw).hexdigest()
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def load_module(name,path,expected):
 raw=Path(path).read_bytes();assert git_blob(raw)==expected,(str(path),git_blob(raw),expected)
 m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m
 exec(compile(raw,str(path),"exec"),m.__dict__);return m,raw
def original(path,label):
 raw=path.read_bytes()
 for at in range(0,len(raw),18000):
  part=raw[at:at+18000]
  print(label+" "+json.dumps(dict(path=str(path),bytes=len(raw),sha256=digest(raw),
      offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
def summary(directory,label):
 path=directory/"summary.json"
 if not path.exists():return None
 raw=path.read_bytes();value=json.loads(raw)
 print(label+" "+raw.decode().strip(),flush=True);return value
def hash_stream(stream):
 h=sha256();n=0
 while True:
  raw=stream.read(1<<18)
  if not raw:break
  n+=len(raw);h.update(raw)
 return dict(bytes=n,sha256=h.hexdigest())
def file_hash(path):
 with Path(path).open("rb") as f:return hash_stream(f)
def checked_encoded(directory):
 receipt=json.loads((directory/"exact-raw-encoding.json").read_bytes())
 assert receipt["schema"]=="hia-complete-raw-lossless-encoding-v1"
 assert receipt["full_effective_extents_retained"] and receipt["no_target_entry_during_encoding"]
 assert len(receipt["rows"])==2
 for name,row in zip(("trace.bin","final-slots.bin"),receipt["rows"]):
  raw=Path(row["raw_path"]);encoded=Path(row["encoded_path"])
  assert raw==directory/name and encoded==directory/(name+".xz") and not raw.exists()
  assert row["compression"]=="xz-crc64-preset3" and row["all_decoded_bytes_compared_to_actual_raw"]
  assert row["raw"]==row["decoded"] and row["raw_mode"]==row["encoded_mode"]
  assert stat.S_IMODE(encoded.stat().st_mode)==row["raw_mode"] and file_hash(encoded)==row["encoded"]
  with lzma.open(encoded,"rb") as f:assert hash_stream(f)==row["raw"]
 closed=json.loads((directory/"closed-evidence.json").read_bytes())
 assert closed["source_image_before_after_exact"] and closed["complete_event_ACK_trace"]
 assert not closed["all_intermediate_workspaces"]
 assert closed["trace"]==receipt["rows"][0]["raw"] and closed["all_final_slots"]==receipt["rows"][1]["raw"]
 process=json.loads((directory/"process.json").read_bytes())
 assert process["exit_code"]==0 and not process["timeout"] and process["child_reaped"]
 assert process["limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0],wall=180)
 return receipt
def case_rows(directory,value):
 paths=sorted((directory/"cases").glob("*/result.json"))
 rows=[json.loads(path.read_bytes()) for path in paths]
 assert len(rows)==value["cases"] and all(row["status"]=="PASS" for row in rows)
 assert len({row["label"] for row in rows})==len(rows)
 total=0;roles={str(i):0 for i in range(1,12)};encodings=0;fullcas=0;crosses=0
 cats={}
 for path,row in zip(paths,rows):
  cats[row["kind"]]=cats.get(row["kind"],0)+1
  total+=row["native_entries"]+row.get("crosscheck_native_entries",0)
  for field in("by_role","crosscheck_by_role"):
   for role,n in row.get(field,{}).items():roles[str(role)]+=n
  if row["kind"]=="PRIVATE_EMITTER_PERMANENT_BAD":
   assert row["interceptions"] in(0,1)
  else:
   assert row["registry"]["complete_ordered_registry_equal"]
   state=row["code_state"]
   assert state.get("code_not_initialized",False) or state["all_code_bytes_labels_fixups_relocations_equal"]
   if row["error"] is None:
    assert row["complete_text_and_ELF_equal"] and row["text_bytes"]>0 and row["object_bytes"]>0
    assert (path.parent/"actual.text.bin").read_bytes()==(path.parent/"reference.text.bin").read_bytes()
    assert (path.parent/"actual.object.bin").read_bytes()==(path.parent/"reference.object.bin").read_bytes()
   else:assert not row["complete_text_and_ELF_equal"] and row["error"]["text"]
   encoded=checked_encoded(path.parent/"native-trace");encodings+=len(encoded["rows"])
  full=path.parent/"python-full-CAS/source-after.json"
  if full.exists():
   c=json.loads(full.read_bytes());assert c["status"]=="PASS" and c["source_pins_unchanged"] and not c["changed"]
   for key in("all_new_pages_decompressed_equal","all_final_pages_rehashed","full_memory_read_before_after_each_entry","delta_pages_reconstruct_identically"):
    assert c[key],(str(full),key)
   assert c["complete_snapshot_descriptors"]==row["native_entries"]*6
   fullcas+=1
  if row.get("crosscheck") is not None:
   c=row["crosscheck"]
   assert all(c[k] for k in("all_native_header_returns_equal","all_command_ACK_bytes_equal",
        "all_final_slot_bytes_permissions_equal","python_full_intermediate_workspace_CAS_retained"))
   assert not c["native_runner_intermediate_workspaces_recorded"] and row["crosscheck_native_entries"]==row["native_entries"]
   crosses+=1
 assert total==value["native_entries"] and roles==value["by_role"]
 assert cats==value["case_categories"]
 return dict(cases=len(rows),counts=cats,native_entries=total,by_role=roles,
             lossless_raw_files=encodings,python_full_CAS_cases=fullcas,crosscheck_cases=crosses)
OLD_FIXTURE="   doc=self.M.doc(self.W.fixture([\"readbuf\"],[\"u32\"],\"zz\")[\"functions\"][0],\n                 self.W.fixture([\"mutbuf\"],[\"u32\"],\"aa\")[\"functions\"][0])\n   doc[\"exports\"]=[\"zz\",\"aa\"];self.exact(\"missing-exports-sort-first\",doc)"
NEW_FIXTURE="   doc=self.M.doc(self.W.fixture([\"u32\"],[\"u32\",\"u64\"],\"zz\")[\"functions\"][0],\n                 self.W.fixture([\"u64\"],[\"u64\",\"u32\"],\"aa\")[\"functions\"][0])\n   doc[\"exports\"]=[\"zz\",\"aa\"];self.exact(\"missing-exports-sort-first\",doc)\n   assert self.cases[-1][\"error\"]==dict(type=\"HIAProgramNativeRejected\",domain=2,\n       text=\"E_HIA_PROGRAM_ABI: explicit exports have signatures outside the native C ABI: aa, zz\")"

OLD_RESERVED="   doc=self.M.doc(self.M.fn(\"normal\"),self.M.fn(\"abort\"))\n   self.exact(\"reserved-after-complete-function-loop\",doc)"
NEW_RESERVED="   doc=self.M.doc(self.M.fn(\"normal\"),self.M.fn(\"_init\"))\n   from hepta import hia_program as core_reference\n   assert \"abort\" in core_reference._RESERVED_FUNCTIONS\n   assert \"_init\" not in core_reference._RESERVED_FUNCTIONS and \"_init\" in self.original._LOADER_HOOKS\n   assert \"_init\" in self.verify(doc).scalar_entrypoints\n   row=self.exact(\"reserved-after-complete-function-loop\",doc)\n   assert row[\"error\"]==dict(type=\"HIAProgramNativeRejected\",domain=2,\n       text=\"E_HIA_PROGRAM_ABI: export conflicts with the closed runtime or loader ABI\")\n   assert [name for name,frame in row[\"registry\"][\"frames\"]]==[\"normal\",\"_init\"]\n   assert row[\"registry\"][\"exports\"]==[\"normal\"]"
def fixture_delta(project):
 old=(project/"evidence/follow39-test-original.py").read_bytes()
 middle=(project/"evidence/follow41-test-original.py").read_bytes()
 new=(project/"tests/test_hia_complete_emitter.py").read_bytes()
 assert old.count(OLD_FIXTURE.encode())==1
 assert old.replace(OLD_FIXTURE.encode(),NEW_FIXTURE.encode(),1)==middle
 assert middle.count(OLD_RESERVED.encode())==1
 assert middle.replace(OLD_RESERVED.encode(),NEW_RESERVED.encode(),1)==new
 return dict(old_test_git=git_blob(old),previous_test_git=git_blob(middle),new_test_git=git_blob(new),
     two_exact_fixture_only_revisions=True,all_other_tests_and_assertions_byte_identical=True)

def production_pair(component,m,build,old):
 previous=old["manifest"]
 stable={k:v for k,v in m.items() if k not in("source_path","image_path","compile_receipt")}
 previous_stable={k:v for k,v in previous.items() if k not in("source_path","image_path","compile_receipt")}
 assert stable==previous_stable,(component,"changed production manifest")
 ignored=("native_elapsed_ns","wall_elapsed_ns","produced_image")
 assert {k:v for k,v in m["compile_receipt"].items() if k not in ignored}=={
        k:v for k,v in previous["compile_receipt"].items() if k not in ignored},component
 pair={}
 for kind in("source","image"):
  current=Path(m[kind+"_path"]);original=Path(old["paths"][kind])
  assert current.read_bytes()==original.read_bytes(),(component,kind,"production bytes changed")
  assert stat.S_IMODE(current.stat().st_mode)==stat.S_IMODE(original.stat().st_mode)
  pair[kind]=dict(current=str(current),original=str(original),**file_hash(current),
      mode=stat.S_IMODE(current.stat().st_mode),full_bytes_equal=True)
 original_build=Path(old["paths"]["source"]).parents[1]
 before=json.loads((build/"source-before.json").read_bytes())
 after=json.loads((build/"source-after.json").read_bytes())
 old_before=json.loads((original_build/"source-before.json").read_bytes())
 old_after=json.loads((original_build/"source-after.json").read_bytes())
 def source_identity(rows):
  return [(Path(r["path"]).name,r["bytes"],r["sha256"],r["mode"]) for r in rows]
 assert source_identity(before)==source_identity(old_before)
 assert len(before)==len(after) and len(old_before)==len(old_after)
 for rows,ends in((before,after),(old_before,old_after)):
  assert all(a["path"]==b["path"] and a["bytes"]==b["bytes"] and a["sha256"]==b["sha256"] and b["same"]
             for a,b in zip(rows,ends))
 return dict(component=component,profile=m["profile"],pair=pair,
     complete_original_sources_and_images_equal=True,all_build_gate_snapshots_equal=True,
     compile_invariant_receipt_equal=True,snapshots=len(before))

def check_pairs_after(pairs):
 for component,proof in pairs.items():
  for kind,info in proof["pair"].items():
   current=Path(info["current"]);original=Path(info["original"])
   assert current.read_bytes()==original.read_bytes(),(component,kind,"post-run source/image changed")
   assert file_hash(current)=={k:info[k] for k in("bytes","sha256")}
   assert stat.S_IMODE(current.stat().st_mode)==info["mode"]
   assert stat.S_IMODE(original.stat().st_mode)==info["mode"]

def main():
 common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
 common,common_raw=load_module("complete_emitter_ci_common",common_path,COMMON_GIT)
 seal_path=Path(__file__).resolve().with_name("emitter_streamed_finish.py")
 seal,seal_raw=load_module("complete_emitter_streamed_seal",seal_path,SEAL_GIT)
 common.PINS[common_path]=common_raw;common.PINS[seal_path]=seal_raw
 common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
 project=None;status="FAIL"
 report=dict(scope="FRESH_EMITTER_REMAINING_9_GROUPS_AFTER_EXACT_FOLLOW39_AND_41_READBACK",status="INCOMPLETE",
     expected_groups=9,expected_cases=60,expected_private_controls=50,expected_fresh_B3_compilations=11,
     previous_run=43184755381,previous_job=131069068249,previous_run_remains_FAILED=True,
     previous_observed_PASS_groups=44,previous_observed_cases=670,single_run_55_group_PASS=False,
     actual_new_compilations=0,actual_cases=0,actual_native_entries=0,actual_private_controls=0,
     groups={},builds={},old_results_inherited=False,old_44_Emitter_groups_rerun=False,
     old_late4_and_late5_rerun=False,previous_follow41_run=43189935529,previous_follow41_job=131086387011,
     previous_follow41_passed_groups=2,previous_follow41_passed_cases=2,old_39_Function_groups_rerun=False,
     old_26_wrapper_groups_rerun=False,full_public_backend=False,installed=False,cold=False,
     host_instruction_symbol_or_ELF_encoding=False,C_mechanics_is_development_TCB=True,
     source_Graph_must_be_actual_immutable_admitted_Core_and_checked_plan=True,header_is_authentication=False)
 try:
  context=common.prepare()
  mine=Path(context["base"])/"complete-emitter-recovery-r4";mine.mkdir()
  project=mine/"native-emitter-next";project.mkdir()
  for row in FILES:
   source=common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
   raw=source.read_bytes();assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
   source.chmod(int(row["mode"],8)&0o777)
  (project/"ci-driver-original.py").write_bytes(Path(__file__).read_bytes())
  env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8")
  report["fixture_delta"]=fixture_delta(project)
  originals=project/"development/follow39-readonly"
  try:
   common.run("emitter-follow39-exact-originals",[context["python"],"-B",project/"ci/read_emitter39_originals.py",
       "--artifact-directory",Path(os.environ["HIA_EMITTER39_ORIGINALS"]).resolve(),
       "--baseline",project/"evidence/follow39-baseline.json","--out",originals],
       cwd=project,timeout=180,env=env)
  finally:
   report["original_readback"]=summary(originals,"HIA_EMITTER39_EXACT_ORIGINAL_READBACK")
  old=report["original_readback"]
  assert old["status"]=="PASS" and old["native_entries"]==old["VM_entries"]==old["product_imports"]==old["subprocesses"]==0
  assert old["limits"]==dict(**LIMITS,wall=180)
  assert old["actual_original_passed_cases"]==670 and old["actual_original_native_entries"]==1549752
  assert old["all_members"]==43774 and old["all_member_bytes"]==1012497507
  assert old["all_original_gate_source_snapshots_verified"] and old["full_tar_bytes_modes_and_SHA256_equal"]
  assert old["all_45_original_groups_bound_to_the_same_eleven_actual_images"]
  assert old["complete_original_encoded_inputs_preserved"] and old["full_tar_readback_completed"]
  assert old["all_recorded_inputs_after_checked_equal"]
  baseline=json.loads((project/"evidence/follow39-baseline.json").read_bytes())
  assert SCHEDULE==baseline["planned_all_55"]
  assert SCHEDULE[:44]==baseline["passed_first_44"]==old["actual_original_passed_groups"]
  assert SCHEDULE[44:]==baseline["remaining_11"]
  baseline41=json.loads((project/"evidence/follow41-baseline.json").read_bytes())
  assert baseline41["planned_all_55"]==SCHEDULE and baseline41["passed_before_failure"]==SCHEDULE[44:46]
  tail=SCHEDULE[46:]
  assert tail==baseline41["remaining_9"] and len(tail)==9 and sum(x[2] for x in tail)==60 and sum(x[3] for x in tail)==50
  originals41=project/"development/follow41-readonly"
  try:
   common.run("emitter-follow41-exact-originals",[context["python"],"-B",project/"ci/read_emitter41_originals.py",
       "--artifact-directory",Path(os.environ["HIA_EMITTER41_ORIGINALS"]).resolve(),
       "--baseline",project/"evidence/follow41-baseline.json","--out",originals41],
       cwd=project,timeout=180,env=env)
  finally:
   report["follow41_readback"]=summary(originals41,"HIA_EMITTER41_EXACT_ORIGINAL_READBACK")
  old41=report["follow41_readback"]
  assert old41["status"]=="PASS" and old41["native_entries"]==old41["VM_entries"]==old41["product_imports"]==old41["subprocesses"]==0
  assert old41["limits"]==dict(**LIMITS,wall=180)
  assert old41["all_members"]==7985 and old41["all_member_bytes"]==404149551
  assert old41["actual_original_passed_groups"]==SCHEDULE[44:46]
  assert old41["actual_original_passed_cases"]==2 and old41["actual_original_native_entries"]==731
  assert old41["all_original_gate_source_snapshots_verified"] and old41["full_tar_bytes_modes_and_SHA256_equal"]
  assert old41["all_3_original_groups_bound_to_the_same_eleven_actual_images"]
  assert old41["complete_original_encoded_inputs_preserved"] and old41["full_tar_readback_completed"]
  assert old41["all_recorded_inputs_after_checked_equal"]
  old_pairs41=json.loads((originals41/"actual-source-image-pairs.json").read_bytes())
  assert set(old_pairs41)==set(COMPONENTS)
  report["production_identity_follow41"]={}
  old_pairs=json.loads((originals/"actual-source-image-pairs.json").read_bytes())
  assert set(old_pairs)==set(COMPONENTS)
  report["production_identity"]={}
  roles={}
  for index,component in enumerate(COMPONENTS,1):
   build=project/"development"/("build-"+component+"-r4")
   try:
    common.run("emitter-fresh-"+component,[context["python"],"-B",project/"tools/build_hia_complete_emitter.py",
       "--reference",context["reference"],"--compiler",context["compiler"],"--out",build,"--component",component],
       cwd=project,timeout=180,env=env)
   finally:
    value=summary(build,"HIA_COMPLETE_EMITTER_BUILD_ORIGINAL")
    if value is not None:
     report["builds"][component]=value
     report["actual_new_compilations"]=sum(v.get("compilations",0) for v in report["builds"].values())
    if build.exists():
     for p in sorted(set(build.rglob("*.stderr"))|set(build.rglob("*.stderr.log"))):original(p,"HIA_COMPLETE_EMITTER_NESTED_STDERR")
     for p in sorted(build.glob("*/profile-before-gates.json")):original(p,"HIA_COMPLETE_EMITTER_PROFILE_ORIGINAL")
   value=report["builds"][component]
   assert value["status"]=="PASS_BUILD_ONLY" and value["source_pins_unchanged"]
   assert value["actual_limits"]==LIMITS and value["compilations"]==1 and value["native_semantic_entries"]==0
   assert set(value["components"])=={component}
   m=value["components"][component]
   owner=next(row for row in FILES if row["path"]=="tools/"+OWNER_NAMES[index-1])
   assert m["schema"]=="hepta.hia.complete-emitter-development.v1" and m["status"]=="BUILT_ONLY"
   assert (m["component"],m["role"],m["author_sha256"])==(component,index,owner["sha256"])
   assert m["compiler_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
   p=m["profile"];r=m["compile_receipt"]
   assert p["functions"]<=128 and p["blocks"]<=1536 and p["ops"]<=8192
   assert p["max_blocks"]<=256 and p["max_params"]<=16 and p["max_ssa_index"]<2048
   assert p["max_function_values"]==p["max_ssa_index"]+1
   assert r["limits"]["cpu_seconds"]==10 and r["limits"]["address_bytes"]==256<<20
   assert r["source_unchanged"] and not r["forbidden_compiler_modules_loaded"]
   for typ in("source","image"):
    assert 0<m[typ+"_bytes"]<=1<<20 and file_hash(m[typ+"_path"])=={"bytes":m[typ+"_bytes"],"sha256":m[typ+"_sha256"]}
   report["production_identity"][component]=production_pair(component,m,build,old_pairs[component])
   report["production_identity_follow41"][component]=production_pair(component,m,build,old_pairs41[component])
   roles[str(index)]=dict(name=component,manifest=m)
  assert report["actual_new_compilations"]==11 and set(roles)=={str(i) for i in range(1,12)}
  assets=project/"development/runtime-assets.json"
  save(assets,dict(schema="hia-emitter-development-runtime-assets-v1",roles=roles,
       actual_fresh_B3_compilations=11,old_results_inherited=False))
  nativebuild=project/"development/native-mechanics-build-r4"
  c_label="emitter-development-C-mechanics-build"
  common.run(c_label,[context["python"],"-B",project/"tools/build_emitter_native_mechanics.py",
      "--stage","build","--source",project/"tools/emitter_native_mechanics.c","--out",nativebuild],
      cwd=project,timeout=180,env=env)
  common.run("emitter-development-C-mechanics-seal",[context["python"],"-B",project/"tools/build_emitter_native_mechanics.py",
      "--stage","seal","--source",project/"tools/emitter_native_mechanics.c","--out",nativebuild,
      "--receipt",common.OUTPUT/"steps"/c_label/"process.json"],cwd=project,timeout=180,env=env)
  report["C_mechanics_build"]=summary(nativebuild,"HIA_EMITTER_C_BUILD_ORIGINAL")
  assert report["C_mechanics_build"]["status"]=="PASS_BUILD_ONLY"
  carrier=nativebuild/"emitter-native-mechanics"
  assert report["C_mechanics_build"]["compiler"]==baseline["actual_C_build"]["compiler"]
  assert report["C_mechanics_build"]["source_sha256"]==baseline["actual_C_build"]["source_sha256"]
  assert report["C_mechanics_build"]["executable"]==baseline["actual_C_build"]["executable"]
  assert carrier.read_bytes()==Path(old["old_C_executable"]).read_bytes()
  assert stat.S_IMODE(carrier.stat().st_mode)==stat.S_IMODE(Path(old["old_C_executable"]).stat().st_mode)
  assert carrier.read_bytes()==Path(old41["old_C_executable"]).read_bytes()
  assert stat.S_IMODE(carrier.stat().st_mode)==stat.S_IMODE(Path(old41["old_C_executable"]).stat().st_mode)
  report["development_carrier_complete_original_bytes_equal"]=True
  assert len(SCHEDULE)==55 and sum(r[2] for r in SCHEDULE)==732 and sum(r[3] for r in SCHEDULE)==50
  for group,variant,count,private in tail:
   label=group+"-"+str(variant);out=project/"development"/("native-"+label+"-r4")
   try:
    common.run("emitter-whole-"+label,[context["python"],"-B",project/"tests/test_hia_complete_emitter.py",
       "--assets",assets,"--carrier",carrier,"--reference",context["reference"],"--out",out,
       "--group",group,"--variant",str(variant)],cwd=project,timeout=180,env=env)
   finally:
    value=summary(out,"HIA_COMPLETE_EMITTER_GROUP_ORIGINAL")
    if value is not None:
     report["groups"][label]=value
     for target,field in(("actual_cases","cases"),("actual_native_entries","native_entries"),("actual_private_controls","private_protocol_controls")):
      report[target]=sum(r.get(field,0) for r in report["groups"].values())
    else:report.setdefault("missing_group_summaries",[]).append(label)
   value=report["groups"][label]
   assert value["status"]=="PASS" and (value["group"],value["variant"])==(group,variant)
   assert (value["cases"],value["private_protocol_controls"])==(count,private)
   assert value["limits"]==dict(**LIMITS,wall=180)
   assert value["native_entries"]==sum(value["by_role"].values())
   assert value["source_custody"]["all_bytes_and_modes_equal"]
   assert value["original_group_limits_include_evidence_encoding"]
   assert not any(value[k] for k in("full_public_backend","installed","cold","host_instruction_or_ELF_generation"))
   value["independent_case_readback"]=case_rows(out,value)
  assert len(report["groups"])==9 and (report["actual_cases"],report["actual_private_controls"])==(60,50)
  cats={name:sum(v["case_categories"].get(name,0) for v in report["groups"].values())
     for name in("WHOLE_NATIVE_EMITTER","PRIVATE_EMITTER_PROFILE","PRIVATE_EMITTER_PERMANENT_BAD")}
  assert cats==dict(WHOLE_NATIVE_EMITTER=2,PRIVATE_EMITTER_PROFILE=8,PRIVATE_EMITTER_PERMANENT_BAD=50)
  assert sum(v["independent_case_readback"]["crosscheck_cases"] for v in report["groups"].values())==0
  assert sum(v["independent_case_readback"]["python_full_CAS_cases"] for v in report["groups"].values())==50
  assert sum(v["independent_case_readback"]["lossless_raw_files"] for v in report["groups"].values())==20
  check_pairs_after(report["production_identity"])
  check_pairs_after(report["production_identity_follow41"])
  assert carrier.read_bytes()==Path(old41["old_C_executable"]).read_bytes()
  assert carrier.read_bytes()==Path(old["old_C_executable"]).read_bytes()
  assert file_hash(carrier)==baseline["actual_C_build"]["executable"]
  fixture_delta(project)
  previous=old["actual_original_passed_groups"]
  assert not ({(g,v) for g,v,_,_ in previous}&{(g,v) for g,v,_,_ in tail})
  middle=old41["actual_original_passed_groups"]
  assert previous+middle+tail==SCHEDULE
  assert len({(g,v) for g,v,_,_ in previous+middle+tail})==55
  report["three_distinct_run_coverage"]=dict(
      same_eleven_production_source_and_image_bytes_before_after=True,
      previous=dict(run=43184755381,job=131069068249,status="FAIL",passed_groups=previous,
                    passed_cases=670,native_entries=1549752),
      middle=dict(run=43189935529,job=131086387011,status="FAIL",passed_groups=middle,passed_cases=2,native_entries=731),
      current=dict(groups=tail,cases=60,native_entries=report["actual_native_entries"]),
      original_schedule_55_covered_without_omission=True,
      combined_cases=732,single_run_55_group_PASS=False)

  report.update(status="PASS",case_categories=cats,
      actual_by_role={str(i):sum(v["by_role"][str(i)] for v in report["groups"].values()) for i in range(1,12)},
      canonical_HIA_source_document_profile_actual_image_retained=True,
      exact_complete_machine_text_ELF_errors_and_surviving_Code_registry_equal=True,
      complete_image_input_command_ACK_and_final_slot_evidence=True,
      all_large_case_intermediate_workspaces_recorded=False,
      current_50_protocol_full_intermediate_CAS_retained=True,
      old_2_crosschecks_preserved_in_exact_original_artifact=True)
  status="PASS"
 except BaseException as error:
  report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  roots={}
  if project is not None and project.exists():roots["emitter-full"]=project
  seal.finish(common,"emitter-full-r4-tail9",status,report,roots=roots)
 if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
