"""Fresh two-image ELF64 inventory gate; exact old errors and complete buffers."""
from pathlib import Path
from hashlib import sha1,sha256
from collections import OrderedDict
import base64,importlib.util,json,os,stat,sys,traceback,types,zlib
sys.dont_write_bytecode=True
PREFIX="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/object-inventory-r1/"
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
SEAL_GIT="ea7a0c34555fc75835c507dc13ffe9e071137dd9"
FILES=[
  {
    "path": "tools/hia_elf_object_inventory.py",
    "mode": "100644",
    "bytes": 19368,
    "sha256": "5b8807b7eaee30a04c12fe2d96a5c457abb0a6f2517804e6b001fbbfc32d16ce",
    "gitsha": "e1088c710fdfc5645b5789e888a63a820c0bf5a0"
  },
  {
    "path": "tools/build_hia_elf_object_inventory.py",
    "mode": "100644",
    "bytes": 9660,
    "sha256": "9de076f55dfc086e6cb5e25b90cff032ca2c54a97f654bf7ebc9bf7bd1f50388",
    "gitsha": "ad73ef119a6e642e23cd1facda668d84f85351e3"
  },
  {
    "path": "tests/test_hia_elf_object_inventory.py",
    "mode": "100644",
    "bytes": 26540,
    "sha256": "1028a5262ed806faaf534453cdb3ef0d308de6b77bc955939abc5ad601cc73bb",
    "gitsha": "9084a7a6f0b56f32fe3d94bba7c3f4f33b82d198"
  },
  {
    "path": "docs/HIA_ELF_OBJECT_INVENTORY_NATIVE.md",
    "mode": "100644",
    "bytes": 14522,
    "sha256": "d1a4d657850402731d6b2230ada50e504df8d3d529b48a3fe731e7bb83b1ecda",
    "gitsha": "41aac2c36722b8d230feaacee6be88ec7912f217"
  },
  {
    "path": "ci/streamed_evidence_finish.py",
    "mode": "100644",
    "bytes": 6120,
    "sha256": "6da813d4be8fd4f268f90ce063e3aadc011e0aae0832163d02f5b6640555e96e",
    "gitsha": "ea7a0c34555fc75835c507dc13ffe9e071137dd9"
  },
  {
    "path": "tools/hia_machine_elf_writer.py",
    "mode": "100644",
    "bytes": 28963,
    "sha256": "84bbd81168ca645807ce0095755bb6e74efb1ffd9419cec3473a439e34dca985",
    "gitsha": "3f92d9e185f17f6df8b45d91a4201ce968723073"
  },
  {
    "path": "tools/function_authoring_reference.py",
    "mode": "100644",
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b",
    "gitsha": "6f1bffe8bd815a068f9834489960006cbaad6fac"
  },
  {
    "path": "tools/hia_agent_edit_source_views.py",
    "mode": "100644",
    "bytes": 23950,
    "sha256": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c",
    "gitsha": "f7d123bdb2bf65b25182b571f024299cb0342828"
  },
  {
    "path": "tests/function_frame_test_reference.py",
    "mode": "100644",
    "bytes": 42184,
    "sha256": "b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6",
    "gitsha": "a7d64f7804753398df08e69158bcebb7afc54747"
  },
  {
    "path": "reference/hia_selfhost_child.py",
    "mode": "100644",
    "bytes": 6791,
    "sha256": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29",
    "gitsha": "2ecbf3a04680eceee0537cb3d621073bac9c52f4"
  },
  {
    "path": "reference/hia_program_native.py",
    "mode": "100644",
    "bytes": 46917,
    "sha256": "bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c",
    "gitsha": "1d0e0344f8300b11b5dd505cbea655170aba5be1"
  },
  {
    "path": "reference/object_structure.py",
    "mode": "100644",
    "bytes": 6155,
    "sha256": "4fb0b3d962e4b7f6ba508257bf605f4403d402e4f3d7e05cffa084b91651f5a8",
    "gitsha": "5231ee37ef4ca65a3175a1162178ea21b9503082"
  },
  {
    "path": "reference/object_symbols.py",
    "mode": "100644",
    "bytes": 14652,
    "sha256": "aff81d724d08ed4a8c3189e3370f75e234daa010ec9e9855aedc1019d55a693f",
    "gitsha": "9476bc3346cdc5e778a145f50c46c30190112780"
  },
  {
    "path": "reference/hia_machine_elf.py",
    "mode": "100644",
    "bytes": 7026,
    "sha256": "c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101",
    "gitsha": "cad2e6d21dccc95ad3cfd368da42964ec52d4bb7"
  }
]
SCHEDULE=[["headers",0,78],["sections",0,21],["tables",0,23],["bindings",0,65],["names",0,127],["names",1,128],["names",2,7],["definitions",0,48],["duplicates",0,9],["closed",0,21],["multi",0,8],["grow",0,3],["large",0,1],["large",1,1],["large",2,1],["large",3,1],["bytes",0,1],["bytes",1,1],["protocol",0,27],["producer",0,8]]
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def load(name,path,expected):
 raw=Path(path).read_bytes();assert gitsha(raw)==expected,(str(path),gitsha(raw),expected)
 m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m
 exec(compile(raw,str(path),"exec"),m.__dict__);return m,raw
def summary(directory,label):
 path=directory/"summary.json"
 if not path.exists():return None
 raw=path.read_bytes();print(label+" "+raw.decode().strip(),flush=True);return json.loads(raw)
def original(path,label):
 raw=path.read_bytes()
 for at in range(0,len(raw),18000):
  chunk=raw[at:at+18000]
  print(label+" "+json.dumps(dict(path=str(path),bytes=len(raw),sha256=digest(raw),
      offset=at,part_bytes=len(chunk),base64=base64.b64encode(chunk).decode()),sort_keys=True),flush=True)
def filehash(path):
 h=sha256();n=0
 with Path(path).open("rb") as stream:
  while True:
   raw=stream.read(1<<18)
   if not raw:break
   h.update(raw);n+=len(raw)
 return dict(bytes=n,sha256=h.hexdigest())

class CASReader:
 def __init__(self,root):
  self.root=root;self.cache=OrderedDict();self.sizes={}
  for path in sorted((root/"cas").glob("*.zlib")):
   raw=zlib.decompress(path.read_bytes());h=path.name[:-5]
   assert 0<len(raw)<=4096 and digest(raw)==h and h not in self.sizes
   self.sizes[h]=len(raw)
 def page(self,h):
  if h in self.cache:
   self.cache.move_to_end(h);return self.cache[h]
  raw=zlib.decompress((self.root/"cas"/(h+".zlib")).read_bytes())
  assert len(raw)==self.sizes[h] and digest(raw)==h
  self.cache[h]=raw
  if len(self.cache)>2048:self.cache.popitem(last=False)
  return raw
 def verify(self,descriptor,return_bytes=False):
  h=sha256();n=0;output=bytearray() if return_bytes else None
  assert descriptor["page_size"]==4096
  for i,key in enumerate(descriptor["pages"]):
   raw=self.page(key);assert len(raw)==min(4096,descriptor["bytes"]-i*4096)
   h.update(raw);n+=len(raw)
   if output is not None:output.extend(raw)
  assert n==descriptor["bytes"] and h.hexdigest()==descriptor["sha256"]
  return bytes(output) if output is not None else None
 def snapshots(self):
  previous={};meta={};count=0;logical=0
  with (self.root/"snapshots.jsonl").open() as stream:
   for line in stream:
    row=json.loads(line);assert row["id"]==count and row["page_size"]==4096
    old=previous.get(row["key"])
    assert row["base"]==(None if old is None else old[0])
    prior=[] if old is None else old[1]
    pages=list(prior[:row["page_count"]])+[None]*max(0,row["page_count"]-len(prior))
    changed=set()
    for i,h in row["changed"]:
     assert i not in changed and 0<=i<len(pages);changed.add(i);pages[i]=h
    assert None not in pages
    self.verify(dict(bytes=row["bytes"],sha256=row["sha256"],page_size=4096,pages=pages))
    previous[row["key"]]=(row["id"],pages)
    meta[count]={k:row[k] for k in("id","key","bytes","sha256")}
    logical+=row["bytes"];count+=1
  return meta,logical

def check_cases(out,value):
 cas=CASReader(out/"full-CAS");meta,logical=cas.snapshots()
 entered={};returned=0;roles={"inventory":0,"elf-producer":0}
 with (out/"full-CAS/entries.jsonl").open() as stream:
  for line in stream:
   row=json.loads(line);number=row["number"]
   if row["status"]=="ENTERING":
    assert number not in entered and number==len(entered);entered[number]=row
    assert len(row["before"])==3 and row["readonly"]==[True,True,False]
    for v in row["before"]:assert meta[v["id"]]==v
   else:
    assert row["status"]=="RETURNED" and number==returned
    original=entered[number];assert row["before"]==original["before"]
    assert row["readonly_bytes_equal"] and row["all_canaries_intact"]
    for v in row["after"]:assert meta[v["id"]]==v
    assert all(row["before"][i]["sha256"]==row["after"][i]["sha256"] for i in(0,1))
    roles[row["role"]]+=1;returned+=1
 assert returned==len(entered)==value["native_entries"]==sum(value["by_role"].values())
 assert roles==value["by_role"] and len(meta)==6*returned
 proof=json.loads((out/"full-CAS/source-after.json").read_bytes())
 assert proof["status"]=="PASS" and proof["complete_snapshot_descriptors"]==len(meta)
 assert proof["logical_buffer_bytes"]==logical and proof["cas_pages"]==len(cas.sizes)
 assert proof["all_new_pages_decompressed_equal"] and proof["all_final_pages_rehashed"]
 assert proof["full_memory_read_before_after_each_entry"] and proof["delta_pages_reconstruct_identically"]
 sources=json.loads((out/"source-before-after.json").read_bytes())
 assert sources and all(row["same"] for row in sources)
 for row in sources:
  assert stat.S_IMODE(Path(row["path"]).stat().st_mode)==row["mode"]
  assert filehash(row["path"])==dict(bytes=row["bytes"],sha256=row["sha256"])
 cases=[json.loads(path.read_bytes()) for path in sorted((out/"cases").glob("*.json"))]
 assert len(cases)==value["cases"] and len({r["label"] for r in cases})==len(cases)
 case_roles={"inventory":0,"elf-producer":0};errors=set();private=0;joins=0
 for row in cases:
  assert row["status"]=="PASS"
  cas.verify(row["object"]);cas.verify(row["expected_command"])
  for role,count in row["actual_entries"].items():case_roles[role]+=count
  event=row["event"]
  if row["kind"]=="PRIVATE_ABI_BAD":
   private+=1
   if event is not None:assert event[:3]==[int.from_bytes(b"HIAMIE01","little"),1,3] and event[15]!=0
   continue
  payload=cas.verify(row["result"],True)
  assert row["original_error_class_and_complete_text_equal"]
  if row["expected"]["error"] is None:
   expected=json.dumps(row["expected"]["value"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
   assert payload==expected and row["complete_sorted_inventory_equal"] and event[2]==0
  else:
   expected=row["expected"]["error"];assert payload.decode("ascii")==expected["text"]
   assert event[2]==2 and event[6]==(2 if expected["class_name"]=="HIAProgramNativeRejected" else 1)
   errors.add(event[7])
  if row["kind"]=="ACTUAL_NATIVE_ELF_PRODUCER_JOIN":
   joins+=1;p=row["native_producer"]
   assert p["complete_native_object_equals_original_writer"] and p["raw_object_opaque_forwarded"]
   for name in("graph","command","object"):cas.verify(p[name])
   assert p["object"]["sha256"]==row["object"]["sha256"] and p["object"]["bytes"]==row["object"]["bytes"]
 assert case_roles==roles and private==value["private_controls"] and joins==value["actual_native_producer_joins"]
 return dict(cases=len(cases),native_entries=returned,by_role=roles,private_controls=private,
     native_producer_joins=joins,semantic_error_ids=sorted(errors),cas_pages=len(cas.sizes),
     complete_snapshots=len(meta),complete_logical_bytes=logical,full_originals_independently_read=True)

def main():
 common_path=Path(os.environ["HIA_CI_COMMON"]).resolve();common,raw=load("inventory_ci_common",common_path,COMMON_GIT)
 sealpath=Path(__file__).resolve().with_name("streamed_evidence_finish.py");seal,sealraw=load("inventory_streamed_seal",sealpath,SEAL_GIT)
 common.PINS[common_path]=raw;common.PINS[sealpath]=sealraw;common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
 project=None;status="FAIL"
 report=dict(status="INCOMPLETE",scope="ELF64_62_STRUCTURE_SYMBOLS_AND_DIRECT_BACKEND_INVENTORY",
     planned_groups=20,planned_cases=579,planned_private_controls=27,planned_actual_producer_joins=8,
     actual_new_compilations=0,actual_cases=0,actual_native_entries=0,groups={},builds={},
     old_results_inherited=False,whole_emitter_join=False,full_public_backend=False,
     COFF_or_MachO=False,shared_library_inspection=False,installed=False,cold=False)
 try:
  c=common.prepare();mine=Path(c["base"])/"object-inventory-recovery-r1";mine.mkdir()
  project=mine/"native-object-inventory-next";project.mkdir()
  for row in FILES:
   path=common.materialize(PREFIX+row["path"],row["gitsha"],project/row["path"])
   data=path.read_bytes();assert len(data)==row["bytes"] and digest(data)==row["sha256"]
   path.chmod(int(row["mode"],8)&0o777)
  (project/"ci-driver-original.py").write_bytes(Path(__file__).read_bytes())
  env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=c["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8")
  manifests={}
  for component in("inventory","elf-producer"):
   out=project/"development"/("build-"+component+"-r1")
   try:
    common.run("object-inventory-build-"+component,[c["python"],"-B",project/"tools/build_hia_elf_object_inventory.py",
       "--reference",c["reference"],"--compiler",c["compiler"],"--out",out,"--component",component],
       cwd=project,timeout=180,env=env)
   finally:
    v=summary(out,"HIA_OBJECT_INVENTORY_BUILD_ORIGINAL")
    if v is not None:
     report["builds"][component]=v;report["actual_new_compilations"]=sum(x.get("compilations",0) for x in report["builds"].values())
    if out.exists():
     for p in sorted(set(out.rglob("*.stderr"))|set(out.rglob("*.stderr.log"))):original(p,"HIA_OBJECT_INVENTORY_NESTED_STDERR")
     if (out/"profile-before-gates.json").exists():original(out/"profile-before-gates.json","HIA_OBJECT_INVENTORY_PROFILE")
   v=report["builds"][component]
   assert v["status"]=="PASS_BUILD_ONLY" and v["source_pins_unchanged"] and v["limits"]==LIMITS
   assert v["compilations"]==1 and v["native_semantic_entries"]==0
   m=v["manifest"];p=m["profile"];r=m["compile_receipt"]
   assert m["component"]==component and m["status"]=="BUILT_ONLY"
   expected_owner=next(x for x in FILES if x["path"]==("tools/hia_elf_object_inventory.py" if component=="inventory" else "tools/hia_machine_elf_writer.py"))
   assert m["author_sha256"]==expected_owner["sha256"]
   assert p["functions"]<=128 and p["blocks"]<=1536 and p["ops"]<=8192
   assert p["max_blocks"]<=256 and p["max_params"]<=16 and p["max_ssa_index"]<2048
   assert m["compiler_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
   assert r["limits"]["cpu_seconds"]==10 and r["limits"]["address_bytes"]==256<<20
   for typ in("source","image"):assert filehash(m[typ+"_path"])==dict(bytes=m[typ+"_bytes"],sha256=m[typ+"_sha256"])
   manifests[component]=out/"inventory.manifest.json"
  assert report["actual_new_compilations"]==2
  assert len(SCHEDULE)==20 and sum(row[2] for row in SCHEDULE)==579
  for group,variant,count in SCHEDULE:
   label=group+"-"+str(variant);out=project/"development"/("native-"+label+"-r1")
   try:
    common.run("object-inventory-"+label,[c["python"],"-B",project/"tests/test_hia_elf_object_inventory.py",
       "--reference",c["reference"],"--inventory",manifests["inventory"],"--producer",manifests["elf-producer"],
       "--out",out,"--group",group,"--variant",str(variant)],cwd=project,timeout=180,env=env)
   finally:
    v=summary(out,"HIA_OBJECT_INVENTORY_GROUP_ORIGINAL")
    if v is not None:
     report["groups"][label]=v
     report["actual_cases"]=sum(x.get("cases",0) for x in report["groups"].values())
     report["actual_native_entries"]=sum(x.get("native_entries",0) for x in report["groups"].values())
    else:report.setdefault("missing_group_summaries",[]).append(label)
   v=report["groups"][label]
   assert v["status"]=="PASS" and v["group"]==group and v["variant"]==variant and v["cases"]==count
   assert v["all_planned_cases_passed"] and v["completed_cases_compared_in_full"]
   assert v["limits"]==dict(**LIMITS,wall=180) and v["source_custody"]["all_bytes_and_modes_equal"]
   v["independent_readback"]=check_cases(out,v)
  values=report["groups"].values()
  assert len(report["groups"])==20 and report["actual_cases"]==579
  controls=sum(v["private_controls"] for v in values);joins=sum(v["actual_native_producer_joins"] for v in values)
  errors=set().union(*(set(v["independent_readback"]["semantic_error_ids"]) for v in values))
  assert controls==27 and joins==8 and errors==set(range(1,18))
  report.update(status="PASS",actual_private_controls=controls,actual_native_producer_joins=joins,
      all_17_original_semantic_errors_observed=True,
      actual_by_role={role:sum(v["by_role"][role] for v in values) for role in("inventory","elf-producer")},
      canonical_HIA_document_source_and_actual_images_preserved=True,
      all_three_complete_buffers_before_after_every_entry=True)
  status="PASS"
 except BaseException as error:
  report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  roots={"object-inventory":project} if project is not None and project.exists() else {}
  seal.finish(common,"object-inventory-r1",status,report,roots=roots)
 if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
