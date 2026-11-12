"""Fresh five-role checked-plan build; no old build result is inherited.

This is development authoring. Each invocation has 90 CPU/180 wall/1 GiB,
and the actual fixed 35ee B3 child remains 10 CPU/20 wall/256 MiB.
The two bounded GraphWire sources are complete already-published HIA, not
host serializers. All five canonical HIA/document/image originals are retained.
"""
from pathlib import Path
from hashlib import sha256
import argparse,importlib.abc,importlib.util,json,resource,stat,sys,time,traceback,types
sys.dont_write_bytecode=True
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
PINS={
 "tools/hia_frozen_ssa_rename.py":"ceafde9ccf11f5d58de8519821e8b29061de9c967c636a63901735c93f3f419b",
 "tools/hia_checked_machine_plan.py":"8fd64a521afb771255d112e40fe7586b1c46c69f343fe5bdd6d42e643d205336",
 "tools/hia_checked_plan_controller.py":"d15c8141db699d1f6df0e6753f6220905903911cf6bd1a01accc41fbbf5103f6",
 "tools/hia_composite_lowering_driver_common.py":"fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1",
 "tools/function_authoring_reference.py":"717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b",
 "tools/hia_agent_edit_source_views.py":"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c",
 "reference/hia_machine_plan.py":"ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a",
 "reference/hia_program.py":"76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92",
 "reference/hia_selfhost_child.py":"1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29",
}
WIRE={
 "wire_scan":dict(bytes=147822,sha256="c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3"),
 "wire_emit":dict(bytes=173680,sha256="9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2")
}
ROLES={"snapshot":1,"wire_scan":2,"wire_emit":3,"semantics":4,"controller":5}
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
class FrozenImports(importlib.abc.MetaPathFinder,importlib.abc.Loader):
 def __init__(self,root,files):self.root,self.files=root,files
 def find_spec(self,fullname,path=None,target=None):
  if fullname.split(".")[0] not in("hepta","tools"):return None
  base=self.root.joinpath(*fullname.split("."))
  for candidate,package in((base.with_suffix(".py"),False),(base/"__init__.py",True)):
   if candidate in self.files:
    return importlib.util.spec_from_file_location(fullname,candidate,loader=self,
       submodule_search_locations=[str(base)] if package else None)
  if any(p.is_relative_to(base) for p in self.files):
   spec=importlib.util.spec_from_loader(fullname,loader=None,is_package=True)
   spec.submodule_search_locations=[str(base)];return spec
  raise ModuleNotFoundError("file absent from immutable reference snapshot: "+fullname)
 def create_module(self,spec):return None
 def exec_module(self,module):
  path=Path(module.__spec__.origin);exec(compile(self.files[path],str(path),"exec"),module.__dict__)
def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 p=argparse.ArgumentParser()
 for name in("reference","compiler","out"):p.add_argument("--"+name,type=Path,required=True)
 p.add_argument("--component",choices=tuple(ROLES),required=True);p.add_argument("--wire-source",type=Path)
 args=p.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
 root=Path(__file__).resolve().parents[1];reference=args.reference.resolve();component=args.component
 started=time.monotonic();pins={};modes={}
 result=dict(status="INCOMPLETE",scope="FRESH_CHECKED_PLAN_SINGLE_COMPONENT",
   component=component,compilations=0,native_semantic_entries=0,old_results_inherited=False,
   full_public_backend=False,installed=False,cold=False,original_limits_unchanged=True)
 def read(path,expected=None):
  path=Path(path).absolute();info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
  path=path.resolve();raw=path.read_bytes()
  if expected is not None:assert digest(raw)==expected,(str(path),digest(raw),expected)
  if path in pins:assert pins[path]==raw
  else:pins[path]=raw;modes[path]=stat.S_IMODE(info.st_mode)
  return raw
 def load(name,path,expected):
  raw=read(path,expected);module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
  exec(compile(raw,str(path),"exec"),module.__dict__);return module
 try:
  assert sys.version_info[:3]==(3,12,14)
  read(__file__)
  for name,h in PINS.items():read(root/name,h)
  assert len(read(args.compiler,COMPILER_SHA))==669556
  frozen={path.resolve():read(path) for prefix in("hepta","tools") for path in sorted((reference/prefix).rglob("*.py"))}
  sys.meta_path.insert(0,FrozenImports(reference,frozen))
  load("tools.hia_agent_edit_source_views",root/"tools/hia_agent_edit_source_views.py",PINS["tools/hia_agent_edit_source_views.py"])
  author=load("checked_plan_author",root/"tools/function_authoring_reference.py",PINS["tools/function_authoring_reference.py"])
  owner=load("checked_plan_values",root/"tools/hia_checked_machine_plan.py",PINS["tools/hia_checked_machine_plan.py"])
  control=load("checked_plan_control",root/"tools/hia_checked_plan_controller.py",PINS["tools/hia_checked_plan_controller.py"])
  common=load("checked_plan_lower_common",root/"tools/hia_composite_lowering_driver_common.py",PINS["tools/hia_composite_lowering_driver_common.py"])
  assert owner.REFERENCE_SHA==PINS["reference/hia_machine_plan.py"]
  assert owner.CORE_REFERENCE_SHA==PINS["reference/hia_program.py"]
  assert control.OWNER_SHA==PINS["tools/hia_checked_machine_plan.py"] and control.COMMON_SHA==PINS["tools/hia_composite_lowering_driver_common.py"]
  alpha=load("checked_plan_frozen_ssa",root/"tools/hia_frozen_ssa_rename.py",PINS["tools/hia_frozen_ssa_rename.py"])
  from hepta.hia_agent_assembly import render_assembly,assemble_program
  import tools.qualify_hia_selfhost as qualifier
  assert Path(qualifier.__file__).resolve()==reference/"tools/qualify_hia_selfhost.py"
  qualifier.CHILD=root/"reference/hia_selfhost_child.py"
  if component in WIRE:
   assert args.wire_source is not None
   source=read(args.wire_source,WIRE[component]["sha256"]);assert len(source)==WIRE[component]["bytes"]
   original_source=source
   original_document=assemble_program(source).as_dict()
   (out/"original-frozen.hiaasm").write_bytes(original_source)
   save(out/"original-frozen.document.json",original_document)
   document,alpha_proof=alpha.rename(original_document)
   source=render_assembly(document).encode("utf-8")
   assert assemble_program(source).as_dict()==document
   assert author.profile(document)==author.profile(original_document)
   alpha_proof.update(original_source_bytes=len(original_source),original_source_sha256=digest(original_source),
      revised_source_bytes=len(source),revised_source_sha256=digest(source),
      transform_source_sha256=PINS["tools/hia_frozen_ssa_rename.py"])
   save(out/"full-SSA-alpha-proof.json",alpha_proof)
   scope=dict(kind="BIJECTIVE_SSA_RENAME_OF_EXACT_PUBLISHED_HIA_FRESH_B3",
      original_source_identity=WIRE[component],transform_source_sha256=PINS["tools/hia_frozen_ssa_rename.py"],
      complete_inverse_document_equal=True,only_SSA_spelling_changed=True)
   owner_sha=digest(original_source)
  else:
   assert args.wire_source is None
   if component=="controller":
    body,constants,scope=control.source(common);owner_sha=PINS["tools/hia_checked_plan_controller.py"]
   else:
    body,constants,scope=owner.source(component);owner_sha=PINS["tools/hia_checked_machine_plan.py"]
   expanded=author.expanded(body,constants);(out/"authoring.py").write_text(expanded)
   document=author.document(expanded,"hia_checked_machine_plan_"+component)
   source=render_assembly(document).encode("utf-8")
   assert assemble_program(source).canonical_bytes
  profile=author.profile(document)
  profile["max_block_ops"]=max(len(b["ops"]) for f in document["functions"] for b in f["blocks"])
  profile["max_function_values"]=max(1+max(int(v["name"][1:])
    for b in f["blocks"] for v in b["params"]+[x for op in b["ops"] for x in op["out"]]) for f in document["functions"])
  profile["max_ssa_index"]=profile["max_function_values"]-1
  save(out/"document.json",document);save(out/"profile-before-gates.json",profile)
  assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
  assert profile["max_blocks"]<=256 and profile["max_params"]<=16 and profile["max_ssa_index"]<2048
  # max_block_ops is recorded, never used as a new gate.
  assert len(source)<=1<<20
  source_path=out/"source.hiaasm";source_path.write_bytes(source)
  save(out/"generation.json",dict(profile=profile,scope=scope,source_bytes=len(source),source_sha256=digest(source)))
  compile_dir=out/"compile";compile_dir.mkdir()
  image_path,receipt=qualifier.compile_stage(compile_dir,"checked-plan-"+component,args.compiler,source)
  result["compilations"]+=1;image=image_path.read_bytes()
  assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
  assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER_SHA
  assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
  assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
  assert receipt["runner_sha256"]==PINS["reference/hia_selfhost_child.py"]
  assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
  assert 0<len(image)<=1<<20
  read(source_path,digest(source));read(image_path,digest(image))
  manifest=dict(schema="hia-checked-machine-plan-development-component-v1",status="BUILT_ONLY",
     component=component,role=ROLES[component],author_sha256=owner_sha,compiler_sha256=COMPILER_SHA,
     source_path=str(source_path),source_bytes=len(source),source_sha256=digest(source),
     image_path=str(image_path.resolve()),image_bytes=len(image),image_sha256=digest(image),
     profile=profile,compile_receipt=receipt,source_scope=scope,abi_second_readonly=component!="controller",
     actual_immutable_previously_admitted_Core_required=True,header_is_authentication=False,
     complete_parent_backend=False,installed=False,cold=False)
  save(out/"plan.manifest.json",manifest)
  result.update(status="PASS_BUILD_ONLY",manifest=manifest)
 except BaseException as error:
  result.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  before=[];after=[]
  for number,(path,raw) in enumerate(pins.items()):
   target=out/"source"/str(number)/path.name;target.parent.mkdir(parents=True)
   target.write_bytes(raw);target.chmod(modes[path])
   before.append(dict(path=str(path),snapshot=str(target.relative_to(out)),bytes=len(raw),sha256=digest(raw),mode=modes[path]))
   try:
    current=path.read_bytes();after.append(dict(path=str(path),bytes=len(current),sha256=digest(current),
       same=current==raw and stat.S_IMODE(path.stat().st_mode)==modes[path]))
   except BaseException as error:after.append(dict(path=str(path),same=False,error=repr(error)))
  save(out/"source-before.json",before);save(out/"source-after.json",after)
  same=all(row["same"] for row in after)
  if not same:result["status"]="FAIL"
  result.update(source_pins_unchanged=same,elapsed_seconds=time.monotonic()-started,
     actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
     address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
  save(out/"summary.json",result);print(json.dumps(result,sort_keys=True),flush=True)
 if result["status"]!="PASS_BUILD_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
