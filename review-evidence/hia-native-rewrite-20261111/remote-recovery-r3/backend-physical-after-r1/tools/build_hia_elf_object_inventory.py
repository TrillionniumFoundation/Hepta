"""Fresh pure-HIA ELF64/62 inventory build and optional actual ELF producer.
No object, instruction or symbol inventory is constructed by this build tool.
Every compiler child keeps the original 10 CPU / 20 wall / 256 MiB gate.
"""
from pathlib import Path
from hashlib import sha256
import argparse,importlib.abc,importlib.util,json,resource,stat,sys,time,traceback,types
sys.dont_write_bytecode=True
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
PINS={
 "tools/hia_elf_object_inventory.py":"5b8807b7eaee30a04c12fe2d96a5c457abb0a6f2517804e6b001fbbfc32d16ce",
 "tools/hia_machine_elf_writer.py":"84bbd81168ca645807ce0095755bb6e74efb1ffd9419cec3473a439e34dca985",
 "tools/function_authoring_reference.py":"717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b",
 "tools/hia_agent_edit_source_views.py":"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c",
 "reference/hia_selfhost_child.py":"1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29",
 "reference/hia_program_native.py":"bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c",
 "reference/object_symbols.py":"aff81d724d08ed4a8c3189e3370f75e234daa010ec9e9855aedc1019d55a693f",
 "reference/object_structure.py":"4fb0b3d962e4b7f6ba508257bf605f4403d402e4f3d7e05cffa084b91651f5a8",
 "reference/hia_machine_elf.py":"c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101"}
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
class FrozenImports(importlib.abc.MetaPathFinder,importlib.abc.Loader):
    def __init__(self,root,files):self.root,self.files=root,files
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split(".")[0] not in ("hepta","tools"):return None
        base=self.root.joinpath(*fullname.split("."))
        for candidate,package in ((base.with_suffix(".py"),False),(base/"__init__.py",True)):
            if candidate in self.files:
                return importlib.util.spec_from_file_location(fullname,candidate,loader=self,
                    submodule_search_locations=[str(base)] if package else None)
        if any(p.is_relative_to(base) for p in self.files):
            spec=importlib.util.spec_from_loader(fullname,loader=None,is_package=True)
            spec.submodule_search_locations=[str(base)];return spec
        raise ModuleNotFoundError("file absent from immutable reference snapshot: "+fullname)
    def create_module(self,spec):return None
    def exec_module(self,module):
        path=Path(module.__spec__.origin)
        exec(compile(self.files[path],str(path),"exec"),module.__dict__)

def main():
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 p=argparse.ArgumentParser()
 for n in("reference","compiler","out"):p.add_argument("--"+n,type=Path,required=True)
 p.add_argument("--component",choices=("inventory","elf-producer"),required=True)
 a=p.parse_args();root=Path(__file__).resolve().parents[1];out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
 reference=a.reference.resolve();pins={};modes={};start=time.monotonic()
 report=dict(status="INCOMPLETE",component=a.component,compilations=0,native_semantic_entries=0,old_results_inherited=False)
 def read(path,expected=None):
  path=Path(path).absolute();info=path.lstat()
  assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
  path=path.resolve();raw=path.read_bytes()
  if expected is not None:assert digest(raw)==expected,(str(path),digest(raw),expected)
  if path in pins:assert pins[path]==raw
  else:pins[path]=raw;modes[path]=stat.S_IMODE(info.st_mode)
  return raw
 def load(name,path,expected):
  raw=read(path,expected);m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m
  exec(compile(raw,str(path),"exec"),m.__dict__);return m
 try:
  assert sys.version_info[:3]==(3,12,14)
  read(__file__)
  for name,h in PINS.items():read(root/name,h)
  assert len(read(a.compiler,COMPILER_SHA))==669556
  frozen={p.resolve():read(p) for prefix in("hepta","tools") for p in sorted((reference/prefix).rglob("*.py"))}
  for name in("hia_program_native.py","object_symbols.py","object_structure.py","hia_machine_elf.py"):
   assert read(reference/"hepta"/name)==read(root/"reference"/name)
  sys.meta_path.insert(0,FrozenImports(reference,frozen))
  load("tools.hia_agent_edit_source_views",root/"tools/hia_agent_edit_source_views.py",PINS["tools/hia_agent_edit_source_views.py"])
  author=load("inventory_authoring",root/"tools/function_authoring_reference.py",PINS["tools/function_authoring_reference.py"])
  elf=load("inventory_elf_helper",root/"tools/hia_machine_elf_writer.py",PINS["tools/hia_machine_elf_writer.py"])
  inspector=load("inventory_owner",root/"tools/hia_elf_object_inventory.py",PINS["tools/hia_elf_object_inventory.py"])
  assert elf.REFERENCE_SHA==PINS["reference/hia_machine_elf.py"]
  assert inspector.ELF_AVL_OWNER_SHA==PINS["tools/hia_machine_elf_writer.py"]
  assert inspector.STRUCTURE_SHA==PINS["reference/object_structure.py"]
  assert inspector.SYMBOLS_SHA==PINS["reference/object_symbols.py"]
  assert inspector.BACKEND_SHA==PINS["reference/hia_program_native.py"]
  if a.component=="inventory":
   body,constants,scope=inspector.source(elf);entry="hia_elf_object_inventory";owner="tools/hia_elf_object_inventory.py"
  else:
   body,constants,scope=elf.source();entry="hia_elf_inventory_test_producer";owner="tools/hia_machine_elf_writer.py"
  expanded=author.expanded(body,constants);(out/"authoring.py").write_text(expanded)
  document=author.document(expanded,entry);profile=author.profile(document)
  profile["max_block_ops"]=max(len(b["ops"]) for f in document["functions"] for b in f["blocks"])
  profile["max_ssa_index"]=max(int(v["name"][1:]) for f in document["functions"] for b in f["blocks"]
      for v in b["params"]+[item for op in b["ops"] for item in op["out"]])
  save(out/"document.json",document);save(out/"profile-before-gates.json",profile)
  assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
  assert profile["max_blocks"]<=256 and profile["max_params"]<=16 and profile["max_ssa_index"]<2048
  from hepta.hia_agent_assembly import render_assembly,assemble_program
  import tools.qualify_hia_selfhost as qualifier
  assert Path(qualifier.__file__).resolve()==reference/"tools/qualify_hia_selfhost.py"
  qualifier.CHILD=root/"reference/hia_selfhost_child.py"
  source=render_assembly(document).encode("utf-8");assert len(source)<=1<<20 and assemble_program(source).canonical_bytes
  sourcepath=out/"source.hiaasm";sourcepath.write_bytes(source)
  save(out/"generation.json",dict(profile=profile,scope=scope,bytes=len(source),sha256=digest(source)))
  directory=out/"compile";directory.mkdir()
  imagepath,receipt=qualifier.compile_stage(directory,"elf-object-"+a.component,a.compiler,source)
  image=imagepath.read_bytes();report["compilations"]=1
  assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
  assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER_SHA
  assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
  assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
  assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
  assert receipt["runner_sha256"]==PINS["reference/hia_selfhost_child.py"] and 0<len(image)<=1<<20
  read(sourcepath,digest(source));read(imagepath,digest(image))
  manifest=dict(schema="hepta.hia.elf-object-inventory-development.v1",status="BUILT_ONLY",
      component=a.component,author_sha256=PINS[owner],source_path=str(sourcepath),source_bytes=len(source),source_sha256=digest(source),
      image_path=str(imagepath.resolve()),image_bytes=len(image),image_sha256=digest(image),profile=profile,
      compiler_sha256=COMPILER_SHA,compile_receipt=receipt,private_actual_immutable_issuers_required=True,
      header_is_authentication=False,full_public_backend=False,installed=False,cold=False)
  save(out/"inventory.manifest.json",manifest);report.update(status="PASS_BUILD_ONLY",manifest=manifest)
 except BaseException as error:
  report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
 finally:
  rows=[];after=[]
  for i,(path,raw) in enumerate(pins.items()):
   target=out/"source"/str(i)/path.name;target.parent.mkdir(parents=True);target.write_bytes(raw);target.chmod(modes[path])
   rows.append(dict(path=str(path),snapshot=str(target.relative_to(out)),bytes=len(raw),sha256=digest(raw),mode=modes[path]))
   try:
    now=path.read_bytes();after.append(dict(path=str(path),bytes=len(now),sha256=digest(now),same=now==raw and stat.S_IMODE(path.stat().st_mode)==modes[path]))
   except BaseException as error:after.append(dict(path=str(path),same=False,error=repr(error)))
  save(out/"source-before.json",rows);save(out/"source-after.json",after)
  unchanged=all(row["same"] for row in after)
  report.update(source_pins_unchanged=unchanged,elapsed_seconds=time.monotonic()-start,
      limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
  if not unchanged:report["status"]="FAIL"
  save(out/"summary.json",report);print(json.dumps(report,sort_keys=True),flush=True)
 if report["status"]!="PASS_BUILD_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
