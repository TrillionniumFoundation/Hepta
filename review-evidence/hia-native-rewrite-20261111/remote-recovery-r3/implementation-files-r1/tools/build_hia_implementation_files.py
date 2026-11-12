"""Fresh original-budget compiler for implementation-file and SHA HIA owners.
All native decisions are in HIA. This authoring/development build retains full
canonical source, document, actual image and receipts. It is not a public build.
"""
from pathlib import Path
from hashlib import sha256
import argparse,importlib.abc,importlib.util,json,resource,stat,sys,time,traceback
sys.dont_write_bytecode=True
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
ROLES={"controller":1,"hash":2}
OWNER_PATHS={"controller":"tools/hia_implementation_files.py","hash":"tools/generate_hia_sha256_stream.py"}
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
PINS={
  "tools/hia_implementation_files.py": "a7fc5e1f656fdf4bacc3e35b754cc6f113c0b257b49dcc13c9a03fa5a23fc871",
  "tools/hia_composite_lowering_driver_common.py": "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1",
  "tools/function_authoring_reference.py": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b",
  "tools/hia_agent_edit_source_views.py": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c",
  "tools/generate_hia_sha256.py": "4114a26ff0ea47229bccbedadcb40efdd9715a8dd0739d2fcb55c98f8ddbdf97",
  "tools/generate_hia_sha256_stream.py": "247816be2a50d384a6dd86a1d8cad909a48fbcdef54444f2394a7789fb137238",
  "reference/hia_program_native.py": "bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c",
  "reference/hia_selfhost_child.py": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29",
  "reference/cpython-3.12.14-fileio.c": "b2266a58fd78f856f0b8b47ff34b3b166bd4cf4ca80adaaacaa271417fbe9f23"
}
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
 resource.setrlimit(resource.RLIMIT_CPU,(90,90))
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 parser=argparse.ArgumentParser()
 for name in("reference","compiler","out"):parser.add_argument("--"+name,type=Path,required=True)
 parser.add_argument("--component",choices=tuple(ROLES),required=True)
 args=parser.parse_args();root=Path(__file__).resolve().parents[1]
 reference=args.reference.resolve();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
 pins={};modes={};started=time.monotonic_ns()
 report=dict(status="INCOMPLETE",component=args.component,compilations=0,native_semantic_entries=0,
     old_results_inherited=False,full_public_backend=False,installed=False,cold=False)
 def read(path,expected=None):
  path=Path(path).absolute();info=path.lstat()
  assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
  path=path.resolve();raw=path.read_bytes()
  if expected is not None:assert digest(raw)==expected,(str(path),digest(raw),expected)
  if path in pins:assert pins[path]==raw
  else:pins[path]=raw;modes[path]=stat.S_IMODE(info.st_mode)
  return raw
 def load(name,path,expected):
  raw=read(path,expected);module=type(sys)(name);module.__file__=str(path)
  sys.modules[name]=module;exec(compile(raw,str(path),"exec"),module.__dict__);return module
 try:
  assert sys.version_info[:3]==(3,12,14)
  read(__file__)
  for name,identity in PINS.items():read(root/name,identity)
  assert len(read(args.compiler,COMPILER_SHA))==669556
  frozen={p.resolve():read(p) for prefix in("hepta","tools")
          for p in sorted((reference/prefix).rglob("*.py"))}
  sys.meta_path.insert(0,FrozenImports(reference,frozen))
  load("tools.hia_agent_edit_source_views",root/"tools/hia_agent_edit_source_views.py",PINS["tools/hia_agent_edit_source_views.py"])
  author=load("backend_author",root/"tools/function_authoring_reference.py",PINS["tools/function_authoring_reference.py"])
  common=load("backend_common",root/"tools/hia_composite_lowering_driver_common.py",PINS["tools/hia_composite_lowering_driver_common.py"])
  owner=load("implementation_files",root/"tools/hia_implementation_files.py",PINS["tools/hia_implementation_files.py"])
  assert owner.COMMON_SHA==PINS["tools/hia_composite_lowering_driver_common.py"]
  assert owner.REFERENCE_SHA==PINS["reference/hia_program_native.py"]
  reference_body=read(root/"reference/hia_program_native.py",owner.REFERENCE_SHA).decode("utf-8")
  import ast
  parsed=ast.parse(reference_body)
  original=next(n for n in parsed.body if isinstance(n,ast.FunctionDef) and n.name=="_implementation_hash")
  names=next(n.iter for n in ast.walk(original) if isinstance(n,ast.For))
  assert tuple(ast.literal_eval(names))==owner.FILES
  if args.component=="controller":body,constants,scope=owner.source(common)
  else:
   load("tools.generate_hia_sha256",root/"tools/generate_hia_sha256.py",PINS["tools/generate_hia_sha256.py"])
   stream=load("implementation_hash_stream",root/"tools/generate_hia_sha256_stream.py",PINS["tools/generate_hia_sha256_stream.py"])
   body=stream.source_program();constants={}
   scope=dict(status="FRESH_BUILD_ONLY",source_algorithm="exact incremental SHA body",
       host_hash_during_native=False,second_writable=True,hash_total_limit=(1<<61)-1)
  expanded=author.expanded(body,constants)
  (out/"authoring.py").write_text(expanded)
  document=author.document(expanded,"hia_implementation_"+args.component)
  profile=author.profile(document)
  profile["max_block_ops"]=max(len(b["ops"]) for f in document["functions"] for b in f["blocks"])
  profile["max_function_values"]=max(1+max(int(v["name"][1:])
      for b in f["blocks"] for v in b["params"]+[item for op in b["ops"] for item in op["out"]])
      for f in document["functions"])
  profile["max_ssa_index"]=profile["max_function_values"]-1
  save(out/"document.json",document);save(out/"profile-before-gates.json",profile)
  # Preserve the exact responsible function/block before any profile refusal.
  # This is evidence only; all existing aggregate compiler gates remain below.
  nodes=ast.parse(expanded).body
  shift=int(nodes[0].args.args[1].annotation.id=="readbuf")
  names={"f"+str(i+shift):node.name for i,node in enumerate(nodes)}
  if shift:names["f0"]="private_RRW_ABI_wrapper"
  function_profiles=[]
  for fn in document["functions"]:
   values=[v for block in fn["blocks"] for v in block["params"]+[item for op in block["ops"] for item in op["out"]]]
   function_profiles.append(dict(function=fn["name"],author_function=names[fn["name"]],
      blocks=len(fn["blocks"]),ops=sum(len(block["ops"]) for block in fn["blocks"]),
      max_params=max(len(block["params"]) for block in fn["blocks"]),
      max_ssa_index=max(int(v["name"][1:]) for v in values),
      parameter_gate_blocks=[dict(block=block["id"],count=len(block["params"]),params=block["params"])
                            for block in fn["blocks"] if len(block["params"])>16]))
  save(out/"profile-functions-before-gates.json",dict(functions=function_profiles,
      parameter_limit=16,ssa_suffix_limit_exclusive=2048,original_limits_unchanged=True))
  assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
  assert profile["max_blocks"]<=256 and profile["max_params"]<=16 and profile["max_ssa_index"]<2048
  from hepta.hia_agent_assembly import render_assembly,assemble_program
  source=render_assembly(document).encode("utf-8")
  assert len(source)<=1<<20 and assemble_program(source).as_dict()==document
  (out/"source.hiaasm").write_bytes(source)
  save(out/"generation.json",dict(scope=scope,profile=profile,source_bytes=len(source),source_sha256=digest(source)))
  import tools.qualify_hia_selfhost as qualifier
  assert Path(qualifier.__file__).resolve()==reference/"tools/qualify_hia_selfhost.py"
  qualifier.CHILD=root/"reference/hia_selfhost_child.py"
  compile_dir=out/"compile";compile_dir.mkdir()
  image_path,receipt=qualifier.compile_stage(compile_dir,"implementation-files-"+args.component,args.compiler,source)
  image=image_path.read_bytes();report["compilations"]+=1
  assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
  assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER_SHA
  assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
  assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
  assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
  assert receipt["runner_sha256"]==PINS["reference/hia_selfhost_child.py"] and 0<len(image)<=1<<20
  read(out/"source.hiaasm",digest(source));read(image_path,digest(image))
  manifest=dict(schema="hia-implementation-files-development-component-v1",status="BUILT_ONLY",
      component=args.component,role=ROLES[args.component],
      source_path=str((out/"source.hiaasm").resolve()),source_bytes=len(source),source_sha256=digest(source),
      image_path=str(image_path.resolve()),image_bytes=len(image),image_sha256=digest(image),
      author_sha256=PINS[OWNER_PATHS[args.component]],compiler_sha256=COMPILER_SHA,
      source_scope=scope,compile_receipt=receipt,profile=profile,
      abi_second_readonly=False,
      actual_private_immutable_producers_required=True,header_is_authentication=False,
      full_public_backend=False,installed=False,cold=False)
  save(out/"implementation.manifest.json",manifest)
  report.update(status="PASS_BUILD_ONLY",manifest=manifest)
 except BaseException as error:
  report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  rows=[];after=[]
  for number,(path,raw) in enumerate(pins.items()):
   target=out/"source"/str(number)/path.name;target.parent.mkdir(parents=True)
   target.write_bytes(raw);target.chmod(modes[path])
   rows.append(dict(path=str(path),snapshot=str(target.relative_to(out)),bytes=len(raw),sha256=digest(raw),mode=modes[path]))
   try:
    now=path.read_bytes();info=path.stat()
    after.append(dict(path=str(path),bytes=len(now),sha256=digest(now),same=now==raw and stat.S_IMODE(info.st_mode)==modes[path]))
   except BaseException as error:after.append(dict(path=str(path),same=False,error=repr(error)))
  save(out/"source-before.json",rows);save(out/"source-after.json",after)
  unchanged=all(row["same"] for row in after)
  report.update(source_pins_unchanged=unchanged,elapsed_ns=time.monotonic_ns()-started,
      actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
        address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
  if not unchanged:report["status"]="FAIL"
  save(out/"summary.json",report);print(json.dumps(report,sort_keys=True),flush=True)
 if report["status"]!="PASS_BUILD_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
