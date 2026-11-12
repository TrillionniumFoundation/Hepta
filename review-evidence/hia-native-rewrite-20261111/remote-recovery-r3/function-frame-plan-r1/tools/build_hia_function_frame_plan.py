"""Build the private HIA function-frame planner from exact immutable snapshots."""
from pathlib import Path
from hashlib import sha256
import argparse,importlib.abc,importlib.util,json,resource,stat,sys,time,traceback
sys.dont_write_bytecode=True
OWNER_SHA="27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd"
AUTHOR_SHA="717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
HELPER_SHA="555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
REFERENCE_SHA="bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
PLAN_SHA="ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a"
CHILD_SHA="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
class FrozenImports(importlib.abc.MetaPathFinder,importlib.abc.Loader):
    def __init__(self,root,files):
        self.root,self.files=root,files
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split(".")[0] not in ("hepta","tools"):return None
        base=self.root.joinpath(*fullname.split("."))
        for candidate,package in ((base.with_suffix(".py"),False),(base/"__init__.py",True)):
            if candidate in self.files:
                return importlib.util.spec_from_file_location(fullname,candidate,loader=self,
                    submodule_search_locations=[str(base)] if package else None)
        if any(p.is_relative_to(base) for p in self.files):
            spec=importlib.util.spec_from_loader(fullname,loader=None,is_package=True)
            spec.submodule_search_locations=[str(base)]
            return spec
        raise ModuleNotFoundError("reference source is absent from frozen snapshot: "+fullname)
    def create_module(self,spec):return None
    def exec_module(self,module):
        path=Path(module.__spec__.origin)
        exec(compile(self.files[path],str(path),"exec"),module.__dict__)
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser=argparse.ArgumentParser()
    for name in ("reference","compiler","out"):parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14)
    root=Path(__file__).resolve().parents[1];reference=args.reference.resolve();pins={};modes={}
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
        sys.modules[name]=module
        exec(compile(raw,str(path),"exec"),module.__dict__);return module
    result=dict(status="INCOMPLETE",scope="PRIVATE_FUNCTION_FRAME_AND_STAGING_PLAN",
        compilations=0,native_semantic_entries=0,original_limits_unchanged=True,
        checked_core_and_machine_plan_required=True,whole_backend_closed=False,
        installed_closed=False,cold_qualified=False)
    started=time.monotonic_ns()
    try:
        read(__file__);read(root/"reference/hia_program_native.py",REFERENCE_SHA)
        read(root/"reference/hia_machine_plan.py",PLAN_SHA)
        compiler=read(args.compiler,COMPILER_SHA);assert len(compiler)==669556
        child=root/"reference/hia_selfhost_child.py";read(child,CHILD_SHA)
        frozen={p.resolve():read(p) for prefix in ("hepta","tools")
                for p in sorted((reference/prefix).rglob("*.py"))}
        importer=FrozenImports(reference,frozen);sys.meta_path.insert(0,importer)
        load("tools.hia_agent_edit_source_views",root/"tools/hia_agent_edit_source_views.py",HELPER_SHA)
        author=load("function_authoring",root/"tools/function_authoring_reference.py",AUTHOR_SHA)
        owner=load("function_source",root/"tools/hia_function_frame_plan.py",OWNER_SHA)
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        import tools.qualify_hia_selfhost as qualifier
        assert Path(qualifier.__file__).resolve()==reference/"tools/qualify_hia_selfhost.py"
        # The restored reference is a precisely enumerated subset. This standalone
        # child is the exact original 0ef file; only its development location differs.
        qualifier.CHILD=child
        body,constants,scope=owner.source()
        expanded=author.expanded(body,constants);(out/"authoring.py").write_text(expanded)
        document=author.document(expanded,"hia_function_frame_plan")
        profile=author.profile(document)
        profile["max_block_ops"]=max(len(b["ops"]) for f in document["functions"] for b in f["blocks"])
        profile["max_function_values"]=max(
            1+max(int(v["name"][1:]) for b in f["blocks"] for v in b["params"]+
                  [item for op in b["ops"] for item in op["out"]]) for f in document["functions"])
        assert profile["functions"]<=128 and profile["blocks"]<=1536
        assert profile["max_blocks"]<=256 and profile["ops"]<=8192 and profile["max_params"]<=16
        # No independent 128-ops/block requirement exists in the original compiler.
        source=render_assembly(document).encode("utf-8");assert len(source)<=1<<20
        assert assemble_program(source).canonical_bytes
        (out/"source.hiaasm").write_bytes(source);save(out/"document.json",document)
        save(out/"generation.json",dict(scope=scope,profile=profile,
            source_bytes=len(source),source_sha256=digest(source)))
        result["generation"]=dict(source_bytes=len(source),source_sha256=digest(source),profile=profile)
        compile_dir=out/"compile";compile_dir.mkdir()
        image_path,receipt=qualifier.compile_stage(compile_dir,"function-frame",args.compiler,source)
        image=image_path.read_bytes();result["compilations"]+=1
        assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER_SHA
        assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        assert receipt["runner_sha256"]==CHILD_SHA
        assert 0<len(image)<=1<<20
        read(out/"source.hiaasm",digest(source));read(image_path,digest(image))
        manifest=dict(schema="hepta.hia.function-frame-development.v1",status="BUILT_ONLY",
            author_sha256=OWNER_SHA,reference_sha256=REFERENCE_SHA,machine_plan_reference_sha256=PLAN_SHA,
            source_path=str((out/"source.hiaasm").resolve()),source_bytes=len(source),source_sha256=digest(source),
            image_path=str(image_path.resolve()),image_bytes=len(image),image_sha256=digest(image),
            compiler_sha256=COMPILER_SHA,compile_receipt=receipt,profile=profile,
            workspace_minimum=4096,private_immutable_leases_required=True,header_is_authentication=False,
            checked_core_and_machine_plan_required=True,whole_backend_closed=False,installed_closed=False,cold_qualified=False)
        save(out/"function-frame.manifest.json",manifest)
        result.update(status="PASS_BUILD_ONLY",manifest=manifest)
    except BaseException as error:
        result.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        rows=[];after=[]
        for number,(path,raw) in enumerate(pins.items()):
            target=out/"source"/str(number)/path.name;target.parent.mkdir(parents=True)
            target.write_bytes(raw);target.chmod(modes[path])
            rows.append(dict(path=str(path),snapshot=str(target.relative_to(out)),bytes=len(raw),
                sha256=digest(raw),mode=modes[path]))
            try:
                now=path.read_bytes();info=path.stat()
                after.append(dict(path=str(path),bytes=len(now),sha256=digest(now),
                    same=now==raw and stat.S_IMODE(info.st_mode)==modes[path]))
            except BaseException as error:after.append(dict(path=str(path),same=False,error=repr(error)))
        save(out/"source-before.json",rows);save(out/"source-after.json",after)
        unchanged=all(row["same"] for row in after)
        result.update(source_pins_unchanged=unchanged,elapsed_ns=time.monotonic_ns()-started,
            actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
                address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
        if not unchanged:result["status"]="FAIL"
        save(out/"summary.json",result);print(json.dumps(result,sort_keys=True),flush=True)
    if result["status"]!="PASS_BUILD_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
