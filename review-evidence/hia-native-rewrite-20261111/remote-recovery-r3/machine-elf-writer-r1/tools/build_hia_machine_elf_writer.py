"""Fresh source-bound native ELF writer build; no inherited compilation result."""
from pathlib import Path
from hashlib import sha256
import argparse,ast,importlib.util,json,os,resource,stat,sys,time,traceback
sys.dont_write_bytecode=True
OWNER_SHA="84bbd81168ca645807ce0095755bb6e74efb1ffd9419cec3473a439e34dca985"
AUTHOR_SHA="717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
HELPER_SHA="555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
REFERENCE_SHA="c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101"
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    parser=argparse.ArgumentParser()
    for name in("reference","compiler","helper","out"):parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14)
    root=Path(__file__).resolve().parents[1];reference=args.reference.resolve();pins={}
    def read(path,expected=None):
        path=Path(path).absolute();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        path=path.resolve();raw=path.read_bytes()
        if expected is not None:assert digest(raw)==expected,(str(path),digest(raw),expected)
        if path in pins:assert pins[path]==raw
        pins[path]=raw;return raw
    def load(name,path,expected):
        raw=read(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        exec(compile(raw,str(path),"exec"),module.__dict__);return module
    result=dict(status="INCOMPLETE",scope="NEW_PURE_ELF64_ET_REL_WRITER_BUILD",
        compilations=0,native_semantic_entries=0,not_general_lowering=True,
        not_installed=True,not_cold_qualification=True,original_limits_unchanged=True)
    started=time.monotonic_ns()
    try:
        read(__file__);read(root/"reference/hia_machine_elf.py",REFERENCE_SHA)
        compiler=read(args.compiler,COMPILER_SHA);assert len(compiler)==669556
        sys.path.insert(0,str(reference))
        load("tools.hia_agent_edit_source_views",args.helper,HELPER_SHA)
        author=load("elf_writer_authoring",root/"tools/elf_authoring_reference.py",AUTHOR_SHA)
        owner=load("elf_writer_source",root/"tools/hia_machine_elf_writer.py",OWNER_SHA)
        text,constants,proof=owner.source()
        expanded=author.expanded(text,constants)
        (out/"writer.authoring.py").write_text(expanded)
        document=author.document(expanded,"hia_machine_elf_writer")
        profile=author.profile(document)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
        assert profile["ops"]<=8192 and profile["max_params"]<=16
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        source=render_assembly(document).encode("utf-8")
        assert len(source)<=1<<20
        assert assemble_program(source).canonical_bytes
        (out/"writer.hiaasm").write_bytes(source)
        save(out/"generation.json",dict(proof=proof,profile=profile,source_bytes=len(source),source_sha256=digest(source)))
        import tools.qualify_hia_selfhost as qualifier
        assert Path(qualifier.__file__).resolve()==reference/"tools/qualify_hia_selfhost.py"
        assert Path(qualifier.CHILD).resolve()==reference/"tools/hia_selfhost_child.py"
        for module in tuple(sys.modules.values()):
            path=getattr(module,"__file__",None)
            if path:
                path=Path(path).resolve()
                if path.suffix==".py" and path.is_relative_to(reference):read(path)
        read(qualifier.CHILD)
        before={str(p):dict(bytes=len(raw),sha256=digest(raw),mode=stat.S_IMODE(p.stat().st_mode)) for p,raw in pins.items()}
        for number,(p,raw) in enumerate(pins.items()):
            target=out/"source"/str(number)/p.name;target.parent.mkdir(parents=True)
            target.write_bytes(raw);target.chmod(stat.S_IMODE(p.stat().st_mode))
        save(out/"source-before.json",before)
        compile_dir=out/"compile";compile_dir.mkdir()
        image_path,receipt=qualifier.compile_stage(compile_dir,"machine-elf-writer",args.compiler,source)
        image=image_path.read_bytes();result["compilations"]=1
        assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER_SHA
        assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        assert receipt["runner_sha256"]==digest(read(qualifier.CHILD))
        assert 0<len(image)<=1<<20
        read(out/"writer.hiaasm",digest(source));read(image_path,digest(image))
        manifest=dict(schema="hepta.hia.machine-elf-writer-development.v1",status="BUILT_ONLY",
            author_sha256=OWNER_SHA,reference_sha256=REFERENCE_SHA,
            source_path=str((out/"writer.hiaasm").resolve()),source_bytes=len(source),source_sha256=digest(source),
            image_path=str(image_path.resolve()),image_bytes=len(image),image_sha256=digest(image),
            compiler_sha256=COMPILER_SHA,compile_receipt=receipt,profile=profile,
            command_magic="HIAELC01",event_magic="HIAELE01",workspace_minimum=4096,
            source_graph_lease_is_not_authentication=True,ordinary_build_closed=False)
        save(out/"machine-elf-writer.manifest.json",manifest)
        result.update(status="PASS_BUILD_ONLY",manifest=manifest,generation=proof)
    except BaseException as error:
        result.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        after={}
        for p,raw in pins.items():
            try:
                current=p.read_bytes();after[str(p)]=dict(bytes=len(current),sha256=digest(current),same=current==raw)
            except BaseException as error:after[str(p)]=dict(error=repr(error),same=False)
        result.update(source_after=after,source_pins_unchanged=all(v["same"] for v in after.values()),
            elapsed_ns=time.monotonic_ns()-started,
            actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
        if not result["source_pins_unchanged"]:result["status"]="FAIL"
        save(out/"summary.json",result)
        print("HIA_MACHINE_ELF_BUILD "+json.dumps(result,sort_keys=True),flush=True)
    if result["status"]!="PASS_BUILD_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
