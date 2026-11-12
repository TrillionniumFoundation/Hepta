"""Fresh single-role build for the complete eleven-image native Emitter.
Each invocation retains the original 90 CPU/180 wall/1 GiB development envelope;
each actual B3 child retains 10 CPU/20 wall/256 MiB. No old result is inherited.
"""
from pathlib import Path
from hashlib import sha256
import argparse,importlib.abc,importlib.util,json,resource,stat,sys,time,traceback
sys.dont_write_bytecode=True
PINS={
 "tools/hia_emitter_prepare.py":"662e4dfc95c70c43495554dfd01cb3042176044bd8f63d10413e29a00cc7e1f2",
 "tools/hia_emitter_finish.py":"66b6480a3f6f37985fc4d97c4d54de848bb7fcd247591f04542df7e94570337c",
 "tools/hia_emitter_controller.py":"3d61004c26b89fdec53b4457659ae4eccd8f2fcd73b8f260fafa716d0af01665",
 "tools/hia_machine_elf_writer.py":"84bbd81168ca645807ce0095755bb6e74efb1ffd9419cec3473a439e34dca985",
 "tools/hia_composite_lowering_driver_common.py":"fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1",
 "tools/hia_emitter_wrapper_tape.py":"332a8633a13f09fcc6021ebdf1f916e97b65b93f4b875b57264abf7eb93b0287",
 "tools/hia_emitter_wrapper_issuer.py":"5eb9752617afea5af7ceddfedb9c309fcf7d88fa3da5f3895e7e1a1aae1d7ff8",
 "reference/hia_native_byte_abi.py":"0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6",
 "tools/hia_function_frame_plan.py":"27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd",
 "tools/hia_function_lowering_tape.py":"e61fcb540bbe51a0e85dc09cd9afa3813b6ba24d6739da2912269c10ce1522eb",
 "tools/hia_function_code_issuer.py":"f126ef9f45988e4eb699e22cd965f3e6057fdcc969e590ebd8e266b520287219",
 "tools/hia_machine_x64_encoder.py":"92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a",
 "tools/function_authoring_reference.py":"717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b",
 "tools/hia_agent_edit_source_views.py":"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c",
 "reference/hia_program_native.py":"bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c",
 "reference/hia_machine_plan.py":"ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a",
 "reference/hia_machine_x64.py":"8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9",
 "reference/hia_selfhost_child.py":"1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29",
}
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
ROLES={"prepare":1,"frame":2,"tape":3,"issuer":4,"wrap_tape":5,"wrap_issuer":6,"encoder":7,"finalizer":8,"finish":9,"elf":10,"controller":11}
OWNER_PATHS={"prepare":"tools/hia_emitter_prepare.py","frame":"tools/hia_function_frame_plan.py",
 "tape":"tools/hia_function_lowering_tape.py","issuer":"tools/hia_function_code_issuer.py",
 "wrap_tape":"tools/hia_emitter_wrapper_tape.py","wrap_issuer":"tools/hia_emitter_wrapper_issuer.py",
 "encoder":"tools/hia_machine_x64_encoder.py","finalizer":"tools/hia_machine_x64_encoder.py",
 "finish":"tools/hia_emitter_finish.py","elf":"tools/hia_machine_elf_writer.py",
 "controller":"tools/hia_emitter_controller.py"}
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
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
    for name in ("reference","compiler","out"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--component",choices=tuple(ROLES),required=True)
    args=parser.parse_args();root=Path(__file__).resolve().parents[1]
    reference=args.reference.resolve();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    pins={};modes={};started=time.monotonic_ns()
    result=dict(status="INCOMPLETE",scope="FRESH_FULL_EMITTER_SINGLE_ROLE_BUILD",
        compilations=0,native_semantic_entries=0,generations={},components={},
        original_limits_unchanged=True,old_test_results_inherited=False,
        whole_emitter=False,whole_backend=False,installed=False,cold=False)
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
        for name,h in PINS.items():read(root/name,h)
        assert len(read(args.compiler,COMPILER_SHA))==669556
        frozen={p.resolve():read(p) for prefix in ("hepta","tools")
                for p in sorted((reference/prefix).rglob("*.py"))}
        sys.meta_path.insert(0,FrozenImports(reference,frozen))
        load("tools.hia_agent_edit_source_views",root/"tools/hia_agent_edit_source_views.py",
             PINS["tools/hia_agent_edit_source_views.py"])
        author=load("function_authoring",root/"tools/function_authoring_reference.py",
             PINS["tools/function_authoring_reference.py"])
        frame=load("frame_source",root/"tools/hia_function_frame_plan.py",PINS["tools/hia_function_frame_plan.py"])
        tape=load("tape_source",root/"tools/hia_function_lowering_tape.py",PINS["tools/hia_function_lowering_tape.py"])
        issuer=load("issuer_source",root/"tools/hia_function_code_issuer.py",PINS["tools/hia_function_code_issuer.py"])
        x64=load("x64_source",root/"tools/hia_machine_x64_encoder.py",PINS["tools/hia_machine_x64_encoder.py"])
        assert tape.FRAME_OWNER_SHA==PINS["tools/hia_function_frame_plan.py"]
        assert issuer.TAPE_OWNER_SHA==PINS["tools/hia_function_lowering_tape.py"]
        wrapper=load("wrapper_source",root/"tools/hia_emitter_wrapper_tape.py",PINS["tools/hia_emitter_wrapper_tape.py"])
        wrapper_issuer=load("wrapper_issuer_source",root/"tools/hia_emitter_wrapper_issuer.py",PINS["tools/hia_emitter_wrapper_issuer.py"])
        assert wrapper.TAPE_OWNER_SHA==PINS["tools/hia_function_lowering_tape.py"]
        assert wrapper.FRAME_OWNER_SHA==PINS["tools/hia_function_frame_plan.py"]
        assert wrapper.BYTE_REFERENCE_SHA==PINS["reference/hia_native_byte_abi.py"]
        assert wrapper_issuer.FUNCTION_ISSUER_SHA==PINS["tools/hia_function_code_issuer.py"]
        assert wrapper_issuer.TAPE_OWNER_SHA==PINS["tools/hia_emitter_wrapper_tape.py"]
        elf=load("elf_source",root/"tools/hia_machine_elf_writer.py",PINS["tools/hia_machine_elf_writer.py"])
        common=load("emitter_common",root/"tools/hia_composite_lowering_driver_common.py",PINS["tools/hia_composite_lowering_driver_common.py"])
        prepare=load("emitter_prepare",root/"tools/hia_emitter_prepare.py",PINS["tools/hia_emitter_prepare.py"])
        finish=load("emitter_finish",root/"tools/hia_emitter_finish.py",PINS["tools/hia_emitter_finish.py"])
        controller=load("emitter_control",root/"tools/hia_emitter_controller.py",PINS["tools/hia_emitter_controller.py"])
        assert prepare.FRAME_SHA==finish.FRAME_SHA==PINS["tools/hia_function_frame_plan.py"]
        assert prepare.ELF_SHA==finish.ELF_SHA==PINS["tools/hia_machine_elf_writer.py"]
        assert controller.COMMON_SHA==PINS["tools/hia_composite_lowering_driver_common.py"]
        assert controller.PREPARE_SHA==PINS["tools/hia_emitter_prepare.py"]
        assert controller.FINISH_SHA==PINS["tools/hia_emitter_finish.py"]
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        import tools.qualify_hia_selfhost as qualifier
        assert Path(qualifier.__file__).resolve()==reference/"tools/qualify_hia_selfhost.py"
        qualifier.CHILD=root/"reference/hia_selfhost_child.py"
        sources={}
        components=(args.component,)
        owner_paths=OWNER_PATHS
        for component in components:
            directory=out/component;directory.mkdir()
            if component=="prepare":body,constants,scope=prepare.source(frame,elf)
            elif component=="frame":body,constants,scope=frame.source()
            elif component=="tape":body,constants,scope=tape.source(frame)
            elif component=="issuer":body,constants,scope=issuer.source(frame)
            elif component=="wrap_tape":body,constants,scope=wrapper.source(frame,tape)
            elif component=="wrap_issuer":body,constants,scope=wrapper_issuer.source(frame,issuer)
            elif component in ("encoder","finalizer"):body,constants,scope=x64.source(component)
            elif component=="finish":body,constants,scope=finish.source(frame,elf)
            elif component=="elf":body,constants,scope=elf.source()
            else:body,constants,scope=controller.source(common)
            expanded=author.expanded(body,constants);(directory/"authoring.py").write_text(expanded)
            document=author.document(expanded,"hia_complete_emitter_"+component)
            profile=author.profile(document)
            profile["max_block_ops"]=max(len(b["ops"]) for f in document["functions"] for b in f["blocks"])
            profile["max_function_values"]=max(1+max(int(v["name"][1:])
                for b in f["blocks"] for v in b["params"]+[item for op in b["ops"] for item in op["out"]])
                for f in document["functions"])
            profile["max_ssa_index"]=profile["max_function_values"]-1
            save(directory/"document.json",document)
            save(directory/"profile-before-gates.json",profile)
            assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
            assert profile["max_blocks"]<=256 and profile["max_params"]<=16
            assert profile["max_ssa_index"]<2048
            # max_block_ops is an observation, never a new admission limit.
            source=render_assembly(document).encode("utf-8")
            assert len(source)<=1<<20 and assemble_program(source).canonical_bytes
            (directory/"source.hiaasm").write_bytes(source)
            save(directory/"generation.json",dict(scope=scope,profile=profile,source_bytes=len(source),source_sha256=digest(source)))
            result["generations"][component]=dict(profile=profile,source_bytes=len(source),source_sha256=digest(source))
            sources[component]=(source,profile)
        for component in components:
            directory=out/component;compile_dir=directory/"compile";compile_dir.mkdir()
            source,profile=sources[component]
            image_path,receipt=qualifier.compile_stage(compile_dir,"complete-emitter-"+component,args.compiler,source)
            image=image_path.read_bytes();result["compilations"]+=1
            assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER_SHA
            assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
            assert receipt["runner_sha256"]==PINS["reference/hia_selfhost_child.py"]
            assert 0<len(image)<=1<<20
            read(directory/"source.hiaasm",digest(source));read(image_path,digest(image))
            manifest=dict(schema="hepta.hia.complete-emitter-development.v1",status="BUILT_ONLY",
                component=component,role=ROLES[component],author_sha256=PINS[owner_paths[component]],
                source_path=str((directory/"source.hiaasm").resolve()),source_bytes=len(source),source_sha256=digest(source),
                image_path=str(image_path.resolve()),image_bytes=len(image),image_sha256=digest(image),
                compiler_sha256=COMPILER_SHA,compile_receipt=receipt,profile=profile,
                private_immutable_actual_issuers_required=True,header_is_authentication=False,
                whole_emitter=False,whole_backend=False,installed=False,cold=False)
            save(directory/"emitter.manifest.json",manifest);result["components"][component]=manifest
        bundle=dict(schema="hepta.hia.complete-emitter-single-role.v1",components=result["components"],
            source_pins=PINS,old_test_results_inherited=False)
        save(out/"bundle.json",bundle)
        result.update(status="PASS_BUILD_ONLY",bundle=str(out/"bundle.json"))
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
