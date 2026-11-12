"""Compile one physical-after HIA owner under the original independent gates.
No old semantic qualification is inherited by this new 23-role composition.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ast,importlib.util,json,stat,sys,traceback,types
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
PINS={
  "tools/hia_backend_physical_after.py": "72c6b155dd1c3c3286f451af78f0f75feb0568a522a5411ddc934b9b28b6ed8e",
  "tools/bounded_physical_subject.py": "d676827c9275c6b0d4185c5e635c67bc6cc35c924c0253fa4c3fef371d0d312f",
  "reference/build_backend_r1.py": "290a22eaaf8d19345c21ac0c6e483cd6387b7462cb32547a186d6dcbc364d078",
  "tools/hia_backend_controller.py": "35ce9e9fccfb0601d3d000834c241ae9140eb70449fabc2747ae19e84c1d2a05",
  "tools/hia_backend_child_forwarder.py": "d089e80fc78c8c3e2d2234aea587c38bbd5caa757178bf1f93845b15c2fe474c",
  "tools/hia_implementation_files.py": "a7fc5e1f656fdf4bacc3e35b754cc6f113c0b257b49dcc13c9a03fa5a23fc871",
  "tools/hia_composite_lowering_driver_common.py": "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1",
  "tools/function_authoring_reference.py": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b",
  "tools/hia_agent_edit_source_views.py": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c",
  "reference/hia_program_native.py": "bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c",
  "reference/hia_selfhost_child.py": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
}
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
ROLES={"parent":20,"files":22,"bridge":23}
ORIGINAL_PARENT_SOURCE=(287979,"546a98d68c3c393b3e747596a1c907e28201475164abbadebd3e76c337366bb0")
ORIGINAL_FILES_SOURCE=(196675,"c77b262cac0e34c2b1db0db0ef5c28471a6546a3c7ad85764d6589b74eea4069")
ORIGINAL_FILES_IMAGE=(203390,"b8268f47b1f3295a968ec44b54626373cbc4c35dd6b19ea8dc3348820ae47b13")
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def boot_subject():
    path=ROOT/"tools/bounded_physical_subject.py"
    assert not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode)
    raw=path.read_bytes();assert digest(raw)==PINS["tools/bounded_physical_subject.py"]
    module=types.ModuleType("physical_subject");module.__file__=str(path)
    sys.modules[module.__name__]=module
    exec(compile(raw,str(path),"exec"),module.__dict__)
    return module

def profiles(author,expanded,document):
    result=author.profile(document)
    result["max_block_ops"]=max(len(b["ops"]) for f in document["functions"] for b in f["blocks"])
    rows=[];nodes=ast.parse(expanded).body
    shift=int(nodes[0].args.args[1].annotation.id=="readbuf")
    names={"f"+str(i+shift):node.name for i,node in enumerate(nodes)}
    if shift:names["f0"]="private_RRW_ABI_wrapper"
    for fn in document["functions"]:
        values=[value for b in fn["blocks"] for value in b["params"]+
                [item for op in b["ops"] for item in op["out"]]]
        suffix=[int(value["name"][1:]) for value in values]
        row=dict(function=fn["name"],author_function=names[fn["name"]],
            blocks=len(fn["blocks"]),ops=sum(len(b["ops"]) for b in fn["blocks"]),
            max_params=max(len(b["params"]) for b in fn["blocks"]),
            max_ssa_index=max(suffix,default=-1),
            parameter_gate_blocks=[dict(block=b["id"],count=len(b["params"]),params=b["params"])
                                   for b in fn["blocks"] if len(b["params"])>16])
        rows.append(row)
    result["max_ssa_index"]=max(row["max_ssa_index"] for row in rows)
    result["max_function_values"]=result["max_ssa_index"]+1
    return result,dict(functions=rows,parameter_limit=16,ssa_suffix_limit_exclusive=2048,
                       max_block_ops_is_observation_only=True,original_limits_unchanged=True)

def main():
    p=argparse.ArgumentParser()
    for key in("reference","compiler","out"):p.add_argument("--"+key,type=Path,required=True)
    p.add_argument("--component",choices=tuple(ROLES),required=True)
    args=p.parse_args();module=boot_subject()
    subject=module.Subject(args.out,"physical-after-"+args.component)
    out=subject.out;report=subject.report
    report.update(component=args.component,role=ROLES[args.component],compilations=0,
        reference_source_reproductions=0,native_semantic_entries=0,
        full_public_backend=False,full_public_transaction=False,
        unchanged_file_owner_expected=True,source_status="NEW_BEFORE_THIS_SUBJECT")
    old_modules={};finder=None
    def load(name,path,expected):
        raw=subject.capture(path,expected)
        value=types.ModuleType(name);value.__file__=str(Path(path).absolute())
        old_modules.setdefault(name,sys.modules.get(name))
        sys.modules[name]=value;exec(compile(raw,str(path),"exec"),value.__dict__)
        return value
    try:
        assert sys.version_info[:3]==(3,12,14)
        subject.capture(__file__)
        for name,identity in PINS.items():subject.capture(ROOT/name,identity)
        compiler=Path(args.compiler).absolute()
        assert len(subject.capture(compiler,COMPILER_SHA))==669556
        reference=Path(args.reference).resolve()
        original_builder=load("physical_original_builder",ROOT/"reference/build_backend_r1.py",
                              PINS["reference/build_backend_r1.py"])
        frozen={path.resolve():subject.capture(path)
                for prefix in("hepta","tools") for path in sorted((reference/prefix).rglob("*.py"))}
        assert frozen
        finder=original_builder.FrozenImports(reference,frozen)
        sys.meta_path.insert(0,finder)
        load("tools.hia_agent_edit_source_views",ROOT/"tools/hia_agent_edit_source_views.py",
             PINS["tools/hia_agent_edit_source_views.py"])
        author=load("physical_authoring_reference",ROOT/"tools/function_authoring_reference.py",
                    PINS["tools/function_authoring_reference.py"])
        common=load("physical_common",ROOT/"tools/hia_composite_lowering_driver_common.py",
                    PINS["tools/hia_composite_lowering_driver_common.py"])
        backend_raw=subject.capture(ROOT/"tools/hia_backend_controller.py",
                                    PINS["tools/hia_backend_controller.py"])
        backend=load("physical_backend",ROOT/"tools/hia_backend_controller.py",
                     PINS["tools/hia_backend_controller.py"])
        forwarder=load("physical_forwarder",ROOT/"tools/hia_backend_child_forwarder.py",
                       PINS["tools/hia_backend_child_forwarder.py"])
        files=load("physical_files",ROOT/"tools/hia_implementation_files.py",
                   PINS["tools/hia_implementation_files.py"])
        owner=load("physical_after_owner",ROOT/"tools/hia_backend_physical_after.py",
                   PINS["tools/hia_backend_physical_after.py"])
        assert owner.BASE_SHA==PINS["tools/hia_backend_controller.py"]
        assert owner.COMMON_SHA==files.COMMON_SHA==backend.COMMON_SHA==forwarder.COMMON_SHA==PINS["tools/hia_composite_lowering_driver_common.py"]
        assert owner.FILES_SHA==PINS["tools/hia_implementation_files.py"]
        assert backend.FORWARDER_SHA==PINS["tools/hia_backend_child_forwarder.py"]
        assert files.REFERENCE_SHA==PINS["reference/hia_program_native.py"]
        original=ast.parse(subject.capture(ROOT/"reference/hia_program_native.py",files.REFERENCE_SHA))
        method=next(n for n in original.body if isinstance(n,ast.FunctionDef) and n.name=="_implementation_hash")
        names=next(n.iter for n in ast.walk(method) if isinstance(n,ast.For))
        assert tuple(ast.literal_eval(names))==files.FILES and len(files.FILES)==20
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        if args.component=="parent":
            original_body,original_constants,original_scope=backend.source(common,forwarder)
            original_expanded=author.expanded(original_body,original_constants)
            old_document=author.document(original_expanded,"hia_backend_controller")
            old_source=render_assembly(old_document).encode("utf-8")
            (out/"original-parent.authoring.py").write_text(original_expanded)
            save(out/"original-parent.document.json",old_document)
            (out/"original-parent.hiaasm").write_bytes(old_source)
            assert (len(old_source),digest(old_source))==ORIGINAL_PARENT_SOURCE
            assert assemble_program(old_source).as_dict()==old_document
            save(out/"original-parent-reproduction.json",dict(status="EXACT_SOURCE_REPRODUCED",
                bytes=len(old_source),sha256=digest(old_source),semantic_entries=0,
                old_source_scope=original_scope,does_not_inherit_old_qualification=True))
            report["reference_source_reproductions"]+=1
        if args.component=="files":
            body,constants,scope=files.source(common)
            module_name="hia_implementation_controller"
        else:
            body,constants,scope=owner.source(common,forwarder,backend,backend_raw,ROLES[args.component])
            module_name="hia_backend_physical_after_"+args.component
        expanded=author.expanded(body,constants)
        (out/"authoring.py").write_text(expanded)
        document=author.document(expanded,module_name)
        profile,functions=profiles(author,expanded,document)
        save(out/"document.json",document)
        save(out/"profile-before-gates.json",profile)
        save(out/"profile-functions-before-gates.json",functions)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
        assert profile["max_blocks"]<=256 and profile["max_params"]<=16 and profile["max_ssa_index"]<2048
        source=render_assembly(document).encode("utf-8")
        source_path=out/"source.hiaasm";source_path.write_bytes(source)
        assert len(source)<=1<<20 and assemble_program(source).as_dict()==document
        if args.component=="files":
            assert (len(source),digest(source))==ORIGINAL_FILES_SOURCE
            report["reference_source_reproductions"]+=1
        save(out/"generation.json",dict(scope=scope,profile=profile,source_bytes=len(source),
            source_sha256=digest(source),second_readonly=False,
            twenty_original_names=list(files.FILES),physical_role=ROLES[args.component]))
        import tools.qualify_hia_selfhost as qualifier
        assert Path(qualifier.__file__).resolve()==reference/"tools/qualify_hia_selfhost.py"
        qualifier.CHILD=ROOT/"reference/hia_selfhost_child.py"
        compile_dir=out/"compile";compile_dir.mkdir()
        image_path,receipt=qualifier.compile_stage(compile_dir,
            "backend-physical-after-"+args.component,compiler,source)
        image=subject.capture(image_path)
        report["compilations"]+=1
        assert receipt["source_sha256"]==receipt["input_sha256"]==digest(source)
        assert receipt["input_bytes"]==len(source)
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER_SHA
        assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["limits"]["output_capacity"]==receipt["limits"]["workspace_bytes"]==1<<20
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        assert receipt["runner_sha256"]==PINS["reference/hia_selfhost_child.py"]
        assert receipt["wall_elapsed_ns"]<20_000_000_000 and 0<len(image)<=1<<20
        if args.component=="files":assert (len(image),digest(image))==ORIGINAL_FILES_IMAGE
        subject.capture(source_path,digest(source))
        manifest=dict(schema="hia-physical-after-development-component-v1",status="BUILT_ONLY",
            component=args.component,role=ROLES[args.component],
            source_path=str(source_path),source_bytes=len(source),source_sha256=digest(source),
            image_path=str(image_path),image_bytes=len(image),image_sha256=digest(image),
            author_sha256=PINS["tools/hia_implementation_files.py" if args.component=="files"
                               else "tools/hia_backend_physical_after.py"],
            compiler_sha256=COMPILER_SHA,compile_receipt=receipt,profile=profile,
            abi_second_readonly=False,source_scope=scope,
            before_implementation_authority_required=True,after_hash_is_physical_file_child=True,
            header_is_authentication=False,full_public_transaction=False,installed=False,cold=False)
        save(out/"physical-after.manifest.json",manifest)
        report.update(status="PASS_BUILD_ONLY",manifest=manifest)
    except BaseException as error:
        subject.failure(error)
        subject.attempt("primary-traceback",lambda:traceback.print_exception(error))
    finally:
        if finder is not None:
            subject.attempt("restore-finder",lambda:sys.meta_path.remove(finder))
        for name,previous in reversed(tuple(old_modules.items())):
            def restore(name=name,previous=previous):
                if previous is None:sys.modules.pop(name,None)
                else:sys.modules[name]=previous
            subject.attempt("restore-module:"+name,restore)
        subject.finish("PASS_BUILD_ONLY")
if __name__=="__main__":main()
