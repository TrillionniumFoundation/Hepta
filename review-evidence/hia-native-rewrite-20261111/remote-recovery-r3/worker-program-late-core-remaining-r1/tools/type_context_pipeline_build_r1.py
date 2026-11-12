"""Generate exact retained drivers first, then the native type-context routes.

All source modules are private copies. Exact old HIA is compared with both the
retained role map and, for role46, the complete original diagnostic archive.
Changing an original authoring file or borrowing a same-named version fails.
r2 restores the exact R9/R10 helper omitted by r1 and audits the complete actual
Python import closure before the first original-author module is loaded.
"""
from __future__ import annotations
import ast,importlib.util,json,os,stat,sys
from hashlib import sha256
from pathlib import Path

PINS={
 "hia_composite_lowering_driver_common.py":(17781,"fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"),
 "hia_composite_lowering_driver_main.py":(19407,"120675ee8bdb22e756277574146fb9319aa2d5009727fc22a49355afa4357824"),
 "hia_composite_lowering_driver_services.py":(25714,"a1757f1137571a52b61dc17f6b8258323de1fc7f22c02433fdfbbd783a81ec57"),
 "hia_composite_lowering_driver_helper.py":(15664,"fb392ada8b16cfaeedbdbfb55b46786c5923a8959f3cc32057f13383b5fa75df"),
 "hia_composite_constructor_driver.py":(18995,"bf9ddc7e0d8f17351483c3ea4b26947c0d871d68ec73689f0dc8baf8049a7741"),
 "generate_hia_composite_lowering_driver.py":(4286,"a8310af4888553243ca1473cc0d2f2eba0d862b785fae8f790c3f29764d7936c"),
 "generate_hia_program_admission_driver.py":(11395,"aaedd6b85df7cb20dd7b3f08610b514fb1b12d63750b3f67769981457137db48"),
 "generate_hia_composite_publication_driver.py":(9471,"e30dfdc977e532c812f985a52d683198203654c260ca52c23e4d38772825a93f"),
 "generate_hia_legacy_import_driver.py":(17529,"53cdf4ce01c8f14ab4894062fdc321a124f0b2ed16e39e284876d7eb37f9968c"),
 "generate_hia_core_diagnostic_drivers.py":(10040,"309db843703af67030c8b162c224da53416eefa69dd1f7865d0aaa504d38ae23"),
}
RETAINED={
 8:(380145,"33969ee0fdec37c27ebf017c52d01e20748118d643589cf280042a39f68e3d6b",541021,"dbe484770638ac36b72fc5930eb03862e4ee27f1e532f3a3b7c30acc5cd78612"),
 40:(138472,"c6cfd6f642c7baef077d2b4553a7cdd357b9f2560f16a24b410eb67219769b53",204836,"3ee7576897bc97d66594b82b1f99ae2541f390a690068256d9f83bc58d326d58"),
 41:(294375,"7ea90751a7694f2db6eabc88c721d1f0d98452225426e9dd4caf159d599b47dc",405541,"b64377c3c2e3a913bf469881c267933dd482e7cc2b768047b185080fe7d57b41"),
 43:(219439,"d947314b5ee9df1e9a5c72e18ca0490c8c30006952540c42166d402f46b3fae2",308470,"1db5c1d9e3a95cdf2c3ff2448fadd9c5cc0485ebfa70a0368d4be32bd661e966"),
 46:(161943,"68c0ddba4e02d48ea1b205ff2f6e2ea65dbddb3aad0e35cfb19085960daf0816",221718,"3b02302959d0f19503770db378360058ef81d354f856c256c4ce3d68b9731ba1"),
}
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def generate(project,reference,out,role_map,read):
    project=Path(project);reference=Path(reference);out=Path(out)
    out.mkdir(parents=True,exist_ok=False)
    import tools
    from hepta.hia_agent_assembly import render_assembly
    original_path=list(sys.path);original_tools_path=list(tools.__path__)
    original_environment=os.environ.get("HIA_BASELINE_ROOT")
    replaced={};originals={};proofs={};documents=[];status="FAIL";failure=None
    stage=out/"exact-authoring";stage.mkdir()
    ordinary=stage/"native-composite-driver-reconstructed"
    program=stage/"native-program-admission-next"
    legacy=stage/"native-composite-legacy-import-next"
    diagnostics=stage/"native-core-diagnostics-next"
    for directory in (ordinary,program,legacy,diagnostics):
        (directory/"tools").mkdir(parents=True)
        (directory/"development").mkdir()
    def copied(name,root):
        raw=read(project/"baseline"/name)
        assert (len(raw),digest(raw))==PINS[name],name
        path=root/"tools"/name;path.write_bytes(raw);path.chmod(0o644);read(path)
        originals[name]=dict(path=str(path),bytes=len(raw),sha256=digest(raw))
        return path
    def load(name,path):
        raw=read(path);ast.parse(raw,filename=str(path))
        if name not in replaced:replaced[name]=sys.modules.get(name)
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        spec.loader.exec_module(module);return module
    def original_gate(role,body,doc):
        raw=render_assembly(doc).encode("utf-8");row=role_map["components"][str(role)]
        source=read(Path(row["source_path"]));image=read(Path(row["image_path"]))
        expected=RETAINED[role]
        assert (len(source),digest(source),len(image),digest(image))==expected,(role,row)
        assert (row["source_bytes"],row["source_sha256"],row["image_bytes"],row["image_sha256"])==expected
        assert raw==source,(role,len(raw),digest(raw),expected)
        folder=out/"retained-generated"/str(role);folder.mkdir(parents=True)
        (folder/"authoring.py").write_text(body);(folder/"source.hiaasm").write_bytes(raw)
        save(folder/"document.json",doc)
        proofs[str(role)]=dict(generated_HIA_bytes_equal_retained=True,
            source_bytes=len(raw),source_sha256=digest(raw),
            retained_image_bytes=len(image),retained_image_sha256=digest(image),
            original_doc_module=doc["module"])
        return raw
    def original_import_closure():
        # Actual Python imports in this selected build, not all possible CLI
        # entrypoints of the historical author modules.
        private={
            "tools.hia_composite_lowering_driver_common":ordinary/"tools/hia_composite_lowering_driver_common.py",
            "tools.hia_composite_lowering_driver_main":ordinary/"tools/hia_composite_lowering_driver_main.py",
            "tools.hia_composite_lowering_driver_services":ordinary/"tools/hia_composite_lowering_driver_services.py",
            "tools.hia_composite_lowering_driver_helper":ordinary/"tools/hia_composite_lowering_driver_helper.py",
            "tools.hia_composite_constructor_driver":ordinary/"tools/hia_composite_constructor_driver.py",
            "tools.generate_hia_composite_lowering_driver":ordinary/"tools/generate_hia_composite_lowering_driver.py",
            "tools.program_authoring":program/"tools/program_authoring.py",
            "type_context_original_corpus_r1":project/"development/type_context_original_corpus_r1.py",
            "type_context_public_plans_r2":project/"development/type_context_public_plans_r2.py",
        }
        actual=dict(private)
        actual.update({
            "frozen_diagnostic_program":program/"tools/generate_hia_program_admission_driver.py",
            "frozen_diagnostic_publication":ordinary/"tools/generate_hia_composite_publication_driver.py",
            "type_context_exact_diagnostic_driver_generator":diagnostics/"tools/generate_hia_core_diagnostic_drivers.py",
            "selected_full_group_test_AST_only":project/"development/test_worker_type_context_program_r2.py",
        })
        references={
            "hepta.hia_agent_assembly":reference/"hepta/hia_agent_assembly.py",
            "hepta.hia_program":reference/"hepta/hia_program.py",
            "tools.generate_hia_selfhost":reference/"tools/generate_hia_selfhost.py",
        }
        stdlib={"__future__","argparse","ast","copy","ctypes","hashlib","importlib","importlib.util",
                "json","os","pathlib","resource","signal","stat","struct","subprocess","sys",
                "time","traceback","types","zlib"}
        rows=[]
        def imports(tree,origin):
            for node in ast.walk(tree):
                if isinstance(node,ast.ImportFrom):
                    assert node.level==0,(origin,node.lineno,"unexpected relative import")
                    yield node.module,node.lineno
                elif isinstance(node,ast.Import):
                    for name in node.names:yield name.name,node.lineno
        for module,path in actual.items():
            raw=read(path);tree=ast.parse(raw,filename=str(path))
            source_imports=list(imports(tree,str(path)))
            embedded=[]
            for node in ast.walk(tree):
                if not isinstance(node,ast.Constant) or not isinstance(node.value,str):continue
                text=node.value
                lines=[line.strip() for line in text.splitlines()]
                if not any(line.startswith(("from tools.","import tools.","from hepta.","import hepta.")) for line in lines):continue
                nested=ast.parse(text,filename=str(path)+"#embedded")
                embedded.extend(imports(nested,str(path)+"#embedded"))
            for dependency,line in source_imports+embedded:
                if dependency in stdlib:continue
                target=private.get(dependency,references.get(dependency))
                assert target is not None,(module,line,"unclosed authoring import",dependency)
                data=read(target)
                assert target.is_file() and not target.is_symlink()
                assert stat.S_IMODE(target.stat().st_mode)==0o644
                rows.append(dict(module=module,dependency=dependency,line=line,path=str(target),
                                 bytes=len(data),sha256=digest(data)))
        generator_tree=ast.parse(read(ordinary/"tools/generate_hia_composite_lowering_driver.py"))
        declarations=[node for node in generator_tree.body if isinstance(node,ast.Assign)
                      and any(isinstance(target,ast.Name) and target.id=="MODULES" for target in node.targets)]
        assert len(declarations)==1
        dynamic=ast.literal_eval(declarations[0].value)
        assert dynamic=={
            "ctor":"tools.hia_composite_constructor_driver",
            "main":"tools.hia_composite_lowering_driver_main",
            "services":"tools.hia_composite_lowering_driver_services",
            "stream":"tools.hia_composite_lowering_driver_stream"}
        selected=("main","services","ctor")
        assert all(dynamic[kind] in private for kind in selected)
        # program.source_program reads legacy BODY through ast.literal_eval;
        # it never imports the legacy module or tools.legacy_authoring.
        legacy_path=legacy/"tools/generate_hia_legacy_import_driver.py"
        legacy_raw=read(legacy_path);legacy_tree=ast.parse(legacy_raw,filename=str(legacy_path))
        assigned=[node for node in legacy_tree.body if isinstance(node,ast.Assign)
                  and any(isinstance(target,ast.Name) and target.id=="BODY" for target in node.targets)]
        assert len(assigned)==1 and isinstance(ast.literal_eval(assigned[0].value),str)
        for module,path in references.items():
            loaded=sys.modules.get(module)
            if loaded is None:
                loaded=importlib.import_module(module)
            assert Path(loaded.__file__).resolve()==path.resolve(),(module,path)
            read(path)
        fixture_loads=[]
        for module,size,identity in (
            ("type_context_original_corpus_r1",11863,"110f96c2f8a1744d4c65e6487bde8d214d76987a3f9e50afebdecb4199188206"),
            ("type_context_public_plans_r2",3973,"1896ec7c44225df0c0acc0e6bdca54e5dcd7ea8e461870b4190995e2b59b8474"),
        ):
            path=private[module];raw=read(path)
            assert (len(raw),digest(raw))==(size,identity),module
            loaded=load(module,path)
            assert Path(loaded.__file__).resolve()==path.resolve(),module
            assert read(path)==raw,module
            fixture_loads.append(dict(module=module,path=str(path),bytes=size,sha256=identity,
                actual_module_loaded_before_B3=True,oracle_case_functions_executed=False))
        assert sys.modules["type_context_original_corpus_r1"].__file__==str(private["type_context_original_corpus_r1"])
        save(out/"exact-original-import-closure.json",dict(
            schema="hia-type-context-authoring-import-closure-r3",status="PASS",
            exact_runpy_test_sibling_import_closure=fixture_loads,
            full_group_test_static_import_inventory_checked=True,
            test_module_not_loaded_via_implicit_sys_path=True,
            all_actual_static_and_embedded_imports_resolved=True,imports=rows,
            actual_dynamic_lowering_kinds=list(selected),
            unchanged_stream_role42_not_generated_or_imported=True,
            legacy_owner_read_as_exact_BODY_only=True,legacy_module_not_imported=True,
            exact_legacy_source_sha256=digest(legacy_raw),
            exact_helper_bytes=15664,
            exact_helper_sha256=PINS["hia_composite_lowering_driver_helper.py"][1],
            exact_helper_origin="R9/R10 original dependencies/native-composite-driver-reconstructed/tools; FOLLOW49 full-member reader",
            new_B3_entries_at_this_gate=0,project_business_functions_executed=0))
    try:
        os.environ["HIA_BASELINE_ROOT"]=str(reference)
        sys.path[:0]=[str(program),str(ordinary),str(reference)]
        tools.__path__=[str(project/"tools"),str(program/"tools"),
                        str(ordinary/"tools"),*original_tools_path]
        for name in ("hia_composite_lowering_driver_common.py",
                     "hia_composite_lowering_driver_main.py",
                     "hia_composite_lowering_driver_services.py",
                     "hia_composite_lowering_driver_helper.py",
                     "hia_composite_constructor_driver.py",
                     "generate_hia_composite_lowering_driver.py",
                     "generate_hia_composite_publication_driver.py"):
            copied(name,ordinary)
        copied("generate_hia_program_admission_driver.py",program)
        copied("generate_hia_legacy_import_driver.py",legacy)
        copied("generate_hia_core_diagnostic_drivers.py",diagnostics)
        restored=project/"restored-type-context-reference"
        helper=read(restored/"program_authoring.py")
        assert (len(helper),digest(helper))==(3142,
            "7507a7f355d6e77532d0bfdce0a90383a679fab263a0e765311e143351bc772d")
        path=program/"tools/program_authoring.py";path.write_bytes(helper);read(path)
        assert read(restored/"generate_hia_core_diagnostic_drivers.py")==read(diagnostics/"tools/generate_hia_core_diagnostic_drivers.py")
        source_before=json.loads(read(restored/"diagnostic-source-before.json"))
        wanted=PINS["generate_hia_core_diagnostic_drivers.py"]
        source_bindings=[row for path,row in source_before.items()
                         if path.endswith("/tools/generate_hia_core_diagnostic_drivers.py")]
        assert len(source_bindings)==1
        assert (source_bindings[0]["bytes"],source_bindings[0]["sha256"])==wanted
        original_import_closure()
        helper_module=load("tools.hia_composite_lowering_driver_helper",ordinary/"tools/hia_composite_lowering_driver_helper.py")
        assert isinstance(helper_module.BODY,str)
        common=load("tools.hia_composite_lowering_driver_common",ordinary/"tools/hia_composite_lowering_driver_common.py")
        main=load("tools.hia_composite_lowering_driver_main",ordinary/"tools/hia_composite_lowering_driver_main.py")
        services=load("tools.hia_composite_lowering_driver_services",ordinary/"tools/hia_composite_lowering_driver_services.py")
        ctor=load("tools.hia_composite_constructor_driver",ordinary/"tools/hia_composite_constructor_driver.py")
        lower=load("tools.generate_hia_composite_lowering_driver",ordinary/"tools/generate_hia_composite_lowering_driver.py")
        for kind,role in (("main",40),("services",41),("ctor",43)):
            body=lower.source_program(kind);original_gate(role,body,lower.document(kind))
        authoring=load("tools.program_authoring",path)
        diag=load("type_context_exact_diagnostic_driver_generator",
                  diagnostics/"tools/generate_hia_core_diagnostic_drivers.py")
        body=diag.source_program("program")
        assert body.encode()==read(restored/"diagnostic_program_authoring_original.py")
        doc=authoring.document(body,"diagnostic_program_driver")
        raw=original_gate(46,body,doc)
        assert raw==read(restored/"diagnostic_program_driver.hiaasm")
        assert read(restored/"diagnostic_program_driver.image.bin")==read(Path(role_map["components"]["46"]["image_path"]))
        original_program=diag.load("program")
        program_constants=dict(original_program.CONSTANTS);program_constants.update(diag.EXTRA)
        extension=load("tools.extend_native_type_context_r1",project/"tools/extend_native_type_context_r1.py")
        reader=load("type_context_route_reader_generator",project/"tools/generate_type_context_reader_r1.py")
        type_owner=load("type_context_route_original_types",reference/"tools/generate_hia_composite_types.py")
        assert digest(read(type_owner.__file__))==extension.ORIGINAL_SHA
        old_type=type_owner.source_program();original_gate(8,old_type,type_owner.document())
        routes=load("tools.type_context_routes_common_r1",project/"tools/type_context_routes_common_r1.py")
        lower_extension=load("type_context_route_lowering_extension",project/"tools/extend_type_context_lowering_r1.py")
        program_extension=load("type_context_route_program_extension",project/"tools/extend_type_context_program_r1.py")
        new_program,program_proof=program_extension.attach(body,program_constants,reader)
        documents.append(dict(role=46,label="context-program-admission",body=new_program,
                              document=authoring.document(new_program,"diagnostic_program_driver")))
        save(out/"program-context-adaptation.json",program_proof)
        adapted=lower_extension.attach(common,main,services,ctor,reader)
        common.COMMON=adapted["common"];common.CONSTANTS.update(adapted["constants"])
        main.BODY=adapted["main"];services.BODY=adapted["services"];ctor.BODY=adapted["ctor"]
        lower.COMMON=common.COMMON;lower.CONSTANTS=common.CONSTANTS
        for kind,role in (("main",40),("services",41),("ctor",43)):
            body=lower.source_program(kind)
            documents.append(dict(role=role,label="context-lowering-"+kind,body=body,document=lower.document(kind)))
        save(out/"lowering-context-adaptation.json",adapted["proof"])
        adaptation=extension.apply(type_owner);save(out/"type-owner-adaptation.json",adaptation)
        body=type_owner.source_program()
        documents.append(dict(role=8,label="context-types",body=body,document=type_owner.document()))
        doc,body,inventory=reader.generated_document()
        save(out/"reader-inventory.json",inventory)
        documents.append(dict(role=50,label="context-reader",body=body,document=doc))
        assert {row["role"] for row in documents}=={8,40,41,43,46,50}
        assert set(proofs)=={"8","40","41","43","46"}
        status="PASS"
        return documents,reader
    except BaseException as exc:
        import traceback
        failure=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
        raise
    finally:
        for name,previous in reversed(tuple(replaced.items())):
            if previous is None:sys.modules.pop(name,None)
            else:sys.modules[name]=previous
        tools.__path__=original_tools_path;sys.path[:]=original_path
        if original_environment is None:os.environ.pop("HIA_BASELINE_ROOT",None)
        else:os.environ["HIA_BASELINE_ROOT"]=original_environment
        save(out/"exact-retained-driver-reproduction.json",dict(
            schema="hia-type-context-native-pipeline-authoring-r1",status=status,
            exact_private_original_sources=originals,retained_source_proofs=proofs,
            newly_generated_roles=[row["role"] for row in documents],
            original_files_modified=False,original_images_executed=False,
            requires_actual_new_B3_and_full_runtime_qualification=True,failure=failure))
