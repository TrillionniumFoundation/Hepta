"""Four original-limit B3 images and two complete native HIA ELF packing runs.

The complete R9 37-role table is first restored and source-bound. Exact old
importer HIA, old packer HIA, their produced images and the full old ELF must
match before the new role46/diagnostic executor may be used.
"""
from __future__ import annotations
import argparse,ast,importlib,json,os,re,resource,stat,struct,subprocess,sys,time,traceback,types
from hashlib import sha256
from pathlib import Path
ROLES=tuple(range(1,30))+tuple(range(40,48))
COMPILER_SHA="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
def digest(raw):return sha256(raw).hexdigest()
def write_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n");path.chmod(0o644)
def profile(doc,raw):
    fns=doc["functions"];blocks=[b for f in fns for b in f["blocks"]]
    numeric=[]
    def walk(v):
        if isinstance(v,str) and re.fullmatch(r"v[0-9]+",v):numeric.append(int(v[1:]))
        elif isinstance(v,list):
            for item in v:walk(item)
        elif isinstance(v,dict):
            for item in v.values():walk(item)
    walk(doc)
    out=dict(functions=len(fns),blocks=len(blocks),ops=sum(len(b["ops"]) for b in blocks),
        instructions=sum(len(b["ops"])+1 for b in blocks),
        max_blocks=max(len(f["blocks"]) for f in fns),
        max_parameters=max([len(f["params"]) for f in fns]+[len(b["params"]) for b in blocks]),
        max_ssa_index=max(numeric,default=-1),source_bytes=len(raw))
    assert out["functions"]<=128 and out["blocks"]<=1536
    assert out["instructions"]<=8192 and out["max_blocks"]<=256
    assert out["max_parameters"]<=16 and out["max_ssa_index"]<2048 and len(raw)<=1<<20
    return out
def main():
    parser=argparse.ArgumentParser()
    for name in ("project","reference","original","compiler","out"):parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();project=args.project.resolve();reference=args.reference.resolve()
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    original_path=args.original.resolve();original=json.loads(original_path.read_bytes())
    assert original["status"]=="VERIFIED_ORIGINAL_BYTES_ONLY" and original["original_members"]==2949
    assert set(map(int,original["components"]))==set(ROLES)
    members=original_path.parent/"members"
    compiler=args.compiler.resolve();assert (compiler.stat().st_size,digest(compiler.read_bytes()))==(668608,COMPILER_SHA)
    assert sys.version_info[:3]==(3,12,14)
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.environ["HIA_BASELINE_ROOT"]=str(reference)
    sys.path[:0]=[str(project/"development"),str(project),str(reference)]
    import tools
    tools.__path__[:]=[str(project/"tools")]+[p for p in tools.__path__ if p!=str(project/"tools")]
    from hepta.hia_agent_assembly import render_assembly
    from tools.qualify_hia_selfhost import compile_stage
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from legacy_diagnostic_test_support_r1 import Buffer,NativeCalls
    from tools import legacy_authoring as author
    from tools import generate_hia_legacy_import_driver as legacy
    from tools import generate_hia_legacy_cli as packer
    from tools import extend_explicit_legacy_group9_r1 as extension
    from tools import compose_explicit_legacy_diagnostic_executor_r1 as mechanical
    pins={};after_errors=[];primary=None;compiled=[];images=[];status="FAIL"
    trace=NativeCalls(out/"actual-native-packing");started=time.monotonic_ns()
    def pin(path):
        path=Path(path).resolve();st=path.lstat()
        assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
        raw=path.read_bytes();value=(raw,stat.S_IMODE(st.st_mode))
        if path in pins:assert pins[path]==value
        else:pins[path]=value
        return raw
    def original_pair(row):
        raw=pin(row["path"])
        assert (len(raw),digest(raw),stat.S_IMODE(Path(row["path"]).stat().st_mode))==(row["bytes"],row["sha256"],row["mode"])
        return raw
    def save_source(path,raw):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644);pin(path)
    def compile_one(label,doc,raw):
        folder=out/label;folder.mkdir()
        save_source(folder/"source.hiaasm",raw)
        shape=profile(doc,raw);write_json(folder/"profile-before-B3.json",shape)
        image,receipt=compile_stage(folder,label,compiler,raw)
        produced=pin(image)
        assert receipt["input_sha256"]==digest(raw) and receipt["artifact_sha256"]==COMPILER_SHA
        assert receipt["produced_sha256"]==digest(produced) and receipt["produced_bytes"]==len(produced)
        row=dict(label=label,source_path=str(folder/"source.hiaasm"),source_bytes=len(raw),source_sha256=digest(raw),
            image_path=str(image),image_bytes=len(produced),image_sha256=digest(produced),
            receipt_path=str(folder/(label+".receipt.json")),profile=shape,compiler_sha256=COMPILER_SHA)
        pin(row["receipt_path"]);compiled.append(row)
        write_json(out/"completed-compiles.json",compiled)
        return row
    def packed(label,row,prefix,table,policy,components,original_exe=None):
        native=NativeHiaJsonImage(pin(row["image_path"]),expected_sha256=row["image_sha256"]);images.append(native)
        raws=[Path(components[str(role)]["image_path"]).read_bytes() for role in ROLES]
        entries=b"".join(struct.pack("<3Q",role,len(raw),0) for role,raw in zip(ROLES,raws))
        size=64+len(entries)+sum(map(len,raws))
        payload=struct.pack("<8Q",packer.MAGIC,37,2,4300,size,0,0,0)+entries+b"".join(raws)
        bound=len(prefix)+sum(len(raw)+15 for raw in raws)
        s=Buffer(payload,readonly=True);o=Buffer(size=bound);w=Buffer(size=64)
        try:
            result=trace.call(native,s,o,w,label=label)
            assert len(prefix)<result<=bound
            actual=o.value()[:result];assert o.value()[result:]==bytes(bound-result)
            expected=bytearray(prefix);placements=[]
            for role,raw in zip(ROLES,raws):
                while len(expected)%16:expected.append(0)
                at=len(expected);expected.extend(raw)
                struct.pack_into("<Q",expected,table+role*8,0x400000+at)
                placements.append(dict(role=role,offset=at,bytes=len(raw),sha256=digest(raw)))
            struct.pack_into("<2Q",expected,96,len(expected),len(expected))
            struct.pack_into("<2Q",expected,policy,2,4300)
            assert actual==bytes(expected)
            if original_exe is not None:assert actual==original_exe
            target=out/label/"hia-import-legacy-composite";target.write_bytes(actual);target.chmod(0o755);pin(target)
            return dict(path=str(target),bytes=len(actual),sha256=digest(actual),mode=0o755,
                full_ELF_and_all_padding_compared=True,roles=placements,actual_packer_return=result,
                exact_historical_ELF=original_exe is not None,source_input_sha256=digest(payload))
        finally:s.close();o.close();w.close()
    summary=dict(status="FAIL",scope="NEW_EXPLICIT_LEGACY_GROUP9_DEVELOPMENT_BUILD",
        actual_compiles=0,compile_plan=4,actual_native_packer_entries=0,
        ordinary_P16_changed=False,whole_worker_closed=False,installed=False)
    bundle=None
    try:
        pin(original_path);pin(compiler)
        for folder in ("tools","development","reference"):
            for path in sorted((project/folder).rglob("*")):
                if path.is_file() and not path.is_relative_to(out):pin(path)
        for base in (reference/"hepta",reference/"tools"):
            for path in sorted(base.glob("*.py")):pin(path)
        source_bindings={}
        for role in ROLES:
            old=original["components"][str(role)]
            source=original_pair(old["source"]);image=original_pair(old["image"])
            assert source==original_pair(old["expected_source"])
            source_bindings[str(role)]=dict(role=role,source_path=old["source"]["path"],source_bytes=len(source),
                source_sha256=digest(source),image_path=old["image"]["path"],image_bytes=len(image),
                image_sha256=digest(image),origin_member=old["source"]["member"])
        oldexe=original_pair(original["executable"])
        old_packer_source=original_pair(original["packer"]["source"])
        old_packer_image=original_pair(original["packer"]["image"])
        # These exact owner/helper sources are simultaneously retained in R9.
        correspondence={
            "generate_hia_legacy_import_driver.py":"importer/tools/generate_hia_legacy_import_driver.py",
            "legacy_authoring.py":"importer/tools/legacy_authoring.py",
            "generate_hia_legacy_cli.py":"importer/tools/generate_hia_legacy_cli.py",
            "legacy_native_executor.S":"importer/tools/legacy_native_executor.S",
            "hia_composite_lowering_driver_common.py":"dependencies/native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py",
            "hia_composite_lowering_driver_services.py":"dependencies/native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_services.py",
            "hia_composite_lowering_driver_helper.py":"dependencies/native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_helper.py"}
        for name,member in correspondence.items():assert pin(project/"tools"/name)==pin(members/member)
        assert Path(legacy.__file__).resolve()==project/"tools/generate_hia_legacy_import_driver.py"
        assert Path(author.__file__).resolve()==project/"tools/legacy_authoring.py"
        assert Path(packer.__file__).resolve()==project/"tools/generate_hia_legacy_cli.py"
        old_text=legacy.source_program()
        old_doc=author.document(old_text,"legacy_composite_import_driver")
        old_hia=render_assembly(old_doc).encode("utf-8")
        assert old_hia==Path(source_bindings["46"]["source_path"]).read_bytes()
        new_text,proof=extension.extend(legacy,pin(legacy.__file__),
            pin(project/"tools/hia_composite_lowering_driver_common.py"),
            pin(reference/"hepta/hia_core_upgrade.py"),pin(reference/"hepta/hia_program.py"))
        new_doc=author.document(new_text,"legacy_composite_import_driver")
        new_hia=render_assembly(new_doc).encode("utf-8")
        save_source(out/"original-importer.authoring.py",old_text.encode())
        save_source(out/"diagnostic-importer.authoring.py",new_text.encode())
        write_json(out/"HIA-diagnostic-derivation.json",proof)
        # Use the complete original pinned template as an immutable baseline.
        # The new template is assembled from the one-edit exact S derivation.
        template_ns=dict(packer.template.__globals__,ROOT=members/"importer")
        old_template=types.FunctionType(packer.template.__code__,template_ns,
            packer.template.__name__,packer.template.__defaults__,packer.template.__closure__)
        old_prefix,old_table,old_policy=old_template()
        for name in ("legacy_native_executor.bin","legacy_native_executor_layout.json"):
            pin(members/"importer/tools"/name)
        new_asm,executor_proof=mechanical.source(pin(project/"tools/legacy_native_executor.S"))
        save_source(out/"diagnostic-native-executor.S",new_asm)
        write_json(out/"executor-exact-inverse.json",executor_proof)
        commands=[["as","--64","-o",str(out/"executor.o"),str(out/"diagnostic-native-executor.S")],
            ["readelf","-rW",str(out/"executor.o")],["nm","-n",str(out/"executor.o")],
            ["objcopy","-O","binary","-j",".text",str(out/"executor.o"),str(out/"executor.bin")]]
        logs=[]
        for i,command in enumerate(commands):
            r=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            save_source(out/("tool-%d.stdout"%i),r.stdout);save_source(out/("tool-%d.stderr"%i),r.stderr)
            logs.append(dict(command=command,returncode=r.returncode));write_json(out/"assembler-commands.json",logs)
            assert r.returncode==0,(command,r.stderr)
        assert b"There are no relocations in this file." in (out/"tool-1.stdout").read_bytes()
        symbols={}
        for line in (out/"tool-2.stdout").read_text().splitlines():
            parts=line.split()
            if len(parts)==3:symbols[parts[2]]=int(parts[0],16)
        binary=pin(out/"executor.bin")
        assert symbols["executor_start"]==0 and symbols["executor_end"]==len(binary)
        assert binary[symbols["image_table"]:symbols["image_table"]+512]==bytes(512)
        assert struct.unpack_from("<2Q",binary,symbols["executable_policy"])==(2,4300)
        new_prefix=old_prefix[:176]+binary
        new_table=176+symbols["image_table"];new_policy=176+symbols["executable_policy"]
        def packer_document(prefix,table,policy):
            source_globals=dict(packer.source_program.__globals__,template=lambda:(prefix,table,policy))
            fn=packer.source_program
            authored=types.FunctionType(fn.__code__,source_globals,fn.__name__,fn.__defaults__,fn.__closure__)
            document_globals=dict(packer.document.__globals__,source_program=authored)
            fn=packer.document
            build=types.FunctionType(fn.__code__,document_globals,fn.__name__,fn.__defaults__,fn.__closure__)
            return build()
        old_pack_doc=packer_document(old_prefix,old_table,old_policy)
        old_pack_hia=render_assembly(old_pack_doc).encode()
        assert old_pack_hia==old_packer_source
        new_pack_doc=packer_document(new_prefix,new_table,new_policy)
        new_pack_hia=render_assembly(new_pack_doc).encode()
        for name,doc,hia in (("original-importer",old_doc,old_hia),
                ("diagnostic-importer",new_doc,new_hia),
                ("original-packer",old_pack_doc,old_pack_hia),
                ("diagnostic-packer",new_pack_doc,new_pack_hia)):
            write_json(out/(name+"-profile.json"),profile(doc,hia))
        write_json(out/"before-B3-exact-origin.json",dict(status="PASS",
            original_role46_HIA_equal=True,original_packer_HIA_equal=True,
            full37_source_image_binding=True,source_members=correspondence,
            executor_source_inverse=executor_proof,original_archive=original["archive"],
            project_imports_before_complete_archive=False))
        original46=compile_one("original-importer",old_doc,old_hia)
        assert Path(original46["image_path"]).read_bytes()==Path(source_bindings["46"]["image_path"]).read_bytes()
        changed46=compile_one("diagnostic-importer",new_doc,new_hia)
        original_pack=compile_one("original-packer",old_pack_doc,old_pack_hia)
        assert Path(original_pack["image_path"]).read_bytes()==old_packer_image
        changed_pack=compile_one("diagnostic-packer",new_pack_doc,new_pack_hia)
        old_exe_result=packed("original-packer",original_pack,old_prefix,old_table,old_policy,source_bindings,oldexe)
        changed_roles=dict(source_bindings);changed_roles["46"]=dict(changed46,role=46)
        new_exe_result=packed("diagnostic-packer",changed_pack,new_prefix,new_table,new_policy,changed_roles)
        constants=dict(legacy.CONSTANTS,**extension.CONSTANTS)
        bundle=dict(schema="hia-explicit-legacy-native-full-diagnostic-bundle-r1",
            status="BUILT_ONLY",components=changed_roles,original_components=source_bindings,
            compiler_sha256=COMPILER_SHA,compiled=compiled,original=original,
            original_executable=old_exe_result,executable=new_exe_result,constants=constants,
            diagnostic_messages=extension.MESSAGES,HIA_derivation=str(out/"HIA-diagnostic-derivation.json"),
            executor_derivation=str(out/"executor-exact-inverse.json"),original37_HIA_image_binding=True,
            original_role46_exact_HIA_image_reproduced=True,original_packer_exact_HIA_image_reproduced=True,
            original_whole_ELF_reproduced=True,actual_packer_entries=2,fresh_B3=4,
            only_semantic_owner_replaced=46,all_other36_source_image_bytes_retained=True,
            ordinary_P16_route_changed=False,group4_public_reachability_proved=False,
            installed=False,whole_worker_closed=False)
        status="PASS"
    except BaseException as exc:
        primary=exc;traceback.print_exc()
    finally:
        for image in images:
            try:image._mapping.close()
            except BaseException as exc:
                after_errors.append(dict(phase="image-close",type=type(exc).__name__,error=str(exc)))
                if primary is None:primary=exc
        try:trace.verify()
        except BaseException as exc:
            after_errors.append(dict(phase="actual-packer-evidence",type=type(exc).__name__,error=str(exc)))
            if primary is None:primary=exc
        for path,(raw,mode) in pins.items():
            try:
                assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode and not path.is_symlink()
            except BaseException as exc:
                after_errors.append(dict(phase="source-image-after",path=str(path),type=type(exc).__name__))
                if primary is None:primary=exc
        if primary is not None or after_errors:status="FAIL"
        write_json(out/"source-and-image-pins.json",[
            dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=mode) for p,(raw,mode) in sorted(pins.items())])
        if bundle is not None:
            bundle["source_and_image_before_after_equal"]=not after_errors
            if status!="PASS":bundle["status"]="FAIL"
            write_json(out/"bundle.json",bundle)
        summary.update(status=status,actual_compiles=len(compiled),actual_compile_attempts=len(compiled),
            actual_native_packer_entries=len(trace.entries),source_and_image_before_after_equal=not after_errors,
            error=None if primary is None else dict(type=type(primary).__name__,error=str(primary)),
            after_errors=after_errors,elapsed_ns=time.monotonic_ns()-started)
        write_json(out/"summary.json",summary)
        print("HIA_EXPLICIT_LEGACY_BUILD "+json.dumps(summary,sort_keys=True),flush=True)
    if primary is not None:raise primary
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
