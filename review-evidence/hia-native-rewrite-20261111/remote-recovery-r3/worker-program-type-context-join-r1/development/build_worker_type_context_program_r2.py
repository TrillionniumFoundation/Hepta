"""Fresh actual type-context P16 fixed-ELF build, thirteen bounded B3 compiles.

This is a development builder. It invokes no public Worker, Store or CLI
business function. The final ELF is emitted by actual HIA and compared in full.
"""
from __future__ import annotations
import argparse,ast,ctypes,importlib.util,json,os,resource,stat,struct,sys,time,traceback,zlib
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
for name in ("project","reference","workspace","compiler","out"):
    p.add_argument("--"+name,type=Path,required=True)
a=p.parse_args()
PROJECT=a.project.resolve();REF=a.reference.resolve();WORK=a.workspace.resolve()
COMPILER=a.compiler.resolve();OUT=a.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
ROOT_TOOLS=PROJECT/"tools"
COMPILER_SHA="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
LIVE_OLD=set(range(1,29))|set(range(40,47))|{55}
NEW_ROLES={50,51,56,59,61,62,63};LIVE=LIVE_OLD|NEW_ROLES
assert len(LIVE_OLD)==36 and len(LIVE)==43
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
PINS={};compiled=[];compile_attempts=[];status="FAIL";failure=None;packer_entries=0
started=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def read(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in PINS:assert PINS[path]==(raw,mode),path
    PINS[path]=(raw,mode);return raw
def unchanged():
    return all(p.is_file() and p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==mode
               for p,(raw,mode) in PINS.items())
def load(name,path):
    raw=read(path);ast.parse(raw,filename=str(path))
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module
def cas(raw):
    raw=bytes(raw);h=digest(raw);target=OUT/"cas"/(h+".zlib")
    target.parent.mkdir(exist_ok=True)
    if not target.exists():target.write_bytes(zlib.compress(raw,1))
    assert zlib.decompress(target.read_bytes())==raw
    return dict(bytes=len(raw),sha256=h,path="cas/"+target.name,compression="zlib")
def compile_document(label,body,doc):
    where=OUT/"compiled"/label;where.mkdir(parents=True)
    (where/"authoring.py").write_text(body);save(where/"document.json",doc)
    profile=generator.measured(doc);save(where/"profile.json",profile)
    raw=render_assembly(doc).encode("utf-8");assemble_program(raw)
    assert 0<len(raw)<=1048576
    source=where/"source.hiaasm";source.write_bytes(raw);read(source)
    assert read(COMPILER)==compiler_raw
    compile_attempts.append(dict(label=label,source_sha256=digest(raw),source_bytes=len(raw),
                                 compiler_sha256=COMPILER_SHA))
    save(OUT/"compile-attempts.json",compile_attempts)
    image,receipt=compile_stage(where,label,COMPILER,raw);binary=read(image)
    assert receipt["status"]=="returned" and receipt["abi_status"]==0
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==268435456
    assert receipt["input_sha256"]==digest(raw) and receipt["produced_sha256"]==digest(binary)
    assert receipt["artifact_sha256"]==COMPILER_SHA and len(binary)==receipt["core_u32"]
    assert 0<len(binary)<=1048576
    row=dict(label=label,source_path=str(source),source_bytes=len(raw),source_sha256=digest(raw),
             image_path=str(image),image_bytes=len(binary),image_sha256=digest(binary),
             profile=profile,receipt=receipt)
    compiled.append(row);save(where/"manifest.json",row)
    print("HIA_WORKER_PROGRAM_COMPILE "+json.dumps(row,sort_keys=True),flush=True)
    return binary,row

class Guard:
    """Private mapped exact extent and full canaries; optional actual mprotect."""
    def __init__(self,raw,size=None,fill=0,readonly=False):
        self.size=len(raw) if size is None else size
        assert 0<=len(raw)<=self.size
        self.total=((self.size+128+4095)//4096)*4096
        self.addr=int(libc.mmap(None,self.total,3,0x22,-1,0))
        assert self.addr!=ctypes.c_void_p(-1).value
        self.ptr=self.addr+64
        ctypes.memset(self.addr,0x5d,self.total)
        if self.size:ctypes.memset(self.ptr,fill,self.size)
        if raw:ctypes.memmove(self.ptr,raw,len(raw))
        self.readonly=readonly
        if readonly:assert libc.mprotect(self.addr,self.total,1)==0
    def value(self):return ctypes.string_at(self.ptr,self.size)
    def check(self):
        assert ctypes.string_at(self.addr,64)==bytes([0x5d])*64
        assert ctypes.string_at(self.ptr+self.size,self.total-self.size-64)==bytes([0x5d])*(self.total-self.size-64)
    def close(self):
        if self.addr is not None:
            assert libc.munmap(self.addr,self.total)==0
            self.addr=None
try:
    read(__file__)
    source_index=json.loads(read(PROJECT/"sources.json"))
    for row in source_index["files"]:
        path=PROJECT/row["path"];raw=read(path)
        assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"])
        assert stat.S_IMODE(path.stat().st_mode)==int(row["mode"],8)&0o777
        if path.suffix==".py":ast.parse(raw,filename=str(path))
    compiler_raw=read(COMPILER)
    assert (len(compiler_raw),digest(compiler_raw))==(668608,COMPILER_SHA)
    sys.path[:0]=[str(ROOT_TOOLS),str(REF)]
    for relative,expected in (
        ("tools/qualify_hia_selfhost.py","2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"),
        ("tools/hia_selfhost_child.py","1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"),
        ("tools/generate_hia_selfhost.py","e4cff0c45d9138ff50b32ef2f6c0c768583ac88b634f2b932411e4ecb2b50ed0")):
        assert digest(read(REF/relative))==expected
    helper=WORK/"native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py"
    helper_raw=read(helper)
    assert (len(helper_raw),digest(helper_raw))==(23950,"555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c")
    overlay=PROJECT/"reference_helpers/tools";overlay.mkdir(parents=True,exist_ok=True)
    target=overlay/"hia_agent_edit_source_views.py";target.write_bytes(helper_raw);read(target)
    import tools
    tools.__path__=[str(overlay),*list(tools.__path__)]
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from tools.qualify_hia_selfhost import compile_stage
    authoring=load("cli_authoring",ROOT_TOOLS/"cli_authoring.py")
    generator=load("worker_program_generator",ROOT_TOOLS/"generate_hia_worker_program_service.py")
    assert "tools.cli_authoring" not in sys.modules or sys.modules["tools.cli_authoring"] is authoring
    sys.modules["tools.cli_authoring"]=authoring
    formatter=load("worker_shared_fixed_catalog",ROOT_TOOLS/"generate_fixed_diagnostic_catalog_r1.py")
    extension=load("worker_fixed_diagnostic_extension",ROOT_TOOLS/"extend_worker_program_diagnostics_r1.py")
    assert digest(read(ROOT_TOOLS/"generate_fixed_diagnostic_catalog_r1.py"))==extension.FORMATTER_SHA
    for filename in [row[1] for row in formatter.TABLES]+[formatter.OUTER[0]]:
        read(PROJECT/"diagnostic_reference"/filename)
    diagnostic_adaptation=extension.attach(generator,formatter,PROJECT/"diagnostic_reference")
    save(OUT/"diagnostic-adaptation.json",diagnostic_adaptation)
    catalog_doc,catalog_body,catalog_inventory,catalog_rom=formatter.generated_document(PROJECT/"diagnostic_reference")
    save(OUT/"diagnostic-catalog.json",catalog_inventory)
    (OUT/"diagnostic-catalog.rom").write_bytes(catalog_rom)
    assert len(catalog_inventory["entries"])==181 and catalog_inventory["groups"]==[1,2,3,4,5]
    syntax=load("worker_program_syntax",ROOT_TOOLS/"assembly_syntax_reference.py")
    renderer=load("worker_program_renderer",ROOT_TOOLS/"assembly_renderer_reference.py")
    obj=load("worker_program_object",ROOT_TOOLS/"assembly_object_prefix_reference.py")
    compose=load("worker_program_executor_composer",ROOT_TOOLS/"compose_worker_program_executor.py")
    packer=load("worker_program_native_packer",ROOT_TOOLS/"generate_hia_worker_program_packer.py")
    role_map_raw=read(PROJECT/"resources/original-role-map.json")
    assert gitsha(role_map_raw)=="35202c1c5961923b60f6100e07fa696e2c8f84a0"
    role_map=json.loads(role_map_raw)
    assert set(role_map["components"])=={str(i) for i in range(1,64)}
    roles={i:b"" for i in range(1,64)};bindings={}
    for role in sorted(LIVE_OLD):
        row=role_map["components"][str(role)]
        source=read(Path(row["source_path"]));image=read(Path(row["image_path"]))
        assert (len(source),digest(source))==(row["source_bytes"],row["source_sha256"])
        assert (len(image),digest(image))==(row["image_bytes"],row["image_sha256"])
        roles[role]=image;bindings[str(role)]=dict(row,origin="EXACT_SOURCE_BOUND_RETAINED_PROGRAM_PEER_NO_NEW_QUALIFICATION")
    # Every old lower/program HIA must be reproduced exactly before any
    # contextual continuation is generated or any replacement is compiled.
    load("tools.type_context_routes_common_r1",ROOT_TOOLS/"type_context_routes_common_r1.py")
    pipeline=load("worker_type_context_pipeline",ROOT_TOOLS/"type_context_pipeline_build_r1.py")
    context_documents,reader=pipeline.generate(PROJECT,REF,OUT/"context-authoring",role_map,read)
    worker_context=load("worker_type_context_route",ROOT_TOOLS/"extend_worker_type_context_r1.py")
    context_adaptation=worker_context.attach(generator,reader)
    save(OUT/"worker-context-adaptation.json",context_adaptation)
    for item in context_documents:
        role=item["role"]
        roles[role],row=compile_document(item["label"],item["body"],item["document"])
        bindings[str(role)]=dict(row,origin="FRESH_HISTORICAL_0E09_B3_NATIVE_TYPE_CONTEXT")
    exact_context={
        8:("6100d3bd689c4066bdd1816aa574c8f8ef6528a357e9652f3fa23378ce622c57",
           "e1341c2417eeacadd16ab40bb5f4645497f344f061ae32ce2add5f5826655f68"),
        50:("1942de3bebe8986f637aeda1ea787714130043a16719bda44dd8f1170b0fccc5",
            "4c879e702a4ef00fb4c9775ea90b7255649a71b0f8945bb8b29c71fa2f8e3393")}
    for role,identity in exact_context.items():
        assert (bindings[str(role)]["source_sha256"],bindings[str(role)]["image_sha256"])==identity
    save(OUT/"unchanged-actual-type-context-images.json",{str(k):v for k,v in exact_context.items()})
    for entry,label,role in (("worker_program_service","worker-program-root",56),("assembly_service","worker-assembly-control",59)):
        body,live=generator.expanded(entry);doc=generator.base.document(body);doc["module"]=label.replace("-","_")
        roles[role],row=compile_document(label,body,doc);row["reachable"]=live
        bindings[str(role)]=dict(row,origin="FRESH_HISTORICAL_0E09_B3")
    for module,label,role in ((syntax,"worker-assembly-syntax",61),(renderer,"worker-assembly-render",62)):
        body,constants,scope=module.source();expanded=authoring.expanded(body,constants)
        doc=authoring.document(expanded,label.replace("-","_"))
        roles[role],row=compile_document(label,expanded,doc);row["source_scope"]=scope
        bindings[str(role)]=dict(row,origin="FRESH_HISTORICAL_0E09_B3")
    body=obj.source_program();doc=obj.document()
    roles[63],row=compile_document("worker-object-prefix",body,doc)
    bindings["63"]=dict(row,origin="FRESH_HISTORICAL_0E09_B3")
    roles[51],row=compile_document("worker-fixed-diagnostic-catalog",catalog_body,catalog_doc)
    bindings["51"]=dict(row,origin="FRESH_HISTORICAL_0E09_B3_EXACT_SHARED_181_TEXT_CATALOG")
    exact_unchanged={
        59:("a16bba533d9bbd72c8a3da797e5c5677b1387d18d1673abebea0c65129efbea7","e79637b8485a723e91c4c69a4a267ea3d9eae6b5f61f5624ff6933ff57dfcc8f"),
        61:("f567ecf6ff7148f32328f42100656f55c29094dfcae6c4df72b1ff831016ecbc","2397fae88d366b3ab74c07dad9b9707e150e89ad5e8be336ef3afda78025b297"),
        62:("b81c8377660b73661774ce563c7c655ff850db366bccdb0f7500a7362432fc20","291ac2e77017d17623550870c04fa89ceac5475a705fa07c78e3aedf83e0486b"),
        63:("7362f885a9da0cc26a52e2930c02dc633ac7e50080e0ad0f622f62da53ffaf9c","f6300b41f981399e5db47a98eb2e30585c61e528df610bdde7d29d1709e29255")}
    for role,pair in exact_unchanged.items():
        assert (bindings[str(role)]["source_sha256"],bindings[str(role)]["image_sha256"])==pair,role
    save(OUT/"unchanged-assembly-peers.json",{str(k):v for k,v in exact_unchanged.items()})
    native=OUT/"carrier";native.mkdir()
    original=read(ROOT_TOOLS/"worker_program_executor_reference.S")
    assembly,mask_proof=worker_context.compose_executor(extension,compose,original)
    save(native/"diagnostic-mask-proof.json",mask_proof)
    assembly_path=native/"worker_program_executor.S";assembly_path.write_bytes(assembly);read(assembly_path)
    prefix,tables,actual=packer.template(assembly_path,native)
    assert actual==assembly and len(tables)==1
    (native/"prefix.bin").write_bytes(prefix)
    save(native/"layout.json",dict(prefix_bytes=len(prefix),prefix_sha256=digest(prefix),
        tables=tables,rows=63,nonzero_roles=sorted(LIVE),empty_roles=sorted(set(roles)-LIVE),
        all_descendant_instruction_text_except_exact_type_transfer_unchanged=True,
        source_kind_depth_and_pending_guards_unchanged=True))
    body=packer.source(prefix,tables)
    doc=authoring.document(body,"worker_program_packer")
    packed_image,packed_row=compile_document("worker-program-ELF-packer",body,doc)
    parts=[roles[i] for i in range(1,64)]
    assert {i for i in roles if roles[i]}==LIVE
    packet=struct.pack("<8Q",int.from_bytes(b"HIAPPK01","little"),1,1,63,
                       568+sum(map(len,parts)),568,64,0)
    packet+=struct.pack("<63Q",*map(len,parts))+b"".join(parts)
    expected=bytearray(prefix)
    for role,raw in enumerate(parts,1):
        if raw:
            expected+=bytes((-len(expected))&15)
            struct.pack_into("<Q",expected,tables[0]+role*8,4194304+len(expected))
            expected+=raw
        else:
            assert struct.unpack_from("<Q",expected,tables[0]+role*8)[0]==0
    struct.pack_into("<Q",expected,96,len(expected));struct.pack_into("<Q",expected,104,len(expected))
    libc=ctypes.CDLL(None,use_errno=True)
    libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    libc.mmap.restype=ctypes.c_void_p
    libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int]
    libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
    native_packer=NativeHiaJsonImage(packed_image,expected_sha256=digest(packed_image))
    src=dst=scratch=None
    try:
        src=Guard(packet,readonly=True);dst=Guard(b"",len(expected),0x91);scratch=Guard(b"",64,0x37)
        before=dict(source=cas(packet),output=cas(dst.value()),workspace=cas(scratch.value()),
                    input_actual_readonly=True)
        save(OUT/"packer-pending.json",before)
        returned=int(native_packer._entry(src.ptr,src.size,dst.ptr,dst.size,scratch.ptr,scratch.size))
        packer_entries+=1
        for value in (src,dst,scratch):value.check()
        output=dst.value()
        save(OUT/"packer-result.json",dict(before=before,returned=returned,output=cas(output),
            workspace=cas(scratch.value()),source_after=cas(src.value()),expected=cas(expected),
            all_canaries_unchanged=True))
        assert returned==len(expected) and output==bytes(expected)
        assert src.value()==packet and scratch.value()==bytes([0x37])*64
    finally:
        for value in (src,dst,scratch):
            if value is not None:value.close()
        native_packer._mapping.close()
    elf=OUT/"hia-worker-program-development";elf.write_bytes(output);elf.chmod(0o700);read(elf)
    for module in tuple(sys.modules.values()):
        name=getattr(module,"__file__",None)
        if name:
            path=Path(name).resolve()
            if path.suffix==".py" and any(path.is_relative_to(root) for root in (REF,WORK,PROJECT)):read(path)
    for path,raw in {**generator.base.RAW,**generator.INPUTS}.items():
        assert read(path)==raw
    manifest=dict(schema="hia-worker-program-assembly-native-fixed-v1",status="BUILT_ONLY",
        executable_path=str(elf),executable_bytes=len(output),executable_sha256=digest(output),
        compiled=compiled,role_bindings=bindings,table_rows=63,nonzero_images=43,
        unused_rows=sorted(set(range(1,64))-LIVE),compiler_sha256=COMPILER_SHA,
        fresh_compiles=13,actual_native_packer_entries=packer_entries,
        complete_composite_11_owners_present=True,complete_public_assembly_profile=True,
        runtime_has_no_hosted_program_json_assembly_owner=True,
        output_frame="HIAWPE01",input_frame="HIAWPI01",
        inherited_composite_refusal_text_missing_groups=[6,9],
        native_adapter_fixed_enum_routing_only=False,
        native_type_context_capture_roles=[8,40,41,43,46,50,56],
        native_context_is_actual_workspace_before_cleanup=True,
        native_context_types_and_reader_exact_follow46_images=True,
        exact_retained_driver_reproduction=str(OUT/"context-authoring/exact-retained-driver-reproduction.json"),
        native_type_context_reader_inventory=str(OUT/"context-authoring/reader-inventory.json"),
        native_type_context_adaptation=str(OUT/"worker-context-adaptation.json"),
        known_public_type_context_text_open=True,whole_public_diagnostics_closed=False,
        fixed_diagnostic_groups=[1,2,3,4,5],fixed_diagnostic_entries=181,
        diagnostic_adaptation=str(OUT/"diagnostic-adaptation.json"),
        diagnostic_catalog=str(OUT/"diagnostic-catalog.json"),
        diagnostic_mask_proof=str(native/"diagnostic-mask-proof.json"),
        retained_four_assembly_peer_source_and_image_bytes_equal=True,
        worker_initializer_program_registry_joined=False,whole_worker_closed=False,
        namespace_issued=False,installed_activated=False,cold_qualified=False)
    save(OUT/"bundle.json",manifest)
    assert len(compiled)==13 and unchanged();status="PASS"
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    same=unchanged()
    if not same:status="FAIL"
    frozen=[]
    for index,(path,(raw,mode)) in enumerate(PINS.items()):
        target=OUT/"frozen-inputs"/str(index)/path.name
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(mode)
        frozen.append(dict(path=str(path),bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),
                           mode=mode,frozen=str(target)))
    save(OUT/"source-pins.json",frozen)
    report=dict(status=status,scope="NEW_WORKER_P16_ACTUAL_TYPE_CONTEXT_BUILD_NOT_RUNTIME_QUALIFICATION",
        actual_compiles=len(compiled),actual_compile_attempts=len(compile_attempts),actual_packer_entries=packer_entries,
        actual_semantic_processes=0,compiled=compiled,failure=failure,
        source_and_image_before_after_equal=same,elapsed_ns=time.monotonic_ns()-started,
        compiler_sha256=COMPILER_SHA,original_compile_limits=dict(cpu=10,wall=20,address=268435456),
        runtime_groups=dict(cpu=90,wall=180,address=1073741824),whole_worker_closed=False)
    save(OUT/"summary.json",report)
    print("HIA_WORKER_PROGRAM_BUILD "+json.dumps(report,sort_keys=True),flush=True)
if status!="PASS":raise SystemExit(1)
