"""Six fresh bounded B3 images for actual patch, candidate recheck and impact."""
from __future__ import annotations
import ast,ctypes,importlib.util,json,os,re,resource,stat,struct,sys,time,traceback,zlib
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
WORK=BASE/"root-recovery/workspace";REF=BASE/"root-recovery/reference-0ef-r2"
ROOT=WORK/"native-ordinary-impact-coordinator-r2";OUT=ROOT/"development/build-r1"
SOURCES=Path(sys.argv[1]).resolve();ROLES=Path(sys.argv[2]).resolve();ROLE_MAP=Path(sys.argv[3]).resolve()
COMPILER=WORK/"native-edit-candidate-next/development/build-r1/source/1/B3.image.bin"
ROOT.mkdir(parents=True,exist_ok=False);OUT.mkdir(parents=True)
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
PINS={};compiled=[];packer_entries=0;status="FAIL";failure=None;started=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def read(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in PINS:assert PINS[path]==(raw,mode),path
    PINS[path]=(raw,mode);return raw
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def cas(raw):
    raw=bytes(raw);h=digest(raw);path=OUT/"cas"/(h+".zlib");path.parent.mkdir(exist_ok=True)
    if not path.exists():path.write_bytes(zlib.compress(raw,1))
    assert zlib.decompress(path.read_bytes())==raw
    return dict(bytes=len(raw),sha256=h,path="cas/"+path.name,compression="zlib")
def unchanged():
    return all(p.is_file() and p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==mode for p,(raw,mode) in PINS.items())
def load(name,path):
    raw=read(path);ast.parse(raw,filename=str(path))
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
def protected(raw,size=None,fill=0):
    size=len(raw) if size is None else size
    assert len(raw)<=size
    guard=bytes(range(32));backing=ctypes.create_string_buffer(64+max(1,size));at=ctypes.addressof(backing)+32
    ctypes.memmove(at-32,guard,32);ctypes.memset(at,fill,max(1,size));ctypes.memmove(at,raw,len(raw));ctypes.memmove(at+max(1,size),guard,32)
    return backing,at,size,guard
def checked(row):
    _,at,size,guard=row
    assert ctypes.string_at(at-32,32)==guard and ctypes.string_at(at+max(1,size),32)==guard
def compile_document(label,module=None,body=None,expected_source=None,expected_image=None):
    if module is not None:
        expanded=module.source_program();doc=module.document()
    else:
        expanded=body;doc=authoring.document(body,label.replace("-","_"))
    where=OUT/"compiled"/label;where.mkdir(parents=True)
    (where/"expanded-authoring.py").write_text(expanded);save(where/"document.json",doc)
    fs=doc["functions"];ssa=[]
    for fn in fs:
        names=[x["name"] for x in fn["params"]]
        for block in fn["blocks"]:
            names.extend(x["name"] for x in block["params"])
            for op in block["ops"]:names.extend(x["name"] for x in op.get("out",[]))
        ssa.extend(int(re.search(r"(\d+)$",n).group(1)) for n in names if re.search(r"(\d+)$",n))
    profile=dict(functions=len(fs),blocks=sum(len(f["blocks"]) for f in fs),
        operations=sum(len(b["ops"]) for f in fs for b in f["blocks"]),
        max_function_blocks=max(len(f["blocks"]) for f in fs),
        max_block_parameters=max(len(b["params"]) for f in fs for b in f["blocks"]),
        max_ssa_numeric_suffix=max(ssa,default=0))
    save(where/"profile.json",profile)
    assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["operations"]<=8192
    assert profile["max_function_blocks"]<=256 and profile["max_block_parameters"]<=16
    assert profile["max_ssa_numeric_suffix"]<2048
    raw=render_assembly(doc).encode();assemble_program(raw)
    assert 0<len(raw)<=1048576
    if expected_source is not None:assert digest(raw)==expected_source
    source=where/"source.hiaasm";source.write_bytes(raw);read(source)
    assert read(COMPILER)==compiler_raw
    image,receipt=compile_stage(where,label,COMPILER,raw);binary=read(image)
    assert receipt["status"]=="returned" and receipt["abi_status"]==0
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==268435456
    assert receipt["input_sha256"]==digest(raw) and receipt["produced_sha256"]==digest(binary)
    assert receipt["artifact_sha256"]==digest(compiler_raw) and len(binary)==receipt["core_u32"]
    assert 0<len(binary)<=1048576
    if expected_image is not None:assert digest(binary)==expected_image
    row=dict(label=label,source_path=str(source),source_bytes=len(raw),source_sha256=digest(raw),
        image_path=str(image),image_bytes=len(binary),image_sha256=digest(binary),
        profile=profile,receipt=receipt)
    compiled.append(row);save(where/"manifest.json",row)
    print("HIA_ORDINARY_IMPACT_COMPILE "+json.dumps(row,sort_keys=True),flush=True)
    return binary,row
try:
    read(__file__)
    for path in sorted(SOURCES.rglob("*")):
        if path.is_file():read(path)
    compiler_raw=read(COMPILER)
    assert (len(compiler_raw),digest(compiler_raw))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
    for path,expected in (
        ("tools/qualify_hia_selfhost.py","2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"),
        ("tools/hia_selfhost_child.py","1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"),
        ("tools/generate_hia_selfhost.py","e4cff0c45d9138ff50b32ef2f6c0c768583ac88b634f2b932411e4ecb2b50ed0")):
        assert digest(read(REF/path))==expected

    for name,row in {
    "tools/generate_hia_core_json_frontend.py": {
        "bytes": 14935,
        "gitsha": "7359bf71993753fbef35d9b43fbdd054132659b0",
        "sha256": "167f1731d717b1f184995e210a2156095d18813a5988efb2ac04fe60275e0cf7"
    },
    "tools/generate_hia_sha256.py": {
        "bytes": 5474,
        "gitsha": "b59c2259f038eab830c16bf498b14a5d15556ee4",
        "sha256": "4114a26ff0ea47229bccbedadcb40efdd9715a8dd0739d2fcb55c98f8ddbdf97"
    },
    "hepta/hia_patch_impact.py": {
        "bytes": 8527,
        "gitsha": "0d270c59bcf6f844dd8fe4e48f67ce8722362474",
        "sha256": "b61710dc320c4b65206a2e6efed67ac525e900a782886be6c289e8acc681e3a1"
    },
    "tools/generate_hia_core_patch.py": {
        "bytes": 25925,
        "gitsha": "136eb04f3da61ecf3cdfccafa1095bdbc5c1dd6f",
        "sha256": "091d6d4b7d7c7c9088a79dc0104672ec679f3088f0f21131542543cc26e0a39f"
    },
    "hepta/hia_program_tools.py": {
        "bytes": 22198,
        "gitsha": "c2be38ffe2871ca199783103d4dfa9867771df10",
        "sha256": "a1b42262d8a00fbce9057e40dd081210ad274ecad8fc0c126ffafe8c3568436a"
    },
    "tools/generate_hia_json_preflight.py": {
        "bytes": 13718,
        "gitsha": "2198579e4e1882c44593f1c7b9253ec788a90f78",
        "sha256": "293e22e217cba119dad1c7a4e04b5a9cd714cbeafdfdc4c9b15f4f716557896c"
    },
    "tools/generate_hia_json_decode.py": {
        "bytes": 8178,
        "gitsha": "54607f809bdbd8cd68c4e423749c40623fe54a69",
        "sha256": "fffc97c704cc75ad88239fe79d7b7f83418199a732364f834e006ebfd5f8548f"
    },
    "tools/generate_hia_json_canonical.py": {
        "bytes": 7307,
        "gitsha": "d9da0321b5aab3cfebb8549b237bce336600a422",
        "sha256": "063053bf7539a605ee834bd32e6a07b98ebd0c6b027af0b224b7f9107b9d47d9"
    },
    "hepta/hia_program.py": {
        "bytes": 45247,
        "gitsha": "5d0027f4453759e4156a3496e64215c441a727e4",
        "sha256": "76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
    }
}.items():
        raw=read(REF/name)
        assert (len(raw),gitsha(raw),digest(raw))==(row['bytes'],row['gitsha'],row['sha256'])
    sys.path[:0]=[str(SOURCES),str(REF)]
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from tools.qualify_hia_selfhost import compile_stage
    authoring=load("cli_authoring",SOURCES/"cli_authoring.py")
    root_author=load("ordinary_patch_root_author",SOURCES/"generate_ordinary_impact_coordinator_r1.py")
    prep_author=load("ordinary_patch_prepare_author",SOURCES/"generate_ordinary_patch_prepare_r1.py")
    receipt_author=load("ordinary_patch_receipt_author",SOURCES/"generate_ordinary_patch_receipt_r1.py")
    prefix_author=load("ordinary_patch_object_prefix_author",SOURCES/"issued_object_prefix_reference.py")
    impact_author=load("ordinary_static_impact_author",SOURCES/"generate_static_impact_r1.py")
    packer=load("ordinary_patch_packer",SOURCES/"generate_ordinary_patch_packer_r1.py")
    manifest_raw=read(ROLE_MAP);assert gitsha(manifest_raw)=="35202c1c5961923b60f6100e07fa696e2c8f84a0"
    original=json.loads(manifest_raw)
    assert set(original["components"])=={str(i) for i in range(1,64)}
    roles={};bindings={}
    for role in range(1,64):
        expected=original["components"][str(role)]
        source=read(ROLES/str(role)/"source.hiaasm");image=read(ROLES/str(role)/"image.bin")
        assert (len(source),digest(source))==(expected["source_bytes"],expected["source_sha256"])
        assert (len(image),digest(image))==(expected["image_bytes"],expected["image_sha256"])
        roles[role]=image
        bindings[str(role)]=dict(source_path=str(ROLES/str(role)/"source.hiaasm"),source_bytes=len(source),source_sha256=digest(source),
            image_path=str(ROLES/str(role)/"image.bin"),image_bytes=len(image),image_sha256=digest(image),origin="EXACT_BOUND_ORIGINAL_DEPENDENCY")
    for role,label,module in ((56,"ordinary-patch-coordinator",root_author),(57,"ordinary-patch-prepare",prep_author),
        (59,"ordinary-patch-receipt",receipt_author),(60,"ordinary-static-impact",impact_author),
        (63,"ordinary-patch-object-prefix",prefix_author)):
        kwargs={}
        if role==59:kwargs=dict(expected_source="e0809903daba34e3fb5392627850077c45b2d2e0e7061ee1230e6886ace78334",
            expected_image="a436aa64a590d1335097ceb1d7778ce7b8405eb2ed1a507ef983b5fe69cb7cd2")
        roles[role],row=compile_document(label,module=module,**kwargs)
        bindings[str(role)]=dict(row,origin="FRESH_ORIGINAL_LIMIT_B3")
    native=OUT/"carrier";native.mkdir()
    assembly=SOURCES/"ordinary_patch_executor.S"
    prefix,tables,actual=packer.template(assembly,native)
    assert actual==read(assembly) and len(tables)==1
    (native/"prefix.bin").write_bytes(prefix)
    save(native/"layout.json",dict(prefix_bytes=len(prefix),prefix_sha256=digest(prefix),tables=tables,
        slots=63,header_bytes=568,assembly_sha256=digest(actual)))
    packed_image,packed_row=compile_document("ordinary-patch-ELF-packer",body=packer.source(prefix,tables))
    parts=[roles[i] for i in range(1,64)]
    packet=struct.pack("<8Q",int.from_bytes(b"HIAPPK01","little"),1,1,63,568+sum(map(len,parts)),568,64,0)
    packet+=struct.pack("<63Q",*map(len,parts))+b"".join(parts)
    expected=bytearray(prefix)
    for role,raw in enumerate(parts,1):
        expected+=bytes((-len(expected))&15)
        struct.pack_into("<Q",expected,tables[0]+role*8,4194304+len(expected));expected+=raw
    struct.pack_into("<Q",expected,96,len(expected));struct.pack_into("<Q",expected,104,len(expected))
    native_packer=NativeHiaJsonImage(packed_image,expected_sha256=digest(packed_image))
    src=protected(packet);dst=protected(b"",len(expected),0x91);work=protected(b"",64,0x37)
    before=dict(source=cas(packet),output=cas(bytes([0x91])*len(expected)),workspace=cas(bytes([0x37])*64))
    save(OUT/"packer-pending.json",before)
    returned=int(native_packer._entry(src[1],src[2],dst[1],dst[2],work[1],work[2]));packer_entries+=1
    for row in (src,dst,work):checked(row)
    output=ctypes.string_at(dst[1],dst[2]);scratch=ctypes.string_at(work[1],64);source_after=ctypes.string_at(src[1],src[2])
    save(OUT/"packer-result.json",dict(before=before,returned=returned,output=cas(output),workspace=cas(scratch),
        source_after=cas(source_after),expected=cas(expected),all_canaries_unchanged=True))
    assert returned==len(expected) and output==bytes(expected) and source_after==packet and scratch==bytes([0x37])*64
    native_packer._mapping.close()
    elf=OUT/"hia-ordinary-impact-development";elf.write_bytes(output);elf.chmod(0o700);read(elf)
    for module in tuple(sys.modules.values()):
        name=getattr(module,"__file__",None)
        if name:
            path=Path(name).resolve()
            if path.suffix==".py" and any(path.is_relative_to(root) for root in (WORK,REF,SOURCES)):read(path)
    manifest=dict(schema="hia-ordinary-raw-impact-fixed-join-v1",status="BUILT_ONLY_NOT_SEMANTIC_QUALIFICATION",
        executable_path=str(elf),executable_bytes=len(output),executable_sha256=digest(output),
        compiled=compiled,role_bindings=bindings,original_role_map_sha256=digest(manifest_raw),
        compiler_sha256=digest(compiler_raw),new_compiles=6,actual_native_packer_entries=packer_entries,
        fixed_runtime_has_no_hosted_business_owner=True,stdin_magic="HIAEJN01",input_mode=1,
        input_views=["original program bytes","original patch bytes","zero unused third view"],
        output_views=["rechecked canonical candidate","actual issued patch receipt","actual complete impact report"],
        extra_candidate_recheck_and_complete_equality_required=True,impact_role=60,
        full_impact_qualified=False,whole_stack_closed=False,installed_activation=False)
    save(OUT/"manifest.json",manifest);assert len(compiled)==6 and unchanged();status="PASS"
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc());traceback.print_exc()
    for path in sorted(OUT.rglob("*.stderr.log")):
        print("HIA_ORDINARY_IMPACT_BUILD_NESTED_STDERR "+json.dumps(dict(path=str(path),text=path.read_text()),sort_keys=True),flush=True)
finally:
    same=unchanged()
    if not same:status="FAIL"
    frozen=[]
    for index,(path,(raw,mode)) in enumerate(PINS.items()):
        dest=OUT/"frozen-inputs"/str(index)/path.name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw);dest.chmod(mode)
        frozen.append(dict(path=str(path),bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=mode))
    save(OUT/"source-pins.json",frozen)
    report=dict(status=status,scope="SIX_FRESH_NATIVE_IMAGES_AND_ACTUAL_HIA_FIXED_ELF_PACKAGING",
        actual_native_compiles=len(compiled),actual_packer_entries=packer_entries,actual_runtime_processes=0,
        compiled=compiled,failure=failure,source_and_image_before_after_equal=same,elapsed_ns=time.monotonic_ns()-started,
        original_B3_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=268435456),
        whole_stack_closed=False,full_impact_qualified=False,installed_activation=False)
    save(OUT/"summary.json",report)
    print("HIA_ORDINARY_IMPACT_BUILD "+json.dumps(report,sort_keys=True),flush=True)
if status!="PASS":raise SystemExit(1)
