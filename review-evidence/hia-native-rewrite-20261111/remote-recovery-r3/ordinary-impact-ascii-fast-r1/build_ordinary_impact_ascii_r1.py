"""Seven exact ASCII reader additions, original 63 roles and unchanged ELF carrier.

This development builder does not execute public semantic cases. The unchanged
six-image baseline build must first reproduce every original source/image and
the actual original ELF recovered by the timing47 readback.
"""
from __future__ import annotations
import ctypes,json,re,resource,stat,struct,sys,time,traceback,zlib
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
WORK=BASE/"root-recovery/workspace";REF=BASE/"root-recovery/reference-0ef-r2"
OLD=WORK/"native-ordinary-impact-coordinator-r2/development/build-r1"
ROOT=WORK/"native-ordinary-impact-ascii-fast-r1";OUT=ROOT/"development/build-r1"
SOURCES=Path(sys.argv[1]).resolve();SUBMITTED=Path(sys.argv[2]).resolve()
COMPILER=WORK/"native-edit-candidate-next/development/build-r1/source/1/B3.image.bin"
CHANGED=(24,26,27,57,59,60,63)
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
started=time.monotonic_ns();first_parent=resource.getrusage(resource.RUSAGE_SELF);first_children=resource.getrusage(resource.RUSAGE_CHILDREN)
ROOT.mkdir(parents=True,exist_ok=False);OUT.mkdir(parents=True)
PINS={};compiled=[];source_checks=[];packer_entries=0;status="FAIL";failure=None
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),gitsha=gitsha(raw),sha256=digest(raw))
def check_pin(raw,row):
    value=pin(raw)
    assert all(value[key]==row[key] for key in ("bytes","gitsha","sha256")),(value,row)
def read(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in PINS:assert PINS[path]==(raw,mode),path
    PINS[path]=(raw,mode);return raw
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def unchanged():
    return all(p.is_file() and p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==mode for p,(raw,mode) in PINS.items())
def cpu_used():
    p=resource.getrusage(resource.RUSAGE_SELF);c=resource.getrusage(resource.RUSAGE_CHILDREN)
    return p.ru_utime+p.ru_stime-first_parent.ru_utime-first_parent.ru_stime+c.ru_utime+c.ru_stime-first_children.ru_utime-first_children.ru_stime
def budget():
    assert cpu_used()<=90,("aggregate parent and reaped child CPU",cpu_used())
    assert time.monotonic_ns()-started<180000000000,"whole builder wall"
def cas(raw):
    raw=bytes(raw);h=digest(raw);path=OUT/"cas"/(h+".zlib");path.parent.mkdir(exist_ok=True)
    if not path.exists():path.write_bytes(zlib.compress(raw,1))
    assert zlib.decompress(path.read_bytes())==raw
    return dict(bytes=len(raw),sha256=h,path="cas/"+path.name,compression="zlib")
def protected(raw,size=None,fill=0):
    size=len(raw) if size is None else size
    assert len(raw)<=size
    guard=bytes(range(32));backing=ctypes.create_string_buffer(64+max(1,size));at=ctypes.addressof(backing)+32
    ctypes.memmove(at-32,guard,32);ctypes.memset(at,fill,max(1,size));ctypes.memmove(at,raw,len(raw));ctypes.memmove(at+max(1,size),guard,32)
    return backing,at,size,guard
def checked(row):
    _,at,size,guard=row
    assert ctypes.string_at(at-32,32)==guard and ctypes.string_at(at+max(1,size),32)==guard
def split_functions(raw):
    parts=re.split(rb"(?m)(?=^fn )",raw);result={}
    assert parts[0].startswith(b"hia-asm.v1 ") and len(parts)>1
    for part in parts[1:]:
        found=re.match(rb"fn ([A-Za-z_][A-Za-z_0-9]*)\(",part)
        assert found is not None and part.endswith(b"end\n")
        name=found[1].decode("ascii");assert name not in result
        result[name]=part
    return parts[0],result
def check_inline_changes(old,new,row):
    check_pin(old,row["original"]);check_pin(new,row["candidate"])
    old_header,old_fns=split_functions(old);new_header,new_fns=split_functions(new)
    assert old_header==new_header and list(old_fns)==list(new_fns)
    decode=row["proof"]["mapping"]["decode_string"]
    allowed={decode}|{a["function"] for a in row["alpha"]}
    assert {name for name in old_fns if old_fns[name]!=new_fns[name]}==allowed
    check_pin(old_fns[decode],row["decode_function_before"])
    check_pin(new_fns[decode],row["decode_function_after"])
    restored=dict(new_fns);restored[decode]=old_fns[decode]
    for a in row["alpha"]:
        name=a["function"];before=old_fns[name];after=new_fns[name]
        check_pin(before,a["before"]);check_pin(after,a["after"])
        pairs=a["bijection"];forward={x["before"].encode():x["after"].encode() for x in pairs}
        inverse={v:k for k,v in forward.items()}
        assert len(forward)==len(inverse)==len(pairs)==a["unique_values"]
        for body in (before,after):
            for literal in re.findall(rb'"(?:\\.|[^"\\])*"',body):
                assert re.search(rb"\bv\d+\b",literal) is None
        assert set(re.findall(rb"\bv\d+\b",before))==set(forward)
        assert set(re.findall(rb"\bv\d+\b",after))==set(inverse)
        assert re.sub(rb"\bv\d+\b",lambda m:forward[m[0]],before)==after
        restored[name]=re.sub(rb"\bv\d+\b",lambda m:inverse[m[0]],after)
        assert restored[name]==before
    assert new_header+b"".join(restored.values())==old
    source_checks.append(dict(role=row["role"],original=pin(old),candidate=pin(new),
        changed_functions=sorted(allowed),all_other_function_bytes_identical=True,
        exact_complete_inverse=True,alpha_variables=sum(a["unique_values"] for a in row["alpha"])))
def check_changes(old,new,row):
    check_pin(new,row["candidate"])
    prior=inline_proof_rows[row["role"]]
    assert row["original"]==prior["original"]
    assert row["input_inline"]==prior["candidate"]
    old_header,old_fns=split_functions(old);new_header,new_fns=split_functions(new)
    helper=row["helper"];name=helper["name"];decode=row["caller"]
    assert name=="f%d"%(max(int(n[1:]) for n in old_fns)+1)
    assert list(new_fns)==list(old_fns)+[name] and new_header==old_header
    assert decode==prior["proof"]["mapping"]["decode_string"]
    assert row["original_unicode_reader"]==prior["proof"]["mapping"]["decoded"]
    check_pin(new_fns[name],helper)
    assert new_fns[name]==helper["source"].encode("ascii")
    check_pin(new_fns[row["original_unicode_reader"]],row["unicode_reader"])
    changed=new_fns[decode]
    check_pin(changed,row["caller_after"])
    before=row["old_call"].encode("ascii");after=row["new_call"].encode("ascii")
    assert changed.count(after)==1 and before not in changed
    original_target=('{"function":"'+row["original_unicode_reader"]+'"}').encode("ascii")
    new_target=('{"function":"'+name+'"}').encode("ascii")
    assert before.count(original_target)==1 and after==before.replace(original_target,new_target)
    restored_caller=changed.replace(after,before)
    check_pin(restored_caller,row["caller_before"])
    reconstructed=new_header+b"".join(restored_caller if n==decode else new_fns[n] for n in old_fns)
    check_pin(reconstructed,row["input_inline"])
    check_inline_changes(old,reconstructed,prior)
    source_checks[-1].update(candidate=pin(new),input_inline=pin(reconstructed),
        exact_ASCII_call_and_appended_function_inverse=True,ASCII_helper=name,
        ASCII_helper_pin=pin(new_fns[name]),every_other_inline_function_byte_identical=True,
        original_unicode_reader_pin=pin(new_fns[row["original_unicode_reader"]]),
        no_bulk_access_or_cross_scalar_cursor_cache=True)
def core_profile(document):
    fs=document["functions"];ssa=[]
    for fn in fs:
        names=[p["name"] for p in fn["params"]]
        for block in fn["blocks"]:
            names.extend(p["name"] for p in block["params"])
            for op in block["ops"]:names.extend(p["name"] for p in op.get("out",[]))
        ssa.extend(int(m[1]) for n in names if (m:=re.search(r"(\d+)$",n)))
    return dict(functions=len(fs),blocks=sum(len(f["blocks"]) for f in fs),
        operations=sum(len(b["ops"]) for f in fs for b in f["blocks"]),
        max_function_blocks=max(len(f["blocks"]) for f in fs),
        max_block_parameters=max(len(b["params"]) for f in fs for b in f["blocks"]),
        max_ssa_numeric_suffix=max(ssa,default=0))
def compile_candidate(role,row):
    budget()
    original_source=read(old_bindings[str(role)]["source_path"])
    raw=read(SUBMITTED/"sources"/("role-%d.hiaasm"%role))
    check_changes(original_source,raw,row)
    assert 0<len(raw)<=1048576
    where=OUT/"compiled"/("inline-role-%d"%role);where.mkdir(parents=True)
    source=where/"source.hiaasm";source.write_bytes(raw);read(source)
    verified=assemble_program(raw);doc=verified.as_dict()
    canonical=render_assembly(doc).encode("utf-8")
    (where/"roundtrip.hiaasm").write_bytes(canonical)
    assert canonical==raw,("exact canonical HIA roundtrip",role)
    profile=core_profile(doc);save(where/"profile.json",profile)
    declared=row["proof"]["textual_profile"]
    assert all(profile[k]==declared[k] for k in profile),(profile,declared)
    assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["operations"]<=8192
    assert profile["max_function_blocks"]<=256 and profile["max_block_parameters"]<=16
    assert profile["max_ssa_numeric_suffix"]<2048
    save(where/"document.json",doc)
    assert read(COMPILER)==compiler_raw
    image,receipt=compile_stage(where,"inline-role-%d"%role,COMPILER,raw)
    binary=read(image)
    assert receipt["status"]=="returned" and receipt["abi_status"]==0
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==268435456
    assert receipt["limits"]["output_capacity"]==receipt["limits"]["workspace_bytes"]==1048576
    assert receipt["wall_elapsed_ns"]<=20000000000
    assert receipt["input_sha256"]==digest(raw) and receipt["produced_sha256"]==digest(binary)
    assert receipt["artifact_sha256"]==digest(compiler_raw) and len(binary)==receipt["core_u32"]
    assert 0<len(binary)<=1048576
    result=dict(role=role,label="inline-role-%d"%role,source_path=str(source),source_bytes=len(raw),
        source_sha256=digest(raw),source_gitsha=gitsha(raw),image_path=str(image),
        image_bytes=len(binary),image_sha256=digest(binary),profile=profile,receipt=receipt,
        origin="FRESH_ORIGINAL_LIMIT_B3_ASCII_FAST_JSON_READER")
    compiled.append(result);save(where/"manifest.json",result)
    print("HIA_ORDINARY_ASCII_COMPILE "+json.dumps(result,sort_keys=True),flush=True)
    budget()
    return binary,result
try:
    read(__file__)
    for directory in (SOURCES,SUBMITTED):
        for path in sorted(directory.rglob("*")):
            if path.is_file():read(path)
    for path in sorted((REF/"hepta").glob("*.py")):read(path)
    for rel,expected in (
        ("tools/qualify_hia_selfhost.py","2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"),
        ("tools/hia_selfhost_child.py","1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"),
        ("tools/generate_hia_selfhost.py","e4cff0c45d9138ff50b32ef2f6c0c768583ac88b634f2b932411e4ecb2b50ed0"),
        ("hepta/hia_agent_assembly.py","e37095496bf159ad573a31214d4d73e916648b4f0664edb541014f54681fbc03")):
        assert digest(read(REF/rel))==expected
    compiler_raw=read(COMPILER)
    assert (len(compiler_raw),digest(compiler_raw))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
    sys.path.insert(0,str(REF))
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from tools.qualify_hia_selfhost import compile_stage
    old_summary=json.loads(read(OLD/"summary.json"))
    assert old_summary["status"]=="PASS" and old_summary["actual_native_compiles"]==6
    assert old_summary["actual_packer_entries"]==1 and old_summary["source_and_image_before_after_equal"]
    old_manifest=json.loads(read(OLD/"manifest.json"))
    assert old_manifest["new_compiles"]==6 and len(old_manifest["compiled"])==6
    assert old_manifest["status"]=="BUILT_ONLY_NOT_SEMANTIC_QUALIFICATION"
    old_bindings=old_manifest["role_bindings"]
    assert set(old_bindings)=={str(i) for i in range(1,64)}
    observed_raw=read(SUBMITTED/"resources/actual47-build-manifest.original.json")
    check_pin(observed_raw,dict(bytes=21225,gitsha="39d4f27505f651fba51171816d05eac3ad80f3e8",
        sha256="db45591a5df693a841eb032b7cc58d786d572391a6f0330f44f1d632c8796d73"))
    observed=json.loads(observed_raw)
    assert len(observed["role_bindings"])==63
    observed_bindings={str(r["role"]):r for r in observed["role_bindings"]}
    assert set(observed_bindings)==set(old_bindings)
    roles={};bindings={}
    for role in range(1,64):
        row=old_bindings[str(role)];old_observed=observed_bindings[str(role)]
        for kind in ("source","image"):
            raw=read(row[kind+"_path"])
            assert (len(raw),digest(raw))==(row[kind+"_bytes"],row[kind+"_sha256"])
            assert (len(raw),digest(raw))==(old_observed[kind+"_bytes"],old_observed[kind+"_sha256"])
            if kind=="image":roles[role]=raw
        bindings[str(role)]=dict(row)
    old_elf=read(old_manifest["executable_path"])
    assert (len(old_elf),digest(old_elf))==(observed["original_elf"]["bytes"],observed["original_elf"]["sha256"])
    inline_proof_raw=read(SUBMITTED/"evidence/inline-source-transform-proof.original.json")
    check_pin(inline_proof_raw,dict(bytes=202873,gitsha="3cfa3d613205fb07db028fceee8d8ee1da3e2595",
        sha256="64faa076ecb678d671aae86ca67de191d8cf15dfc32309d213d3be85512b5d5f"))
    inline_proof=json.loads(inline_proof_raw)
    assert [r["role"] for r in inline_proof["roles"]]==list(CHANGED)
    inline_proof_rows={r["role"]:r for r in inline_proof["roles"]}
    proof_raw=read(SUBMITTED/"evidence/source-transform-proof.json")
    check_pin(proof_raw,dict(bytes=94747,gitsha="92781bd45591f622d544e54faa9842adf8438826",
        sha256="e0487d5b78def8ba34fa5ef8eef2c5f4233a4ad09655c802880e045dd53abc06"))
    proof=json.loads(proof_raw)
    assert proof["prior_inline_proof"]==dict(bytes=202873,gitsha="3cfa3d613205fb07db028fceee8d8ee1da3e2595",sha256="64faa076ecb678d671aae86ca67de191d8cf15dfc32309d213d3be85512b5d5f")
    assert [r["role"] for r in proof["roles"]]==list(CHANGED)
    for row in proof["roles"]:
        role=row["role"];roles[role],bindings[str(role)]=compile_candidate(role,row)
    for role in set(range(1,64))-set(CHANGED):
        assert bindings[str(role)]==old_bindings[str(role)]
        assert roles[role]==read(old_bindings[str(role)]["image_path"])
    prefix=read(OLD/"carrier/prefix.bin");layout=json.loads(read(OLD/"carrier/layout.json"))
    assert (len(prefix),digest(prefix))==(layout["prefix_bytes"],layout["prefix_sha256"])
    assert layout["slots"]==63 and layout["header_bytes"]==568
    assert layout["assembly_sha256"]=="659afe0dc2dcb4975e823fe96c4c3287450cca9428929e7a7211fe023212757d"
    tables=layout["tables"];assert len(tables)==1
    packer_rows=[r for r in old_manifest["compiled"] if r["label"]=="ordinary-patch-ELF-packer"]
    assert len(packer_rows)==1
    packer_row=packer_rows[0]
    packed_image=read(packer_row["image_path"])
    assert (len(packed_image),digest(packed_image))==(packer_row["image_bytes"],packer_row["image_sha256"])
    assert packer_row["receipt"]["artifact_sha256"]==digest(compiler_raw)
    assert packer_row["receipt"]["status"]=="returned" and packer_row["receipt"]["abi_status"]==0
    parts=[roles[i] for i in range(1,64)]
    packet=struct.pack("<8Q",int.from_bytes(b"HIAPPK01","little"),1,1,63,568+sum(map(len,parts)),568,64,0)
    packet+=struct.pack("<63Q",*map(len,parts))+b"".join(parts)
    expected=bytearray(prefix)
    for role,raw in enumerate(parts,1):
        expected+=bytes((-len(expected))&15)
        struct.pack_into("<Q",expected,tables[0]+role*8,4194304+len(expected));expected+=raw
    struct.pack_into("<Q",expected,96,len(expected));struct.pack_into("<Q",expected,104,len(expected))
    src=protected(packet);dst=protected(b"",len(expected),0x91);work=protected(b"",64,0x37)
    before=dict(source=cas(packet),output=cas(bytes([0x91])*len(expected)),workspace=cas(bytes([0x37])*64))
    save(OUT/"packer-pending.json",before);budget()
    native_packer=NativeHiaJsonImage(packed_image,expected_sha256=digest(packed_image))
    try:
        returned=int(native_packer._entry(src[1],src[2],dst[1],dst[2],work[1],work[2]));packer_entries+=1
        for guarded in (src,dst,work):checked(guarded)
        output=ctypes.string_at(dst[1],dst[2]);scratch=ctypes.string_at(work[1],64);source_after=ctypes.string_at(src[1],src[2])
        save(OUT/"packer-result.json",dict(before=before,returned=str(returned),output=cas(output),
            workspace=cas(scratch),source_after=cas(source_after),expected=cas(expected),all_canaries_unchanged=True))
        assert returned==len(expected) and output==bytes(expected) and source_after==packet and scratch==bytes([0x37])*64
    finally:native_packer._mapping.close()
    elf=OUT/"hia-ordinary-impact-development";elf.write_bytes(output);elf.chmod(0o700);read(elf)
    for module in tuple(sys.modules.values()):
        name=getattr(module,"__file__",None)
        if name:
            path=Path(name).resolve()
            if path.suffix==".py" and any(path.is_relative_to(root) for root in (WORK,REF,SOURCES,SUBMITTED)):read(path)
    save(OUT/"source-change-checks.json",source_checks)
    manifest=dict(schema="hia-ordinary-impact-seven-HIA-ASCII-reader-build-v1",
        status="BUILT_ONLY_NOT_SEMANTIC_QUALIFICATION",executable_path=str(elf),
        executable_bytes=len(output),executable_sha256=digest(output),
        compiled=old_manifest["compiled"]+compiled,role_bindings=bindings,
        compiler_sha256=digest(compiler_raw),new_compiles=13,baseline_new_compiles=6,
        optimization_new_compiles=7,changed_roles=list(CHANGED),unchanged_roles=56,
        actual_native_packer_entries=2,baseline_packer_entries=1,optimization_packer_entries=packer_entries,
        original_all_63_source_and_image_pins_reproduced=True,actual_original_ELF_reproduced=True,
        original_observed_manifest=pin(observed_raw),source_transform_proof=pin(proof_raw),
        original_executable_sha256=digest(old_elf),fixed_runtime_has_no_hosted_business_owner=True,
        stdin_magic="HIAEJN01",input_mode=1,
        input_views=["original program bytes","original patch bytes","zero unused third view"],
        output_views=["rechecked canonical candidate","actual issued patch receipt","actual complete impact report"],
        extra_candidate_recheck_and_complete_equality_required=True,impact_role=60,
        full_impact_qualified=False,whole_stack_closed=False,installed_activation=False)
    save(OUT/"manifest.json",manifest)
    assert len(compiled)==7 and len(source_checks)==7 and packer_entries==1 and unchanged()
    budget();status="PASS"
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
    for path in sorted(OUT.rglob("*.stderr.log")):
        print("HIA_ORDINARY_ASCII_NESTED_STDERR "+json.dumps(dict(path=str(path),text=path.read_text()),sort_keys=True),flush=True)
finally:
    frozen=[]
    for index,(path,(raw,mode)) in enumerate(PINS.items()):
        dest=OUT/"frozen-inputs"/str(index)/path.name;dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(raw);dest.chmod(mode)
        assert dest.read_bytes()==raw and stat.S_IMODE(dest.stat().st_mode)==mode
        frozen.append(dict(path=str(path),bytes=len(raw),sha256=digest(raw),gitsha=gitsha(raw),mode=mode))
    save(OUT/"source-and-image-pins.json",frozen)
    cas_count=0;cas_bytes=0
    for path in sorted((OUT/"cas").glob("*.zlib")):
        raw=zlib.decompress(path.read_bytes());assert digest(raw)==path.stem
        cas_count+=1;cas_bytes+=len(raw)
    same=unchanged();cpu=cpu_used();elapsed=time.monotonic_ns()-started
    if not same or cpu>90 or elapsed>=180000000000:status="FAIL"
    report=dict(status=status,scope="SEVEN_ACTUAL_HIA_ASCII_READER_IMAGES_AND_FRESH_FIXED_ELF",
        actual_optimization_B3=len(compiled),actual_optimization_packer_entries=packer_entries,
        actual_public_semantic_processes=0,compiled=compiled,source_change_checks=source_checks,
        failure=failure,source_and_image_before_after_equal=same,all_frozen_inputs_read_back=True,
        complete_CAS_verified=True,cas_objects=cas_count,logical_cas_bytes=cas_bytes,
        parent_plus_children_cpu_seconds=cpu,elapsed_ns=elapsed,
        original_B3_limits=dict(cpu_seconds=10,wall_seconds=20,address_space_bytes=268435456),
        original_builder_limits=dict(cpu_seconds=90,wall_seconds=180,address_space_bytes=1073741824),
        whole_stack_closed=False,full_impact_qualified=False,installed_activation=False)
    save(OUT/"summary.json",report)
    print("HIA_ORDINARY_ASCII_BUILD "+json.dumps(report,sort_keys=True),flush=True)
if status!="PASS":raise SystemExit(1)
