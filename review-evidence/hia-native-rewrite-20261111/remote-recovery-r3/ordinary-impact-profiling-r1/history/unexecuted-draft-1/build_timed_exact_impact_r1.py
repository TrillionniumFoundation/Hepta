"""One fresh bounded HIA packer for timing an exact previously qualified image set."""
from __future__ import annotations
import argparse,ast,ctypes,importlib.util,json,os,re,resource,stat,struct,sys,time,traceback,zlib
from hashlib import sha1,sha256
from pathlib import Path
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
p.add_argument("--original-readback",type=Path,required=True)
p.add_argument("--reference",type=Path,required=True)
p.add_argument("--trace-author",type=Path,required=True)
p.add_argument("--out",type=Path,required=True)
a=p.parse_args()
ROOT=a.original_readback.resolve();REF=a.reference.resolve();OUT=a.out.resolve()
OUT.mkdir(parents=True,exist_ok=False)
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
started=time.monotonic_ns();PINS={};compiled=[];status="FAIL";details={}
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def pin(path):
    path=Path(path).resolve()
    st=path.lstat();assert stat.S_ISREG(st.st_mode) and st.st_nlink==1,str(path)
    raw=path.read_bytes();mode=stat.S_IMODE(st.st_mode)
    if path in PINS:assert PINS[path]==(raw,mode)
    PINS[path]=(raw,mode)
    return raw
def save(name,obj):
    path=OUT/name;path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
def load(name,path):
    raw=pin(path);ast.parse(raw,filename=str(path))
    spec=importlib.util.spec_from_file_location(name,path)
    mod=importlib.util.module_from_spec(spec);sys.modules[name]=mod;spec.loader.exec_module(mod)
    return mod
def unchanged():
    return all(path.is_file() and path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
        for path,(raw,mode) in PINS.items())
try:
    index_raw=pin(ROOT/"impact-original-member-index.json")
    assert len(index_raw)==1376145 and digest(index_raw)=="9e63275d5f9541d69aa8bf75a0c2e2fa8f736af0fdc62374fdcfdd2ef97b4b48"
    index=json.loads(index_raw);assert len(index)==3090
    by_name={r["name"]:r for r in index};assert len(by_name)==3090
    by_old_path={}
    for r in index:
        by_old_path.setdefault(r["path"],[]).append(r)
    def original(name):
        row=by_name[name];path=ROOT/"archive-originals"/name
        assert path.resolve().is_relative_to((ROOT/"archive-originals").resolve())
        raw=pin(path)
        assert (len(raw),digest(raw),stat.S_IMODE(path.stat().st_mode))==(row["bytes"],row["sha256"],row["mode"]),name
        return path,raw
    def from_old_path(path,size,d):
        rows=by_old_path[path];assert rows
        assert all((r["bytes"],r["sha256"])==(size,d) for r in rows)
        result=None
        for r in rows:
            pair=original(r["name"])
            if result is None:result=pair
            else:assert result[1]==pair[1]
        return result
    stem="ordinary-impact-coordinator/development/build-r1/"
    _,manifest_raw=original(stem+"manifest.json")
    manifest=json.loads(manifest_raw)
    assert manifest["status"]=="BUILT_ONLY_NOT_SEMANTIC_QUALIFICATION"
    assert manifest["new_compiles"]==6 and manifest["actual_native_packer_entries"]==1
    assert set(manifest["role_bindings"])=={str(i) for i in range(1,64)}
    bindings=[];parts=[]
    for role in range(1,64):
        b=manifest["role_bindings"][str(role)]
        _,source=from_old_path(b["source_path"],b["source_bytes"],b["source_sha256"])
        _,image=from_old_path(b["image_path"],b["image_bytes"],b["image_sha256"])
        assert 0<len(source)<=1048576 and 0<len(image)<=1048576
        parts.append(image)
        bindings.append(dict(role=role,source_bytes=len(source),source_sha256=digest(source),
            image_bytes=len(image),image_sha256=digest(image)))
    _,old_elf=from_old_path(manifest["executable_path"],manifest["executable_bytes"],manifest["executable_sha256"])
    compiler_rows=[r for r in index if r["bytes"]==669556 and r["sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"]
    assert compiler_rows,"exact original B3 missing; no substitute"
    COMPILER,compiler_raw=original(compiler_rows[0]["name"])
    for row in compiler_rows[1:]:assert original(row["name"])[1]==compiler_raw
    subject="ordinary-impact-coordinator-submitted-source/"
    builder_path,builder_raw=original(subject+"build_ordinary_impact_coordinator_r1.py")
    assert gitsha(builder_raw)=="c6c6ad3248c09faa1153e9e754cd2d4943a7455c"
    assembly_path,assembly_raw=original(subject+"ordinary_patch_executor.S")
    assert gitsha(assembly_raw)=="aeaf61efa6fde911dd5a031adaa55b865e407518"
    packer_path,packer_raw=original(subject+"generate_ordinary_patch_packer_r1.py")
    assert gitsha(packer_raw)=="8be428f48fd6353daa52747eaeacdf569a3136c6"
    authoring_path,authoring_raw=original(subject+"cli_authoring.py")
    assert gitsha(authoring_raw)=="6f1bffe8bd815a068f9834489960006cbaad6fac"
    assert gitsha(pin(a.trace_author))=="bce0fc69dbd381f21f4b37c885e6ac32ee8d5677"
    sys.path[:0]=[str(packer_path.parent),str(REF)]
    from hepta.hia_agent_assembly import render_assembly,assemble_program
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    from tools.qualify_hia_selfhost import compile_stage
    authoring=load("cli_authoring",authoring_path)
    packer=load("original_impact_fixed_packer",packer_path)
    trace_author=load("impact_timing_only_author",a.trace_author.resolve())
    traced,reverse=trace_author.instrument(assembly_raw)
    assert reverse["complete_reverse_bytes_equal"] and reverse["changed_HIA_semantic_images"]==0
    (OUT/"original.S").write_bytes(assembly_raw);(OUT/"timed.S").write_bytes(traced)
    save("mechanical-source-reverse-proof.json",reverse)
    plain_dir=OUT/"original-template";plain_dir.mkdir()
    original_prefix,original_tables,observed=packer.template(assembly_path,plain_dir)
    assert observed==assembly_raw
    _,expected_old_prefix=original(stem+"carrier/prefix.bin")
    assert original_prefix==expected_old_prefix
    def expected_elf(prefix,tables):
        assert len(tables)==1
        value=bytearray(prefix)
        for role,raw in enumerate(parts,1):
            value+=bytes((-len(value))&15)
            struct.pack_into("<Q",value,tables[0]+role*8,4194304+len(value))
            value+=raw
        struct.pack_into("<Q",value,96,len(value));struct.pack_into("<Q",value,104,len(value))
        return bytes(value)
    assert expected_elf(original_prefix,original_tables)==old_elf
    timed_dir=OUT/"timed-template";timed_dir.mkdir()
    prefix,tables,observed=packer.template(OUT/"timed.S",timed_dir)
    assert observed==traced
    (OUT/"timed-prefix.bin").write_bytes(prefix)
    expected=expected_elf(prefix,tables)
    # Only exact function definitions are reused. The six-compile top-level
    # original builder is not executed and no previous build count is inherited.
    tree=ast.parse(builder_raw,filename=str(builder_path))
    required={"digest","gitsha","read","save","cas","unchanged","load","protected","checked","compile_document"}
    functions=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in required]
    assert {n.name for n in functions}==required
    helpers=dict(__builtins__=__builtins__,__name__="impact_original_bounded_build_helpers",
        ast=ast,ctypes=ctypes,importlib=importlib,json=json,os=os,re=re,resource=resource,
        stat=stat,struct=struct,sys=sys,time=time,traceback=traceback,zlib=zlib,
        sha1=sha1,sha256=sha256,Path=Path,OUT=OUT,PINS=PINS,compiled=compiled,
        COMPILER=COMPILER,compiler_raw=compiler_raw,authoring=authoring,
        render_assembly=render_assembly,assemble_program=assemble_program,compile_stage=compile_stage)
    exec(compile(ast.Module(body=functions,type_ignores=[]),str(builder_path),"exec"),helpers)
    image,record=helpers["compile_document"]("mechanical-timing-ELF-packer",body=packer.source(prefix,tables))
    assert len(compiled)==1
    packet=struct.pack("<8Q",int.from_bytes(b"HIAPPK01","little"),1,1,63,568+sum(map(len,parts)),568,64,0)
    packet+=struct.pack("<63Q",*map(len,parts))+b"".join(parts)
    protected,checked=helpers["protected"],helpers["checked"]
    source=protected(packet);output=protected(b"",len(expected),0x91);work=protected(b"",64,0x37)
    native=NativeHiaJsonImage(image,expected_sha256=digest(image))
    returned=int(native._entry(source[1],source[2],output[1],output[2],work[1],work[2]))
    for row in (source,output,work):checked(row)
    actual=ctypes.string_at(output[1],output[2])
    assert returned==len(expected) and actual==expected
    assert ctypes.string_at(source[1],source[2])==packet
    assert ctypes.string_at(work[1],64)==bytes([0x37])*64
    native._mapping.close()
    (OUT/"packer-input.bin").write_bytes(packet)
    (OUT/"packer-expected-output.bin").write_bytes(expected)
    (OUT/"packer-output.bin").write_bytes(actual)
    (OUT/"packer-output-before.bin").write_bytes(bytes([0x91])*len(expected))
    (OUT/"packer-work-before.bin").write_bytes(bytes([0x37])*64)
    (OUT/"packer-work-after.bin").write_bytes(ctypes.string_at(work[1],64))
    plain=OUT/"original-unchanged.elf";plain.write_bytes(old_elf);plain.chmod(0o700)
    timed=OUT/"timed-exact-images.elf";timed.write_bytes(actual);timed.chmod(0o700)
    pin(plain);pin(timed)
    for module in tuple(sys.modules.values()):
        name=getattr(module,"__file__",None)
        if name:
            path=Path(name).resolve()
            if path.suffix==".py" and (path.is_relative_to(REF) or path.is_relative_to(ROOT)):
                pin(path)
    assert unchanged()
    details.update(schema="hia-original-impact-timing-build-v1",status="BUILT_DIAGNOSTIC_ONLY",
        original_archive_members=3090,retained_HIA_images=63,all_retained_source_image_bytes_bound=True,
        original_ELF_reproduced_full_bytes=True,complete_assembly_reverse_equal=True,
        fresh_B3=1,actual_native_packer_entries=1,actual_semantic_processes=0,
        original_elf=dict(path=str(plain),bytes=len(old_elf),sha256=digest(old_elf)),
        timed_elf=dict(path=str(timed),bytes=len(actual),sha256=digest(actual)),
        trace_fd=198,trace_record_bytes=128,role_bindings=bindings,compiled=compiled,
        timing_includes_before_hook_sampling_and_write_overhead=True,
        original_impact_failure_unchanged=True,semantic_qualification=False,whole_stack_closed=False)
    save("manifest.json",details);status="PASS"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    same=unchanged()
    if not same:status="FAIL"
    save("source-and-image-pins.json",[dict(path=str(path),bytes=len(raw),sha256=digest(raw),
        gitsha=gitsha(raw),mode=mode) for path,(raw,mode) in PINS.items()])
    details.update(build_status=status,source_and_image_before_after_equal=same,
        actual_fresh_B3=len(compiled),elapsed_ns=time.monotonic_ns()-started,
        whole_stack_closed=False,semantic_qualification=False)
    save("summary.json",details)
    print("HIA_IMPACT_TIMING_BUILD "+json.dumps(details,sort_keys=True),flush=True)
if status!="PASS":raise SystemExit(1)
