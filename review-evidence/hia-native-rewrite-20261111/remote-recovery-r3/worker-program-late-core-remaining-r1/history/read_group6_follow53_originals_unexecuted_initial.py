"""Exact FOLLOW53 full original late-Core artifact readback. Zero target replay.
All ZIP/tar members, compressed CAS, six complete cases and frozen source/mode
identities are checked before a separate continuation may use the old six.
"""
from __future__ import annotations
import argparse,base64,binascii,hashlib,json,os,resource,shutil,signal,stat,struct,subprocess,sys,tarfile,time,traceback,zipfile,zlib
from pathlib import Path,PurePosixPath

ZIP_BYTES=100633717
ZIP_SHA="36f8063dd97c8fffeed958797a22d38e091d9185ef1c90604c75ff509b70093d"
INNER_BYTES=28834052
INNER_SHA="0ac66c2a6be8b599368294a017becc2b39fe4a9f0276e86a38bba0ed07666ea7"
INDEX_BYTES=292041
INDEX_SHA="24e653fd7dd2d8edf319d75abd7dce47a6f589deacf70ab0ea1394be9239f6e8"
MEMBERS=756
ORIGINAL_BYTES=195136808
OUTER_PREFIX="hia-worker-program-late-core-recovery/"
ROOT="worker-late-Core/"
OLD_PROJECT="/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/worker-late-Core-native-r1"
BUILD=ROOT+"development/build-r1/"
COMPILER_SHA="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
GROUPS=("late-node-below","late-node-equal","late-node-over",
        "late-byte-below","late-byte-equal","late-byte-over")
HEX=set("0123456789abcdef")
MATERIALIZED={}
PENDING={}
SELECTED={}
EXPORTED=[]
CHUNK=1024*1024
REFERENCE_COMMIT="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
REFERENCE_TREE=None
REPO=None

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def git_blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode("ascii")+b"\0"+raw).hexdigest()

def safe_name(name):
    assert isinstance(name,str) and name and "\\" not in name and "\0" not in name,name
    p=PurePosixPath(name)
    assert not p.is_absolute() and all(s not in ("",".","..") for s in name.split("/")),name
    assert p.as_posix()==name,name
    return name

def stream_hash(path):
    sha=hashlib.sha256();size=0
    with Path(path).open("rb") as f:
        while True:
            raw=f.read(CHUNK)
            if not raw:break
            size+=len(raw);sha.update(raw)
    return size,sha.hexdigest()

def file_fact(path):
    p=Path(path);st=p.lstat()
    assert stat.S_ISREG(st.st_mode) and not p.is_symlink(),str(p)
    n,h=stream_hash(p)
    return dict(path=str(p.resolve()),bytes=n,sha256=h,mode=stat.S_IMODE(st.st_mode))

def register(path,size=None,sha=None,mode=None):
    p=Path(path).resolve();row=file_fact(p)
    if size is not None:assert row["bytes"]==size,(str(p),row["bytes"],size)
    if sha is not None:assert row["sha256"]==sha,(str(p),row["sha256"],sha)
    if mode is not None:assert row["mode"]==mode,(str(p),row["mode"],mode)
    key=str(p)
    if key in MATERIALIZED:assert MATERIALIZED[key]==row,key
    else:MATERIALIZED[key]=row
    PENDING.pop(key,None)
    return row

def write_bytes(path,raw,mode=0o644):
    p=Path(path).resolve();p.parent.mkdir(parents=True,exist_ok=True)
    assert not p.exists(),str(p)
    wanted=dict(path=str(p),bytes=len(raw),sha256=digest(raw),mode=mode)
    PENDING[str(p)]=wanted
    with p.open("xb") as f:f.write(raw)
    p.chmod(mode)
    return register(p,wanted["bytes"],wanted["sha256"],mode)

def write_json(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n").encode("utf-8")
    return write_bytes(path,raw)

def json_bytes(raw):
    # Metadata only. Original JSON byte copies are always retained separately.
    return json.loads(raw)

def original_export(name,raw):
    row=dict(name=name,bytes=len(raw),sha256=digest(raw),gitsha=git_blob(raw))
    EXPORTED.append(row)
    print("HIA_LATE_CORE53_ORIGINAL "+json.dumps(dict(row,base64=base64.b64encode(raw).decode("ascii")),sort_keys=True),flush=True)
    return row

def selected(name):
    return True

def named_cas(name):
    p=PurePosixPath(name)
    if p.suffix not in (".zlib",".gz"):return None
    stem=p.stem
    if len(stem)==64 and set(stem)<=HEX:return stem
    return None

def consume_tar_member(tf,item,target,cas_sha):
    sha=hashlib.sha256();size=0;decoded=hashlib.sha256();logical=0
    dec=zlib.decompressobj(31 if item.name.endswith(".gz") else 15) if cas_sha else None
    output=None
    if target is not None:
        target.parent.mkdir(parents=True,exist_ok=True)
        assert not target.exists(),str(target)
        PENDING[str(target.resolve())]=dict(path=str(target.resolve()),
            bytes=item.size,sha256=None,mode=item.mode,original_member=item.name)
        output=target.open("xb")
    try:
        source=tf.extractfile(item)
        assert source is not None,item.name
        with source:
            while True:
                raw=source.read(CHUNK)
                if not raw:break
                size+=len(raw);sha.update(raw)
                if output:output.write(raw)
                if dec:
                    pending=raw
                    while pending:
                        out=dec.decompress(pending,CHUNK)
                        decoded.update(out);logical+=len(out)
                        tail=dec.unconsumed_tail
                        assert tail!=pending or out,(item.name,"CAS no progress")
                        pending=tail
            if dec:
                while True:
                    out=dec.decompress(b"",CHUNK)
                    decoded.update(out);logical+=len(out)
                    if not out:break
                out=dec.flush()
                decoded.update(out);logical+=len(out)
                assert dec.eof and not dec.unused_data and not dec.unconsumed_tail,(item.name,"CAS extent")
                assert decoded.hexdigest()==cas_sha,(item.name,"CAS logical SHA",decoded.hexdigest(),cas_sha)
    finally:
        if output:output.close()
    assert size==item.size,(item.name,size,item.size)
    if target is not None:
        target.chmod(item.mode)
        register(target,size,sha.hexdigest(),item.mode)
        SELECTED[item.name]=str(target.resolve())
    return dict(bytes=size,sha256=sha.hexdigest(),
                cas=None if not dec else dict(bytes=logical,sha256=decoded.hexdigest()))

def scan_zip(retained,out):
    outer=[];names=set();captured={}
    capture_names={OUTER_PREFIX+base:base for base in ("custody.json","evidence-members.json","evidence.tar.xz")}
    with zipfile.ZipFile(retained) as z:
        for item in z.infolist():
            if item.is_dir():
                safe_name(item.filename.rstrip("/"))
                assert item.file_size==0
                continue
            name=safe_name(item.filename);assert name not in names,name;names.add(name)
            kind=(item.external_attr>>16)&0o170000
            assert kind in (0,stat.S_IFREG),(name,"nonregular ZIP member",kind)
            assert not(item.flag_bits&1),(name,"encrypted")
            sha=hashlib.sha256();crc=0;count=0
            target=out/"outer"/name if name in capture_names else None
            handle=None
            if target:
                target.parent.mkdir(parents=True,exist_ok=True)
                PENDING[str(target.resolve())]=dict(path=str(target.resolve()),bytes=item.file_size,
                    sha256=None,mode=0o644,original_member=name)
                handle=target.open("xb")
            try:
                with z.open(item) as f:
                    while True:
                        raw=f.read(CHUNK)
                        if not raw:break
                        count+=len(raw);sha.update(raw);crc=binascii.crc32(raw,crc)
                        if handle:handle.write(raw)
            finally:
                if handle:handle.close()
            assert count==item.file_size and (crc&0xffffffff)==item.CRC,name
            row=dict(name=name,bytes=count,sha256=sha.hexdigest(),crc32=item.CRC,
                     mode=(item.external_attr>>16)&0o777,compressed_bytes=item.compress_size)
            outer.append(row)
            if target:
                target.chmod(0o644);register(target,count,sha.hexdigest(),0o644)
                captured[capture_names[name]]=target
    # Preserve the complete actual ZIP inventory even if the exact capture gate fails.
    write_json(out/"outer-members.json",outer)
    assert len(outer)==978,(len(outer),"original upload reported 978 files")
    assert set(captured)=={"custody.json","evidence-members.json","evidence.tar.xz"}
    assert stream_hash(captured["evidence.tar.xz"])==(INNER_BYTES,INNER_SHA)
    assert stream_hash(captured["evidence-members.json"])==(INDEX_BYTES,INDEX_SHA)
    custody=json_bytes(captured["custody.json"].read_bytes())
    assert custody["schema"]=="hia-independent-ci-artifact-custody-v1"
    assert custody["scope"]=="worker-ordinary-late-Core-native-full-text-r1"
    assert custody["status"]=="FAIL" and custody["whole_stack_closed"] is False
    assert custody["all_original_and_tar_member_bytes_sha256_modes_readback"] is True
    assert (custody["bytes"],custody["sha256"],custody["members"],custody["original_bytes"])==(INNER_BYTES,INNER_SHA,MEMBERS,ORIGINAL_BYTES)
    assert (custody["member_index_bytes"],custody["member_index_sha256"])==(INDEX_BYTES,INDEX_SHA)
    ledger=json_bytes(captured["evidence-members.json"].read_bytes())
    assert isinstance(ledger,list) and len(ledger)==MEMBERS
    expected={}
    for row in ledger:
        name=safe_name(row["name"]);assert name not in expected,name
        assert isinstance(row["bytes"],int) and row["bytes"]>=0
        assert isinstance(row["mode"],int) and 0<=row["mode"]<=0o777
        assert len(row["sha256"])==64 and set(row["sha256"])<=HEX
        expected[name]=row
    assert sum(r["bytes"] for r in ledger)==ORIGINAL_BYTES
    return captured,expected,outer

def scan_inner(archive,expected,out):
    actual=[];seen=set();cas_count=0;logical_bytes=0
    with tarfile.open(archive,"r|xz") as tf:
        for item in tf:
            name=safe_name(item.name)
            assert item.isfile() and not item.issym() and not item.islnk(),name
            assert name not in seen and name in expected,name;seen.add(name)
            row=expected[name]
            assert (item.size,item.mode)==(row["bytes"],row["mode"]),(name,"size/mode")
            assert item.uid==0 and item.gid==0 and item.mtime==0,name
            target=out/"members"/name if selected(name) else None
            value=consume_tar_member(tf,item,target,named_cas(name))
            assert value["sha256"]==row["sha256"],(name,"full bytes")
            if value["cas"]:
                cas_count+=1;logical_bytes+=value["cas"]["bytes"]
            actual.append(dict(name=name,mode=item.mode,**value))
    assert seen==set(expected)
    assert len(actual)==MEMBERS and sum(r["bytes"] for r in actual)==ORIGINAL_BYTES
    write_json(out/"inner-members-readback.json",actual)
    return dict(members=len(actual),original_bytes=sum(r["bytes"] for r in actual),
                compressed_CAS_count=cas_count,decoded_CAS_bytes=logical_bytes,
                every_CAS_logical_SHA_verified=True)

def resolve_cas(run_prefix,record):
    assert isinstance(record,dict) and record["compression"]=="zlib",record
    rel=safe_name(record["path"])
    name=run_prefix+rel
    assert name in SELECTED,name
    raw=zlib.decompress(Path(SELECTED[name]).read_bytes())
    assert (len(raw),digest(raw))==(record["bytes"],record["sha256"]),(name,"referenced CAS")
    return raw


def original_raw(name):
    assert name in SELECTED,("missing exact original member",name)
    row=MATERIALIZED[SELECTED[name]]
    raw=Path(SELECTED[name]).read_bytes()
    assert (len(raw),digest(raw),stat.S_IMODE(Path(SELECTED[name]).stat().st_mode))==(
        row["bytes"],row["sha256"],row["mode"]),name
    return raw

def original_json(name):
    return json_bytes(original_raw(name))

def mapped_original_path(path):
    assert isinstance(path,str) and path.startswith(OLD_PROJECT+"/"),path
    return ROOT+safe_name(path[len(OLD_PROJECT)+1:])

def exact_reference_file(path,out):
    global REFERENCE_TREE
    prefix="/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/reference-0ef-r2/"
    assert path.startswith(prefix),("unretained runtime dependency outside original reference",path)
    relative=safe_name(path[len(prefix):])
    if REFERENCE_TREE is None:
        raw=subprocess.check_output(["/usr/bin/git","ls-tree","-rz","--full-tree","-r",REFERENCE_COMMIT],cwd=REPO)
        REFERENCE_TREE={}
        for item in raw.split(b"\0"):
            if not item:continue
            head,name=item.split(b"\t",1);mode,kind,sha=head.decode("ascii").split()
            name=name.decode("utf-8");safe_name(name)
            assert name not in REFERENCE_TREE
            REFERENCE_TREE[name]=(mode,kind,sha)
        write_bytes(out/"original-reference-tree.bin",raw)
    assert relative in REFERENCE_TREE,relative
    mode,kind,sha=REFERENCE_TREE[relative]
    assert (mode,kind)==("100644","blob"),relative
    target=out/"exact-original-reference"/relative
    if str(target.resolve()) in MATERIALIZED:
        raw=target.read_bytes()
    else:
        raw=subprocess.check_output(["/usr/bin/git","cat-file","blob",sha],cwd=REPO)
        assert git_blob(raw)==sha,(relative,"original reference Git identity")
        write_bytes(target,raw,0o644)
    assert git_blob(raw)==sha
    return raw,0o644

def check_sources_and_build(out):
    pins=original_json(BUILD+"source-pins.json")
    assert type(pins) is list and pins
    by_path={};rows=[]
    for pin in pins:
        path=pin["path"];assert path not in by_path,path
        name=mapped_original_path(pin["frozen"])
        assert name.startswith(BUILD+"frozen-inputs/"),name
        raw=original_raw(name)
        assert (len(raw),digest(raw),git_blob(raw),MATERIALIZED[SELECTED[name]]["mode"])==(
            pin["bytes"],pin["sha256"],pin["gitsha"],pin["mode"]),(path,"frozen source identity")
        by_path[path]=dict(pin,member=name)
        rows.append(dict(original_path=path,member=name,bytes=len(raw),
                         sha256=digest(raw),gitsha=git_blob(raw),mode=pin["mode"]))
    def bound(path,size,sha):
        assert path in by_path,("not bound by original source-before/after",path)
        pin=by_path[path]
        assert (pin["bytes"],pin["sha256"])==(size,sha),(path,"source binding")
        raw=original_raw(pin["member"])
        assert len(raw)==size and digest(raw)==sha
        return pin
    bundle=original_json(BUILD+"bundle.json")
    report=original_json(BUILD+"summary.json")
    assert bundle["status"]=="BUILT_ONLY" and bundle["compiler_sha256"]==COMPILER_SHA
    assert (bundle["fresh_compiles"],bundle["nonzero_images"],bundle["table_rows"])==(13,43,63)
    assert report["status"]=="PASS" and report["source_and_image_before_after_equal"] is True
    assert (report["actual_compile_attempts"],report["actual_compiles"],report["actual_packer_entries"])==(13,13,1)
    assert report["actual_semantic_processes"]==0 and report["compiler_sha256"]==COMPILER_SHA
    assert report["original_compile_limits"]==dict(cpu=10,wall=20,address=268435456)
    assert report["runtime_groups"]==dict(cpu=90,wall=180,address=1<<30)
    roles=bundle["role_bindings"]
    assert set(roles)=={str(i) for i in set(range(1,29))|set(range(40,47))|{50,51,55,56,59,61,62,63}}
    verified_roles={}
    for role,row in roles.items():
        result={}
        for which in ("source","image"):
            pin=bound(row[which+"_path"],row[which+"_bytes"],row[which+"_sha256"])
            result[which]=dict(bytes=pin["bytes"],sha256=pin["sha256"],gitsha=pin["gitsha"],
                               mode=pin["mode"],frozen_member=pin["member"])
        verified_roles[role]=result
    executable=bound(bundle["executable_path"],bundle["executable_bytes"],bundle["executable_sha256"])
    assert executable["mode"]==0o700
    compiled=report["compiled"]
    assert len(compiled)==13 and compiled==bundle["compiled"]
    compile_rows=[]
    for row in compiled:
        for which in ("source","image"):
            bound(row[which+"_path"],row[which+"_bytes"],row[which+"_sha256"])
        receipt=row["receipt"]
        assert receipt["status"]=="returned" and receipt["abi_status"]==0
        assert receipt["artifact_sha256"]==COMPILER_SHA and receipt["source_unchanged"] is True
        assert receipt["forbidden_compiler_modules_loaded"]==[]
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==268435456
        assert receipt["limits"]["output_capacity"]==1048576
        assert 0<=receipt["wall_elapsed_ns"]<20_000_000_000
        assert (receipt["input_bytes"],receipt["input_sha256"])==(row["source_bytes"],row["source_sha256"])
        assert (receipt["produced_bytes"],receipt["produced_sha256"])==(row["image_bytes"],row["image_sha256"])
        compile_rows.append(dict(label=row["label"],source_sha256=row["source_sha256"],
                                 image_sha256=row["image_sha256"],original_receipt=receipt))
    write_json(out/"verified-original-source-pins.json",rows)
    return dict(status="PASS",role_bindings=verified_roles,compiler_sha256=COMPILER_SHA,
        executable=executable,compiled=compile_rows,source_count=len(rows),
        bundle_member=BUILD+"bundle.json",bundle_copy=SELECTED[BUILD+"bundle.json"],
        bundle_sha256=digest(original_raw(BUILD+"bundle.json")),
        original_build_pass=True,by_path=by_path)

def verify_case_source_pins(prefix,build,out):
    pins=original_json(prefix+"source-pins.json")
    assert type(pins) is list and pins
    for pin in pins:
        path=pin["path"]
        if path.startswith(OLD_PROJECT+"/") and mapped_original_path(path) in SELECTED:
            name=mapped_original_path(path);raw=original_raw(name)
            mode=MATERIALIZED[SELECTED[name]]["mode"]
        elif path in build["by_path"]:
            old=build["by_path"][path];raw=original_raw(old["member"]);mode=old["mode"]
        else:
            # The old runtime record can include a lazily imported original
            # reference module not copied by the build. Recover only its exact
            # immutable 0ef Git blob, verify against the old recorded SHA/mode,
            # and retain those full bytes. Never read the vanished old path.
            raw,mode=exact_reference_file(path,out)
        assert (len(raw),digest(raw),mode)==(pin["bytes"],pin["sha256"],pin["mode"]),path
    return len(pins)

def verify_complete_case(group,build,out):
    prefix=ROOT+"development/actual-"+group+"-r1/"
    summary=original_json(prefix+"summary.json")
    assert summary["status"]=="PASS" and summary["source_image_executable_before_after_equal"] is True
    assert (summary["planned_cases"],summary["completed_cases"],summary["attempted_case_results"],
            summary["actual_native_processes"],summary["actual_private_kernel_entries"])==(1,1,1,1,0)
    assert summary["source_after_errors"]==[] and summary["public_case_failures"]==[]
    assert summary["original_limits"]==dict(cpu=90,wall=180,address=1<<30)
    assert 0<=summary["aggregate_cpu_seconds"]<90 and 0<=summary["elapsed_ns"]<180_000_000_000
    process=original_json("run/steps/worker-late-Core-group-"+group+"/process.json")
    assert process["status"]=="PASS" and process["returncode"]==0 and process["timed_out"] is False
    assert process["timeout_seconds"]==180 and 0<=process["child_cpu_seconds"]<90
    assert 0<=process["elapsed_ns"]<180_000_000_000
    completed=original_json(prefix+"cases-completed.json")
    plan=original_json(prefix+"planned-corpus.json")
    assert len(completed)==len(plan)==1
    row,planned=completed[0],plan[0]
    assert row["label"]==planned["label"]==group and row["status"]=="PASS"
    assert row["public_original_oracle"] and row["enum_not_substituted"]
    assert row["complete_payload_and_Core_bytes_equal"] and row["actual_receipt_digests_equal"]
    case=prefix+"cases/"+group+"/"
    actual=original_json(case+"process.json")
    assert actual==row["process"] and actual["returncode"]==2 and actual["timed_out"] is False
    assert actual["parent_cleanup_complete"] and actual["empty_PATH_and_HOME"]
    assert actual["no_runtime_python_or_oracle_callback"]
    input_raw=original_raw(case+"input.bin")
    stdout=original_raw(case+"stdout.bin")
    stderr=original_raw(case+"stderr.bin")
    for name,raw in (("input",input_raw),("stdout",stdout),("stderr",stderr)):
        assert resolve_cas(prefix,actual[name])==raw
    assert resolve_cas(prefix,row["actual_complete_stdout"])==stdout
    assert resolve_cas(prefix,row["actual_complete_stderr"])==stderr
    source=resolve_cas(prefix,planned["input"])
    header=struct.unpack("<8Q",input_raw[:64])
    assert header==(int.from_bytes(b"HIAWPI01","little"),0x575d0001,1,4300,len(source),1,0,0)
    assert input_raw[64:]==source and stdout==b""
    expected=planned["expected"]
    assert expected["kind"]==4 and expected["program"] is None
    payload=resolve_cas(prefix,expected["payload"])
    assert resolve_cas(prefix,row["expected_complete_payload"])==payload
    assert len(stderr)>=384
    terminal=struct.unpack("<16Q",stderr[:128]);result=stderr[128:]
    assert terminal[0]==int.from_bytes(b"HIACDE01","little") and terminal[1]==7
    assert terminal[2]==header[1] and terminal[3]>0
    assert terminal[4:9]==(1,expected["domain"],30,0,len(result))
    assert terminal[9:12]==(4,expected["domain"],len(result)) and terminal[12:]==(0,0,0,0)
    words=struct.unpack_from("<32Q",result)
    assert words[:10]==(int.from_bytes(b"HIAWPE01","little"),1,header[1],1,1,
                       4,expected["domain"],expected["phase"],expected["line"],len(result))
    assert words[10:14]==(0,0,0,0) and words[18:]==(0,)*14
    at,size,code_at,code_size=words[14:18]
    assert (at,code_at,size,len(result))==(256,256,len(payload),256+len(payload))
    assert 0<code_size<=size and result[at:]==payload
    assert result[code_at:code_at+code_size]==expected["code"].encode("utf-8")
    assert resolve_cas(prefix,row["result"])==result
    evidence=original_json(prefix+"original-late-Core-fixture-evidence.json")
    assert evidence["group"]==group and len(evidence["cases"])==1
    witness=evidence["cases"][0]
    assert witness["label"]==group and witness["original_public_trace"]["text"].encode("utf-8")==payload
    assert resolve_cas(prefix,witness["source"])==source
    for name in ("canonical_source","actual_original_elaborated_Core"):
        resolve_cas(prefix,witness[name])
    assert witness["all_original_semantics_finished_before_native_interval"] is True
    pins=verify_case_source_pins(prefix,build,out)
    return dict(group=group,status="PASS",original_actual_processes=1,
        full_input_bytes=len(input_raw),full_stdout_bytes=0,full_stderr_bytes=len(stderr),
        input_sha256=digest(input_raw),stderr_sha256=digest(stderr),
        original_expected_full_text=payload.decode("utf-8"),source_pins_verified=pins,
        original_public_trace=witness["original_public_trace"],
        original_process_receipt=process,original_case_receipt=actual,
        complete_actual_bytes_and_expected_payload_equal=True)

def diagnose(out):
    build=check_sources_and_build(out)
    cases=[verify_complete_case(group,build,out) for group in GROUPS]
    assert len(cases)==6
    failures=[]
    for group,entries,error in (("late-depth-and-order",0,"AssertionError"),
                                 ("late-private-protocol",1,"KeyError")):
        prefix=ROOT+"development/actual-"+group+"-r1/"
        report=original_json(prefix+"summary.json")
        assert report["status"]=="FAIL" and report["completed_cases"]==0
        assert report["actual_native_processes"]==0 and report["actual_private_kernel_entries"]==entries
        assert report["failure"]["error_class"]==error and report["source_after_errors"]==[]
        failures.append(dict(group=group,original_summary=report))
    build.pop("by_path")
    write_json(out/"verified-original-build.json",build)
    write_json(out/"six-original-public-cases.json",cases)
    write_json(out/"original-two-fixture-failures.json",failures)
    return dict(status="PASS",original_target_status="FAIL",completed_original_public_cases=6,
        original_uncompleted_groups=failures,all_43_source_image_bytes_bound=True,
        complete_original_ELF_and_13_compiler_outputs_bound=True,
        original_build=build,complete_original_cases=cases,
        source_and_modes_before_after_evidence_bound=True,
        original_limits_unchanged=True,old_413_cases_reexecuted=False,new_target_entries=0)


def measured(start,before,children):
    own=resource.getrusage(resource.RUSAGE_SELF)
    child=resource.getrusage(resource.RUSAGE_CHILDREN)
    return dict(elapsed_ns=time.monotonic_ns()-start,
        aggregate_cpu_seconds=own.ru_utime+own.ru_stime-before.ru_utime-before.ru_stime+
            child.ru_utime+child.ru_stime-children.ru_utime-children.ru_stime)

def wall_timeout(*_):
    raise TimeoutError("original readback180wall")

def main():
    global REPO
    assert sys.version_info[:3]==(3,12,14)
    parser=argparse.ArgumentParser()
    parser.add_argument("--zip",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--repo",type=Path,required=True)
    args=parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    start=time.monotonic_ns();before=resource.getrusage(resource.RUSAGE_SELF)
    children=resource.getrusage(resource.RUSAGE_CHILDREN)
    signal.signal(signal.SIGALRM,wall_timeout)
    signal.setitimer(signal.ITIMER_REAL,180)
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    REPO=args.repo.resolve()
    status="FAIL";primary=None;after_errors=[];facts={};inner={};outer=[]
    input_before={};after_rows=[];retained=out/"original-follow53.zip"
    retained_after=False;full_members_after=False
    try:
        for path in (Path(__file__).resolve(),args.zip.resolve()):
            row=file_fact(path);input_before[str(path)]=row
        zip_before=input_before[str(args.zip.resolve())]
        assert (zip_before["bytes"],zip_before["sha256"])==(ZIP_BYTES,ZIP_SHA)
        PENDING[str(retained)]=dict(path=str(retained),bytes=ZIP_BYTES,sha256=ZIP_SHA,mode=0o600)
        shutil.copyfile(args.zip,retained);retained.chmod(0o600)
        register(retained,ZIP_BYTES,ZIP_SHA,0o600)
        captured,expected,outer=scan_zip(retained,out)
        inner=scan_inner(captured["evidence.tar.xz"],expected,out)
        facts=diagnose(out)
        assert facts["status"]=="PASS" and facts["new_target_entries"]==0
        status="PASS"
    except BaseException as exc:
        primary=dict(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        for path,row in input_before.items():
            try:
                after=file_fact(path)
                assert after==row,(path,"input or self bytes/mode changed")
                after_rows.append(dict(kind="input",before=row,after=after,status="PASS"))
            except BaseException as exc:
                after_errors.append(dict(kind="input",path=path,error_class=type(exc).__name__,
                                         error=str(exc),traceback=traceback.format_exc()))
        for path,row in tuple(MATERIALIZED.items()):
            try:
                after=file_fact(path)
                assert after==row,(path,"materialized original bytes/mode changed")
                if path==str(retained):retained_after=True
                after_rows.append(dict(kind="materialized",before=row,after=after,status="PASS"))
            except BaseException as exc:
                after_errors.append(dict(kind="materialized",path=path,error_class=type(exc).__name__,
                                         error=str(exc),traceback=traceback.format_exc()))
        pending=[]
        for path,wanted in PENDING.items():
            observation=dict(path=path,wanted=wanted,status="INCOMPLETE_MATERIALIZATION")
            try:
                if Path(path).exists():observation["actual_partial"]=file_fact(path)
                else:observation["actual_partial"]=None
            except BaseException as exc:
                observation["read_error"]=dict(error_class=type(exc).__name__,error=str(exc))
            pending.append(observation)
        if pending:after_errors.append(dict(kind="pending",records=pending))
        full_members_after=(inner.get("members")==MEMBERS and
            inner.get("original_bytes")==ORIGINAL_BYTES and
            len(SELECTED)==MEMBERS and not after_errors)
        if after_errors:status="FAIL"
        budget=measured(start,before,children)
        if not (0<=budget["aggregate_cpu_seconds"]<90 and 0<=budget["elapsed_ns"]<180_000_000_000):
            status="FAIL"
            after_errors.append(dict(kind="original-budget",**budget))
        report=dict(schema="hia-follow53-late-Core-complete-original-readback-r1",
            status=status,original_target_status="FAIL",source_head="8f27671ad748dc7c081a1eaad897b057d8d9f42e",
            run=43237029243,job=131248772749,artifact=13952974167,
            original_zip_bytes=ZIP_BYTES,original_zip_sha256=ZIP_SHA,
            full_zip_members=len(outer),inner=inner,facts=facts,
            primary_failure=primary,after_errors=after_errors,
            complete_original_ZIP_retained_and_after_verified=retained_after,
            all_756_original_members_retained_and_after_verified=full_members_after,
            original_inputs_and_self_unchanged=bool(input_before) and
                not any(e["kind"]=="input" for e in after_errors),
            materialized_count=len(MATERIALIZED),pending_count=len(PENDING),
            exact_reference_commit=REFERENCE_COMMIT,
            original_project_imports=0,new_target_entries=0,new_compiler_entries=0,
            original_runtime_budget=dict(cpu=90,wall=180,address=1<<30),
            budget=budget,old_target_failure_reclassified=False,whole_worker_closed=False)
        write_json(out/"input-and-materialized-aftercheck.json",after_rows)
        summary=out/"summary.json"
        raw=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode("utf-8")
        # New reader receipt only. Every retained original remains immutable.
        summary.write_bytes(raw);summary.chmod(0o644)
        compact=dict(status=status,original_target_status="FAIL",artifact=13952974167,
            summary_bytes=len(raw),summary_sha256=digest(raw),full_zip_members=len(outer),
            original_members=inner.get("members"),completed_original_public_cases=facts.get("completed_original_public_cases"),
            retained_zip_after_verified=retained_after,all_original_members_after_verified=full_members_after,
            new_target_entries=0,new_compiler_entries=0,
            primary_error=None if primary is None else primary["error_class"],
            after_error_count=len(after_errors),budget=budget)
        print("HIA_LATE_CORE53_READBACK "+json.dumps(compact,sort_keys=True),flush=True)
        final=measured(start,before,children)
        if not (0<=final["aggregate_cpu_seconds"]<90 and 0<=final["elapsed_ns"]<180_000_000_000):
            status="FAIL";report["status"]="FAIL"
            report["after_errors"].append(dict(kind="post-output-original-budget",**final))
            report["budget"]=final
            summary.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
            summary.chmod(0o644)
        else:
            write_json(out/"post-output-budget.json",dict(status="PASS",**final))
        # The caller also verifies its complete process receipt after exit/log readback.
        signal.setitimer(signal.ITIMER_REAL,0)
    return 0 if status=="PASS" else 1

if __name__=="__main__":
    raise SystemExit(main())
