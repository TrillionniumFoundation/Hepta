"""Read only the complete FOLLOW50 whole type-context original artifact.

No project module, compiler, native image, executable or original test is run.
All ZIP and tar members are streamed and hashed; every named compressed CAS is
also decoded and checked. Small stdout exports preserve original byte values.
"""
from __future__ import annotations
import argparse,base64,binascii,hashlib,json,os,resource,shutil,stat,struct,sys,tarfile,time,traceback,zipfile,zlib
from pathlib import Path,PurePosixPath

ZIP_BYTES=98664861
ZIP_SHA="21f6294bfd90c441eb166ed963773256bb309e2b78e08755df88b7a197520233"
INNER_BYTES=27313896
INNER_SHA="7b751119394b9813d73d6d8b3cc1b2ff44dfbf645d4d134a39c4087448d29665"
INDEX_BYTES=1543788
INDEX_SHA="d76ab56cd177786e55858f2f2eef6efae19c8ca74a876e4191a117961ef52f5d"
MEMBERS=3554
ORIGINAL_BYTES=189178620
STDERR_SHA="a888546bbab0a05858ff048c77cbe8878d88a8ac9ddfc204c5a1bcbdce97f075"
ROOT="worker-type-context-join/"
PUBLIC=ROOT+"development/actual-public-context-r1/"
PRIVATE=ROOT+"development/actual-context-protocol-r1/"
LABELS=("nominal-type-name","nominal-type-inventory","field-name","type-parameter-name")
HEX=set("0123456789abcdef")
MATERIALIZED={}
PENDING={}
SELECTED={}
EXPORTED=[]
CHUNK=1024*1024

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
    print("HIA_TYPEJOIN50_ORIGINAL "+json.dumps(dict(row,base64=base64.b64encode(raw).decode("ascii")),sort_keys=True),flush=True)
    return row

def selected(name):
    if name.startswith(PUBLIC) or name.startswith(PRIVATE):return True
    if name=="run/summary.json":return True
    if name.startswith(ROOT+"development/build-r1/"):
        return name.endswith((".S","/bundle.json","/source-pins.json","/summary.json",
                              "/diagnostic-mask-proof.json","/worker-context-adaptation.json",
                              "/type-context-lowering-proof.json","/type-context-program-proof.json"))
    return name.startswith(ROOT+"tools/") and name.endswith(".py")

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
            target=out/"outer"/name if name in ("custody.json","evidence-members.json","evidence.tar.xz") else None
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
                captured[name]=target
    assert set(captured)=={"custody.json","evidence-members.json","evidence.tar.xz"}
    assert stream_hash(captured["evidence.tar.xz"])==(INNER_BYTES,INNER_SHA)
    assert stream_hash(captured["evidence-members.json"])==(INDEX_BYTES,INDEX_SHA)
    custody=json_bytes(captured["custody.json"].read_bytes())
    assert custody["schema"]=="hia-independent-ci-artifact-custody-v1"
    assert custody["scope"]=="worker-program-actual-native-type-context-r1"
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
    write_json(out/"outer-members.json",outer)
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

def diagnose(out):
    observed=[]
    for suffix in LABELS:
        label="public-context-"+suffix
        name=PUBLIC+"cases/"+label+"/stderr.bin"
        assert name in SELECTED,name
        raw=Path(SELECTED[name]).read_bytes()
        assert (len(raw),digest(raw))==(32,STDERR_SHA),(name,len(raw),digest(raw))
        assert raw[:8]==b"HIAXER01"
        code,role,sequence=struct.unpack("<3Q",raw[8:])
        assert code==3,(name,code)
        observed.append(dict(label=label,original_member=name,
            error_class="ACTUAL_FIXED_EXECUTOR_ABI_REFUSAL",
            code=code,role=role,sequence=sequence,sha256=digest(raw)))
        original_export(name,raw)
    entries=[]
    for serial in (1,2):
        name=PRIVATE+"entries/"+str(serial).zfill(6)+".json"
        assert name in SELECTED,name
        raw=Path(SELECTED[name]).read_bytes();row=json_bytes(raw)
        assert row["entry"]==serial and row["role"]==56
        source=resolve_cas(PRIVATE,row["source"])
        output=resolve_cas(PRIVATE,row["output_after"])
        work=resolve_cas(PRIVATE,row["workspace"])
        after=resolve_cas(PRIVATE,row["workspace_after"])
        source_after=resolve_cas(PRIVATE,row["source_after"])
        before_output=resolve_cas(PRIVATE,row["output"])
        assert source==source_after and len(output)==row["output_extent"]==128
        assert len(work)==len(after)==row["workspace_extent"]
        assert len(before_output)==128
        assert row["returned"]==128 and row["complete_input_and_canaries_unchanged"] is True
        words=struct.unpack("<16Q",output)
        assert output[:8]==b"HIACDE01"
        # Numeric projection is for mechanical action analysis only.
        entries.append(dict(entry=serial,label=row["label"],image_sha256=row["image_sha256"],
            source_bytes=len(source),source_sha256=digest(source),
            event_sha256=digest(output),event_words_decimal=[str(x) for x in words],
            complete_before_after_workspaces_verified=True,
            classification="PRIVATE_UNISSUED_CHILD_FIXTURE"))
        original_export(name,raw)
        original_export(PRIVATE+"observed-entry-"+str(serial)+"-event.bin",output)
    assembly_name=ROOT+"development/build-r1/carrier/worker_program_executor.S"
    assert assembly_name in SELECTED,assembly_name
    assembly=Path(SELECTED[assembly_name]).read_bytes()
    pins_name=ROOT+"development/build-r1/source-pins.json"
    assert pins_name in SELECTED,pins_name
    pins=json_bytes(Path(SELECTED[pins_name]).read_bytes())
    matching=[row for row in pins if row["path"].endswith("/development/build-r1/carrier/worker_program_executor.S")]
    assert len(matching)==1,matching
    binding=matching[0]
    assert (len(assembly),digest(assembly),git_blob(assembly))==(binding["bytes"],binding["sha256"],binding["gitsha"])
    split="/development/build-r1/"
    assert binding["frozen"].count(split)==1,binding["frozen"]
    frozen_name=ROOT+"development/build-r1/"+binding["frozen"].split(split,1)[1]
    safe_name(frozen_name)
    assert frozen_name in SELECTED and Path(SELECTED[frozen_name]).read_bytes()==assembly
    assert stat.S_IMODE(Path(SELECTED[assembly_name]).stat().st_mode)==binding["mode"]
    assert stat.S_IMODE(Path(SELECTED[frozen_name]).stat().st_mode)==binding["mode"]
    original_export(assembly_name,assembly)
    write_json(out/"actual-error-and-private-frontier.json",dict(
        public_original_stderr=observed,private_original_entries=entries,
        actual_fixed_executor=dict(name=assembly_name,bytes=len(assembly),sha256=digest(assembly)),
        source_of_all_bytes="EXACT_FIXED_ORIGINAL_ARTIFACT_NOT_RECONSTRUCTION",
        private_fixture_not_public_issuer=True,production_root_cause_not_asserted_from_header_alone=True))
    return dict(public_stderr=observed,private_entries=entries)

def cpu():
    own=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime+own.ru_stime+children.ru_utime+children.ru_stime

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--zip",required=True)
    parser.add_argument("--out",required=True);args=parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    started=time.monotonic_ns();start_cpu=cpu()
    original=Path(args.zip).resolve();out=Path(args.out).resolve()
    out.mkdir(parents=True,exist_ok=False)
    inputs={};primary=None;after_errors=[];facts={};status="FAIL"
    retained=out/"retained-original.zip";retained_complete=False
    try:
        for p in (Path(__file__).resolve(),original):inputs[str(p)]=file_fact(p)
        assert (inputs[str(original)]["bytes"],inputs[str(original)]["sha256"])==(ZIP_BYTES,ZIP_SHA)
        PENDING[str(retained)]=dict(path=str(retained),bytes=ZIP_BYTES,sha256=ZIP_SHA,mode=0o644,
                                   classification="ORIGINAL_ZIP_COPY_PENDING")
        shutil.copyfile(original,retained);retained.chmod(0o644)
        register(retained,ZIP_BYTES,ZIP_SHA,0o644)
        captured,expected,outer=scan_zip(retained,out)
        facts["outer"]=dict(members=len(outer),bytes=sum(r["bytes"] for r in outer))
        facts["inner"]=scan_inner(captured["evidence.tar.xz"],expected,out)
        facts["frontier"]=diagnose(out)
        write_json(out/"selected-originals.json",[
            dict(name=name,**MATERIALIZED[path]) for name,path in sorted(SELECTED.items())])
        status="PASS"
    except BaseException as exc:
        primary=dict(type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        for key,before in inputs.items():
            try:
                after=file_fact(key)
                assert after==before,(key,"input changed",before,after)
            except BaseException as exc:
                after_errors.append(dict(path=key,scope="INPUT_OR_SELF",
                    type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
        # All completed and partial copies are inspected even after first error.
        for key,before in list(MATERIALIZED.items()):
            try:
                after=file_fact(key);assert after==before,(key,"materialized bytes/mode changed")
                if key==str(retained):retained_complete=True
            except BaseException as exc:
                after_errors.append(dict(path=key,scope="MATERIALIZED",
                    type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc()))
        partial=[]
        for key,wanted in PENDING.items():
            item=dict(wanted)
            try:item["actual_partial"]=file_fact(key) if Path(key).exists() else None
            except BaseException as exc:item["inspection_error"]=dict(type=type(exc).__name__,error=str(exc))
            partial.append(item)
        aggregate=cpu()-start_cpu;elapsed=time.monotonic_ns()-started
        if aggregate>=90:after_errors.append(dict(scope="CPU",actual=aggregate,limit=90))
        if elapsed>=180_000_000_000:after_errors.append(dict(scope="WALL",actual_ns=elapsed,limit_ns=180_000_000_000))
        if primary or after_errors or partial:status="FAIL"
        # These small final indexes describe failures without masking the first.
        materialized=list(MATERIALIZED.values())
        report=dict(schema="hia-follow50-whole-type-context-original-readback-r3",
            status=status,head="49e5cd97f11b3fb35d8a390e7ad4ed0c5b2fe030",
            run_id=43220473879,job_id=131190423991,artifact_id=13945268820,
            exact_original_ZIP=dict(bytes=ZIP_BYTES,sha256=ZIP_SHA),
            complete_original_ZIP_retained_and_afterchecked=retained_complete,
            original_target_status="FAIL",primary_error=primary,after_errors=after_errors,
            pending_partial_files=partial,inputs_before=inputs,facts=facts,
            all_materialized_afterchecked=len(materialized),original_exports=EXPORTED,
            aggregate_CPU_seconds=aggregate,elapsed_ns=elapsed,
            original_limits=dict(CPU=90,wall=180,AS=1024**3),
            actual_native_entries=0,project_imports=0,target_reruns=0,new_B3=0,
            native_failure_not_changed_by_readback=True,whole_Worker_closed=False)
        # Do not print large inventories; preserve them as complete files.
        write_json(out/"materialized-aftercheck.json",materialized)
        write_json(out/"summary.json",report)
        for p in (out/"materialized-aftercheck.json",out/"summary.json"):
            row=MATERIALIZED[str(p.resolve())];assert file_fact(p)==row
        final_cpu=cpu()-start_cpu;final_elapsed=time.monotonic_ns()-started
        if final_cpu>=90 or final_elapsed>=180_000_000_000:
            status="FAIL"
            write_json(out/"final-budget-failure.json",dict(status="FAIL",CPU=final_cpu,elapsed_ns=final_elapsed,
                       original_summary_status=report["status"],limit_CPU=90,limit_wall_ns=180_000_000_000))
        compact=dict(schema=report["schema"],status=status,artifact_id=13945268820,
            original_target_status="FAIL",primary_error=primary,after_errors=after_errors,
            complete_original_ZIP_retained_and_afterchecked=retained_complete,
            outer=facts.get("outer"),inner=facts.get("inner"),frontier=facts.get("frontier"),
            final_aggregate_CPU_seconds=final_cpu,final_elapsed_ns=final_elapsed,
            summary=MATERIALIZED.get(str((out/"summary.json").resolve())),
            target_reruns=0,whole_Worker_closed=False)
        print("HIA_TYPEJOIN50_READBACK "+json.dumps(compact,sort_keys=True),flush=True)
    return 0 if status=="PASS" else 1

if __name__=="__main__":raise SystemExit(main())
