"""Read only the complete FOLLOW51 seven-inline original impact artifact.

No project module, compiler, native image, executable or original test is run.
All ZIP and tar members are streamed and hashed; every named compressed CAS is
also decoded and checked. Small stdout exports preserve original byte values.
"""
from __future__ import annotations
import argparse,base64,binascii,hashlib,json,os,resource,shutil,stat,struct,sys,tarfile,time,traceback,zipfile,zlib
from pathlib import Path,PurePosixPath

ZIP_BYTES=99436852
ZIP_SHA="1b1509d6f1aba5ff1f10e907f4ae8c31cad3431ffc01131d16bcd89f77d6d920"
INNER_BYTES=40901028
INNER_SHA="b8a90321c1891fd2485dcd9c925346d4e74b81610174c35e825651446aea26ea"
INDEX_BYTES=1561783
INDEX_SHA="90ea9d889d21067076663d04e9e1141e3ead84e9e400932113d6cac53809a420"
MEMBERS=3538
ORIGINAL_BYTES=260366769
OUTER_MEMBERS=902
OUTER_PREFIX="hia-ordinary-impact-json-inline-r1-recovery/"
ROOT="ordinary-impact-json-inline/"
BASELINE="ordinary-inline-original-six-image-build/"
COMPILER="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
EVENT=int.from_bytes(b"HIACDE01","little");RESULT=int.from_bytes(b"HIAEDR01","little")
GROUPS=(("semantic",113),("errors",58),("interfaces",48),("input",67),("identity",3),("functions-1024",1),("large-bytes",1),("large-nodes",1),("large-valid",1),("impact-semantic",33),("graph-1024",1),("graph-dense",1),("graph-long-report",1))
FAILED={"large-valid","graph-long-report"}
NEW_BINDINGS={
    24:(111822,"e29178124be2960c2e2dc237013c74527a6187cf2fb427f6d764103b226ff454",139935,"537129ebc84d16c07f117bb320d6d6dd75484e240421d43600dc75ffdefc0db4"),
    26:(136140,"83e61a4ee02225dd27f51aed6f3e3b2a82b9f3ab1d1df340be3674c526098f9a",180107,"519a968429c7bfc2cb2ae38bc6ff9acf087cb9534fa04e3d368e312372522af9"),
    27:(427257,"4effe0b91323ea0c66c5ae96b411e4c8188a0be73350cddc10cce322fe2cb389",611173,"73617834b5c0d691409abb3be0d8b9699c3f25f265d9c1632937cd1234cd834d"),
    57:(292082,"9cca13699ec5f6b96a7046806dd7d54c115bccd52d37ef2789273d26daedaa53",394348,"4d1b6a24c623356e3b6b71324264e55fb968a9c53df61168822ccaa259ab8c2f"),
    59:(252995,"59932d1c0fb853ba59033b6a0ff095ff2e0eab47fd707d1cfcdc4c842f664378",352131,"65a5739efcebc00dffbcf41299937b83160112ecbb625a5b3ec86bfd4c923dc0"),
    60:(295382,"2c947364a0496e013d18d95563d78349e1997b57f6577800701e267f58d6c754",401344,"7518feed6d225297fc0b4e308d12cd7e6b24ff20423c31e893994533f948bdf5"),
    63:(176892,"b72a2ca735372dfd954033608de93b2f00a3dbc5131a993e277eea863d534497",242864,"4911dec02f624b7eee7c216857de22b074e9c5cc59c9b5e6efe8ffca9854e00c"),
}
ORIGINAL_PATHS={}
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
    print("HIA_IMPACT51_ORIGINAL "+json.dumps(dict(row,base64=base64.b64encode(raw).decode("ascii")),sort_keys=True),flush=True)
    return row

def selected(name):
    # Retain every inner member, including exact executable/source bytes.
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
            part=name[len(OUTER_PREFIX):] if name.startswith(OUTER_PREFIX) else None
            target=out/"outer"/name if part in ("custody.json","evidence-members.json","evidence.tar.xz") else None
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
                assert part not in captured
                captured[part]=target
    write_json(out/"outer-members.json",outer)
    assert len(outer)==OUTER_MEMBERS
    assert set(captured)=={"custody.json","evidence-members.json","evidence.tar.xz"}
    assert stream_hash(captured["evidence.tar.xz"])==(INNER_BYTES,INNER_SHA)
    assert stream_hash(captured["evidence-members.json"])==(INDEX_BYTES,INDEX_SHA)
    custody=json_bytes(captured["custody.json"].read_bytes())
    assert custody["schema"]=="hia-independent-ci-artifact-custody-v1"
    assert custody["scope"]=="ordinary-impact-json-inline-r1"
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
        assert isinstance(row["path"],str) and row["path"].startswith("/")
        ORIGINAL_PATHS.setdefault(row["path"],[]).append(name)
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

def diagnose(out):
    def original(name,export=False):
        assert name in SELECTED,name
        value=Path(SELECTED[name]).read_bytes()
        if export:original_export(name,value)
        return value
    def parsed(name,export=False):
        return json_bytes(original(name,export))
    def by_original_path(path,size,sha):
        names=ORIGINAL_PATHS.get(path,[])
        assert names,("missing exact archived original path",path)
        found=[]
        for name in names:
            value=original(name)
            assert (len(value),digest(value))==(size,sha),(name,"path-bound full bytes")
            found.append(name)
        return found
    def component(row):
        for kind in ("source","image"):
            by_original_path(row[kind+"_path"],row[kind+"_bytes"],row[kind+"_sha256"])
        receipt=row["receipt"]
        assert receipt["status"]=="returned" and receipt["abi_status"]==0
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==COMPILER
        assert receipt["input_bytes"]==row["source_bytes"]
        assert receipt["input_sha256"]==receipt["source_sha256"]==row["source_sha256"]
        assert receipt["produced_bytes"]==row["image_bytes"] and receipt["produced_sha256"]==row["image_sha256"]
        limits=receipt["limits"]
        assert limits["cpu_seconds"]==10 and limits["address_bytes"]==268435456
        assert limits["output_capacity"]==limits["workspace_bytes"]==1048576
        assert receipt["wall_elapsed_ns"]<20000000000 and receipt["source_unchanged"]
        profile=row["profile"]
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["operations"]<=8192
        assert profile["max_function_blocks"]<=256 and profile["max_block_parameters"]<=16
        assert profile["max_ssa_numeric_suffix"]<2048
    old=parsed(BASELINE+"development/build-r1/manifest.json",True)
    manifest=parsed(ROOT+"development/build-r1/manifest.json",True)
    old_report=parsed(BASELINE+"development/build-r1/summary.json",True)
    report=parsed(ROOT+"development/build-r1/summary.json",True)
    assert old_report["status"]==report["status"]=="PASS"
    assert old_report["actual_native_compiles"]==6 and old_report["actual_packer_entries"]==1
    assert report["actual_optimization_B3"]==7 and report["actual_optimization_packer_entries"]==1
    assert old["new_compiles"]==6 and manifest["new_compiles"]==13
    assert manifest["baseline_new_compiles"]==6 and manifest["optimization_new_compiles"]==7
    assert manifest["actual_native_packer_entries"]==2
    assert manifest["baseline_packer_entries"]==manifest["optimization_packer_entries"]==1
    assert manifest["changed_roles"]==sorted(NEW_BINDINGS) and manifest["unchanged_roles"]==56
    assert manifest["original_all_63_source_and_image_pins_reproduced"] and manifest["actual_original_ELF_reproduced"]
    assert len(manifest["compiled"])==13 and len(old["compiled"])==6
    assert manifest["compiled"][:6]==old["compiled"]
    assert set(manifest["role_bindings"])==set(old["role_bindings"])=={str(i) for i in range(1,64)}
    for key,row in manifest["role_bindings"].items():
        for kind in ("source","image"):
            by_original_path(row[kind+"_path"],row[kind+"_bytes"],row[kind+"_sha256"])
        role=int(key);identity=tuple(row[k] for k in ("source_bytes","source_sha256","image_bytes","image_sha256"))
        if role in NEW_BINDINGS:assert identity==NEW_BINDINGS[role],("changed role",role)
        else:assert identity==tuple(old["role_bindings"][key][k] for k in ("source_bytes","source_sha256","image_bytes","image_sha256")),("unchanged role",role)
    for row in manifest["compiled"]:component(row)
    by_original_path(old["executable_path"],old["executable_bytes"],old["executable_sha256"])
    by_original_path(manifest["executable_path"],manifest["executable_bytes"],manifest["executable_sha256"])
    assert manifest["original_executable_sha256"]==old["executable_sha256"]
    all_groups=[];completed=0;processes=0;failed=0
    for group,case_count in GROUPS:
        prefix=ROOT+"development/native-"+group+"/"
        summary=parsed(prefix+"summary.json",True)
        plan=parsed(prefix+"planned-inventory.json")
        assert summary["group"]==plan["group"]==group and plan["cases"]==case_count
        assert len(plan["labels"])==case_count and summary["planned"]==plan["labels"]
        assert summary["actual_native_processes"]==summary["reference_full_impact_calls"]==case_count
        assert summary["source_and_image_before_after_equal"] and summary["complete_process_streams_preserved"] and summary["complete_CAS_verified"]
        assert summary["original_limits"]==dict(cpu_seconds=90,wall_seconds=180,address_space_bytes=1073741824)
        assert summary["old_counts_inherited"] is False and summary["whole_stack_closed"] is False
        is_failure=group in FAILED
        assert summary["status"]==("FAIL" if is_failure else "PASS")
        assert summary["completed_cases"]==(0 if is_failure else case_count)
        if is_failure:
            assert summary["error_class"]=="AssertionError" and "original aggregate CPU bound" in summary["error"]
            assert summary["parent_plus_children_cpu_seconds"]>90
            failed+=1
        else:
            assert summary["cases"]==case_count and summary["parent_plus_children_cpu_seconds"]<=90
            assert summary["elapsed_ns"]<180000000000 and summary["complete_result_and_error_bytes_equal"]
        records=[]
        for index,label in enumerate(plan["labels"],1):
            pending=parsed(prefix+"pending-%04d.json"%index,is_failure)
            process=parsed(prefix+"process-%04d.json"%index,is_failure)
            assert pending["label"]==process["label"]==label
            assert process["stdin"]==pending["input"]
            assert process["executable_sha256"]==manifest["executable_sha256"]
            stdin=resolve_cas(prefix,pending["input"])
            program=resolve_cas(prefix,pending["program"]);request=resolve_cas(prefix,pending["request"])
            stdout=resolve_cas(prefix,process["stdout"]);stderr=resolve_cas(prefix,process["stderr"])
            header=struct.unpack_from("<8Q",stdin)
            assert header==(int.from_bytes(b"HIAEJN01","little"),1001+index*8,1,pending["digits"],len(program),len(request),0,0)
            assert stdin[64:]==program+request
            assert type(process["elapsed_ns"]) is int and process["elapsed_ns"]>=0
            before=process["group_cpu_before"];after=process["group_cpu_after"]
            assert isinstance(before,(float,int)) and isinstance(after,(float,int)) and 0<=before<=after
            expected=pending["expected"];outputs={}
            for key,value in expected.items():
                if isinstance(value,dict):outputs[key]=resolve_cas(prefix,value)
            event=None;equal=False;error=None
            try:
                assert not process["timed_out"],"original target timed out"
                assert len(stderr)>=128,"incomplete terminal frame"
                event=struct.unpack_from("<16Q",stderr)
                assert event[:3]==(EVENT,7,header[1]) and event[3]>0
                assert event[6]==30 and event[7]==0 and event[8]>0 and event[9]==1 and not any(event[11:])
                if expected["kind"]=="error":
                    assert process["returncode"]==2 and not stdout
                    assert event[8]==len(stderr)-128 and event[5]!=0
                    assert (event[4]==2 if expected["domain"] in ("program","impact") else event[4] in (1,3))
                    if expected["domain"]=="impact":assert event[10]==60
                    assert stderr[128:]==outputs["payload"],"complete error payload differs"
                else:
                    assert expected["kind"]=="result" and process["returncode"]==0
                    assert len(stderr)==128 and event[4]==event[5]==event[10]==0
                    assert event[8]==len(stdout)
                    wanted=struct.pack("<8Q",RESULT,1,*[len(outputs[k]) for k in ("candidate","receipt","impact")],0,0,0)
                    wanted+=b"".join(outputs[k] for k in ("candidate","receipt","impact"))
                    assert stdout==wanted,"complete candidate receipt or impact bytes differ"
                equal=True
            except BaseException as exc:
                error=dict(type=type(exc).__name__,error=str(exc))
            finished_name=prefix+"completed-%04d.json"%index
            if is_failure:assert finished_name not in SELECTED
            else:
                assert equal,(group,index,"original completed case no longer equals recorded oracle",error)
                finished=parsed(finished_name)
                assert finished["status"]=="PASS" and finished["label"]==label
                assert finished["terminal_event"]==[str(x) for x in event]
                assert finished["elapsed_ns"]==process["elapsed_ns"]
                completed+=1
            processes+=1
            records.append(dict(label=label,original_completed=not is_failure,
                recorded_returncode=process["returncode"],recorded_timed_out=process["timed_out"],
                recorded_native_interval_ns=str(process["elapsed_ns"]),
                recorded_group_CPU_before=before,recorded_group_CPU_after=after,
                recorded_interval_parent_plus_reaped_child_CPU=after-before,
                stdin_bytes=len(stdin),stdout_bytes=len(stdout),stderr_bytes=len(stderr),
                expected_output_bytes={k:len(v) for k,v in outputs.items()},
                recorded_terminal=None if event is None else [str(x) for x in event],
                recorded_bytes_equal=equal,recorded_comparison_error=error,
                independent_new_native_executions=0,original_qualification_status_unchanged=True))
        all_groups.append(dict(group=group,original_status=summary["status"],
            original_completed_cases=summary["completed_cases"],
            original_group_CPU=summary["parent_plus_children_cpu_seconds"],
            original_group_elapsed_ns=str(summary["elapsed_ns"]),processes=records))
    assert len(all_groups)==13 and completed==327 and processes==329 and failed==2
    result=dict(schema="hia-impact51-complete-recorded-stream-comparison-v1",
        old_target_status="FAIL",original_completed_cases=completed,recorded_ELF_processes=processes,
        original_passed_groups=11,original_failed_groups=2,
        complete_actual_role_source_image_bytes=63,unchanged_from_actual_baseline_roles=56,
        original_compile_receipts_checked=13,original_packer_entries_reported=2,
        original_full_output_and_error_cases_recompared=327,
        original_failed_groups_not_requalified=True,groups=all_groups,
        timing_scope="Original recorded interval covers the original subprocess interval; no per-component timings or internal HIA entry counts are inferred.",
        new_B3=0,new_VM=0,new_native=0,project_imports=0,whole_stack_closed=False)
    write_json(out/"recorded-stream-comparison.json",result)
    original_export("recorded-stream-comparison.json",(out/"recorded-stream-comparison.json").read_bytes())
    return dict(original_completed_cases=completed,recorded_ELF_processes=processes,
        original_passed_groups=11,original_failed_groups=2,
        complete_actual_role_source_image_bytes=63,original_compile_receipts_checked=13,
        original_full_output_and_error_cases_recompared=327,
        failed_group_original_processes=[r for g in all_groups if g["group"] in FAILED for r in g["processes"]],
        new_native_entries=0,original_failure_unchanged=True)

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
        report=dict(schema="hia-follow51-seven-inline-original-readback-r1",
            status=status,head="969bebebdd71f5bf185dd5e22ef990cfc0a6bc0b",
            run_id=43225855642,job_id=131208740363,artifact_id=13948294840,
            exact_original_ZIP=dict(bytes=ZIP_BYTES,sha256=ZIP_SHA),
            complete_original_ZIP_retained_and_afterchecked=retained_complete,
            original_target_status="FAIL",primary_error=primary,after_errors=after_errors,
            pending_partial_files=partial,inputs_before=inputs,facts=facts,
            all_materialized_afterchecked=len(materialized),original_exports=EXPORTED,
            aggregate_CPU_seconds=aggregate,elapsed_ns=elapsed,
            original_limits=dict(CPU=90,wall=180,AS=1024**3),
            actual_native_entries=0,project_imports=0,target_reruns=0,new_B3=0,
            native_failure_not_changed_by_readback=True,whole_stack_closed=False)
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
        compact=dict(schema=report["schema"],status=status,artifact_id=13948294840,
            original_target_status="FAIL",primary_error=primary,after_errors=after_errors,
            complete_original_ZIP_retained_and_afterchecked=retained_complete,
            outer=facts.get("outer"),inner=facts.get("inner"),frontier=facts.get("frontier"),
            final_aggregate_CPU_seconds=final_cpu,final_elapsed_ns=final_elapsed,
            summary=MATERIALIZED.get(str((out/"summary.json").resolve())),
            target_reruns=0,whole_stack_closed=False)
        print("HIA_IMPACT51_READBACK "+json.dumps(compact,sort_keys=True),flush=True)
        post_stdout_cpu=cpu()-start_cpu;post_stdout_wall=time.monotonic_ns()-started
        post=dict(status="PASS" if status=="PASS" and post_stdout_cpu<90 and post_stdout_wall<180000000000 else "FAIL",
                  CPU_seconds=post_stdout_cpu,elapsed_ns=str(post_stdout_wall),
                  includes_final_summary_index_and_stdout_flush=True,target_executions=0)
        write_json(out/"post-stdout-budget.json",post)
        assert file_fact(out/"post-stdout-budget.json")==MATERIALIZED[str((out/"post-stdout-budget.json").resolve())]
        if post["status"]!="PASS" or cpu()-start_cpu>=90 or time.monotonic_ns()-started>=180000000000:status="FAIL"
    return 0 if status=="PASS" else 1

if __name__=="__main__":raise SystemExit(main())
