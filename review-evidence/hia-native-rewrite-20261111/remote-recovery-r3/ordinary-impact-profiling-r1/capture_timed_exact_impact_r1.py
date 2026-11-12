"""Capture exact original impact inputs with a timing-only mechanical carrier.

All original HIA images are retained. This is a bounded diagnostic, never a
replacement qualification. Complete raw streams and trace bytes are preserved.
"""
from __future__ import annotations
import argparse,errno,hashlib,json,os,resource,signal,stat,struct,subprocess,sys,time,traceback,zlib
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
p.add_argument("--original-readback",type=Path,required=True)
p.add_argument("--build",type=Path,required=True)
p.add_argument("--out",type=Path,required=True)
a=p.parse_args()
ROOT=a.original_readback.resolve();BUILD=a.build.resolve();OUT=a.out.resolve()
assert OUT!=ROOT and OUT!=BUILD and not OUT.is_relative_to(ROOT) and not OUT.is_relative_to(BUILD)
OUT.mkdir(parents=True,exist_ok=False)
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
START=time.monotonic_ns();PINS={};records=[];attempts=0;status="FAIL";details={}
TRACE_FD=198
def digest(raw):return hashlib.sha256(raw).hexdigest()
def save(name,value):
    path=OUT/name;path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def identity(path):
    path=Path(path)
    st=path.lstat()
    assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not path.is_symlink(),str(path)
    with path.open("rb") as f:value=hashlib.file_digest(f,"sha256").hexdigest()
    after=path.lstat()
    assert (st.st_dev,st.st_ino,st.st_size,st.st_mode,st.st_mtime_ns,st.st_ctime_ns)==(
        after.st_dev,after.st_ino,after.st_size,after.st_mode,after.st_mtime_ns,after.st_ctime_ns)
    return dict(path=str(path.resolve()),bytes=st.st_size,sha256=value,mode=stat.S_IMODE(st.st_mode))
def pin(path):
    path=Path(path).resolve();row=identity(path)
    if path in PINS:assert row==PINS[path],str(path)
    PINS[path]=row
    raw=path.read_bytes()
    assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
    return raw
def unchanged():
    errors=[]
    for path,wanted in PINS.items():
        try:assert identity(path)==wanted,str(path)
        except BaseException as exc:errors.append(dict(path=str(path),error=repr(exc)))
    return errors
def cpu():
    own=resource.getrusage(resource.RUSAGE_SELF)
    child=resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime+own.ru_stime+child.ru_utime+child.ru_stime
def exact_file(path,expected):
    at=0
    with Path(path).open("rb") as stream:
        while True:
            raw=stream.read(1<<20)
            if not raw:break
            if raw!=expected[at:at+len(raw)]:return False
            at+=len(raw)
    return at==len(expected)
def original(name):
    row=by_name[name];path=ROOT/"archive-originals"/name
    assert path.resolve().is_relative_to((ROOT/"archive-originals").resolve())
    raw=pin(path)
    assert (len(raw),digest(raw),stat.S_IMODE(path.stat().st_mode))==(row["bytes"],row["sha256"],row["mode"]),name
    return raw
def case(group):
    stem="ordinary-impact-coordinator/development/native-"+group+"/"
    pending_raw=original(stem+"pending-0001.json")
    process_raw=original(stem+"process-0001.json")
    summary_raw=original(stem+"summary.json")
    pending=json.loads(pending_raw);process=json.loads(process_raw);summary=json.loads(summary_raw)
    def restore(row):
        relative=PurePosixPath(row["path"])
        assert not relative.is_absolute() and ".." not in relative.parts and row["compression"]=="zlib"
        encoded=original(stem+relative.as_posix())
        dec=zlib.decompressobj();raw=dec.decompress(encoded,64<<20)
        assert dec.eof and not dec.unused_data and not dec.unconsumed_tail
        assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
        return raw
    stdin=restore(pending["input"])
    assert process["stdin"]==pending["input"]
    stdout=restore(process["stdout"]);stderr=restore(process["stderr"])
    assert process["executable_sha256"]==build["original_elf"]["sha256"]
    if group=="semantic":
        completed_raw=original(stem+"completed-0001.json")
        completed=json.loads(completed_raw)
        assert summary["status"]=="PASS" and summary["completed_cases"]==113
        assert completed["status"]=="PASS" and completed["label"]==pending["label"]==process["label"]
        assert process["returncode"] in (0,2) and process["timed_out"] is False
    else:
        completed_raw=None
        assert group=="large-valid" and summary["status"]=="FAIL"
        assert process["returncode"]==-9 and process["timed_out"] is False
        assert stdout==stderr==b"" and pending["expected"]["kind"]=="result"
    directory=OUT/("original-"+group);directory.mkdir()
    for name,raw in (("pending.original.json",pending_raw),("process.original.json",process_raw),
                     ("summary.original.json",summary_raw),("stdin.bin",stdin),("stdout.bin",stdout),("stderr.bin",stderr)):
        (directory/name).write_bytes(raw)
    if completed_raw is not None:(directory/"completed.original.json").write_bytes(completed_raw)
    wanted=None
    if group=="large-valid":
        components=[restore(pending["expected"][k]) for k in ("candidate","receipt","impact")]
        wanted=struct.pack("<8Q",int.from_bytes(b"HIAEDR01","little"),1,*map(len,components),0,0,0)+b"".join(components)
        assert len(stdin)==8370475 and digest(stdin)=="8672352b719ab283e2efd48e0f0c753c194cda9fce5cb990660106875e285f05"
        assert len(wanted)==8371538 and digest(wanted)=="9e3c7056f89a954cefff8affe8430a3f1988579d8bb74b9579bf4a17101ee2b9"
        (directory/"complete-original-expected-output.bin").write_bytes(wanted)
    return dict(group=group,label=pending["label"],stdin=stdin,stdout=stdout,stderr=stderr,
                process=process,wanted=wanted,directory=directory)
def run(label,elf,data,calibration):
    global attempts
    directory=OUT/label;directory.mkdir()
    binary_before=identity(elf)
    assert binary_before["sha256"] in (build["original_elf"]["sha256"],build["timed_elf"]["sha256"])
    raw=data["stdin"];input_path=directory/"stdin.bin";input_path.write_bytes(raw)
    # Reserve four CPU seconds for parent hashing, full equality and custody.
    # A diagnostic may be stricter than the unchanged original 90-second gate.
    before_cpu=cpu();remaining=90-before_cpu-4
    child_budget=int(min(12,remaining) if calibration else remaining)
    assert child_budget>=1,(label,before_cpu)
    wall_remaining=180-(time.monotonic_ns()-START)/1e9-3
    assert wall_remaining>0
    record=dict(label=label,status="PENDING_ACTUAL_CHILD",calibration=calibration,
        actual_HIA_images_changed=0,semantic_qualification=False,
        executable=binary_before,input=dict(bytes=len(raw),sha256=digest(raw)),
        child_CPU_limit_seconds=child_budget,whole_group_CPU_limit_seconds=90,
        reserved_parent_CPU_seconds=4,child_wall_timeout_seconds=wall_remaining,
        trace_fd=TRACE_FD,trace_record_bytes=128,group_CPU_before=before_cpu)
    save(label+"/process.json",record)
    try:os.fstat(TRACE_FD)
    except OSError as exc:assert exc.errno==errno.EBADF
    else:raise AssertionError("dedicated timing FD already in use")
    child=None;fd_installed=False;timed_out=False;cleanup_errors=[];primary_error=None
    child_before=resource.getrusage(resource.RUSAGE_CHILDREN)
    start=time.monotonic_ns()
    def child_limits():
        resource.setrlimit(resource.RLIMIT_CPU,(child_budget,child_budget))
        resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def close_owned_trace():
        nonlocal fd_installed
        if fd_installed:
            # Consume ownership before close; never retry an ambiguous close
            # and accidentally close a subsequently reused descriptor.
            fd_installed=False
            try:os.close(TRACE_FD)
            except BaseException as exc:cleanup_errors.append(dict(operation="close-trace",error=repr(exc)))
    try:
        # Reserve 198 before opening the four streams, so none can acquire it.
        reserved=os.open("/dev/null",os.O_RDONLY|os.O_CLOEXEC)
        if reserved==TRACE_FD:
            fd_installed=True
            os.set_inheritable(TRACE_FD,False)
        else:
            try:
                os.dup2(reserved,TRACE_FD,inheritable=False);fd_installed=True
            finally:os.close(reserved)
        with input_path.open("rb") as inp,(directory/"stdout.bin").open("xb") as out,(directory/"stderr.bin").open("xb") as err,(directory/"timing.raw").open("xb") as trace:
            assert all(stream.fileno()!=TRACE_FD for stream in (inp,out,err,trace))
            os.dup2(trace.fileno(),TRACE_FD,inheritable=True)
            child=subprocess.Popen([str(elf)],stdin=inp,stdout=out,stderr=err,
                close_fds=True,pass_fds=(TRACE_FD,),preexec_fn=child_limits,
                env=dict(PATH="/usr/bin:/bin",LANG="C.UTF-8",LC_ALL="C.UTF-8"))
            attempts+=1
            close_owned_trace()
            try:child.wait(timeout=wall_remaining)
            except subprocess.TimeoutExpired:
                timed_out=True;child.kill();child.wait()
    except BaseException as exc:
        primary_error=exc
        raise
    finally:
        close_owned_trace()
        if child is not None:
            try:
                if child.poll() is None:
                    try:child.kill()
                    except ProcessLookupError:pass
            except BaseException as exc:cleanup_errors.append(dict(operation="kill-child",error=repr(exc)))
            finally:
                try:child.wait()
                except BaseException as exc:cleanup_errors.append(dict(operation="reap-child",error=repr(exc)))
        if cleanup_errors:
            try:save(label+"/cleanup-errors.json",cleanup_errors)
            except BaseException as report_error:
                cleanup_errors.append(dict(operation="preserve-cleanup-observations",error=repr(report_error)))
                if primary_error is None:raise AssertionError(("diagnostic cleanup evidence failed",cleanup_errors)) from report_error
            if primary_error is not None:primary_error.add_note("Cleanup observations: "+repr(cleanup_errors))
            else:raise AssertionError(("diagnostic cleanup failed",cleanup_errors))
    elapsed=time.monotonic_ns()-start
    child_after=resource.getrusage(resource.RUSAGE_CHILDREN)
    streams={name:identity(directory/filename) for name,filename in
        (("stdin","stdin.bin"),("stdout","stdout.bin"),("stderr","stderr.bin"),("trace","timing.raw"))}
    assert streams["stdin"]["bytes"]==len(raw) and streams["stdin"]["sha256"]==digest(raw)
    assert identity(elf)==binary_before
    if calibration:
        equal=(child.returncode==data["process"]["returncode"] and not timed_out
            and exact_file(directory/"stdout.bin",data["stdout"]) and exact_file(directory/"stderr.bin",data["stderr"]))
        expected_equal=equal
    else:
        equal=None
        expected_equal=child.returncode==0 and exact_file(directory/"stdout.bin",data["wanted"])
    record.update(status="CAPTURED_DIAGNOSTIC_ONLY",returncode=child.returncode,timed_out=timed_out,
        elapsed_ns=str(elapsed),group_CPU_after=cpu(),
        child_user_CPU_seconds=child_after.ru_utime-child_before.ru_utime,
        child_system_CPU_seconds=child_after.ru_stime-child_before.ru_stime,
        streams=streams,complete_calibration_returncode_stdout_stderr_equal_original=equal,
        complete_original_expected_output_equal=expected_equal,
        executable_before_after_equal=True,original_failure_unchanged=True)
    records.append(record);save(label+"/process.json",record);save("captured-processes.json",records)
    assert not timed_out,(label,"diagnostic wall timeout")
    assert cpu()<90,(label,"whole diagnostic CPU budget",cpu())
    if calibration:assert equal,(label,"complete original calibration mismatch")
    else:
        assert child.returncode in (0,-signal.SIGKILL),(label,"unexpected diagnostic exit",child.returncode)
        if child.returncode==0:assert expected_equal,(label,"full original expected output mismatch")
    return record
try:
    pin(__file__)
    index_raw=pin(ROOT/"impact-original-member-index.json")
    assert (len(index_raw),digest(index_raw))==(1376145,"9e63275d5f9541d69aa8bf75a0c2e2fa8f736af0fdc62374fdcfdd2ef97b4b48")
    index=json.loads(index_raw);assert len(index)==3090
    by_name={r["name"]:r for r in index};assert len(by_name)==3090
    build=json.loads(pin(BUILD/"manifest.json"))
    assert build["status"]=="BUILT_DIAGNOSTIC_ONLY" and build["fresh_B3"]==1
    assert build["retained_HIA_images"]==63 and build["all_retained_source_image_bytes_bound"]
    assert build["original_ELF_reproduced_full_bytes"] and build["complete_assembly_reverse_equal"]
    assert build["trace_fd"]==TRACE_FD and build["trace_record_bytes"]==128
    assert not build["semantic_qualification"]
    build_pins=json.loads(pin(BUILD/"source-and-image-pins.json"))
    for row in build_pins:
        raw=pin(row["path"])
        assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
        assert stat.S_IMODE(Path(row["path"]).stat().st_mode)==row["mode"]
    original_elf=Path(build["original_elf"]["path"]).resolve()
    timed_elf=Path(build["timed_elf"]["path"]).resolve()
    assert original_elf.is_relative_to(BUILD) and timed_elf.is_relative_to(BUILD)
    for key,path in (("original_elf",original_elf),("timed_elf",timed_elf)):
        raw=pin(path);assert (len(raw),digest(raw))==(build[key]["bytes"],build[key]["sha256"])
    calibration=case("semantic");large=case("large-valid")
    run("calibration-original",original_elf,calibration,True)
    assert records[-1]["streams"]["trace"]["bytes"]==0
    run("calibration-timed",timed_elf,calibration,True)
    assert records[-1]["streams"]["trace"]["bytes"]>0
    run("large-valid-timed",timed_elf,large,False)
    assert records[-1]["streams"]["trace"]["bytes"]>0
    assert attempts==3 and len(records)==3
    assert not unchanged() and cpu()<90 and time.monotonic_ns()-START<180000000000
    status="PASS_DIAGNOSTIC_CAPTURE_ONLY"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    after_errors=unchanged()
    final_CPU=cpu();final_elapsed=time.monotonic_ns()-START
    if after_errors or final_CPU>=90 or final_elapsed>=180000000000:status="FAIL"
    details.update(schema="hia-original-impact-timing-capture-v1",status=status,
        actual_ELF_processes_started=attempts,actual_processes_with_returned_record=len(records),
        actual_new_B3=0,actual_new_VM=0,retained_HIA_images=63,semantic_images_changed=0,
        processes=records,source_and_image_before_after_equal=not after_errors,
        after_check_errors=after_errors,complete_raw_streams_and_timing_files_preserved=True,
        parent_plus_children_CPU_seconds=final_CPU,elapsed_ns=str(final_elapsed),
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE)),
            wall_seconds=180),
        timing_includes_hook_sampling_write_and_layout_overhead=True,
        original_large_valid_failed_native_90058572023ns_and_90CPU_result_unchanged=True,
        original_failure_unchanged=True,semantic_qualification=False,whole_stack_closed=False)
    save("source-pins.json",list(PINS.values()));save("summary.json",details)
    print("HIA_IMPACT_TIMING_CAPTURE "+json.dumps(details,sort_keys=True),flush=True)
if status!="PASS_DIAGNOSTIC_CAPTURE_ONLY":raise SystemExit(1)
