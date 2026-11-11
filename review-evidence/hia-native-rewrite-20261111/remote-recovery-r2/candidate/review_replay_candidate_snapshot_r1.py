"""Review retained oracle evidence, then replay it through the new complete ELF.
The earlier harness required empty stderr on success; the actual public transport
also emits its 128-byte domain-zero completion frame. Earlier files stay intact.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,json,struct,subprocess,resource,time,traceback
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
ROOT=BASE/"root-recovery/workspace/native-edit-candidate-snapshot-r2-next"
ORIGINAL=ROOT/"development/original-reproduction-r1"
REVIEW=ROOT/"development/original-review-r2"
OUT=ROOT/"development/complete-elf-replay-r1"
BUILD=ROOT/"development/build-r2"
PINS={}
RESULTS=[]
def digest(raw):return hashlib.sha256(raw).hexdigest()
def read(p):
    p=Path(p).resolve();raw=p.read_bytes()
    if p in PINS:assert PINS[p]==raw
    PINS[p]=raw;return raw
def save(p,v):Path(p).write_text(json.dumps(v,indent=2,sort_keys=True)+"\n")
def limits():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def compare(case,stdout,stderr,rc,timed_out=False):
    folder=ORIGINAL/case["name"];oracle=case["oracle"]
    header=struct.unpack_from("<16Q",stderr) if len(stderr)>=128 else None
    common=(header is not None and stderr[:8]==b"HIACDE01" and header[1]==7
        and header[2]==case["lease"] and header[3]>0 and header[9]==1
        and tuple(header[11:])==(0,0,0,0,0))
    if oracle["kind"]=="success":
        expected=read(folder/"oracle.stdout.bin")
        body_equal=stdout==expected
        terminal=(common and len(stderr)==128 and header[4]==0 and header[5]==0
            and header[6]==30 and header[7]==0 and header[8]==len(stdout) and header[10]==0)
        match=rc==0 and body_equal and terminal and not timed_out
    else:
        expected=read(folder/"oracle.error-message.bin")
        body_equal=stderr[128:]==expected
        terminal=common and header[4]==oracle["domain"] and header[8]==len(expected)
        match=rc==2 and stdout==b"" and body_equal and terminal and not timed_out
    return dict(matches_exact_reference=bool(match),payload_equal=body_equal,terminal_valid=bool(terminal),
        returncode=rc,timed_out=timed_out,stdout_bytes=len(stdout),stderr_bytes=len(stderr),
        stdout_sha256=digest(stdout),stderr_sha256=digest(stderr),
        terminal=list(header) if header else None,
        message=stderr[128:].decode("utf-8","backslashreplace") if len(stderr)>128 else None,
        private_failure_words=list(struct.unpack("<4Q",stderr)) if len(stderr)==32 else None)
def main():
    assert not REVIEW.exists() and not OUT.exists()
    REVIEW.mkdir();OUT.mkdir();(OUT/"empty").mkdir()
    source=json.loads(read(ORIGINAL/"summary.json"));assert source["cases"]==17
    reviewed=[]
    for case in source["rows"]:
        folder=ORIGINAL/case["name"]
        result=compare(case,read(folder/"stdout.bin"),read(folder/"stderr.bin"),case["native"]["returncode"],case["native"]["timed_out"])
        reviewed.append(dict(name=case["name"],original_record_match=case["native"]["matches_exact_reference"],reviewed=result))
    controls=["small-no-op","small-valid-change","large-no-op-control"]
    control_ok=all(next(r for r in reviewed if r["name"]==name)["reviewed"]["matches_exact_reference"] for name in controls)
    failed=[r["name"] for r in reviewed if not r["reviewed"]["matches_exact_reference"]]
    save(REVIEW/"summary.json",dict(schema="hia-candidate-baseline-review-v2",status="COMPLETE_WITH_DIFFERENCES" if failed else "PASS",
        correction="Domain-zero 128-byte success terminal is required; empty stderr was a harness error",
        original_native_run=str(ORIGINAL),fresh_native_calls=0,reviewed_cases=len(reviewed),matched=len(reviewed)-len(failed),
        differences=failed,success_controls=controls,success_controls_pass=control_ok,rows=reviewed,
        original_records_unchanged=True,whole_stack_closed=False))
    print(json.dumps(dict(stage="original_review",success_controls_pass=control_ok,matched=len(reviewed)-len(failed),differences=failed)),flush=True)
    assert control_ok,"Stop attribution until original controls match the exact reference and public terminal"
    bundle=json.loads(read(BUILD/"bundle.json"));assert bundle["status"]=="PASS" and bundle["replacement_roles"]==[59,60]
    ELF=Path(bundle["executable"]["path"])
    assert digest(read(ELF))==bundle["executable"]["sha256"]
    for case in source["rows"]:
        folder=OUT/case["name"];folder.mkdir()
        payload=read(ORIGINAL/case["name"]/"stdin.bin")
        (folder/"stdin.bin").write_bytes(payload)
        before=resource.getrusage(resource.RUSAGE_CHILDREN);started=time.monotonic()
        with (folder/"stdin.bin").open("rb") as inp,(folder/"stdout.bin").open("wb") as out,(folder/"stderr.bin").open("wb") as err:
            proc=subprocess.Popen([str(ELF)],stdin=inp,stdout=out,stderr=err,cwd=OUT/"empty",
                env={"PATH":"","HOME":"","LANG":"C"},preexec_fn=limits)
            timed_out=False
            try:rc=proc.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out=True;proc.kill();rc=proc.wait()
        elapsed=time.monotonic()-started;after=resource.getrusage(resource.RUSAGE_CHILDREN)
        result=compare(case,(folder/"stdout.bin").read_bytes(),(folder/"stderr.bin").read_bytes(),rc,timed_out)
        result.update(elapsed_seconds=elapsed,child_user_seconds=after.ru_utime-before.ru_utime,
            child_system_seconds=after.ru_stime-before.ru_stime,children_maxrss_kib=after.ru_maxrss,
            original_fixture=str(ORIGINAL/case["name"]),stdin_sha256=digest(payload),stdin_bytes=len(payload))
        save(folder/"native.json",result)
        RESULTS.append(dict(name=case["name"],oracle=case["oracle"],native=result))
        save(OUT/"progress.json",dict(cases=RESULTS))
        print(json.dumps(dict(stage="new_elf",name=case["name"],matches=result["matches_exact_reference"],
            returncode=rc,reference=case["oracle"].get("message","success"),native=result["message"],
            private=result["private_failure_words"])),flush=True)
    differences=[r["name"] for r in RESULTS if not r["native"]["matches_exact_reference"]]
    all_pins_equal=all(p.read_bytes()==raw for p,raw in PINS.items());assert all_pins_equal
    summary=dict(schema="hia-candidate-complete-elf-fresh-replay-v1",status="PASS" if not differences else "COMPLETE_WITH_DIFFERENCES",
        cases=len(RESULTS),matched=len(RESULTS)-len(differences),differences=differences,rows=RESULTS,
        executable=bundle["executable"],source_before_after_equal=all_pins_equal,
        limits=dict(cpu_seconds=90,address_bytes=1<<30,stack_bytes=8<<20,wall_seconds=180,core=0),
        scope="DEVELOPMENT_NATIVE_REPLAY_NOT_FULL_COLD_OR_WHOLE_STACK_CLOSURE",whole_stack_closed=False)
    save(OUT/"summary.json",summary)
    print(json.dumps(dict(status=summary["status"],cases=len(RESULTS),matched=summary["matched"],differences=differences)),flush=True)
try:main()
except BaseException:
    if OUT.exists():(OUT/"harness-failure.txt").write_text(traceback.format_exc())
    traceback.print_exc();raise
finally:
    if OUT.exists():
        save(OUT/"input-pins.json",{str(p):dict(bytes=len(raw),sha256=digest(raw)) for p,raw in PINS.items()})
