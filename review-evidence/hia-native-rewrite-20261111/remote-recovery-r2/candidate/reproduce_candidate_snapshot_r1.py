"""Fresh exact-reference reproduction of candidate snapshot boundaries.
Runs the retained standalone ELF under unchanged 90 CPU/1 GiB child limits.
Differences are findings, never qualification passes. Preserves raw inputs.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import json, struct, subprocess, resource, time, traceback, hashlib, os
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
REF=BASE/"root-recovery/reference-0ef-r2"
WORK=BASE/"root-recovery/workspace"
OUT=WORK/"native-edit-candidate-snapshot-r2-next/development/original-reproduction-r1"
ELF=WORK/"native-edit-candidate-next/development/build-r1/hia-edit-candidate-limit"
EXPECTED_ELF="d78571cc3826186011c8e1efd44ec6f3be159f83c77836f61c4e3cb6ccb65199"
PINS={}
ROWS=[]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(p):
    p=Path(p).resolve();raw=p.read_bytes()
    if p in PINS:assert PINS[p]==raw
    PINS[p]=raw
    return raw
def save(path,value):
    Path(path).write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+"\n")
def wire(value):return json.dumps(value,separators=(",",":"),ensure_ascii=False,sort_keys=False,allow_nan=False).encode()
def node_count(value):
    stack=[value];n=0
    while stack:
        v=stack.pop();n+=1
        if type(v) is dict:stack.extend(v.values())
        elif type(v) is list:stack.extend(v)
    return n
def operation(i,value=1):
    return {"op":"const","args":[],"out":[{"name":"v"+str(i),"type":"u32"}],"attrs":{"value":value}}
def function(name,n=1):
    return {"name":name,"params":[],"returns":["u32"],"effects":[],"entry":"entry",
        "blocks":[{"id":"entry","params":[],"ops":[operation(i) for i in range(n)],"term":{"op":"ret","values":["v0"]}}]}
def program(large=False):
    funcs=([function("pad"+str(i),27+(108 if i==999 else 0)) for i in range(1000)] if large else [])
    funcs.append(function("calculate"))
    return {"schema":"hepta.hia.program.v6","module":"snapshot","functions":funcs}
def nested(n):
    v=1
    for _ in range(n):v=[v]
    return v
def limits():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def native_run(folder,payload,lease,expected):
    (folder/"stdin.bin").write_bytes(payload)
    before=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.monotonic()
    with (folder/"stdin.bin").open("rb") as inp,(folder/"stdout.bin").open("wb") as out,(folder/"stderr.bin").open("wb") as err:
        proc=subprocess.Popen([str(ELF)],stdin=inp,stdout=out,stderr=err,cwd=OUT/"empty",
            env={"PATH":"","HOME":"","LANG":"C"},preexec_fn=limits)
        timed_out=False
        try:rc=proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            timed_out=True;proc.kill();rc=proc.wait()
    elapsed=time.monotonic()-start;after=resource.getrusage(resource.RUSAGE_CHILDREN)
    stdout=(folder/"stdout.bin").read_bytes();stderr=(folder/"stderr.bin").read_bytes()
    metadata=dict(returncode=rc,timed_out=timed_out,elapsed_seconds=elapsed,
        child_user_seconds=after.ru_utime-before.ru_utime,child_system_seconds=after.ru_stime-before.ru_stime,
        children_maxrss_kib=after.ru_maxrss,stdout_bytes=len(stdout),stderr_bytes=len(stderr),
        stdout_sha256=sha(stdout),stderr_sha256=sha(stderr))
    if expected["kind"]=="success":
        correct=rc==0 and stderr==b"" and stdout==(folder/"oracle.stdout.bin").read_bytes()
    else:
        message=(folder/"oracle.error-message.bin").read_bytes()
        header=struct.unpack_from("<16Q",stderr) if len(stderr)>=128 else None
        metadata["error_header"]=list(header) if header else None
        correct=(rc==2 and stdout==b"" and header is not None
            and stderr[:8]==b"HIACDE01" and header[1]==7 and header[2]==lease
            and header[4]==expected["domain"] and header[8]==len(message)
            and stderr[128:]==message)
        if len(stderr)==32:
            metadata["private_failure_words"]=list(struct.unpack("<4Q",stderr))
        if len(stderr)>=128:
            metadata["native_error_message"]=stderr[128:].decode("utf-8","backslashreplace")
    metadata["matches_exact_reference"]=bool(correct and not timed_out)
    save(folder/"native.json",metadata)
    return metadata
def run_case(name,base,query,response,large=False):
    from hepta.hia_edit_query import apply_edit
    from hepta.hia_program import HIAProgramRejected
    from hepta.hia_program_tools import bounded_json_wire,HIAEditRejected
    folder=OUT/name;folder.mkdir()
    raw=wire(response)
    assert len(raw)<=16384,(name,len(raw))
    querywire=bounded_json_wire(query,1<<20)
    (folder/"program.bin").write_bytes(base);(folder/"query.bin").write_bytes(querywire);(folder/"response.bin").write_bytes(raw)
    oracle_started=time.monotonic()
    try:
        verified,receipt=apply_edit(base,query,raw)
        candidate=verified.canonical_bytes;receiptwire=bounded_json_wire(receipt,8<<20)
        expected=dict(kind="success",candidate_bytes=len(candidate),receipt_bytes=len(receiptwire),query_bytes=len(querywire))
        oracle=struct.pack("<8Q",int.from_bytes(b"HIAEDR01","little"),1,len(candidate),len(receiptwire),len(querywire),0,0,0)+candidate+receiptwire+querywire
        (folder/"oracle.stdout.bin").write_bytes(oracle)
    except (HIAProgramRejected,HIAEditRejected,UnicodeError) as exc:
        domain=2 if isinstance(exc,HIAProgramRejected) else (3 if isinstance(exc,UnicodeError) else 1)
        expected=dict(kind="error",domain=domain,error_class=type(exc).__name__,message=str(exc),code=getattr(exc,"code",None))
        (folder/"oracle.error-message.bin").write_bytes(str(exc).encode())
    expected["elapsed_seconds"]=time.monotonic()-oracle_started
    save(folder/"oracle.json",expected)
    lease=0x9acdfa+len(ROWS)
    payload=struct.pack("<8Q",int.from_bytes(b"HIAEJN01","little"),lease,1,4300,len(base),len(querywire),len(raw),0)+base+querywire+raw
    result=native_run(folder,payload,lease,expected)
    row=dict(name=name,large=large,lease=lease,program_bytes=len(base),query_bytes=len(querywire),response_bytes=len(raw),
        oracle=expected,native=result)
    ROWS.append(row);save(OUT/"progress.json",dict(cases=ROWS))
    print(json.dumps(dict(name=name,match=result["matches_exact_reference"],returncode=result["returncode"],
        reference=expected.get("message","success"),native=result.get("native_error_message"),
        child_cpu=result["child_user_seconds"]+result["child_system_seconds"])),flush=True)
def main():
    assert not OUT.exists();OUT.mkdir();(OUT/"empty").mkdir()
    assert sha(pin(ELF))==EXPECTED_ELF
    for key in list(os.environ):
        if key.startswith("HEPTA_HIA_"):del os.environ[key]
    sys.path.insert(0,str(REF))
    from hepta.hia_edit_query import prepare_edit
    from hepta.hia_program import verify_program
    base=wire(program());checked=verify_program(base)
    query=prepare_edit(base,function="calculate",block="entry",output="v0",fields=["attrs"])
    for name,value in [("small-no-op",1),("small-valid-change",2)]:
        run_case(name,base,query,{"attrs":{"value":value}})
    for depth in [55,56,57,58,119,126,127,128,129]:
        run_case("depth-"+str(depth),base,query,{"attrs":{"value":nested(depth)}})
    for name,value in [("float-integral",1.0),("float-fractional",1.5)]:
        run_case(name,base,query,{"attrs":{"value":value}})
    large_program=program(True);large=wire(large_program)
    count=node_count(large_program);assert count==260001 and len(large)<8<<20,(count,len(large))
    large_checked=verify_program(large)
    large_query=prepare_edit(large,function="calculate",block="entry",output="v0",fields=["attrs"])
    save(OUT/"large-base-admission.json",dict(nodes=count,bytes=len(large),sha256=sha(large),
        independently_verified=True,canonical_sha256=large_checked.sha256,functions=1001,
        selected_function_last=True,response_limit=16384))
    run_case("large-no-op-control",large,large_query,{"attrs":{"value":1}},True)
    wide=[0]*5000;deep=nested(57)
    run_case("large-wide-only",large,large_query,{"attrs":{"value":wide}},True)
    run_case("large-deep-then-wide",large,large_query,{"attrs":{"value":{"z_deep":deep,"a_wide":wide}}},True)
    run_case("large-wide-then-deep",large,large_query,{"attrs":{"value":{"a_wide":wide,"z_deep":deep}}},True)
    for module in list(sys.modules.values()):
        path=getattr(module,"__file__",None)
        if path:
            p=Path(path)
            if p.is_file() and p.suffix==".py" and p.is_relative_to(REF):pin(p)
    assert all(p.read_bytes()==raw for p,raw in PINS.items())
    failed=[r["name"] for r in ROWS if not r["native"]["matches_exact_reference"]]
    control=next(r for r in ROWS if r["name"]=="large-no-op-control")
    summary=dict(schema="hia-candidate-snapshot-fresh-original-reproduction-v1",status="COMPLETE_WITH_DIFFERENCES" if failed else "PASS",
        cases=len(ROWS),matching=len(ROWS)-len(failed),differences=failed,large_no_op_control_pass=control["native"]["matches_exact_reference"],
        rows=ROWS,original_executable_sha256=EXPECTED_ELF,reference_commit="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5",
        reference_python=sys.version,scope="OBSERVED_ORIGINAL_BASELINE_NOT_A_FIXED_VERSION_QUALIFICATION",whole_stack_closed=False,
        limits=dict(cpu_seconds=90,address_bytes=1<<30,stack_bytes=8<<20,wall_seconds=180,core=0),
        source_before_after_equal=True)
    save(OUT/"summary.json",summary)
    print(json.dumps({k:v for k,v in summary.items() if k!="rows"},sort_keys=True),flush=True)
try:main()
except BaseException:
    if OUT.exists():(OUT/"harness-failure.txt").write_text(traceback.format_exc())
    traceback.print_exc();raise
finally:
    if OUT.exists():
        save(OUT/"source-pins.json",{str(p):dict(bytes=len(raw),sha256=sha(raw)) for p,raw in PINS.items()})
