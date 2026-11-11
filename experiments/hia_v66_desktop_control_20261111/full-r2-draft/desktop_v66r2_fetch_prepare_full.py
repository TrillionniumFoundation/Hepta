"""Fresh fresh final-v66 desktop custody and preparation, then exec reviewed v7 --full.

Runs only as the child of the unchanged external subreaper guardian. All Git,
preparation and test descendants remain under that owner across exec/setsid.
No old source, environment, evidence, or product gate is modified.
"""
from __future__ import annotations
from hashlib import file_digest
import json,os,stat,sys,time
from pathlib import Path
import workflow_process

ROOT=Path("/home/qian-qi/he26v66r2")
SOURCE=ROOT/"s"
CONTROL=ROOT/"control"
PREPARATION=ROOT/"p"
TEMPORARY=ROOT/"t"
OUTPUT=ROOT/"q"
BORROW=Path("/home/qian-qi/he26v65r2/s")
PREREQUISITES=Path("/home/qian-qi/hia-e26e-v64-prerequisites")
PYTHON=Path("/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python")
PYTHON_REPORT=Path("/home/qian-qi/hia-e26e-python314-linux-completion-r2/python-linux-preparation.json")
PYTHON_GUARD=Path("/home/qian-qi/hia-e26e-python314-linux-completion-r2/guard/guardian.json")
PYTHON_SHA="b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493"
PYTHON_REPORT_SHA="f834e072227ed59f06d347772b8db126c1910c574e660d66f9d15c1c1ec43967"
PYTHON_GUARD_SHA="f4115e59f8a6eb22db8a002960fbca83e248e071e5694d89e93371b2262b036d"
HEAD="__FROZEN_HEAD_PENDING__"
TREE="__FROZEN_TREE_PENDING__"
BASE_HEAD="4161e8d12d87906fde144f039da07908ad52d98a"
BASE_TREE="1c6ab0228f012429149997d1f731833739f433eb"
CONTRACT="docs/HIA_SELFHOST_CORE_SUPPORT.json"
CONTRACT_SHA="__FROZEN_CONTRACT_PENDING__"
COVERAGE_SHA="__FROZEN_COVERAGE_PENDING__"
PROFILE="__FROZEN_PROFILE_PENDING__"
SOURCE_COUNT=0  # Filled only from the final published contract and readback.
REPOSITORY="https://github.com/TrillionniumFoundation/Hepta.git"
EXPECTED_HELPER="f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80"
ORIGINAL_PINS={
 "/home/qian-qi/he26v65r2/q/QUALIFICATION.json":"d91d279d192a9fe6b6a7521d8732197bdc37f4af3a03a694cfccb15929748b60",
 "/home/qian-qi/he26v65r2/q/cold.json":"938b9331e28e53442a21796acb319f3c9683fc26748cad49893b56873bf02ad4",
 "/home/qian-qi/he26v65r2/q/source-tests.json":"a2a84183bbca9df57ee352524e874420c446cb472bba34a5abd04551556593de",
 "/home/qian-qi/he26v65r2/guard/guardian.json":"ae721abf9b428acedb43fe99d5b072fed1de3299fd331b457410fdb5858519f1",
 "/home/qian-qi/he26v66r1/guard/guardian.json":"c843ea8a9c841ebc0d9fa3102056dc061709a1dd9ae81282f54116b810303077",
 "/home/qian-qi/hia-native-closure-evidence/4161e8d12d87906fde144f039da07908ad52d98a/desktop-full-hold-r2-preservation-r3/PRESERVATION.json":"6edd6d762f9ca2f95c1b3c0b40d1cd543c83e030fa0ecba1a72a2c26507644de",
}
os.umask(0o077)
def require(ok,message):
    if not ok:raise RuntimeError(message)
def sha(path):
    with Path(path).open("rb") as stream:return file_digest(stream,"sha256").hexdigest()
def create(path,raw):
    with Path(path).open("xb") as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
def wire(value):return (json.dumps(value,indent=2,sort_keys=True)+"\n").encode()
def private(path):
    info=path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid()
            and stat.S_IMODE(info.st_mode)==0o700,"owned private directory required: "+str(path))
    require(not any(p.is_symlink() for p in (path,*path.parents)),"symlink ancestor refused")
require(SOURCE_COUNT>634 and len(HEAD)==40 and len(TREE)==40
        and len(CONTRACT_SHA)==64 and len(COVERAGE_SHA)==64
        and all(c in "0123456789abcdef" for c in HEAD+TREE+CONTRACT_SHA+COVERAGE_SHA),
        "final published source identity has not been frozen")
for path in (ROOT,CONTROL,ROOT/"guard"):private(path)
require(not any(os.path.lexists(p) for p in (SOURCE,PREPARATION,TEMPORARY,OUTPUT)),
        "fresh source/preparation/temp/output required; reconcile the original job")
require(Path(workflow_process.__file__).resolve()==CONTROL/"workflow_process.py"
        and sha(workflow_process.__file__)==EXPECTED_HELPER,"reviewed adjacent workflow helper changed")
LOGS=ROOT/"preparation-logs";LOGS.mkdir(mode=0o700)
ENV={k:v for k,v in os.environ.items() if not k.startswith(("HEPTA_HIA_","GIT_"))
     and k not in ("PYTHONPATH","PYTHONHOME","PYTHONSTARTUP","LD_PRELOAD")}
ENV.update(PATH="/usr/bin:/bin",LANG="C.UTF-8",LC_ALL="C.UTF-8",PYTHONDONTWRITEBYTECODE="1",
           PYTHONUNBUFFERED="1",PYTHONNOUSERSITE="1",GIT_TERMINAL_PROMPT="0",
           GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",CARGO_BUILD_JOBS="2")
report={"schema":"hia.desktop-v66-exact-source-fresh-preparation.v1","status":"RUNNING",
        "head":HEAD,"tree":TREE,"profile":PROFILE,"cold_manifest_count":SOURCE_COUNT+1,
        "source":str(SOURCE),"preparation":str(PREPARATION),"temporary":str(TEMPORARY),
        "qualification_output":str(OUTPUT),"source_contract_sha256":CONTRACT_SHA,
        "language_coverage_sha256":COVERAGE_SHA,"steps":[],"started_unix_ns":time.time_ns(),
        "whole_native_delivery_qualified":False,"prior_runs_modified":False,
        "cold_180_seconds_or_two_workers_modified":False}
def checkpoint():
    raw=wire(report);tmp=ROOT/"custody.next.json"
    create(tmp,raw);os.replace(tmp,ROOT/"custody.json")
    fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def run(label,command,seconds=120):
    print(json.dumps({"stage":"FRESH_V66_PREPARATION","step":label}),flush=True)
    stdout=LOGS/(label+".stdout.log");stderr=LOGS/(label+".stderr.log")
    owner=workflow_process.run_workflow_step(list(map(str,command)),cwd=ROOT,env=ENV,
        stdout_path=stdout,stderr_path=stderr,receipt_path=LOGS/(label+".owner.json"),seconds=seconds)
    report["steps"].append({"label":label,"owner":owner});checkpoint()
    clean=(owner.get("timed_out") is False and owner.get("cleanup",{}).get("complete") is True
           and owner["cleanup"].get("errors")==[] and owner["cleanup"].get("signalled")==[])
    require(clean,"step was interrupted, timed out, or retained descendants: "+label)
    require(owner.get("status")=="WORKFLOW_STEP_COMPLETED" and owner.get("returncode")==0,
            "owned preparation step failed: "+label)
    return owner.get("returncode"),stdout.read_text().strip()
def git(path,*args):
    return ["/usr/bin/git","--no-replace-objects","-c","core.hooksPath=/dev/null",
            "-c","http.version=HTTP/1.1","-C",str(path),*args]
def complete_objects(path):
    obj=path/".git/objects"
    require(obj.is_dir() and not obj.is_symlink(),"complete real Git object store required")
    require(not (obj/"info/alternates").exists() and not (obj/"info/http-alternates").exists()
            and not list(obj.rglob("*.promisor")),"external/promisor objects refused")
    for p in obj.rglob("*"):
        if p.is_file():
            require(not p.is_symlink() and p.stat().st_nlink==1,"external object hardlink refused")
try:
    require({name:sha(name) for name in ORIGINAL_PINS}==ORIGINAL_PINS, "prior originals changed")
    report["original_evidence_pins_before"]=dict(ORIGINAL_PINS)
    require(sha(PYTHON)==PYTHON_SHA and sha(PYTHON_REPORT)==PYTHON_REPORT_SHA
            and sha(PYTHON_GUARD)==PYTHON_GUARD_SHA,"new Linux Python preparation identity differs")
    python_report=json.loads(PYTHON_REPORT.read_bytes())
    python_guard=json.loads(PYTHON_GUARD.read_bytes())
    require(python_report.get("status")=="CPYTHON_LINUX_AND_LOCKED_DEPS_READY_NOT_QUALIFICATION"
            and python_report.get("qualification_executed") is False
            and python_report.get("source_head")==BASE_HEAD and python_report.get("source_tree")==BASE_TREE
            and python_report.get("original_sealed_memfd_gate_passed") is True
            and python_report.get("venv_actual_linux_apis",{}).get("sealed_memfd_ok") is True
            and python_report.get("python",{}).get("path")==str(PYTHON)
            and python_report["python"].get("sha256")==PYTHON_SHA,
            "actual newly built Linux Python and sealed-memory proof required")
    require(python_guard.get("status")=="EXTERNAL_OWNED_PROCESS_COMPLETED"
            and python_guard.get("input_identity_preserved") is True
            and python_guard.get("lifecycle",{}).get("cleanup",{}).get("complete") is True
            and python_guard["lifecycle"]["cleanup"].get("observed_echild") is True,
            "new interpreter build owner did not close")
    report["new_linux_python_preparation"]={"report":str(PYTHON_REPORT),
        "report_sha256":PYTHON_REPORT_SHA,"guardian":str(PYTHON_GUARD),
        "guardian_sha256":PYTHON_GUARD_SHA,"python":str(PYTHON),"binary_sha256":PYTHON_SHA,
        "original_preparation_HOLD_preserved":"/var/tmp/he26v65",
        "original_job":"1a1c9d62f72-2564-30a","same_attempt_replayed":False,"historical_tool_preparation_head":BASE_HEAD,
        "current_source_admitted_only_by_fresh_preparation":True}
    require(sha(PREREQUISITES/"fixed-tools-ready-report.json")==
            "103c181ad14f8be33600a26a9e0f5d08ad45b51489e358406526e6489f9d5770","fixed-tools receipt changed")
    require(sha(PREREQUISITES/"fixture-build-report-r2.json")==
            "04d446583cab0ff060dee9c18e3463e1f9bb354e8d5a50d8c3feb475bcd6a406","six-fixture receipt changed")
    _,before=run("borrow-before",git(BORROW,"rev-parse","HEAD","HEAD^{tree}"))
    require(before.splitlines()==[BASE_HEAD,BASE_TREE],"borrowed416 identity changed")
    _,clean=run("borrow-clean-before",git(BORROW,"status","--porcelain=v1","--untracked-files=all"))
    require(not clean,"borrowed416 source is not clean")
    complete_objects(BORROW)
    run("independent-local-clone",["/usr/bin/git","-c","core.hooksPath=/dev/null",
        "clone","--local","--no-hardlinks","--no-checkout",str(BORROW),str(SOURCE)],seconds=300)
    run("fetch-exact-published-once",
        git(SOURCE,"fetch","--no-tags","--depth","1",REPOSITORY,HEAD),seconds=900)
    report["fetch_attempts"]=1
    report["fetch_depth"]=1
    report["ancestral_history_required"]=False
    _,identity=run("fetched-identity",git(SOURCE,"rev-parse","FETCH_HEAD",HEAD+"^{tree}"))
    require(identity.splitlines()==[HEAD,TREE],"fetched exact commit/tree differs")
    run("checkout",git(SOURCE,"checkout","--quiet","--detach",HEAD))
    run("object-integrity",git(SOURCE,"fsck","--full","--strict","--no-dangling"),seconds=300)
    complete_objects(SOURCE)
    _,current=run("checkout-identity",git(SOURCE,"rev-parse","HEAD","HEAD^{tree}"))
    require(current.splitlines()==[HEAD,TREE],"checked-out exact identity differs")
    _,clean=run("checkout-clean",git(SOURCE,"status","--porcelain=v1","--untracked-files=all"))
    require(not clean,"new source is not clean")
    require(sha(SOURCE/CONTRACT)==CONTRACT_SHA,"frozen contract digest differs")
    contract=json.loads((SOURCE/CONTRACT).read_bytes());pins=contract["source_identity"]["files"]
    require(contract["profile"]==PROFILE and len(pins)==SOURCE_COUNT,"profile or complete source count differs")
    for name,digest in pins.items():
        relative=Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts,"invalid pinned source path")
        require(sha(SOURCE/relative)==digest,"pinned source member differs: "+name)
    require(sha(SOURCE/"docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json")==COVERAGE_SHA,"coverage digest differs")
    require((SOURCE/"review-evidence/hia-native-rewrite-20261111/workflow_process.py").read_bytes()
            ==(CONTROL/"workflow_process.py").read_bytes(),"source workflow helper differs from reviewed owner")
    create(ROOT/"cold-source-manifest-before.json",wire({**pins,CONTRACT:CONTRACT_SHA}))
    _,after=run("borrow-after",git(BORROW,"rev-parse","HEAD","HEAD^{tree}"))
    _,clean=run("borrow-clean-after",git(BORROW,"status","--porcelain=v1","--untracked-files=all"))
    require(after==before and not clean,"borrowed416 source changed")
    require({name:sha(name) for name in ORIGINAL_PINS}==ORIGINAL_PINS, "prior originals changed")
    report["original_evidence_pins_after"]=dict(ORIGINAL_PINS)
    report.update(status="EXACT_SOURCE_READY_NOT_QUALIFICATION",source_members_verified=SOURCE_COUNT,
                  independent_complete_objects=True,borrowed_source_preserved=True)
    checkpoint()
    run("fresh-source-bound-prerequisites",[str(PYTHON),"-B",
        str(CONTROL/"prepare_private_cargo_environment.py"),"--source",str(SOURCE),
        "--output",str(PREPARATION),"--temporary-root",str(TEMPORARY),
        "--prereq-root",str(PREREQUISITES),"--python",str(PYTHON),
        "--candidate-environment",str(CONTROL/"desktop-retained-input-hints.json")],seconds=900)
    prep=json.loads((PREPARATION/"preparation.json").read_bytes())
    require(prep.get("status")=="READY" and prep.get("missing")==[]
            and prep.get("source")==str(SOURCE) and prep.get("qualification_executed") is False
            and prep.get("python")==str(PYTHON)
            and prep.get("checks",{}).get("sealed_memfd",{}).get("returncode")==0,
            "fresh original preparation did not pass every required prerequisite")
    report.update(status="FRESH_PREREQUISITES_READY_FULL_EXEC_REQUESTED",
                  preparation_sha256=sha(PREPARATION/"preparation.json"),
                  environment_sha256=sha(PREPARATION/"environment.json"),
                  qualification_exec_requested=True)
    argv=[str(PYTHON),"-B",str(PREPARATION/"launch.py"),
          str(CONTROL/"run_hia_qualification_v7.py"),"--source",str(SOURCE),
          "--output",str(OUTPUT),"--prerequisite-environment",str(PREPARATION/"environment.json"),
          "--prerequisite-report",str(PREPARATION/"preparation.json"),"--full"]
    report["qualification_command"]=argv;checkpoint()
    print(json.dumps({"stage":report["status"],"head":HEAD,"cold_manifest_count":SOURCE_COUNT+1}),flush=True)
    os.execve(str(PYTHON),argv,ENV)
except BaseException as error:
    report.update(status="PREPARATION_HOLD",error_type=type(error).__name__,error=str(error))
    checkpoint()
    raise
