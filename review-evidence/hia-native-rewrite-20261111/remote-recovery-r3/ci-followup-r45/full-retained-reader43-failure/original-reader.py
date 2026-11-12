"""Read only the exact completed full-retained37 evidence; execute no target."""
from __future__ import annotations
import base64,hashlib,json,os,resource,stat,sys,tarfile,time,traceback
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
ROOT=Path(os.environ["HIA_FULL_RETAINED37_ORIGINALS"]).resolve()
OUT=Path(os.environ["HIA_CI_OUTPUT"]).resolve()
assert OUT!=ROOT and not OUT.is_relative_to(ROOT)
OUT.mkdir(parents=True,exist_ok=False)
PINS={
"original-evidence.tar.xz":(1195190880,"52cb5aefa90e5f022905a2f29a38b1541a789444925b83f7e8c301bc6a866ebb"),
"members.jsonl":(7340439,"1ecfd0da7ab41cc1f01c147d9dc8bae4e51ff20d9691ec97f4fca34edeb72ac2"),
"members-after.jsonl":(7340439,"1ecfd0da7ab41cc1f01c147d9dc8bae4e51ff20d9691ec97f4fca34edeb72ac2")}
WANTED={
"qualification/QUALIFICATION.json",
"qualification/full-retained-regression.json",
"qualification/full-retained-regression.stdout.log",
"qualification/full-retained-regression.stderr.log",
"qualification/full-retained-regression.owner.json",
"qualification/steps.json",
"qualification/cold.json",
"qualification/source-before.json",
"qualification/source-after.json",
"qualification/harness-before.json"}
started=time.monotonic_ns()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def fingerprint(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def file_pin(path):
    initial=path.lstat()
    assert stat.S_ISREG(initial.st_mode),str(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,"rb") as f:
        opened=os.fstat(f.fileno());assert fingerprint(initial)==fingerprint(opened)
        value=hashlib.file_digest(f,"sha256").hexdigest()
        final=os.fstat(f.fileno())
    assert fingerprint(initial)==fingerprint(final)==fingerprint(path.lstat())
    return dict(bytes=initial.st_size,sha256=value,mode=stat.S_IMODE(initial.st_mode))
def snapshot():
    result={}
    for p in sorted(ROOT.rglob("*")):
        name=p.relative_to(ROOT).as_posix()
        assert not p.is_symlink(),name
        if p.is_file():result[name]=file_pin(p)
        else:assert p.is_dir(),name
    return result
before=None;complete=False;status="FAIL";selected={};details={
"scope":"READ_ONLY_COMPLETED_FULL_RETAINED37_ORIGINALS",
"run_id":43180758665,"job_id":131055860427,"artifact_id":13932871680,
"outer_ZIP_declared_bytes":1535039324,
"outer_ZIP_declared_sha256":"9cf8cfaf39c95d2a16441f529e8f5ef7d2bf9958b9e8e714fab9fd454daeab06",
"outer_ZIP_independently_read":False,
"actual_target_executions":0,"actual_HIA_generation":0,"actual_B3":0,"actual_VM":0,"actual_native":0,
"legacy_4157_tests_187_errors_1_failure_18_skips_result_unchanged":True,
"whole_native_delivery_qualified":False,"installed_activation":False,"whole_stack_closed":False}
try:
    before=snapshot()
    for name,(size,digest) in PINS.items():
        assert (before[name]["bytes"],before[name]["sha256"])==(size,digest),name
    (OUT/"input-files-before.json").write_text(json.dumps(before,indent=2,sort_keys=True)+"\n")
    custody_raw=(ROOT/"custody.json").read_bytes()
    (OUT/"producer-custody.original.json").write_bytes(custody_raw)
    custody=json.loads(custody_raw)
    for key,value in {
        "schema":"hia-full-retained-streamed-artifact-custody-v2",
        "status":"PASS_READBACK_ONLY","members":33465,"regular_files":30113,
        "original_bytes":3713148003,"all_selected_original_bytes_modes_and_links_before_after_equal":True,
        "every_tar_member_independently_readback":True,"missing_roots":[],
        "qualification_executed":False,"whole_stack_closed":False}.items():
        assert custody[key]==value,(key,custody.get(key))
    assert (custody["archive_bytes"],custody["archive_sha256"])==PINS["original-evidence.tar.xz"]
    assert (custody["index_bytes"],custody["index_sha256"])==PINS["members.jsonl"]
    count=regular=total=0;names=set()
    with (ROOT/"members.jsonl").open("rb") as catalog:
        with tarfile.open(ROOT/"original-evidence.tar.xz",mode="r|xz") as archive:
            for member in archive:
                line=catalog.readline();assert line,"extra archive member"
                expected=json.loads(line)
                name=member.name;pure=PurePosixPath(name)
                assert name and not pure.is_absolute() and ".." not in pure.parts and name not in names,name
                names.add(name);row=dict(name=name,mode=member.mode)
                if member.isfile():
                    h=hashlib.sha256();length=0
                    keep=name in WANTED
                    target=OUT/"originals"/name
                    if keep:target.parent.mkdir(parents=True,exist_ok=True)
                    dest=target.open("xb") if keep else None
                    try:
                        with archive.extractfile(member) as stream:
                            while True:
                                chunk=stream.read(1<<20)
                                if not chunk:break
                                h.update(chunk);length+=len(chunk)
                                if dest is not None:dest.write(chunk)
                    finally:
                        if dest is not None:dest.close()
                    assert length==member.size,name
                    row.update(kind="file",bytes=length,sha256=h.hexdigest())
                    if keep:selected[name]=dict(path=target.relative_to(OUT).as_posix(),bytes=length,sha256=h.hexdigest(),mode=member.mode)
                    regular+=1;total+=length
                elif member.issym():row.update(kind="symlink",target=member.linkname)
                elif member.isdir():row.update(kind="directory")
                else:raise AssertionError(("unsupported original member",name))
                assert row==expected,("member mismatch",name)
                archive.members.clear();count+=1
            assert not catalog.read(1),"missing archive member"
    assert (count,regular,total)==(33465,30113,3713148003),(count,regular,total)
    required={"qualification/QUALIFICATION.json","qualification/full-retained-regression.json","qualification/steps.json","qualification/cold.json"}
    assert required<=selected.keys(),sorted(required-selected.keys())
    def original(name):return (OUT/selected["qualification/"+name]["path"]).read_bytes()
    qualification=json.loads(original("QUALIFICATION.json"))
    regression=json.loads(original("full-retained-regression.json"))
    steps=json.loads(original("steps.json"))
    assert qualification["status"]=="FULL_RETAINED_PASS"
    assert qualification["source_preserved"] is True and qualification["harness_preserved"] is True
    assert qualification["full_retained_regression_requested"] is True
    assert qualification["full_retained_regression_executed"] is True
    assert qualification["full_retained_regression_qualified"] is True
    assert qualification["whole_native_delivery_qualified"] is False
    assert len(steps)==28 and steps==qualification["steps"]
    assert all(s["returncode"]==0 and s["timeout"] is False for s in steps)
    assert type(regression["tests_run"]) is int and regression["tests_run"]>0
    assert regression["tests_run"]==regression["tests_loaded"]
    assert regression["successful"] is True
    for key in ("errors","failures","skipped","expected_failures","unexpected_successes"):
        assert regression[key]==[],(key,regression[key])
    complete=True
    details.update(complete_original_archive_members_verified=count,
        complete_original_regular_files_verified=regular,complete_original_file_bytes_verified=total,
        steps=28,tests_loaded=regression["tests_loaded"],tests_run=regression["tests_run"],
        errors=0,failures=0,skipped=0,expected_failures=0,unexpected_successes=0,
        original_source_identity=qualification["source_identity"],
        cold_qualified=qualification["cold_qualified"],selected_originals=selected)
    payloads=[]
    for name in ("QUALIFICATION.json","full-retained-regression.json"):
        raw=original(name)
        payloads.append("HIA_FULL_RETAINED37_ORIGINAL "+json.dumps(dict(
            name="qualification/"+name,bytes=len(raw),sha256=sha(raw),
            encoding="base64",data=base64.b64encode(raw).decode()),sort_keys=True))
    assert sum(len(x.encode()) for x in payloads)<900000,"do not truncate original console evidence"
    for line in payloads:print(line,flush=True)
    status="PASS_READ_ONLY"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    if before is not None:
        try:
            after=snapshot()
            (OUT/"input-files-after.json").write_text(json.dumps(after,indent=2,sort_keys=True)+"\n")
            details["all_downloaded_file_bytes_and_modes_before_after_equal"]=after==before
            if after!=before:status="FAIL"
        except BaseException as exc:
            details["after_readback_error"]=repr(exc);status="FAIL"
    details.update(status=status,complete_archive_readback=complete,elapsed_ns=time.monotonic_ns()-started)
    (OUT/"observation.json").write_text(json.dumps(details,indent=2,sort_keys=True)+"\n")
    print("HIA_FULL_RETAINED37_READBACK "+json.dumps(details,sort_keys=True),flush=True)
if status!="PASS_READ_ONLY":raise SystemExit(1)
