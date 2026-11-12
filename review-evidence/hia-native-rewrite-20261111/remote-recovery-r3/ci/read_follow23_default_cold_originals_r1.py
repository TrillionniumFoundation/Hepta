"""Read complete original default cold evidence; never execute qualification."""
from pathlib import Path
from hashlib import sha1,sha256
import base64,json,os,resource,stat,time,traceback,zipfile
SOURCE=Path(os.environ["HIA_ORIGINAL_COLD_ARTIFACT"]).absolute()
OUT=Path(os.environ["HIA_COLD_READBACK_OUTPUT"]).absolute()
EXPECTED_RUN=43144028930
EXPECTED_JOB=130937528343
EXPECTED_HEAD="60a165de5eb2621fe2f23905428114f2c93ef278"
EXPECTED_ARTIFACT=13911626793
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
OUT.mkdir(parents=True,exist_ok=False)
START=time.monotonic_ns()
SELF=Path(__file__).resolve();SELF_RAW=SELF.read_bytes()
inventory={};originals=[];archives=[];failures=[]
def metadata(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def read(path):
    path=Path(path)
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode):raise ValueError("nonregular artifact member "+str(path))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        if metadata(os.fstat(fd))!=metadata(before):raise ValueError("member identity changed")
        with os.fdopen(fd,"rb",closefd=False) as handle:raw=handle.read()
        if len(raw)!=before.st_size or metadata(os.fstat(fd))!=metadata(before) or metadata(path.lstat())!=metadata(before):
            raise ValueError("member changed during complete read")
    finally:os.close(fd)
    return raw
def identity(raw):
    return dict(bytes=len(raw),sha256=sha256(raw).hexdigest(),
        gitsha=sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def save(name,value):
    path=OUT/name;path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def original(path):
    raw=read(path);relative=path.relative_to(SOURCE).as_posix();row=dict(path=relative,**identity(raw))
    target=OUT/"originals"/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    assert target.read_bytes()==raw
    originals.append(row)
    if raw:
        for offset in range(0,len(raw),12000):
            part=raw[offset:offset+12000]
            print("HIA_DEFAULT_COLD_ORIGINAL "+json.dumps(dict(**row,offset=offset,
                part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
    else:
        print("HIA_DEFAULT_COLD_ORIGINAL "+json.dumps(dict(**row,offset=0,part_bytes=0,base64=""),sort_keys=True),flush=True)
    return raw
def verify_stage_zip(path):
    raw=read(path);before=identity(raw)
    with zipfile.ZipFile(path) as handle:
        infos=handle.infolist();names=[i.filename for i in infos]
        if len(names)!=len(set(names)) or "HIA_ARCHIVE_MANIFEST.json" not in names:
            raise ValueError("stage archive inventory "+str(path))
        manifest_info=handle.getinfo("HIA_ARCHIVE_MANIFEST.json")
        if manifest_info.file_size>32<<20:raise ValueError("archive manifest extent")
        manifest=json.loads(handle.read(manifest_info))
        files=manifest["files"]
        if type(files)is not dict or set(names)!=(set(files)|{"HIA_ARCHIVE_MANIFEST.json"}):
            raise ValueError("stage archive member set")
        total=0
        for name,row in files.items():
            if Path(name).is_absolute() or ".." in Path(name).parts:raise ValueError("archive path")
            info=handle.getinfo(name)
            if not 0<=info.file_size<=16<<20 or info.file_size!=row["bytes"]:raise ValueError("member extent")
            total+=info.file_size
            if total>512<<20:raise ValueError("stage aggregate extent")
            data=handle.read(info)
            if len(data)!=row["bytes"] or sha256(data).hexdigest()!=row["sha256"]:
                raise ValueError("stage full member digest")
            if (info.external_attr>>16)&0o777!=row["mode"]:raise ValueError("stage member mode")
        if total!=manifest["unpacked_bytes"]:raise ValueError("stage aggregate differs")
    if identity(read(path))!=before:raise ValueError("stage archive changed")
    return dict(path=path.relative_to(SOURCE).as_posix(),**before,members=len(files),
        unpacked_bytes=total,every_member_bytes_digest_mode_verified=True)
summary=dict(status="FAIL",run=EXPECTED_RUN,job=EXPECTED_JOB,head=EXPECTED_HEAD,
    artifact=EXPECTED_ARTIFACT,provider_zip_bytes=56558264,
    provider_zip_sha256="c6d6eb411a056f86b5204f761bb918926a25ba40eb63c09b06205e0ae41c30a7",
    outer_zip_independently_reread=False,new_AST=0,new_B3=0,new_VM=0,new_native=0,
    whole_stack_closed=False,original_failure_relabelled=False)
try:
    if SOURCE==OUT or SOURCE in OUT.parents or OUT in SOURCE.parents:raise ValueError("output must be separate from original evidence")
    summary["reader_source_identity"]=identity(SELF_RAW)
    if any(p.is_symlink() for p in (SOURCE,*SOURCE.parents)):raise ValueError("artifact root symlink")
    files=[]
    for path in sorted(SOURCE.rglob("*")):
        info=path.lstat()
        if stat.S_ISDIR(info.st_mode):continue
        if not stat.S_ISREG(info.st_mode):raise ValueError("nonregular provider member")
        raw=read(path);relative=path.relative_to(SOURCE).as_posix()
        inventory[relative]=identity(raw);files.append(path)
    if len(files)!=1498:raise ValueError("original uploaded member count differs: "+str(len(files)))
    save("complete-original-member-manifest.json",inventory)
    root=SOURCE/"hia-cold.cold"
    # Emit exact raw report and owner before deriving or assuming their shape.
    report=json.loads(original(SOURCE/"hia-cold.json"))
    for relative in ("process-owner.json","request.json","stdout.log","stderr.log","qualification.json"):
        path=root/relative
        if path.is_file():original(path)
    indexes=[p for p in files if p.name=="phase-index.json" and root in p.parents and root/"source" not in p.parents]
    for path in indexes:original(path)
    for path in files:
        if root/"source" in path.parents:continue
        if path.name.startswith("phase-") and path.name.endswith((".process.json",".stderr.log")):
            original(path)
        elif path.name.endswith(".receipt.json") and root in path.parents:
            original(path)
    for path in files:
        if path.suffix==".zip" and "phase-runs" in path.parts:
            archives.append(verify_stage_zip(path))
    manifest=report["source_manifest"]
    if type(manifest)is not dict:raise ValueError("cold manifest type")
    for name,expected in manifest.items():
        if Path(name).is_absolute() or ".." in Path(name).parts:raise ValueError("source manifest path")
        raw=read(root/"source"/name)
        if sha256(raw).hexdigest()!=expected:raise ValueError("exported source mismatch "+name)
    expected_qualifier="5827d103856fb871db6fe07772068aece8827458215cf4d2b89d5f14dee6e023"
    expected_contract="33bca4ce1b186ed5b34265b840028c8d6b9cb62f28cd18d0bc67c9984617f400"
    if manifest["tools/qualify_hia_selfhost.py"]!=expected_qualifier:raise ValueError("qualifier source differs")
    if manifest["docs/HIA_SELFHOST_CORE_SUPPORT.json"]!=expected_contract:raise ValueError("contract source differs")

    # The earlier independently executed candidate provides an exact complete
    # source manifest, not authority to replace this run's own cold result.
    expected_path=Path(os.environ["GITHUB_WORKSPACE"])/"review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/cold-archive-overlap-r1/follow20-originals/hia-cold.json"
    expected_raw=read(expected_path)
    if identity(expected_raw)!={"bytes":69705,"gitsha":"97632c31e5197db333323929a334c764dccd7e22","sha256":"37671675a36642eeab95a4ae469961cc11e1efa09107539219e7c8c686a1d61e"}:
        raise ValueError("prior original report identity differs")
    expected_report=json.loads(expected_raw)
    if manifest!=expected_report["source_manifest"]:
        raise ValueError("default source manifest differs from prior qualified candidate")
    if report["status"]!="COLD_SELFHOST_REPLAY_PASS" or len(report["checks"])!=11 or not all(value is True for value in report["checks"].values()):
        raise ValueError("this original default report did not pass all eleven checks")
    if report["generation_sha256"]!=["0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"]*3:
        raise ValueError("default original generations differ")
    if report["modified_generation_sha256"]!=["931b7441f3d04e1ad73d3201da8febdd83b0815c3c08dd665f99ec95be04d718","d606beeaf5503627138073970ea4537975a53fd657c07f89e36cc36d25610ac2","d606beeaf5503627138073970ea4537975a53fd657c07f89e36cc36d25610ac2"]:
        raise ValueError("default modified generations differ")
    if read(expected_path)!=expected_raw:raise ValueError("prior report changed during comparison")
    summary["complete_source_manifest_equal_to_prior_actual_candidate"]=True
    summary["prior_candidate_original_report_identity"]=identity(expected_raw)
    summary["old_failed_default_run_retained"]=43141350829

    owner=report["process_owner"]
    phases=[json.loads(read(p)) for p in indexes]
    observed=[]
    for path in files:
        if path.name.startswith("phase-") and path.name.endswith(".process.json") and root/"source" not in path.parents:
            row=json.loads(read(path))
            observed.append({k:row.get(k) for k in ("family","compiler_label","returncode",
                "worker_pid","started_monotonic_ns","completed_monotonic_ns","wall_elapsed_ns",
                "archive_completed_monotonic_ns","report_sha256")})
    summary.update(status="PASS_READBACK_ONLY",original_cold_status=report["status"],
        checks=report["checks"],checks_passed=sum(report["checks"].values()),checks_total=len(report["checks"]),
        owner_status=owner.get("status"),owner_timed_out=owner.get("timed_out"),
        owner_exit_before_deadline=owner.get("exit_observed_before_deadline"),cleanup=owner.get("cleanup"),
        original_wall_elapsed_ns=report["wall_elapsed_ns"],
        original_qualification_seconds=report["qualification_wall_limit_seconds"],
        original_cleanup_seconds=report["cleanup_wall_limit_seconds"],
        all_exported_source_members_verified=len(manifest),actual_phase_indexes=phases,
        actual_process_receipts=observed,all_inner_stage_archives=archives,
        original_nested_report_sha256=report.get("nested_report_sha256"),
        native_generation_hashes_as_reported=report["generation_sha256"],
        modified_generation_hashes_as_reported=report["modified_generation_sha256"])
except BaseException as exc:
    summary.update(error_class=type(exc).__name__,error=str(exc))
    (OUT/"failure.txt").write_text(traceback.format_exc());traceback.print_exc()
finally:
    try:
        after={p.relative_to(SOURCE).as_posix():identity(read(p))
            for p in sorted(SOURCE.rglob("*")) if not p.is_dir()}
        if after!=inventory:raise ValueError("original artifact changed during readback")
        if SELF.read_bytes()!=SELF_RAW:raise ValueError("reader source changed")
        summary["all_original_files_before_after_equal"]=True
    except BaseException as exc:
        summary.update(status="FAIL",after_error=str(exc),all_original_files_before_after_equal=False)
    summary.update(original_files=len(inventory),original_raw_bytes=sum(r["bytes"] for r in inventory.values()),
        original_exports=originals,elapsed_ns=time.monotonic_ns()-START)
    save("readback-summary.json",summary);save("original-export-index.json",originals)
    print("HIA_DEFAULT_COLD_OBSERVED "+json.dumps({k:v for k,v in summary.items() if k not in ("original_exports","actual_phase_indexes")},sort_keys=True),flush=True)
if summary["status"]!="PASS_READBACK_ONLY":raise SystemExit(1)
