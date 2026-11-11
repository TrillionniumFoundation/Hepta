"""Independent GitHub Actions recovery, preserving pinned source and raw evidence.
Development tooling only. It neither activates production nor supplies runtime semantics.
"""
from hashlib import sha1, sha256
import ast, importlib.metadata, io, json, os, platform, resource, shutil, signal
import sqlite3, stat, subprocess, sys, tarfile, time, traceback, unicodedata
from pathlib import Path
sys.dont_write_bytecode = True
BASE = Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
REPO = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd())).resolve()
OUTPUT = Path(os.environ.get("HIA_CI_OUTPUT", "/tmp/hia-native-recovery-evidence")).resolve()
PREFIX = "review-evidence/hia-native-rewrite-20261111/"
PREPARED = False
STEPS = []
SOURCE_INDEX = []
REFERENCE_INDEX = []
PINS = {}
GIT_PACK_MAPPING = {"core.packedGitWindowSize": "16m", "core.packedGitLimit": "64m"}
def configure_git_pack_mapping():
    # Append command-scope settings, inherited by restorers and their Git children.
    # Preserve any pre-existing environment configuration without logging its values.
    count = int(os.environ.get("GIT_CONFIG_COUNT", "0"))
    assert count >= 0, "Invalid inherited Git configuration count"
    for key, value in GIT_PACK_MAPPING.items():
        os.environ["GIT_CONFIG_KEY_" + str(count)] = key
        os.environ["GIT_CONFIG_VALUE_" + str(count)] = value
        count += 1
    os.environ["GIT_CONFIG_COUNT"] = str(count)
    for key, value in GIT_PACK_MAPPING.items():
        actual = subprocess.check_output(
            ["/usr/bin/git", "config", "--get", key], cwd=REPO, text=True).strip()
        assert actual == value, (key, actual, value)
def digest(raw):
    return sha256(raw).hexdigest()
def git_blob(raw):
    return sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def pinned(relative, expected):
    path=REPO/relative
    raw=path.read_bytes()
    assert git_blob(raw)==expected,(relative,git_blob(raw),expected)
    PINS[path]=raw
    return raw
def materialize(relative,expected,destination):
    raw=pinned(relative,expected)
    destination=Path(destination)
    destination.parent.mkdir(parents=True,exist_ok=True)
    assert not destination.exists(),str(destination)
    if destination.suffix==".py": ast.parse(raw,filename=str(destination))
    with destination.open("xb") as handle: handle.write(raw)
    assert destination.read_bytes()==raw
    return destination
def run(label,args,cwd=None,timeout=900,env=None):
    assert label and label.replace("-","").replace("_","").isalnum()
    directory=OUTPUT/"steps"/label
    directory.mkdir(parents=True,exist_ok=False)
    before=resource.getrusage(resource.RUSAGE_CHILDREN)
    start=time.monotonic_ns()
    command=list(map(str,args))
    record=dict(label=label,argv=command,cwd=str(cwd or REPO),
                timeout_seconds=timeout,status="INCOMPLETE")
    save(directory/"process.json",record)
    timed_out=False
    with (directory/"stdout.log").open("xb") as out,(directory/"stderr.log").open("xb") as err:
        child=subprocess.Popen(command,cwd=cwd or REPO,stdout=out,stderr=err,
            env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1",**(env or {})},
            start_new_session=True)
        try: child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out=True
            os.killpg(child.pid,signal.SIGKILL)
            child.wait()
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    stdout=(directory/"stdout.log").read_bytes()
    stderr=(directory/"stderr.log").read_bytes()
    record.update(returncode=child.returncode,timed_out=timed_out,
        elapsed_ns=time.monotonic_ns()-start,
        child_cpu_seconds=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
        children_cumulative_maxrss_kib=after.ru_maxrss,
        stdout_bytes=len(stdout),stdout_sha256=digest(stdout),
        stderr_bytes=len(stderr),stderr_sha256=digest(stderr),
        status="PASS" if child.returncode==0 and not timed_out else "FAIL")
    save(directory/"process.json",record)
    STEPS.append(record)
    save(OUTPUT/"steps.json",STEPS)
    print(json.dumps({k:v for k,v in record.items() if k not in ("argv","cwd")}),flush=True)
    if record["status"]!="PASS":
        print(stderr[-12000:].decode("utf-8","replace"),file=sys.stderr,flush=True)
        raise RuntimeError("Independent recovery step failed: "+label)
    return record
def tree_index(root,commit):
    raw=subprocess.check_output(["/usr/bin/git","ls-tree","-rz","--long",commit],cwd=root)
    rows=[]
    for entry in raw.split(b"\0"):
        if not entry: continue
        meta,name=entry.split(b"\t",1)
        mode,kind,expected,size=meta.split()
        assert kind==b"blob" and mode in (b"100644",b"100755")
        path=root/os.fsdecode(name)
        data=path.read_bytes()
        assert path.is_file() and not path.is_symlink()
        assert (len(data),git_blob(data),stat.S_IMODE(path.stat().st_mode))==(int(size),expected.decode(),int(mode,8)&0o777)
        rows.append(dict(path=str(path),relative=os.fsdecode(name),bytes=len(data),
            git_sha=expected.decode(),sha256=digest(data),mode=int(mode,8)&0o777))
    return rows
def unchanged(rows):
    for row in rows:
        p=Path(row["path"])
        if not p.is_file() or p.is_symlink(): return False
        if stat.S_IMODE(p.stat().st_mode)!=row["mode"]: return False
        raw=p.read_bytes()
        if len(raw)!=row["bytes"] or digest(raw)!=row["sha256"]: return False
    return True
def prepare():
    global PREPARED,SOURCE_INDEX,REFERENCE_INDEX
    assert os.environ.get("GITHUB_ACTIONS")=="true","Use the independent CI environment"
    assert not BASE.exists(),"Fresh runner required; do not overwrite prior runs"
    OUTPUT.mkdir(parents=True,exist_ok=False)
    BASE.mkdir(mode=0o700)
    resource.setrlimit(resource.RLIMIT_AS,(1 << 30,1 << 30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    allowed_cpus=os.sched_getaffinity(0)
    assert allowed_cpus
    os.sched_setaffinity(0,{min(allowed_cpus)})
    identity=dict(parent_address_space_limit_bytes=1 << 30,parent_allowed_cpus=sorted(os.sched_getaffinity(0)),schema="hia-independent-ci-identity-v1",host="github-actions",
        run_id=os.environ.get("GITHUB_RUN_ID"),run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"),
        workflow=os.environ.get("GITHUB_WORKFLOW"),repository=os.environ.get("GITHUB_REPOSITORY"),
        commit=os.environ.get("GITHUB_SHA"),python=sys.version,
        executable=sys.executable,executable_sha256=digest(Path(sys.executable).resolve().read_bytes()),
        implementation=platform.python_implementation(),platform=platform.platform(),
        machine=platform.machine(),unicode_version=unicodedata.unidata_version,
        sqlite_version=sqlite3.sqlite_version,z3_distribution=importlib.metadata.version("z3-solver"),
        whole_stack_closed=False,production_activated=False)
    save(OUTPUT/"identity.json",identity)
    assert sys.version_info[:3]==(3,12,14),sys.version
    assert unicodedata.unidata_version=="15.0.0"
    assert platform.machine()=="x86_64"
    assert identity["z3_distribution"]=="4.15.4.0"
    configure_git_pack_mapping()
    save(OUTPUT/"git-pack-mapping.json",dict(settings=GIT_PACK_MAPPING,
        scope="process environment inherited by all recovery descendants",
        parent_address_space_limit_bytes=1 << 30,native_resource_limits_changed=False))
    head=subprocess.check_output(["/usr/bin/git","rev-parse","HEAD"],cwd=REPO,text=True).strip()
    assert head==identity["commit"],(head,identity["commit"])
    source=BASE/"source"
    baseline="a3c61136b79fdb7a4b6d6428fb4bdf31cd5ed270"
    run("checkout-pinned-baseline",["/usr/bin/git","worktree","add","--detach",source,baseline],timeout=300)
    actual_tree=subprocess.check_output(["/usr/bin/git","rev-parse","HEAD^{tree}"],cwd=source,text=True).strip()
    assert actual_tree=="a29123841003090d9a5759e152d7681a79568ce3"
    SOURCE_INDEX=tree_index(source,baseline)
    assert len(SOURCE_INDEX)==3350 and sum(row["bytes"] for row in SOURCE_INDEX)==496858110
    checkpoint=dict(schema="hia-independent-ci-source-checkout-v1",host="github-actions",
        source=str(source),head=baseline,tree=actual_tree,verified_files=len(SOURCE_INDEX),
        verified_bytes=sum(row["bytes"] for row in SOURCE_INDEX),
        verified_git_blob_bytes_modes_sizes=True)
    save(BASE/"RECOVERY_CHECKOUT.json",checkpoint)
    save(OUTPUT/"source-checkout.json",checkpoint)
    root_template=pinned(PREFIX+"remote-recovery-r1/restore_root_archives_r1.py",
        "9c3f0bcea935a9e074b20855b6084b75b38c4141")
    old=b'"host":"rog"'
    assert root_template.count(old)==1
    root_source=root_template.replace(old,b'"host":"github-actions"')
    script=BASE/"restore_root_archives_ci_r1.py"
    script.write_bytes(root_source)
    (OUTPUT/"sources").mkdir()
    (OUTPUT/"sources"/script.name).write_bytes(root_source)
    save(OUTPUT/"root-restorer-adaptation.json",dict(
        original_git_sha=git_blob(root_template),executed_sha256=digest(root_source),
        only_change="restore receipt host label rog -> github-actions; no archive/source/test changes"))
    run("restore-exact-published-root-archives",[sys.executable,"-B",script],timeout=600)
    reference_checkout=REPO/"ci-reference-source"
    reference_head=subprocess.check_output(
        ["/usr/bin/git","rev-parse","HEAD"],cwd=reference_checkout,text=True).strip()
    reference_tree=subprocess.check_output(
        ["/usr/bin/git","rev-parse","HEAD^{tree}"],cwd=reference_checkout,text=True).strip()
    assert reference_head=="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
    assert reference_tree=="6ef9e1713065436a3b1886fe9edcf0a4a1120773"
    run("import-exact-reference-objects",["/usr/bin/git","fetch","--no-tags","--depth=1",
        reference_checkout,reference_head],cwd=source,timeout=180)
    reference_template=pinned(PREFIX+"remote-recovery-r1/restore_reference_r2.py",
        "0b42cafc95e30da5e24b85ff9f97aab142e3a752")
    old=b'"first_attempt":"r1 failed archive mode/size assertion; original script and log retained"'
    assert reference_template.count(old)==1
    reference_source=reference_template.replace(old,
        b'"provenance":"independent CI restore using frozen ROG r2 source; no CI failure inherited"')
    script=BASE/"restore_reference_ci_r1.py"
    script.write_bytes(reference_source)
    (OUTPUT/"sources"/script.name).write_bytes(reference_source)
    save(OUTPUT/"reference-restorer-adaptation.json",dict(
        original_git_sha=git_blob(reference_template),executed_sha256=digest(reference_source),
        only_change="historical ROG first-attempt label replaced by explicit independent CI provenance"))
    run("restore-exact-reference",[sys.executable,"-B",script],timeout=300)
    ref=BASE/"root-recovery/reference-0ef-r2"
    receipt=json.loads((BASE/"root-recovery/REFERENCE_RECEIPT-r2.json").read_bytes())
    assert receipt["status"]=="PASS" and receipt["commit"]=="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
    assert receipt["files"]==2798 and receipt["bytes"]==100772825 and receipt["existing_difference_count"]==0
    rows=json.loads((BASE/"root-recovery/reference-0ef-r2-index.json").read_bytes())
    REFERENCE_INDEX=[dict(row,path=str(ref/row["path"])) for row in rows]
    assert unchanged(REFERENCE_INDEX)
    compiler=BASE/"root-recovery/workspace/native-edit-candidate-next/development/build-r1/source/1/B3.image.bin"
    assert (compiler.stat().st_size,digest(compiler.read_bytes()))==(669556,
        "35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
    for filename in ("RESTORE_RECEIPT.json","REFERENCE_RECEIPT-r2.json",
                     "reference-0ef-r2-index.json","workspace-index.json","overlays.json"):
        shutil.copyfile(BASE/"root-recovery"/filename,OUTPUT/filename)
    PREPARED=True
    context=dict(base=str(BASE),repo=str(REPO),source=str(source),reference=str(ref),
        workspace=str(BASE/"root-recovery/workspace"),compiler=str(compiler),
        output=str(OUTPUT),python=sys.executable)
    save(OUTPUT/"context.json",context)
    return context
def finish(scope,status,details,roots=None):
    assert status in ("PASS","FAIL")
    OUTPUT.mkdir(parents=True,exist_ok=True)
    exact_sources=PREPARED and unchanged(SOURCE_INDEX) and unchanged(REFERENCE_INDEX)
    exact_script_pins=all(path.read_bytes()==raw for path,raw in PINS.items())
    if status=="PASS": assert exact_sources and exact_script_pins
    summary=dict(schema="hia-independent-ci-qualification-v1",scope=scope,status=status,
        details=details,steps=STEPS,prepared=PREPARED,
        frozen_source_and_reference_before_after_equal=exact_sources,
        submitted_script_pins_before_after_equal=exact_script_pins,
        whole_stack_closed=False,production_activated=False,
        inherited_test_counts=False,original_ROG_launches_not_resolved_by_this_run=True)
    save(OUTPUT/"summary.json",summary)
    mapping={"run":OUTPUT}
    mapping.update({name:Path(path) for name,path in (roots or {}).items() if Path(path).exists()})
    members=[]
    seen=set()
    for label,root in sorted(mapping.items()):
        assert label and "/" not in label and label not in (".","..")
        root=root.resolve()
        assert root==OUTPUT or root.is_relative_to(BASE)
        files=[root] if root.is_file() else sorted(root.rglob("*"))
        for path in files:
            if path.is_dir():continue
            assert path.is_file() and not path.is_symlink()
            assert path.stat().st_nlink==1,(str(path),"multiple links")
            rel=path.name if root.is_file() else path.relative_to(root).as_posix()
            name=label+"/"+rel
            assert name not in seen
            seen.add(name)
            raw=path.read_bytes()
            members.append(dict(name=name,path=str(path),bytes=len(raw),
                mode=stat.S_IMODE(path.stat().st_mode),sha256=digest(raw)))
    index=OUTPUT/"evidence-members.json"
    save(index,members)
    archive=OUTPUT/"evidence.tar.xz"
    with tarfile.open(archive,"w:xz",preset=1) as tf:
        for row in members:
            p=Path(row["path"])
            raw=p.read_bytes()
            assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
            info=tarfile.TarInfo(row["name"])
            info.size=len(raw);info.mode=row["mode"];info.mtime=0;info.uid=info.gid=0
            info.uname=info.gname=""
            tf.addfile(info,io.BytesIO(raw))
    expected={r["name"]:r for r in members}
    checked=set()
    with tarfile.open(archive,"r:xz") as tf:
        for item in tf:
            assert item.isfile() and item.name not in checked
            row=expected[item.name]
            raw=tf.extractfile(item).read()
            assert (len(raw),digest(raw),item.mode)==(row["bytes"],row["sha256"],row["mode"])
            checked.add(item.name)
    assert checked==set(expected)
    assert all(Path(row["path"]).stat().st_size==row["bytes"] and
        stat.S_IMODE(Path(row["path"]).stat().st_mode)==row["mode"] and
        digest(Path(row["path"]).read_bytes())==row["sha256"] for row in members)
    custody=dict(schema="hia-independent-ci-artifact-custody-v1",scope=scope,status=status,
        archive=str(archive),bytes=archive.stat().st_size,sha256=digest(archive.read_bytes()),
        members=len(members),original_bytes=sum(r["bytes"] for r in members),
        member_index_bytes=index.stat().st_size,member_index_sha256=digest(index.read_bytes()),
        all_original_and_tar_member_bytes_sha256_modes_readback=True,
        whole_stack_closed=False)
    save(OUTPUT/"custody.json",custody)
    print(json.dumps(custody,sort_keys=True),flush=True)
    step_summary=os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary,"a") as f:
            f.write("## Native recovery "+scope+"\n\n")
            f.write("Status: **"+status+"**. This is an independent component qualification; whole-stack closure remains open.\n\n")
            f.write("Artifact: "+custody["sha256"]+" ("+str(custody["bytes"])+" bytes), "+str(len(members))+" verified members.\n\n")
    return summary,custody
