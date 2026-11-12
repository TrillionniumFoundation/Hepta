"""Read every original R9 explicit-importer byte before exporting its owners.

The historical 37-image importer is distinct from the ordinary P16 role table.
This reader executes no original module, compiler, image, ELF or test. It keeps
the original archive/ledger/custody, exports exact source bytes and bundle data,
and records every original path, mode and hash. Console export is explicitly
bounded; complete selected originals remain in the output artifact.
"""
from __future__ import annotations
import argparse,base64,json,lzma,os,platform,resource,signal,stat,subprocess,sys,tarfile,time,traceback
from hashlib import sha1,sha256
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
STARTED=time.monotonic_ns()
PLAN=json.loads(r'''{"name":"R9-explicit-importer","archive":{"gitsha":"a75abe1202c5b35e1411ba1d4fd69e33faa4e236","bytes":4595336,"sha256":"19c16b47ab03bad544bca724a23988ff65600e3739cfd0fde3052472a2fed1db","path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/legacy-import-r3.tar.xz"},"ledger":{"gitsha":"a54869645bf2e5c952b944c77a736549cf550dee","bytes":69184,"sha256":"10ec135b2661c5507e769d6fae693ec09a370e5f3ed9c76b04a5267fb2cfc555","original_bytes":1116524,"original_sha256":"1d8a45345e150dd548e1b94d6b2f9bc85fc021fd67e09d7b4b038d540821071d","path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/legacy-import-original-member-manifest.json.xz"},"custody":{"gitsha":"4303f24270508bea95812f01d376f8fa8fe095a5","bytes":1737,"path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/legacy-import-r3-custody.json","sha256":"85629375c887ecfb1fe5c26deff5c1323c8b48e59d66e21ad3e9919450634e3f"},"members":2949,"files":2389,"raw_file_bytes":71724847}''')
REFERENCE=dict(path="hepta/hia_core_upgrade.py",gitsha="b44d36b28e00a79391df7d4ef26bb6eb91d7f26a",
    bytes=8607,sha256="550608c7b654c0af45cda8f122230188c1989069fda2dac4e05c285f7ce77570")
DRIVER_BYTES=17529
DRIVER_SHA="53cdf4ce01c8f14ab4894062fdc321a124f0b2ed16e39e284876d7eb37f9968c"
INPUTS={}
PENDING={}
OUTPUTS={}
CONSOLE_RAW_LIMIT=400000

def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def absolute_cpu():
    own=resource.getrusage(resource.RUSAGE_SELF)
    child=resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime+own.ru_stime+child.ru_utime+child.ru_stime
def fact(path):
    path=Path(path);info=path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink(),str(path)
    size=0;hasher=sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1<<20),b""):
            size+=len(chunk);hasher.update(chunk)
    return dict(path=str(path.resolve()),bytes=size,sha256=hasher.hexdigest(),mode=stat.S_IMODE(info.st_mode))
def safe_name(name):
    assert type(name) is str and name and "\0" not in name and "\\" not in name,name
    path=PurePosixPath(name)
    assert not path.is_absolute() and path.as_posix()==name,name
    assert all(part not in ("",".","..") for part in name.split("/")),name
    return path
def write_raw(path,raw,mode=0o644):
    path=Path(path).resolve();path.parent.mkdir(parents=True,exist_ok=True)
    wanted=dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=mode)
    key=str(path);assert key not in OUTPUTS and key not in PENDING,key
    PENDING[key]=wanted
    with path.open("xb") as stream:stream.write(raw)
    path.chmod(mode)
    assert fact(path)==wanted,(key,"completed write/readback")
    OUTPUTS[key]=wanted;PENDING.pop(key)
    return wanted
def write_json(path,value):
    return write_raw(path,(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n").encode("utf-8"))
def original_export(row,raw):
    assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"])
    print("HIA_EXPLICIT_LEGACY_ORIGINAL "+json.dumps(
        dict(row,base64=base64.b64encode(raw).decode("ascii")),sort_keys=True),flush=True)
def selected(path):
    name=path.name
    return (path.suffix in (".py",".S",".s",".md") or
        name in ("bundle.json","source.json","source-before.json","source-after.json",
                 "source-manifest.json","source-pins.json","manifest.json",
                 "FINAL_SOURCE_MANIFEST.json") or name.endswith(".manifest.json"))
def console_priority(row):
    name=row["basename"];lower=name.lower()
    member_names=" ".join(row["original_members"]).lower()
    is_legacy="legacy" in lower or "import" in lower
    is_python=name.endswith(".py")
    is_assembly=name.endswith((".S",".s"))
    if is_python and is_legacy and name.startswith("generate_"):rank=0
    elif is_assembly:rank=1
    elif name=="bundle.json":rank=2
    elif is_python and is_legacy and name.startswith("build_"):rank=3
    elif is_legacy and name.endswith(".md"):rank=4
    elif is_python and is_legacy:rank=5
    else:rank=100
    # A later historical revision is printed before its retained predecessors.
    revision=0 if "r3" in member_names else 1 if "r2" in member_names else 2
    return rank,revision,row["basename"],row["sha256"]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();repo=args.repo.resolve();out=args.out.resolve()
    out.mkdir(parents=True,exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def expired(signum,frame):
        raise TimeoutError("Original readonly wall budget 180 seconds")
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,180)
    git=["/usr/bin/git","-c","core.packedGitWindowSize=16m","-c","core.packedGitLimit=64m"]
    status="FAIL";primary=None;after_errors=[];checked=[];exports=[];console=[]
    exact_archive=False;ledger_complete=False;selected_complete=False;source_before={};head=None
    archive=out/"original"/"legacy-import-r3.tar.xz"
    def fetch(row,path):
        raw=subprocess.check_output(git+["cat-file","blob",row["gitsha"]],cwd=repo,timeout=30)
        assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"]),row["path"]
        record=subprocess.check_output(git+["ls-tree","-z","--long","HEAD","--",row["path"]],cwd=repo,timeout=30)
        assert record.endswith(b"\0") and len(record.split(b"\0"))==2,row["path"]
        meta,name=record[:-1].split(b"\t",1)
        mode,kind,identity,size=meta.split()
        assert (mode,kind,identity,size,name)==(
            b"100644",b"blob",row["gitsha"].encode(),str(row["bytes"]).encode(),row["path"].encode()),row["path"]
        write_raw(path,raw)
        return raw
    try:
        self_path=Path(__file__).resolve();INPUTS[str(self_path)]=fact(self_path)
        assert sys.version_info[:3]==(3,12,14),sys.version
        assert platform.machine()=="x86_64",platform.machine()
        head=subprocess.check_output(git+["rev-parse","HEAD"],cwd=repo,timeout=30).decode("ascii").strip()
        assert len(head)==40
        if os.environ.get("GITHUB_SHA"):assert head==os.environ["GITHUB_SHA"]
        for key in ("archive","ledger","custody"):
            path=repo/PLAN[key]["path"]
            before=fact(path);INPUTS[str(path.resolve())]=before
            assert (before["bytes"],before["sha256"],before["mode"])==(
                PLAN[key]["bytes"],PLAN[key]["sha256"],0o644),str(path)
            source_before[key]=before
        reference_path=repo/REFERENCE["path"]
        reference_before=fact(reference_path);INPUTS[str(reference_path.resolve())]=reference_before
        assert (reference_before["bytes"],reference_before["sha256"],reference_before["mode"])==(
            REFERENCE["bytes"],REFERENCE["sha256"],0o644)
        source_before["reference"]=reference_before
        fetch(PLAN["archive"],archive)
        ledger_xz=fetch(PLAN["ledger"],out/"original"/"legacy-import-members.json.xz")
        ledger_raw=lzma.decompress(ledger_xz)
        assert (len(ledger_raw),digest(ledger_raw))==(PLAN["ledger"]["original_bytes"],PLAN["ledger"]["original_sha256"])
        write_raw(out/"original"/"legacy-import-members.json",ledger_raw)
        custody_raw=fetch(PLAN["custody"],out/"original"/"legacy-import-custody.json")
        reference_raw=fetch(REFERENCE,out/"original"/"hia_core_upgrade.py")
        custody=json.loads(custody_raw)
        assert (custody["bytes"],custody["sha256"],custody["members"],custody["file_members"],custody["raw_file_bytes"])==(
            PLAN["archive"]["bytes"],PLAN["archive"]["sha256"],PLAN["members"],PLAN["files"],PLAN["raw_file_bytes"])
        assert (custody["member_manifest"]["bytes"],custody["member_manifest"]["sha256"])==(
            len(ledger_raw),digest(ledger_raw))
        rows=json.loads(ledger_raw)["members"]
        assert type(rows) is list and len(rows)==PLAN["members"]
        expected={}
        for row in rows:
            safe_name(row["path"]);assert row["path"] not in expected,row["path"]
            assert row["kind"] in ("directory","file")
            assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
            expected[row["path"]]=row
        seen=set();files=0;directories=0;total=0;unique={}
        with tarfile.open(archive,"r|xz") as tf:
            for member in tf:
                path=safe_name(member.name)
                assert member.name not in seen and member.name in expected,member.name
                seen.add(member.name);row=expected[member.name]
                assert member.mode==row["mode"],member.name
                if member.isdir():
                    assert row["kind"]=="directory"
                    directories+=1
                    checked.append(dict(path=member.name,kind="directory",mode=member.mode))
                    continue
                assert member.isfile() and not member.islnk() and not member.issym(),member.name
                assert row["kind"]=="file" and member.size==row["bytes"],member.name
                keep=selected(path);chunks=[] if keep else None
                hasher=sha256();size=0
                handle=tf.extractfile(member);assert handle is not None
                with handle:
                    for chunk in iter(lambda:handle.read(1<<20),b""):
                        hasher.update(chunk);size+=len(chunk)
                        if chunks is not None:chunks.append(chunk)
                assert (size,hasher.hexdigest())==(row["bytes"],row["sha256"]),member.name
                files+=1;total+=size
                checked.append(dict(path=member.name,kind="file",bytes=size,sha256=hasher.hexdigest(),mode=member.mode))
                if keep:
                    raw=b"".join(chunks);key=(row["sha256"],path.name,member.mode)
                    if key in unique:
                        assert unique[key]["raw"]==raw
                        unique[key]["members"].append(member.name)
                    else:unique[key]=dict(raw=raw,basename=path.name,mode=member.mode,members=[member.name])
        assert seen==set(expected)
        assert (len(seen),files,directories,total)==(
            PLAN["members"],PLAN["files"],PLAN["members"]-PLAN["files"],PLAN["raw_file_bytes"])
        ledger_complete=True
        # No original source is exported or inspected until every member passed.
        write_json(out/"complete-original-member-readback.json",checked)
        for (sha,basename,mode),value in sorted(unique.items()):
            raw=value["raw"]
            destination=out/"recovered"/sha/str(mode)/basename
            saved=write_raw(destination,raw,mode)
            row=dict(basename=basename,path=str(destination.relative_to(out)),
                bytes=len(raw),sha256=sha,gitsha=gitsha(raw),mode=mode,
                original_members=value["members"],complete_archive_readback_before_export=True,
                original_code_executed=False,original_AST_performed=False)
            exports.append(row)
        selected_complete=len(exports)==len(unique)
        assert selected_complete
        required_driver=[row for row in exports if row["basename"]=="generate_hia_legacy_import_driver.py"
            and (row["bytes"],row["sha256"])==(DRIVER_BYTES,DRIVER_SHA)]
        assert required_driver,"Exact original importer author absent; no substitute permitted"
        assert any(row["basename"].endswith((".S",".s")) for row in exports),"Original fixed executor source missing"
        assert any(row["basename"]=="bundle.json" for row in exports),"Original image bundle missing"
        write_json(out/"complete-selected-source-bundle-inventory.json",exports)
        executable_candidates=[row for row in checked if row["kind"]=="file" and
            (row["mode"]&0o111 or row["path"].endswith((".elf",".bin",".hiaasm")))]
        write_json(out/"complete-image-executable-source-inventory.json",executable_candidates)
        consumed=0
        for row in sorted(exports,key=console_priority):
            rank=console_priority(row)[0]
            if rank==100:continue
            if row["bytes"]>262144 or consumed+row["bytes"]>CONSOLE_RAW_LIMIT:continue
            raw=(out/row["path"]).read_bytes()
            original_export(row,raw);console.append(row);consumed+=len(raw)
        status="PASS"
    except BaseException as exc:
        primary=dict(type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        # No original failure may bypass full input/self/output after-checks.
        signal.setitimer(signal.ITIMER_REAL,0)
        for collection,label in ((INPUTS,"original-input-or-self"),(OUTPUTS,"completed-output")):
            for key,before in list(collection.items()):
                try:
                    assert fact(key)==before,(label,key,"bytes/mode changed")
                    if key==str(archive):exact_archive=True
                except BaseException as exc:
                    after_errors.append(dict(scope=label,path=key,type=type(exc).__name__,
                        error=str(exc),traceback=traceback.format_exc()))
        partial=[]
        for key,wanted in PENDING.items():
            item=dict(wanted)
            try:item["actual_partial"]=fact(key) if Path(key).exists() else None
            except BaseException as exc:item["inspection_error"]=dict(type=type(exc).__name__,error=str(exc))
            partial.append(item)
        cpu=absolute_cpu();elapsed=time.monotonic_ns()-STARTED
        if cpu>=90:after_errors.append(dict(scope="aggregate-process-tree-CPU",actual=cpu,limit=90))
        if elapsed>=180000000000:after_errors.append(dict(scope="complete-wall",actual_ns=elapsed,limit_ns=180000000000))
        if primary or after_errors or partial:status="FAIL"
        report=dict(schema="hia-explicit-legacy-original-owners-readback-r1",status=status,submitted_head=head,
            original_archive=PLAN,reference=REFERENCE,source_before=source_before,
            complete_original_archive_retained_and_afterchecked=exact_archive,
            complete_original_ledger_verified=ledger_complete,
            verified_member_count=len(checked),selected_unique_originals=len(exports),
            selected_source_and_bundle_bytes=sum(row["bytes"] for row in exports),
            console_original_count=len(console),console_original_bytes=sum(row["bytes"] for row in console),
            console_raw_byte_limit=CONSOLE_RAW_LIMIT,console_is_selected_not_complete_inventory=True,
            complete_selected_originals_retained_in_artifact=selected_complete and not partial and not after_errors,
            primary_error=primary,after_errors=after_errors,pending_partial_files=partial,
            input_aftercheck_count=len(INPUTS),completed_output_aftercheck_count=len(OUTPUTS),
            aggregate_CPU_seconds=cpu,elapsed_ns=elapsed,limits=dict(CPU=90,wall=180,AS=1<<30),
            original_AST=0,project_imports=0,HIA_generation=0,B3=0,native_entries=0,
            original_tests_reexecuted=0,new_public_qualification=False,
            ordinary_P16_does_not_run_explicit_importer=True,whole_Worker_closed=False)
        write_json(out/"console-originals-index.json",console)
        write_json(out/"materialized-originals-aftercheck.json",list(OUTPUTS.values()))
        write_json(out/"summary.json",report)
        for name in ("console-originals-index.json","materialized-originals-aftercheck.json","summary.json"):
            assert fact(out/name)==OUTPUTS[str((out/name).resolve())]
        final_cpu=absolute_cpu();final_elapsed=time.monotonic_ns()-STARTED
        if final_cpu>=90 or final_elapsed>=180000000000:
            status="FAIL"
            write_json(out/"final-budget-failure.json",dict(status="FAIL",
                aggregate_CPU_seconds=final_cpu,elapsed_ns=final_elapsed,limit_CPU=90,limit_wall=180))
        compact={key:value for key,value in report.items() if key not in ("original_archive","source_before")}
        compact.update(status=status,summary=OUTPUTS[str((out/"summary.json").resolve())],
            final_aggregate_CPU_seconds=final_cpu,final_elapsed_ns=final_elapsed)
        print("HIA_EXPLICIT_LEGACY_ORIGINAL_READBACK "+json.dumps(compact,sort_keys=True),flush=True)
        post_console_cpu=absolute_cpu();post_console_elapsed=time.monotonic_ns()-STARTED
        if not (0<=post_console_cpu<90 and 0<=post_console_elapsed<180000000000):
            status="FAIL"
            write_json(out/"post-console-budget-failure.json",dict(
                status="FAIL",scope="complete reader including final flushed console output",
                aggregate_CPU_seconds=post_console_cpu,elapsed_ns=post_console_elapsed,
                limit_CPU=90,limit_wall=180,primary_error=primary,after_errors=after_errors,
                summary=OUTPUTS[str((out/"summary.json").resolve())]))
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
