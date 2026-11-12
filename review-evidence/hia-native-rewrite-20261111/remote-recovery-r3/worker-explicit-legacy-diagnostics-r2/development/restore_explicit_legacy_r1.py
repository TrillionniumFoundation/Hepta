"""Complete R9 importer archive restoration before any new target import.

This is a source/image dependency reader. It does not run the historical tests,
compiler, importer or executor. All 2949 members are verified before a portable
37-role table is returned to the separately bounded new build.
"""
from __future__ import annotations
import argparse,json,lzma,os,resource,signal,stat,subprocess,sys,tarfile,time,traceback
from hashlib import sha1,sha256
from pathlib import Path,PurePosixPath
PLAN={"name":"R9-explicit-importer","archive":{"gitsha":"a75abe1202c5b35e1411ba1d4fd69e33faa4e236","bytes":4595336,"sha256":"19c16b47ab03bad544bca724a23988ff65600e3739cfd0fde3052472a2fed1db","path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/legacy-import-r3.tar.xz"},"ledger":{"gitsha":"a54869645bf2e5c952b944c77a736549cf550dee","bytes":69184,"sha256":"10ec135b2661c5507e769d6fae693ec09a370e5f3ed9c76b04a5267fb2cfc555","original_bytes":1116524,"original_sha256":"1d8a45345e150dd548e1b94d6b2f9bc85fc021fd67e09d7b4b038d540821071d","path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/legacy-import-original-member-manifest.json.xz"},"custody":{"gitsha":"4303f24270508bea95812f01d376f8fa8fe095a5","bytes":1737,"path":"review-evidence/hia-native-rewrite-20261111/reconstructed-components-r9/legacy-import-r3-custody.json","sha256":"85629375c887ecfb1fe5c26deff5c1323c8b48e59d66e21ad3e9919450634e3f"},"members":2949,"files":2389,"raw_file_bytes":71724847}
BUNDLE_MEMBER="importer/development/build-r3/bundle.json"
BUNDLE_BYTES=46296
BUNDLE_SHA="cef4fe1edfe8394cde3e2b6bac3f69043aaf73f841052f99c0be30c9b600f339"
OLD_PREFIX="/workspace/scratch/9acdfa9f5639/"
OLD_IMPORTER=OLD_PREFIX+"native-composite-legacy-import-next/"
ROLES=tuple(range(1,30))+tuple(range(40,48))
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def safe(name):
    assert type(name) is str and name and "\0" not in name and "\\" not in name
    p=PurePosixPath(name)
    assert not p.is_absolute() and p.as_posix()==name
    assert all(x not in ("",".","..") for x in name.split("/"))
    return p
def fact(path):
    path=Path(path);s=path.lstat()
    assert stat.S_ISREG(s.st_mode) and not path.is_symlink(),str(path)
    h=sha256();n=0
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1<<20),b""):h.update(block);n+=len(block)
    return dict(path=str(path.resolve()),bytes=n,sha256=h.hexdigest(),mode=stat.S_IMODE(s.st_mode))
def cpu():
    a=resource.getrusage(resource.RUSAGE_SELF);b=resource.getrusage(resource.RUSAGE_CHILDREN)
    return a.ru_utime+a.ru_stime+b.ru_utime+b.ru_stime
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repo",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();repo=args.repo.resolve();out=args.out.resolve()
    assert sys.version_info[:3]==(3,12,14)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    start=time.monotonic_ns()
    def alarm(*_):raise TimeoutError("Original restoration180wall")
    signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,180)
    out.mkdir(parents=True,exist_ok=False)
    originals=out/"originals";originals.mkdir()
    members=out/"members";members.mkdir()
    inputs={};written={};pending={};checked=[];directories=[];errors=[]
    primary=None;status="FAIL";portable=None;summary={}
    def write(path,raw,mode=0o644):
        path.parent.mkdir(parents=True,exist_ok=True)
        row=dict(path=str(path.resolve()),bytes=len(raw),sha256=digest(raw),mode=mode)
        pending[str(path)]=row
        with path.open("xb") as f:f.write(raw)
        path.chmod(mode);assert fact(path)==row
        written[str(path)]=row;pending.pop(str(path))
        return path
    def save(path,value):return write(path,(json.dumps(value,sort_keys=True,indent=2)+"\n").encode())
    def fetched(row,target):
        origin=repo/row["path"];p=fact(origin);inputs[str(origin)]=p
        assert (p["bytes"],p["sha256"],p["mode"])==(row["bytes"],row["sha256"],0o644)
        raw=subprocess.check_output(["/usr/bin/git","cat-file","blob",row["gitsha"]],cwd=repo,timeout=30)
        assert raw==origin.read_bytes()
        assert (len(raw),digest(raw),gitsha(raw))==(row["bytes"],row["sha256"],row["gitsha"])
        write(target,raw);return raw
    try:
        own=Path(__file__).resolve();inputs[str(own)]=fact(own)
        archive=originals/"legacy-import-r3.tar.xz"
        fetched(PLAN["archive"],archive)
        ledger=lzma.decompress(fetched(PLAN["ledger"],originals/"member-manifest.json.xz"))
        assert (len(ledger),digest(ledger))==(PLAN["ledger"]["original_bytes"],PLAN["ledger"]["original_sha256"])
        write(originals/"member-manifest.json",ledger)
        custody=json.loads(fetched(PLAN["custody"],originals/"custody.json"))
        assert (custody["bytes"],custody["sha256"],custody["members"],custody["file_members"],custody["raw_file_bytes"])==(
            PLAN["archive"]["bytes"],PLAN["archive"]["sha256"],2949,2389,71724847)
        assert (custody["member_manifest"]["bytes"],custody["member_manifest"]["sha256"])==(len(ledger),digest(ledger))
        rows=json.loads(ledger)["members"];assert len(rows)==2949
        expected={}
        for row in rows:
            safe(row["path"]);assert row["path"] not in expected
            assert row["kind"] in ("directory","file")
            assert type(row["mode"]) is int and 0<=row["mode"]<=0o777
            expected[row["path"]]=row
        seen=set();total=0;files=0
        with tarfile.open(archive,"r|xz") as tf:
            for member in tf:
                rel=safe(member.name);assert member.name in expected and member.name not in seen
                seen.add(member.name);row=expected[member.name]
                assert member.mode==row["mode"]
                target=members/rel
                if member.isdir():
                    assert row["kind"]=="directory"
                    target.mkdir(parents=True,exist_ok=True)
                    directories.append((target,member.mode))
                    checked.append(dict(path=member.name,kind="directory",mode=member.mode))
                    continue
                assert member.isfile() and not member.issym() and not member.islnk()
                assert row["kind"]=="file" and member.size==row["bytes"]
                handle=tf.extractfile(member);assert handle is not None
                with handle:raw=handle.read()
                assert len(raw)==row["bytes"] and digest(raw)==row["sha256"]
                write(target,raw,member.mode)
                checked.append(dict(path=member.name,kind="file",bytes=len(raw),sha256=digest(raw),mode=member.mode))
                total+=len(raw);files+=1
        assert seen==set(expected) and (len(seen),files,len(directories),total)==(2949,2389,560,71724847)
        for directory,mode in reversed(directories):directory.chmod(mode)
        # Only after the entire immutable archive passes may a table be used.
        raw=(members/BUNDLE_MEMBER).read_bytes()
        assert (len(raw),digest(raw),gitsha(raw))==(BUNDLE_BYTES,BUNDLE_SHA,"38321b2cb2ab2f9019916683c9a71d4b77ce2508")
        bundle=json.loads(raw)
        assert bundle["status"]=="PASS" and set(map(int,bundle["components"]))==set(ROLES)
        assert bundle["compiler_sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
        def locate(origin,size,sha,mode=0o644):
            assert type(origin) is str and Path(origin).is_absolute()
            mapped=None
            if origin.startswith(OLD_IMPORTER):mapped="importer/"+origin[len(OLD_IMPORTER):]
            elif origin.startswith(OLD_PREFIX):mapped="dependencies/"+origin[len(OLD_PREFIX):]
            choices=[r for r in checked if r["kind"]=="file" and
                (r["bytes"],r["sha256"],r["mode"])==(size,sha,mode)]
            assert choices,(origin,size,sha,mode)
            preferred=[r for r in choices if r["path"]==mapped]
            chosen=preferred[0] if preferred else sorted(choices,key=lambda r:r["path"])[0]
            actual=members/chosen["path"];value=actual.read_bytes()
            assert all((members/r["path"]).read_bytes()==value for r in choices)
            return dict(path=str(actual),bytes=size,sha256=sha,mode=mode,
                original_path=origin,member=chosen["path"],exact_mapped_member=bool(preferred),
                all_identity_matched_members=[r["path"] for r in choices])
        roles={}
        for role in ROLES:
            row=bundle["components"][str(role)];assert row["role"]==role
            source=locate(row["source_path"],row["source_bytes"],row["source_sha256"])
            expected_source=locate(row["expected_source_path"],row["source_bytes"],row["source_sha256"])
            image=locate(row["image_path"],row["image_bytes"],row["image_sha256"])
            assert Path(source["path"]).read_bytes()==Path(expected_source["path"]).read_bytes()
            roles[str(role)]=dict(role=role,source=source,image=image,expected_source=expected_source,
                original_metadata=row)
        pack=bundle["packer"];r=pack["receipt"]
        packer=dict(source=locate(pack["source"],r["input_bytes"],pack["source_sha256"]),
            image=locate(pack["image"],r["produced_bytes"],pack["image_sha256"]),
            original_receipt=r)
        oldexe=bundle["executable"]
        executable=locate(oldexe["path"],oldexe["bytes"],oldexe["sha256"],0o755)
        portable=dict(schema="hia-explicit-legacy-complete-original-portable-bundle-r1",
            status="VERIFIED_ORIGINAL_BYTES_ONLY",archive=PLAN,original_bundle_sha256=BUNDLE_SHA,
            original_bundle_path=str(members/BUNDLE_MEMBER),components=roles,packer=packer,
            executable=executable,compiler_sha256=bundle["compiler_sha256"],
            original_members=2949,original_files=2389,original_raw_file_bytes=71724847,
            generated_HIA=0,new_B3=0,new_native=0,old_tests_reexecuted=False)
        save(out/"portable-original-bundle.json",portable)
        save(out/"full-member-readback.json",checked)
        status="PASS"
    except BaseException as exc:
        primary=exc
        try:traceback.print_exc()
        except BaseException as diagnostic:errors.append(dict(phase="traceback",type=type(diagnostic).__name__))
    finally:
        for scope,collection in (("input",inputs),("materialized",written)):
            for path,before in collection.items():
                try:assert fact(path)==before
                except BaseException as exc:
                    errors.append(dict(scope=scope,path=path,type=type(exc).__name__,error=str(exc)))
                    if primary is None:primary=exc
        for path,mode in directories:
            try:assert path.is_dir() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode)==mode
            except BaseException as exc:
                errors.append(dict(scope="directory",path=str(path),type=type(exc).__name__))
                if primary is None:primary=exc
        if pending or errors or primary is not None:status="FAIL"
        used=cpu();elapsed=time.monotonic_ns()-start
        if not (0<=used<90 and 0<=elapsed<180_000_000_000):
            status="FAIL";errors.append(dict(scope="budget",cpu=used,elapsed_ns=elapsed))
        summary=dict(schema="hia-explicit-legacy-full-original-restoration-r1",status=status,
            members=len(checked),files=sum(r["kind"]=="file" for r in checked),
            original_archive=PLAN["archive"],input_count=len(inputs),materialized_count=len(written),
            pending=list(pending.values()),after_errors=errors,
            primary=None if primary is None else dict(type=type(primary).__name__,error=str(primary)),
            complete_original_members_retained_and_verified=bool(portable) and not pending and not errors,
            source_imports=0,new_B3=0,new_native=0,aggregate_CPU_seconds=used,elapsed_ns=elapsed)
        def output_attempt(phase,fn):
            nonlocal primary,status
            try:fn()
            except BaseException as exc:
                status="FAIL";errors.append(dict(phase=phase,type=type(exc).__name__,error=str(exc)))
                if primary is None:primary=exc
        def summary_write():
            summary["status"]=status
            summary["primary"]=None if primary is None else dict(type=type(primary).__name__,error=str(primary))
            (out/"summary.json").write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
        output_attempt("aftercheck",lambda:(out/"all-inputs-and-materialized-pins.json").write_text(
            json.dumps(dict(inputs=inputs,materialized=written),sort_keys=True,indent=2)+"\n"))
        output_attempt("summary",summary_write)
        output_attempt("console",lambda:print("HIA_LEGACY_ORIGINAL_RESTORATION "+json.dumps(
            {k:v for k,v in summary.items() if k not in ("original_archive","pending","after_errors")},sort_keys=True),flush=True))
        output_attempt("disable_alarm",lambda:signal.setitimer(signal.ITIMER_REAL,0))
        used=cpu();elapsed=time.monotonic_ns()-start
        if not (0<=used<90 and 0<=elapsed<180_000_000_000):
            status="FAIL";errors.append(dict(scope="post-output-budget",cpu=used,elapsed_ns=elapsed))
        if status!="PASS":output_attempt("failure-summary",summary_write)
    if primary is not None:raise primary
    return 0 if status=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
