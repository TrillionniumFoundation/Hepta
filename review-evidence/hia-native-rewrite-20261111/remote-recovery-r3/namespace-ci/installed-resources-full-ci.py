"""Focused actual source/sdist/wheel/installed-resource gate, with original raw custody.

Runs the complete existing module:3 source tests and17 actual installed-resource
tests. No assertion, timeout, native build or fallback policy is replaced.
"""
import sys
sys.dont_write_bytecode=True
import contextlib,hashlib,io,json,os,platform,shutil,stat,subprocess,tarfile,time,traceback,unittest
from pathlib import Path
EXPECTED=[{"path":"MANIFEST.in","blob":"d5c48443144dc55638d2a295f85dd03e83753790","bytes":2356,"sha256":"be75342d4545f7e8213bd5da0c16a6c085bd46a924bec8f955e850584728de52"},{"path":"tools/hia_selfhost_contract.py","blob":"9301f6130754304255a8c1def20668ff07ec9bdf","bytes":66312,"sha256":"ee4c52cc2078df94264e2aff989fd8cff7cad80df0f511e46e08bb69c78a149d"},{"path":"tests/test_hia_agent_installed_resources.py","blob":"02cf4cc33f53cf2605f670bf45184fa55f27f901","bytes":30676,"sha256":"0c85a50e6cd26c81624b68535a4911a20d64566a229dec92ae44d9f4fefd029e"},{"path":"docs/HIA_SELFHOST_CORE_SUPPORT.json","blob":"6de076689c0b7e5f8410c5fcc3457900446e7144","bytes":107840,"sha256":"67d98a62b6cdd7f1226426fdb42b24dbe7a3f549c05200d19f764315cd8b4721"}]
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def file_pin(path):
    info=path.lstat();assert stat.S_ISREG(info.st_mode)
    raw=path.read_bytes();assert len(raw)==info.st_size
    return dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
def main():
    root=Path(os.environ.get("GITHUB_WORKSPACE",Path.cwd())).resolve()
    out=Path(os.environ["HIA_CI_OUTPUT"]).absolute()
    assert not out.is_relative_to(root)
    out.mkdir(parents=True,exist_ok=False)
    (out/"submitted-driver.py").write_bytes(Path(__file__).read_bytes())
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    assert sys.version_info[:2]==(3,14),sys.version
    before={};failure=None;module=None
    report=dict(schema="hia.installed-resource-complete-focused-gate.v1",status="INCOMPLETE",
        whole_native_delivery_qualified=False,source_root=str(root),python=sys.version,
        platform=platform.platform(),scope="COMPLETE_EXISTING20_TEST_MODULE_WITH_REAL_SDIST_WHEEL_AND_INSTALLED_NATIVE_WORKER",
        source_only_reconstruction_not_claimed=True,all_test_ids_preserved=True,
        original_failure_run=43109366123,original_failure_head="d1e2ffda9369afcd198210fba5878c7a7b9c7ea8",
        actual_native_entry_count=None,original_compile_limits_unchanged=True,raw_captures=[])
    captured=False
    def capture():
        nonlocal captured
        if captured or module is None:return
        folder=getattr(module.AgentInstalledResourceTests,"folder",None)
        if folder is None or not Path(folder).is_dir():return
        folder=Path(folder);destination=out/"original-installed-resource-fixture";destination.mkdir()
        rows=[]
        for path in [folder,*sorted(folder.rglob("*"))]:
            info=path.lstat();relative="." if path==folder else path.relative_to(folder).as_posix()
            row=dict(relative=relative,kind=stat.S_IFMT(info.st_mode),mode=stat.S_IMODE(info.st_mode),
                device=info.st_dev,inode=info.st_ino,nlink=info.st_nlink,bytes=info.st_size)
            if stat.S_ISDIR(info.st_mode):
                (destination/relative).mkdir(parents=True,exist_ok=True)
            elif stat.S_ISREG(info.st_mode):
                raw=path.read_bytes();assert len(raw)==info.st_size
                target=destination/relative;target.parent.mkdir(parents=True,exist_ok=True)
                with target.open("xb") as stream:stream.write(raw)
                target.chmod(row["mode"]);assert target.read_bytes()==raw
                row["sha256"]=sha(raw)
            elif stat.S_ISLNK(info.st_mode):
                # Record a link itself; never follow fixture links while sealing.
                row["target_hex"]=os.fsencode(os.readlink(path)).hex()
            else:
                row["captured_as_metadata_only"]=True
            rows.append(row)
        save(out/"fixture-members.json",rows)
        report["raw_captures"].append(dict(source=str(folder),destination=str(destination),
            entries=len(rows),regular_members=sum(r["kind"]==stat.S_IFREG for r in rows),
            original_regular_bytes=sum(r["bytes"] for r in rows if r["kind"]==stat.S_IFREG),
            original_hardlink_identity_preserved_in_manifest=True,
            captured_regular_copies_independently_readback=True))
        captured=True
    try:
        head=subprocess.check_output(["/usr/bin/git","rev-parse","HEAD"],cwd=root,text=True).strip()
        assert head==os.environ["GITHUB_SHA"];report["head"]=head
        for item in EXPECTED:
            path=root/item["path"];raw=path.read_bytes()
            assert (len(raw),sha(raw),blob(raw))==(item["bytes"],item["sha256"],item["blob"]),item["path"]
        sys.path.insert(0,str(root))
        from tools.hia_selfhost_contract import validate_contract,file_digests,CONTRACT_PATH
        declared=validate_contract()
        report["contract_profile"]=declared["profile"]
        report["source_identity_before"]=dict(declared["source_identity"]["files"])
        assert file_digests()==report["source_identity_before"]
        from tests import test_hia_agent_installed_resources as loaded
        module=loaded
        assert Path(module.__file__).resolve()==root/"tests/test_hia_agent_installed_resources.py"
        resources=module.RESOURCES
        assert len(resources)==len(set(resources))==45
        watched=set(resources)|{"setup.py","pyproject.toml","MANIFEST.in","tools/hia_selfhost_contract.py",
            "tests/test_hia_agent_installed_resources.py",CONTRACT_PATH}
        watched.update(p.relative_to(root).as_posix() for p in (root/"hepta").rglob("*.py"))
        before={name:file_pin(root/name) for name in sorted(watched)}
        save(out/"source-before.json",before)
        old_teardown=module.AgentInstalledResourceTests.tearDownClass
        @classmethod
        def preserve_then_original_cleanup(cls):
            # Only append custody after all assertions; retain original cleanup.
            capture()
            return old_teardown()
        module.AgentInstalledResourceTests.tearDownClass=preserve_then_original_cleanup
        suite=unittest.defaultTestLoader.loadTestsFromModule(module)
        def identifiers(node):
            if isinstance(node,unittest.TestSuite):
                return [identity for child in node for identity in identifiers(child)]
            return [node.id()]
        ids=identifiers(suite)
        assert len(ids)==len(set(ids))==20
        assert sum(".AgentInstalledResourceSourceTests." in name for name in ids)==3
        assert sum(".AgentInstalledResourceTests." in name for name in ids)==17
        save(out/"expected-test-ids.json",ids)
        started=time.monotonic_ns()
        with (out/"unittest.stdout.log").open("w",encoding="utf-8") as stdout,(out/"unittest.stderr.log").open("w",encoding="utf-8") as stderr:
            with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                result=unittest.TextTestRunner(stream=stderr,verbosity=2).run(suite)
        report["tests"]=dict(test_ids=ids,tests_loaded=len(ids),tests_run=result.testsRun,elapsed_ns=time.monotonic_ns()-started,
            failures=[(t.id(),v) for t,v in result.failures],errors=[(t.id(),v) for t,v in result.errors],
            skipped=[(t.id(),v) for t,v in result.skipped],expected_failures=[(t.id(),v) for t,v in result.expectedFailures],
            unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
        save(out/"unittest.json",report["tests"])
        assert result.wasSuccessful() and result.testsRun==20
        assert not any(report["tests"][key] for key in ("failures","errors","skipped","expected_failures","unexpected_successes"))
        assert captured,"raw original fixture was not captured before original teardown"
        report["status"]="PASS"
    except BaseException as error:
        failure=error;report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        try:capture()
        except BaseException as error:
            report["capture_failure"]=dict(error=repr(error),traceback=traceback.format_exc());report["status"]="FAIL"
        try:
            after={name:file_pin(root/name) for name in before}
            report["source_before"]=before;report["source_after"]=after
            report["source_before_after_equal"]=bool(before) and before==after
            if module is not None:
                from tools.hia_selfhost_contract import file_digests
                report["source_identity_after"]=file_digests()
                report["source_identity_before_after_equal"]=report.get("source_identity_before")==report["source_identity_after"]
            else:report["source_identity_before_after_equal"]=False
            if not report["source_before_after_equal"] or not report["source_identity_before_after_equal"]:report["status"]="FAIL"
        except BaseException as error:
            report["source_after_error"]=repr(error);report["status"]="FAIL"
        save(out/"summary.json",report)
        entries=[]
        for path in sorted(out.rglob("*")):
            if path.is_dir():continue
            assert path.is_file() and not path.is_symlink()
            row=file_pin(path);row["name"]=path.relative_to(out).as_posix();entries.append(row)
        save(out/"members.json",entries)
        archive=out/"raw.tar.xz"
        with tarfile.open(archive,"w:xz",preset=1) as tar:
            for row in entries:
                raw=(out/row["name"]).read_bytes();assert (len(raw),sha(raw))==(row["bytes"],row["sha256"])
                item=tarfile.TarInfo(row["name"]);item.size=len(raw);item.mode=row["mode"];item.mtime=0
                tar.addfile(item,io.BytesIO(raw))
        expected={row["name"]:row for row in entries};seen=set()
        with tarfile.open(archive,"r:xz") as tar:
            for item in tar:
                assert item.isfile() and item.name in expected and item.name not in seen
                raw=tar.extractfile(item).read();row=expected[item.name]
                assert (len(raw),sha(raw),item.mode)==(row["bytes"],row["sha256"],row["mode"])
                assert file_pin(out/item.name)=={k:row[k] for k in ("bytes","sha256","mode")}
                seen.add(item.name)
        assert seen==set(expected)
        custody=dict(status=report["status"],archive=file_pin(archive),member_index=file_pin(out/"members.json"),
            members=len(entries),raw_bytes=sum(r["bytes"] for r in entries),all_member_bytes_sha256_modes_verified=True,
            original_failed_run_unchanged=True,scope=report["scope"])
        save(out/"custody.json",custody)
        print(json.dumps(custody,sort_keys=True),flush=True)
        if report["status"]!="PASS":
            stderr=out/"unittest.stderr.log"
            if stderr.exists():print(stderr.read_text(),file=sys.stderr,flush=True)
    return 0 if report["status"]=="PASS" else 1
if __name__=="__main__":raise SystemExit(main())
