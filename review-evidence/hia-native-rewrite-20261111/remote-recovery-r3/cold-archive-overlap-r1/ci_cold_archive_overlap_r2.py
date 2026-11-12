"""Isolated cold replay with only bounded phase-archive scheduling changed.

The submitted default tree is never edited. Its original 180-second owned cold
gate, two native/reference workers and all compiler/image/input semantics remain
unchanged. A current pass can only come from the complete new frozen candidate.
"""
from pathlib import Path
from hashlib import sha1,sha256
from copy import deepcopy
import argparse,ast,base64,json,os,platform,subprocess,sys,time,traceback
ORIGINAL="e9f999167b7e37c27187c199be117934de91c6db"
CANDIDATE="0bc5eb3dc49ee79faa67d3ff0d2e504689bab1f8"
CONTROL="04c3a14e03bafad93b21d5976fad14d73d8dbb38"
REPLAY="0d53ccbd2e56240280938ab829fe9c9798f02075"
GENERATOR="8697f63b20f2817b3cc6071c60946e5f9bb2fbc3"
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
def main():
    p=argparse.ArgumentParser();p.add_argument("--repo",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True);p.add_argument("--worktree",type=Path,required=True)
    a=p.parse_args();repo=a.repo.resolve();out=a.out.resolve();work=a.worktree.resolve()
    out.mkdir(parents=True,exist_ok=False);assert not work.exists()
    assert sys.version_info[:3]==(3,14,10),sys.version
    pins={};steps=[];status="FAIL";failure=None;cold=None;contract=None;original_contract=None
    def read(path):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in pins:assert pins[path]==raw
        pins[path]=raw;return raw
    def run(label,command,cwd,timeout):
        directory=out/"steps"/label;directory.mkdir(parents=True,exist_ok=False)
        started=time.monotonic_ns();record=dict(label=label,argv=list(map(str,command)),cwd=str(cwd),timeout=timeout)
        with (directory/"stdout.log").open("wb") as stdout,(directory/"stderr.log").open("wb") as stderr:
            try:
                done=subprocess.run(list(map(str,command)),cwd=cwd,stdout=stdout,stderr=stderr,
                    stdin=subprocess.DEVNULL,timeout=timeout,env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"})
                record.update(returncode=done.returncode,status="PASS" if done.returncode==0 else "FAIL")
            except BaseException as error:
                record.update(status="FAIL",error_class=type(error).__name__,error=str(error));raise
            finally:
                record["elapsed_ns"]=time.monotonic_ns()-started
                for name in ("stdout","stderr"):
                    raw=(directory/(name+".log")).read_bytes();record[name]=dict(bytes=len(raw),sha256=digest(raw))
                steps.append(record);save(directory/"process.json",record);save(out/"steps.json",steps)
                print("HIA_COLD_CANDIDATE_STEP "+json.dumps(record,sort_keys=True),flush=True)
        if done.returncode:raise RuntimeError("candidate step failed: "+label)
    try:
        read(__file__)
        head=subprocess.check_output(["git","rev-parse","HEAD"],cwd=repo).decode().strip()
        tree=subprocess.check_output(["git","rev-parse","HEAD^{tree}"],cwd=repo).decode().strip()
        assert head==os.environ["GITHUB_SHA"]
        candidate=read(repo/R3/"cold-archive-overlap-r1/qualify_hia_selfhost_candidate_r1.py")
        controls=read(repo/R3/"cold-archive-overlap-r1/test_archive_admission_r1.py")
        assert gitsha(candidate)==CANDIDATE and gitsha(controls)==CONTROL
        ast.parse(candidate);ast.parse(controls)
        original=read(repo/"tools/qualify_hia_selfhost.py");assert gitsha(original)==ORIGINAL
        cold_driver=read(repo/"tools/replay_hia_selfhost_cold.py");assert gitsha(cold_driver)==REPLAY
        generator=read(repo/"tools/generate_hia_selfhost_contract.py");assert gitsha(generator)==GENERATOR
        # The actual compiler author's HIA, all native application HIA and the
        # ABI execution children remain exactly those of this submitted tree.
        source=read(repo/"examples/hia_bootstrap/selfhost.hiaasm")
        original_contract=json.loads(read(repo/"docs/HIA_SELFHOST_CORE_SUPPORT.json"))
        run("isolated-worktree",["git","worktree","add","--detach",work,head],repo,180)
        assert not subprocess.check_output(["git","status","--porcelain"],cwd=work).strip()
        assert (work/"tools/qualify_hia_selfhost.py").read_bytes()==original
        (work/"tools/qualify_hia_selfhost.py").write_bytes(candidate)
        run("generate-exact-candidate-contract",
            [sys.executable,"-B","tools/generate_hia_selfhost_contract.py"],work,90)
        candidate_contract_raw=(work/"docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes()
        contract=json.loads(candidate_contract_raw)
        expected=deepcopy(original_contract)
        expected["source_identity"]["files"]["tools/qualify_hia_selfhost.py"]=digest(candidate)
        assert contract==expected,"candidate changed more than the one selected qualification source identity"
        assert (work/"examples/hia_bootstrap/selfhost.hiaasm").read_bytes()==source
        changed=subprocess.check_output(["git","diff","--name-only"],cwd=work).decode().splitlines()
        assert set(changed)=={"tools/qualify_hia_selfhost.py","docs/HIA_SELFHOST_CORE_SUPPORT.json"}
        frozen=out/"frozen-inputs";frozen.mkdir()
        for name,raw in (("original-qualifier.py",original),("candidate-qualifier.py",candidate),
            ("original-contract.json",read(repo/"docs/HIA_SELFHOST_CORE_SUPPORT.json")),
            ("candidate-contract.json",candidate_contract_raw),("archive-controls.py",controls)):
            (frozen/name).write_bytes(raw)
        for relative,expected_hash in contract["source_identity"]["files"].items():
            assert digest((work/relative).read_bytes())==expected_hash,relative
        save(out/"candidate-identity.json",dict(parent_commit=head,parent_tree=tree,
            submitted_default_source_not_changed=True,selected_qualifier_gitsha=CANDIDATE,
            original_qualifier_gitsha=ORIGINAL,original_support_contract_gitsha=gitsha(read(repo/"docs/HIA_SELFHOST_CORE_SUPPORT.json")),
            candidate_support_contract_gitsha=gitsha(candidate_contract_raw),
            candidate_support_contract_sha256=digest(candidate_contract_raw),
            full_source_identity=contract["source_identity"]["files"],
            compiler_HIA_sha256=digest(source),compiler_HIA_unchanged=True,
            python=sys.version,platform=platform.platform(),cold_limit_seconds=180,cleanup_seconds=3,
            host_oracle_workers=2,archive_workers=1,maximum_pending_archives=2))
        run("archive-admission-controls",[sys.executable,"-B",
            repo/R3/"cold-archive-overlap-r1/test_archive_admission_r1.py",
            "--source",work,"--out",out/"archive-controls"],work,120)
        checks=json.loads((out/"archive-controls/summary.json").read_bytes())
        assert checks["status"]=="PASS" and checks["source_unchanged"]
        assert checks["cases"]==checks["expected_cases"] and checks["new_archive_lane_controls"]==4
        assert checks["actual_native_entries"]==0
        # Call the unchanged owned supervisor directly. A subprocess.run outer
        # timeout would kill only its immediate child and can cut off the
        # supervisor before its original 180+3 second ownership protocol ends.
        assert not any(name=="tools" or name.startswith("tools.") for name in sys.modules)
        sys.path.insert(0,str(work))
        from tools import replay_hia_selfhost_cold as replay
        assert Path(replay.__file__).resolve()==work/"tools/replay_hia_selfhost_cold.py"
        assert gitsha(Path(replay.__file__).read_bytes())==REPLAY
        directory=out/"steps"/"unchanged-owned-cold-replay";directory.mkdir(parents=True,exist_ok=False)
        started=time.monotonic_ns()
        record=dict(label="unchanged-owned-cold-replay",invocation="unchanged cold_replay function",
            cwd=str(work),qualification_seconds=180,cleanup_seconds=3,
            outer_subprocess_timeout_added=False)
        import contextlib
        prior_cwd=Path.cwd()
        with (directory/"stdout.log").open("w") as stdout,(directory/"stderr.log").open("w") as stderr:
            try:
                os.chdir(work)
                with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                    cold=replay.cold_replay(out/"hia-cold.json")
                    print(json.dumps({"status":cold["status"],"output":str(out/"hia-cold.json"),
                        "checks_passed":sum(cold["checks"].values()),"checks_total":len(cold["checks"]),
                        "generation_sha256":cold["generation_sha256"],
                        "modified_generation_sha256":cold["modified_generation_sha256"]},sort_keys=True))
                record.update(status="PASS" if cold["status"]=="COLD_SELFHOST_REPLAY_PASS" else "FAIL",
                    cold_status=cold["status"],owner_status=cold["process_owner"]["status"])
            except BaseException as error:
                record.update(status="FAIL",error_class=type(error).__name__,error=str(error));raise
            finally:
                os.chdir(prior_cwd);stdout.flush();stderr.flush()
                record["elapsed_ns"]=time.monotonic_ns()-started
                for name in ("stdout","stderr"):
                    raw=(directory/(name+".log")).read_bytes();record[name]=dict(bytes=len(raw),sha256=digest(raw))
                steps.append(record);save(directory/"process.json",record);save(out/"steps.json",steps)
                print("HIA_COLD_CANDIDATE_STEP "+json.dumps(record,sort_keys=True),flush=True)
        cold_raw=(out/"hia-cold.json").read_bytes()
        assert json.loads(cold_raw)==cold
        assert cold["status"]=="COLD_SELFHOST_REPLAY_PASS" and len(cold["checks"])==11 and all(cold["checks"].values())
        assert cold["qualification_wall_limit_seconds"]==180 and cold["cleanup_wall_limit_seconds"]==3
        assert cold["process_owner"]["status"]=="OWNED_PROCESS_COMPLETED"
        for relative,expected_hash in contract["source_identity"]["files"].items():
            assert digest((work/relative).read_bytes())==expected_hash,relative
        assert (work/"docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes()==candidate_contract_raw
        status="PASS_ISOLATED_COLD_CANDIDATE_ONLY"
    except BaseException as error:
        failure=dict(error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        cold_path=out/"hia-cold.json"
        if cold_path.is_file():
            raw=cold_path.read_bytes()
            print("HIA_COLD_CANDIDATE_ORIGINAL "+json.dumps(dict(bytes=len(raw),sha256=digest(raw),
                base64=base64.b64encode(raw).decode("ascii")),sort_keys=True),flush=True)
        unchanged=all(path.read_bytes()==raw for path,raw in pins.items())
        if not unchanged:status="FAIL"
        report=dict(status=status,failure=failure,submitted_inputs_unchanged=unchanged,
            native_compiler_HIA_changed=False,default_source_activated=False,
            original_default_failures_preserved=True,whole_stack_closed=False,
            candidate_qualification_only=True,steps=steps)
        save(out/"summary.json",report)
        save(out/"input-pins.json",[dict(path=str(p),bytes=len(raw),sha256=digest(raw)) for p,raw in pins.items()])
        print("HIA_COLD_ARCHIVE_OVERLAP_CANDIDATE "+json.dumps(report,sort_keys=True),flush=True)
    if status!="PASS_ISOLATED_COLD_CANDIDATE_ONLY":raise SystemExit(1)
if __name__=="__main__":main()
