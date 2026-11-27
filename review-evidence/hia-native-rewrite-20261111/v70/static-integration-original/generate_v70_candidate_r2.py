import hashlib,json,os,pathlib,re,shutil,stat,subprocess,sys,time,traceback
BASE=pathlib.Path("/home/qq/hia-native-self-rewrite-20261111-dda7")
ROOT=BASE/"static-budget-integration-v70-r1"
A=ROOT/".git"/"hia-static-integration-recovery-r1"
PRIOR=A/"source-reconstruction-r1"
OUT=A/"source-generation-r2"
FACTS=json.loads("{\"content\":\"## Current v70 candidate: reconstructed static budget integration, qualification pending\\n\\nThis candidate starts from the published `8ca2197693c98e48d0d16ab3c077efc7cd535653`\\ntree `d9a0a779301d25ffbfdc1601ed86ce0d76a9236b`. Its 2,994 retained\\npaths were restored and checked against their exact Git blob identities and\\nmodes. The lost local `92fbc134f522c9cff616419b9555056e7cdd7d51`\\ncommit object, author identity and tree have not been recovered. The current\\ncandidate is **NEW_RECONSTRUCTION_FROM_SAVED_OWNER_FILES**: the 14 complete\\nsource files in the verified `9028d181` archive plus the preserved 17-path\\nregistration recipe. It does not inherit the lost integration's Git identity,\\nunknown source-gate result or qualification. The original attempt to admit the\\nincremental bundle failed because prerequisite `f5bb6d4a2014fc43a14737b92bc94e21e5b3be4b`\\nwas absent; that failure and the unchanged bundle remain retained.\\n\\nThe original complete `e03c82d1` qualification has finished with **HOLD**.\\nAll 32 stages actually ran. Total runner time was 6,760.128471506992 seconds.\\nFull discovery ran 4,583 tests with four failures and one error, and zero skips,\\nexpected failures or unexpected successes. Unittest reported 3,464.998 seconds;\\nthe enclosing full-retained step took 3,468.475736 seconds. The five top-level\\nfailures were an identity-worker empty-JSON error, the namespace caller wrapper,\\nthe ledger caller wrapper, and two scalar-proof identity assertions that\\nexpected `unknown` but observed `proved`. The nested manifest fixture for\\nthe identity-worker case was later repaired in `7d664e7d`; that later\\nobservation does not change the original error.\\n\\nThe original full-run namespace and ledger nested panels each reported one\\nfailure and one error across their 35 and 48 controls. Their original\\nthree-second and 1,000-millisecond deadlines are unchanged. A subsequent complete\\nread of the original compact evidence identified the two reference-loop\\n`RequestJournalUnknown` causes: the test callback's\\n`assertGreater(remaining, 0)` failed with remaining values\\n`-0.7292891502380371` and `-0.7449177265167236`, with the message\\n`fixture preparation exhausted the original context budget`. The original\\ntrace runs through ticket `run`/`encode_response(invoke())`, service\\n`evaluate`, and the test callback. The unknown acknowledgement classification\\nremains intact; it is not recast as an ordinary `E_BUDGET` result or a pass.\\nEarlier records that had not yet recovered this cause remain historical evidence.\\nThe complete original compact observation is 36,308 bytes, SHA256\\n`391f270c3bdca4465455c54c3e4912f41521323aa14b9a9ca028eb38693fe2e5`, retained as\\n[Git blob b3da5d03](https://api.github.com/repos/TrillionniumFoundation/Hepta/git/blobs/b3da5d034fbbf90ed65216477b8fc9e4ea251c2f).\\nFor context, the original e03 source closure has 751 entries totaling 20,198,062\\nbytes. Multiplying that static size by 98 preparations gives 1,979,410,076 bytes;\\nthis is a static estimate, not measured runtime I/O.\\n\\nAll three original `8ca` Core CI runs failed:\\n\\n| Run | Original native-stage result | Later result |\\n| --- | --- | --- |\\n| `43070250214` | Cold timeout after 180.185358450 seconds | Source job also failed on stale coverage support identity |\\n| `43070309546` | Cold passed 11/11 checks in 135.457622031 seconds | Stopped at `validate_inventory`; actual language cases did not run |\\n| `43070317835` | Cold timeout after 180.210550521 seconds | Source job also failed on stale coverage support identity |\\n\\nThe two timed-out cold runs recorded only six of eleven checks; owned process\\ncleanup completed. The original 180-second plus three-second cleanup bounds\\nremain unchanged. The earlier 26-control source panel did not include the\\nfailing inventory gate and therefore did not establish a complete source-CI\\npass.\\n\\nThe two original scalar-proof fixtures patched only `totality.__file__`,\\nwhile `checker_source_identity` reads `checker_identity.__file__`.\\nThe repaired fixture adds the actual owner's path patch and positive assertions\\nthat its source-lock SHA changes and is restored, retaining the original three\\ntest names and assertions. Its exact source SHA256 is\\n`03cbde73f488afc7b44dbc0fd25b785a35ffa4acd8cda19feabc72c10558be0e`.\\nA separate e03 fixture candidate passed 3/3 controls with no failure, error or\\nskip: unittest 0.135 seconds, runner 0.141893857 seconds. After copying that\\nfixture to the restored 8ca tree, the original `coverage_manifest` generation\\nand `validate_inventory` passed. That 176,645-byte coverage file changed only\\nits semantic support identity and had SHA256\\n`1da737da6e955e75b5d20bf18230827467b27a3e78e2d0f81bf5ce986d3ac049`.\\nThose are two-file repair observations. The static candidate must generate its\\nown coverage and rerun the original three controls; the earlier hash and results\\nare not imposed on the new source.\\n\\nThe original proof failures, exact fixture candidate, patch, freeze, summary,\\nraw test log, published-source restoration, static archive restoration and\\ntwo-file application record are retained in\\n[the fixed v70 recovery commit](https://github.com/TrillionniumFoundation/Hepta/tree/cc79242ffb316ce3fbc1f2fd858a99886d2b5bb7/review-evidence/hia-native-rewrite-20261111/v70/recovery).\\nThe original full-run failure index is retained in\\n[the fixed e03 evidence revision](https://github.com/TrillionniumFoundation/Hepta/blob/378d60da59ada59690768757849d2ac3fa836510/review-evidence/hia-native-rewrite-20261111/v69/recovery/e03-final-failure-index.json).\\nThe reconstruction recipe and unavailable-workspace custody are retained in\\n[the fixed recovery recipe commit](https://github.com/TrillionniumFoundation/Hepta/tree/70bc0a6c57d9536664c7cba4bc665a3dc8ada854/review-evidence/hia-native-rewrite-20261111/v69/recovery).\\n\\nWhole-native delivery, default activation, live migration and old-stack deletion\\nremain **false**. Adding the structural-budget candidate does not close public\\nlive-heap policy, complete public normalization, all general backend profiles,\\nservice and worker behavior, CLI/build/provider paths, or scalar-proof policy.\\nThe `541a` normalization candidate still has its two cause-preservation\\nboundaries, physical stack behavior and Python 3.14 exception-note behavior open.\\nThe structural owner also retains its explicit heap and final JSON/hash foreign\\ncontinuations. Final retirement is authorized, but it requires actual native\\nreplacements and a fresh qualified chain before old owners can be removed.\\n\\n\",\"sha256\":\"695f31c2a7ce3c680f3192ca7af91aaa723f23a692aaaf3851a08b67a9f85746\"}")
ENV=dict(os.environ,GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0")
record={"schema":"hepta.hia.static-budget-precommit-generation.v1",
"scope":"NEW_RECONSTRUCTION_FROM_SAVED_OWNER_FILES_PRECOMMIT_GENERATION",
"root":str(ROOT),"status":"RUNNING","started_unix_ns":time.time_ns(),
"prior_reconstruction_harness_failure_retained":True,"qualification":False,
"clean_source_gate_run":False,"native_tests_run":False,"cold_run":False,
"whole_native":False,"default_native":False,"live_migration":False,"legacy_deletion":False,
"lost_92fbc_recovered":False,"steps":[],"commands":[]}
error=None
created=False
def sha(raw):return hashlib.sha256(raw).hexdigest()
def dump(path,value):
    path.write_bytes((json.dumps(value,indent=2,sort_keys=True)+"\n").encode())
def git(*args,details=True):
    argv=["git","-C",str(ROOT),*args]
    r=subprocess.run(argv,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
    record["commands"].append({"argv":argv,"returncode":r.returncode,
       "stdout":r.stdout.decode("utf-8","backslashreplace") if details else None,
       "stdout_bytes":len(r.stdout),"stdout_sha256":sha(r.stdout),
       "stderr":r.stderr.decode("utf-8","backslashreplace")})
    if r.returncode:raise RuntimeError("git command failed: "+repr(argv))
    return r.stdout
def file_identity(path):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode):raise RuntimeError("nonregular candidate input: "+str(path))
    raw=path.read_bytes()
    after=path.lstat()
    if (st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns):
        raise RuntimeError("input changed while hashing: "+str(path))
    return {"bytes":len(raw),"mode":stat.S_IMODE(st.st_mode),"sha256":sha(raw)}
def snapshot():
    names=[x.decode() for x in git("ls-files","-z",details=False).split(b"\0") if x]
    return {name:file_identity(ROOT/name) for name in names}
def names(raw):return {x.decode() for x in raw.split(b"\0") if x}
try:
    if sys.version_info[:3]!=(3,14,4):raise RuntimeError("unexpected interpreter")
    if os.path.lexists(OUT):raise FileExistsError("generation observation directory already exists")
    prior_raw=(PRIOR/"report.json").read_bytes()
    if len(prior_raw)!=34926 or sha(prior_raw)!="6291d4f10c61ad81d1b335bfeec238aa2aa08264b59a1cb0b10ae5565f2811bd":
        raise RuntimeError("original reconstruction failure receipt changed")
    prior=json.loads(prior_raw)
    if prior["status"]!="FAILED" or prior["error"]["message"]!="staged path set differs from authorized source plan" or len(prior["written"])!=30 or len(prior["patch_hunks"])!=40:
        raise RuntimeError("unexpected original reconstruction boundary")
    diagnostic=(A/"plan-diff-diagnostic-r1.json").read_bytes()
    if len(diagnostic)!=6212 or sha(diagnostic)!="54cb6818fb19cd213349943ee8157d84e2e370993ee4f3e01ffb70c8ecc518c5":
        raise RuntimeError("original Git/POSIX mode diagnostic changed")
    record["git_mode_correction"]={
        "diagnostic_sha256":sha(diagnostic),
        "original_generation_failure_retained":str(A/"source-generation-r1-failed-before-write.json"),
        "comparison":"Git mode 100644/100755 from executable bits; full POSIX modes independently retained and verified",
        "no_product_source_rewrite_for_permission_only_difference":True}
    plan=json.loads((PRIOR/"write-plan.json").read_bytes())
    plan_map={row["path"]:row for row in plan}
    if len(plan_map)!=30:raise RuntimeError("unexpected frozen write plan")
    for row in prior["written"]:
        if file_identity(ROOT/row["path"])!={k:row[k] for k in ("bytes","mode","sha256")}:
            raise RuntimeError("source changed after original reconstruction: "+row["path"])
        if plan_map[row["path"]]["after"]!={k:row[k] for k in ("bytes","mode","sha256")}:
            raise RuntimeError("write plan and original receipt differ")
    expected_changed={path for path,row in plan_map.items() if not row["before"]["exists"] or
                      any(row["before"][key]!=row["after"][key] for key in ("bytes","sha256")) or
                      bool(row["before"]["mode"] & 0o111)!=bool(row["after"]["mode"] & 0o111)}
    actual_changed=names(git("diff","--cached","--name-only","-z",details=False))
    if actual_changed!=expected_changed:
        raise RuntimeError("actual staged changes differ from byte/mode-changing plan entries")
    if git("diff","--name-only","-z",details=False):raise RuntimeError("unexpected unstaged source edits")
    if git("ls-files","--others","--exclude-standard","-z",details=False):raise RuntimeError("unexpected untracked source")
    record["original_write_plan_reconciliation"]={"planned_writes":30,"actual_changed_paths":sorted(actual_changed),
        "unchanged_exact_source_copies":sorted(set(plan_map)-actual_changed),
        "original_guard_overcounted_noop_copies":True}
    OUT.mkdir(mode=0o700);created=True
    dump(OUT/"plan-reconciliation.json",record["original_write_plan_reconciliation"])
    before=snapshot();dump(OUT/"source-before.json",before)
    record["source_before"]={"paths":len(before),"sha256":sha((OUT/"source-before.json").read_bytes())}
    if sha(FACTS["content"].encode())!=FACTS["sha256"]:raise RuntimeError("current status facts identity changed")
    status_path=ROOT/"docs/HIA_NATIVE_REWRITE_STATUS_20261111.md"
    old=status_path.read_text()
    heading="## Current v69 integration: execution, static budgets and direct ledger pending"
    prior_heading="## Prior v69 checkpoint: execution, static budgets and direct ledger pending"
    if old.count(heading)!=1 or "## Current v70 candidate:" in old:
        raise RuntimeError("status history insertion context changed")
    updated=old.replace(heading,FACTS["content"]+prior_heading,1)
    status_path.write_text(updated)
    record["status_facts"]={"before_sha256":sha(old.encode()),"after_sha256":sha(updated.encode()),
                           "facts_sha256":FACTS["sha256"],"historical_body_retained":True}
    (OUT/"current-status-facts.md").write_text(FACTS["content"])
    HARNESS=ROOT/"review-evidence/hia-native-rewrite-20261111/v69/qualification"
    sys.path.insert(0,str(HARNESS))
    import workflow_process
    if pathlib.Path(workflow_process.__file__).resolve()!=HARNESS/"workflow_process.py":
        raise RuntimeError("unexpected workflow process owner")
    record["workflow_process"]=file_identity(pathlib.Path(workflow_process.__file__))
    env=dict(ENV)
    discarded={}
    for key in sorted(tuple(env)):
        if key.startswith("HEPTA_HIA_") and (key.endswith(("_MANIFEST","_COLD_REPORT")) or "_DEVELOPMENT" in key):
            value=env.pop(key)
            discarded[key]={"bytes":len(os.fsencode(value)),"sha256":sha(os.fsencode(value))}
    env["PATH"]=str(pathlib.Path(sys.executable).parent)+os.pathsep+env.get("PATH","")
    env["PYTHONDONTWRITEBYTECODE"]="1";env["PYTHONUNBUFFERED"]="1"
    if not os.path.samefile(shutil.which("python",path=env["PATH"]),sys.executable):
        raise RuntimeError("workflow python does not resolve to pinned interpreter")
    record["prerequisites"]={"executable":sys.executable,"resolved_executable":str(pathlib.Path(sys.executable).resolve()),
       "executable_identity":file_identity(pathlib.Path(sys.executable).resolve()),"version":sys.version,
       "removed_selections":discarded}
    def run_step(name,command):
        print(json.dumps({"starting":name}),flush=True)
        receipt=OUT/(name+".owner.json")
        stdout=OUT/(name+".stdout")
        stderr=OUT/(name+".stderr")
        owner=workflow_process.run_workflow_step(command,cwd=ROOT,env=env,
            stdout_path=stdout,stderr_path=stderr,receipt_path=receipt,seconds=1800)
        passed=(owner.get("returncode")==0 and owner.get("timed_out") is False and
                owner.get("status")=="WORKFLOW_STEP_COMPLETED" and owner.get("cleanup",{}).get("complete") is True)
        row={"name":name,"command":command,"owner":owner,"passed":passed,
             "stdout":file_identity(stdout),"stderr":file_identity(stderr)}
        record["steps"].append(row);dump(OUT/"steps.json",record["steps"])
        print(json.dumps({"finished":name,"passed":passed,"returncode":owner.get("returncode")}),flush=True)
        if not passed:raise RuntimeError("source generation/check failed: "+name)
    lines=(ROOT/".github/workflows/hia-core.yml").read_text().splitlines()
    start,=[i for i,line in enumerate(lines) if line=="      - name: Regenerate actual HIA sources"]
    stop=next(i for i in range(start+1,len(lines)) if lines[i].startswith("      - "))
    step=lines[start:stop];begin=step.index("        run: |")+1
    body=[line[10:] for line in step[begin:] if line.startswith("          ")]
    if body[-1]!="git diff --exit-code":raise RuntimeError("CI regeneration tail changed")
    generation_body="\n".join(body[:-1])+"\n"
    if not any("static_budget; do" in line for line in body):raise RuntimeError("static generator is not registered")
    (OUT/"actual-ci-generation-body.sh").write_text(generation_body)
    generation_before=snapshot()
    run_step("actual-ci-hia-generators-precommit",["bash","--noprofile","--norc","-c",generation_body])
    generation_after=snapshot()
    changed_by_generators=sorted(path for path in generation_before if generation_before[path]!=generation_after[path])
    record["hia_generator_changed_paths"]=changed_by_generators
    if changed_by_generators:raise RuntimeError("actual generators disagree with reconstructed checked HIA inputs")
    run_step("support-generate-1",[sys.executable,"-B","tools/generate_hia_selfhost_contract.py"])
    run_step("language-inventory-generate",[sys.executable,"-B","tests/test_hia_selfhost_language_coverage.py","--generate-inventory"])
    run_step("support-generate-2",[sys.executable,"-B","tools/generate_hia_selfhost_contract.py"])
    run_step("support-check",[sys.executable,"-B","tools/generate_hia_selfhost_contract.py","--check"])
    run_step("original-language-inventory-validation",[sys.executable,"-B","-c",
       "from tests.test_hia_selfhost_language_coverage import validate_inventory; import json; "
       "r=validate_inventory(); print(json.dumps({'validated': True, 'semantic_support_sha256': r['source']['semantic_support_sha256']}))"])
    additions={"docs/HIA_SELFHOST_CORE_SUPPORT.json","docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json",
               "docs/HIA_NATIVE_REWRITE_INVENTORY.json"}
    allowed=set(plan_map)|additions
    git("add","--",*sorted((set(plan_map)|additions)-{"docs/HIA_NATIVE_REWRITE_INVENTORY.json"}))
    run_step("actual-static-inventory-generator",[sys.executable,"-B","tools/audit_hia_native_rewrite.py","--output","docs/HIA_NATIVE_REWRITE_INVENTORY.json"])
    inventory=json.loads((ROOT/"docs/HIA_NATIVE_REWRITE_INVENTORY.json").read_bytes())
    if any(inventory["claims"].values()) or inventory["scope"]["live_worker_migrated"]:
        raise RuntimeError("inventory claimed a forbidden migration/qualification")
    if any(row.get("kind")=="missing_or_nonregular" for row in inventory["files"]):
        raise RuntimeError("static inventory found missing tracked source")
    record["inventory_counts"]=inventory["counts"]
    record["inventory_head"]=inventory["git_head"]
    record["inventory_index_changes"]=inventory["index_vs_head_changed_paths"]
    git("add","--",*sorted(allowed))
    git("diff","--cached","--check")
    if git("diff","--name-only","-z",details=False):raise RuntimeError("unstaged source remains after explicit staging")
    changed=names(git("diff","--cached","--name-only","-z",details=False))
    if not changed.issubset(allowed) or not expected_changed.issubset(changed):
        raise RuntimeError("final source diff escapes expected paths or omits an original intended change")
    record["changed_paths"]=sorted(changed)
    record["allowed_paths"]=sorted(allowed)
    record["new_source_tree"]=git("write-tree").decode().strip()
    record["base_head"]=git("rev-parse","HEAD").decode().strip()
    if record["base_head"]!="8ca2197693c98e48d0d16ab3c077efc7cd535653":
        raise RuntimeError("source HEAD moved without authorized publication")
    record["diff_stat"]=git("diff","--cached","--stat").decode()
    patch=git("diff","--cached","--binary",details=False)
    (OUT/"candidate-vs-8ca.patch").write_bytes(patch)
    record["patch"]={"path":str(OUT/"candidate-vs-8ca.patch"),"bytes":len(patch),"sha256":sha(patch)}
    final=snapshot();dump(OUT/"source-final.json",final)
    record["source_final"]={"paths":len(final),"sha256":sha((OUT/"source-final.json").read_bytes())}
    record["generated_files"]={p:file_identity(ROOT/p) for p in sorted(additions)}
    coverage=json.loads((ROOT/"docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json").read_bytes())
    record["semantic_support_sha256"]=coverage["source"]["semantic_support_sha256"]
    sys.path.insert(0,str(ROOT))
    from tools.hia_selfhost_contract import SOURCE_FILES
    record["source_closure_count"]=len(SOURCE_FILES)
    record["status"]="GENERATED_AND_STATICALLY_VALIDATED_PENDING_CLEAN_COMMIT_GATES"
except BaseException as exc:
    error=exc
    record["status"]="FAILED"
    record["error"]={"type":type(exc).__name__,"message":str(exc),"traceback":traceback.format_exc()}
finally:
    record["ended_unix_ns"]=time.time_ns()
    report=OUT/"report.json" if created else A/"source-generation-r2-failed-before-write.json"
    dump(report,record)
    raw=report.read_bytes()
    print(json.dumps({"status":record["status"],"scope":record["scope"],"error":record.get("error"),
      "report":str(report),"report_bytes":len(raw),"report_sha256":sha(raw),
      "new_source_tree":record.get("new_source_tree"),"changed_paths":record.get("changed_paths"),
      "source_closure_count":record.get("source_closure_count"),"inventory_counts":record.get("inventory_counts"),
      "semantic_support_sha256":record.get("semantic_support_sha256"),"qualification":False,
      "clean_source_gate_run":False,"native_tests_run":False,"cold_run":False},sort_keys=True,indent=2),flush=True)
sys.exit(0 if error is None else 1)
