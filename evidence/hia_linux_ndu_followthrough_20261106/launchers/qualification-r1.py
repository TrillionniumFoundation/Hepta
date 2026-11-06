import os, sys, json, pathlib, subprocess, hashlib, time
root=pathlib.Path("/data/hepta-hia-linux-followthrough-20261106-bedaafad8a2f")
repo=root/"repo"
head="02e421c562ab48a96fb45ff19ff2891186d259c1"
out=root/"results"/"qualification-r1"
out.mkdir(parents=True,exist_ok=False)
def git(*args):
    return subprocess.check_output(["git","--no-replace-objects","-C",str(repo),*args],text=True).strip()
if git("status","--porcelain","--untracked-files=all"):
    raise RuntimeError("existing isolated checkout became dirty")
subprocess.run(["git","-C",str(repo),"fetch","--no-tags","origin",head],check=True,timeout=90)
subprocess.run(["git","-C",str(repo),"checkout","--detach",head],check=True,timeout=30)
assert git("rev-parse","HEAD")==head
assert git("rev-parse","HEAD^{tree}")=="f354d010315378732729f879e4e59fa499ce244e"
assert not git("status","--porcelain","--untracked-files=all")
env={k:v for k,v in os.environ.items() if k in ("PATH","HOME","TMPDIR")}
env.update(PYTHONDONTWRITEBYTECODE="1",LC_ALL="C",LANG="C",TZ="UTC",
    HIA_KERNEL_CLANG=str(root/"llvm20/sysroot/usr/lib/llvm-20/bin/clang"),
    HIA_KERNEL_OBJDUMP=str(root/"llvm20/sysroot/usr/lib/llvm-20/bin/llvm-objdump"),
    LD_LIBRARY_PATH=str(root/"llvm20/sysroot/usr/lib/x86_64-linux-gnu"))
sys.dont_write_bytecode=True
sys.path.insert(0,str(repo))
from tools.qualify_hia_linux_baseline import CommandRunner
runner=CommandRunner(out,env)
py=str(root/"venv/bin/python")
ndu_script=out/"run-ndu-regressions.py"
ndu_script.write_text("""import sys,json,hashlib,platform,unittest
from pathlib import Path
repo=Path('/data/hepta-hia-linux-followthrough-20261106-bedaafad8a2f/repo')
sys.path.insert(0,str(repo))
from tools.qualify_hia_linux_tests import git
from tools.qualify_hia_three_lane import _IdentityRecordingResult,_outcome_admissible,_planned_test_ids
modules=('tests.test_hia_ndu_compute_debit','tests.test_hia_ndu_feedback','tests.test_hia_ndu_feedback_campaign','tests.test_hia_ndu_economical','tests.test_hia_ndu_compute_price','tests.test_hia_ndu_feedback_ci_paths')
before={'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}')}
assert not git('status','--porcelain','--untracked-files=all')
suite=unittest.defaultTestLoader.loadTestsFromNames(modules)
planned=_planned_test_ids(suite)
result=unittest.TextTestRunner(stream=sys.stderr,verbosity=2,resultclass=_IdentityRecordingResult).run(suite)
after={'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}')}
dirty=git('status','--porcelain','--untracked-files=all')
passed=_outcome_admissible(result,planned,immutable=before==after and not dirty)
record={'schema':'hepta.hia.ndu-compute-debit-regressions.v1','status':'PASS' if passed else 'FAIL','source_before':before,'source_after':after,'source_status_after':dirty,'python_version':platform.python_version(),'modules':list(modules),'tests_planned':len(planned),'tests_executed':result.testsRun,'planned_ids':list(planned),'started_ids':result.started_ids,'finished_ids':result.finished_ids,'planned_ids_sha256':hashlib.sha256(json.dumps(planned,separators=(',',':')).encode()).hexdigest(),'errors':[t.id() for t,_ in result.errors],'failures':[t.id() for t,_ in result.failures],'skipped':[{'test':t.id(),'reason':r} for t,r in result.skipped],'expected_failures':[t.id() for t,_ in result.expectedFailures],'unexpected_successes':[t.id() for t in result.unexpectedSuccesses],'scope':'deterministic_compute_debit_and_existing_model_regressions_not_native_performance','claims':{'kernel_booted':False,'whole_kernel_rewritten':False,'global_comparison_completed':False,'ndu_gain_established':False}}
Path(sys.argv[1]).write_text(json.dumps(record,indent=2)+'\\n')
print(json.dumps({k:record[k] for k in ('status','tests_planned','tests_executed','skipped')}))
raise SystemExit(0 if passed else 1)
""")
report={"schema":"hepta.hia.linux-ndu-followthrough-launch.v1","source_before":{"commit":head,"tree":git("rev-parse","HEAD^{tree}")},"status":"FAIL","boot_id":pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),"stages":[]}
started=time.monotonic_ns()
try:
    for name,argv in [
        ("linux-regressions",[py,"-B",str(repo/"tools/qualify_hia_linux_tests.py"),"--output",str(out/"linux-regressions.json")]),
        ("ndu-regressions",[py,"-B",str(ndu_script),str(out/"ndu-regressions.json")]),
    ]:
        receipt=runner.run(name,argv,cwd=repo,timeout=180,check=False)
        report["stages"].append(receipt)
    report["status"]="PASS" if all(r["exit_code"]==0 and r["timed_out"] is False and not r.get("incomplete_process_group",False) and "interruption" not in r for r in report["stages"]) else "FAIL"
finally:
    report["outer_wall_ns"]=time.monotonic_ns()-started
    report["source_after"]={"commit":git("rev-parse","HEAD"),"tree":git("rev-parse","HEAD^{tree}"),"dirty":git("status","--porcelain","--untracked-files=all")}
    for name in ["clang","llvm-objdump"]:
        p=root/"llvm20/sysroot/usr/lib/llvm-20/bin"/name
        report[name]={"path":str(p),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
    report["ndu_runner_sha256"]=hashlib.sha256(ndu_script.read_bytes()).hexdigest()
    (out/"LAUNCH.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({"status":report["status"],"source":head,"out":str(out),"stages":[{"name":r["name"],"exit_code":r["exit_code"],"timed_out":r["timed_out"]} for r in report["stages"]]}),flush=True)
for f in ["linux-regressions.json","ndu-regressions.json"]:
    p=out/f
    if p.exists():
        v=json.loads(p.read_text())
        print(json.dumps({"file":f,**{k:v.get(k) for k in ["status","tests_planned","tests_executed","errors","failures","skipped"]}}),flush=True)
raise SystemExit(0 if report["status"]=="PASS" else 1)
