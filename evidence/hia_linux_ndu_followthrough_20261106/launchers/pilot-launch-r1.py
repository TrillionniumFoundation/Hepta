import os,sys,json,pathlib,time,platform,hashlib,subprocess
root=pathlib.Path("/data/hepta-hia-linux-followthrough-20261106-bedaafad8a2f")
repo=root/"repo"
head="02e421c562ab48a96fb45ff19ff2891186d259c1"
out=root/"results"/"pilot-launch-r1"
out.mkdir(parents=True,exist_ok=False)
sys.dont_write_bytecode=True
sys.path.insert(0,str(repo))
from tools.qualify_hia_linux_tests import git
from tools.qualify_hia_linux_baseline import CommandRunner,command_succeeded
assert git("rev-parse","HEAD")==head and not git("status","--porcelain","--untracked-files=all")
for name in ("linux-regressions.json","ndu-regressions.json"):
    prior=json.loads((root/"results/qualification-r1"/name).read_text())
    assert prior["status"]=="PASS" and prior["source_before"]["commit"]==head and prior["source_after"]["commit"]==head and not prior["skipped"]
env={k:v for k,v in os.environ.items() if k in ("PATH","HOME","TMPDIR")}
clang=root/"llvm20/sysroot/usr/lib/llvm-20/bin/clang"
objdump=root/"llvm20/sysroot/usr/lib/llvm-20/bin/llvm-objdump"
env.update(PYTHONDONTWRITEBYTECODE="1",LC_ALL="C",LANG="C",TZ="UTC",HIA_KERNEL_CLANG=str(clang),HIA_KERNEL_OBJDUMP=str(objdump),LD_LIBRARY_PATH=str(root/"llvm20/sysroot/usr/lib/x86_64-linux-gnu"))
runner=CommandRunner(out,env)
py=str(root/"venv/bin/python")
extension=out/"run-ndu-policy-regressions.py"
old=(root/"results/qualification-r1/run-ndu-regressions.py").read_text()
lines=old.splitlines()
found=[i for i,line in enumerate(lines) if line.startswith("modules=")]
assert len(found)==1
lines[found[0]]="modules=('tests.test_hia_ndu_feedback_coverage','tests.test_hia_ndu_policy_audit','tests.test_hia_ndu_policy_campaign')"
extension.write_text("\n".join(lines)+"\n")
cpu=47
assert cpu in os.sched_getaffinity(0)
cpuinfo={}
for line in pathlib.Path("/proc/cpuinfo").read_text().split("\n\n")[0].splitlines():
    if ":" in line:
        key,value=line.split(":",1)
        if key.strip() in ("vendor_id","cpu family","model","model name","stepping","microcode","cache size"):
            cpuinfo[key.strip()]=value.strip()
host={"platform":platform.platform(),"cpu_info":cpuinfo,"selected_cpu":cpu,"allowed_cpus":sorted(os.sched_getaffinity(0)),"boot_id":pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip(),"shared_host":True,"frequency_locked":False}
for key,path in {"governor":"/sys/devices/system/cpu/cpu47/cpufreq/scaling_governor","thread_siblings":"/sys/devices/system/cpu/cpu47/topology/thread_siblings_list"}.items():
    p=pathlib.Path(path)
    host[key]=p.read_text().strip() if p.exists() else None
report={"schema":"hepta.hia.native-pilot-launch.v1","source_before":{"commit":head,"tree":git("rev-parse","HEAD^{tree}")},"status":"FAIL","host":host,"stages":[]}
started=time.monotonic_ns()
try:
    r=runner.run("ndu-policy-regressions",[py,"-B",str(extension),str(out/"ndu-policy-regressions.json")],cwd=repo,timeout=180,check=False)
    report["stages"].append(r)
    if not command_succeeded(r):
        raise RuntimeError("shared default planner regressions failed before pilot")
    r=runner.run("native-pilot",[py,"-B",str(repo/"tools/qualify_hia_linux_native_pilot.py"),"--output",str(root/"results/native-pilot-r1"),"--upstream",str(root/"inputs/upstream-hweight.S"),"--clang",str(clang),"--objdump",str(objdump),"--expected-head",head,"--cpu",str(cpu)],cwd=repo,timeout=240,check=False)
    report["stages"].append(r)
    if not command_succeeded(r):
        raise RuntimeError("native pilot did not complete successfully")
    report["status"]="PASS"
except BaseException as error:
    report["error"]={"type":type(error).__name__,"message":str(error)}
finally:
    report["outer_wall_ns"]=time.monotonic_ns()-started
    report["source_after"]={"commit":git("rev-parse","HEAD"),"tree":git("rev-parse","HEAD^{tree}"),"dirty":git("status","--porcelain","--untracked-files=all")}
    report["extension_runner_sha256"]=hashlib.sha256(extension.read_bytes()).hexdigest()
    (out/"LAUNCH.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({k:report[k] for k in ("status","host","source_before","source_after")}),flush=True)
if "error" in report:
    print(json.dumps(report["error"]),flush=True)
for file in [out/"ndu-policy-regressions.json",root/"results/native-pilot-r1/RESULT.json"]:
    if file.exists():
        v=json.loads(file.read_text())
        print(json.dumps({"file":str(file),**{k:v.get(k) for k in ("status","tests_planned","tests_executed","errors","failures","skipped","error","summary","bridge_over_stock_paired_ratio_median","outer_wall_ns")}}),flush=True)
        if "cells" in v:
            counts={}
            for c in v["cells"]:counts[c["status"]]=counts.get(c["status"],0)+1
            print(json.dumps({"cells":counts,"negative_control":v.get("negative_control",{}).get("status"),"route":v.get("linked_route_inspection",{}).get("status")}),flush=True)
raise SystemExit(0 if report["status"]=="PASS" else 1)
