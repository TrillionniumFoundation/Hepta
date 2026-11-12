"""Run one zero-target local seal with independent original aggregate budgets."""
from pathlib import Path
import argparse,importlib.util,json,os,resource,sys,time,traceback
BASE=Path("/workspace/scratch/9acdfa9f5639/native-checker-development")
def cpu():
    a=resource.getrusage(resource.RUSAGE_SELF);b=resource.getrusage(resource.RUSAGE_CHILDREN)
    return a.ru_utime+a.ru_stime+b.ru_utime+b.ru_stime
def main():
    p=argparse.ArgumentParser();p.add_argument("--name",required=True);p.add_argument("--root",action="append",required=True);a=p.parse_args()
    assert a.name.isascii() and a.name.replace("-","").isalnum()
    assert sys.version_info[:3]==(3,12,14);os.sched_setaffinity(0,{6})
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    start=time.monotonic_ns();c0=cpu();out=Path("/dev/shm/hia-native-checker-physical-seals-r1")/a.name
    out.mkdir(parents=True,exist_ok=False);os.environ["HIA_CI_OUTPUT"]=str(out/"process")
    spec=importlib.util.spec_from_file_location("local_seal_common",BASE/"local-tools/ci_recovery_common_original.py")
    common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
    report={"scope":"LOCAL_ZERO_TARGET_STORAGE_ONLY","status":"INCOMPLETE","name":a.name,"native_entries_executed":0}
    primary=None
    try:
        args=[sys.executable,"-B",BASE/"local-tools/seal_local_physical_development.py","--out",out/"sealed"]
        for item in a.root:args+=["--root",item]
        v=common.run("seal",args,cwd=BASE,timeout=180,env={"PYTHONDONTWRITEBYTECODE":"1"})
        assert v["status"]=="PASS" and v["child_cpu_seconds"]<90 and v["elapsed_ns"]<180000000000
        report["process"]=v;report["status"]="PASS"
    except BaseException as e:primary=e;report.update(status="FAIL",error=repr(e),traceback=traceback.format_exc())
    finally:
        for label,path in (("seal",out/"sealed/summary.json"),("process",out/"process/steps/seal/process.json")):
            try:
                if path.is_file():report[label]=json.loads(path.read_bytes())
            except BaseException as e:
                if primary is None:primary=e
                else:primary.add_note("capture "+label+": "+repr(e))
                report["status"]="FAIL"
        report["aggregate_cpu_seconds"]=cpu()-c0;report["aggregate_wall_seconds"]=(time.monotonic_ns()-start)/1e9
        if report["aggregate_cpu_seconds"]>=90 or report["aggregate_wall_seconds"]>=180:
            e=AssertionError("local zero-target seal aggregate budget")
            if primary is None:primary=e
            else:primary.add_note(repr(e))
            report["status"]="FAIL"
        try:common.save(out/"local-seal-observation.json",report)
        except BaseException as e:
            if primary is None:primary=e
            else:primary.add_note("save seal observation: "+repr(e))
        print(json.dumps({"name":a.name,"status":report["status"],"path":str(out/"local-seal-observation.json")}),flush=True)
    if primary is not None:raise primary
    assert cpu()-c0<90 and time.monotonic_ns()-start<180000000000
if __name__=="__main__":main()
