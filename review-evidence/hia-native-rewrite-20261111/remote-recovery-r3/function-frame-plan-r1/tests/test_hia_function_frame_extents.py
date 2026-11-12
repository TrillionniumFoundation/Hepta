"""Additional original-domain Function block and staging boundaries."""
from pathlib import Path
from hashlib import sha256
import argparse,importlib.util,json,resource,sys,time,traceback,types
sys.dont_write_bytecode=True
BASE_SHA="b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
def main():
    parser=argparse.ArgumentParser()
    for name in("manifest","reference","out"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--group",choices=("blocks","edge","call","saved"),required=True)
    parser.add_argument("--variant",type=int,default=0)
    args=parser.parse_args();root=Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True,exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    raw=(root/"tests/test_hia_function_frame_plan.py").read_bytes()
    assert sha256(raw).hexdigest()==BASE_SHA
    module=types.ModuleType("function_frame_frozen_test")
    module.__file__=str(root/"tests/test_hia_function_frame_plan.py")
    exec(compile(raw,module.__file__,"exec"),module.__dict__)
    actual=None;started=time.monotonic_ns()
    summary=dict(status="INCOMPLETE",group=args.group,variant=args.variant,
        scope="ORIGINAL_FUNCTION_DOMAIN_BOUNDARIES",whole_backend_closed=False,cold_qualified=False)
    try:
        actual=module.Actual(args.manifest,args.reference.resolve(),root,args.out)
        actual.evidence.pin(__file__)
        if args.group=="blocks":
            blocks=[module.block("b"+str(i),[],[],
                dict(op="jump",target="b"+str(i+1),args=[]) if i<4095 else dict(op="ret",values=[]))
                for i in range(4096)]
            doc=module.program(module.function("many_blocks",blocks=blocks))
            actual.compare("original-4096-block-domain",doc,serial=4095)
        elif args.group=="edge":
            count=(4091,4092,4093)[args.variant]
            params=[module.param("v"+str(i),"u64") for i in range(count)]
            doc=module.program(module.function("edge_staging_boundary",params=params))
            actual.compare("edge-parameter-words-"+str(count),doc,serial=77)
        elif args.group=="call":
            count=(2728,2729)[args.variant]
            params=[module.param("p"+str(i),"u64") for i in range(count)]
            callee=module.function("callee",params=params,
                ops=[module.op("const",[],[module.param("value","u64")],{"value":42})],
                returns=["u64"],term=dict(op="ret",values=["value"]))
            caller=module.function("caller",params=params,
                ops=[module.op("call",[p["name"] for p in params],[module.param("result","u64")],{"function":"callee"})],
                returns=["u64"],term=dict(op="ret",values=["result"]))
            actual.compare("call-argument-words-"+str(count),module.program(callee,caller),index=1,serial=87)
        elif args.group=="saved":
            count,saved=((8182,2),(8182,3),(8184,1))[args.variant]
            values=[module.param("v"+str(i),"u64") for i in range(count)]
            ops=[module.op("const",[],[value],{"value":i}) for i,value in enumerate(values)]
            doc=module.program(module.function("saved_boundary",ops=ops))
            mapping={values[i]["name"]:module.REGS[i+1] for i in range(saved)}
            plan=module.machine_plan(doc,registers={"saved_boundary":mapping})
            actual.compare("saved-register-frame-"+str(count)+"-"+str(saved),doc,plan,serial=99)
        summary["status"]="PASS"
    except BaseException as error:
        summary.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        if actual is not None:
            summary.update(cases=len(actual.cases),native_entries=actual.calls,private_controls=actual.private_controls,
                admitted_core_cases=actual.validated,private_constructor_pressure_cases=actual.pressure)
            try:summary["custody"]=actual.close()
            except BaseException as error:
                summary.update(status="FAIL",cleanup_error=repr(error),cleanup_traceback=traceback.format_exc());traceback.print_exc()
        summary.update(elapsed_ns=time.monotonic_ns()-started,
            limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
        module.save(args.out/"summary.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
    if summary["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
