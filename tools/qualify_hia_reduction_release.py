#!/usr/bin/env python3
"""Frozen two-workload checked reduction comparison, including negative gates.

The four arms include both the existing strong Rust source and a Rust source
with explicit byte arithmetic. All samples, refusal probes, actual compiler
streams, proof queries, artifact identities and one-time costs are retained.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sys
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from tools.qualify_hia_native_ndu import (Driver, METRIC_NAMES, digest, file_identity,
    require, run_command, source_state, summary, wire)

FIXTURES=ROOT/"benchmarks/hia_reduction_release"
METRICS=ROOT/"benchmarks/hia_native_ndu"
ARMS=("hia_checked","hia_reduction","rust_release","rust_byte_release")
MASK32=2**32-1


def specification():
    return {"schema":"hepta.hia.reduction-release.protocol.v1",
        "workloads":["linear","affine"], "arms":list(ARMS),
        "regression_sizes":[0,1,64,257,4096,8193,65536],
        "holdout_sizes":[13,127,509,2053,12289,65521,131071,262147],
        "seeds":[383,659,4294967295], "samples":21,"batch_calls":64,"warmup_calls":3,
        "correctness_sizes":[0,1,15,16,17,255,256,257,4097],
        "refusal_boundary_sizes":[0,1,72340172838076673,72340172838076674,2**63-1,2**63,2**64-1],
        "performance_gate":{"median_ratio_maximum":1.10,"p95_ratio_maximum":1.20},
        "cost_horizons":[1,1000,1000000],
        "source_profile":"Rust 1.95.0 actual identity; Clang 20+ actual identity; generic x86_64; no target-cpu=native",
        "rust_flags":["opt-level=3","lto=fat","codegen-units=1","panic=abort","overflow-checks=off","force-frame-pointers=no"],
        "semantics":"fallible zero-initialized owned bytes, explicit wrapping fill, checked u64 reduction, release; refusal returns 1001",
        "baseline_overflow_scope":"Rust release sum wraps outside its representable result range; all timed/successful probe sizes are <=1048576, so u64 overflow is impossible there. Huge probes force allocation refusal. The HIA proof retains checked semantics beyond this measurement profile.",
        "registration":"both workload sources and all lengths frozen before campaign; affine is a second arithmetic/load shape, not an independent production application",
        "order":"rotate all four arms by seed index, reverse odd rotations; retain every sample and predeclared gate",
        "claims_limits":["one shared Linux x86_64 host; affinity is not exclusive CPU ownership",
            "Rust byte arm receives the same modular arithmetic simplification explicitly",
            "guard is machine-range-based and executed; benchmark lengths are not proof assumptions",
            "p95/p99 are batch latencies, not per-invocation tail latencies",
            "native compiler/linker/libc/hardware remain trusted; no backend refinement theorem",
            "manual engineering, historical tool acquisition and energy costs are unknown"]}


def bindings():
    paths=list((ROOT/"hepta").glob("*.py"))+list(FIXTURES.glob("*"))
    paths += [Path(__file__), ROOT/"tools/qualify_hia_native_ndu.py"]
    paths += [METRICS/name for name in ("metrics.c","metrics.h","probe_exports.c")]
    return {str(p.relative_to(ROOT)):file_identity(p)["sha256"] for p in sorted(paths) if p.is_file()}


def checksum(workload,n,seed):
    # An independent periodic formula; it does not call any measured library.
    values=[(i+seed)%256 if workload=="linear" else (i*seed+17)%256 for i in range(256)]
    cycles,tail=divmod(n,256)
    return cycles*sum(values)+sum(values[:tail])


def check_metrics(row,n,fail,*,boundary=False):
    require(len(row["metrics"])==len(METRIC_NAMES),"metric shape")
    m=dict(zip(METRIC_NAMES,row["metrics"]))
    attempt=int(n>0 and (not boundary or n<=2**63-1))
    require(m["attempts"]==attempt and m["refusals"]==attempt*fail,"allocation attempt/refusal sequence")
    require(m["allocations"]==m["frees"]==attempt*(1-fail),"allocation/free count")
    require(m["accounting_errors"]==m["live"]==m["live_requested"]==m["live_usable"]==0,"resource accounting/live bytes")
    if attempt and not fail:
        require(m["peak_requested"]==n and m["peak_usable"]>=n,"requested and usable peak")
    row["metrics"]=m


class ReductionDriver(Driver):
    def load(self,label,products):
        identifier=ARMS.index(label)
        row=self.ask(f"L {identifier} {products[label]['path']}")
        require(row.get("loaded")==identifier,"loaded identity")
        self.path_ids[products[label]["path"]]=identifier
        row["mapping"]=self.mapping(products[label]["path"])
        return row

    def measure(self,workload,label,n,seed,calls,samples,warmup=0,fail=0):
        identifier=ARMS.index(label)
        row=self.ask(f"R {identifier} {n} {seed} {calls} {samples} {warmup} {fail}")
        require(row.get("id")==identifier and row.get("n")==n and row.get("seed")==seed,"native response identity")
        require(row["cold_value"]==checksum(workload,n,seed),"cold result")
        require(row["batch_checksum"]==sum(checksum(workload,n,(seed+i)&MASK32) for i in range(calls)),"batch checksum")
        require(row["observed"]==(1001 if n and fail else checksum(workload,n,seed)),"normal/refusal result")
        require(len(row["times_ns"])==samples and sum(row["times_ns"])==row["elapsed_ns"],"complete native sample accounting")
        check_metrics(row,n,fail)
        row.update(backend=label,workload=workload)
        return row

    def refusal(self,workload,label,n,seed):
        identifier=ARMS.index(label)
        row=self.ask(f"F {identifier} {n} {seed}")
        require(row.get("id")==identifier and row.get("n")==n and row.get("seed")==seed,"refusal identity")
        require(row["observed"]==(1001 if n else 0),"machine-boundary refusal behavior")
        check_metrics(row,n,1,boundary=True)
        row.update(workload=workload,backend=label)
        return row


@contextmanager
def child_driver(executable,raw_path):
    child=ReductionDriver(executable,raw_path)
    try: yield child
    finally: child.close()


@contextmanager
def capture_native_commands(directory,ledger):
    """Observe the real bounded compiler calls, returning their exact result.

    This campaign instrumentation delegates without altering arguments, limits,
    return codes or bytes. Production admission and publication run unchanged.
    """
    import hepta.hia_program_llvm as backend
    original=backend.run_bounded
    def observed(argv,**kwargs):
        index=len(ledger)
        row={"argv":list(map(str,argv)),"capture_limits":kwargs,"status":"attempted"}
        ledger.append(row)
        started=time.monotonic_ns()
        for argument in argv:
            path=Path(argument)
            if path.suffix==".ll" and path.is_file():
                target=directory/f"command-{index:03d}.input.ll"
                target.write_bytes(path.read_bytes());row["llvm_input"]=file_identity(target)
        try:
            result=original(argv,**kwargs)
            row.update(returncode=result.returncode,status="passed" if result.returncode==0 else "failed")
            for stream in ("stdout","stderr"):
                raw=getattr(result,"raw_"+stream)
                if raw is None: raw=getattr(result,stream).encode()
                target=directory/f"command-{index:03d}.{stream}"
                target.write_bytes(raw);row[stream]=file_identity(target)
            return result
        except BaseException as error:
            row.update(status="failed",error={"type":type(error).__name__,"message":str(error)})
            capture=getattr(error,"capture",None)
            if capture is not None:
                row["returncode"]=capture.returncode
                for stream in ("stdout","stderr"):
                    target=directory/f"command-{index:03d}.{stream}"
                    target.write_bytes(getattr(capture,stream));row[stream]=file_identity(target)
            raise
        finally: row["wall_ns"]=time.monotonic_ns()-started
    with patch.object(backend,"run_bounded",side_effect=observed): yield


def build(output,clang,rustc,report):
    from hepta.hia_program_source import lower_source
    from hepta.hia_program_llvm import build_program_native
    from hepta.hia_reduction import propose_reduction_pipeline,build_reduction_native
    ledger=report["build_commands"]
    flags=["-O3","-fPIC","-fomit-frame-pointer","-fstack-usage"]
    wraps=["-Wl,--wrap="+name for name in ("malloc","calloc","realloc","free")]
    for name in ("metrics","probe_exports"):
        run_command([clang,*flags,"-I",METRICS,"-c",METRICS/(name+".c"),"-o",output/(name+".o")],output,ledger)
    run_command([clang,"-O2","-fno-omit-frame-pointer","-I",METRICS,FIXTURES/"driver.c","-ldl","-o",output/"driver"],output,ledger)
    report["driver_identity"]=file_identity(output/"driver")
    report["artifacts"]={};report["compilation"]={};report["backend_build_wall_ns"]={}
    for workload in report["protocol"]["workloads"]:
        directory=output/workload;directory.mkdir()
        core=lower_source((FIXTURES/(workload+".hepta")).read_text())
        (directory/"checked.core.json").write_bytes(core.canonical_bytes+b"\n")
        report["artifacts"][workload]={};report["compilation"][workload]={};report["backend_build_wall_ns"][workload]={}
        for arm in ARMS:
            started=time.monotonic_ns()
            target=directory/(arm+".so")
            if arm.startswith("hia"):
                obj=directory/(arm+".o")
                if arm=="hia_checked":
                    with capture_native_commands(output,ledger):
                        receipt=build_program_native(core,obj,clang=str(clang),kind="object")
                else:
                    proposal=propose_reduction_pipeline(core)
                    (directory/"PROPOSAL.json").write_bytes(wire(proposal)+b"\n")
                    with capture_native_commands(output,ledger):
                        receipt=build_reduction_native(core,proposal,obj,clang=str(clang),kind="object")
                report["compilation"][workload][arm]=receipt
                run_command([clang,"-shared",obj,output/"metrics.o",output/"probe_exports.o",*wraps,"-o",target],output,ledger)
            else:
                source=FIXTURES/(workload+("_byte" if arm=="rust_byte_release" else "")+".rs")
                args=[rustc,"--edition=2021","--crate-type=cdylib","--emit=link="+str(target)+",asm="+str(directory/(arm+".s"))]
                for flag in report["protocol"]["rust_flags"]: args += ["-C",flag]
                args += ["-C","linker="+str(clang),"-C","link-arg="+str(output/"metrics.o")]
                for flag in wraps: args += ["-C","link-arg="+flag]
                run_command([*args,source],output,ledger)
            report["backend_build_wall_ns"][workload][arm]=time.monotonic_ns()-started
            report["artifacts"][workload][arm]=file_identity(target)
            assembly=run_command(["/usr/bin/objdump","-d","--disassemble=calculate",target],output,ledger)
            (directory/(arm+".calculate.asm")).write_text(assembly)
    return report["artifacts"]


def assess(rows,spec):
    expected={(workload,phase,arm,n,seed) for workload in spec["workloads"]
        for phase in ("regression","holdout") for arm in ARMS
        for n in spec[phase+"_sizes"] for seed in spec["seeds"]}
    actual=[(r["workload"],r["phase"],r["backend"],r["n"],r["seed"]) for r in rows]
    require(len(actual)==len(set(actual)) and set(actual)==expected,"missing, duplicate or unexpected cohort")
    require(all(len(r["times_ns"])==spec["samples"] and r["calls"]==spec["batch_calls"] for r in rows),"missing/padded samples or changed load")
    cohorts,comparisons=[],[]
    gate=spec["performance_gate"]
    for workload in spec["workloads"]:
        for phase in ("regression","holdout"):
            for n in spec[phase+"_sizes"]:
                values={arm:summary([v for row in rows if (row["workload"],row["phase"],row["backend"],row["n"])==(workload,phase,arm,n) for v in row["times_ns"]]) for arm in ARMS}
                cohorts.append({"workload":workload,"phase":phase,"n":n,"summaries":values})
                for baseline in ("hia_checked","rust_release","rust_byte_release"):
                    ratios={stat+"_ratio":values["hia_reduction"][stat]/max(1,values[baseline][stat]) for stat in ("median","p95","p99")}
                    comparisons.append({"workload":workload,"phase":phase,"n":n,"baseline":baseline,**ratios,
                        "passed":ratios["median_ratio"]<=gate["median_ratio_maximum"] and ratios["p95_ratio"]<=gate["p95_ratio_maximum"]})
    rust=[r for r in comparisons if r["baseline"].startswith("rust")]
    return {"cohorts":cohorts,"comparisons":comparisons,
        "all_rust_gate_passed":all(r["passed"] for r in rust),
        "rust_comparisons_passed":sum(r["passed"] for r in rust),"rust_comparisons_total":len(rust),
        "independent_holdout_passed":all(r["passed"] for r in rust if r["phase"]=="holdout"),
        "broad_rust_performance_parity_established":False}


def amortization(report):
    result=[];calls=report["protocol"]["batch_calls"]
    for cohort in report["assessment"]["cohorts"]:
        workload=cohort["workload"]
        times={arm:s["median"]/calls for arm,s in cohort["summaries"].items()}
        # The minimum of two Rust arms is a deliberately strong comparator.
        reference=min(("rust_release","rust_byte_release"),key=lambda arm:times[arm])
        load={arm:sum(r["load_ns"] for r in report["loads"] if r["workload"]==workload and r["backend"]==arm)/len(report["protocol"]["seeds"]) for arm in ARMS}
        one_time={arm:report["backend_build_wall_ns"][workload][arm]+load[arm] for arm in ARMS}
        thresholds=[]
        for baseline in ("rust_release","rust_byte_release"):
            delta=times[baseline]-times["hia_reduction"]
            extra=one_time["hia_reduction"]-one_time[baseline]
            thresholds.append(max(1,math.ceil(extra/delta)) if delta>0 else 1 if delta==0 and extra<=0 else None)
        result.append({"workload":workload,"phase":cohort["phase"],"n":cohort["n"],"reference":reference,
            "estimated_per_call_ns":times,"one_time_build_proof_link_load_ns":one_time,
            "break_even_calls":max(thresholds) if all(n is not None for n in thresholds) else None,
            "horizons":[{"calls":n,"hia_total_ns":one_time["hia_reduction"]+n*times["hia_reduction"],
                "rust_total_ns":min(one_time[a]+n*times[a] for a in ("rust_release","rust_byte_release")),
                "rust_reference":min(("rust_release","rust_byte_release"),key=lambda a:one_time[a]+n*times[a])} for n in report["protocol"]["cost_horizons"]],
            "scope":"modeled amortization of measured medians; horizons are not executed replay traces; common harness setup excluded from both arms"})
    return result


def run(output,clang,rustc):
    started=time.monotonic_ns();output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    affinity=sorted(os.sched_getaffinity(0));spec=specification()
    report={"schema":"hepta.hia.reduction-release.result.v1","status":"running",
        "started_utc":datetime.now(timezone.utc).isoformat(),"protocol":spec,"protocol_sha256":digest(spec),
        "source_before":source_state(),"bindings_before":bindings(),
        "host":{"platform":platform.platform(),"machine":platform.machine(),"original_affinity":affinity,"selected_cpu":affinity[0],"exclusive":False},
        "build_commands":[],"measurements":[],"correctness":[],"refusals":[],"loads":[],"stage_wall_ns":{},
        "manual_engineering_ns":None,"energy_joules":None,"historical_tool_acquisition_ns":None}
    (output/"REGISTRATION.json").write_bytes(wire(report)+b"\n")
    def checkpoint(): (output/"RESULT.json").write_bytes(wire(report)+b"\n")
    try:
        require(platform.system()=="Linux" and platform.machine()=="x86_64","only actual Linux x86_64 admitted")
        os.sched_setaffinity(0,{affinity[0]})
        report["toolchains"]={}
        for label,tool in (("clang",clang),("rustc",rustc),("objdump",Path("/usr/bin/objdump"))):
            report["toolchains"][label]={**file_identity(tool),"version":run_command([tool,"--version"],output,report["build_commands"])}
        require(report["toolchains"]["rustc"]["version"].startswith("rustc 1.95.0 "),"this registered profile requires actual Rust 1.95.0")
        stage=time.monotonic_ns();products=build(output,clang,rustc,report)
        report["stage_wall_ns"]["build_and_proofs"]=time.monotonic_ns()-stage;checkpoint()
        stage=time.monotonic_ns()
        for workload in spec["workloads"]:
            for offset,seed in enumerate(spec["seeds"]):
                arms=list(ARMS[offset:]+ARMS[:offset])
                if offset%2: arms.reverse()
                for arm in arms:
                    with child_driver(output/"driver",output/f"timing-{workload}-{offset}-{arm}.jsonl") as child:
                        report["loads"].append({"workload":workload,"backend":arm,**child.load(arm,products[workload])})
                        for phase in ("regression","holdout"):
                            for n in spec[phase+"_sizes"]:
                                row=child.measure(workload,arm,n,seed,spec["batch_calls"],spec["samples"],spec["warmup_calls"])
                                row["phase"]=phase;report["measurements"].append(row)
                    checkpoint()
        report["stage_wall_ns"]["timing"]=time.monotonic_ns()-stage
        stage=time.monotonic_ns()
        for workload in spec["workloads"]:
            for arm in ARMS:
                with child_driver(output/"driver",output/f"correctness-{workload}-{arm}.jsonl") as child:
                    child.load(arm,products[workload])
                    for n in spec["correctness_sizes"]:
                        for fail in (0,1): report["correctness"].append(child.measure(workload,arm,n,4294967295,1,1,fail=fail))
                    for n in spec["refusal_boundary_sizes"]: report["refusals"].append(child.refusal(workload,arm,n,4294967295))
                checkpoint()
        report["stage_wall_ns"]["correctness_refusal"]=time.monotonic_ns()-stage
        report["assessment"]=assess(report["measurements"],spec)
        report["amortization"]=amortization(report)
        report["status"]="completed"
    except BaseException as error:
        report.update(status="failed",error={"type":type(error).__name__,"message":str(error)})
    finally:
        os.sched_setaffinity(0,set(affinity))
        report["source_after"],report["bindings_after"]=source_state(),bindings()
        report["source_unchanged"]=(report["source_before"]==report["source_after"] and report["bindings_before"]==report["bindings_after"])
        identities={"tool:"+k:v for k,v in report.get("toolchains",{}).items()}
        identities.update({w+":"+a:v for w,arms in report.get("artifacts",{}).items() for a,v in arms.items()})
        if "driver_identity" in report: identities["driver"]=report["driver_identity"]
        report["identities_after"]={}
        for label,identity in identities.items():
            try: report["identities_after"][label]=file_identity(identity["path"])
            except OSError: report["identities_after"][label]=None
        report["tool_artifact_identities_unchanged"]=all(report["identities_after"][k] is not None and all(report["identities_after"][k][field]==v[field] for field in ("path","bytes","sha256")) for k,v in identities.items())
        report["whole_lifecycle_wall_ns"]=time.monotonic_ns()-started
        report["cost_scope"]="campaign wall includes setup, proofs, compilation, link, all launches/loads/cold calls/warmups/timed samples, independent oracle validation and cleanup; nested stage/command costs are not added again"
        report["qualification_valid"]=report["status"]=="completed" and report["source_unchanged"] and report["tool_artifact_identities_unchanged"]
        report["report_sha256"]=digest(report);checkpoint()
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True);parser.add_argument("--clang",default=shutil.which("clang"));parser.add_argument("--rustc",default=shutil.which("rustc"))
    args=parser.parse_args()
    result=run(args.output,Path(args.clang).resolve(),Path(args.rustc).resolve())
    print(json.dumps({k:result.get(k) for k in ("status","qualification_valid","whole_lifecycle_wall_ns","error")}))
    if "assessment" in result:
        print(json.dumps({k:v for k,v in result["assessment"].items() if k not in ("cohorts","comparisons")}))
    return 0 if result["qualification_valid"] else 1


if __name__=="__main__": raise SystemExit(main())
