#!/usr/bin/env python3
"""Prospective six-arm AOT entry-layout campaign with unchanged historical gates.

Every old v2 cohort and prior wrapper length is retained. The new layout must
beat the same two Rust sources; the old wrapper remains a measured comparator.
No sample exclusion or best-of retry. This is a shared-host, opt-in layout
experiment, not universal Rust parity or a backend refinement theorem.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import qualify_hia_reduction_release as release
from tools import qualify_hia_empty_reduction as empty
from tools.qualify_hia_native_ndu import (
    digest, file_identity, require, run_command, source_state, summary, wire,
)
from hepta.hia_entry_layout import LAYOUT

FIXTURES, METRICS = release.FIXTURES, release.METRICS
WRAPPER, CANDIDATE = "hia_empty_wrapper", "hia_guarded_outline"
ARMS = (*release.ARMS, WRAPPER, CANDIDATE)
child_driver = empty.child_driver


def specification():
    historical = release.specification(release.INDUCTION_PROFILE)
    previous = empty.specification(empty.WRAPPER_PROFILE)["groups"][-1]
    groups = [
        {"name": "historical_regression", "sizes": historical["regression_sizes"], "seeds": historical["seeds"]},
        {"name": "historical_holdout", "sizes": historical["holdout_sizes"], "seeds": historical["seeds"]},
        {"name": "prior_wrapper_lengths", "sizes": previous["sizes"], "seeds": previous["seeds"]},
        {"name": "prospective_lengths", "sizes": [31, 101, 331, 1327, 5317, 21269, 85037, 340157],
         "seeds": [20011, 20021, 4294967197]},
    ]
    return {
        "schema": "hepta.hia.guarded-outline-observation.protocol.v1",
        "layout": LAYOUT, "historical_profile": historical, "arms": list(ARMS), "groups": groups,
        "batch_loads": historical["batch_loads"], "samples": historical["samples"],
        "warmup_calls": historical["warmup_calls"], "performance_gate": historical["performance_gate"],
        "correctness_sizes": historical["correctness_sizes"],
        "refusal_boundary_sizes": historical["refusal_boundary_sizes"],
        "cost_horizons": historical["cost_horizons"],
        "timing_requests": 3348, "timed_batches": 70308, "timed_kernel_calls": 1898316,
        "order": "retain old four-arm seed rotation/reversal; insert old wrapper at seed index and outline at (seed index+3)%6",
        "registration": "exact source/tool bindings and all cohorts saved before proof, compilation, correctness or timing",
        "sample_exclusion": "none; every native sample and failure retained; no best-of retry",
        "baseline_scope": "Rust 1.95.0 O3/fat-LTO/single-codegen-unit conventional and explicit-byte sources; PGO not included",
        "prospective_scope": "new registered lengths and seeds for two existing workloads, not a new program population",
        "claims_limits": [
            "shared Linux x86_64 host; fixed process affinity is not exclusive ownership",
            "batch p95/p99 are not per-invocation tails",
            "compiler/linker/libc/hardware trusted; no machine-checked backend refinement",
            "new layout preserves original Core, including evaluator steps; native layout is explicitly opt-in",
            "both branch components inherit the original whole-function initialization decision",
            "all automated current build/proof/load/execute costs recorded; human engineering, acquisition and energy unknown",
            "source parsing is independently repeated and charged to each HIA arm",
            "amortization uses observed warm medians; cold-first-call observations are reported separately",
        ],
    }


def bindings():
    return {**empty.bindings(), str(Path(__file__).relative_to(ROOT)): file_identity(__file__)["sha256"],
            "tests/test_hia_entry_layout.py": file_identity(ROOT / "tests/test_hia_entry_layout.py")["sha256"],
            "tests/test_hia_outlined_aot_protocol.py": file_identity(ROOT / "tests/test_hia_outlined_aot_protocol.py")["sha256"],
            "benchmarks/hia_outlined_aot/PROTOCOL.json": file_identity(ROOT / "benchmarks/hia_outlined_aot/PROTOCOL.json")["sha256"]}


def assess(rows, spec):
    require(type(spec) is dict and wire(spec) == wire(specification()),
            "changed guarded-outline observation registration")
    expected = {(w, g["name"], a, n, seed, calls)
                for w in spec["historical_profile"]["workloads"] for g in spec["groups"]
                for a in ARMS for n in g["sizes"] for seed in g["seeds"] for calls in spec["batch_loads"]}
    require(type(rows) is list and len(rows) == len(expected), "complete registered cohort inventory required")
    require(all(type(r) is dict and all(type(r.get(k)) is str for k in ("workload", "group", "backend"))
                and all(type(r.get(k)) is int for k in ("n", "seed", "calls")) for r in rows),
            "cohort field types must match registration")
    actual = [(r["workload"], r["group"], r["backend"], r["n"], r["seed"], r["calls"]) for r in rows]
    require(len(actual) == len(set(actual)) and set(actual) == expected, "missing, duplicate or unexpected cohort")
    require(all(type(r["calls"]) is int and r["calls"] in spec["batch_loads"]
                and type(r["times_ns"]) is list and len(r["times_ns"]) == spec["samples"]
                and all(type(v) is int and v > 0 for v in r["times_ns"]) for r in rows),
            "missing/padded samples or changed batch load")
    grouped = {}
    for row in rows:
        key = (row["workload"], row["group"], row["n"], row["calls"], row["backend"])
        grouped.setdefault(key, []).extend(row["times_ns"])
    cohorts, comparisons = [], []
    gate = spec["performance_gate"]
    for workload in spec["historical_profile"]["workloads"]:
        for group in spec["groups"]:
            for n in group["sizes"]:
                for calls in spec["batch_loads"]:
                    values = {a: summary(grouped[(workload, group["name"], n, calls, a)]) for a in ARMS}
                    common = {"workload": workload, "group": group["name"], "n": n, "calls": calls}
                    cohorts.append({**common, "summaries": values})
                    for baseline in ARMS[:-1]:
                        ratios = {s + "_ratio": values[CANDIDATE][s] / values[baseline][s] for s in ("median", "p95", "p99")}
                        passed = all(ratios[s + "_ratio"] <= gate[s + "_ratio_maximum"] for s in ("median", "p95", "p99"))
                        comparisons.append({**common, "baseline": baseline, **ratios, "passed": passed})
    rust = [r for r in comparisons if r["baseline"].startswith("rust")]
    return {"cohorts": cohorts, "comparisons": comparisons,
            "candidate_rust_comparisons_passed": sum(r["passed"] for r in rust),
            "candidate_rust_comparisons_total": len(rust),
            "candidate_all_registered_rust_gates_passed": bool(rust) and all(r["passed"] for r in rust),
            "by_group": {g["name"]: {"passed": sum(r["passed"] for r in rust if r["group"] == g["name"]),
                                         "total": sum(r["group"] == g["name"] for r in rust)} for g in spec["groups"]},
            "broad_rust_performance_parity_established": False, "full_lifecycle_net_benefit_established": False}

def build_references(output,clang,rustc,report):
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
    for workload in report["protocol"]["historical_profile"]["workloads"]:
        directory=output/workload;directory.mkdir()
        report["artifacts"][workload]={};report["compilation"][workload]={};report["backend_build_wall_ns"][workload]={}
        for arm in release.ARMS:
            started=time.monotonic_ns()
            target=directory/(arm+".so")
            if arm.startswith("hia"):
                core=lower_source((FIXTURES/(workload+".hepta")).read_text())
                (directory/"checked.core.json").write_bytes(core.canonical_bytes+b"\n")
                obj=directory/(arm+".o")
                if arm=="hia_checked":
                    with release.capture_native_commands(output,ledger):
                        receipt=build_program_native(core,obj,clang=str(clang),kind="object")
                else:
                    proposal=propose_reduction_pipeline(core,
                        include_induction=report["protocol"]["historical_profile"].get("include_induction",False))
                    (directory/"PROPOSAL.json").write_bytes(wire(proposal)+b"\n")
                    with release.capture_native_commands(output,ledger):
                        receipt=build_reduction_native(core,proposal,obj,clang=str(clang),kind="object")
                report["compilation"][workload][arm]=receipt
                run_command([clang,"-shared",obj,output/"metrics.o",output/"probe_exports.o",*wraps,"-o",target],output,ledger)
            else:
                source=FIXTURES/(workload+("_byte" if arm=="rust_byte_release" else "")+".rs")
                args=[rustc,"--edition=2021","--crate-type=cdylib","--emit=link="+str(target)+",asm="+str(directory/(arm+".s"))]
                for flag in report["protocol"]["historical_profile"]["rust_flags"]: args += ["-C",flag]
                args += ["-C","linker="+str(clang),"-C","link-arg="+str(output/"metrics.o")]
                for flag in wraps: args += ["-C","link-arg="+flag]
                # Fat LTO plus --emit=link,asm can produce additional .rcgu
                # intermediates beside the compiler's working directory even
                # with explicitly named final outputs. Keep those bytes in
                # this arm's evidence directory, outside the source checkout.
                run_command([*args,source],output,ledger,cwd=directory)
            report["backend_build_wall_ns"][workload][arm]=time.monotonic_ns()-started
            report["artifacts"][workload][arm]=file_identity(target)
            assembly=run_command(["/usr/bin/objdump","-d","--disassemble=calculate",target],output,ledger)
            (directory/(arm+".calculate.asm")).write_text(assembly)
    return report["artifacts"]


def build_extras(output, clang, report):
    from hepta.hia_program_source import lower_source
    from hepta.hia_reduction import propose_reduction_pipeline, _admit, reduction_checker_identity
    from hepta.hia_program_llvm import emit_program_llvm, compile_program_llvm
    wrapper_report = {**report, "protocol": empty.specification(empty.WRAPPER_PROFILE)}
    empty.build_candidate(output, clang, wrapper_report)
    for workload in report["protocol"]["historical_profile"]["workloads"]:
        for key in ("artifacts", "compilation", "backend_build_wall_ns"):
            report[key][workload][WRAPPER] = report[key][workload].pop(empty.CANDIDATE)
        directory = output / workload
        started = time.monotonic_ns()
        core = lower_source((FIXTURES / (workload + ".hepta")).read_text())
        proposal = propose_reduction_pipeline(core, include_induction=True)
        proof, candidate = _admit(core, proposal, None)
        ir = emit_program_llvm(candidate, layout=LAYOUT)
        (directory / "OUTLINE_PROPOSAL.json").write_bytes(wire(proposal) + b"\n")
        (directory / "OUTLINE_PROOF.json").write_bytes(wire(proof) + b"\n")
        (directory / "outline.core.json").write_bytes(candidate.canonical_bytes + b"\n")
        (directory / "outline.ll").write_text(ir.text)
        obj, target = directory / (CANDIDATE + ".o"), directory / (CANDIDATE + ".so")
        with release.capture_native_commands(output, report["build_commands"]):
            receipt = compile_program_llvm(ir, program=candidate, output=obj, clang=str(clang), kind="object")
        require(receipt["core_sha256"] == candidate.sha256
                and receipt["entry_layout"] == LAYOUT
                and reduction_checker_identity() == proof["checker_sha256"],
                "outline proof/source/layout identity changed")
        wraps = ["-Wl,--wrap=" + name for name in ("malloc", "calloc", "realloc", "free")]
        run_command([clang, "-shared", obj, output / "metrics.o", output / "probe_exports.o", *wraps, "-o", target],
                    output, report["build_commands"])
        report["backend_build_wall_ns"][workload][CANDIDATE] = time.monotonic_ns() - started
        report["compilation"][workload][CANDIDATE] = {"proof": proof, "native": receipt}
        report["artifacts"][workload][CANDIDATE] = file_identity(target)
        for name, argv in (
            ("all.asm", ["/usr/bin/objdump", "-dr", obj]),
            ("calculate.asm", ["/usr/bin/objdump", "-d", "--disassemble=calculate", target]),
            ("symbols.txt", ["/usr/bin/nm", "-S", "--defined-only", obj]),
            ("sections.txt", ["/usr/bin/size", "-A", obj]),
        ):
            (directory / (CANDIDATE + "." + name)).write_text(run_command(argv, output, report["build_commands"]))


def cost_and_memory(report):
    arms = {}
    for workload in report["protocol"]["historical_profile"]["workloads"]:
        arms[workload] = {}
        for arm in ARMS:
            rows = [r for r in report["measurements"] if r["workload"] == workload and r["backend"] == arm]
            loads = [r for r in report["loads"] if r["workload"] == workload and r["backend"] == arm]
            arms[workload][arm] = {
                "compile_and_proofs_wall_ns": report["backend_build_wall_ns"][workload][arm],
                "load_ns": summary([r["load_ns"] for r in loads]),
                "library_file_bytes": report["artifacts"][workload][arm]["bytes"],
                "loader_mapped_bytes_max": max(r["mapping"]["mapped_bytes"] for r in loads),
                "loader_backing_resident_bytes_max": max(r["mapping"]["backing_resident_bytes"] for r in loads),
                "allocation_peak_requested_max": max(r["metrics"]["peak_requested"] for r in rows),
                "allocation_peak_usable_max": max(r["metrics"]["peak_usable"] for r in rows),
                "process_maxrss_kib_max": max(r["maxrss_kib"] for r in rows),
                "first_library_calls": [
                    {k: r[k] for k in ("group", "n", "seed", "cold_ns", "cold_value")}
                    for r in rows if r["first_library_call"]],
            }
    horizons = []
    for cohort in report["assessment"]["cohorts"]:
        workload = cohort["workload"]
        calls = cohort["calls"]
        per_call = {a: cohort["summaries"][a]["median"] / calls for a in ARMS}
        costs = {a: arms[workload][a]["compile_and_proofs_wall_ns"] + arms[workload][a]["load_ns"]["median"]
                 for a in ARMS}
        for count in report["protocol"]["cost_horizons"]:
            totals = {a: costs[a] + count * per_call[a] for a in ARMS}
            horizons.append({**{k: cohort[k] for k in ("workload", "group", "n", "calls")},
                             "invocations": count, "estimated_automated_cost_ns": totals,
                             "outline_minus_best_rust_ns": totals[CANDIDATE] - min(
                                 totals["rust_release"], totals["rust_byte_release"])})
    return {"arms": arms, "amortization": horizons,
            "amortization_equation": "actual arm build/proof/frontend wall + median actual load wall + horizon * observed warm batch median / batch calls",
            "cold_start_scope": "actual first-library-call latency and values retained separately; warm model is not a cold-tail guarantee",
            "measurement_apparatus_scope": "shared metrics and driver builds, test probes and instrumentation are in whole campaign wall but are not charged to one language arm",
            "manual_engineering_ns": None, "historical_tool_acquisition_ns": None, "energy_joules": None,
            "full_lifecycle_net_benefit_established": False}


def run(output, clang, rustc, *, cpu=None):
    started = time.monotonic_ns()
    output = Path(output).resolve()
    require(output != ROOT and ROOT not in output.parents, "evidence output must be outside source checkout")
    output.mkdir(parents=True, exist_ok=False)
    affinity, spec = sorted(os.sched_getaffinity(0)), specification()
    selected = affinity[0] if cpu is None else cpu
    require(type(selected) is int and selected in affinity, "selected CPU must belong to the inherited affinity")
    report = {"schema": "hepta.hia.guarded-outline-observation.result.v1", "status": "running",
              "started_utc": datetime.now(timezone.utc).isoformat(), "protocol": spec,
              "protocol_sha256": digest(spec), "source_before": source_state(), "bindings_before": bindings(),
              "host": {"platform": platform.platform(), "machine": platform.machine(), "original_affinity": affinity,
                       "selected_cpu": selected, "exclusive": False, "loadavg_before": list(os.getloadavg())},
              "build_commands": [], "measurements": [], "correctness": [], "refusals": [], "loads": [],
              "stage_wall_ns": {}, "manual_engineering_ns": None, "energy_joules": None,
              "historical_tool_acquisition_ns": None, "entry_layout_opt_in": True, "load_observations": []}
    (output / "REGISTRATION.json").write_bytes(wire(report) + b"\n")

    def checkpoint():
        (output / "RESULT.json").write_bytes(wire(report) + b"\n")

    try:
        require(report["source_before"]["status"] == "", "clean committed source required before campaign")
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86_64 required")
        os.sched_setaffinity(0, {selected})
        report["toolchains"] = {}
        for name, tool in (("clang", clang), ("rustc", rustc), ("objdump", Path("/usr/bin/objdump")),
                           ("nm", Path("/usr/bin/nm")), ("size", Path("/usr/bin/size"))):
            report["toolchains"][name] = {**file_identity(tool), "version": run_command([tool, "--version"], output, report["build_commands"])}
        require(report["toolchains"]["rustc"]["version"].startswith("rustc 1.95.0 "), "actual Rust 1.95.0 required")
        stage = time.monotonic_ns()
        build_references(output, clang, rustc, report)
        build_extras(output, clang, report)
        report["stage_wall_ns"]["build_and_proofs"] = time.monotonic_ns() - stage
        checkpoint()
        stage = time.monotonic_ns()
        for workload in spec["historical_profile"]["workloads"]:
            for arm in ARMS:
                with child_driver(output / "driver", output / f"correctness-{workload}-{arm}.jsonl") as child:
                    child.load(arm, report["artifacts"][workload])
                    for n in spec["correctness_sizes"]:
                        for fail in (0, 1):
                            report["correctness"].append(child.measure(workload, arm, n, 4294967295, 1, 1, fail=fail))
                    for n in spec["refusal_boundary_sizes"]:
                        report["refusals"].append(child.refusal(workload, arm, n, 4294967295))
                checkpoint()
        report["stage_wall_ns"]["correctness_refusal"] = time.monotonic_ns() - stage
        stage = time.monotonic_ns()
        for workload in spec["historical_profile"]["workloads"]:
            for group in spec["groups"]:
                for offset, seed in enumerate(group["seeds"]):
                    arms = list(release.ARMS[offset:] + release.ARMS[:offset])
                    if offset % 2:
                        arms.reverse()
                    arms.insert(offset, WRAPPER)
                    arms.insert((offset + 3) % len(ARMS), CANDIDATE)
                    report["load_observations"].append({"workload": workload, "group": group["name"],
                        "seed": seed, "loadavg": list(os.getloadavg()), "monotonic_ns": time.monotonic_ns()})
                    for arm in arms:
                        name = f"timing-{workload}-{group['name']}-{offset}-{arm}.jsonl"
                        with child_driver(output / "driver", output / name) as child:
                            report["loads"].append({"workload": workload, "group": group["name"], "backend": arm,
                                                    **child.load(arm, report["artifacts"][workload])})
                            for n in group["sizes"]:
                                for calls in spec["batch_loads"]:
                                    row = child.measure(workload, arm, n, seed, calls, spec["samples"], spec["warmup_calls"])
                                    row["group"] = group["name"]
                                    report["measurements"].append(row)
                        checkpoint()
        report["stage_wall_ns"]["timing"] = time.monotonic_ns() - stage
        historical = [{**r, "phase": r["group"].removeprefix("historical_")}
                      for r in report["measurements"] if r["group"].startswith("historical_") and r["backend"] in release.ARMS]
        report["historical_v2_replay_assessment"] = release.assess(historical, spec["historical_profile"])
        report["assessment"] = assess(report["measurements"], spec)
        report["cost_and_memory"] = cost_and_memory(report)
        report["status"] = "completed"
    except BaseException as error:
        report.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    finally:
        os.sched_setaffinity(0, set(affinity))
        report["source_after"], report["bindings_after"] = source_state(), bindings()
        report["source_unchanged"] = (report["source_before"] == report["source_after"] and report["bindings_before"] == report["bindings_after"])
        identities = {"tool:" + k: v for k, v in report.get("toolchains", {}).items()}
        identities.update({w + ":" + a: v for w, arms in report.get("artifacts", {}).items() for a, v in arms.items()})
        if "driver_identity" in report:
            identities["driver"] = report["driver_identity"]
        report["identities_after"] = {}
        for label, identity in identities.items():
            try:
                report["identities_after"][label] = file_identity(identity["path"])
            except OSError:
                report["identities_after"][label] = None
        report["tool_artifact_identities_unchanged"] = all(report["identities_after"][k] is not None
            and all(report["identities_after"][k][f] == v[f] for f in ("path", "bytes", "sha256")) for k, v in identities.items())
        report["host"]["loadavg_after"] = list(os.getloadavg())
        report["whole_lifecycle_wall_ns"] = time.monotonic_ns() - started
        report["qualification_valid"] = (report["status"] == "completed" and report["source_unchanged"] and report["tool_artifact_identities_unchanged"])
        report["report_sha256"] = digest(report)
        checkpoint()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--cpu", type=int)
    args = parser.parse_args()
    report = run(args.output, args.clang, args.rustc, cpu=args.cpu)
    print(json.dumps({"status": report["status"], "qualification_valid": report["qualification_valid"],
                      "assessment": {k: v for k, v in report.get("assessment", {}).items()
                                     if k not in {"cohorts", "comparisons"}},
                      "whole_lifecycle_wall_ns": report["whole_lifecycle_wall_ns"]}, sort_keys=True))
    raise SystemExit(0 if report["qualification_valid"] else 1)


if __name__ == "__main__":
    main()
