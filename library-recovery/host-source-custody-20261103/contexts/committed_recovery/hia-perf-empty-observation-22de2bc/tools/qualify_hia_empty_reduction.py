#!/usr/bin/env python3
"""Observe an isolated empty-entry candidate; historical release gates stay intact.

All v2 cohorts, samples and thresholds remain present beside a prospective group
of new lengths/seeds. All failures are retained. No production admission changes.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import qualify_hia_reduction_release as release
from tools.qualify_hia_native_ndu import (digest, file_identity, require,
                                         run_command, source_state, summary, wire)

ARMS = (*release.ARMS, "hia_empty_candidate")
CANDIDATE = ARMS[-1]


def specification():
    historical = release.specification(release.INDUCTION_PROFILE)
    return {
        "schema": "hepta.hia.empty-reduction-observation.protocol.v1",
        "historical_profile": historical, "arms": list(ARMS),
        "groups": [
            {"name": "historical_regression", "sizes": historical["regression_sizes"], "seeds": historical["seeds"]},
            {"name": "historical_holdout", "sizes": historical["holdout_sizes"], "seeds": historical["seeds"]},
            {"name": "prospective_lengths", "sizes": [23, 89, 283, 1151, 4337, 17333, 69497, 277393],
             "seeds": [10007, 10009, 4294967279]},
        ],
        "batch_loads": historical["batch_loads"], "samples": historical["samples"],
        "warmup_calls": historical["warmup_calls"], "performance_gate": historical["performance_gate"],
        "correctness_sizes": historical["correctness_sizes"], "refusal_boundary_sizes": historical["refusal_boundary_sizes"],
        "order": "old arms retain v2 rotation/reversal within each seed; insert candidate at seed index; repeat for every group",
        "registration": "saved before proof, compilation or timing; candidate chosen after historical v2 observations",
        "sample_exclusion": "none; every native sample and failure retained",
        "prospective_scope": "new lengths/seeds in two existing workloads; no unseen-program or application claim",
        "claims_limits": ["experimental candidate; production admission unchanged",
            "shared Linux x86_64 host; affinity is not exclusive ownership",
            "batch p95/p99 are not single-call tails",
            "compiler/linker/libc/hardware trusted; no backend refinement theorem",
            "Core quotas excluded; candidate adds three steps per transformed entry",
            "all current costs recorded; full lifecycle advantage not established"],
    }


def bindings():
    return {**release.bindings(), str(Path(__file__).relative_to(ROOT)): file_identity(__file__)["sha256"]}


class CandidateDriver(release.ReductionDriver):
    """A separate child loads each arm into slot zero of the unchanged C driver."""
    def load(self, label, products):
        return super().load("hia_checked", {"hia_checked": products[label]})

    def measure(self, workload, label, *args, **kwargs):
        row = super().measure(workload, "hia_checked", *args, **kwargs)
        row["backend"] = label
        return row

    def refusal(self, workload, label, *args):
        row = super().refusal(workload, "hia_checked", *args)
        row["backend"] = label
        return row


@contextmanager
def child_driver(executable, path):
    child = CandidateDriver(executable, path)
    try:
        yield child
    finally:
        child.close()


def assess(rows, spec):
    require(spec == specification(), "changed empty-entry observation registration")
    expected = {(w, g["name"], a, n, seed, calls)
                for w in spec["historical_profile"]["workloads"] for g in spec["groups"]
                for a in ARMS for n in g["sizes"] for seed in g["seeds"] for calls in spec["batch_loads"]}
    actual = [(r["workload"], r["group"], r["backend"], r["n"], r["seed"], r["calls"]) for r in rows]
    require(len(actual) == len(set(actual)) and set(actual) == expected, "missing, duplicate or unexpected cohort")
    require(all(type(r["calls"]) is int and r["calls"] in spec["batch_loads"]
                and len(r["times_ns"]) == spec["samples"]
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
                    for baseline in release.ARMS:
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


def build_candidate(output, clang, report):
    from hepta.hia_empty_reduction import (empty_reduction_program, propose_empty_reduction, verify_empty_reduction)
    from hepta.hia_program_llvm import build_program_native
    from hepta.hia_program_source import lower_source
    from hepta.hia_reduction import propose_reduction_pipeline
    ledger = report["build_commands"]
    for workload in report["protocol"]["historical_profile"]["workloads"]:
        directory = output / workload
        started = time.monotonic_ns()
        core = lower_source((release.FIXTURES / (workload + ".hepta")).read_text())
        reduction = propose_reduction_pipeline(core, include_induction=True)
        proposal = propose_empty_reduction(core, reduction)
        proof = verify_empty_reduction(core, proposal)
        require(proof["status"] == "verified", "empty-entry proof refused")
        candidate = empty_reduction_program(core, proposal)
        require(proof["candidate_sha256"] == candidate.sha256, "fresh candidate identity changed")
        (directory / "EMPTY_PROPOSAL.json").write_bytes(wire(proposal) + b"\n")
        (directory / "EMPTY_PROOF.json").write_bytes(wire(proof) + b"\n")
        (directory / "empty.core.json").write_bytes(candidate.canonical_bytes + b"\n")
        obj, target = directory / (CANDIDATE + ".o"), directory / (CANDIDATE + ".so")
        with release.capture_native_commands(output, ledger):
            receipt = build_program_native(candidate, obj, clang=str(clang), kind="object")
        require(receipt["core_sha256"] == candidate.sha256, "native input identity changed")
        report["compilation"][workload][CANDIDATE] = {"proof": proof, "native": receipt}
        wraps = ["-Wl,--wrap=" + name for name in ("malloc", "calloc", "realloc", "free")]
        run_command([clang, "-shared", obj, output / "metrics.o", output / "probe_exports.o", *wraps, "-o", target], output, ledger)
        report["backend_build_wall_ns"][workload][CANDIDATE] = time.monotonic_ns() - started
        report["artifacts"][workload][CANDIDATE] = file_identity(target)
        for name, argv in (("calculate.asm", ["/usr/bin/objdump", "-d", "--disassemble=calculate", target]),
                           ("symbols.txt", ["/usr/bin/nm", "-S", "--defined-only", obj]), ("sections.txt", ["/usr/bin/size", "-A", obj])):
            (directory / (CANDIDATE + "." + name)).write_text(run_command(argv, output, ledger))


def run(output, clang, rustc):
    started = time.monotonic_ns()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    affinity, spec = sorted(os.sched_getaffinity(0)), specification()
    report = {"schema": "hepta.hia.empty-reduction-observation.result.v1", "status": "running",
              "started_utc": datetime.now(timezone.utc).isoformat(), "protocol": spec,
              "protocol_sha256": digest(spec), "source_before": source_state(), "bindings_before": bindings(),
              "host": {"platform": platform.platform(), "machine": platform.machine(), "original_affinity": affinity,
                       "selected_cpu": affinity[0], "exclusive": False, "loadavg_before": list(os.getloadavg())},
              "build_commands": [], "measurements": [], "correctness": [], "refusals": [], "loads": [],
              "stage_wall_ns": {}, "manual_engineering_ns": None, "energy_joules": None,
              "historical_tool_acquisition_ns": None, "production_admission_changed": False}
    (output / "REGISTRATION.json").write_bytes(wire(report) + b"\n")

    def checkpoint():
        (output / "RESULT.json").write_bytes(wire(report) + b"\n")

    try:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86_64 required")
        os.sched_setaffinity(0, {affinity[0]})
        report["toolchains"] = {}
        for name, tool in (("clang", clang), ("rustc", rustc), ("objdump", Path("/usr/bin/objdump")),
                           ("nm", Path("/usr/bin/nm")), ("size", Path("/usr/bin/size"))):
            report["toolchains"][name] = {**file_identity(tool), "version": run_command([tool, "--version"], output, report["build_commands"])}
        require(report["toolchains"]["rustc"]["version"].startswith("rustc 1.95.0 "), "actual Rust 1.95.0 required")
        stage = time.monotonic_ns()
        build_report = {"protocol": spec["historical_profile"], "build_commands": report["build_commands"]}
        release.build(output, clang, rustc, build_report)
        report.update({k: v for k, v in build_report.items() if k != "protocol"})
        build_candidate(output, clang, report)
        report["stage_wall_ns"]["build_and_proofs"] = time.monotonic_ns() - stage
        checkpoint()
        stage = time.monotonic_ns()
        for workload in spec["historical_profile"]["workloads"]:
            for group in spec["groups"]:
                for offset, seed in enumerate(group["seeds"]):
                    arms = list(release.ARMS[offset:] + release.ARMS[:offset])
                    if offset % 2:
                        arms.reverse()
                    arms.insert(offset, CANDIDATE)
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
        historical = [{**r, "phase": r["group"].removeprefix("historical_")}
                      for r in report["measurements"] if r["group"].startswith("historical_") and r["backend"] in release.ARMS]
        report["historical_v2_replay_assessment"] = release.assess(historical, spec["historical_profile"])
        report["assessment"] = assess(report["measurements"], spec)
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
    args = parser.parse_args()
    report = run(args.output, Path(args.clang).resolve(), Path(args.rustc).resolve())
    print(json.dumps({k: report.get(k) for k in ("status", "qualification_valid", "whole_lifecycle_wall_ns", "error")}))
    for name in ("assessment", "historical_v2_replay_assessment"):
        if name in report:
            print(json.dumps({name: {k: v for k, v in report[name].items() if k not in ("cohorts", "comparisons")}}, sort_keys=True))
    return 0 if report["qualification_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
