#!/usr/bin/env python3
"""A frozen native release comparison; negative performance is a valid result.

Uses the existing fallible-owned-buffer workload and actual allocator probes.
The additional sizes are held out from the earlier campaign, not external
production traffic or independent application families. No tuning uses them.
"""
from __future__ import annotations

import argparse
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

from tools.qualify_hia_native_ndu import (
    build, digest, driver, file_identity, protocol, source_inventory,
    source_state, summary, wire,
)
from tools.provider_adapter.llama_cpp_engine import resource_observation


def specification():
    base = protocol()
    return {"schema": "hepta.hia.release-parity.protocol.v1",
            "workload": base["workload"], "semantics": base["semantics"],
            "build_profile": "optimized-release-v1", "backends": base["backends"],
            "training_sizes": base["sizes"], "training_seeds": base["training_seeds"],
            "holdout_sizes": [2, 63, 257, 1025, 8193, 32769, 65535],
            "holdout_seeds": [383, 659, 1069],
            "correctness_sizes": base["correctness_sizes"],
            "correctness_seeds": base["correctness_seeds"],
            "batch_calls": base["batch_calls"], "samples": base["training_samples_per_request"],
            "warmup_calls": base["warmup_calls"],
            "performance_gate": base["performance_gate"],
            "order": "rotate backends by seed index, reverse odd rotations; preserve every sample",
            "decision_rule": "No tuning, retries, trimming or best-of selection after measurements.",
            "limits": ["One bounded owned-buffer kernel, not multiple independent applications.",
                       "63 batch samples per backend/size; p99 equals the observed maximum, not per-call p99.",
                       "One shared host; affinity does not imply exclusive CPU or stable frequency.",
                       "Energy, manual engineering and past tool acquisition are unknown."]}


def bindings():
    values = source_inventory()
    for name in ("tools/qualify_hia_release_parity.py", "tools/provider_adapter/llama_cpp_engine.py"):
        values[name] = file_identity(ROOT / name)["sha256"]
    return values


def assess(rows, spec):
    expected = {(phase, backend, n, seed)
                for phase in ("training", "holdout") for backend in spec["backends"]
                for n in spec[phase+"_sizes"] for seed in spec[phase+"_seeds"]}
    keys = [(row["phase"], row["backend"], row["n"], row["seed"]) for row in rows]
    if len(keys) != len(set(keys)) or set(keys) != expected:
        raise ValueError("E_RELEASE_COHORT: missing, duplicated or unexpected native request")
    if any(len(row["times_ns"]) != spec["samples"] for row in rows):
        raise ValueError("E_RELEASE_COHORT: incomplete or padded batch samples")
    cohorts, comparisons = {}, []
    gate = spec["performance_gate"]
    for phase in ("training", "holdout"):
        cohorts[phase] = {}
        for n in spec[phase+"_sizes"]:
            values = {backend: summary([value for row in rows
                      if row["phase"] == phase and row["backend"] == backend and row["n"] == n
                      for value in row["times_ns"]]) for backend in spec["backends"]}
            cohorts[phase][str(n)] = values
            for backend in ("c", "cpp", "rust"):
                reference, hia = values[backend], values["hia"]
                ratios = {stat+"_ratio": hia[stat]/reference[stat] for stat in ("median", "p95", "p99")}
                comparisons.append({"phase": phase, "size": n, "baseline": backend, **ratios,
                    "passed": ratios["median_ratio"] <= gate["hia_median_ratio_maximum"]
                              and ratios["p95_ratio"] <= gate["hia_tail_ratio_maximum"]})
    return {"cohorts": cohorts, "comparisons": comparisons,
            "performance_gate_passed": all(row["passed"] for row in comparisons),
            "holdout_gate_passed": all(row["passed"] for row in comparisons if row["phase"] == "holdout"),
            "rust_comparisons_passed": sum(row["passed"] for row in comparisons if row["baseline"] == "rust"),
            "all_rust_comparisons": sum(row["baseline"] == "rust" for row in comparisons),
            "broad_rust_performance_parity_established": False}


def run(output, clang, rustc):
    started = time.monotonic_ns()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    spec = specification()
    original_affinity = sorted(os.sched_getaffinity(0))
    selected_cpu = original_affinity[0]
    report = {"schema": "hepta.hia.release-parity.result.v1", "status": "running",
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "protocol": spec, "protocol_sha256": digest(spec),
              "source_before": source_state(), "bindings_before": bindings(),
              "host": {"platform": platform.platform(), "machine": platform.machine(),
                       "original_affinity": original_affinity, "selected_cpu": selected_cpu,
                       "exclusive_host": False},
              "resources_before": resource_observation(),
              "measurements": [], "correctness": [], "loads": [], "stage_wall_ns": {},
              "whole_lifecycle_cost_ns": None, "manual_engineering_ns": None, "energy_joules": None}
    (output / "REGISTRATION.json").write_bytes(wire(report)+b"\n")

    def checkpoint():
        (output / "RESULT.json").write_bytes(wire(report)+b"\n")

    try:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("E_RELEASE_HOST: this campaign qualifies Linux x86_64 only")
        os.sched_setaffinity(0, {selected_cpu})
        stage = time.monotonic_ns()
        try:
            products = build(output, clang, rustc, report, build_profile=spec["build_profile"])
        finally:
            report["stage_wall_ns"]["build"] = time.monotonic_ns()-stage
            checkpoint()
        for phase in ("training", "holdout"):
            stage = time.monotonic_ns()
            try:
                for offset, seed in enumerate(spec[phase+"_seeds"]):
                    names = spec["backends"][offset:]+spec["backends"][:offset]
                    if offset % 2:
                        names.reverse()
                    for backend in names:
                        with driver(output / "driver", output / f"{phase}-{offset}-{backend}.jsonl") as child:
                            report["loads"].append({"phase": phase, "backend": backend, **child.load(backend, products)})
                            for n in spec[phase+"_sizes"]:
                                row = child.measure(backend, n, seed, spec["batch_calls"], spec["samples"], spec["warmup_calls"])
                                row.update(phase=phase, mapping_after=child.mapping(products[backend]["path"]))
                                report["measurements"].append(row)
                        checkpoint()
            finally:
                report["stage_wall_ns"][phase] = time.monotonic_ns()-stage
                checkpoint()
        stage = time.monotonic_ns()
        try:
            for backend in spec["backends"]:
                with driver(output / "driver", output / f"correctness-{backend}.jsonl") as child:
                    child.load(backend, products)
                    for n in spec["correctness_sizes"]:
                        for seed in spec["correctness_seeds"]:
                            report["correctness"].append(child.measure(backend, n, seed, 1, 1))
                        report["correctness"].append(child.measure(backend, n, 29, 1, 1, fail=1))
                checkpoint()
        finally:
            report["stage_wall_ns"]["correctness_and_refusal"] = time.monotonic_ns()-stage
        report["assessment"] = assess(report["measurements"], spec)
        report["status"] = "completed"
    except BaseException as error:
        report.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    finally:
        os.sched_setaffinity(0, set(original_affinity))
        report["source_after"], report["bindings_after"] = source_state(), bindings()
        report["source_unchanged"] = (report["source_before"] == report["source_after"]
                                      and report["bindings_before"] == report["bindings_after"])
        report["identities_after"] = {}
        report["tool_and_artifact_identities_unchanged"] = True
        recorded = {"tool:"+key: value for key, value in report.get("toolchains", {}).items()}
        recorded.update({"artifact:"+key: value for key, value in report.get("native_artifacts", {}).items()})
        if "driver_identity" in report:
            recorded["driver"] = report["driver_identity"]
        for name, value in recorded.items():
            try:
                actual = file_identity(value["path"])
                stable = all(actual[key] == value[key] for key in ("path", "bytes", "sha256"))
                report["identities_after"][name] = actual
            except OSError as error:
                stable = False
                report["identities_after"][name] = {"error": type(error).__name__}
            report["tool_and_artifact_identities_unchanged"] &= stable
        report["resources_after"] = resource_observation()
        report["campaign_wall_ns"] = time.monotonic_ns()-started
        report["other_measured_wall_ns"] = report["campaign_wall_ns"]-sum(report["stage_wall_ns"].values())
        report["cost_scope"] = "Campaign wall includes setup, build, load, validation, all samples, probes, cleanup and reporting to final snapshot; stage rows partition this interval. Build-command/backend timings are nested, never added again. Earlier tool acquisition, human time and energy are unknown."
        report["valid_observation"] = (report["status"] == "completed" and report["source_unchanged"]
                                       and report["tool_and_artifact_identities_unchanged"])
        if not report["valid_observation"] and "assessment" in report:
            report["invalidated_assessment"] = report.pop("assessment")
        checkpoint()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--rustc", required=True)
    args = parser.parse_args()
    result = run(args.output, args.clang, args.rustc)
    print(json.dumps({"status": result["status"], "valid_observation": result["valid_observation"],
                      "performance_gate_passed": result.get("assessment", {}).get("performance_gate_passed"),
                      "campaign_wall_ns": result["campaign_wall_ns"]}))
    return 0 if result["valid_observation"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
