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
import math
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
from tools.hia_rust_pgo import PROFILE as RUST_PGO_PROFILE, training_registration, prepare_rust_pgo, check_pgo_identities

INITIALIZED_RUST_PGO_PROFILE = "verified-initialized-reduction-rust-pgo-release-v1"
INITIALIZED_PROTOCOL = ROOT / "benchmarks/hia_native_ndu/INITIALIZED_RELEASE_TIMING_PROTOCOL.json"


def specification(build_profile="optimized-release-v1"):
    if build_profile == INITIALIZED_RUST_PGO_PROFILE:
        # The new prospective cohort has one source-bound registration. Never
        # rewrite the older v1/v2 axes or substitute their negative results.
        spec = json.loads(INITIALIZED_PROTOCOL.read_text())
        if (type(spec) is not dict or spec.get("schema") != "hepta.hia.release-parity.protocol.v3"
                or spec.get("build_profile") != build_profile):
            raise ValueError("E_RELEASE_PROFILE: malformed initialized release registration")
        return spec
    if build_profile not in {"optimized-release-v1", "verified-reduction-release-v1",
                             "verified-reduction-narrowed-release-v1", RUST_PGO_PROFILE}:
        raise ValueError("E_RELEASE_PROFILE: unsupported release comparison")
    base = protocol()
    spec = {"schema": "hepta.hia.release-parity.protocol.v1",
            "workload": base["workload"], "semantics": base["semantics"],
            "build_profile": build_profile, "backends": base["backends"],
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
    if build_profile == RUST_PGO_PROFILE:
        spec.update(schema="hepta.hia.release-parity.protocol.v2",
                    rust_pgo=training_registration())
    return spec


def bindings():
    values = source_inventory()
    for name in ("tools/qualify_hia_release_parity.py", "tools/hia_rust_pgo.py",
                 "tools/provider_adapter/llama_cpp_engine.py", "formal/HiaInitializationPrefix.lean",
                 "tools/qualify_hia_initialization_prefix.py"):
        values[name] = file_identity(ROOT / name)["sha256"]
    return values


def _validate_release_registration(spec):
    """Reject vacuous or nonfinite cohorts before set-based coverage checks.

    A duplicate registration can collapse into one element of the expected
    set; an empty axis can make both all([]) acceptance gates appear green.
    Keep both complete training and independent holdout compulsory.
    """
    if type(spec) is not dict or spec.get("backends") != ["c", "cpp", "rust", "hia"]:
        raise ValueError("E_RELEASE_COHORT: exact four-backend registration required")
    for name, low, high in (("training_sizes", 1, 65536),
                             ("holdout_sizes", 1, 65536),
                             ("training_seeds", 0, (1 << 32) - 1),
                             ("holdout_seeds", 0, (1 << 32) - 1)):
        values = spec.get(name)
        if (type(values) is not list or not values
                or any(type(value) is not int or not low <= value <= high for value in values)
                or len(values) != len(set(values))):
            raise ValueError("E_RELEASE_COHORT: invalid or duplicate " + name)
    # The holdout must be unseen in both the workload length and seed dimensions.
    # Comparing phase-tagged rows alone cannot detect a replayed training cohort.
    if (set(spec["training_sizes"]) & set(spec["holdout_sizes"])
            or set(spec["training_seeds"]) & set(spec["holdout_seeds"])):
        raise ValueError("E_RELEASE_COHORT: training and holdout must be disjoint")
    samples = spec.get("samples")
    if type(samples) is not int or not 1 <= samples <= 65536:
        raise ValueError("E_RELEASE_COHORT: invalid native sample count")
    if "schema" in spec:
        if (spec["schema"] not in {"hepta.hia.release-parity.protocol.v1", "hepta.hia.release-parity.protocol.v2",
                                  "hepta.hia.release-parity.protocol.v3"}
                or type(spec.get("build_profile")) is not str):
            raise ValueError("E_RELEASE_COHORT: unknown formal release registration")
        registered = specification(spec["build_profile"])
        if spec["schema"] != registered["schema"] or spec.get("rust_pgo") != registered.get("rust_pgo"):
            raise ValueError("E_RELEASE_COHORT: changed profile or PGO training registration")
        if (spec.get("initialization_coverage") != registered.get("initialization_coverage")
                or spec.get("timing_cohort") != registered.get("timing_cohort")):
            raise ValueError("E_RELEASE_COHORT: changed initialization or prospective timing registration")
        # Full native registrations bind the amount of measured work as well
        # as its axes. The schema-free miniature synthetic cohorts used by
        # acceptance tests are not native experiment registrations.
        for field in ("backends", "training_sizes", "training_seeds", "holdout_sizes",
                      "holdout_seeds", "batch_calls", "samples", "warmup_calls"):
            if (spec.get(field) != registered[field]
                    or field in {"batch_calls", "samples", "warmup_calls"}
                    and type(spec.get(field)) is not int):
                raise ValueError("E_RELEASE_COHORT: changed frozen native work or axis " + field)
    gate = spec.get("performance_gate")
    required = {"hia_median_ratio_maximum", "hia_tail_ratio_maximum",
                "all_baselines_and_sizes_required"}
    if type(gate) is not dict or set(gate) != required or gate["all_baselines_and_sizes_required"] is not True:
        raise ValueError("E_RELEASE_COHORT: incomplete registered performance gate")
    # A finite number can still silently relax the frozen safety limit.
    # Anchor the admission maxima to the source-bound native protocol; only
    # stricter local limits are permissible, never a wider performance gate.
    frozen = protocol().get("performance_gate")
    if (type(frozen) is not dict or set(frozen) != required
            or frozen["all_baselines_and_sizes_required"] is not True):
        raise ValueError("E_RELEASE_COHORT: invalid frozen performance gate")
    for name in ("hia_median_ratio_maximum", "hia_tail_ratio_maximum"):
        value, cap = gate[name], frozen[name]
        if (type(value) not in (int, float) or not math.isfinite(value) or value <= 0
                or type(cap) not in (int, float) or not math.isfinite(cap) or cap <= 0
                or value > cap):
            raise ValueError("E_RELEASE_COHORT: relaxed, nonfinite or invalid " + name)


def assess(rows, spec):
    _validate_release_registration(spec)
    # Require the actual native JSON receipt shape before Python's bool/int and
    # float/int equality can launder an unregistered request into set coverage.
    if type(rows) is not list:
        raise ValueError("E_RELEASE_COHORT: native rows must be a list")
    for row in rows:
        if (type(row) is not dict
                or type(row.get("phase")) is not str
                or type(row.get("backend")) is not str
                or type(row.get("n")) is not int
                or type(row.get("seed")) is not int
                or type(row.get("times_ns")) is not list):
            raise ValueError("E_RELEASE_COHORT: invalid native request or sample shape")
        if "schema" in spec and any(
                type(row.get(field)) is not int or row[field] != spec[registered]
                for field, registered in (("calls", "batch_calls"), ("samples", "samples"))):
            raise ValueError("E_RELEASE_COHORT: native batch work differs from registration")
        samples = row["times_ns"]
        if (len(samples) != spec["samples"]
                or any(type(sample) is not int or not 0 < sample <= (1 << 63) - 1
                       for sample in samples)):
            raise ValueError("E_RELEASE_COHORT: invalid native timing sample")
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
                              and ratios["p95_ratio"] <= gate["hia_tail_ratio_maximum"]
                              and ratios["p99_ratio"] <= gate["hia_tail_ratio_maximum"]})
    return {"cohorts": cohorts, "comparisons": comparisons,
            "native_batch_work_identity_checked": "schema" in spec,
            "performance_gate_passed": all(row["passed"] for row in comparisons),
            "holdout_gate_passed": all(row["passed"] for row in comparisons if row["phase"] == "holdout"),
            "rust_comparisons_passed": sum(row["passed"] for row in comparisons if row["baseline"] == "rust"),
            "all_rust_comparisons": sum(row["baseline"] == "rust" for row in comparisons),
            "broad_rust_performance_parity_established": False}


def _require_initialized_artifact(output, report, spec):
    """Recheck actual optimized Core and object; a saved witness is not input."""
    from hepta.hia_initialization import verify_initialization_coverage
    from hepta.hia_program import verify_program
    core = verify_program((Path(output) / "hia.optimized.core.json").read_bytes())
    coverage = verify_initialization_coverage(core)
    expected = spec["initialization_coverage"]
    function = next((fn for fn in core.as_dict()["functions"] if fn["name"] == expected["function"]), None)
    observed = next((fn for fn in coverage["functions"] if fn["function"] == expected["function"]), None)
    allocations = {op["out"][0]["name"] for block in function["blocks"] for op in block["ops"]
                   if op["op"] in {"buffer.new", "buffer.try_new"}} if function is not None else set()
    covered = {w["allocation"] for w in observed["witnesses"]} if observed is not None else set()
    native = report["hia_compilation"]
    imports = native["binary_inventory"].get("undefined", [])
    if (coverage["core_sha256"] != native["core_sha256"] or observed is None or not observed["eligible"]
            or len(allocations) != expected["expected_local_allocations"] or covered != allocations
            or "malloc" not in imports or "calloc" in imports):
        raise ValueError("E_RELEASE_INITIALIZATION: actual Core coverage or native allocator path differs")
    report["hia_initialization_coverage"] = coverage
    report["initialization_artifact_qualified"] = True
    (Path(output) / "hia.initialization-coverage.json").write_bytes(wire(coverage) + b"\n")


def run(output, clang, rustc, *, build_profile="optimized-release-v1", llvm_profdata=None):
    started = time.monotonic_ns()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    spec = specification(build_profile)
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
            uses_pgo = build_profile in {RUST_PGO_PROFILE, INITIALIZED_RUST_PGO_PROFILE}
            base_profile = "verified-reduction-narrowed-release-v1" if uses_pgo else build_profile
            products = build(output, clang, rustc, report, build_profile=base_profile)
            if uses_pgo:
                products = prepare_rust_pgo(output, clang, rustc, llvm_profdata, products, report,
                                            registration=spec["rust_pgo"])
            if build_profile == INITIALIZED_RUST_PGO_PROFILE:
                _require_initialized_artifact(output, report, spec)
                report["build_profile"].update(id=build_profile, hia_complete_initialization_checked=True)
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
        report["pgo_preparation_qualified"] = (
            check_pgo_identities(report["rust_pgo"]) if "rust_pgo" in report else False)
        report["campaign_wall_ns"] = time.monotonic_ns()-started
        report["other_measured_wall_ns"] = report["campaign_wall_ns"]-sum(report["stage_wall_ns"].values())
        report["cost_scope"] = "Campaign wall includes setup, build, load, validation, all samples, probes, cleanup and reporting to final snapshot; stage rows partition this interval. Build-command/backend timings are nested, never added again. Earlier tool acquisition, human time and energy are unknown."
        report["valid_observation"] = (report["status"] == "completed" and report["source_unchanged"]
                                       and report["tool_and_artifact_identities_unchanged"]
                                       and (build_profile not in {RUST_PGO_PROFILE, INITIALIZED_RUST_PGO_PROFILE}
                                            or report["pgo_preparation_qualified"])
                                       and (build_profile != INITIALIZED_RUST_PGO_PROFILE
                                            or report.get("initialization_artifact_qualified") is True))
        if not report["valid_observation"] and "assessment" in report:
            report["invalidated_assessment"] = report.pop("assessment")
        checkpoint()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--llvm-profdata", help="Explicit matching LLVM20 tool, required by the Rust PGO profile")
    parser.add_argument("--build-profile", default="optimized-release-v1",
                        choices=("optimized-release-v1", "verified-reduction-release-v1",
                                 "verified-reduction-narrowed-release-v1", RUST_PGO_PROFILE,
                                 INITIALIZED_RUST_PGO_PROFILE))
    args = parser.parse_args()
    result = run(args.output, args.clang, args.rustc, build_profile=args.build_profile,
                 llvm_profdata=args.llvm_profdata)
    print(json.dumps({"status": result["status"], "valid_observation": result["valid_observation"],
                      "performance_gate_passed": result.get("assessment", {}).get("performance_gate_passed"),
                      "campaign_wall_ns": result["campaign_wall_ns"]}))
    return 0 if result["valid_observation"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
