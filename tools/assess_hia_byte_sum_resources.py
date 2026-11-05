#!/usr/bin/env python3
"""Replay separately preregistered memory/cost gates over one unchanged AOT run.

No native program, model, compiler or benchmark is executed by this assessor.
Threshold failures remain completed observations; incomplete accounting is invalid.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import qualify_hia_outlined_aot as aot
from tools.qualify_hia_native_ndu import METRIC_NAMES, digest, require, wire

PROTOCOL_PATH = ROOT / "benchmarks/hia_byte_sum_resource_cost.json"
SPECIFICATION = {
    "schema": "hepta.hia.byte-sum-resource-cost.protocol.v1",
    "candidate": "hia_guarded_outline",
    "baselines": [
        "rust_release",
        "rust_byte_release"
    ],
    "historical_protocol_path": "benchmarks/hia_outlined_aot/PROTOCOL.json",
    "historical_protocol_file_sha256": "66d45590cfcd6e7e0a09f31ea91e93d8b04af32eaf974ed2da563648e1ddb31b",
    "historical_protocol_canonical_sha256": "8706e62e4069669a0a8155c7d6b93e9701f23e4836ffa93c9bf14630ffa9ddfa",
    "timing_requests": 3348,
    "rust_runtime_comparisons": 372,
    "allocator_metric_ratio_maximum": 1,
    "allocator_metrics": [
        "requested_total",
        "usable_total",
        "peak_requested",
        "peak_usable",
        "stack_max_distance"
    ],
    "loader_metric_ratio_maximum": 1,
    "loader_metrics": [
        "mapped_bytes",
        "backing_resident_bytes"
    ],
    "library_file_ratio_maximum": 1,
    "build_and_proof_ratio_maximum": 1,
    "median_loader_wall_ratio_maximum": 1,
    "cold_first_call_ratio_maximum": 1.2,
    "estimated_automated_cost_ratio_maximum": 1,
    "cost_horizons": [
        1,
        1000,
        1000000
    ],
    "resource_gate_scope": "Every paired timed workload/group/length/seed/batch observation; every paired library load; file bytes per workload. No extra allowance for stack observation.",
    "cost_gate_scope": "Actual per-arm frontend/proof/build wall, median actual loader wall, every matched first-library-call observation, and every old warm-median amortization horizon. No discarded samples or new measurements.",
    "claim_limits": [
        "Only two authored reduction workloads on one shared nonexclusive x86_64 host.",
        "Stack metric is allocator-hook distance, not a full function stack high-water proof.",
        "Loader mapped/backing-resident pages and file bytes are different observations; RSS is reported but is not an attributable per-arm heap metric.",
        "Cold-first-call observations are individual paired observations, not a population tail guarantee.",
        "Amortization is a warm-median estimate; every raw cold observation and complete campaign wall remain separate.",
        "Development, prerequisite/tool-copy and evidence-postprocess work is reported separately from the measured campaign. Unknown human engineering, energy and historical acquisition remain null.",
        "Passing these finite observed gates does not establish broad Rust parity, universal full lifecycle benefit or a verified machine backend."
    ],
    "rerun_policy": "One preregistered full historical six-arm campaign per frozen candidate. No exclusions, adaptive thresholds, selected-cell reruns, or best-of selection."
}


def specification():
    return deepcopy(SPECIFICATION)


def _integer(value, label, *, positive=False):
    require(type(value) is int and value >= (1 if positive else 0), label)
    return value


def _metric_check(row, n, failed, *, boundary=False):
    metrics = row["metrics"]
    require(type(metrics) is dict and set(metrics) == set(METRIC_NAMES), "complete metric fields")
    for name, value in metrics.items():
        _integer(value, "integer metric " + name)
    attempt = int(n > 0 and (not boundary or n <= 2**63 - 1))
    require(metrics["attempts"] == attempt and metrics["refusals"] == attempt * failed,
            "allocation attempt/refusal sequence")
    require(metrics["allocations"] == metrics["frees"] == attempt * (1 - failed),
            "allocation/free count")
    require(all(metrics[k] == 0 for k in ("live", "live_requested", "live_usable", "accounting_errors")),
            "resource leak or incomplete accounting")
    expected = n if attempt and not failed else 0
    require(metrics["requested_total"] == metrics["peak_requested"] == expected,
            "exact requested total and peak")
    require(metrics["usable_total"] == metrics["peak_usable"] >= expected,
            "exact single-owner usable total and peak")
    if not expected:
        require(metrics["usable_total"] == 0, "no allocation must have zero usable bytes")


def _identity(row):
    return tuple(row[k] for k in ("workload", "group", "n", "seed", "calls"))


def _load_identity(row):
    return tuple(row[k] for k in ("workload", "group", "seed"))


def _check(label, dimension, value, reference, maximum):
    return {"gate": label, **dimension, "candidate": value, "baseline_value": reference,
            "ratio_maximum": maximum, "limit": reference * maximum,
            "passed": value <= reference * maximum}



RAW_RESPONSE_FIELDS = frozenset({
    "id", "n", "seed", "calls", "samples", "observed", "cold_value", "cold_ns",
    "first_library_call", "times_ns", "batch_checksum", "elapsed_ns", "cpu_ns",
    "maxrss_kib", "minor_faults", "major_faults", "voluntary_switches",
    "involuntary_switches", "metrics",
})


def registered_load_schedule(protocol):
    """Reproduce the frozen runner's complete order, including both inserts."""
    result = []
    for workload in protocol["historical_profile"]["workloads"]:
        for group in protocol["groups"]:
            for offset, seed in enumerate(group["seeds"]):
                arms = list(aot.release.ARMS[offset:] + aot.release.ARMS[:offset])
                if offset % 2:
                    arms.reverse()
                arms.insert(offset, aot.WRAPPER)
                arms.insert((offset + 3) % len(aot.ARMS), aot.CANDIDATE)
                for arm in arms:
                    result.append({"workload": workload, "group": group["name"], "seed": seed,
                                   "backend": arm, "offset": offset, "sizes": group["sizes"]})
    return result


def attributed_loads(report, raw_directory):
    """Recover absent load seeds only from the full actual request/response logs.

    The old runner never wrote a seed into its load rows. Its fixed row order
    alone is not sufficient authority: every load, mapping, timed response and
    final child-close acknowledgement is reconciled with its retained log.
    """
    require(raw_directory is not None, "raw timing logs are required for loader attribution")
    raw_directory = Path(raw_directory)
    protocol = report["protocol"]
    schedule = registered_load_schedule(protocol)
    require(len(report["loads"]) == len(schedule), "complete native load schedule")
    observations = [(w, g["name"], seed) for w in protocol["historical_profile"]["workloads"]
                    for g in protocol["groups"] for seed in g["seeds"]]
    require(len(report["load_observations"]) == len(observations), "complete load-observation schedule")
    previous = -1
    for row, expected in zip(report["load_observations"], observations):
        require(_load_identity(row) == expected, "load observation identity/order")
        moment = _integer(row["monotonic_ns"], "load observation monotonic time", positive=True)
        require(moment >= previous, "load observation time ordering")
        previous = moment
    indexed = {(_identity(row), row["backend"]): row for row in report["measurements"]}
    associated = []
    for ordinal, (row, expected) in enumerate(zip(report["loads"], schedule)):
        w, group, seed, arm = (expected[k] for k in ("workload", "group", "seed", "backend"))
        require((row["workload"], row["group"], row["backend"]) == (w, group, arm),
                "native loader record order changed")
        if "seed" in row:
            require(type(row["seed"]) is int and row["seed"] == seed, "explicit load seed disagrees")
        name = f"timing-{w}-{group}-{expected['offset']}-{arm}.jsonl"
        path = raw_directory / name
        try:
            require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 512 * 1024,
                    "bounded regular native timing log required")
            raw = path.read_bytes()
        except OSError as error:
            raise ValueError("E_HIA_NATIVE_ECONOMICS: missing raw timing log " + name) from error
        records = [json.loads(line) for line in raw.splitlines()]
        timed = [(n, calls) for n in expected["sizes"] for calls in protocol["batch_loads"]]
        commands = [
            "L 0 " + report["artifacts"][w][arm]["path"],
            "M 0",
            *[f"R 0 {n} {seed} {calls} {protocol['samples']} {protocol['warmup_calls']} 0"
              for n, calls in timed],
            "Q",
        ]
        require(len(records) == 2 + 2 * len(commands), "complete raw native request/response/exit inventory")
        def response(record, sequence):
            require(set(record) == {"sequence", "response_hex"} and type(record["sequence"]) is int
                    and record["sequence"] == sequence and type(record["response_hex"]) is str,
                    "raw response sequence/shape")
            value = json.loads(bytes.fromhex(record["response_hex"]).decode("utf-8"))
            require(type(value) is dict, "native JSON object response")
            return value
        ready = response(records[0], 0)
        require(set(ready) == {"ready", "pid"} and ready["ready"] is True
                and type(ready["pid"]) is int and ready["pid"] > 0, "raw native readiness")
        for sequence, command in enumerate(commands, 1):
            request, encoded = records[2 * sequence - 1:2 * sequence + 1]
            require(request == {"sequence": sequence, "request": command}, "raw native request binding")
            value = response(encoded, sequence)
            if sequence == 1:
                require(set(value) == {"loaded", "load_ns"} and value["loaded"] == 0
                        and all(row.get(k) == v for k, v in value.items()), "raw loader observation binding")
            elif sequence == 2:
                require(set(value) == {"status", "mapped_bytes", "backing_resident_bytes", "mincore_failed_pages"}
                        and all(row["mapping"].get(k) == v for k, v in value.items()),
                        "raw mapping observation binding")
            elif command == "Q":
                require(value == {"closed": True}, "actual native child close acknowledgement")
            else:
                n, calls = timed[sequence - 3]
                observed = indexed[((w, group, n, seed, calls), arm)]
                require(set(value) == RAW_RESPONSE_FIELDS, "complete raw timed response fields")
                require(type(value["metrics"]) is list and len(value["metrics"]) == len(METRIC_NAMES),
                        "raw allocator fields")
                value["metrics"] = dict(zip(METRIC_NAMES, value["metrics"]))
                require(all(observed.get(k) == v for k, v in value.items()), "raw timed response binding")
        terminal = records[-1]
        require(set(terminal) == {"exit_code", "stderr_hex"} and terminal["exit_code"] == 0
                and type(terminal["stderr_hex"]) is str, "native child terminal receipt")
        stderr = bytes.fromhex(terminal["stderr_hex"])
        associated.append({**row, "seed": seed, "source_load_ordinal": ordinal,
                           "raw_trace_file": name, "raw_trace_sha256": sha256(raw).hexdigest(),
                           "retained_stderr_bytes": len(stderr)})
    return associated


def validate_complete_result(report, spec, *, raw_directory=None):
    old = aot.specification()
    require(wire(spec) == wire(specification()), "resource/cost protocol changed")
    require(digest(old) == spec["historical_protocol_canonical_sha256"], "historical protocol changed")
    protocol_file = ROOT / spec["historical_protocol_path"]
    require(sha256(protocol_file.read_bytes()).hexdigest() == spec["historical_protocol_file_sha256"],
            "historical protocol file bytes changed")
    require(wire(report["protocol"]) == wire(old) and report["protocol_sha256"] == digest(old),
            "run did not use the unchanged complete historical protocol")
    require(report["status"] == "completed"
            and report["qualification_valid"] is True
            and report["source_unchanged"] is True
            and report["tool_artifact_identities_unchanged"] is True, "completed stable run required")
    require(report["source_before"] == report["source_after"]
            and report["source_before"]["status"] == "", "clean source identity changed")
    require(report["bindings_before"] == report["bindings_after"], "source binding drift")
    require(report["bindings_before"][spec["historical_protocol_path"]]
            == spec["historical_protocol_file_sha256"], "run historical protocol binding")
    unhashed = {k: v for k, v in report.items() if k != "report_sha256"}
    require(report["report_sha256"] == digest(unhashed), "run result digest mismatch")
    checksum_cache = {}
    def reference(workload, length, seed):
        key = workload, length, seed
        if key not in checksum_cache:
            checksum_cache[key] = aot.release.checksum(*key)
        return checksum_cache[key]
    assessment = aot.assess(report["measurements"], old)
    require(wire(assessment) == wire(report["assessment"]), "runtime assessment differs on replay")
    _integer(report["whole_lifecycle_wall_ns"], "complete campaign wall", positive=True)
    for row in report["measurements"]:
        _metric_check(row, row["n"], 0)
        for key in ("cold_ns", "maxrss_kib"):
            _integer(row[key], "integer observation " + key, positive=True)
        require(type(row["first_library_call"]) is bool, "first-call marker required")
        require(sum(row["times_ns"]) == row["elapsed_ns"], "complete sample elapsed accounting")
        require(row["cold_value"] == reference(row["workload"], row["n"], row["seed"])
                and row["observed"] == row["cold_value"], "independent native checksum")
        require(row["batch_checksum"] == sum(
            reference(row["workload"], row["n"], (row["seed"] + i) & (2**32 - 1))
            for i in range(row["calls"])), "independent batch checksum")

    expected_correctness = [(w, a, n, fail) for w in old["historical_profile"]["workloads"]
                            for a in aot.ARMS for n in old["correctness_sizes"] for fail in (0, 1)]
    require(len(report["correctness"]) == len(expected_correctness), "complete correctness inventory")
    for row, (workload, arm, n, failed) in zip(report["correctness"], expected_correctness):
        require((row["workload"], row["backend"], row["n"], row["seed"], row["calls"])
                == (workload, arm, n, 2**32 - 1, 1), "correctness identity/order")
        _metric_check(row, n, failed)
        expected = 1001 if n and failed else reference(workload, n, 2**32 - 1)
        require(row["observed"] == expected, "normal/refusal correctness result")

    expected_refusals = [(w, a, n) for w in old["historical_profile"]["workloads"]
                        for a in aot.ARMS for n in old["refusal_boundary_sizes"]]
    require(len(report["refusals"]) == len(expected_refusals), "complete refusal inventory")
    for row, expected in zip(report["refusals"], expected_refusals):
        require((row["workload"], row["backend"], row["n"]) == expected, "refusal identity/order")
        _metric_check(row, row["n"], 1, boundary=True)
        require(row["observed"] == (1001 if row["n"] else 0), "refusal value")

    associated_loads = attributed_loads(report, raw_directory)
    for row in associated_loads:
        _integer(row["load_ns"], "loader wall", positive=True)
        require(row["mapping"]["mincore_failed_pages"] == 0, "incomplete loader page observations")
        for metric in spec["loader_metrics"]:
            _integer(row["mapping"][metric], "loader metric " + metric, positive=True)
    for workload in old["historical_profile"]["workloads"]:
        for arm in aot.ARMS:
            _integer(report["backend_build_wall_ns"][workload][arm], "actual build/proof wall", positive=True)
            _integer(report["artifacts"][workload][arm]["bytes"], "library file size", positive=True)
    costs = aot.cost_and_memory({**report, "assessment": assessment})
    require(wire(costs) == wire(report["cost_and_memory"]), "cost/memory ledger differs on replay")
    return assessment, costs, associated_loads


def assess(report, spec=None, *, raw_directory=None):
    spec = specification() if spec is None else spec
    runtime, costs, associated_loads = validate_complete_result(report, spec, raw_directory=raw_directory)
    candidate = spec["candidate"]
    indexed = {(_identity(r), r["backend"]): r for r in report["measurements"]}
    loads = {(_load_identity(r), r["backend"]): r for r in associated_loads}
    checks = []
    for row in report["measurements"]:
        if row["backend"] != candidate:
            continue
        key = _identity(row)
        dimension = dict(zip(("workload", "group", "n", "seed", "calls"), key))
        for baseline in spec["baselines"]:
            other = indexed[(key, baseline)]
            dims = {**dimension, "baseline": baseline}
            for metric in spec["allocator_metrics"]:
                checks.append(_check("memory." + metric, dims, row["metrics"][metric],
                                     other["metrics"][metric], spec["allocator_metric_ratio_maximum"]))
            require(row["first_library_call"] == other["first_library_call"], "paired cold marker mismatch")
            if row["first_library_call"]:
                checks.append(_check("cost.cold_first_call", dims, row["cold_ns"], other["cold_ns"],
                                     spec["cold_first_call_ratio_maximum"]))
    expected_cold = {(w, g["name"], g["sizes"][0], seed, report["protocol"]["batch_loads"][0])
                     for w in report["protocol"]["historical_profile"]["workloads"]
                     for g in report["protocol"]["groups"] for seed in g["seeds"]}
    for arm in aot.ARMS:
        actual_cold = {_identity(r) for r in report["measurements"]
                       if r["backend"] == arm and r["first_library_call"]}
        require(actual_cold == expected_cold, "complete actual first-library-call inventory")
    for row in associated_loads:
        if row["backend"] != candidate:
            continue
        key = _load_identity(row)
        dimension = dict(zip(("workload", "group", "seed"), key))
        for baseline in spec["baselines"]:
            other = loads[(key, baseline)]
            for metric in spec["loader_metrics"]:
                checks.append(_check("memory.loader_" + metric, {**dimension, "baseline": baseline},
                                     row["mapping"][metric], other["mapping"][metric],
                                     spec["loader_metric_ratio_maximum"]))
    for workload, arms in costs["arms"].items():
        for baseline in spec["baselines"]:
            dims = {"workload": workload, "baseline": baseline}
            for gate, field, limit in (
                ("memory.library_file", "library_file_bytes", "library_file_ratio_maximum"),
                ("cost.build_and_proof", "compile_and_proofs_wall_ns", "build_and_proof_ratio_maximum"),
            ):
                checks.append(_check(gate, dims, arms[candidate][field], arms[baseline][field], spec[limit]))
            checks.append(_check("cost.median_load", dims, arms[candidate]["load_ns"]["median"],
                                 arms[baseline]["load_ns"]["median"], spec["median_loader_wall_ratio_maximum"]))
    for row in costs["amortization"]:
        require(row["invocations"] in spec["cost_horizons"], "unknown amortization horizon")
        for baseline in spec["baselines"]:
            dims = {k: row[k] for k in ("workload", "group", "n", "calls", "invocations")}
            checks.append(_check("cost.estimated_automated", {**dims, "baseline": baseline},
                                 row["estimated_automated_cost_ns"][candidate],
                                 row["estimated_automated_cost_ns"][baseline],
                                 spec["estimated_automated_cost_ratio_maximum"]))
    groups = {}
    for row in checks:
        group = groups.setdefault(row["gate"], {"passed": 0, "total": 0})
        group["passed"] += int(row["passed"]); group["total"] += 1
    memory = [r for r in checks if r["gate"].startswith("memory.")]
    cost = [r for r in checks if r["gate"].startswith("cost.")]
    return {"schema": "hepta.hia.byte-sum-resource-cost.result.v1", "status": "completed",
            "assessment_valid": True, "protocol": spec, "protocol_sha256": digest(spec),
            "input_report_sha256": report["report_sha256"],
            "runtime_gates_passed": runtime["candidate_rust_comparisons_passed"],
            "runtime_gates_total": runtime["candidate_rust_comparisons_total"],
            "all_original_runtime_gates_passed": runtime["candidate_all_registered_rust_gates_passed"],
            "all_registered_memory_gates_passed": bool(memory) and all(r["passed"] for r in memory),
            "all_registered_automated_cost_gates_passed": bool(cost) and all(r["passed"] for r in cost),
            "checks": checks, "by_gate": groups, "original_cost_and_memory": costs,
            "load_receipt_associations": associated_loads,
            "actual_campaign_wall_ns": report["whole_lifecycle_wall_ns"],
            "actual_shared_host": report["host"], "whole_function_stack_bound_established": False,
            "broad_rust_parity_established": False, "full_lifecycle_net_benefit_established": False,
            "human_engineering_ns": None, "historical_acquisition_ns": None, "energy_joules": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic_ns()
    original = args.result.read_bytes()
    protocol = PROTOCOL_PATH.read_bytes()
    result = {"schema": "hepta.hia.byte-sum-resource-cost.result.v1", "status": "invalid",
              "assessment_valid": False}
    try:
        require(wire(json.loads(protocol)) == wire(specification()), "registered resource/cost bytes changed")
        result = assess(json.loads(original), raw_directory=args.result.parent)
    except Exception as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        result.update(input_path=str(args.result.resolve()), input_file_sha256=sha256(original).hexdigest(),
                      resource_protocol_file_sha256=sha256(protocol).hexdigest(),
                      analysis_wall_ns=time.monotonic_ns() - started,
                      analysis_is_a_new_measurement=False)
        require(args.result.read_bytes() == original and PROTOCOL_PATH.read_bytes() == protocol,
                "input or protocol changed during read-only assessment")
        with args.output.open("xb") as stream:
            stream.write(wire(result) + b"\n")
    print(json.dumps({k: v for k, v in result.items()
                      if k not in ("checks", "original_cost_and_memory", "load_receipt_associations", "protocol", "actual_shared_host")},
                     sort_keys=True))
    raise SystemExit(0 if result["assessment_valid"] else 1)


if __name__ == "__main__":
    main()
