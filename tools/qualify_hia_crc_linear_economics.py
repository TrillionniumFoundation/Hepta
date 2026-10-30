#!/usr/bin/env python3
"""Run the separate frozen CRC linear proposal study without changing v3 work."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_crc_kernel import POLYNOMIALS, kernel, step
from hepta.hia_crc_linear import LABELS, candidates
from hepta.hia_finite_context import build_bank
from hepta.hia_program import verify_program
from tools import qualify_hia_crc_context as historical
from tools import qualify_hia_crc_context_reuse as reuse
from tools.qualify_hia_crc_linear import (disassembly, edge_cases, require, save,
                                         source_state, tool_state, wire)
from tools.qualify_hia_ndu_loop import EpisodeBudget, measured

PROTOCOL = ROOT / "experiments/hia_crc_linear_20261030/PROTOCOL.json"
PROTOCOL_SHA256 = "19b46aafdccf573cecd19311e7f2767026274bc180b002a4cb119d0a05716038"
STATIC = {"coalesced_baseline": "baseline", "coalesced_ieee_only": "ieee_guard",
          "coalesced_castagnoli_only": "castagnoli_guard",
          "coalesced_linear_ieee_only": "linear_ieee",
          "coalesced_linear_castagnoli_only": "linear_castagnoli",
          "coalesced_linear_dual": "linear_dual"}
ARMS = ("fresh_child_baseline", *STATIC, "coalesced_poly_dispatch")
LEGACY_ARMS = tuple(STATIC)[:3]
NEW_ARMS = tuple(STATIC)[3:]


def protocol():
    raw = PROTOCOL.read_bytes()
    require(sha256(raw).hexdigest() == PROTOCOL_SHA256, "frozen protocol bytes changed")
    p = json.loads(raw)
    old = reuse.protocol(3)  # Also rechecks the retained v1 and v2 protocol bytes.
    inherited = ("data", "workloads", "trials_per_phase", "bytes_per_request", "requests_per_trace",
                 "calls_per_trace", "seed_per_request", "max_study_wall_ns", "context_limits", "reference_reuse")
    require(all(p[name] == old[name] for name in inherited), "historical data/work/lifetime/budget changed")
    require(p["schema"] == "hepta.hia.crc-linear-economics.protocol.v1"
            and p["labels"] == list(LABELS) and p["arms"] == list(ARMS) and p["static_targets"] == STATIC
            and p["expected_observations"] == 96 and p["expected_native_contexts"] == 276
            and p["expected_delivered_requests"] == 1536 and p["expected_delivered_kernel_calls"] == 393216,
            "closed arm/count contract differs")
    return p


def requests(p, payload, workload, arm):
    require(arm in ARMS and workload in p["workloads"], "unknown fixed policy/workload")
    rows = []
    for index in range(p["requests_per_trace"]):
        polynomial = POLYNOMIALS[0 if workload == "ieee" else 1 if workload == "castagnoli" else index % 2]
        label = ("baseline" if arm == "fresh_child_baseline" else STATIC[arm] if arm in STATIC else
                 "linear_ieee" if polynomial == POLYNOMIALS[0] else "linear_castagnoli")
        begin = index * p["bytes_per_request"]
        rows.append({"id": index, "candidate": label, "mode": "xor_fold", "parameter": polynomial,
            "seed": p["seed_per_request"], "values": list(payload[begin:begin + p["bytes_per_request"]])})
    return rows


def prepare_data(p, out):
    data = {phase: reuse.phase_input(p, phase) for phase in ("training", "validation")}
    diversity = reuse.input_diversity(p, data)
    identities = {}
    for phase, raw in data.items():
        path = out / (phase + ".bin")
        path.write_bytes(raw)
        identities[phase] = {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    return data, {"identities": identities, "diversity": diversity}


def deliver(bank, p, payload, key, out, sample, primed, *, deadline=None):
    phase, trial, workload, arm = key
    started = time.monotonic_ns()
    sample.update(phase=phase, trial=trial, workload=workload, arm=arm, status="started", contexts=[],
                  calls=0, completed_requests=0, kernel_ns=0, native_outer_wall_ns=0,
                  trace_preparation_wall_ns=0, loaded_candidates=[])
    try:
        plan = requests(p, payload, workload, arm)
        save(out / "PLAN.json", plan)
        groups = [[row] for row in plan] if arm == "fresh_child_baseline" else [plan]
        loaded = set()
        for index, group in enumerate(groups):
            if deadline is not None:
                deadline.remaining_ns()
            begin = time.monotonic_ns()
            trace = bank.prepare_trace(group)
            sample["trace_preparation_wall_ns"] += time.monotonic_ns() - begin
            stats = bank.oracle_reference_statistics()
            require(stats["misses"] == primed["misses"] and stats["capacity_bypasses"] == 0
                    and stats["failed_computations"] == 0, "fixed policy escaped the common primed reference set")
            save(out / f"{index:02d}.plan.json", {"requests": group, "trace_sha256": trace.sha256,
                "images": trace.images, "expected": trace.expected})
            observed = {}
            sample["contexts"].append({"plan": f"{index:02d}.plan.json", "native": f"{index:02d}.native.json"})
            try:
                if deadline is not None:
                    deadline.remaining_ns()
                bank.run(trace, report=observed)
            finally:
                save(out / f"{index:02d}.native.json", observed)
                # Failed traces retain and account their actual decoded prefix.
                # Missing measurements remain explicitly incomplete, not free.
                results = observed.get("prefix", {}).get("completed_requests", [])
                sample["completed_requests"] += len(results)
                for field, native_field in (("calls", "calls"), ("kernel_ns", "kernel_ns")):
                    values = [row.get(native_field) for row in results]
                    if all(type(value) is int and value >= 0 for value in values):
                        sample[field] += sum(values)
                    else:
                        sample.setdefault("unknown_native_measurements", []).append({"context": index, "field": field})
                if type(observed.get("outer_wall_ns")) is int:
                    sample["native_outer_wall_ns"] += observed["outer_wall_ns"]
                else:
                    sample.setdefault("unknown_native_measurements", []).append({"context": index, "field": "outer_wall_ns"})
                loaded.update(row["candidate"] for row in observed.get("loaded_inventory", []))
            require(observed["status"] == "completed" and observed["prefix"]["complete"], "native trace incomplete")
            if deadline is not None:
                deadline.remaining_ns()
        sample.update(status="completed", loaded_candidates=sorted(loaded))
    except BaseException as error:
        sample.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        sample["arm_host_wall_ns"] = time.monotonic_ns() - started
        save(out / "OBSERVATION.json", sample)
        sample["arm_host_wall_ns"] = time.monotonic_ns() - started
        # The final small rewrite remains in the containing whole-study cost.
        save(out / "OBSERVATION.json", sample)
    return sample


def analyze(samples, p, bank_report):
    """Pure finite-envelope analysis. No live timing ledger is read here."""
    expected = set(historical.schedule(p))
    require(type(samples) is list and len(samples) == p["expected_observations"], "complete sample denominator required")
    actual = {}
    for row in samples:
        key = tuple(row[name] for name in ("phase", "trial", "workload", "arm"))
        require(type(row["trial"]) is int and all(type(row[name]) is str for name in ("phase", "workload", "arm"))
                and key in expected and key not in actual and row["status"] == "completed"
                and not row.get("unknown_native_measurements"), "missing/duplicate/failed/unknown sample")
        for name in ("calls", "completed_requests", "kernel_ns", "native_outer_wall_ns", "arm_host_wall_ns"):
            require(type(row[name]) is int and row[name] > 0, "complete exact positive cost/count required")
        require(row["calls"] == p["calls_per_trace"] and row["completed_requests"] == p["requests_per_trace"]
                and row["arm_host_wall_ns"] >= row["native_outer_wall_ns"] >= row["kernel_ns"],
                "native/full-host scope or actual-work count differs")
        require(len(row["contexts"]) == (16 if key[3] == "fresh_child_baseline" else 1), "context denominator differs")
        expected_labels = ({"baseline"} if key[3] == "fresh_child_baseline" else {STATIC[key[3]]} if key[3] in STATIC
            else {"linear_ieee", "linear_castagnoli"} if key[2] == "mixed_alternating"
            else {"linear_ieee"} if key[2] == "ieee" else {"linear_castagnoli"})
        require(type(row["loaded_candidates"]) is list and len(row["loaded_candidates"]) == len(expected_labels)
                and set(row["loaded_candidates"]) == expected_labels, "fixed loaded-image control differs")
        actual[key] = row
    require(set(actual) == expected and sum(len(r["contexts"]) for r in samples) == p["expected_native_contexts"]
            and sum(r["calls"] for r in samples) == p["expected_delivered_kernel_calls"], "whole-study count differs")
    require(set(bank_report["candidates"]) == set(LABELS), "complete candidate pool required")
    prep = {name: row["preparation_wall_ns"] for name, row in bank_report["candidates"].items()}
    require(all(type(value) is int and value > 0 for value in prep.values()), "actual per-image preparation required")
    codes = {name: row["code"]["sha256"] for name, row in bank_report["candidates"].items()}
    require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in codes.values()), "exact export identities required")
    groups = []
    for phase in ("training", "validation"):
        for workload in p["workloads"]:
            subset = [row for key, row in actual.items() if (key[0], key[2]) == (phase, workload)]
            envelopes = {arm: {metric: {"min": min(r[metric] for r in subset if r["arm"] == arm),
                "max": max(r[metric] for r in subset if r["arm"] == arm)}
                for metric in ("kernel_ns", "native_outer_wall_ns", "arm_host_wall_ns")} for arm in ARMS}
            legacy_kernel = min(envelopes[a]["kernel_ns"]["min"] for a in LEGACY_ARMS)
            legacy_host = min(envelopes[a]["arm_host_wall_ns"]["min"] for a in LEGACY_ARMS)
            strong_host = min(envelopes[a]["arm_host_wall_ns"]["min"] for a in STATIC)
            contrasts = {}
            for arm in NEW_ARMS:
                saving = legacy_kernel - envelopes[arm]["kernel_ns"]["max"]
                contrasts[STATIC[arm]] = {"kernel_saving_vs_fastest_legacy_ns": saving,
                    "kernel_saving_ns_per_call": saving / p["calls_per_trace"],
                    "full_host_saving_vs_fastest_legacy_ns": legacy_host - envelopes[arm]["arm_host_wall_ns"]["max"],
                    "image_preparation_delta_over_each_legacy_ns": {
                        old: prep[STATIC[arm]] - prep[old] for old in LABELS[:3]}}
            groups.append({"phase": phase, "workload": workload, "envelopes": envelopes,
                "new_candidate_contrasts": contrasts,
                "dispatch_host_increment_over_all_six_fixed_ns": strong_host - envelopes["coalesced_poly_dispatch"]["arm_host_wall_ns"]["max"],
                "batching_host_increment_ns": envelopes["fresh_child_baseline"]["arm_host_wall_ns"]["min"]
                    - envelopes["coalesced_baseline"]["arm_host_wall_ns"]["max"]})
    return {"groups": groups, "image_preparation_ns": prep,
        "additional_three_image_preparation_component_ns": sum(prep[name] for name in LABELS[3:]),
        "new_exports_differ_from_every_legacy": all(codes[name] not in {codes[old] for old in LABELS[:3]} for name in LABELS[3:]),
        "delivered_host_sum_ns": sum(row["arm_host_wall_ns"] for row in samples),
        "actual_delivered_kernel_calls": sum(row["calls"] for row in samples),
        "preparation_is_counterfactual_deployment_estimate": False,
        "envelopes_are_statistical_confidence_intervals": False, "NDU_incremental_value_established": False,
        "break_even_is_observed_profit": False, "production_demand_established": False}


def charge(analysis, p, whole_wall_ns, *, outer_verified=False):
    """Recompute a conservative cold charge from a complete observed interval.

    Only the sum of actual full arm intervals is removed. Every other observed
    cost remains charged, including analysis/identity/cleanup and evidence work.
    External reviewers can pass the retained actual outer process duration.
    """
    require(type(outer_verified) is bool and type(whole_wall_ns) is int
            and whole_wall_ns >= analysis["delivered_host_sum_ns"], "whole interval is incomplete")
    result = copy.deepcopy(analysis)
    cost = whole_wall_ns - result["delivered_host_sum_ns"]
    result.update(charged_whole_wall_ns=whole_wall_ns, shared_non_delivery_charge_ns=cost,
                  actual_outer_execution_cost_verified=outer_verified)
    for row in result["groups"]:
        row["cold_dispatch_net_over_all_six_fixed_ns"] = row["dispatch_host_increment_over_all_six_fixed_ns"] - cost
        for contrast in row["new_candidate_contrasts"].values():
            saving = contrast["kernel_saving_vs_fastest_legacy_ns"]
            contrast["cold_candidate_net_vs_fastest_legacy_ns"] = contrast["full_host_saving_vs_fastest_legacy_ns"] - cost
            contrast["conditional_break_even_calls_full_charge"] = (
                (cost * p["calls_per_trace"] + saving - 1) // saving if saving > 0 else None)
            extra = result["additional_three_image_preparation_component_ns"]
            contrast["conditional_break_even_calls_additional_three_image_component"] = (
                (extra * p["calls_per_trace"] + saving - 1) // saving if saving > 0 else None)
    passed = result["new_exports_differ_from_every_legacy"] and all(
        row["cold_dispatch_net_over_all_six_fixed_ns"] > 0 for row in result["groups"])
    result["inner_cold_gate_passed"] = passed
    result["complete_cost_cold_gate_passed"] = passed and outer_verified
    return result


def study(*, output, expected_head, clang, cc, objdump):
    started = time.monotonic_ns()
    p = protocol()
    out = Path(output).resolve()
    require(out != ROOT and ROOT not in out.parents, "external new output required")
    out.mkdir(parents=True, exist_ok=False)
    (out / "FROZEN_PROTOCOL.json").write_bytes(PROTOCOL.read_bytes())
    ledger, bank = [], None
    report = {"schema": "hepta.hia.crc-linear-economics.v1", "qualified": False, "status": "failed",
        "started_utc": datetime.now(timezone.utc).isoformat(), "expected_head": expected_head,
        "protocol_sha256": PROTOCOL_SHA256, "protocol": p, "claims": dict(p["claims"]),
        "ledger": ledger, "samples": [], "errors": [], "prior_failures_replaced": False}
    budget = EpisodeBudget(started, p["max_study_wall_ns"])
    run = lambda label, action: budget.stage(label, ledger, action)

    def fail(label, error):
        report["qualified"] = False
        report["errors"].append({"stage": label, "type": type(error).__name__, "message": str(error)})

    try:
        report["source_before"] = run("source.before", lambda: source_state(expected_head))
        report["tools_before"] = run("tools.before", lambda: tool_state(clang, cc, objdump))
        run("source.capture-and-bridge", lambda: historical._capture_and_compare(out, clang, cc, report))
        pool = run("proposal.generate", candidates)
        require({k: verify_program(v).sha256 for k, v in pool.items()} == p["candidate_core_sha256"], "registered candidate bytes differ")
        for label, document in pool.items():
            save(out / (label + ".hia.json"), document)
        require(report["source_bridge"]["kernel_sha256"] == p["candidate_core_sha256"]["baseline"], "fresh source bridge root differs")
        images = out / "bank"
        images.mkdir()
        report["bank"] = {}
        bank = run("bank.prepare", lambda: build_bank(kernel(), pool, images, clang=clang,
            cases=edge_cases(), oracle=step, report=report["bank"], reuse_oracle=True))
        report["code_inspection"] = run("code.inspect", lambda: disassembly(report["bank"], images, objdump))
        data, report["inputs"] = run("data.prepare", lambda: prepare_data(p, out))
        report["reference_priming"] = run("reference.prime", lambda: reuse.prime_references(bank, p, data))
        primed = report["reference_state_after_priming"] = bank.oracle_reference_statistics()
        require(primed["entries"] == 64 and primed["misses"] == 64 and primed["capacity_bypasses"] == 0
                and primed["failed_computations"] == 0, "complete common reference set not primed")
        observations = out / "samples"
        observations.mkdir()
        for index, key in enumerate(historical.schedule(p)):
            directory = observations / f"{index:03d}"
            directory.mkdir()
            sample = {"directory": str(directory)}
            report["samples"].append(sample)
            run(f"sample.{index:03d}", lambda: deliver(bank, p, data[key[0]], key, directory, sample, primed, deadline=budget))
            if (index + 1) % len(ARMS) == 0:
                print(json.dumps({"completed_observations": index + 1, "phase": key[0], "trial": key[1], "workload": key[2]}), flush=True)
        report["actual_counts"] = {
            "original_C_reference_cases": report["original_c_differential"]["cases_executed"],
            "native_preparation_differential_cases": sum(row["native_differential"]["cases_executed"]
                for row in report["bank"]["candidates"].values()),
            "delivered_requests": sum(row["completed_requests"] for row in report["samples"]),
            "delivered_kernel_calls": sum(row["calls"] for row in report["samples"]),
            "native_contexts": sum(len(row["contexts"]) for row in report["samples"]), "ndu_decisions": 0}
        report["qualified"] = True
    except BaseException as error:
        fail("study", error)
    finally:
        if bank is not None:
            try:
                report["reference_state_before_close"] = bank.oracle_reference_statistics()
            except BaseException as error:
                fail("reference.final", error)
            try:
                report["release"] = measured("bank.close", ledger, bank.close)
                require(report["release"]["complete"] is True, "bank release uncertain; no retry")
            except BaseException as error:
                fail("bank.close", error)
        for name, action in (("source", lambda: source_state(expected_head)),
                             ("tools", lambda: tool_state(clang, cc, objdump)), ("protocol", protocol)):
            try:
                report[name + "_after"] = measured(name + ".after", ledger, action)
                expected = p if name == "protocol" else report.get(name + "_before")
                require(report[name + "_after"] == expected, name + " changed")
            except BaseException as error:
                fail(name + ".after", error)
        if len(report["samples"]) == p["expected_observations"]:
            try:
                snapshot = copy.deepcopy(ledger)
                require(all(type(row.get("wall_ns")) is int and row["wall_ns"] >= 0
                            and row["status"] in {"completed", "failed"} for row in snapshot), "unfinished cost ledger")
                report["closed_pre_analysis_ledger_sha256"] = sha256(wire(snapshot)).hexdigest()
                base = measured("analysis", ledger, lambda: analyze(report["samples"], p, report["bank"]))
                report["economics"] = charge(base, p, time.monotonic_ns() - started)
            except BaseException as error:
                fail("analysis", error)
        report["wall_ns"] = time.monotonic_ns() - started
        if report["wall_ns"] > p["max_study_wall_ns"]:
            fail("deadline", RuntimeError("complete study including cleanup/identity/analysis exceeded budget"))
        report["status"] = "completed" if report["qualified"] else "failed"
        save(out / "RESULT.json", report)
        report["wall_through_first_result_write_ns"] = time.monotonic_ns() - started
        if "economics" in report:
            report["economics"] = charge(report["economics"], p, report["wall_through_first_result_write_ns"])
        if report["wall_through_first_result_write_ns"] > p["max_study_wall_ns"]:
            fail("result.deadline", RuntimeError("first result write exceeded budget"))
            report["status"] = "failed"
        save(out / "RESULT.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--objdump", default="objdump")
    options = parser.parse_args()
    report = study(output=options.output_directory, expected_head=options.expected_head,
                   clang=options.clang, cc=options.cc, objdump=options.objdump)
    print(json.dumps({"qualified": report["qualified"], "status": report["status"],
        "observations": len(report["samples"]), "inner_cold_gate_passed": report.get("economics", {}).get("inner_cold_gate_passed"),
        "actual_outer_cost_still_required": True}, sort_keys=True))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
