#!/usr/bin/env python3
"""Replay beam for every recorded actual NDU model; preserve the original pilot.

This adds a separately charged post-pilot audit. It never executes the HIA
workload, changes the original source/result, recalibrates costs, or substitutes
new timings for the original service measurements.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_ndu_dynamic import JsonProcess, REQUEST_SCHEMA, read_json, require, wire
from hepta.hia_result_cache_audit import matched_model_audit
from tools.qualify_hia_result_cache import (bound_inputs, identity, require_clean_source,
    require_same_bindings, save)

MAX_RESULT_BYTES = 32 * 1024 * 1024


def read_bound_json(path, expected):
    require(0 < expected["bytes"] <= MAX_RESULT_BYTES, "bounded pilot input")
    raw = Path(path).read_bytes()
    require(len(raw) == expected["bytes"] and sha256(raw).hexdigest() == expected["sha256"],
            "pilot input changed while loading")
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate pilot JSON key")
            value[key] = item
        return value
    def constant(_):
        raise ValueError("nonfinite pilot JSON value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def actual_ndu_models(original):
    rows = []
    keys = set()
    declared = 0
    for episode in original["episodes"]:
        if episode["policy"] != "beam_ndu":
            continue
        declared += episode["ndu_requests"]
        for step in episode["steps"]:
            decision = step["decision"]
            if "response" not in decision:
                continue
            response, receipt = decision["response"], decision["receipt"]
            require(response["mode"] == "beam_ndu", "recorded mode differs from actual NDU arm")
            request = wire({"schema": REQUEST_SCHEMA, "mode": "beam_ndu", "model": step["model"]})
            require(receipt["request"].encode() == request
                and sha256(request).hexdigest() == receipt["request_sha256"], "original request frame binding")
            response_bytes = receipt["response"].encode()
            require(sha256(response_bytes).hexdigest() == receipt["response_sha256"]
                and wire(read_json(response_bytes)) == wire(response), "original response frame binding")
            key = (episode["name"], step["index"])
            require(key not in keys, "duplicate actual-model identity")
            keys.add(key)
            rows.append({"episode": key[0], "step": key[1], "policy": "beam_ndu",
                "model": step["model"], "response": response,
                "recorded_executor_selection_matches_native": wire(step["selected"]) == wire(response["selected_first_action"])})
    require(len(rows) == declared, "recorded actual NDU count does not match frames")
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--planner", required=True)
    parser.add_argument("--planner-manifest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.resolve().is_relative_to(ROOT), "audit output must be outside source checkout")
    args.output.mkdir(parents=True, exist_ok=False)
    begin = time.monotonic_ns()
    session = None
    inputs = None
    source = None
    report = {"schema": "hepta.hia.result-cache.post-pilot-audit.v1", "completed": False,
        "authority": "DENY_ALL", "p1_closed": False, "service_timings_modified": False,
        "workload_reexecuted": False,
        "binding_scope": "trusted-host before/after observations; original pilot lacks a retrospective full checkout/tool-custody proof"}
    try:
        input_paths = {"result": args.result, "registration": args.registration,
            "planner": args.planner, "planner_manifest": args.planner_manifest,
            "audit_driver": Path(__file__)}
        inputs = {name:identity(path) for name,path in input_paths.items()}
        original = read_bound_json(args.result, inputs["result"])
        registered = read_bound_json(args.registration, inputs["registration"])
        require(original["completed"] is True, "audit requires a completed retained pilot")
        require(inputs["registration"]["sha256"] == original["registration_sha256"], "original registration binding")
        require(inputs["planner"]["sha256"] == registered["planner"]["sha256"], "counterfactual planner differs from original registration")
        require(inputs["planner_manifest"]["sha256"] == registered["planner_manifest"]["sha256"], "counterfactual build manifest differs from original")
        # Clang is observed as a tool identity only; this audit performs no build.
        args.clang = original["hia_build"]["toolchain"]["path"]
        source = bound_inputs(args)
        require_clean_source(source["source"])
        report.update(inputs_before=inputs, audit_source_before=source,
            original_source=registered["source"], original_protocol=registered["protocol"],
            original_campaign_wall_ns=original["observed_campaign_wall_ns"],
            original_historical_bridge_build_ns=registered["existing_planner_build"]["wall_ns"],
            original_service_totals_ns={k:v["service_ns"] for k,v in original["totals"].items()})
        rows = actual_ndu_models(original)
        report["actual_ndu_models"] = len(rows)
        report["all_recorded_executor_selections_match_native"] = all(r["recorded_executor_selection_matches_native"] for r in rows)
        session = JsonProcess(args.planner, args.planner_manifest, role="--planner-stream",
            log=args.output / "matched-beam.jsonl")
        require(session.binary_sha256 == inputs["planner"]["sha256"], "executed counterfactual image differs from registration")
        report["audit"] = matched_model_audit(rows, session)
        require(report["audit"]["all_match"], "actual-model counterfactual mismatch")
        report["completed"] = True
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if session is not None:
            session.close()
            report["planner_lifecycle"] = {"startup_ns": session.startup_ns, "close_ns": session.close_ns,
                "calls": session.calls, "returncode": session.returncode}
            if session.returncode != 0:
                report["completed"] = False
        if inputs is not None:
            try:
                report["inputs_after"] = {name: identity(path) for name,path in input_paths.items()}
                require_same_bindings(inputs, report["inputs_after"])
                if source is not None:
                    report["audit_source_after"] = bound_inputs(args)
                    require_same_bindings(source, report["audit_source_after"])
                report["inputs_unchanged"] = True
            except Exception as exc:
                report["completed"] = False
                report["inputs_unchanged"] = False
                report["binding_error"] = {"type": type(exc).__name__, "message": str(exc)}
        report["audit_observed_wall_ns"] = time.monotonic_ns() - begin
        if "original_campaign_wall_ns" in report:
            report["original_plus_postaudit_measured_work_ns"] = report["original_campaign_wall_ns"] + report["audit_observed_wall_ns"]
            report["known_work_with_one_full_prior_bridge_build_ns"] = report["original_plus_postaudit_measured_work_ns"] + report["original_historical_bridge_build_ns"]
        report["cost_scope"] = {
            "audit_wall": "includes original input read/validation, all matched-model replay, logging, startup/close, final source/tool/input checks; excludes interpreter/import startup and final report serialization",
            "combined_measured_work": "sum of original measured campaign interval and new audit interval, not elapsed time between runs; original service costs are unchanged",
            "historical_build": "one full pinned bridge build is separately added as known cost; original standalone per-policy allocations must not be summed",
            "not_known": ["human effort", "energy", "toolchain provisioning", "transitive Python/libc dependency identities"]}
        save(args.output / "audit.json", report)
        summary = {key: report[key] for key in ["completed","actual_ndu_models","all_recorded_executor_selections_match_native",
            "audit_observed_wall_ns","original_plus_postaudit_measured_work_ns","known_work_with_one_full_prior_bridge_build_ns","inputs_unchanged","error"] if key in report}
        if "audit" in report:
            summary["all_models_match"] = report["audit"]["all_match"]
            summary["matched_model_replay_wall_ns"] = report["audit"]["wall_ns"]
        save(args.output / "summary.json", summary)
        print(json.dumps(summary, sort_keys=True))
    return 0 if report["completed"] else 1

if __name__ == "__main__": raise SystemExit(main())
