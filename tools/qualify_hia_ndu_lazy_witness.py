#!/usr/bin/env python3
"""Qualify lazy witnesses without replacing the original Rust NDU evaluator.

All complete model outputs must match the pinned baseline and an independent
schedule enumerator. The native phase executes the corrected 8e52 stream for
both frontends. This is preparation/transport evidence, not application or
full-lifecycle NDU benefit. The existing four-arm full-cost study is separate.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta import hia_ndu_cost as current
from hepta.hia_ndu_session import NduSession
from tests.test_hia_ndu_cost import independent_frontier
from tools.qualify_hia_ndu_budget_erasure import corpus, encoded, first_costs, require, save

PROTOCOL = ROOT / "benchmarks/hia_ndu_cost/LAZY_WITNESS_PROTOCOL.json"
BASELINE = ROOT / "benchmarks/hia_ndu_cost/historical_hia_ndu_cost_f2b76f5741c83822be2e12cf5a50b50a8d27b96a.py"
BASELINE_SHA256 = "e5ba69bcb9ac9fa78c6cd216e76e9abaa3bd850df1a8c8add7ce160bdfae0142"
PROTOCOL_SHA256 = "ac437291394cf7b33d2706919df9f06b7e54bf1c3c1d24f973df05a69e93a166"


def load_protocol():
    raw = PROTOCOL.read_bytes()
    require(sha256(raw).hexdigest() == PROTOCOL_SHA256, "changed lazy-witness registration")
    return json.loads(raw)


def load_baseline():
    raw = BASELINE.read_bytes()
    require(sha256(raw).hexdigest() == BASELINE_SHA256, "changed frozen lazy-witness baseline")
    module = types.ModuleType("hepta._lazy_witness_historical")
    module.__package__ = "hepta"
    exec(compile(raw, str(BASELINE), "exec"), module.__dict__)
    return module


def inventory():
    paths = list((ROOT / "hepta").glob("*.py"))
    paths += [Path(__file__), PROTOCOL, BASELINE,
              ROOT / "tests/test_hia_ndu_cost.py",
              ROOT / "tests/test_hia_ndu_lazy_witness.py",
              ROOT / "tools/qualify_hia_ndu_budget_erasure.py"]
    return {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest()
            for p in sorted(set(paths))}


def git_identity(expected_source, source):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(ROOT), *args])
    head = git("rev-parse", "HEAD").decode().strip()
    require(head == expected_source, "unexpected HIA source commit")
    require(not git("status", "--porcelain", "--untracked-files=normal"),
            "qualification requires a clean source worktree")
    # Read actual selected source bytes, independently of index hiding flags.
    for path, digest in source.items():
        require(sha256(git("show", head + ":" + path)).hexdigest() == digest,
                "materialized source differs from commit: " + path)
    return {"commit": head, "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "materialized_source_matches_git": True}


def compare_model(old, model):
    before = deepcopy(model)
    original, replacement = old.exact_control(model), current.exact_control(model)
    require(encoded(original) == encoded(replacement), "complete witness/search mismatch")
    require(first_costs(replacement["witnesses"]) == independent_frontier(model),
            "independent first-action minimum mismatch")
    native_old, native_new = old.build_request(model), current.build_request(model)
    require(encoded(native_old) == encoded(native_new), "native request/plan bytes mismatch")
    require(first_costs(native_new["plans"].values()) ==
            independent_frontier(model, committed_call=True),
            "independent committed minimum mismatch")
    require(model == before, "caller input changed")
    return {"horizon": len(model["baseline"]["latency_ns"]),
            "first_actions": len(replacement["witnesses"]),
            "native_first_actions": len(native_new["plans"]),
            "search": replacement["search"],
            "request_sha256": sha256(encoded(native_new["request"])).hexdigest()}


def summarize(samples, key, arms):
    result = {}
    for name in sorted({row[key] for row in samples}):
        arm_rows = {}
        for arm in arms:
            values = [r["wall_ns"] for r in samples if r[key] == name and r["arm"] == arm]
            require(bool(values), "missing timing arm")
            arm_rows[arm] = {"median_ns": statistics.median(values),
                            "p95_ns": sorted(values)[math.ceil(.95 * len(values)) - 1],
                            "samples": len(values), "total_ns": sum(values)}
        result[name] = {"arms": arm_rows,
                       "new_over_old_median": arm_rows["lazy"]["median_ns"] / arm_rows["baseline"]["median_ns"],
                       "new_over_old_total": arm_rows["lazy"]["total_ns"] / arm_rows["baseline"]["total_ns"]}
    return result


def native_compare(output, models, old, args, protocol):
    phase_started = time.monotonic_ns()
    rows = []
    modules = {"baseline": old, "lazy": current}
    session = None
    result = {"attempted_invocations": 0, "completed_invocations": 0,
              "startup_ns": None, "close_ns": None, "all_responses_equal": False,
              "source_pin": protocol["native_source"], "profile": protocol["native_profile"]}
    try:
        start = time.monotonic_ns()
        try:
            session = NduSession.for_stream_profile(
                args.bridge, args.identity, profile=protocol["native_profile"])
        finally:
            result["startup_ns"] = time.monotonic_ns() - start
        result["build_manifest_sha256"] = sha256(Path(args.identity).read_bytes()).hexdigest()
        result["binary_sha256"] = sha256(Path(args.bridge).read_bytes()).hexdigest()
        manifest = json.loads(Path(args.identity).read_bytes())
        result["historical_build_cost"] = manifest.get("build_cost")
        result["fresh_build_observed_here"] = False
        for number, model in enumerate(models[:protocol["native_model_count"]]):
            order = ("baseline", "lazy") if number % 2 == 0 else ("lazy", "baseline")
            pair = {}
            for arm in order:
                row = {"case": number, "arm": arm, "status": "failed"}
                began = time.monotonic_ns()
                try:
                    bundle = modules[arm].build_request(model)
                    built = time.monotonic_ns()
                    result["attempted_invocations"] += 1
                    response = session.evaluate(bundle["request"])
                    evaluated = time.monotonic_ns()
                    action = modules[arm].project_advice(bundle, response)
                    finished = time.monotonic_ns()
                    result["completed_invocations"] += 1
                    row.update(status="passed", preparation_ns=built-began,
                               roundtrip_ns=evaluated-built, projection_ns=finished-evaluated,
                               wall_ns=finished-began, request=bundle["request"],
                               response=response, action=action,
                               raw_envelope_hex=session._last_received_frame.hex())
                    pair[arm] = response, action
                except Exception as error:
                    row.update(wall_ns=time.monotonic_ns()-began,
                               error={"type": type(error).__name__, "message": str(error)})
                    raise
                finally:
                    rows.append(row)
                    with (output / "NATIVE_CALLS.jsonl").open("a") as stream:
                        stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
            require(encoded(pair["baseline"]) == encoded(pair["lazy"]),
                    "original native response/advice mismatch")
        result["all_responses_equal"] = True
    finally:
        if session is not None:
            began = time.monotonic_ns()
            try:
                session.close()
            except Exception as error:
                result["cleanup_error"] = {"type": type(error).__name__, "message": str(error)}
            finally:
                result["close_ns"] = time.monotonic_ns()-began
                result["session"] = session.snapshot()
        result["rows_count"] = len(rows)
        result["known_session_total_ns"] = (
            sum(r["wall_ns"] for r in rows) + (result["startup_ns"] or 0) +
            (result["close_ns"] or 0))
        result["phase_wall_ns_excluding_summary_write"] = time.monotonic_ns()-phase_started
        result["other_phase_ns"] = result["phase_wall_ns_excluding_summary_write"] - result["known_session_total_ns"]
        result["cost_scope"] = "actual frontend, original native transport/evaluation/projection, startup, cleanup, pair checks and raw logs; final summary write remains in the caller envelope; no application execution"
        save(output / "NATIVE_SUMMARY.json", result)
    require("cleanup_error" not in result, "native cleanup failed")
    require(result["completed_invocations"] == protocol["native_model_count"] * 2,
            "incomplete native comparisons")
    return result


def qualify(args):
    started = time.monotonic_ns()
    output = Path(args.output).resolve()
    require(not output.is_relative_to(ROOT), "evidence output must be outside the source worktree")
    output.mkdir(parents=True, exist_ok=False)
    protocol = load_protocol()
    source = inventory()
    old = load_baseline()
    models = corpus(protocol)
    require(len(models) == protocol["cases"] > 0, "complete registered corpus required")
    report = {"schema": "hepta.hia.ndu.lazy-witness.result.v1", "status": "failed",
              "protocol": protocol, "source_before": source, "model_count": len(models),
              "corpus_sha256": sha256(encoded(models)).hexdigest(),
              "host": {"platform": platform.platform(), "python": sys.version},
              "checks": [], "samples": [], "native_invocations": 0,
              "native_ndu_advantage_established": False, "full_lifecycle_net_benefit_established": False,
              "application_execution_measured": False, "authority": "DENY_ALL",
              "safety_certificate": False}
    save(output / "PROTOCOL.json", protocol)
    save(output / "CORPUS.json", models)
    save(output / "REGISTRATION.json", {"source": source,
         "corpus_sha256": report["corpus_sha256"], "before_first_comparison_or_timing": True})
    try:
        report["git"] = git_identity(args.expected_source, source)
        for number, model in enumerate(models):
            report["checks"].append({"case": number, **compare_model(old, model)})
        modules = {"baseline": old, "lazy": current}
        for _ in range(protocol["warmup_sweeps"]):
            for module in modules.values():
                for operation in protocol["operations"]:
                    for model in models:
                        getattr(module, operation)(model)
        report["warmup_sweeps_completed"] = protocol["warmup_sweeps"]
        for round_number in range(protocol["rounds"]):
            order = ("baseline", "lazy") if round_number % 2 == 0 else ("lazy", "baseline")
            for operation in protocol["operations"]:
                for arm in order:
                    call = getattr(modules[arm], operation)
                    began = time.monotonic_ns()
                    for model in models:
                        call(model)
                    sample = {"round": round_number, "operation": operation, "arm": arm,
                              "calls": len(models), "wall_ns": time.monotonic_ns()-began}
                    report["samples"].append(sample)
                    with (output / "SAMPLES.jsonl").open("a") as stream:
                        stream.write(json.dumps(sample, sort_keys=True) + "\n")
        report["summary"] = summarize(report["samples"], "operation", tuple(modules))
        report["native"] = native_compare(output, models, old, args, protocol)
        report["native_invocations"] = report["native"]["completed_invocations"]
        report["source_after"] = inventory()
        require(report["source_after"] == source, "source changed during qualification")
        require(git_identity(args.expected_source, report["source_after"]) == report["git"],
                "source identity changed")
        report.update(status="passed", all_complete_witnesses_equal=True,
                      all_native_request_bytes_equal=True, all_independent_frontiers_equal=True)
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        # A later refusal must not relabel an observed native prefix as zero.
        native_summary = output / "NATIVE_SUMMARY.json"
        if native_summary.exists():
            report["native"] = json.loads(native_summary.read_bytes())
            report["native_invocations"] = report["native"]["completed_invocations"]
    report["outer_wall_ns_excluding_final_result_write"] = time.monotonic_ns()-started
    save(output / "RESULT.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("output", "expected-source", "bridge", "identity"):
        parser.add_argument("--" + argument, required=True)
    report = qualify(parser.parse_args())
    print(json.dumps({k: report.get(k) for k in
          ("status", "model_count", "summary", "native_invocations", "error")}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
