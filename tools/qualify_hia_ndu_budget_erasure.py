#!/usr/bin/env python3
"""Check all first actions and compare exact historical/current planning work.

The registered models are declared inputs, not real workload observations.
This experiment can establish a model-planner cost reduction, never native NDU
or application-wide net benefit. No native evaluator is imitated or invoked.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path
import platform
import random
import statistics
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta import hia_ndu_cost as current
from tests.test_hia_ndu_cost import fixture, independent_frontier

PROTOCOL = ROOT / "benchmarks/hia_ndu_cost/BUDGET_ERASURE_PROTOCOL.json"
BASELINE = ROOT / "benchmarks/hia_ndu_cost/historical_hia_ndu_cost_931c96fcc7fb698226b809862c233a345dcca4ec.py"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def save(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def corpus(protocol):
    rng = random.Random(protocol["seed"])
    rows = []
    for number in range(protocol["cases"]):
        horizon = 1 + number % 4
        model = fixture(horizon)
        model["variants"] = model["variants"][:1 + (number // 4) % 2]
        count = len(model["variants"])
        model["memory_budget_bytes"] = number % (count + 1)
        model["ready"] = [v["id"] for v in model["variants"]][:model["memory_budget_bytes"]] if number % 3 else []
        model["session_ready"] = bool((number // 8) % 2)
        model["budget_ns"] = rng.randrange(100, 30000)
        model["baseline"]["latency_ns"] = [rng.randrange(0, 3000) for _ in range(horizon)]
        for variant in model["variants"]:
            variant["status"] = "rejected" if rng.randrange(11) == 0 else "verified"
            variant["valid"] = [rng.randrange(5) != 0 for _ in range(horizon)]
            variant["latency_ns"] = [rng.randrange(0, 3000) for _ in range(horizon)]
            for key in ("prepare_ns", "proof_ns", "retire_ns", "holding_ns"):
                variant[key] = rng.randrange(0, 1200)
        for key in model["decision"]:
            model["decision"][key] = rng.randrange(0, 400)
        rows.append(model)
    return rows


def inventory():
    paths = [ROOT / "hepta/hia_ndu_cost.py", ROOT / "hepta/hia_ndu.py",
             ROOT / "hepta/hia_program_tools.py", ROOT / "hepta/hia_json_preflight.py",
             ROOT / "tests/test_hia_ndu_cost.py", ROOT / "formal/HiaNduBudgetErasure.lean",
             PROTOCOL, BASELINE, Path(__file__)]
    return {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in paths}


def first_costs(plans):
    values = {}
    for plan in plans:
        first = plan["actions"][0]
        key = (first["mode"], tuple(first["ready_after"]) if first["mode"] == "invoke" else ())
        values[key] = plan["total_ns"]
    return values


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def historical_model(protocol):
    """Load the exact protocol-bound source bytes without requiring Git history."""
    old_bytes = BASELINE.read_bytes()
    require(sha256(old_bytes).hexdigest() == protocol["baseline_sha256"], "frozen baseline source mismatch")
    old = types.ModuleType("hepta._budget_erasure_historical")
    old.__package__ = "hepta"
    exec(compile(old_bytes, protocol["baseline_file"] + "@" + protocol["baseline_commit"], "exec"), old.__dict__)
    return old, old_bytes


def qualify(output):
    started = time.monotonic_ns()
    destination = Path(output).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    protocol = json.loads(PROTOCOL.read_bytes())
    source = inventory()
    old, old_bytes = historical_model(protocol)
    models = corpus(protocol)
    report = {"schema": "hepta.hia.ndu.budget-erasure.result.v1", "status": "failed",
              "protocol": protocol, "source_before": source, "model_count": len(models),
              "corpus_sha256": sha256(encoded(models)).hexdigest(),
              "host": {"platform": platform.platform(), "python": sys.version},
              "checks": [], "samples": [], "native_invocations": 0,
              "native_ndu_advantage_established": False, "full_lifecycle_net_benefit_established": False,
              "authority": "DENY_ALL", "safety_certificate": False}
    save(destination / "PROTOCOL.json", protocol)
    save(destination / "CORPUS.json", models)
    save(destination / "REGISTRATION.json", {"source": source, "corpus_sha256": report["corpus_sha256"],
        "baseline_sha256": protocol["baseline_sha256"], "before_first_comparison_or_timing": True})
    (destination / "historical_hia_ndu_cost.py").write_bytes(old_bytes)
    try:
        for number, model in enumerate(models):
            before = deepcopy(model)
            original, replacement = old.exact_control(model), current.exact_control(model)
            require({k:v for k,v in original.items() if k != "search"} ==
                    {k:v for k,v in replacement.items() if k != "search"}, "witness mismatch: " + str(number))
            require(first_costs(replacement["witnesses"]) == independent_frontier(model),
                    "independent first-action mismatch: " + str(number))
            native_old, native_new = old.build_request(model), current.build_request(model)
            require(encoded(native_old) == encoded(native_new), "native request byte mismatch: " + str(number))
            require(first_costs(native_new["plans"].values()) == independent_frontier(model, committed_call=True),
                    "independent committed first-action mismatch: " + str(number))
            require(model == before, "caller input changed")
            report["checks"].append({"case": number, "horizon": len(model["baseline"]["latency_ns"]),
                "first_actions": len(replacement["witnesses"]), "native_first_actions": len(native_new["plans"]),
                "old_search": original["search"], "new_search": replacement["search"],
                "native_request_sha256": sha256(encoded(native_new["request"])).hexdigest()})
        modules = {"historical": old, "budget_erased": current}
        for _ in range(protocol["warmup_sweeps"]):
            for module in modules.values():
                for operation in protocol["operations"]:
                    for model in models:
                        getattr(module, operation)(model)
        report["warmup_sweeps_completed"] = protocol["warmup_sweeps"]
        for round_number in range(protocol["rounds"]):
            order = ("historical", "budget_erased") if round_number % 2 == 0 else ("budget_erased", "historical")
            for operation in protocol["operations"]:
                for arm in order:
                    call = getattr(modules[arm], operation)
                    start = time.monotonic_ns()
                    for model in models:
                        call(model)
                    elapsed = time.monotonic_ns() - start
                    sample = {"round": round_number, "operation": operation, "arm": arm,
                              "calls": len(models), "wall_ns": elapsed}
                    report["samples"].append(sample)
                    with (destination / "SAMPLES.jsonl").open("a") as stream:
                        stream.write(json.dumps(sample, sort_keys=True) + "\n")
        report["summary"] = {}
        for operation in protocol["operations"]:
            arms = {}
            for arm in modules:
                values = [row["wall_ns"] for row in report["samples"] if row["operation"] == operation and row["arm"] == arm]
                arms[arm] = {"median_ns": statistics.median(values), "p95_ns": sorted(values)[math.ceil(.95 * len(values))-1],
                             "total_ns": sum(values), "samples": len(values)}
            report["summary"][operation] = {"arms": arms,
                "new_over_old_median": arms["budget_erased"]["median_ns"] / arms["historical"]["median_ns"],
                "new_over_old_total": arms["budget_erased"]["total_ns"] / arms["historical"]["total_ns"]}
        report["source_after"] = inventory()
        require(report["source_after"] == source, "registered source changed during qualification")
        report["status"] = "passed"
        report["all_complete_witnesses_equal"] = True
        report["all_native_request_bytes_equal"] = True
        report["all_independent_frontiers_equal"] = True
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    report["outer_wall_ns_excluding_final_result_write"] = time.monotonic_ns() - started
    save(destination / "RESULT.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    report = qualify(parser.parse_args().output)
    print(json.dumps({key: report.get(key) for key in ("status", "model_count", "summary", "error")}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
