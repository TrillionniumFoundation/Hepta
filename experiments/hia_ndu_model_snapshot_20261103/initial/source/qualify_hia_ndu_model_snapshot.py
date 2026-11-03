#!/usr/bin/env python3
"""Compare finite snapshot costs with the pinned pre-change model implementation.

Complete native request bytes and all independent finite first-action minima
must agree before timing. This measures Python preparation, never native NDU
efficacy or full lifecycle benefit. The old budget-erasure protocol is untouched.
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
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta import hia_ndu_cost as current
from tests.test_hia_ndu_cost import independent_frontier
from tools.qualify_hia_ndu_budget_erasure import corpus, encoded, first_costs, require, save

PROTOCOL = ROOT / "benchmarks/hia_ndu_cost/MODEL_SNAPSHOT_PROTOCOL.json"
BASELINE = ROOT / "benchmarks/hia_ndu_cost/historical_hia_ndu_cost_18291446e048f760f5519823e865727ef51db11a.py"


def inventory():
    paths = [ROOT / name for name in ("hepta/hia_ndu_cost.py", "hepta/hia_ndu.py",
             "hepta/hia_program_tools.py", "hepta/hia_json_preflight.py", "tests/test_hia_ndu_cost.py",
             "tests/test_hia_ndu_model_snapshot.py", "tools/qualify_hia_ndu_budget_erasure.py")]
    return {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in [*paths, PROTOCOL, BASELINE, Path(__file__)]}


def qualify(output):
    started = time.monotonic_ns()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    protocol = json.loads(PROTOCOL.read_bytes())
    source = inventory()
    old_bytes = BASELINE.read_bytes()
    require(sha256(old_bytes).hexdigest() == protocol["baseline_sha256"], "frozen snapshot baseline mismatch")
    old = types.ModuleType("hepta._model_snapshot_historical")
    old.__package__ = "hepta"
    exec(compile(old_bytes, str(BASELINE), "exec"), old.__dict__)
    models = corpus(protocol)
    report = {"schema": "hepta.hia.ndu.model-snapshot.result.v1", "status": "failed",
              "protocol": protocol, "source_before": source, "model_count": len(models),
              "corpus_sha256": sha256(encoded(models)).hexdigest(),
              "host": {"platform": platform.platform(), "python": sys.version},
              "checks": [], "samples": [], "native_invocations": 0,
              "native_ndu_advantage_established": False, "full_lifecycle_net_benefit_established": False,
              "authority": "DENY_ALL", "safety_certificate": False}
    save(output / "PROTOCOL.json", protocol)
    save(output / "CORPUS.json", models)
    save(output / "REGISTRATION.json", {"source": source, "corpus_sha256": report["corpus_sha256"],
                                        "before_first_comparison_or_timing": True})
    try:
        for number, model in enumerate(models):
            before = deepcopy(model)
            require(old.validate_model(model) == current.validate_model(model), "snapshot mismatch")
            original, replacement = old.exact_control(model), current.exact_control(model)
            require(encoded(original) == encoded(replacement), "complete witness/search mismatch")
            require(first_costs(replacement["witnesses"]) == independent_frontier(model), "independent frontier mismatch")
            native_old, native_new = old.build_request(model), current.build_request(model)
            require(encoded(native_old) == encoded(native_new), "native request/plan bytes mismatch")
            require(first_costs(native_new["plans"].values()) == independent_frontier(model, committed_call=True),
                    "independent committed frontier mismatch")
            require(model == before, "caller input changed")
            report["checks"].append({"case": number, "horizon": len(model["baseline"]["latency_ns"]),
                "first_actions": len(replacement["witnesses"]), "native_first_actions": len(native_new["plans"]),
                "search": replacement["search"], "native_request_sha256": sha256(encoded(native_new["request"])).hexdigest()})
        modules = {"baseline": old, "snapshot": current}
        for _ in range(protocol["warmup_sweeps"]):
            for module in modules.values():
                for operation in protocol["operations"]:
                    for model in models:
                        getattr(module, operation)(model)
        report["warmup_sweeps_completed"] = protocol["warmup_sweeps"]
        for round_number in range(protocol["rounds"]):
            order = ("baseline", "snapshot") if round_number % 2 == 0 else ("snapshot", "baseline")
            for operation in protocol["operations"]:
                for arm in order:
                    call = getattr(modules[arm], operation)
                    began = time.monotonic_ns()
                    for model in models:
                        call(model)
                    sample = {"round": round_number, "operation": operation, "arm": arm,
                              "calls": len(models), "wall_ns": time.monotonic_ns() - began}
                    report["samples"].append(sample)
                    with (output / "SAMPLES.jsonl").open("a") as stream:
                        stream.write(json.dumps(sample, sort_keys=True) + "\n")
        report["summary"] = {}
        for operation in protocol["operations"]:
            arms = {}
            for arm in modules:
                values = [r["wall_ns"] for r in report["samples"] if r["operation"] == operation and r["arm"] == arm]
                arms[arm] = {"median_ns": statistics.median(values), "p95_ns": sorted(values)[math.ceil(.95 * len(values)) - 1],
                             "total_ns": sum(values), "samples": len(values)}
            report["summary"][operation] = {"arms": arms,
                "new_over_old_median": arms["snapshot"]["median_ns"] / arms["baseline"]["median_ns"],
                "new_over_old_total": arms["snapshot"]["total_ns"] / arms["baseline"]["total_ns"]}
        report["source_after"] = inventory()
        require(report["source_after"] == source, "source changed during qualification")
        report.update(status="passed", all_complete_witnesses_equal=True,
                      all_native_request_bytes_equal=True, all_independent_frontiers_equal=True,
                      all_snapshots_equal=True)
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    report["outer_wall_ns_excluding_final_result_write"] = time.monotonic_ns() - started
    save(output / "RESULT.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    report = qualify(parser.parse_args().output)
    print(json.dumps({k: report.get(k) for k in ("status", "model_count", "summary", "error")}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
