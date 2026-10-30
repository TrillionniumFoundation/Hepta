#!/usr/bin/env python3
"""Qualify exact finite-graph compression and measure the real native control path.

The fixture timings are declared model inputs, not hardware workload evidence.
This report covers controller construction, native admission/startup, request,
response, evidence writes and shutdown. Use qualify_hia_ndu_graph with the
optional ndu-compact arm for actual proof/build/load/run lifecycle measurements.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from fractions import Fraction
from hashlib import sha256
import json
from pathlib import Path
import platform
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu import NduBridgeError, Q32, finite_plan_request
from hepta.hia_ndu_session import NduSession
from hepta.hia_planning import compact_finite_plan_request
from tools.qualify_hia_ndu_graph import (PROTOCOL, arithmetic_choice, graph_fields, light_bundle)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def save(path, value):
    path.write_bytes(encoded(value) + b"\n")


def model_bank():
    """Explicit, reproducible modeled inputs for a same-information comparison."""
    rows = (("base", [10, 200, 200], 0, "verified"),
            ("guard-small", [50, 180, 180], 20, "verified"),
            ("guard-wide", [50, 1, 1], 20, "verified"),
            ("refused-unguarded", [0, 0, 0], 2, "rejected"))
    candidates = {}
    for index, (name, values, setup, status) in enumerate(rows, 1):
        candidates[name] = {"source_sha256": f"{index:064x}",
            "verification": {"verification_sha256": f"{index + 10:064x}", "status": status},
            "setup_ns": setup * 1_000_000,
            "latency_ns": {str(size): value * 1_000_000 for size, value in zip((3, 17, 33), values)}}
    return {"schema": "explicit-modeled-cost-fixture-not-measured-hardware",
            "bank_sha256": sha256(encoded(candidates)).hexdigest(), "candidates": candidates}


def reference_frontier(request):
    """Full feasible-set oracle using rational ties-to-even backward recursion."""
    scores = {}
    for row in request["candidates"]:
        if (not row["verified"] or row["resource_cost_q32"] > request["resource_budget_q32"]
                or row["risk_q32"] > request["risk_ceiling_q32"]):
            continue
        value = row["terminal_q32"]
        for step in reversed(row["events"]):
            value = step["instant_q32"] + round(Fraction(step["discount_q32"] * value, Q32))
        scores[row["id"]] = value
    best = max(scores.values())
    return {"ids": sorted(name for name, value in scores.items() if value == best),
            "value_q32": best, "feasible_count": len(scores)}


def differential_cases(fields):
    result = []
    # Fixed model/filtration, including refusal and unaffordable delivery.
    for budget, completion in ((1_000_000_000, 2_000_000_000), (1, 2_000_000_000),
                               (1_000_000_000, 0), (34_000_000, 34_000_000)):
        result.append(dict(deepcopy(fields), remaining_budget_ns=budget,
                           completion_value_ns=completion))
    for status in ("unknown", "rejected", "timeout"):
        item = deepcopy(fields)
        item["states"]["guard-wide"]["status"] = status
        result.append(item)
    tied = deepcopy(fields)
    tied["decision_cost_ns"] = 0
    tied["batch_costs_ns"] = {name: [1_000_000] * 3 for name in tied["states"]}
    for transition in tied["transitions"]:
        transition["setup_ns"] = 0
    result.append(tied)
    return result


def qualify(output, *, identity=None, repetitions=9):
    if type(repetitions) is not int or not 1 <= repetitions <= 30:
        raise ValueError("one to thirty predeclared repetitions are required")
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    source_paths = ["hepta/hia_ndu.py", "hepta/hia_ndu_session.py", "hepta/hia_planning.py",
                    "tools/qualify_hia_ndu_graph.py", "tools/qualify_hia_ndu_compression.py",
                    "tests/test_hia_planning.py"]
    source_identity = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in source_paths}
    bank = model_bank()
    arguments = dict(current="base", remaining_sizes=[3, 17, 33], observations=[],
                     remaining_ns=1_000_000_000, decision_ns=1_000_000,
                     protocol=PROTOCOL, snapshot="b" * 64, generation=1)
    fields = graph_fields(bank, **arguments)
    full = finite_plan_request(**fields)
    compact = compact_finite_plan_request(**fields)
    expected = reference_frontier(full["request"])
    assert reference_frontier(compact["request"])["ids"] == expected["ids"]
    save(root / "INPUT.json", {"bank": bank, "arguments": arguments, "fields": fields})
    save(root / "SOURCE_IDENTITY.json", source_identity)
    save(root / "EXHAUSTIVE.json", full)
    save(root / "COMPACT.json", compact)
    checks, native_checks, samples = [], [], []
    manifest = None
    session = None
    native = {"status": "blocked", "reason": "original native NDU identity was not supplied"}
    for index, item in enumerate(differential_cases(fields)):
        a, b = finite_plan_request(**item), compact_finite_plan_request(**item)
        oracle_a, oracle_b = reference_frontier(a["request"]), reference_frontier(b["request"])
        assert oracle_a["ids"] == oracle_b["ids"]
        checks.append({"case": index, "full_paths": len(a["plans"]), "compact_paths": len(b["plans"]),
                       "oracle_ids": oracle_a["ids"], "exact_frontier_match": True})
    try:
        if identity is not None:
            admission = time.monotonic_ns()
            manifest = json.loads(Path(identity).read_bytes())
            session = NduSession(manifest["binary"], identity)
            native = {"status": "executed", "admission_wall_ns": time.monotonic_ns() - admission,
                      "identity": manifest["identity"], "binary_sha256": manifest["binary_sha256"]}
            save(root / "NATIVE_BUILD_IDENTITY.json", manifest)
            for index, item in enumerate(differential_cases(fields)):
                a, b = finite_plan_request(**item), compact_finite_plan_request(**item)
                ra, rb = session.evaluate(a["request"]), session.evaluate(b["request"])
                for key in ("advisory_candidate_id", "pareto_candidate_ids", "disposition"):
                    assert ra[key] == rb[key], (index, key, ra[key], rb[key])
                assert ra["pareto_candidate_ids"] == reference_frontier(a["request"])["ids"]
                native_checks.append({"case": index, "full": ra, "compact": rb,
                                      "complete_frontier_and_disposition_equal": True})
            save(root / "NATIVE_DIFFERENTIAL.json", native_checks)

        arms = ("light-nanosecond-dp", "native-exhaustive", "native-compact") if session else ("light-nanosecond-dp",)
        for repeat in range(repetitions):
            order = arms if repeat % 2 == 0 else arms[::-1]
            for arm in order:
                outer = time.monotonic_ns()
                construction = outer
                if arm == "light-nanosecond-dp":
                    bundle = light_bundle(bank, **arguments)
                elif arm == "native-exhaustive":
                    bundle = finite_plan_request(**fields)
                else:
                    bundle = compact_finite_plan_request(**fields)
                construction_ns = time.monotonic_ns() - construction
                decision = time.monotonic_ns()
                if arm == "light-nanosecond-dp":
                    selected = arithmetic_choice(bundle, remaining_ns=fields["remaining_budget_ns"],
                                                 completion_ns=fields["completion_value_ns"])
                    response = {"algorithm": "existing-additive-nanosecond-control-not-native-NDU",
                                "advisory_candidate_id": selected["id"] if selected else "abstain"}
                else:
                    response = session.evaluate(bundle["request"])
                    assert response["pareto_candidate_ids"] == expected["ids"]
                decision_ns = time.monotonic_ns() - decision
                # Store all real candidates and receipts; their unequal evidence
                # volume is charged to the arm producing it, never hidden shared.
                evidence = time.monotonic_ns()
                filename = f"sample-{repeat:02d}-{arm}.json"
                save(root / filename, {"arm": arm, "bundle": bundle, "response": response,
                                      "construction_ns": construction_ns, "decision_ns": decision_ns})
                evidence_ns = time.monotonic_ns() - evidence
                samples.append({"arm": arm, "repeat": repeat, "construction_ns": construction_ns,
                                "decision_ns": decision_ns, "evidence_encoding_write_ns": evidence_ns,
                                "total_wall_ns": time.monotonic_ns() - outer, "evidence": filename})
    finally:
        if session is not None:
            shutdown = time.monotonic_ns()
            session.close()
            native["shutdown_wall_ns"] = time.monotonic_ns() - shutdown
            native["session"] = session.snapshot()
    medians = {arm: statistics.median(row["total_wall_ns"] for row in samples if row["arm"] == arm)
               for arm in {row["arm"] for row in samples}}
    build = manifest.get("build_cost") if manifest else None
    build_known = (type(build) is dict and type(build.get("wall_ns")) is int
                   and build["wall_ns"] >= 0 and build.get("target_cache") == "empty")
    build_ns = build["wall_ns"] if build_known else None
    setup_ns = native.get("admission_wall_ns", 0) + native.get("shutdown_wall_ns", 0)
    standalone = {arm: sum(row["total_wall_ns"] for row in samples if row["arm"] == arm)
                  + (setup_ns + build_ns if arm.startswith("native-") and build_known else 0)
                  for arm in medians}
    assert source_identity == {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in source_paths}, "source changed during qualification"
    result = {"schema": "hepta.hia.ndu.compression.qualification.v1", "host": platform.platform(),
              "source_identity": source_identity, "repetitions": repetitions,
              "input_scope": "modeled-cost protocol fixtures; no actual program-performance claim",
              "same_information_digest": sha256(encoded(fields)).hexdigest(),
              "exhaustive_path_count": len(full["plans"]), "retained_path_count": len(compact["plans"]),
              "model_differential": checks, "native_differential_count": len(native_checks),
              "native": native, "samples": samples, "median_pipeline_wall_ns": medians,
              "reported_original_native_build_ns": build_ns, "standalone_control_total_ns": standalone,
              "native_build_executed_this_run": False, "build_cost_provenance": "unchanged executable's original manifest",
              "cost_complete_for_declared_controller_scope": session is not None and build_known,
              "cost_scope": "construction, native manifest/process admission, request/response, own evidence writes, shutdown, original native build",
              "excluded": ["actual candidate proof, compiler and workload execution (separate seven-arm graph qualification)",
                           "toolchain installation", "native binary copy", "qualification-only oracle comparisons",
                           "process/import startup", "final aggregate report write"],
              "full_program_net_benefit_established": False, "statistical_superiority_established": False,
              "unrestricted_global_optimality": False, "authority": "DENY_ALL", "safety_certificate": False,
              "qualification_wall_ns_before_final_report": time.monotonic_ns() - started}
    save(root / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--repetitions", type=int, default=9)
    args = parser.parse_args()
    result = qualify(args.output, identity=args.identity, repetitions=args.repetitions)
    print(json.dumps({key: result[key] for key in ("exhaustive_path_count", "retained_path_count",
          "native_differential_count", "median_pipeline_wall_ns", "standalone_control_total_ns")}, indent=2))


if __name__ == "__main__":
    main()
