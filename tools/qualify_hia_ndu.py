#!/usr/bin/env python3
"""Run a real, finite Core -> native measurements -> pinned NDU candidate loop.

An explicit no-change is a successful result. No code is activated. Performance
projection assumes the declared call horizon and exactly the supplied corpus.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from time import perf_counter_ns

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu import (DECISION_RESERVE_NS, UPSTREAM_COMMIT, assess_samples,
                          identity, invoke_ndu, make_plan, observe_semantics,
                          prepare_candidate, read_json)
from hepta.hia_program import verify_program
from hepta.hia_program_tools import read_bounded
from tools.hia_ndu_measure import measure_pair


def _cases(value, *, allow_empty=False):
    if type(value) not in (list, tuple) or not (0 if allow_empty else 1) <= len(value) <= 64:
        raise ValueError("bounded scalar corpus required")
    result = []
    for row in value:
        if (type(row) is not list or len(row) != 4
                or any(type(v) is not int or not 0 <= v < (1 << 64) for v in row)):
            raise ValueError("case must contain exactly four usize values")
        result.append(list(row))
    return result


def qualify(program, plan, cases, *, negative_cases=(), bridge,
            expected_bridge_sha256, clang="clang", samples=31, iterations=10_000):
    started = perf_counter_ns()
    report = {"schema": "hepta.hia.ndu-qualification.v1", "ok": False,
              "status": "no_change", "decision": "no_change", "activated": False,
              "upstream_commit": UPSTREAM_COMMIT,
              "scope": "primitive v1-v6 byte-swap candidate; fixed native microbenchmark corpus",
              "budget_enforcement": {"search_cost": "measured admission ceiling; not a preemptive whole-call deadline",
                                     "native_processes": "individually bounded by the measurement instrument",
                                     "decision_reserve_ns": DECISION_RESERVE_NS},
              "claims": {"real_ndu_evaluator_executed": False,
                         "backend_refinement_proved": False, "all_input_equivalence_proved": False,
                         "global_optimum_proved": False, "production_gain_proved": False,
                         "native_hot_swap_performed": False, "p0_p7_fully_closed": False},
              "diagnostics": [], "costs": {}}
    try:
        prepared = prepare_candidate(program, plan)
        plan = prepared.plan
        cases, negative_cases = _cases(cases), _cases(negative_cases, allow_empty=True)
        report["plan"] = prepared.plan
        report["plan_sha256"] = prepared.plan_sha256
        report["candidate"] = {"baseline_sha256": prepared.baseline.sha256,
                               "candidate_sha256": prepared.candidate.sha256,
                               "replacements": prepared.replacements,
                               "canonical_core": prepared.candidate.canonical_json,
                               "relation": "exact_reproduced_byte_swap"}
        observations = observe_semantics(prepared, cases, negative_cases=negative_cases)
        report["semantic_validation"] = observations
        if not observations["ok"]:
            raise ValueError("finite semantic observation mismatch; no native candidate selected")
        if perf_counter_ns() - started + DECISION_RESERVE_NS > plan["objective"]["maximum_search_ns"]:
            raise ValueError("cost ceiling already exhausted before native measurement")
        measurement = measure_pair(prepared.baseline, prepared.candidate, plan["entry"], cases,
                                   clang=clang, samples=samples, iterations=iterations)
        report["measurement"] = measurement
        if not measurement["ok"]:
            raise ValueError("native measurement failed; all available observations retained")
        cost = perf_counter_ns() - started
        assessment = assess_samples(measurement["raw_samples"],
            calls_per_sample=measurement["counts"]["calls_per_sample"],
            objective=plan["objective"], search_cost_ns=cost)
        if prepared.replacements == 0 or prepared.candidate.sha256 == prepared.baseline.sha256:
            assessment["eligible"] = False
            assessment["reasons"].append("no_registered_rewrite")
        report["assessment"] = assessment
        evidence = {"plan_sha256": prepared.plan_sha256,
                    "validation_sha256": identity(observations),
                    "measurement_sha256": identity(measurement),
                    "assessment_sha256": identity(assessment)}
        report["evidence_bindings"] = evidence
        candidates = []
        for role, candidate_id, core in (("baseline", "abstain", prepared.baseline),
                                        ("candidate", "byte_swap", prepared.candidate)):
            artifact = measurement["native"][role]
            if artifact["core_sha256"] != core.sha256:
                raise ValueError("compiled artifact identity differs from the validated Core")
            candidates.append({"id": candidate_id, "core_sha256": core.sha256,
                "artifact_sha256": artifact["artifact_sha256"],
                "evidence_sha256": identity({**evidence, "role": role}),
                "feasible": True if role == "baseline" else assessment["eligible"],
                "projected_total_ns": assessment["projected_" + role + "_total_ns"],
                "peak_live_bytes": observations["peak_live_bytes"][role],
                "artifact_bytes": artifact["artifact_bytes"]})
        objective = plan["objective"]
        request = {"schema": "hepta.hia.ndu-request.v1", "objective_sha256": prepared.plan_sha256,
                   "generation": plan["generation"],
                   "maximum_live_bytes": objective["maximum_live_bytes"],
                   "maximum_artifact_bytes": objective["maximum_artifact_bytes"],
                   "candidates": candidates}
        # This reservation includes request/binding serialization, executable
        # identity checks and subprocess work, not just the evaluator's CPU.
        receipt = invoke_ndu(request, bridge=bridge, expected_binary_sha256=expected_bridge_sha256)
        selection_wall_ns = perf_counter_ns() - started - cost
        report["ndu"] = receipt
        report["claims"]["real_ndu_evaluator_executed"] = True
        report["costs"]["selection_wall_ns"] = selection_wall_ns
        report["costs"]["search_before_decision_ns"] = cost
        if selection_wall_ns > DECISION_RESERVE_NS:
            report["diagnostics"].append({"code": "decision_cost_exceeded_reserve"})
        elif (receipt["response"]["advisory_recommendation"] == "byte_swap"
              and assessment["eligible"]):
            report["decision"] = "candidate_advised"
        report["ok"] = True
        report["status"] = "completed_" + report["decision"]
        report["reason"] = ("validated finite candidate advised; separate host activation required"
                            if report["decision"] == "candidate_advised" else
                            "baseline retained; measured gain, cost, resource limits or NDU frontier did not justify selection")
    except Exception as error:
        report["diagnostics"].append({"type": type(error).__name__, "message": str(error)})
        report["status"] = "failed_closed_no_change"
    finally:
        report["costs"]["total_paid_wall_ns"] = perf_counter_ns() - started
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--negative-cases", type=Path)
    parser.add_argument("--entry", required=True)
    parser.add_argument("--bridge", required=True, type=Path)
    parser.add_argument("--bridge-sha256", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--samples", type=int, default=31)
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--horizon-calls", type=int, default=100_000_000)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    # All source and case files are read before opening an exclusive new report.
    program_bytes = read_bounded(args.program)
    program = verify_program(program_bytes)
    plan = make_plan(program, entry=args.entry, horizon_calls=args.horizon_calls)
    cases = read_json(read_bounded(args.cases, limit=1_048_576))
    negative = read_json(read_bounded(args.negative_cases, limit=1_048_576)) if args.negative_cases else []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        # Reserve the destination before paying for an experiment. A repeated
        # command cannot run a new search and then discard it on FileExistsError.
        report = {"schema": "hepta.hia.ndu-qualification.v1", "ok": False,
                  "status": "started_no_completed_measurement", "decision": "no_change",
                  "activated": False, "diagnostics": []}
        json.dump(report, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        try:
            report = qualify(program, plan, cases, negative_cases=negative,
                             bridge=args.bridge, expected_bridge_sha256=args.bridge_sha256,
                             clang=args.clang, samples=args.samples, iterations=args.iterations)
            report["input_files"] = {"program_sha256": sha256(program_bytes).hexdigest(),
                                     "cases_sha256": identity(cases), "negative_cases_sha256": identity(negative)}
        except BaseException as error:
            report.update(ok=False, status="interrupted_no_change", decision="no_change", activated=False)
            report["diagnostics"].append({"type": type(error).__name__, "message": str(error)})
            raise
        finally:
            stream.seek(0)
            stream.truncate()
            json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
    print(json.dumps({"ok": report["ok"], "status": report["status"],
                      "decision": report["decision"], "report": str(args.output)}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
