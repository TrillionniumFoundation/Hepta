#!/usr/bin/env python3
"""Execute registered coverage witnesses without selecting on physical timing."""
from __future__ import annotations
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import qualify_hia_ndu_feedback as common
from experiments.hia_ndu_feedback_20261106 import model
from experiments.hia_ndu_feedback_20261106.workload import NativeCache

PROTOCOL = ROOT / "benchmarks/hia_ndu_feedback_state_coverage/WITNESS_PROTOCOL.json"


def select_witnesses(coverage, p):
    selected, memberships = {}, []
    for family in p["families"]:
        for environment in p["environments"]:
            for mechanism, definition in p["mechanisms"].items():
                matches = sorted((r for r in coverage["rows"] if r["status"] == "passed"
                    and r["environment"] == environment
                    and (family == "all-distinct" or family in r["families"])
                    and all(r["flags"].get(flag, False) for flag in definition["flags"])), key=lambda r: r["id"])
                state = matches[0] if matches else None
                membership = {"family": family, "environment": environment, "mechanism": mechanism,
                              "matching_state_count": len(matches), "selected_state_id": state["id"] if state else None}
                memberships.append(membership)
                if state is not None:
                    for arm in ("dynamic-ndu", "same-objective", definition["comparison_arm"]):
                        selected.setdefault((state["id"], arm), {"state_id": state["id"], "arm": arm,
                            "scenario": state["scenario"], "observation": state["observation"],
                            "coverage_action": state["answers"].get(arm, {}).get("action"), "memberships": []})["memberships"].append(membership)
    return {"memberships": memberships, "cells": [selected[k] for k in sorted(selected)]}


def execute(cell, p, inputs, directory):
    started = time.monotonic_ns()
    scenario, observation = model.Scenario(**cell["scenario"]), model.Observation(**cell["observation"])
    worker, backend = None, None
    row = {**cell, "status": "failed", "errors": [], "physically_executed": False, "authority": "DENY_ALL"}
    try:
        worker = NativeCache(inputs["workload_binary"]["path"], inputs["workload_manifest"]["path"],
            directory / "workload.jsonl", n=p["dimension"], seed=p["matrix_seed"])
        if observation.resident >= 0:
            worker._ask({"command": "prepare", "id": observation.resident, "epoch": 1})
        if worker.resident != observation.resident:
            raise ValueError("supplied public/physical resident mismatch")
        if cell["arm"] in ("dynamic-ndu", "fixed-preference-ndu"):
            backend = common.LazyBackend(inputs, directory / "values.jsonl")
        decision = model.plan(scenario, observation, cell["arm"], backend=backend, fixed_action=0,
                              max_transitions=p["max_transitions_per_decision"])
        row["decision"] = decision
        if cell["arm"] != "fixed" and decision["action"] != cell["coverage_action"]:
            raise ValueError("repeated decision differs from registered coverage action")
        if decision["action"] is None:
            row["physical_outcome"] = {"status": "explicit_abstain", "executed": False}
        else:
            outcome = worker.execute(decision["action"], observation.request, repeats=p["kernel_repeats"],
                vector_seed=p["vector_seed"], expected_state_digest=worker.state_digest)
            row["physical_outcome"] = outcome
            if outcome["selected_resident"] != decision["action"] or worker.resident != decision["action"]:
                raise ValueError("native decision was not consumed by actual cache dispatch")
            row["physically_executed"] = True
        row["status"] = "passed"
    except BaseException as error:
        row["errors"].append({"type": type(error).__name__, "message": str(error),
                              "traceback": traceback.format_exc(), "search_stats": getattr(error, "search_stats", {})})
    finally:
        for name, obj in (("workload_close", worker), ("native_close", backend)):
            if obj is not None:
                try:
                    row[name] = obj.close()
                except BaseException as error:
                    row["status"] = "failed"
                    row["errors"].append({"phase": name, "type": type(error).__name__, "message": str(error)})
        row["wall_ns"] = time.monotonic_ns()-started
        row["workload_attempts"] = worker.rows if worker is not None else []
        row["workload_wall_ns"] = sum(r["workload_wall_ns"] for r in row["workload_attempts"])
    return row


def run(args):
    started = time.monotonic_ns()
    source = common.source_identity()
    p = json.loads(PROTOCOL.read_text())
    coverage_identity = common.identity(args.coverage)
    coverage = json.loads(Path(args.coverage).read_text())
    prior_identity = common.identity(args.registration)
    prior = json.loads(Path(args.registration).read_text())
    inputs = prior["inputs"]
    if coverage["source"]["commit"] != source["commit"] or not coverage["original_native_executed"]:
        raise ValueError("coverage was not original-native on this exact source")
    if (coverage.get("status") != "passed" or coverage.get("all_states_original_native_qualified") is not True
        or len(coverage["rows"]) != coverage["planned_distinct_states"]
        or any(r["status"] != "passed" for r in coverage["rows"])):
        raise ValueError("incomplete coverage cannot qualify physical witnesses")
    for info in inputs.values():
        if common.identity(info["path"]) != info:
            raise ValueError("native witness input changed")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    selection = select_witnesses(coverage, p)
    frozen = {"schema": "hepta.hia.ndu.physical-witness-freeze.v1", "source": source,
        "protocol": p, "coverage": coverage_identity, "prior_registration": prior_identity, "inputs": inputs,
        "selection": selection, "before_any_physical_measurement": True, "authority": "DENY_ALL"}
    common.write(output / "REGISTRATION.json", frozen)
    rows, fatal = [], None
    try:
        for index, cell in enumerate(selection["cells"]):
            directory = output / "cells" / f"{index:03d}"
            directory.mkdir(parents=True)
            row = execute(cell, p, inputs, directory)
            row["cell_index"] = index
            common.write(directory / "RESULT.json", row)
            rows.append(row)
    except BaseException as error:
        fatal = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
    errors = []
    try:
        if common.source_identity() != source:
            errors.append("source drift")
        for info in [coverage_identity, prior_identity, *inputs.values()]:
            if common.identity(info["path"]) != info:
                errors.append("input drift: " + info["path"])
    except BaseException as error:
        errors.append(str(error))
    checks = {"every_selected_cell_retained": len(rows) == len(selection["cells"]),
              "every_selected_dispatch_passed": bool(rows) and all(r["status"] == "passed" for r in rows),
              "source_and_inputs_unchanged": not errors}
    result = {"schema": "hepta.hia.ndu.physical-witness-result.v1", "source": source,
        "planned_cells": len(selection["cells"]), "retained_cells": len(rows),
        "physical_actions": sum(r["physically_executed"] for r in rows),
        "explicit_abstentions": sum(r.get("physical_outcome", {}).get("status") == "explicit_abstain" for r in rows),
        "checks": checks, "fatal_error": fatal, "postflight_errors": errors,
        "total_cell_wall_ns": sum(r["wall_ns"] for r in rows), "wall_before_report_ns": time.monotonic_ns()-started,
        "memberships": selection["memberships"], "scope": p["scope"], "resource_units": p["resource_units"],
        "unique_NDU_advantage_claim": False, "authority": "DENY_ALL", "production_activation": False}
    common.write(output / "RESULT.json", result)
    print(json.dumps(result), flush=True)
    return 0 if fatal is None and all(checks.values()) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    raise SystemExit(run(parser.parse_args()))
