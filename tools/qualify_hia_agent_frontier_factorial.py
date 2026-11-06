#!/usr/bin/env python3
"""Run the existing matched 2x2 task/evaluator with external model responses.

The external transport supplies no attested token usage or hard isolation.
Consequently this records finite native coding outcomes and observed delivery
wall only; it cannot certify total-cost or human-review productivity gains.
The existing local-model cohort and all its negative results are unchanged.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import qualify_hia_agent_edit_factorial as base
from tools import qualify_hia_upstream_factorial as upstream
from hepta.hia_program_tools import read_bounded
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity

SCHEMA = "hepta.agent.frontier-factorial.v1"
PROTOCOL = {
    "schema": SCHEMA,
    "cohort": "authored",
    "models": [{"id": "inherited_session_model", "provider": "delegated_model"}],
    "tasks": ["average_floor_stamp", "clamped_delta_bias", "stride_span_v2", "floor_multiple_v2"],
    "arms": [list(arm) for arm in base.ARMS], "expected_cells": 16,
    "attempts_per_cell": 1, "response_limit_bytes": 65536, "max_delivery_wall_seconds": 240,
    "generation_interface": "fresh delegated session with the complete matched public prompt",
    "tool_policy": "read only the registered PUBLIC_PROMPT.txt and write RESPONSE.json; no other source, evaluator, hidden or reference reads",
    "isolation": "instruction boundary only; no hardened filesystem or provider isolation attestation",
    "effective_weights_attested": False, "token_usage_available": False,
    "human_review_seconds": None, "total_cost_advantage_proved": False,
    "native_scoring": "existing matched evaluator, immutable image, terminal public/hidden checks",
    "task_scope": "four inherited authored two-file tasks; not real upstream maintenance population",
    "schedule": "existing rotated 2x2 order; no retry, replacement or result-based reselection",
    "wall_scope": "host-observed begin-to-response ingestion including dispatch and file publication",
}
UPSTREAM_PROTOCOL = {
    **PROTOCOL, "cohort": "upstream",
    "tasks": ["stb_floor_overflow", "stb_euclidean_int_min"],
    "expected_cells": 8,
    "task_scope": "two inherited historical stb_divide fixes; one project, unknown training exposure, not an independent maintenance population",
    "native_scoring": "existing upstream factorial native evaluator and same-Core VM check for admitted HIA; immutable image; terminal public/hidden checks",
}


def cohort(configuration):
    for registered, owner in ((PROTOCOL, base), (UPSTREAM_PROTOCOL, upstream)):
        if type(configuration) is dict and canonical(configuration) == canonical(registered):
            return owner
    raise ValueError("unregistered external factorial cohort")


def save(path, value):
    base.save(Path(path), value)


def git(*args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT, env=env)


def bindings():
    sources = base.source_bindings()
    sources.update(upstream.source_bindings())
    sources[str(Path(__file__).relative_to(ROOT))] = file_identity(__file__)["sha256"]
    return dict(sorted(sources.items()))


def current_identity():
    head = git("rev-parse", "HEAD").decode().strip()
    sources = bindings()
    for name, expected in sources.items():
        # Resolve canonical objects, not replacement refs or a clean-status bit.
        raw = git("show", head + ":" + name)
        if sha256(raw).hexdigest() != expected:
            raise ValueError("uncommitted or changed factorial source: " + name)
    return {"head": head, "tree": git("rev-parse", head + "^{tree}").decode().strip(), "sources": sources}


def prepare(output, clang, rustc, cohort_name="authored"):
    configuration = {"authored": PROTOCOL, "upstream": UPSTREAM_PROTOCOL}.get(cohort_name)
    owner = cohort(configuration)
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("evidence must be outside the source checkout")
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    source = current_identity()
    tasks = owner.fixtures.make_fixtures()
    if [t["id"] for t in tasks] != configuration["tasks"]:
        raise ValueError("task inventory changed")
    controls = ((base.evaluator.reference_controls if owner is base else upstream.reference_controls)
                (tasks, output / "controls", clang, rustc))
    if controls["passed"] != controls["count"]:
        raise ValueError("native positive/negative controls failed")
    schedule = owner.schedule(configuration)
    for index, descriptor in enumerate(schedule):
        task = next(t for t in tasks if t["id"] == descriptor["task"])
        directory = output / ("cell-" + str(index).zfill(2))
        directory.mkdir()
        text = owner.prompt(task, descriptor["language"], descriptor["interface"])
        (directory / "PUBLIC_PROMPT.txt").write_text(text + "\n")
        descriptor["prompt_sha256"] = sha256((text + "\n").encode()).hexdigest()
    record = {"schema": SCHEMA + ".registration", "protocol": configuration,
              "source": source, "fixtures_sha256": owner.digest(tasks), "schedule": schedule,
              "tools": {k: file_identity(v) for k, v in (("clang", clang), ("rustc", rustc))},
              "controls": {"count": controls["count"], "passed": controls["passed"],
                           "file": file_identity(output / "controls/CONTROLS.json")},
              "prepared_unix_ns": time.time_ns(), "preparation_wall_ns": time.monotonic_ns() - started,
              "model_requests": 0}
    if source != current_identity():
        raise ValueError("source drift during preparation")
    save(output / "REGISTRATION.json", record)
    return record


def validate(output):
    output = Path(output).resolve()
    record = json.loads((output / "REGISTRATION.json").read_bytes())
    owner = cohort(record["protocol"])
    if (record.get("schema") != SCHEMA + ".registration"
            or record["source"] != current_identity()
            or record["fixtures_sha256"] != owner.digest(owner.fixtures.make_fixtures())):
        raise ValueError("factorial registration/source drift")
    schedule = owner.schedule(record["protocol"])
    if len(record["schedule"]) != len(schedule):
        raise ValueError("factorial schedule changed")
    for index, (actual, expected) in enumerate(zip(record["schedule"], schedule)):
        if {k: v for k, v in actual.items() if k != "prompt_sha256"} != expected:
            raise ValueError("factorial schedule identity changed")
        path = output / ("cell-" + str(index).zfill(2)) / "PUBLIC_PROMPT.txt"
        if sha256(path.read_bytes()).hexdigest() != actual["prompt_sha256"]:
            raise ValueError("public prompt changed")
    for tool in record["tools"].values():
        if file_identity(tool["path"]) != tool:
            raise ValueError("factorial compiler changed")
    if file_identity(record["controls"]["file"]["path"]) != record["controls"]["file"]:
        raise ValueError("native controls changed")
    return record


def cell_dir(output, index, record):
    if type(index) is not int or not 0 <= index < len(record["schedule"]):
        raise ValueError("unregistered factorial cell")
    return Path(output).resolve() / ("cell-" + str(index).zfill(2))


def begin(output, index):
    record = validate(output)
    folder = cell_dir(output, index, record)
    if any(not (cell_dir(output, previous, record) / "CELL.json").is_file() for previous in range(index)):
        raise ValueError("previous scheduled cell has no terminal observation")
    if (folder / "RESPONSE.json").exists():
        raise ValueError("response already exists before generation start")
    start = {"descriptor": record["schedule"][index], "started_unix_ns": time.time_ns(),
             "started_monotonic_ns": time.monotonic_ns(),
             "registration_sha256": file_identity(Path(output) / "REGISTRATION.json")["sha256"]}
    save(folder / "STARTED.json", start)
    return {"prompt_path": str(folder / "PUBLIC_PROMPT.txt"), "response_path": str(folder / "RESPONSE.json"), **start}


def evaluate(output, index):
    record = validate(output)
    configuration = record["protocol"]
    owner = cohort(configuration)
    folder = cell_dir(output, index, record)
    start = json.loads((folder / "STARTED.json").read_bytes())
    if (start["descriptor"] != record["schedule"][index]
            or start["registration_sha256"] != file_identity(Path(output) / "REGISTRATION.json")["sha256"]):
        raise ValueError("generation start differs from registered cell")
    save(folder / "EVALUATION_STARTED.json", {"unix_ns": time.time_ns()})
    entered = time.monotonic_ns()
    row = {**start["descriptor"], "correct": False, "status": "response_missing", "token_usage": None,
           "human_review_seconds": None, "delivery_wall_ns": entered - start["started_monotonic_ns"],
           "response_provenance": "external delegated response; provider token/routing attestation absent"}
    try:
        if row["delivery_wall_ns"] < 0 or row["delivery_wall_ns"] > configuration["max_delivery_wall_seconds"] * 1_000_000_000:
            raise ValueError("external delivery wall budget exceeded")
        raw = read_bounded(folder / "RESPONSE.json", configuration["response_limit_bytes"])
        with (folder / "RAW_RESPONSE.txt").open("xb") as stream:
            stream.write(raw)
        row["response_sha256"] = sha256(raw).hexdigest()
        task = next(t for t in owner.fixtures.make_fixtures() if t["id"] == row["task"])
        text = owner.materialize(task, row["language"], row["interface"], raw.decode())
        row["status"] = "native_validation"
        built = owner.evaluator.build(task, row["language"], text, folder / "candidate",
                                     record["tools"]["clang"]["path"], record["tools"]["rustc"]["path"])
        row["build"] = built
        row["status"] = built["status"]
        if built["native_built"]:
            public = owner.evaluator.execute(built, task, task["public_cases"], task["public_expected"])
            row["public"] = public
            if public["status"] == "correct" and public["artifact_unchanged"]:
                hidden = owner.evaluator.execute(built, task, task["hidden_cases"], task["hidden_expected"])
                row["hidden"] = hidden
                row["correct"] = hidden["status"] == "correct" and hidden["artifact_unchanged"]
                row["status"] = "correct" if row["correct"] else "hidden_wrong"
            else:
                row["status"] = "public_wrong"
        validate(output)
    except Exception as error:
        # A previously correct output cannot survive a later source/tool or
        # evidence failure. Correctness belongs to the complete observation.
        row.update(correct=False, status="rejected_or_infrastructure_failure",
                   error={"type": type(error).__name__, "message": str(error)})
    finally:
        row["validation_wall_ns"] = time.monotonic_ns() - entered
        save(folder / "CELL.json", row)
    return row


def summarize(output):
    record = validate(output)
    configuration = record["protocol"]
    owner = cohort(configuration)
    rows, missing = [], []
    for index, descriptor in enumerate(record["schedule"]):
        path = cell_dir(output, index, record) / "CELL.json"
        if path.is_file():
            row = json.loads(path.read_bytes())
            if any(row.get(k) != v for k, v in descriptor.items()):
                raise ValueError("result identity differs from scheduled cell")
            if type(row.get("correct")) is not bool:
                raise ValueError("result correctness must be Boolean")
            if row["correct"] and (row.get("status") != "correct" or row.get("error") is not None
                    or row.get("build", {}).get("native_built") is not True
                    or any(row.get(stage, {}).get("status") != "correct"
                           or row.get(stage, {}).get("artifact_unchanged") is not True
                           for stage in ("public", "hidden"))):
                raise ValueError("correctness differs from complete terminal native evidence")
            rows.append(row)
        else:
            missing.append(descriptor["id"])
    arms = []
    for language, interface in owner.ARMS:
        selected = [r for r in rows if (r["language"], r["interface"]) == (language, interface)]
        arms.append({"language": language, "interface": interface, "planned": len(configuration["tasks"]), "observed": len(selected),
                     "correct": sum(r["correct"] is True and r["status"] == "correct" for r in selected),
                     "delivery_wall_ns": sum(r["delivery_wall_ns"] for r in selected),
                     "validation_wall_ns": sum(r["validation_wall_ns"] for r in selected),
                     "token_usage": None, "human_review_seconds": None, "total_cost_advantage_proved": False})
    return {"schema": SCHEMA + ".result", "complete": not missing, "planned_cells": configuration["expected_cells"],
            "observed_cells": len(rows), "missing_cells": missing, "arms": arms,
            "preparation_wall_ns": record["preparation_wall_ns"], "protocol": configuration,
            "source": record["source"], "population_productivity_proved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "begin", "evaluate", "summary"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--cohort", choices=("authored", "upstream"), default="authored")
    parser.add_argument("--clang"); parser.add_argument("--rustc"); parser.add_argument("--cell", type=int)
    args = parser.parse_args()
    if args.action == "prepare":
        result = prepare(args.output, args.clang, args.rustc, args.cohort)
        print(json.dumps({"prepared": True, "expected_cells": len(result["schedule"]), "controls": result["controls"]["passed"]}))
    elif args.action == "begin":
        print(json.dumps(begin(args.output, args.cell), indent=2))
    elif args.action == "evaluate":
        row = evaluate(args.output, args.cell)
        print(json.dumps({k: row[k] for k in ("id", "status", "correct")}))
    else:
        result = summarize(args.output)
        save(Path(args.output) / "RESULT.json", result)
        print(json.dumps({k: result[k] for k in ("complete", "planned_cells", "observed_cells", "arms")}, indent=2))


if __name__ == "__main__":
    main()
