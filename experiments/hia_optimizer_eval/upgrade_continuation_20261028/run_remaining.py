#!/usr/bin/env python3
"""Supplemental execution of registered upgrade cells never attempted before.

The original experiment is immutable. A timeout remains a failed registered
cell; it is never retried here. This driver only repairs the outer-loop abort
which otherwise prevents the remaining language/task comparisons from running.
It imports the frozen evaluator, prompts, inputs, compiler and feedback logic.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from experiments.hia_optimizer_eval.next_20261028 import upgrade_pilot as frozen
from experiments.hia_optimizer_eval.next_20261028.run_agent import validate_registration
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical, file_identity

SCHEMA = "hepta.hia.upgrade-unstarted-cell-continuation.v1"
FEEDBACK = ("The submitted upgrade failed compilation or public validation. Submit both complete replacement files again within the same interface contract. Hidden tests have not run.\n")


def read(path):
    return json.loads(Path(path).read_bytes())


def pending_cells(plan, result, previous):
    order = plan["scheduled_cells"]
    ids = [cell["id"] for cell in order]
    if len(ids) != len(set(ids)) or len(ids) != 4:
        raise ValueError("invalid original registered order")
    rows = result["cells"]
    attempted = [row["id"] for row in rows]
    if attempted != ids[:len(attempted)] or any(not row.get("attempts") for row in rows):
        raise ValueError("original attempted cells are not a nonempty-attempt prefix")
    actual = {path.parent.name for path in Path(previous).glob("*/attempt-*.request.json")}
    if actual != set(attempted):
        raise ValueError("original request artifacts disagree with attempted cells")
    return copy.deepcopy(order[len(attempted):])


def require_canonical_output(previous, output):
    wanted = Path(previous).resolve(strict=True).parent / "upgrade-continuation"
    if Path(output).resolve() != wanted or wanted.exists():
        raise ValueError("only the unique, never-created upgrade-continuation directory is allowed")
    return wanted


def previous_costs(previous, result):
    transports = [(path, read(path)) for path in sorted((previous / "engine").glob("transport-*.request.json"))]
    attempts = []
    for row in result["cells"]:
        for attempt in row["attempts"]:
            request_path = previous / row["id"] / f"attempt-{attempt['index']}.request.json"
            wanted = read(request_path)["messages"]
            matches = [(path, value) for path, value in transports if value["messages"] == wanted]
            known_input = len(matches[0][1]["payload"]["prompt"]) if len(matches) == 1 else None
            usage = attempt.get("usage")
            attempts.append({"cell": row["id"], "attempt": attempt["index"],
                "request_artifact": file_identity(request_path),
                "transport_request_artifact": file_identity(matches[0][0]) if len(matches) == 1 else None,
                "known_input_tokens": known_input,
                "validated_output_tokens": usage["output_tokens"] if usage else None,
                "usage_complete": usage is not None,
                "measured_inference_ns": attempt.get("inference_ns"),
                "original_status": attempt["status"]})
    log = previous / "engine/server.log"
    counters = re.findall(r"n_gen\s*=\s*(\d+)", log.read_text()) if log.exists() else []
    return {"experiment_wall_ns": result["experiment_wall_ns"],
        "requests_started": result["new_model_requests"], "responses_received": result["responses_received"],
        "attempts": attempts, "original_missing_counter_sums_are_not_zero_cost": True,
        "all_usage_complete": all(item["usage_complete"] for item in attempts),
        "total_validated_output_tokens": sum(item["validated_output_tokens"] for item in attempts)
            if all(item["usage_complete"] for item in attempts) else None,
        "total_measured_inference_ns": sum(item["measured_inference_ns"] for item in attempts)
            if all(item["measured_inference_ns"] is not None for item in attempts) else None,
        "last_partial_server_generation_counter": int(counters[-1]) if counters else None,
        "partial_counter_scope": "Last server n_gen observation, not validated returned token IDs or complete usage; never substituted for an unknown response count.",
        "server_log": file_identity(log) if log.exists() else None}


def public_retry_messages(messages, response, built, observed):
    return messages + [{"role": "assistant", "content": response["text"]},
        {"role": "user", "content": FEEDBACK + canonical(frozen.public_feedback(built, observed)).decode()}]


def transport_input_count(engine):
    path = engine.output / ("transport-" + str(engine.generation_count).zfill(3) + ".request.json")
    if not path.is_file():
        return None
    return len(read(path)["payload"]["prompt"])


def run_cell(cell, task, folder, engine, clang, rustc, expected_sources):
    folder.mkdir(exist_ok=False)
    row = {**cell, "attempts": [], "status": "incomplete", "correct": False,
           "hidden_tests_evaluated": False, "manual_time_ns": None,
           "human_repair_rounds": 0, "original_cell_retried": False}
    messages = [{"role": "user", "content": frozen.prompt(task, cell["language"])}]
    final_build = None
    engine_usable = True
    for index in range(frozen.ATTEMPTS):
        if frozen.bindings() != expected_sources:
            raise RuntimeError("frozen source changed before continuation request")
        attempt = {"index": index, "status": "inference_started", "input_tokens": None,
                   "output_tokens": None, "wall_budget_seconds": 180,
                   "maximum_output_tokens": frozen.LIMIT}
        row["attempts"].append(attempt)
        frozen.save(folder / f"attempt-{index}.request.json", {"messages": messages, "limit": frozen.LIMIT})
        request_started = time.monotonic_ns()
        count_before = engine.generation_count
        try:
            response = engine.generate(messages, limit=frozen.LIMIT, wall_seconds=180)
        except Exception as error:
            attempt.update(status="budget_timeout" if isinstance(error, TimeoutError) else "generation_error",
                           diagnostic={"type": type(error).__name__, "message": str(error)},
                           request_wall_ns=time.monotonic_ns() - request_started,
                           completion_requests_started=engine.generation_count - count_before,
                           known_input_tokens=transport_input_count(engine)
                               if engine.generation_count > count_before else None,
                           output_tokens=None, usage_complete=False)
            frozen.save(folder / f"attempt-{index}.evaluation.json", attempt)
            row["status"] = attempt["status"]
            engine_usable = False
            break  # A failed transport is never used to retry this cell.
        attempt["request_wall_ns"] = time.monotonic_ns() - request_started
        frozen.save(folder / f"attempt-{index}.response.json", response)
        attempt.update(usage=response["usage"], inference_ns=response["wall_nanoseconds"],
                       input_tokens=response["usage"]["input_tokens"],
                       output_tokens=response["usage"]["output_tokens"], usage_complete=True,
                       completion_requests_started=engine.generation_count - count_before)
        evaluation_started = time.monotonic_ns()
        built = frozen.build(task, cell["language"], response["text"], folder / f"attempt-{index}.candidate", clang, rustc)
        observed = frozen.execute(built, task["public_cases"], task["public_expected"]) if built["native_built"] else None
        attempt.update(build=built, public_validation=observed,
                       evaluation_ns=time.monotonic_ns() - evaluation_started,
                       status="public_passed" if observed and observed["status"] == "correct" else
                           built["status"] if not built["native_built"] else observed["status"])
        frozen.save(folder / f"attempt-{index}.evaluation.json", attempt)
        if built["status"] == "infrastructure_failure" or (observed is not None and not observed["artifact_unchanged"]):
            row["status"] = "native_infrastructure_failure"
            engine_usable = False
            break
        if observed is not None and observed["status"] == "correct":
            final_build = built
            break
        row["status"] = "public_validation_failed"
        if index + 1 < frozen.ATTEMPTS:
            messages = public_retry_messages(messages, response, built, observed)
    if final_build is not None:
        hidden_started = time.monotonic_ns()
        hidden = frozen.execute(final_build, task["hidden_cases"], task["hidden_expected"])
        row.update(hidden_tests_evaluated=True, hidden_validation=hidden,
                   hidden_validation_ns=time.monotonic_ns() - hidden_started,
                   correct=hidden["status"] == "correct" and hidden["artifact_unchanged"],
                   status="correct" if hidden["status"] == "correct" and hidden["artifact_unchanged"] else "hidden_validation_failed")
    row["automatic_repair_rounds"] = max(0, len(row["attempts"]) - 1)
    row["usage_complete"] = all(attempt.get("usage_complete") for attempt in row["attempts"])
    row["known_input_tokens"] = sum(attempt.get("usage", {}).get("input_tokens", attempt.get("known_input_tokens") or 0) for attempt in row["attempts"])
    row["known_output_tokens"] = sum(attempt.get("usage", {}).get("output_tokens", 0) for attempt in row["attempts"])
    row["input_tokens"] = row["known_input_tokens"] if row["usage_complete"] else None
    row["output_tokens"] = row["known_output_tokens"] if row["usage_complete"] else None
    frozen.save(folder / "CELL.json", row)
    return row, engine_usable


def observe_condition(engine):
    process = Path("/proc", str(engine.process.pid))
    values = [value.decode() for value in (process / "environ").read_bytes().split(b"\0")
              if value.startswith(b"LLAMA_ARG_REPACK=")]
    executable = Path(os.readlink(process / "exe")).resolve()
    result = {"pid": engine.process.pid, "whitelisted_environment": values,
              "executable": str(executable), "expected_executable": str(engine.binary),
              "condition_matches": values == ["LLAMA_ARG_REPACK=0"] and executable == engine.binary,
              "identity_sha256": file_identity(engine.output / "identity.json")["sha256"]}
    frozen.save(engine.output / "RUNTIME_CONDITION.json", result)
    if not result["condition_matches"]:
        raise RuntimeError("actual owned server runtime environment differs")
    return result


def run(previous, output):
    started = time.monotonic_ns()
    previous = Path(previous).resolve(strict=True)
    output = require_canonical_output(previous, output)
    original_plan, original = read(previous / "PLAN.json"), read(previous / "RESULT.json")
    validate_registration()
    sources = frozen.bindings()
    if original_plan["source_bindings"] != sources or original_plan["tasks"] != frozen.fixtures():
        raise ValueError("frozen compiler, evaluator or fixtures differ")
    if (original_plan["attempts_per_cell"] != 2 or original_plan["max_new_tokens_per_attempt"] != 1536
            or frozen.ATTEMPTS != 2 or frozen.LIMIT != 1536 or original_plan["threads"] != 4):
        raise ValueError("registered budget differs")
    if original.get("controls") != {"count": 16, "passed": 16} or not original.get("source_unchanged") or not original.get("tools_unchanged"):
        raise ValueError("original controls or identities failed")
    identity = original.get("model_and_runtime_identity", {})
    if not identity.get("model_unchanged") or not identity.get("runtime_unchanged"):
        raise ValueError("original model/runtime identity failed")
    tools = original_plan["tools"]
    if any(file_identity(item["path"]) != item for item in tools.values()):
        raise ValueError("frozen tools differ")
    model = original_plan["model"]
    if file_identity(model["path"]) != identity["model"]:
        raise ValueError("same model bytes required")
    if any(file_identity(item["path"]) != item for item in identity["runtime_files"]):
        raise ValueError("runtime libraries differ")
    if os.environ.get("LLAMA_ARG_REPACK") != "0":
        raise ValueError("approved runtime environment required")
    pending = pending_cells(original_plan, original, previous)
    if not pending:
        raise ValueError("no never-attempted cells remain")
    output.mkdir(parents=True, exist_ok=False)
    plan = {"schema": SCHEMA, "previous_directory": str(previous),
            "previous_plan": file_identity(previous / "PLAN.json"),
            "previous_result": file_identity(previous / "RESULT.json"),
            "continuation_source": file_identity(__file__), "source_bindings": sources,
            "model": model, "tools": tools, "runtime_files": identity["runtime_files"],
            "runtime_environment": {"LLAMA_ARG_REPACK": "0"},
            "runtime_amendment": file_identity(ROOT / "experiments/hia_optimizer_eval/next_20261028/RUNTIME_AMENDMENT.json"),
            "original_order": original_plan["scheduled_cells"], "pending_cells": pending,
            "skipped_already_attempted": [row["id"] for row in original["cells"]],
            "initial_prompt_sha256": {cell["id"]: hashlib.sha256(frozen.prompt(next(t for t in frozen.fixtures() if t["id"] == cell["task"]), cell["language"]).encode()).hexdigest() for cell in pending},
            "budget": {"attempts_per_cell": 2, "maximum_output_tokens": 1536, "wall_seconds_per_request": 180,
                       "threads": 4, "context": 8192, "seed": 0, "greedy": True},
            "previous_timeout_cell_retried": False, "added_after_original_registration": True,
            "claims": {"original_driver_completed": False, "original_scientific_gate_passed": False},
            "known_limitation": "Original timeout output tokens are unknown; no missing request is assigned zero token cost.",
            "manual_time_ns": None}
    frozen.save(output / "PLAN.json", plan)
    frozen.save(output / "source_snapshot.json", {"source_sha256": plan["continuation_source"]["sha256"], "text": Path(__file__).read_text()})
    result = {"schema": SCHEMA, "status": "incomplete", "cells": [], "engines": [],
              "manual_time_ns": None, "preparation_wall_ns": time.monotonic_ns() - started,
              "previous_costs": previous_costs(previous, original),
              "plan_sha256": file_identity(output / "PLAN.json")["sha256"]}
    engine = None
    def close_engine():
        nonlocal engine
        if engine is None:
            return
        # Stop timed-out compute before hashing files. No further generation.
        close_started = time.monotonic_ns()
        engine.close()
        result["engines"][-1].update(requests_started=engine.generation_count,
                                     responses_received=engine.response_count,
                                     final_identity=engine.verify_final_identity(),
                                     shutdown_and_identity_wall_ns=time.monotonic_ns() - close_started)
        engine = None
    try:
        tasks = {task["id"]: task for task in frozen.fixtures()}
        for cell in pending:
            if frozen.bindings() != sources:
                raise RuntimeError("source drift before pending cell")
            if engine is None:
                engine_started = time.monotonic_ns()
                engine = LlamaCppEngine(binary=tools["binary"]["path"], model=model["path"],
                    model_sha256=model["sha256"], output_dir=output / ("engine-" + str(len(result["engines"]))),
                    threads=4, context=8192, json_object=True)
                result["engines"].append({"directory": str(engine.output), "startup_wall_ns": time.monotonic_ns() - engine_started})
                if engine.runtime_identity != identity["runtime_files"] or engine.model_identity != identity["model"]:
                    raise RuntimeError("actual complete runtime/model identity differs before first request")
                result["engines"][-1]["runtime_condition"] = observe_condition(engine)
            row, usable = run_cell(cell, tasks[cell["task"]], output / cell["id"], engine,
                                  tools["clang"]["path"], tools["rustc"]["path"], sources)
            result["cells"].append(row)
            print(json.dumps({"continuation": cell["id"], "status": row["status"], "correct": row["correct"],
                              "attempts": len(row["attempts"]), "usage_complete": row["usage_complete"]}), flush=True)
            if not usable:
                close_engine()
        result["status"] = "all_previously_unstarted_cells_attempted"
    except Exception as error:
        result["diagnostic"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        try:
            close_engine()
        except Exception as error:
            result["shutdown_or_identity_error"] = {"type": type(error).__name__, "message": str(error)}
        result["source_unchanged"] = frozen.bindings() == sources
        result["tools_unchanged"] = all(file_identity(item["path"]) == item for item in tools.values())
        result["previous_plan_unchanged"] = file_identity(previous / "PLAN.json") == plan["previous_plan"]
        result["previous_result_unchanged"] = file_identity(previous / "RESULT.json") == plan["previous_result"]
        result["continuation_source_unchanged"] = file_identity(__file__) == plan["continuation_source"]
        result["all_original_cells_attempted"] = [row["id"] for row in original["cells"] + result["cells"]] == [cell["id"] for cell in original_plan["scheduled_cells"]]
        result["integrity_valid"] = all(result[key] for key in ("source_unchanged", "tools_unchanged",
            "previous_plan_unchanged", "previous_result_unchanged", "continuation_source_unchanged")) and all(
            item.get("final_identity", {}).get("model_unchanged") and item.get("final_identity", {}).get("runtime_unchanged")
            and item.get("runtime_condition", {}).get("condition_matches") for item in result["engines"])
        result["execution_record_valid"] = (result["all_original_cells_attempted"] and result["integrity_valid"]
            and "diagnostic" not in result and "shutdown_or_identity_error" not in result)
        if not result["execution_record_valid"]:
            result["status"] = "invalid_or_incomplete_continuation_execution"
        result["original_scientific_gate_passed"] = False
        result["experiment_wall_ns"] = time.monotonic_ns() - started
        result["combined_original_and_supplemental_upgrade_wall_ns"] = original["experiment_wall_ns"] + result["experiment_wall_ns"]
        result["combined_cost_scope"] = "Sum of the original upgrade phase and this complete supplemental execution; manual repair/tool construction time remains unmeasured. Missing per-request usage stays unknown."
        frozen.save(output / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", required=True)
    parser.add_argument("--output", required=True)
    result = run(**vars(parser.parse_args()))
    print(json.dumps({key: result[key] for key in ("status", "all_original_cells_attempted", "execution_record_valid", "experiment_wall_ns")}), flush=True)
    return 0 if result["execution_record_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
