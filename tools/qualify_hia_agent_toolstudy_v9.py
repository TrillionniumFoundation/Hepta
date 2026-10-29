#!/usr/bin/env python3
"""Fresh real-node qualification, then gated 16-cell full/node Agent study."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.hia_agent_factorial_v4_20261028 import evaluator
from experiments.hia_agent_toolstudy_v8_20261029 import budget, validation
from experiments.hia_agent_toolstudy_v9_20261029 import prompts, support
from experiments.hia_agent_toolstudy_v8_20261029.engine import ToolStudyEngine
from tools.provider_adapter.llama_cpp_engine import file_identity
from tools.qualify_hia_agent_primitive_repair import runtime_preflight


def summarize(cells, selection):
    groups = {}
    for arm in support.protocol()["arms"]:
        rows = [cell for cell in cells if cell["arm"] == arm]
        attempts = [attempt for row in rows for attempt in row["attempts"]]
        known = [attempt["usage"] for attempt in attempts if attempt.get("usage")]
        partial = [attempt["partial_usage"] for attempt in attempts if attempt.get("partial_usage")]
        requests = sum(attempt.get("actual_generation_requested", False) for attempt in attempts)
        complete = requests == len(known)
        correct = sum(row["correct"] for row in rows)
        input_tokens = sum(u["input_tokens"] for u in known) + sum(u["input_tokens"] for u in partial)
        output_tokens = sum(u["output_tokens"] for u in known)
        groups[arm] = {"planned_cells": 4, "attempted_cells": len(rows), "correct": correct,
                       "requests": requests, "submissions": len(attempts), "complete_usage": complete,
                       "unknown_usage_requests": requests-len(known), "known_input_tokens": input_tokens,
                       "known_output_tokens": output_tokens,
                       "partial_output_token_lower_bound": sum(u["observed_output_token_lower_bound"] for u in partial),
                       "total_tokens": input_tokens+output_tokens if complete else None,
                       "tokens_per_correct_cell": (input_tokens+output_tokens)/correct if complete and correct else None,
                       "automatic_repairs": sum(max(0, len(row["attempts"])-1) for row in rows),
                       "hidden_failures": sum(row["status"] == "hidden_failed" for row in rows),
                       "request_wall_ns": sum(attempt.get("request_wall_ns", 0) for attempt in attempts),
                       "validation_wall_ns": sum(attempt.get("validation_wall_ns", 0) for attempt in attempts),
                       "history_preparation_wall_ns": sum(attempt.get("history_preparation_wall_ns", 0) for attempt in attempts),
                       "cell_wall_ns": sum(row.get("cell_wall_ns", 0) for row in rows), "human_answer_repairs": 0}
    hn, rn, hf = (groups[arm] for arm in ("hia_node", "rust_node", "hia_full"))
    complete = len(cells) == 16 and all(group["complete_usage"] for group in groups.values())
    advantage = bool(selection and selection["eligible"] and complete and hn["correct"] == 4
                     and hn["correct"] >= rn["correct"] and hn["correct"] >= hf["correct"]
                     and hn["total_tokens"] <= rn["total_tokens"] and hn["total_tokens"] < hf["total_tokens"])
    return {"groups": groups, "complete_costed_coverage": complete, "descriptive_advantage_gate": advantage,
            "general_agent_productivity_proved": False, "real_long_term_maintenance_measured": False}


def run(*, stage, output, model, binary, tokenizer, clang, rustc, capacity, calibration_result=None):
    started = time.monotonic_ns()
    if stage not in {"calibration", "main"} or os.environ.get("LLAMA_ARG_REPACK") != "0":
        raise ValueError("registered stage and LLAMA_ARG_REPACK=0 required")
    cfg = support.protocol(); generation = cfg["generation"]
    head, source = support.clean_committed_source()
    runtime = runtime_preflight()
    chosen = support.check_model(model)
    tools = support.tool_identities(binary, tokenizer, clang, rustc)
    capacity_identity = file_identity(capacity)
    capacity_record = json.loads(Path(capacity).read_text())
    support.validate_capacity(capacity_record, tools=tools, model=chosen)
    selection = None
    if stage == "main":
        if calibration_result is None:
            raise ValueError("E_TOOLSTUDY_FRESH_QUALIFICATION_REQUIRED")
        qualified = json.loads(Path(calibration_result).read_text())
        selection = support.validate_qualification(qualified, tools=tools, model=chosen, capacity_sha256=capacity_identity["sha256"])
        selection["record"] = file_identity(calibration_result)
    elif calibration_result is not None:
        raise ValueError("E_TOOLSTUDY_NO_INHERITED_ELIGIBILITY")
    root = Path(output).absolute(); root.mkdir(parents=True, exist_ok=False)
    prompt_identity = support.prompt_bindings()
    plan = {"schema": cfg["schema"], "stage": stage, "protocol": cfg, "source_commit": head,
            "source_bindings": source, "prompt_bindings": prompt_identity, "model": chosen, "tools": tools,
            "capacity": capacity_identity, "selection": selection, "runtime_preflight": runtime,
            "model_requests_before_plan": 0, "human_answer_repairs": 0, "started_unix_ns": time.time_ns(),
            "execution_location": cfg["execution_location"], "performance_timing_qualified": False}
    support.snapshot(root, source); evaluator.save(root / "PLAN.json", plan)
    result = {"schema": cfg["schema"], "stage": stage, "source_commit": head, "source_bindings": source,
              "prompt_bindings": prompt_identity, "protocol_sha256": file_identity(support.HERE / "PROTOCOL.json")["sha256"],
              "model": chosen, "tools": tools, "capacity_sha256": capacity_identity["sha256"],
              "plan_sha256": file_identity(root / "PLAN.json")["sha256"], "selection": selection,
              "cells": [], "engines": [], "human_answer_repairs": 0, "status": "incomplete"}
    engine = None

    def close_engine():
        nonlocal engine
        if engine is None:
            return
        record = {"folder": str(engine.output), "requests": engine.generation_count, "responses": engine.response_count,
                  "preparations": engine.preparation_count, "service_calls": engine.service_calls}
        try:
            record["identity"] = engine.verify_final_identity()
        finally:
            before = time.monotonic_ns(); engine.close(); record["shutdown_ns"] = time.monotonic_ns()-before
            record["exited"] = engine.process.poll() is not None
            evaluator.save(engine.output / "SERVICE_CALLS.json", engine.service_calls)
            result["engines"].append(record); engine = None
        if not record["exited"] or not all(record["identity"][key] for key in ("model_unchanged", "runtime_unchanged")):
            raise RuntimeError("E_TOOLSTUDY_ENGINE_IDENTITY_OR_SHUTDOWN")

    try:
        for task, prompt_arm in support.cells(stage):
            cell_started = time.monotonic_ns()
            if support.bindings() != source:
                raise RuntimeError("E_TOOLSTUDY_SOURCE_DRIFT")
            language, interface = support.language_interface(prompt_arm)
            arm = language + "_" + interface
            ident = task["id"] + "_" + arm
            folder = root / ident; folder.mkdir()
            row = {"id": ident, "task": task["id"], "category": task["category"], "arm": arm,
                   "attempts": [], "correct": False, "hidden_evaluated": False, "status": "not_started"}
            result["cells"].append(row)
            session = support.session_for(task, prompt_arm, clang, rustc)
            captured_query = session.query()
            initial = prompts.prompt(task, prompt_arm, captured_query)
            key = stage + "/" + task["id"] + "/" + prompt_arm
            if (hashlib.sha256(initial.encode()).hexdigest() != prompt_identity[key]["prompt_sha256"]
                    or captured_query["query_sha256"] != prompt_identity[key]["query_sha256"]):
                raise RuntimeError("E_TOOLSTUDY_PROMPT_QUERY_DRIFT")
            evaluator.save(folder / "CAPTURED_QUERY.json", captured_query)
            if engine is None:
                before = time.monotonic_ns()
                engine = ToolStudyEngine(binary=binary, model=model, model_sha256=chosen["sha256"],
                                         output_dir=root / ("engine-" + str(len(result["engines"])).zfill(2)),
                                         threads=generation["threads"], context=generation["context_tokens"])
                entries = Path("/proc/" + str(engine.process.pid) + "/environ").read_bytes().split(b"\0")
                if b"LLAMA_ARG_REPACK=0" not in entries:
                    raise RuntimeError("E_TOOLSTUDY_RUNTIME_ENVIRONMENT")
                evaluator.save(engine.output / "STARTUP.json", {"wall_ns": time.monotonic_ns()-before})
            messages = prompts.messages(initial)
            for index in range(generation["attempts_per_cell"]):
                attempt = {"index": index, "usage": None, "actual_generation_requested": False, "status": "preparing"}
                row["attempts"].append(attempt)
                evaluator.save(folder / f"attempt-{index}.request.json", {"messages": messages, "captured_query_sha256": captured_query["query_sha256"]})
                before = time.monotonic_ns(); old_count = engine.generation_count
                try:
                    answer = engine.generate(messages, language=language, interface=interface,
                                             limit=generation["max_output_tokens"], wall_seconds=generation["wall_seconds"])
                    attempt.update(usage=answer["usage"], request_wall_ns=time.monotonic_ns()-before,
                                   actual_generation_requested=engine.generation_count > old_count)
                    evaluator.save(folder / f"attempt-{index}.response.json", answer)
                except Exception as exc:
                    attempt.update(request_wall_ns=time.monotonic_ns()-before,
                                   actual_generation_requested=engine.generation_count > old_count,
                                   error={"type": type(exc).__name__, "message": str(exc)},
                                   partial_usage=engine.last_usage_receipt,
                                   status="budget_failure" if isinstance(exc, budget.BudgetFailure) else "timeout" if isinstance(exc, TimeoutError) else "inference_failure")
                    row["status"] = attempt["status"]
                    evaluator.save(folder / f"attempt-{index}.evaluation.json", attempt)
                    if attempt["status"] == "timeout":
                        close_engine()
                    elif attempt["status"] != "budget_failure":
                        raise
                    break
                before = time.monotonic_ns()
                observed = validation.evaluate(task, language, interface, session, captured_query, answer["text"],
                                               folder / f"candidate-{index}", clang, rustc)
                attempt.update(validation_wall_ns=time.monotonic_ns()-before, evaluation=observed, status=observed["status"])
                row["status"] = attempt["status"]
                if observed["status"] == "infrastructure_failure":
                    evaluator.save(folder / f"attempt-{index}.evaluation.json", attempt)
                    raise RuntimeError("E_TOOLSTUDY_CANDIDATE_INFRASTRUCTURE")
                if observed["accepted"]:
                    before = time.monotonic_ns()
                    hidden = evaluator.execute(observed["build"], task, task["hidden_cases"], task["hidden_expected"])
                    evaluator.save(folder / "HIDDEN.json", hidden)
                    row.update(hidden_evaluated=True, hidden_wall_ns=time.monotonic_ns()-before,
                               correct=hidden["status"] == "correct" and hidden["artifact_unchanged"],
                               status="correct" if hidden["status"] == "correct" and hidden["artifact_unchanged"] else "hidden_failed")
                    evaluator.save(folder / f"attempt-{index}.evaluation.json", attempt)
                    # Hidden execution is terminal. No hidden observation can
                    # enter a subsequent request, including a failed gate.
                    break
                if index + 1 < generation["attempts_per_cell"]:
                    before = time.monotonic_ns()
                    try:
                        messages, receipt = budget.repair_messages(initial, answer["text"], observed["feedback"], engine.tokenize, cfg["history"])
                        evaluator.save(folder / f"attempt-{index}.repair-budget.json", receipt)
                    except budget.BudgetFailure as exc:
                        attempt["history_budget_failure"] = str(exc)
                        row["status"] = "budget_failure"
                    finally:
                        attempt["history_preparation_wall_ns"] = time.monotonic_ns()-before
                evaluator.save(folder / f"attempt-{index}.evaluation.json", attempt)
                if row["status"] == "budget_failure":
                    break
            row["cell_wall_ns"] = time.monotonic_ns()-cell_started
            evaluator.save(folder / "CELL.json", row)
            boundary = {"source_unchanged": support.bindings() == source,
                        "model_unchanged": file_identity(model) == chosen["file"],
                        "tools_unchanged": all(file_identity(value["path"]) == value for value in tools.values())}
            evaluator.save(folder / "BOUNDARY.json", boundary)
            if not all(boundary.values()):
                raise RuntimeError("E_TOOLSTUDY_BOUNDARY_IDENTITY")
            print(json.dumps({"stage": stage, "cell": ident, "correct": row["correct"], "status": row["status"], "attempts": len(row["attempts"])}), flush=True)
        result["status"] = "all_cells_attempted"
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        try:
            close_engine()
        except Exception as exc:
            result.update(status="incomplete", shutdown_error=str(exc))
        result["source_unchanged"] = support.bindings() == source
        result["tools_unchanged"] = all(file_identity(value["path"]) == value for value in tools.values())
        result["model_unchanged"] = file_identity(model) == chosen["file"]
        result["valid_observation"] = bool(result["status"] == "all_cells_attempted" and len(result["cells"]) == len(support.cells(stage))
                                           and all(result[key] for key in ("source_unchanged", "tools_unchanged", "model_unchanged")))
        attempts = [attempt for cell in result["cells"] for attempt in cell["attempts"]]
        known = [attempt["usage"] for attempt in attempts if attempt.get("usage")]
        partials = [attempt["partial_usage"] for attempt in attempts if attempt.get("partial_usage")]
        result["requests"] = sum(engine["requests"] for engine in result["engines"])
        result["responses"] = sum(engine["responses"] for engine in result["engines"])
        result["unknown_usage_requests"] = result["requests"]-result["responses"]
        result["known_input_tokens"] = sum(u["input_tokens"] for u in known) + sum(u["input_tokens"] for u in partials)
        result["known_output_tokens"] = sum(u["output_tokens"] for u in known)
        result["partial_output_token_lower_bound"] = sum(u["observed_output_token_lower_bound"] for u in partials)
        result["total_tokens"] = result["known_input_tokens"]+result["known_output_tokens"] if not result["unknown_usage_requests"] else None
        result["calibration_eligible"] = bool(stage == "calibration" and result["valid_observation"]
                                              and all(cell["correct"] for cell in result["cells"])
                                              and all(attempt.get("usage") is not None for attempt in attempts)
                                              and result["unknown_usage_requests"] == 0)
        result["first_submission_correct"] = sum(cell["correct"] and len(cell["attempts"]) == 1 for cell in result["cells"])
        result["validation_calls"] = sum("evaluation" in attempt for attempt in attempts)
        result["terminal_hidden_calls"] = sum(cell["hidden_evaluated"] for cell in result["cells"])
        if stage == "main":
            result["summary"] = summarize(result["cells"], selection)
            result["summary"]["descriptive_advantage_gate"] &= result["valid_observation"]
        result["experiment_wall_ns"] = time.monotonic_ns()-started
        evaluator.save(root / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("calibration", "main"))
    for name in ("output", "model", "binary", "tokenizer", "clang", "rustc", "capacity"):
        parser.add_argument("--"+name, required=True)
    parser.add_argument("--calibration-result")
    result = run(**vars(parser.parse_args()))
    print(json.dumps({key: result.get(key) for key in ("stage", "status", "calibration_eligible", "requests", "responses", "total_tokens")}))
    return 0 if result["valid_observation"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
