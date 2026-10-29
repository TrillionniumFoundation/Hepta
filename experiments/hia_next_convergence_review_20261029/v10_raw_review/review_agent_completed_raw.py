#!/usr/bin/env python3
"""Read-only reconciliation of one completed calibration with complete SSE usage.

This imports no experiment, model, tokenizer, compiler, evaluator, or test code.
It deliberately refuses incomplete/partial-usage studies instead of treating
unknown tokens as zero. Such studies need a separately scoped partial audit.
All source-result expectations and input locations are supplied explicitly.
"""
from pathlib import Path, PurePosixPath
import argparse
import collections
import datetime
import hashlib
import json
import os
import sys


READS = {}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def same(actual, expected, label):
    require(actual == expected, "mismatch: " + label)


def child(base, relative):
    part = PurePosixPath(relative)
    require(not part.is_absolute() and all(v not in ("", ".", "..") for v in part.parts), "unsafe relative path")
    result = base.joinpath(*part.parts)
    require(result.resolve().is_relative_to(base.resolve()), "path escaped evidence root")
    return result


def read(path):
    path = Path(path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(before.st_size <= 64 * 1024 * 1024, "audit member exceeds 64 MiB")
        data = stream.read(64 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    same((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "member changed during read")
    same(len(data), after.st_size, "member byte count")
    identity = {"path": str(path), "bytes": len(data), "sha256": sha(data)}
    if str(path) in READS:
        same(READS[str(path)], identity, "member changed between reads")
    READS[str(path)] = identity
    return data


def load(path):
    return json.loads(read(path))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def public_pass(record):
    return (record["status"] == "correct" and all(record[key] is True for key in
            ("native_executed", "artifact_unchanged", "resource_contract_passed", "vm_contract_passed")))


def audit(args):
    raw = Path(args.raw)
    result = load(raw / "RESULT.json")
    same(READS[str(raw / "RESULT.json")]["sha256"], args.result_sha256, "RESULT identity")
    plan, capacity, refusal = load(raw / "PLAN.json"), load(args.capacity), load(args.refusal)
    same(READS[str(raw / "PLAN.json")]["sha256"], result["plan_sha256"], "PLAN identity")
    same(READS[str(Path(args.capacity))]["sha256"], result["capacity_sha256"], "capacity identity")
    for record in (plan, result, capacity, refusal):
        same(record["source_commit"], args.source_commit, "frozen source commit")
        same(record["source_bindings"], result["source_bindings"], "source bindings")
    for relative, expected in result["source_bindings"].items():
        same(sha(read(child(raw / "source_snapshot", relative))), expected, "source snapshot " + relative)
    for key in ("model", "tools", "prompt_bindings"):
        same(result[key], plan[key], "plan " + key)
        same(result[key], capacity[key], "capacity " + key)
    same(result["protocol_sha256"], capacity["protocol_sha256"], "capacity protocol")
    protocol = load(child(raw / "source_snapshot", args.protocol_relative_path))
    same(READS[str(child(raw / "source_snapshot", args.protocol_relative_path))]["sha256"],
         result["protocol_sha256"], "source protocol digest")
    generation = protocol["generation"]
    context, reserve = generation["context_tokens"], generation["max_output_tokens"]
    for key in ("source_unchanged", "model_unchanged", "tools_unchanged", "valid_observation"):
        require(result[key] is True, "producer boundary: " + key)
    same(result["stage"], "calibration", "study stage")
    same(result["selection"], None, "no selected main model")
    same(result["unknown_usage_requests"], 0, "this audit supports complete usage only")
    same(result["partial_output_token_lower_bound"], 0, "partial usage requires separate audit")
    request_count = result["requests"]
    require(type(request_count) is int and request_count > 0, "nonempty complete study")
    same(result["responses"], request_count, "complete response count")
    same([c["task"] for c in result["cells"]], protocol["qualification"]["tasks"], "ordered qualification task registry")
    require(all(c["arm"] == protocol["qualification"]["arm"] for c in result["cells"]), "qualification arm registry")

    engine = raw / "engine-00"
    before, after = load(engine / "identity.json"), load(engine / "identity-after.json")
    same(before["model"], after["model"], "model identity before/after")
    same(before["runtime_files"], after["runtime_files"], "runtime identities before/after")
    require(after["model_unchanged"] is True and after["runtime_unchanged"] is True, "runtime boundary")
    same(result["model"]["file"], before["model"], "model-file binding")
    same(len(result["engines"]), 1, "complete single-engine profile")
    owned = result["engines"][0]
    require(owned["exited"] is True, "owned engine exited in producer receipt")
    for key in ("requests", "responses", "preparations"):
        same(owned[key], request_count, "engine " + key)
    same(owned["identity"], after, "engine final identity")
    service = load(engine / "SERVICE_CALLS.json")
    same(owned["service_calls"], service, "service request ledger")
    routes = collections.Counter(row["endpoint"] for row in service)
    require(set(routes).issubset({"/health", "/props", "/apply-template", "/tokenize"}), "unexpected unaccounted service endpoint")
    # Startup health failures are retained; they are not generation requests.
    require(all(row["success"] is True for row in service if row["endpoint"] != "/health"), "non-health service failure needs separate audit")
    outcomes = [{"endpoint": endpoint, "success": success, "calls": count}
                for (endpoint, success), count in collections.Counter((r["endpoint"], r["success"]) for r in service).items()]
    read(engine / "server.log")
    load(engine / "STARTUP.json")
    same(len(list(raw.glob("engine-*"))), 1, "actual engine directories")
    transports = sorted(engine.glob("transport-*.request.json"))
    same(len(transports), request_count, "actual transport request count")
    for suffix in ("response.json", "response.sse", "usage.json"):
        same(len(list(engine.glob("transport-*." + suffix))), request_count, "actual transport " + suffix)
    ordered = []
    for cell in result["cells"]:
        folder = child(raw, cell["id"])
        same(load(folder / "CELL.json"), cell, "per-cell result")
        boundary = load(folder / "BOUNDARY.json")
        require(all(boundary[key] is True for key in ("source_unchanged", "model_unchanged", "tools_unchanged")), "per-cell identity boundary")
        same([a["index"] for a in cell["attempts"]], list(range(len(cell["attempts"]))), "contiguous attempt indices")
        require(1 <= len(cell["attempts"]) <= generation["attempts_per_cell"], "registered attempt budget")
        ordered.extend((cell, attempt) for attempt in cell["attempts"])
    same(len(ordered), request_count, "attempt/transport count")

    rows = []
    by_task = collections.defaultdict(list)
    for number, ((cell, attempt), transport) in enumerate(zip(ordered, transports), 1):
        prefix = f"transport-{number:03d}"
        same(transport.name, prefix + ".request.json", "contiguous transport IDs")
        request = load(transport)
        response, usage = load(engine / (prefix + ".response.json")), load(engine / (prefix + ".usage.json"))
        preparation = load(engine / f"preparation-{number:03d}.json")
        sse = read(engine / (prefix + ".response.sse"))
        events = []
        for line in sse.decode().splitlines():
            if line.startswith("data:"):
                value = line[5:].strip()
                if value != "[DONE]":
                    events.append(json.loads(value))
        require(bool(events), "nonempty SSE")
        same(sum(event.get("stop") is True for event in events), 1, "single final SSE event")
        require(events[-1]["stop"] is True, "SSE terminal stop ordering")
        final = events[-1]
        text = "".join(event.get("content", "") for event in events)
        ids = [token for event in events for token in event.get("tokens", [])]
        prompt_ids = request["payload"]["prompt"]
        require(type(prompt_ids) is list and all(type(v) is int for v in prompt_ids), "actual integer prompt IDs")
        same(preparation["input_token_ids"], prompt_ids, "prepared/submitted IDs")
        same(preparation["messages"], request["messages"], "prepared/submitted messages")
        for value in (preparation["rendered_prompt"], response["prompt"], final["prompt"]):
            same(value, request["rendered_prompt"], "exact rendered prompt")
        require(preparation["actual_generation_submitted"] is True and preparation["fits"] is True, "actual prepared submission")
        same(preparation["reserved_output_tokens"], reserve, "output reservation")
        same(preparation["context"], context, "context budget")
        require(len(prompt_ids) + reserve <= context, "actual complete-request capacity")
        same(text, response["content"], "SSE/response text")
        same(ids, response["tokens"], "SSE/response IDs")
        same(ids, usage["observed_output_token_ids"], "SSE/usage IDs")
        for value in (response, final):
            same(value["tokens_evaluated"], len(prompt_ids), "prompt token count")
            same(value["tokens_predicted"], len(ids), "output token count")
            same(value["timings"]["prompt_n"], len(prompt_ids), "timing prompt count")
            same(value["timings"]["predicted_n"], len(ids), "timing output count")
            require(value["truncated"] is False, "truncated output needs separate audit")
            same(value["stop_type"], "eos", "complete EOS profile")
        same(usage["events"], len(events), "SSE event count")
        same(usage["response_bytes"], len(sse), "SSE byte count")
        for key, expected in (("input_tokens", len(prompt_ids)), ("output_tokens", len(ids)),
                              ("total_tokens", len(prompt_ids) + len(ids)), ("observed_output_token_lower_bound", len(ids))):
            same(usage[key], expected, "transport usage " + key)
        require(usage["complete"] is True and usage["unknown_output_tokens"] is False, "complete known usage")
        same(usage["error"], None, "transport usage error")
        same(usage["unknown_reason"], None, "transport unknown reason")
        folder, index = child(raw, cell["id"]), attempt["index"]
        per_request = load(folder / f"attempt-{index}.request.json")
        answer = load(folder / f"attempt-{index}.response.json")
        same(load(folder / f"attempt-{index}.evaluation.json"), attempt, "retained attempt")
        same(per_request["messages"], request["messages"], "attempt/transport messages")
        same(per_request["captured_query_sha256"], load(folder / "CAPTURED_QUERY.json")["query_sha256"], "original query binding")
        roles = [message["role"] for message in per_request["messages"]]
        if index == 0:
            same(roles, ["user"], "fresh task messages")
        else:
            same(roles, ["user", "assistant", "user"], "repair role ordering")
            same(per_request["messages"][0], load(folder / "attempt-0.request.json")["messages"][0], "unchanged initial request")
            same(per_request["messages"][1]["content"], load(folder / f"attempt-{index-1}.response.json")["text"], "full immediately previous answer")
            require(cell["attempts"][index-1]["evaluation"]["accepted"] is False, "no repair after public acceptance")
        same(answer["text"], text, "attempt/transport output")
        same(answer["input_token_ids"], prompt_ids, "attempt prompt IDs")
        same(answer["output_token_ids"], ids, "attempt output IDs")
        same(answer["usage"], attempt["usage"], "attempt usage record")
        for key, expected in (("input_tokens", len(prompt_ids)), ("output_tokens", len(ids)),
                              ("returned_token_ids", len(ids)), ("total_tokens", len(prompt_ids) + len(ids))):
            same(attempt["usage"][key], expected, "attempt usage " + key)
        require(attempt["actual_generation_requested"] is True and "partial_usage" not in attempt, "one complete actual generation")
        require(attempt["request_wall_ns"] >= usage["wall_ns"] >= 0, "nested request duration")
        evaluation = attempt["evaluation"]
        same(load(folder / f"candidate-{index}/STUDY_EVALUATION.json"), evaluation, "candidate evaluation")
        if evaluation.get("accepted") is True:
            same(evaluation["status"], "correct", "public accepted status")
            require(evaluation["build"]["status"] == "compiled" and evaluation["build"]["native_built"] is True, "accepted build gate")
            require(public_pass(evaluation["public"]), "accepted public gate chain")
            same(index, len(cell["attempts"]) - 1, "public acceptance terminates requests")
        else:
            require(evaluation["hidden_evaluated"] is False, "failed public submission has no hidden evaluation")
        row = {"transport": number, "task": cell["task"], "attempt": index,
               "input_tokens": len(prompt_ids), "output_tokens": len(ids), "text_bytes": len(text.encode()),
               "text_sha256": sha(text.encode()), "sse_sha256": sha(sse), "sse_events": len(events),
               "complete": True, "status": attempt["status"], "accepted": evaluation.get("accepted") is True,
               "error_category": (evaluation.get("error") or {}).get("message"),
               "build_status": (evaluation.get("build") or {}).get("status"),
               "public_native_executed": (evaluation.get("public") or {}).get("native_executed") is True,
               "transport_wall_ns": usage["wall_ns"], "generation_wrapper_wall_ns": attempt["request_wall_ns"],
               "messages_sha256": sha(canonical(request["messages"])), "prompt_ids_sha256": sha(canonical(prompt_ids)),
               "output_ids_sha256": sha(canonical(ids))}
        rows.append(row)
        by_task[cell["task"]].append(row)

    totals = {"requests": len(rows), "input_tokens": sum(r["input_tokens"] for r in rows),
              "output_tokens": sum(r["output_tokens"] for r in rows)}
    totals["total_tokens"] = totals["input_tokens"] + totals["output_tokens"]
    for key, field in (("input_tokens", "known_input_tokens"), ("output_tokens", "known_output_tokens"), ("total_tokens", "total_tokens")):
        same(totals[key], result[field], "result " + field)
    transport_ns = sum(row["transport_wall_ns"] for row in rows)
    generate_ns = sum(row["generation_wrapper_wall_ns"] for row in rows)
    require(result["experiment_wall_ns"] >= generate_ns >= transport_ns, "nested run/request/transport durations")
    hidden_count, hidden_correct = 0, 0
    for cell in result["cells"]:
        hidden_file = child(raw, cell["id"]) / "HIDDEN.json"
        if cell["hidden_evaluated"]:
            hidden = load(hidden_file)
            require(cell["attempts"][-1]["evaluation"]["accepted"] is True, "hidden requires terminal accepted public gate")
            correct = hidden["status"] == "correct" and hidden["artifact_unchanged"]
            same(cell["correct"], correct, "cell/hidden result")
            if correct:
                require(public_pass(hidden), "successful hidden gate chain")
                hidden_correct += 1
            hidden_count += 1
        else:
            require(not hidden_file.exists(), "no hidden evidence for unexecuted cell")
            require(cell["correct"] is False, "cell cannot pass without hidden gate")
    same(result["terminal_hidden_calls"], hidden_count, "terminal hidden count")
    same(result["validation_calls"], len(ordered), "public validation count")
    correct_tasks = sum(cell["correct"] for cell in result["cells"])
    same(correct_tasks, hidden_correct, "correct task count")
    first_correct = sum(cell["correct"] and len(cell["attempts"]) == 1 for cell in result["cells"])
    same(result["first_submission_correct"], first_correct, "first-submission correct count")
    same(result["calibration_eligible"], all(cell["correct"] for cell in result["cells"]), "calibration qualification gate")
    # This profile requires an actual rejected main receipt; never infer it
    # merely from qualification failure or from absence of a main directory.
    require(result["calibration_eligible"] is False, "qualified main study requires separate audit")
    same(refusal["returncode"], 1, "actual main rejection returncode")
    same(refusal["model_requests"], 0, "main model requests")
    same(refusal["main_cells_started"], 0, "main cells")
    require(refusal["gate_rejected_before_engine_construction"] is True and refusal["main_output_directory_created"] is False, "actual main refusal boundary")
    require("E_TOOLSTUDY_NO_QUALIFIED_MODEL" in refusal["stderr"], "actual main refusal diagnostic")
    same(refusal["qualification"]["sha256"], args.result_sha256, "main qualification digest")
    same(refusal["capacity"]["sha256"], result["capacity_sha256"], "main capacity digest")
    same(len(capacity["rows"]), 19, "registered human-reference controls")
    require(capacity["complete"] is True and capacity["model_requests"] == 0, "capacity is complete controls only")
    for row in capacity["rows"]:
        require(all(row[key] is True for key in ("passed", "capacity_passed", "reference_passed_all_gates",
                    "template_exact_match", "tokenizer_ids_match", "actual_complete_requests_always_rechecked")), "capacity control gates")
    capstats = {key: max(row[key] for row in capacity["rows"]) for key in
                ("initial_input_tokens", "complete_reference_output_tokens", "max_observed_repair_plus_output_reserve", "allocated_worst_repair_plus_output_reserve")}
    require(capstats["complete_reference_output_tokens"] <= reserve and
            capstats["max_observed_repair_plus_output_reserve"] <= context and
            capstats["allocated_worst_repair_plus_output_reserve"] <= context, "measured capacity envelopes")
    duplicate_groups = []
    for task, task_rows in by_task.items():
        counts = collections.Counter(row["text_sha256"] for row in task_rows)
        duplicate_groups.append({"task": task, "attempts": len(task_rows), "distinct_texts": len(counts),
                                 "repeated_texts": [{"sha256": digest, "occurrences": count} for digest, count in counts.items() if count > 1],
                                 "observed_error_categories": sorted({row["error_category"] for row in task_rows if row["error_category"]})})
    return {"schema": "hepta.agent.completed-calibration.independent-raw-accounting-review.v1",
            "completed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source_commit": args.source_commit, "result_sha256": args.result_sha256,
            "review_script_sha256": sha(Path(__file__).read_bytes()), "input_arguments": vars(args), "passed_checks": True,
            "totals": totals, "transport_wall_ns": transport_ns, "generation_wrapper_wall_ns": generate_ns,
            "experiment_wall_ns": result["experiment_wall_ns"], "capacity_reference_wall_ns": capacity["experiment_wall_ns"],
            "main_refusal_wall_ns": refusal["wall_ns"],
            "sum_three_recorded_phase_wall_ns": result["experiment_wall_ns"] + capacity["experiment_wall_ns"] + refusal["wall_ns"],
            "phase_sum_is_not_total_project_or_outer_process_cost": True,
            "rows": rows, "task_output_groups": duplicate_groups, "correct_tasks": correct_tasks,
            "qualification_tasks": len(result["cells"]), "first_submission_correct": first_correct,
            "calibration_eligible": False, "public_native_execution_count": sum(r["public_native_executed"] for r in rows),
            "terminal_hidden_execution_count": hidden_count, "main_cells_started": 0, "main_requests": 0,
            "HIA_model_cells": sum(c["arm"].startswith("hia_") for c in result["cells"]),
            "source_snapshot_files_rehashed": len(result["source_bindings"]),
            "source_model_tools_boundaries_all_true": True, "retained_model_and_runtime_identities_before_after_equal": True,
            "runtime_companion_records": len(before["runtime_files"]),
            "owned_server_exited_in_retained_shutdown_record": owned["exited"],
            "service_call_routes": dict(routes), "service_call_outcomes": outcomes,
            "capacity_summary_rechecked": capstats, "actual_request_context_tokens": context, "output_reserve_tokens": reserve,
            "no_hidden_feedback_repair_evidence": {"hidden_files": hidden_count, "hidden_acceptance_is_terminal_in_each_cell": True,
                "failed_cells_hidden_files": 0, "next_task_resets_messages": True,
                "scope": "Retained ordered messages/public acceptance/terminal hidden call flow; no evaluator replay."},
            "read_only_limits": [
                "Only retained JSON/SSE/source bytes are read and hashed with the standard library. No model, tokenizer, compiler, native executable, solver, test, or experiment runner is invoked.",
                "Prompt/output IDs match retained preparation, actual payload, SSE, response and usage ledgers. No independent text-to-vocabulary tokenization is rerun.",
                "Source snapshot hashes match all recorded bindings. Git commit attribution and method review remain distinct checks; these records are not rewritten.",
                "Model/runtime stability and server exit are compared producer records, not independent historical process observations or a new multi-gigabyte weights digest.",
                "Only completed calibration with one engine, complete EOS usage, and an actual main-refusal receipt is supported by this audit profile. Partial/timeout or qualified-main cases fail closed for separate review.",
                "Failure categories and repeated outputs are reported as observed. No repaired answer, counterfactual language ability, or hidden-feedback inference is manufactured.",
                "Wall clocks are retained producer observations. Nested transport/request/run durations must not be added; the three disjoint recorded phases exclude human labor and other historical costs.",
                "Reference controls do not count as model success. Failed Rust calibration and main refusal provide no between-language Agent productivity comparison."
            ], "new_native_model_tokenizer_compiler_solver_test_runs": 0,
            "scientific_acceptance_gates_changed": False, "authority": "DENY_ALL"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("raw", "capacity", "refusal", "source-commit", "result-sha256", "protocol-relative-path", "output"):
        parser.add_argument("--" + option, required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    try:
        report = audit(args)
    except Exception as error:
        failure = {"schema": "hepta.agent.completed-calibration.review-failure.v1", "passed_checks": False,
                   "review_script_sha256": sha(Path(__file__).read_bytes()), "input_arguments": vars(args),
                   "error_type": type(error).__name__, "error": str(error),
                   "scope": "Audit did not complete. No successful producer-outcome conclusion follows from this file."}
        (output / "REVIEW_ERROR.json").write_text(json.dumps(failure, indent=2) + "\n")
        raise
    finally:
        (output / "READ_FILES.json").write_text(json.dumps({"schema": "hepta.agent.review-read-files.v1", "files": list(READS.values())}, indent=2) + "\n")
    (output / "REVIEW.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: report[key] for key in ("passed_checks", "totals", "transport_wall_ns", "generation_wrapper_wall_ns",
        "experiment_wall_ns", "capacity_reference_wall_ns", "main_refusal_wall_ns", "sum_three_recorded_phase_wall_ns",
        "correct_tasks", "public_native_execution_count", "terminal_hidden_execution_count", "source_snapshot_files_rehashed")}, indent=2))


if __name__ == "__main__":
    main()
