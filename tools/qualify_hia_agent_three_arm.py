#!/usr/bin/env python3
"""Portable, prospective Codex replication of the three-representation study.

This does not rescore the frozen local-model experiment. Its task provenance is
explicit: four authored two-file maintenance/upgrade tasks, not sampled issues
from production projects. Author controls never count as model completions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.hia_agent_assembly_v4_20261030 import evaluator, fixtures
from tools.hia_agent_codex_transport import (
    CodexEvents, EventFailure, canonical, checked_usage, identity, protocol as transport_protocol,
    recover_reported_usage, run_owned, save,
)

SCHEMA = "hepta.hia.agent-three-arm-codex.v1"
ARMS = ("hia", "assembly", "rust")
TERMINAL_CODING = {"correct", "public_validation_failed", "hidden_validation_failed"}


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def protocol():
    return {
        "schema": SCHEMA, "requested_model": "gpt-6.1-sol", "arms": list(ARMS),
        "tasks": [t["id"] for t in fixtures.make_fixtures()],
        "task_provenance": "reused authored v4 tasks; two maintenance and two API upgrades; no production issue sampling",
        "arm_meanings": {"hia": "JSON HIA", "assembly": "compact HIA", "rust": "safe scalar Rust"},
        "attempts_per_cell": 2, "request_wall_seconds": 180,
        "max_reported_input_tokens": 20000, "max_conservative_output_tokens": 6000,
        "max_conservative_tokens_per_cell": 52000,
        "token_limits": "post-response limits, not claimed hard provider generation caps; unknown usage blocks readout",
        "token_accounting": "retain all five provider counters; input+output+reasoning is a conservative sum, not independently attested billing",
        "generation": "fresh ephemeral CLI for every attempt; complete public conversation; no CLI tool use; no constrained decoder",
        "feedback": "one correction from compile/public feedback; hidden tests run once and never enter a prompt",
        "schedule": "rotate (JSON HIA, compact HIA, Rust) by task index modulo three",
        "context": "same task semantics, starting two-file project, public tests and budgets; representation documentation differs",
        "provider_limitations": "weights, provider system context, cache, scheduling and actual routing are not independently attested",
        "human_review": "unknown unless separately measured by a human; model/operator elapsed time is not human labor",
        "gate": "complete exact coverage and usage required; descriptive compact advantage requires 4/4 correct deliveries, no more attempts, and lower conservative tokens and complete cell time; human-cost advantage additionally requires measured review cost",
    }


def prompt(task, arm):
    text = fixtures.prompt(task, arm).replace(
        "The decoder constrains only envelope, filenames and content types; it supplies no solution.",
        "The host validates the files envelope after generation; no constrained decoder or answer completion is applied.")
    return ("Do not use tools, inspect files, or browse. Only the provided public workspace is task context. "
            "Follow all higher-priority rules. Return one JSON object, without Markdown.\n" + text)


def schedule():
    rows = []
    for index, task in enumerate(fixtures.make_fixtures()):
        for arm in ARMS[index % 3:] + ARMS[:index % 3]:
            rows.append({"id": task["id"] + "_" + arm, "task": task["id"],
                         "stratum": task["stratum"], "language": arm})
    return rows


def source_bindings():
    # Bind the implementation inventory, not just modules imported so far.
    patterns = ("hepta/*.py", "tools/*.py", "tools/provider_adapter/*.py",
                "experiments/hia_agent_assembly_v4_20261030/*.py",
                "experiments/hia_agent_matched_v3_20261028/*.py",
                "experiments/hia_optimizer_eval/next_20261028/*.py")
    paths = {p for pattern in patterns for p in ROOT.glob(pattern)}
    paths.add(ROOT / "benchmarks/hia_agent_public_tools/PROTOCOL.json")
    return {str(p.relative_to(ROOT)): identity(p)["sha256"] for p in sorted(paths)}


def bindings_unchanged(bindings):
    return all((ROOT / name).is_file() and identity(ROOT / name)["sha256"] == sha
               for name, sha in bindings.items())


def tool_bindings(codex, clang, rustc):
    return {name: identity(path) for name, path in (("codex", codex), ("clang", clang),
                                                  ("rustc", rustc), ("python", sys.executable))}


def validate_registration(folder):
    folder = Path(folder)
    value = read(folder / "REGISTRATION.json")
    tasks = fixtures.make_fixtures()
    if (value.get("schema") != SCHEMA or value.get("protocol") != protocol()
            or value.get("schedule") != schedule() or value.get("fixtures_sha256") != digest(tasks)
            or value.get("prompts") != {t["id"] + ":" + a: digest(prompt(t, a)) for t in tasks for a in ARMS}
            or value.get("sources") != source_bindings()
            or value["tools"].get("python") != identity(sys.executable)
            or not all(identity(v["path"]) == v for v in value["tools"].values())
            or identity(folder / "controls/CONTROLS.json")["sha256"] != value["controls_sha256"]):
        raise ValueError("E_THREE_ARM_REGISTRATION_DRIFT")
    controls = read(folder / "controls/CONTROLS.json")
    if controls.get("count") != 36 or controls.get("passed") != 36 or controls.get("model_answers") is not False:
        raise ValueError("E_THREE_ARM_CONTROLS")
    return value


def prepare(output, codex, clang, rustc):
    started = time.monotonic_ns()
    folder = Path(output).absolute()
    folder.mkdir(parents=True, exist_ok=False)
    sources = source_bindings()
    tools = tool_bindings(codex, clang, rustc)
    tasks = fixtures.make_fixtures()
    save(folder / "PLAN.json", {"schema": SCHEMA, "protocol": protocol(), "schedule": schedule(),
                               "sources": sources, "tools": tools, "model_requests_before_plan": 0})
    try:
        controls = evaluator.reference_controls(tasks, folder / "controls", clang, rustc)
        if (controls["passed"] != 36 or controls["count"] != 36 or not bindings_unchanged(sources)
                or tools != tool_bindings(codex, clang, rustc)):
            raise RuntimeError("E_THREE_ARM_CONTROL_OR_IDENTITY_FAILURE")
    except Exception as error:
        save(folder / "PREPARATION_FAILURE.json", {"schema": SCHEMA, "status": "blocked_before_registration",
             "error": {"type": type(error).__name__, "message": str(error)},
             "preparation_wall_ns": time.monotonic_ns() - started, "benchmark_model_requests": 0,
             "controls_are_model_successes": False})
        raise
    value = {"schema": SCHEMA, "protocol": protocol(), "schedule": schedule(),
             "sources": sources, "tools": tools, "fixtures_sha256": digest(tasks),
             "prompts": {t["id"] + ":" + a: digest(prompt(t, a)) for t in tasks for a in ARMS},
             "controls_sha256": identity(folder / "controls/CONTROLS.json")["sha256"],
             "created_unix_ns": time.time_ns(), "preparation_wall_ns": time.monotonic_ns() - started,
             "benchmark_model_requests": 0, "human_review_time_ns": None,
             "compiler_runtime_dependencies_independently_attested": False}
    save(folder / "REGISTRATION.json", value)
    return value


def conservative_tokens(usage):
    return usage["input_tokens"] + usage["output_tokens"] + usage["reasoning_output_tokens"]


def request(messages, output, registration):
    cfg = registration["protocol"]
    events = CodexEvents(transport_protocol()["registered_startup_warnings"])
    work = Path(tempfile.mkdtemp(prefix="hepta-three-arm-"))
    state, logs = work / "state", work / "logs"
    state.mkdir(); logs.mkdir()
    argv = [registration["tools"]["codex"]["path"], "exec", "--json", "--ephemeral", "--sandbox", "read-only",
            "--skip-git-repo-check", "-c", "sqlite_home=" + json.dumps(str(state)),
            "-c", "log_dir=" + json.dumps(str(logs)), "-m", cfg["requested_model"], "-"]
    process = run_owned(argv, work, output, input_bytes=canonical({"messages": messages}),
                        wall_seconds=cfg["request_wall_seconds"], on_line=events.line)
    result = {"process": process, "usage": events.usage or recover_reported_usage(Path(output) / "stdout.raw"),
              "status": "infrastructure_failure", "text": None}
    if process["status"] == "exited" and process["cleanup_confirmed"]:
        try:
            completed = events.complete()
            result.update(status="completed", **completed)
        except EventFailure as error:
            result["error"] = str(error)
    if result["usage"] is not None:
        result["conservative_tokens"] = conservative_tokens(result["usage"])
    save(Path(output) / "RESPONSE.json", result)
    return result


def run_cell(cell, task, folder, registration):
    started = time.monotonic_ns()
    folder = Path(folder); folder.mkdir(parents=True, exist_ok=False)
    cfg, tools = registration["protocol"], registration["tools"]
    row = {**cell, "status": "not_started", "correct": None, "attempts": [],
           "human_review_time_ns": None, "human_answer_edits": 0}
    messages = [{"role": "user", "content": prompt(task, cell["language"])}]
    for attempt in range(cfg["attempts_per_cell"]):
        if not bindings_unchanged(registration["sources"]) or not all(identity(v["path"]) == v for v in tools.values()):
            row["status"] = "identity_drift"
            break
        response = request(messages, folder / ("request-" + str(attempt)), registration)
        item = {"index": attempt, "status": response["status"], "usage": response["usage"],
                "request_wall_ns": response["process"]["wall_ns"], "conservative_tokens": response.get("conservative_tokens")}
        row["attempts"].append(item)
        if response["status"] != "completed" or response["usage"] is None:
            row["status"] = "provider_or_transport_blocked"
            break
        usage = response["usage"]
        if (usage["input_tokens"] > cfg["max_reported_input_tokens"]
                or usage["output_tokens"] + usage["reasoning_output_tokens"] > cfg["max_conservative_output_tokens"]
                or sum(a["conservative_tokens"] for a in row["attempts"]) > cfg["max_conservative_tokens_per_cell"]):
            row["status"] = "reported_token_budget_exceeded"
            break
        evaluation_started = time.monotonic_ns()
        try:
            built = evaluator.build(task, cell["language"], response["text"], folder / ("build-" + str(attempt)),
                                    tools["clang"]["path"], tools["rustc"]["path"])
            if built["status"] == "infrastructure_failure":
                raise RuntimeError("native compiler or artifact infrastructure failed")
            public = evaluator.execute(built, task, task["public_cases"], task["public_expected"]) if built["native_built"] else None
            save(folder / ("public-" + str(attempt) + ".json"), {"build": built, "execution": public})
            if public is not None and public.get("artifact_unchanged") is not True:
                raise RuntimeError("public native artifact identity changed")
            item["status"] = "public_passed" if public and public["status"] == "correct" and public["artifact_unchanged"] else "public_failed"
            if item["status"] == "public_passed":
                hidden = evaluator.execute(built, task, task["hidden_cases"], task["hidden_expected"])
                save(folder / "HIDDEN.json", hidden)
                if hidden.get("artifact_unchanged") is not True:
                    raise RuntimeError("hidden native artifact identity changed")
                row["correct"] = hidden["status"] == "correct" and hidden["artifact_unchanged"]
                row["status"] = "correct" if row["correct"] else "hidden_validation_failed"
                break
            row.update(correct=False, status="public_validation_failed")
            if attempt + 1 < cfg["attempts_per_cell"]:
                messages += [{"role": "assistant", "content": response["text"]},
                             {"role": "user", "content": "One allowed correction using only this public feedback. Return both complete files.\n" + canonical(evaluator.feedback(built, public)).decode()}]
        except Exception as error:
            row.update(status="native_infrastructure_failure", correct=None,
                       error={"type": type(error).__name__, "message": str(error)})
            break
        finally:
            item["evaluation_wall_ns"] = time.monotonic_ns() - evaluation_started
    row["identities_unchanged"] = bindings_unchanged(registration["sources"]) and all(identity(v["path"]) == v for v in tools.values())
    row["usage_complete"] = bool(row["attempts"]) and all(a["usage"] is not None for a in row["attempts"])
    row["known_conservative_tokens"] = sum(a["conservative_tokens"] or 0 for a in row["attempts"])
    row["conservative_tokens"] = row["known_conservative_tokens"] if row["usage_complete"] else None
    row["repair_rounds"] = max(0, len(row["attempts"]) - 1)
    row["cell_wall_ns"] = time.monotonic_ns() - started
    save(folder / "CELL.json", row)
    return row


def valid_observation(row):
    """Unknown, inconsistent or truncated cell accounting cannot admit a gate."""
    try:
        attempts = row["attempts"]
        usages = [checked_usage(a["usage"]) for a in attempts]
        totals = [conservative_tokens(u) for u in usages]
        cfg = protocol()
        statuses = [a["status"] for a in attempts]
        terminal = (statuses == ["public_failed"] * cfg["attempts_per_cell"]
                    if row["status"] == "public_validation_failed"
                    else bool(statuses) and statuses[-1] == "public_passed"
                         and all(s == "public_failed" for s in statuses[:-1]))
        return bool(row["status"] in TERMINAL_CODING and type(row["correct"]) is bool
                    and (row["status"] == "correct") == row["correct"]
                    and terminal
                    and row["usage_complete"] is True and row["identities_unchanged"] is True
                    and 1 <= len(attempts) <= cfg["attempts_per_cell"]
                    and all(u["input_tokens"] <= cfg["max_reported_input_tokens"]
                            and u["output_tokens"] + u["reasoning_output_tokens"] <= cfg["max_conservative_output_tokens"]
                            for u in usages)
                    and sum(totals) <= cfg["max_conservative_tokens_per_cell"]
                    and [a["index"] for a in attempts] == list(range(len(attempts)))
                    and [a["conservative_tokens"] for a in attempts] == totals
                    and row["known_conservative_tokens"] == row["conservative_tokens"] == sum(totals)
                    and row["repair_rounds"] == len(attempts) - 1
                    and type(row["cell_wall_ns"]) is int and row["cell_wall_ns"] >= 0)
    except (ValueError, KeyError, TypeError):
        return False


def summarize(cells, planned=None):
    planned = schedule() if planned is None else planned
    descriptor = lambda r: tuple(r.get(k) for k in ("id", "task", "stratum", "language"))
    wanted, actual = [descriptor(r) for r in planned], [descriptor(r) for r in cells]
    exact = bool(planned == schedule() and len(actual) == len(set(actual)) and set(actual) == set(wanted))
    eligible = exact and all(valid_observation(r) for r in cells)
    groups = {}
    for arm in ARMS:
        rows = [r for r in cells if r["language"] == arm]
        observed = [r for r in rows if valid_observation(r)]
        groups[arm] = {"planned_cells": 4, "attempted_cells": len(rows), "scored_cells": len(observed),
                       "correct_deliveries": sum(r["correct"] for r in observed),
                       "delivery_rate": sum(r["correct"] for r in observed) / len(observed) if observed else None,
                       "cohort_delivery_rate": sum(r["correct"] for r in observed) / 4 if eligible else None,
                       "requests": sum(len(r["attempts"]) for r in rows), "repair_rounds": sum(r["repair_rounds"] for r in rows),
                       "known_conservative_tokens": sum(r["known_conservative_tokens"] for r in rows),
                       "conservative_tokens": sum(r["conservative_tokens"] for r in rows) if eligible else None,
                       "cell_wall_ns": sum(r["cell_wall_ns"] for r in rows), "human_review_time_ns": None}
    compact = groups["assembly"]
    comparisons = {}
    for other in ("hia", "rust"):
        comparator = groups[other]
        comparisons[other] = bool(eligible and compact["correct_deliveries"] == 4
                                  and compact["requests"] <= comparator["requests"]
                                  and compact["conservative_tokens"] < comparator["conservative_tokens"]
                                  and compact["cell_wall_ns"] < comparator["cell_wall_ns"])
    return {"exact_coverage": exact, "eligible_comparison": eligible, "groups": groups,
            "descriptive_compact_advantage": comparisons, "human_cost_advantage_qualified": False,
            "general_agent_productivity_proved": False, "production_project_coverage": False,
            "missing_or_blocked_cells_count_as_coding_failures": False}


def run(prepared, preflight_evidence=None):
    started = time.monotonic_ns()
    prepared = Path(prepared).absolute()
    registration = validate_registration(prepared)
    folder = prepared / "execution"; folder.mkdir(exist_ok=False)
    result = {"schema": SCHEMA, "registration_sha256": identity(prepared / "REGISTRATION.json")["sha256"],
              "cells": [], "status": "starting", "human_review_time_ns": None}
    save(folder / "PLAN.json", {"registration": registration, "model_requests_before_plan": 0})
    if preflight_evidence is not None:
        preflight = read(preflight_evidence)
        # A supplied non-success is a stop receipt, never an eligibility token.
        if preflight.get("process_status") == "exited":
            raise ValueError("E_THREE_ARM_PREFLIGHT_IS_NOT_AUTHORITY: omit successful receipts and execute the registered cohort")
        result.update(status="blocked_before_benchmark", preflight=preflight,
                      preflight_evidence=identity(preflight_evidence), benchmark_model_requests=0)
    else:
        tasks = {t["id"]: t for t in fixtures.make_fixtures()}
        for cell in registration["schedule"]:
            row = run_cell(cell, tasks[cell["task"]], folder / cell["id"], registration)
            result["cells"].append(row)
            if row["status"] not in TERMINAL_CODING or not row["identities_unchanged"]:
                result["status"] = "blocked_or_invalid_cohort"
                break
        else:
            result["status"] = "all_cells_attempted"
        result["benchmark_model_requests"] = sum(len(r["attempts"]) for r in result["cells"])
    result["summary"] = summarize(result["cells"])
    result["execution_wall_ns"] = time.monotonic_ns() - started
    result["preparation_wall_ns"] = registration["preparation_wall_ns"]
    result["external_preflight_wall_ns"] = result.get("preflight", {}).get("wall_ns")
    result["unrun_cells"] = [c for c in registration["schedule"] if c["id"] not in {r["id"] for r in result["cells"]}]
    save(folder / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    p = commands.add_parser("prepare")
    for name in ("output", "codex", "clang", "rustc"):
        p.add_argument("--" + name, required=True)
    r = commands.add_parser("run")
    r.add_argument("--prepared", required=True); r.add_argument("--preflight-evidence")
    args = vars(parser.parse_args()); action = args.pop("action")
    result = {"prepare": prepare, "run": run}[action](**args)
    print(json.dumps({"action": action, "status": result.get("status", "registered"),
                      "benchmark_model_requests": result.get("benchmark_model_requests", 0)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
