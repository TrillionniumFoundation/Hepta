#!/usr/bin/env python3
"""Fresh maintenance author controls, provider preflight and registered live run.

--preflight-only invokes no model. --run requires an exact prior registration
commit and an actual provider executable; raw streams and usage are retained.
A missing provider is blocked, never replaced with old or authored answers.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PROTOCOL_PATH = ROOT / "benchmarks/hia_agent_maintenance/PROTOCOL.json"
TASK_PATH = ROOT / "benchmarks/hia_agent_maintenance/tasks.py"
spec = importlib.util.spec_from_file_location("fresh_hia_maintenance_tasks", TASK_PATH)
TASK_MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TASK_MODULE)

from hepta.hia_agent_context import focused_context, measure_payloads
from hepta.hia_opcodes import opcode_catalog
from hepta.hia_program import verify_program
from hepta.hia_program_tools import MAX_INPUT_BYTES, apply_program_patch, bounded_json_wire, decode_json
from tools.hia_agent_codex_transport import (CodexEvents, EventFailure, identity,
                                            recover_reported_usage, run_owned)


def wire(value):
    return bounded_json_wire(value, MAX_INPUT_BYTES, ensure_ascii=False)


def save(path, value):
    with Path(path).open("xb") as output:
        output.write(wire(value) + b"\n")


def source_paths():
    return sorted(set((ROOT / "hepta").glob("*.py")) | {
        Path(__file__), PROTOCOL_PATH, TASK_PATH, ROOT / "tools/hia_agent_context.py",
        ROOT / "tools/hia_agent_codex_transport.py",
        ROOT / "tests/test_hia_agent_context.py", ROOT / "tests/test_hia_agent_maintenance.py"})


def bindings(registration_commit=None):
    if registration_commit is not None:
        if re.fullmatch(r"[0-9a-f]{40}", registration_commit) is None:
            raise ValueError("registration requires an exact 40-character commit")
        subprocess.run(["git", "merge-base", "--is-ancestor", registration_commit, "HEAD"],
                       cwd=ROOT, check=True, capture_output=True)
    result = {}
    for path in source_paths():
        name = str(path.relative_to(ROOT))
        actual = path.read_bytes()
        if registration_commit is not None:
            committed = subprocess.check_output(["git", "show", registration_commit + ":" + name], cwd=ROOT)
            if committed != actual:
                raise ValueError("registered source differs: " + name)
        result[name] = sha256(actual).hexdigest()
    return result


def provider_preflight(command=None):
    """Check only an explicit executable or PATH; do not inspect credentials."""
    requested = "codex" if command is None else command
    if type(requested) is not str or not requested:
        raise ValueError("provider executable must be nonempty text")
    found = shutil.which(requested)
    identity = None
    if found is not None:
        path = Path(found).resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            found = None
        else:
            digest = sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            identity = {"path": str(path), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}
    return {"requested_executable": requested, "provider_executable_available": found is not None,
            "executable_identity": identity, "executable_invoked": False,
            "provider_connectivity_verified": False, "credentials_inspected": False,
            "model_requests": 0,
            "scope": "executable inventory only; not inference authentication or availability"}


def execute_contract(candidate, task, arguments):
    """Observe original VM operations for these fresh task cases only."""
    from hepta.hia_program_runtime import _Machine, _underlying, execute_program
    events = []
    original = _Machine.operation

    def observe(machine, instruction, environment, depth):
        kind = instruction["op"]
        actual = [environment[name] for name in instruction["args"]]
        ident = (_underlying(actual[0]).ident
                 if kind in {"buffer.store", "buffer.load", "owner.drop"} else None)
        original(machine, instruction, environment, depth)
        if kind in {"buffer.new", "buffer.try_new"}:
            owner = environment[instruction["out"][0]["name"]]
            events.append({"op": "allocate", "owner": owner.ident, "size": len(owner.data),
                           "zeroed": not any(owner.data)})
        elif kind == "buffer.store":
            events.append({"op": "store", "owner": ident, "index": actual[1], "value": actual[2]})
        elif kind == "buffer.load":
            events.append({"op": "load", "owner": ident, "index": actual[1],
                           "value": environment[instruction["out"][0]["name"]]})
        elif kind == "owner.drop":
            events.append({"op": "drop", "owner": ident})

    with patch.object(_Machine, "operation", observe):
        report = execute_program(candidate, "target", arguments, max_steps=10000,
                                 max_heap_bytes=65536, max_call_depth=32)
    expected = TASK_MODULE.oracle(task["id"], *arguments)
    if report["result"] != expected:
        raise ValueError("fresh independent task oracle disagrees with actual VM result")
    resources = report["resources"]
    if resources["live_owners"] or resources["live_local_loans"]:
        raise ValueError("actual execution left local owners/loans")
    if task["resource_witness"]:
        x, y = arguments
        size, value = x % 7 + 1, (x + y) % 256
        position = y % size
        allocations = [(index, row) for index, row in enumerate(events) if row["op"] == "allocate"]
        drops = [(index, row) for index, row in enumerate(events) if row["op"] == "drop"]
        if (resources["allocations"] != 1 or resources["frees"] != 1
                or len(allocations) != 1 or len(drops) != 1):
            raise ValueError("exactly one real allocation and release required")
        ai, allocation = allocations[0]
        di, drop = drops[0]
        owner = allocation["owner"]
        writes = [index for index, row in enumerate(events)
                  if row == {"op": "store", "owner": owner, "index": position, "value": value}]
        reads = [index for index, row in enumerate(events)
                 if row == {"op": "load", "owner": owner, "index": position, "value": value}]
        if (allocation["size"] != size or not allocation["zeroed"] or drop["owner"] != owner
                or not any(ai < wi < ri < di for wi in writes for ri in reads)):
            raise ValueError("no actual matching allocate/store/load/release sequence")
    return {"arguments": arguments, "result": report["result"], "resources": resources,
            "operation_events": events}


def evaluate_cases(candidate, task, values):
    rows = []
    for arguments in values:
        try:
            rows.append({"accepted": True, **execute_contract(candidate, task, arguments)})
        except Exception as error:
            rows.append({"accepted": False, "arguments": arguments,
                         "error": {"type": type(error).__name__, "message": str(error)}})
    return {"all_correct": all(row["accepted"] for row in rows),
            "case_count": len(rows), "failed_count": sum(not row["accepted"] for row in rows), "cases": rows}


def task_controls(task):
    source = TASK_MODULE.source(task["id"])
    checked = verify_program(source)
    candidate, receipt = apply_program_patch(checked, TASK_MODULE.author_patch(task["id"], checked.sha256))
    values = TASK_MODULE.cases(task) + TASK_MODULE.cases(task, hidden=True)
    negative = evaluate_cases(checked, task, values)
    positive = evaluate_cases(candidate, task, values)
    if negative["failed_count"] == 0 or not positive["all_correct"]:
        raise ValueError("fresh positive/negative author control failed")
    unchanged = {fn["name"]: fn for fn in source["functions"] if fn["name"] not in task["focus"]}
    after = {fn["name"]: fn for fn in candidate.as_dict()["functions"] if fn["name"] not in task["focus"]}
    if unchanged != after or not receipt["claims"]["whole_module_rechecked"]:
        raise ValueError("author control escaped the fresh maintenance boundary")
    return {"task": task["id"], "kind": "author-harness-control-not-model",
            "original_sha256": checked.sha256, "author_fixed_sha256": candidate.sha256,
            "positive": positive, "negative": negative, "model_requests": 0}, source


def collect(output, *, codex=None, registration_commit=None):
    started = time.monotonic_ns()
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False)
    record = {"schema": "hepta.hia.agent-maintenance-preflight.v1", "status": "starting",
        "phase": "development_author_controls_and_environment_preflight",
        "registration_commit": registration_commit, "model_requests": 0,
        "historical_model_results_read": 0, "model_tokens": None, "model_wall_ns": None,
        "provider_generation_attempted": False, "model_efficiency_improvement": False,
        "native_execution_qualified": False, "previous_negative_results_replaced": False}
    try:
        record["source_bindings"] = bindings(registration_commit)
        protocol = json.loads(PROTOCOL_PATH.read_bytes())
        if protocol["tasks"] != [task["id"] for task in TASK_MODULE.TASKS]:
            raise ValueError("fresh task protocol drift")
        record["protocol_sha256"] = sha256(wire(protocol)).hexdigest()
        record["provider"] = provider_preflight(codex)
        provider_identity = record["provider"]["executable_identity"]
        registered_binary = protocol["registered_provider_executable"]
        record["provider_matches_registered_binary"] = (provider_identity is not None
            and all(provider_identity[key] == registered_binary[key] for key in ("sha256", "bytes")))
        record["tasks"] = []
        for task in TASK_MODULE.TASKS:
            directory = root / task["id"]
            directory.mkdir()
            controls, source = task_controls(task)
            context = focused_context(source, task["focus"])
            measurement = measure_payloads(source, task["focus"])
            save(directory / "SOURCE.json", source)
            save(directory / "CONTEXT.json", context)
            save(directory / "AUTHOR_CONTROLS.json", controls)
            save(directory / "PAYLOAD.json", measurement)
            record["tasks"].append({"id": task["id"], "payload": measurement,
                "positive_control_passed": controls["positive"]["all_correct"],
                "negative_control_failures": controls["negative"]["failed_count"],
                "author_cases": controls["positive"]["case_count"]})
        if any(sha256((ROOT / name).read_bytes()).hexdigest() != expected
               for name, expected in record["source_bindings"].items()):
            raise ValueError("source changed during preflight")
        record["blockers"] = (["provider_executable_missing"] if not record["provider"]["provider_executable_available"]
            else ["provider_binary_not_registered"] if not record["provider_matches_registered_binary"] else [])
        record["status"] = "blocked" if record["blockers"] else "preflight_complete"
        record["preflight_controls_completed"] = True
        record["unknown_costs"] = {"future_provider_tokens": None, "future_model_wall_ns": None,
                                   "human_work_ns": None, "provider_cache_effect": None}
    except Exception as error:
        record.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    record["observed_preflight_wall_ns"] = time.monotonic_ns() - started
    record["timing_scope"] = "development collection before final aggregate write; not formal model performance"
    save(root / "RESULT.json", record)
    print(wire({"status": record["status"], "blockers": record.get("blockers"),
                "model_requests": 0, "error": record.get("error"), "output": str(root)}).decode())
    return 0 if record["status"] in {"blocked", "preflight_complete"} and record.get("preflight_controls_completed") else 1


def public_prompt(task, arm):
    source = TASK_MODULE.source(task["id"])
    checked = verify_program(source)
    if arm == "complete-json":
        representation = {"program": source, "opcode_catalog": opcode_catalog(source["schema"])}
    elif arm == "focused-json":
        representation = focused_context(source, task["focus"])
    else:
        raise ValueError("unregistered maintenance arm")
    return {"task": task["description"], "editable_functions": task["focus"],
        "original_snapshot_sha256": checked.sha256, "representation": representation,
        "public_cases": [{"arguments": values, "result": TASK_MODULE.oracle(task["id"], *values)}
                         for values in TASK_MODULE.cases(task)],
        "rpc": {
            "catalog": {"action": "catalog"},
            "context": {"action": "context", "functions": ["FUNCTION_NAME"], "extra_opcodes": []},
            "check": {"action": "check", "patch": "existing hepta.hia.patch.v1/v2 JSON object"},
            "final": "{action:final,patch:PATCH} or {action:final,patch_sha256:ACCEPTED_CHECK_DIGEST}",
        },
        "patch_grammar": {"schema": "hepta.hia.patch.v1", "expected_sha256": checked.sha256,
            "edits": "1..64 exact edits: replace_operation(function,block,index,operation), replace_terminator(function,block,term), or replace_function(function,definition). All function interfaces and noneditable bodies must be preserved. No add_function. v2 requires interface_policy=preserve."},
        "rules": "Each check/final patch applies to the complete original snapshot, not a previous attempt. Complete catalog and additional bodies are available to both arms. Return exactly one JSON RPC object. No direct CLI/file/network tools, hand-off or prose."}


def request_text(messages):
    return ("Solve this frozen maintenance task using only the public conversation below. "
        "Return one JSON RPC object; the host executes the public tools. Do not run CLI tools, "
        "read files, inspect repositories, browse or obtain reference answers.\n"
        + wire(messages).decode("utf-8") + "\nReturn only the next JSON RPC object.\n")


def parse_action(text):
    action = decode_json(text)
    if type(action) is not dict or type(action.get("action")) is not str:
        raise ValueError("one JSON RPC object required")
    choices = {"catalog": [{"action"}],
        "context": [{"action", "functions"}, {"action", "functions", "extra_opcodes"}],
        "check": [{"action", "patch"}],
        "final": [{"action", "patch"}, {"action", "patch_sha256"}]}
    if action["action"] not in choices or set(action) not in choices[action["action"]]:
        raise ValueError("unknown action or incorrect RPC fields")
    if "patch_sha256" in action and (type(action["patch_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", action["patch_sha256"]) is None):
        raise ValueError("final patch_sha256 must be an accepted lowercase SHA-256")
    return action


def evaluate_patch(source, task, request):
    digest = sha256(wire(request)).hexdigest()
    try:
        if type(request) is not dict or (request.get("schema") == "hepta.hia.patch.v2"
                and request.get("interface_policy") != "preserve"):
            raise ValueError("maintenance requires the existing preserve-interface patch policy")
        candidate, admission = apply_program_patch(source, request)
        before = {fn["name"]: fn for fn in source["functions"]}
        after = {fn["name"]: fn for fn in candidate.as_dict()["functions"]}
        if (set(before) != set(after) or admission["interface_changes"]
                or any(after[name] != body for name, body in before.items() if name not in task["focus"])):
            raise ValueError("maintenance patch changed an interface or a noneditable body")
        observed = evaluate_cases(candidate, task, TASK_MODULE.cases(task))
        feedback = {"status": "public_checked", "accepted": observed["all_correct"],
            "patch_sha256": digest, "candidate_sha256": candidate.sha256,
            "admission": admission, "public_execution": observed}
        return candidate if observed["all_correct"] else None, feedback
    except Exception as error:
        return None, {"status": "patch_rejected", "accepted": False, "patch_sha256": digest,
                      "error": {"type": type(error).__name__, "message": str(error)}}


def run_cell(task, arm, folder, cfg, provider, assert_live, *, experiment_deadline,
             observation_kind="provider-observed", live_record=None):
    """Run only fresh provider responses; tests label scripted controls explicitly."""
    started = time.monotonic_ns()
    deadline = min(experiment_deadline, time.monotonic() + cfg["max_cell_wall_seconds"])
    folder = Path(folder)
    folder.mkdir()
    row = {} if live_record is None else live_record
    row.update({"task": task["id"], "arm": arm, "status": "starting", "correct": False,
        "hidden_evaluated": False, "requests": [], "tool_calls": [], "human_answer_repairs": 0,
        "observation_kind": observation_kind, "model_result_eligible": observation_kind == "provider-observed"})
    source = TASK_MODULE.source(task["id"])
    messages = [{"role": "user", "content": public_prompt(task, arm)}]
    save(folder / "START.json", {"task": task["id"], "arm": arm, "messages": messages})
    approved = {}
    public_checks = 0
    for index in range(cfg["max_requests_per_cell"]):
        if deadline - time.monotonic() <= cfg["cleanup_reserve_seconds"]:
            row["status"] = "wall_budget_before_request"
            break
        request_folder = folder / f"request-{index}"
        request_folder.mkdir()
        cwd = Path(tempfile.mkdtemp(prefix="hia-fresh-maintenance-", dir="/tmp"))
        events = CodexEvents(cfg["registered_startup_warnings"])
        receipt = {"index": index, "usage": None, "observed_usage": None, "unknown_usage": True,
                   "provider_launch_attempted": False, "actual_generation_observed": False}
        row["requests"].append(receipt)
        stop = False
        try:
            assert_live()
            text = request_text(messages)
            save(request_folder / "REQUEST.json", {"messages": messages,
                "text_sha256": sha256(text.encode()).hexdigest(), "utf8_bytes": len(text.encode())})
            command = [provider["path"], "exec", "--json", "--ephemeral", "--sandbox", "read-only",
                       "--skip-git-repo-check", "-m", cfg["model"], "-"]
            receipt["provider_launch_attempted"] = True
            receipt["process"] = run_owned(command, cwd, request_folder / "transport", input_bytes=text.encode(),
                wall_seconds=min(cfg["max_request_wall_seconds"],
                    max(0.001, deadline - time.monotonic() - cfg["cleanup_reserve_seconds"])),
                on_line=events.line, transport_config=cfg["transport"])
            receipt["actual_generation_observed"] = events.turn_count > 0
            raw = request_folder / "transport/stdout.raw"
            receipt["observed_usage"] = recover_reported_usage(raw) if raw.exists() else events.usage
            if receipt["observed_usage"] is None:
                receipt["observed_usage"] = events.usage
            if receipt["process"]["status"] != "exited":
                raise EventFailure("provider transport: " + receipt["process"]["status"])
            answer = events.complete()
            if receipt["observed_usage"] != answer["usage"]:
                raise EventFailure("provider usage differs across the complete stream")
            receipt.update(usage=answer["usage"], unknown_usage=False)
            save(request_folder / "ANSWER.json", answer)
            usage = answer["usage"]
            total = sum(sum(r["observed_usage"][key] for key in ("input_tokens", "output_tokens", "reasoning_output_tokens"))
                        for r in row["requests"] if r["observed_usage"] is not None)
            if (usage["input_tokens"] > cfg["max_reported_input_tokens_per_request"]
                    or usage["output_tokens"] + usage["reasoning_output_tokens"] > cfg["max_charged_output_tokens_per_request"]
                    or total > cfg["max_charged_tokens_per_cell"]):
                raise EventFailure("observed provider token budget exceeded")
            messages.append({"role": "assistant", "content": answer["text"]})
            try:
                action = parse_action(answer["text"])
            except ValueError as error:
                feedback = {"status": "rpc_rejected", "error": str(error)}
                row["tool_calls"].append({"action": "invalid", "feedback": feedback})
            else:
                name = action["action"]
                call = {"action": name}
                row["tool_calls"].append(call)
                if name == "catalog":
                    feedback = opcode_catalog(source["schema"])
                elif name == "context":
                    try:
                        feedback = focused_context(source, action["functions"], extra_opcodes=action.get("extra_opcodes", []))
                    except ValueError as error:
                        feedback = {"status": "context_rejected", "error": str(error)}
                elif name == "check" and public_checks >= cfg["max_public_checks_per_cell"]:
                    feedback = {"status": "public_check_budget_exhausted", "accepted": False}
                else:
                    if "patch" in action:
                        public_checks += int(name == "check")
                        candidate, feedback = evaluate_patch(source, task, action["patch"])
                        call["public"] = feedback
                        if candidate is not None:
                            approved[feedback["patch_sha256"]] = candidate
                            save(request_folder / "CANDIDATE.json", candidate.as_dict())
                        action = {"action": name, "patch_sha256": feedback["patch_sha256"]}
                    else:
                        feedback = {"status": "final_received"}
                    if name == "final":
                        selected = approved.get(action["patch_sha256"])
                        if selected is None:
                            row["status"] = "final_not_publicly_accepted"
                        elif time.monotonic() >= deadline:
                            row["status"] = "wall_budget_before_hidden"
                        else:
                            terminal = evaluate_cases(selected, task, TASK_MODULE.cases(task, hidden=True))
                            save(request_folder / "TERMINAL_HIDDEN.json", terminal)
                            row.update(hidden_evaluated=True, correct=terminal["all_correct"],
                                       status="correct" if terminal["all_correct"] else "hidden_failed")
                        stop = True
            save(request_folder / "PUBLIC_FEEDBACK.json", feedback)
            # Terminal hidden data is never appended to the public conversation.
            if not stop:
                messages.append({"role": "user", "content": feedback})
        except Exception as error:
            row.update(status="terminal_provider_or_protocol_failure", correct=False)
            receipt["error"] = {"type": type(error).__name__, "message": str(error)}
            stop = True
        finally:
            receipt["actual_generation_observed"] = events.turn_count > 0
            if receipt["observed_usage"] is None:
                receipt["observed_usage"] = events.usage
            receipt["cwd_entries_after"] = sorted(path.name for path in cwd.iterdir())
            if not receipt["cwd_entries_after"] and receipt.get("process", {}).get("cleanup_confirmed"):
                cwd.rmdir()
                receipt["empty_cwd_removed"] = True
            else:
                receipt["empty_cwd_removed"] = False
            if receipt["cwd_entries_after"]:
                row.update(status="unexpected_provider_cwd_write", correct=False)
                stop = True
            save(request_folder / "RECEIPT.json", receipt)
        if stop:
            break
    if row["status"] == "starting":
        row["status"] = "request_budget_exhausted"
    row["complete_usage"] = bool(row["requests"]) and all(not r["unknown_usage"] for r in row["requests"])
    row["observed_usage_totals"] = {key: sum(r["observed_usage"][key] for r in row["requests"]
        if r["observed_usage"] is not None) for key in ("input_tokens", "cached_input_tokens", "cache_write_input_tokens",
                                                       "output_tokens", "reasoning_output_tokens")}
    row["known_token_units"] = sum(row["observed_usage_totals"][key]
        for key in ("input_tokens", "output_tokens", "reasoning_output_tokens"))
    row["token_units"] = row["known_token_units"] if row["complete_usage"] else None
    row["public_failed_checks"] = sum("public" in call and not call["public"]["accepted"] for call in row["tool_calls"])
    row["provider_requests_attempted"] = sum(r["provider_launch_attempted"] for r in row["requests"])
    row["wall_ns_before_final_evidence_write"] = time.monotonic_ns() - started
    row["final_evidence_scope"] = "aggregate cell.wall_ns includes this final CELL.json write"
    save(folder / "CELL.json", row)
    row["wall_ns"] = time.monotonic_ns() - started
    row["actual_wall_budget_passed"] = time.monotonic() <= deadline
    if not row["actual_wall_budget_passed"]:
        row.update(status="wall_budget_exceeded", correct=False)
    return row


def summarize_cells(rows, cfg, study_wall_ns):
    expected = {(task, arm) for task in cfg["tasks"] for arm in cfg["arms"]}
    actual = [(row["task"], row["arm"]) for row in rows]
    if len(set(actual)) != len(actual) or not set(actual) <= expected:
        raise ValueError("duplicate or unregistered maintenance cell")
    common = study_wall_ns - sum(row["wall_ns"] for row in rows)
    if common < 0:
        raise ValueError("overlapping maintenance wall accounting")
    totals = {}
    for arm in cfg["arms"]:
        cells = [row for row in rows if row["arm"] == arm]
        known = sum(row["known_token_units"] for row in cells)
        complete = len(cells) == len(cfg["tasks"]) and all(row["complete_usage"] for row in cells)
        totals[arm] = {"successes": sum(row["correct"] and row["status"] == "correct" for row in cells),
            "token_units": known if complete else None, "known_partial_token_units": known,
            "standalone_wall_ns": common + sum(row["wall_ns"] for row in cells),
            "failed_public_checks": sum(row["public_failed_checks"] for row in cells),
            "provider_requests_attempted": sum(row["provider_requests_attempted"] for row in cells)}
    experiment_budget_passed = study_wall_ns <= cfg["max_experiment_wall_seconds"] * 1_000_000_000
    eligible = (experiment_budget_passed and set(actual) == expected
        and all(row["status"] == "correct" and row["complete_usage"] and row["hidden_evaluated"]
                and row["correct"] and row["actual_wall_budget_passed"] and row["model_result_eligible"] for row in rows))
    full, focus = totals["complete-json"], totals["focused-json"]
    advantage = (eligible and focus["successes"] >= full["successes"]
        and focus["token_units"] < full["token_units"] and focus["standalone_wall_ns"] < full["standalone_wall_ns"]
        and focus["failed_public_checks"] <= full["failed_public_checks"])
    return {"all_registered_model_cells_eligible": eligible, "arm_totals": totals,
        "actual_experiment_wall_budget_passed": experiment_budget_passed,
        "common_preparation_charged_once_to_each_standalone_arm_ns": common,
        "descriptive_focused_context_advantage": advantage,
        "general_model_productivity_proved": False, "complete_lifetime_productivity_proved": False,
        "unknown_costs": {"human_work_ns": None, "provider_cache_effect": None,
                          "process_startup_before_main_ns": None, "final_aggregate_write_ns": None}}


def run_registered(output, *, registration_commit, codex=None):
    started = time.monotonic_ns()
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False)
    record = {"schema": "hepta.hia.agent-maintenance-run.v1", "status": "starting",
        "registration_commit": registration_commit, "cells": [], "model_requests": 0,
        "host": {"platform": sys.platform, "machine": os.uname().machine,
                 "python": sys.version, "started_unix_ns": time.time_ns()},
        "historical_model_results_read": 0, "previous_negative_results_replaced": False,
        "human_answer_repairs": 0, "native_execution_claim": False}
    try:
        if registration_commit is None:
            raise ValueError("--run requires an exact prior --registration-commit")
        frozen = bindings(registration_commit)
        cfg = json.loads(PROTOCOL_PATH.read_bytes())
        if (cfg["schema"] != "hepta.hia.agent-maintenance.protocol.v1"
                or cfg["tasks"] != [task["id"] for task in TASK_MODULE.TASKS]
                or cfg["arms"] != ["complete-json", "focused-json"]
                or cfg["registered_generation_runner_available"] is not True):
            raise ValueError("generation protocol does not match implemented runner")
        provider = provider_preflight(codex)
        record.update(source_bindings=frozen, protocol=cfg, provider=provider)
        if not provider["provider_executable_available"]:
            record.update(status="blocked", blockers=["provider_executable_missing"])
        else:
            binary = provider["executable_identity"]
            if any(binary[key] != cfg["registered_provider_executable"][key] for key in ("sha256", "bytes")):
                raise ValueError("provider binary differs from the exact preregistered executable")

            def assert_live():
                if (any(sha256((ROOT / name).read_bytes()).hexdigest() != value for name, value in frozen.items())
                        or identity(binary["path"]) != binary):
                    raise ValueError("registered source/provider binary drift")

            controls = []
            for task in TASK_MODULE.TASKS:
                control, _ = task_controls(task)
                controls.append(control)
            save(root / "AUTHOR_CONTROLS.json", controls)
            save(root / "PLAN.json", {**record, "formal_model_requests_before_plan": 0,
                "author_controls_sha256": sha256(wire(controls)).hexdigest()})
            # The registered total cap starts at function entry, including
            # registration, initialization, controls and evidence preparation.
            deadline = started / 1_000_000_000 + cfg["max_experiment_wall_seconds"]
            for index, task in enumerate(TASK_MODULE.TASKS):
                order = cfg["arms"] if index % 2 == 0 else list(reversed(cfg["arms"]))
                for arm in order:
                    row = {"task": task["id"], "arm": arm, "status": "starting", "requests": []}
                    record["cells"].append(row)
                    cell_started = time.monotonic_ns()
                    try:
                        run_cell(task, arm, root / (task["id"] + "-" + arm), cfg, binary, assert_live,
                                 experiment_deadline=deadline, live_record=row)
                    except Exception as error:
                        # Retain raw request artifacts and the live row even if
                        # a later evidence write or infrastructure step fails.
                        known = sum(sum(request["observed_usage"][key]
                            for key in ("input_tokens", "output_tokens", "reasoning_output_tokens"))
                            for request in row["requests"] if request.get("observed_usage") is not None)
                        row.update(status="cell_infrastructure_failed", correct=False, complete_usage=False,
                            hidden_evaluated=row.get("hidden_evaluated", False), actual_wall_budget_passed=False,
                            model_result_eligible=False, token_units=None, known_token_units=known,
                            public_failed_checks=sum("public" in call and not call["public"]["accepted"]
                                for call in row.get("tool_calls", [])),
                            provider_requests_attempted=sum(request.get("provider_launch_attempted", False)
                                for request in row["requests"]), wall_ns=time.monotonic_ns() - cell_started,
                            error={"type": type(error).__name__, "message": str(error)})
                    record["model_requests"] += row["provider_requests_attempted"]
            assert_live()
            record["observed_study_wall_ns"] = time.monotonic_ns() - started
            record["summary"] = summarize_cells(record["cells"], cfg, record["observed_study_wall_ns"])
            record["status"] = "complete"
    except Exception as error:
        record.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    record["observed_attempt_wall_ns"] = time.monotonic_ns() - started
    save(root / "RESULT.json", record)
    print(wire({"status": record["status"], "model_requests": record["model_requests"],
                "blockers": record.get("blockers"), "error": record.get("error"),
                "summary": record.get("summary"), "output": str(root)}).decode())
    if record["status"] == "blocked":
        return 2
    return 0 if record["status"] == "complete" and record["summary"]["all_registered_model_cells_eligible"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight-only", action="store_true")
    mode.add_argument("--run", action="store_true", help="actual fresh provider run, requiring prior source registration")
    parser.add_argument("--output", required=True)
    parser.add_argument("--codex", help="exact requested executable; absent means PATH codex")
    parser.add_argument("--registration-commit", help="exact prior source registration commit; mandatory with --run")
    args = parser.parse_args(argv)
    if args.run and args.registration_commit is None:
        parser.error("--run requires --registration-commit")
    operation = run_registered if args.run else collect
    return operation(args.output, codex=args.codex, registration_commit=args.registration_commit)


if __name__ == "__main__":
    raise SystemExit(main())
