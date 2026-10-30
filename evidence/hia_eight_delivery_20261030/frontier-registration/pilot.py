#!/usr/bin/env python3
"""Independent fixed-alias Codex pilot; existing Hepta evaluators stay unchanged."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import threading
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = Path("/workspace/scratch/8245a7ab856a/Hepta")
SOURCE_COMMIT = "60dfedc626b7ce3feaaa87ac16d711fe0cc8e9d3"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))

from experiments.hia_agent_factorial_v4_20261028 import evaluator
from experiments.hia_agent_toolstudy_v8_20261029 import validation
from experiments.hia_agent_toolstudy_v9_20261029 import prompts, support


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def save(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".writing")
    with temporary.open("xb") as stream:
        stream.write(canonical(value) + b"\n")
    temporary.replace(path)


def identity(path):
    path = Path(path).resolve(strict=True)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def protocol():
    value = json.loads((HERE / "PROTOCOL.json").read_text())
    if value["source_commit"] != SOURCE_COMMIT:
        raise ValueError("E_PILOT_SOURCE_PROTOCOL")
    return value


def source_identity():
    head, files = support.clean_committed_source()
    if head != SOURCE_COMMIT:
        raise ValueError("E_PILOT_WRONG_SOURCE_COMMIT")
    return {"commit": head, "bindings": files}


def code_identity():
    return {name: identity(HERE / name) for name in ("PROTOCOL.json", "pilot.py", "test_controls.py")}


def tool_identity(cfg):
    return {name: identity(path) for name, path in cfg["tools"].items()}


def verify_freeze():
    frozen = json.loads((HERE / "FREEZE.json").read_text())
    if (frozen["source"] != source_identity()
            or frozen["pilot_files"] != code_identity()
            or frozen["tools"] != tool_identity(protocol())
            or frozen["prompt_bindings"] != support.prompt_bindings()):
        raise ValueError("E_PILOT_FROZEN_IDENTITY_DRIFT")
    return frozen


class EventFailure(ValueError):
    pass


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise EventFailure("E_PILOT_DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def checked_usage(value):
    fields = ("input_tokens", "cached_input_tokens", "cache_write_input_tokens",
              "output_tokens", "reasoning_output_tokens")
    if (type(value) is not dict or set(value) != set(fields)
            or any(type(value.get(key)) is not int or value[key] < 0 for key in fields)
            or value["cached_input_tokens"] > value["input_tokens"]):
        raise EventFailure("E_PILOT_UNKNOWN_OR_MALFORMED_USAGE")
    return copy.deepcopy(value)


def recover_reported_usage(path):
    """Retain a complete usage event even when a preceding tool violation rejected."""
    observations = []
    for line in Path(path).read_bytes().splitlines():
        try:
            event = strict_json(line)
            if type(event) is dict and event.get("type") == "turn.completed":
                observations.append(checked_usage(event.get("usage")))
        except (ValueError, UnicodeError, RecursionError):
            continue
    return observations[0] if len(observations) == 1 else None


class CodexEvents:
    """Observe the complete event stream; no output repair or tool acceptance."""
    def __init__(self, warnings):
        self.warnings = set(warnings)
        self.warning_limits = {message: warnings.count(message) for message in warnings}
        self.warning_counts = {}
        self.events = []
        self.messages = []
        self.usage = None
        self.thread_count = 0
        self.turn_count = 0
        self.completed_count = 0
        self.unknown_usage = True
        self.failure = None

    def line(self, raw):
        try:
            event = strict_json(raw)
        except (ValueError, UnicodeError) as exc:
            raise EventFailure("E_PILOT_INVALID_JSONL") from exc
        self.events.append(event)
        if type(event) is not dict:
            raise EventFailure("E_PILOT_EVENT_SHAPE")
        kind = event.get("type")
        if kind == "thread.started":
            if set(event) != {"type", "thread_id"} or type(event["thread_id"]) is not str:
                raise EventFailure("E_PILOT_THREAD_FIELDS")
            self.thread_count += 1
            if self.thread_count != 1 or self.turn_count:
                raise EventFailure("E_PILOT_THREAD_SEQUENCE")
        elif kind == "turn.started":
            if set(event) != {"type"}:
                raise EventFailure("E_PILOT_TURN_FIELDS")
            self.turn_count += 1
            if self.thread_count != 1 or self.turn_count != 1:
                raise EventFailure("E_PILOT_TURN_SEQUENCE")
        elif kind in {"item.started", "item.updated", "item.completed"}:
            if set(event) != {"type", "item"}:
                raise EventFailure("E_PILOT_ITEM_EVENT_FIELDS")
            item = event.get("item")
            if type(item) is not dict:
                raise EventFailure("E_PILOT_ITEM_SHAPE")
            item_type = item.get("type")
            if (item_type == "error" and kind == "item.completed" and self.thread_count == 1
                    and not self.turn_count and set(item) == {"id", "type", "message"}
                    and type(item["id"]) is str
                    and item.get("message") in self.warnings):
                message = item["message"]
                self.warning_counts[message] = self.warning_counts.get(message, 0) + 1
                if self.warning_counts[message] > self.warning_limits[message]:
                    raise EventFailure("E_PILOT_WARNING_MULTIPLICITY")
                return
            if item_type != "agent_message":
                raise EventFailure("E_PILOT_TOOL_OR_UNREGISTERED_ITEM:" + str(item_type))
            if (not {"id", "type"} <= set(item) or not set(item) <= {"id", "type", "text"}
                    or type(item["id"]) is not str):
                raise EventFailure("E_PILOT_AGENT_MESSAGE_FIELDS")
            if self.turn_count != 1 or self.completed_count:
                raise EventFailure("E_PILOT_MESSAGE_SEQUENCE")
            if kind == "item.completed":
                if type(item.get("text")) is not str:
                    raise EventFailure("E_PILOT_MESSAGE_TEXT")
                self.messages.append(item["text"])
        elif kind == "turn.completed":
            if set(event) != {"type", "usage"}:
                raise EventFailure("E_PILOT_COMPLETION_FIELDS")
            self.completed_count += 1
            if self.turn_count != 1 or self.completed_count != 1:
                raise EventFailure("E_PILOT_COMPLETION_SEQUENCE")
            self.usage = checked_usage(event.get("usage"))
            self.unknown_usage = False
        else:
            # This includes turn.failed, runtime errors and future unknown events.
            raise EventFailure("E_PILOT_UNREGISTERED_EVENT:" + str(kind))

    def complete(self):
        if (self.thread_count != 1 or self.turn_count != 1 or self.completed_count != 1
                or len(self.messages) != 1 or self.usage is None):
            raise EventFailure("E_PILOT_INCOMPLETE_RESPONSE_OR_USAGE")
        return {"text": self.messages[0], "usage": self.usage}


def run_owned(argv, cwd, output, *, input_bytes=b"", wall_seconds, on_line=None):
    """Own a new process group. Kill that group before reaping its leader."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    cfg = protocol()
    caps = {"stdout": cfg["transport"]["stdout_limit_bytes"],
            "stderr": cfg["transport"]["stderr_limit_bytes"]}
    started = time.monotonic_ns()
    deadline = time.monotonic() + max(0.0, wall_seconds)
    record = {"argv": [str(x) for x in argv], "cwd": str(cwd),
              "wall_limit_seconds": wall_seconds, "started_unix_ns": time.time_ns(),
              "status": "starting", "leader_reaped": False,
              "group_kill_before_reap": False, "streams_complete": False,
              "ownership_confirmed": False, "ownership_uncertain": False,
              "signal_attempted": False, "signal_delivered": False,
              "reap_attempted": False, "cleanup_confirmed": False,
              "bytes_observed": {"stdout": 0, "stderr": 0}}
    save(output / "PROCESS.json", record)
    process = None
    selector = selectors.DefaultSelector()
    pending = b""
    reason = None
    active = {}
    streams = {name: (output / (name + ".raw")).open("xb") for name in caps}
    stdin_path = output / "stdin.raw"
    stdin_path.write_bytes(input_bytes)

    def observe_owned():
        if record["reap_attempted"] or record["ownership_uncertain"]:
            raise RuntimeError("E_PILOT_CHILD_OWNERSHIP_UNCERTAIN")
        try:
            observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except BaseException:
            record["ownership_confirmed"] = False
            record["ownership_uncertain"] = True
            raise
        record["ownership_confirmed"] = True
        return observed

    def stop_once():
        if record["signal_attempted"] or record["reap_attempted"]:
            raise RuntimeError("E_PILOT_SIGNAL_RETRY_FORBIDDEN")
        observe_owned()
        record["signal_attempted"] = True
        record["signal_attempted_before_reap"] = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            record["group_signal"] = "group_absent_at_signal_attempt; cleanup_unconfirmed"
        else:
            record["group_signal"] = "SIGKILL"
            record["signal_delivered"] = True
            record["group_kill_before_reap"] = True

    def reap_once():
        if record["reap_attempted"]:
            raise RuntimeError("E_PILOT_REAP_RETRY_FORBIDDEN")
        observe_owned()
        record["reap_attempted"] = True
        record["returncode"] = process.wait(timeout=5)
        record["leader_reaped"] = True

    try:
        if not math.isfinite(wall_seconds) or wall_seconds <= 0 or time.monotonic() >= deadline:
            reason = "wall_timeout_before_launch"
            raise RuntimeError("E_PILOT_EXPIRED_BEFORE_LAUNCH")
        if (signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
                or threading.active_count() != 1 or not hasattr(os, "WNOWAIT")):
            raise RuntimeError("E_PILOT_SINGLE_OWNER_WAITID_ADMISSION")
        # Probe the actual waitid flags before launching a child. Self is not a child.
        try:
            os.waitid(os.P_PID, os.getpid(), os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            pass
        else:
            raise RuntimeError("E_PILOT_WAITID_CAPABILITY_PROBE")
        if time.monotonic() >= deadline:
            reason = "wall_timeout_before_launch"
            raise RuntimeError("E_PILOT_EXPIRED_BEFORE_LAUNCH")
        with stdin_path.open("rb") as stdin:
            process = subprocess.Popen(argv, cwd=cwd, stdin=stdin, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
        record.update(pid=process.pid, pgid=process.pid, status="running")
        save(output / "PROCESS.json", record)
        for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
            active[name] = pipe
        while True:
            if time.monotonic() >= deadline:
                reason = "wall_timeout"
                break
            for key, _ in selector.select(min(0.05, max(0.0, deadline-time.monotonic()))):
                name = key.data
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    active.pop(name, None)
                    continue
                before = record["bytes_observed"][name]
                record["bytes_observed"][name] += len(chunk)
                streams[name].write(chunk[:max(0, caps[name]-before)])
                streams[name].flush()
                if record["bytes_observed"][name] > caps[name]:
                    reason = "output_limit"
                    break
                if name == "stdout" and on_line is not None:
                    pending += chunk
                    if len(pending) > cfg["transport"]["max_jsonl_line_bytes"]:
                        reason = "jsonl_line_limit"
                        break
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        if not line:
                            reason = "protocol_violation"
                            record["event_error"] = "E_PILOT_EMPTY_EVENT_LINE"
                            break
                        try:
                            on_line(line)
                        except Exception as exc:
                            reason = "protocol_violation"
                            record["event_error"] = str(exc)
                            break
                if reason:
                    break
            if reason:
                break
            # WNOWAIT observes exit without releasing/reusing the leader PID.
            exited = observe_owned()
            if exited is not None:
                record["leader_exit_observed_without_reap"] = True
                break
        stop_once()
        # Drain already-produced raw bytes after the owned group is stopped.
        drain_deadline = time.monotonic() + 2.0
        while active and time.monotonic() < drain_deadline:
            for key, _ in selector.select(0.05):
                name = key.data
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    active.pop(name, None)
                    continue
                before = record["bytes_observed"][name]
                record["bytes_observed"][name] += len(chunk)
                streams[name].write(chunk[:max(0, caps[name]-before)])
                if record["bytes_observed"][name] > caps[name]:
                    reason = reason or "output_limit"
                if name == "stdout" and on_line is not None and reason is None:
                    pending += chunk
                    if len(pending) > cfg["transport"]["max_jsonl_line_bytes"]:
                        reason = "jsonl_line_limit"
                    while b"\n" in pending and reason is None:
                        line, pending = pending.split(b"\n", 1)
                        try:
                            if not line:
                                raise EventFailure("E_PILOT_EMPTY_EVENT_LINE")
                            on_line(line)
                        except Exception as exc:
                            reason = "protocol_violation"
                            record["event_error"] = str(exc)
        record["streams_complete"] = not active
        if active:
            reason = reason or "stream_cleanup_incomplete"
        if pending and on_line is not None and reason is None:
            try:
                on_line(pending)
            except Exception as exc:
                reason = "protocol_violation"
                record["event_error"] = str(exc)
        reap_once()
        record["cleanup_confirmed"] = bool(record["signal_delivered"] and record["leader_reaped"]
                                           and record["streams_complete"])
        record["status"] = (reason or "cleanup_uncertain" if not record["cleanup_confirmed"]
                            else reason or ("exited" if record["returncode"] == 0 else "process_failure"))
    except BaseException as exc:
        record["error"] = {"type": type(exc).__name__, "message": str(exc)}
        record["status"] = reason or "infrastructure_failure"
        if (process is not None and not record["ownership_uncertain"]
                and not record["reap_attempted"]):
            try:
                if not record["signal_attempted"]:
                    stop_once()
                reap_once()
            except Exception as cleanup_error:
                record["cleanup_error"] = str(cleanup_error)
    finally:
        selector.close()
        for pipe in active.values():
            pipe.close()
        for stream in streams.values():
            stream.close()
        if process is not None:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
        record["wall_ns"] = time.monotonic_ns()-started
        record["files"] = {name: identity(output / name) for name in ("stdin.raw", "stdout.raw", "stderr.raw")}
        save(output / "PROCESS.json", record)
    return record


def choose_task(stage, task_id, arm):
    matches = [(task, selected_arm) for task, selected_arm in support.cells(stage)
               if task["id"] == task_id and selected_arm == arm]
    if len(matches) != 1:
        raise ValueError("E_PILOT_UNREGISTERED_TASK_ARM")
    return matches[0][0]


def evaluate_worker(args):
    """Separate owned process; public acceptance is followed by terminal hidden."""
    cfg = protocol()
    task = choose_task(args.stage, args.task, args.arm)
    language, interface = support.language_interface(args.arm)
    session = support.session_for(task, args.arm, cfg["tools"]["clang"], cfg["tools"]["rustc"])
    query = json.loads(Path(args.query).read_text())
    if session.query() != query:
        raise ValueError("E_PILOT_CAPTURED_QUERY_CHANGED")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    if args.reference:
        # This module is only imported for explicitly labelled human controls.
        from experiments.hia_agent_toolstudy_v8_20261029 import references
        answer = (references.reference(session, query, task) if interface == "node"
                  else {"files": task["correct_" + language]})
        text = canonical(answer).decode()
        (output / "HUMAN_REFERENCE.txt").write_text(text)
    else:
        text = Path(args.response).read_text()
    observed = validation.evaluate(task, language, interface, session, query, text,
                                   output / "candidate", cfg["tools"]["clang"], cfg["tools"]["rustc"])
    result = {"public": observed, "correct": False, "hidden_evaluated": False,
              "status": observed["status"], "reference_control": bool(args.reference)}
    if observed["accepted"]:
        hidden = evaluator.execute(observed["build"], task, task["hidden_cases"], task["hidden_expected"])
        save(output / "HIDDEN.json", hidden)
        result.update(hidden=hidden, hidden_evaluated=True,
                      correct=hidden["status"] == "correct" and hidden["artifact_unchanged"],
                      status="infrastructure_failure" if not hidden["artifact_unchanged"]
                      else "correct" if hidden["status"] == "correct" else "hidden_failed")
    save(output / "EVALUATION.json", result)
    return 0


def evaluate_isolated(stage, task, arm, query_path, response_path, output, deadline, *, reference=False):
    args = [sys.executable, str(HERE / "pilot.py"), "_evaluate", "--stage", stage,
            "--task", task["id"], "--arm", arm, "--query", str(query_path),
            "--output", str(output / "evaluation")]
    args += ["--reference"] if reference else ["--response", str(response_path)]
    remaining = min(120.0, deadline-time.monotonic()-protocol()["budgets"]["cleanup_reserve_seconds"])
    if remaining <= 0:
        return {"status": "experiment_wall_timeout", "correct": False, "hidden_evaluated": False}
    process = run_owned(args, HERE, output / "evaluation-process", wall_seconds=remaining)
    receipt = output / "evaluation/EVALUATION.json"
    if process["status"] != "exited" or not receipt.is_file():
        return {"status": "evaluation_infrastructure_failure", "correct": False,
                "hidden_evaluated": False, "process": process}
    result = json.loads(receipt.read_text())
    result["process"] = process
    return result


def wrapped_request(messages):
    return (protocol()["request_wrapper"] + "\n\nCOMPLETE_CONVERSATION_JSON:\n"
            + canonical(messages).decode() + "\n\nReturn only the requested final JSON.\n")


def prepare_controls(output):
    cfg = protocol()
    frozen = {"schema": "hepta.agent-frontier-freeze.v1", "source": source_identity(),
              "pilot_files": code_identity(), "tools": tool_identity(cfg),
              "prompt_bindings": support.prompt_bindings(), "created_unix_ns": time.time_ns(),
              "benchmark_task_requests_before_freeze": 0, "bootstrap_requests_already_observed": 2,
              "bootstrap_cost_complete": False}
    if (HERE / "FREEZE.json").exists():
        raise ValueError("E_PILOT_FREEZE_ALREADY_EXISTS")
    save(HERE / "FREEZE.json", frozen)
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False)
    result = {"schema": "hepta.agent-frontier-controls.v1", "freeze": identity(HERE / "FREEZE.json"),
              "reference_controls": [], "dummy_controls": [], "model_requests": 0,
              "reference_controls_are_model_successes": False, "passed": False}
    save(root / "RESULT.json", result)
    try:
        for stage in ("calibration", "main"):
            for task, arm in support.cells(stage):
                folder = root / (stage + "__" + task["id"] + "__" + arm)
                folder.mkdir()
                session = support.session_for(task, arm, cfg["tools"]["clang"], cfg["tools"]["rustc"])
                query = session.query()
                save(folder / "CAPTURED_QUERY.json", query)
                (folder / "dummy.txt").write_text("{}")
                reference = evaluate_isolated(stage, task, arm, folder / "CAPTURED_QUERY.json", None,
                                              folder / "reference", time.monotonic()+120, reference=True)
                dummy = evaluate_isolated(stage, task, arm, folder / "CAPTURED_QUERY.json", folder / "dummy.txt",
                                          folder / "dummy", time.monotonic()+120)
                result["reference_controls"].append({"stage": stage, "task": task["id"], "arm": arm,
                                                    "correct": reference["correct"], "hidden_evaluated": reference["hidden_evaluated"],
                                                    "status": reference["status"], "output": str(folder / "reference")})
                result["dummy_controls"].append({"stage": stage, "task": task["id"], "arm": arm,
                                                "rejected": dummy["status"] == "response_rejected"
                                                    and not dummy["hidden_evaluated"] and not dummy["correct"],
                                                "output": str(folder / "dummy")})
                save(root / "RESULT.json", result)
                print(json.dumps(result["reference_controls"][-1]), flush=True)
        verify_freeze()
        result["passed"] = (len(result["reference_controls"]) == 19
                            and all(row["correct"] and row["hidden_evaluated"] for row in result["reference_controls"])
                            and len(result["dummy_controls"]) == 19
                            and all(row["rejected"] for row in result["dummy_controls"]))
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    save(root / "RESULT.json", result)
    return 0 if result["passed"] else 1


def checked_review(review_path, controls_path):
    frozen = verify_freeze()
    review = json.loads(Path(review_path).read_text())
    controls = json.loads(Path(controls_path).read_text())
    if (review.get("schema") != "hepta.agent-frontier-independent-review.v1"
            or review.get("decision") != "allow_generation"
            or review.get("source_commit") != SOURCE_COMMIT
            or review.get("freeze_sha256") != identity(HERE / "FREEZE.json")["sha256"]
            or review.get("controls_sha256") != identity(controls_path)["sha256"]
            or review.get("model_requests_by_reviewer") != 0
            or controls.get("freeze") != identity(HERE / "FREEZE.json")
            or controls.get("passed") is not True or controls.get("model_requests") != 0):
        raise ValueError("E_PILOT_INDEPENDENT_REVIEW_OR_CONTROLS")
    return frozen


def usage_charge(usage):
    # Preserve raw CLI fields. This conservative budget may count reasoning twice.
    return usage["input_tokens"] + usage["output_tokens"] + usage["reasoning_output_tokens"]


def run_cell(stage, task, arm, root, deadline, cfg, frozen, rows):
    folder = root / (stage + "__" + task["id"] + "__" + arm)
    folder.mkdir()
    session = support.session_for(task, arm, cfg["tools"]["clang"], cfg["tools"]["rustc"])
    query = session.query()
    initial = prompts.prompt(task, arm, query)
    key = stage + "/" + task["id"] + "/" + arm
    expected = frozen["prompt_bindings"][key]
    if (hashlib.sha256(initial.encode()).hexdigest() != expected["prompt_sha256"]
            or query["query_sha256"] != expected["query_sha256"]):
        raise ValueError("E_PILOT_PROMPT_QUERY_DRIFT")
    save(folder / "CAPTURED_QUERY.json", query)
    (folder / "INITIAL_PROMPT.txt").write_text(initial)
    messages = prompts.messages(initial)
    row = {"stage": stage, "task": task["id"], "arm": support.language_interface(arm)[0] + "_"
           + support.language_interface(arm)[1], "attempts": [], "correct": False,
           "hidden_evaluated": False, "status": "not_started", "charged_tokens": 0}
    # Register before any request so even later infrastructure exceptions retain costs.
    rows.append(row)
    save(folder / "CELL.json", row)
    for index in range(cfg["budgets"]["attempts_per_cell"]):
        remaining = deadline-time.monotonic()-cfg["budgets"]["cleanup_reserve_seconds"]
        if remaining <= 0:
            row["status"] = "experiment_wall_timeout"
            break
        verify_freeze()
        attempt_dir = folder / ("attempt-" + str(index))
        attempt_dir.mkdir()
        cwd_root = Path(cfg["model_cwd_root"])
        cwd_root.mkdir(parents=True, exist_ok=True)
        cwd = cwd_root / ("request-" + uuid.uuid4().hex)
        cwd.mkdir(exist_ok=False)
        request = wrapped_request(messages)
        save(attempt_dir / "REQUEST.json", {"messages": messages, "wrapper": cfg["request_wrapper"],
                                          "request_utf8_sha256": hashlib.sha256(request.encode()).hexdigest(),
                                          "captured_query_sha256": query["query_sha256"],
                                          "empty_working_directory": str(cwd),
                                          "cwd_outside_source_and_evidence": True})
        events = CodexEvents(cfg["registered_startup_warnings"])
        argv = [cfg["tools"]["codex"], "exec", "--json", "--ephemeral", "--sandbox", "read-only",
                "--skip-git-repo-check", "-m", cfg["model"]["requested_alias"], "-"]
        attempt = {"index": index, "request_started": False, "cli_launch_attempted": False, "usage": None,
                   "unknown_usage": True, "status": "starting"}
        row["attempts"].append(attempt)
        save(folder / "CELL.json", row)
        try:
            # An exception inside the transport may occur after process creation.
            # None means launch outcome unknown, never a zero-cost known nonlaunch.
            attempt.update(cli_launch_attempted=True, request_started=None)
            process = run_owned(argv, cwd, attempt_dir / "transport", input_bytes=request.encode(),
                                wall_seconds=min(cfg["budgets"]["request_wall_seconds"],
                                                 deadline-time.monotonic()-cfg["budgets"]["cleanup_reserve_seconds"]),
                                on_line=events.line)
            # Register launch and observed costs BEFORE any subsequent disk operation.
            attempt.update(process=process, request_started="pid" in process,
                           observed_usage=events.usage, unknown_usage=True,
                           status=process["status"], actual_generation_observed=events.turn_count > 0)
            if events.usage is not None:
                attempt["charged_tokens"] = usage_charge(events.usage)
            row["charged_tokens"] = sum(a.get("charged_tokens", 0) for a in row["attempts"])
            save(attempt_dir / "EVENTS.json", events.events)
            recovered_usage = recover_reported_usage(attempt_dir / "transport/stdout.raw")
            if recovered_usage is not None:
                attempt["observed_usage"] = recovered_usage
                attempt["charged_tokens"] = usage_charge(recovered_usage)
                row["charged_tokens"] = sum(a.get("charged_tokens", 0) for a in row["attempts"])
            verify_freeze()
            if process["status"] != "exited":
                raise EventFailure("E_PILOT_TRANSPORT:" + process["status"])
            answer = events.complete()
            usage = answer["usage"]
            if recovered_usage != usage:
                raise EventFailure("E_PILOT_USAGE_RECEIPT_MISMATCH")
            attempt.update(usage=usage, unknown_usage=False)
            if (usage["input_tokens"] > cfg["budgets"]["observed_input_tokens_per_request"]
                    or usage["output_tokens"]+usage["reasoning_output_tokens"] > cfg["budgets"]["charged_output_tokens_per_request"]
                    or row["charged_tokens"] > cfg["budgets"]["charged_tokens_per_cell"]):
                raise EventFailure("E_PILOT_OBSERVED_TOKEN_BUDGET")
            (attempt_dir / "RESPONSE.txt").write_text(answer["text"])
            save(attempt_dir / "RESPONSE.json", answer)
            observed = evaluate_isolated(stage, task, arm, folder / "CAPTURED_QUERY.json",
                                         attempt_dir / "RESPONSE.txt", attempt_dir / "validation", deadline)
            attempt["evaluation"] = observed
            verify_freeze()
            attempt["status"] = observed["status"]
            row.update(status=observed["status"], correct=observed["correct"],
                       hidden_evaluated=observed["hidden_evaluated"])
            if observed["hidden_evaluated"]:
                # Never place hidden data in a subsequent model request.
                break
            if observed["status"] in {"infrastructure_failure", "evaluation_infrastructure_failure",
                                       "experiment_wall_timeout"}:
                break
            if index+1 < cfg["budgets"]["attempts_per_cell"]:
                # Same V9 message/repair interface, complete raw public feedback.
                # No unavailable provider tokenizer is imitated with byte counts.
                messages = prompts.messages(initial, answer["text"], observed["public"]["feedback"])
                save(attempt_dir / "REPAIR.json", {"messages": messages, "code_truncated": False,
                     "public_cases_removed": False, "feedback_clipped": False,
                     "provider_token_preflight": "unavailable; next actual usage is checked after execution"})
        except Exception as exc:
            # The transport may have delivered events before its own final receipt
            # write failed. Keep those observed fields without certifying completeness.
            attempt["actual_generation_observed"] = events.turn_count > 0
            if attempt.get("observed_usage") is None and events.usage is not None:
                attempt["observed_usage"] = copy.deepcopy(events.usage)
                attempt["charged_tokens"] = usage_charge(events.usage)
                row["charged_tokens"] = sum(a.get("charged_tokens", 0) for a in row["attempts"])
            attempt["error"] = {"type": type(exc).__name__, "message": str(exc)}
            row["status"] = attempt["status"] = "terminal_protocol_or_runtime_failure"
            break
        finally:
            try:
                attempt["cwd_entries_after"] = sorted(path.name for path in cwd.iterdir())
                if (not attempt["cwd_entries_after"]
                        and attempt.get("process", {}).get("leader_reaped")
                        and attempt.get("process", {}).get("cleanup_confirmed")):
                    cwd.rmdir()
                    attempt["empty_cwd_removed"] = True
                else:
                    attempt["empty_cwd_removed"] = False
            except Exception as cleanup_error:
                attempt["cwd_cleanup_error"] = str(cleanup_error)
                row.update(correct=False, status="terminal_protocol_or_runtime_failure")
            save(attempt_dir / "ATTEMPT.json", attempt)
            save(folder / "CELL.json", row)
    if not row["correct"] and row["status"] == "response_rejected":
        row["status"] = "public_repairs_exhausted"
    save(folder / "CELL.json", row)
    return row


def experiment(output, review, controls):
    monotonic_start = time.monotonic()
    started = time.monotonic_ns()
    cfg = protocol()
    frozen = checked_review(review, controls)
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False)
    deadline = monotonic_start + cfg["budgets"]["experiment_wall_seconds"]
    result = {"schema": "hepta.agent-frontier-pilot.v1", "source_commit": SOURCE_COMMIT,
              "freeze": identity(HERE / "FREEZE.json"), "independent_review": identity(review),
              "controls": identity(controls), "model": cfg["model"], "started_unix_ns": time.time_ns(),
              "qualification": [], "main": [], "qualification_eligible": False,
              "status": "running", "requests": 0, "unknown_usage_requests": 0,
              "historical_results_reclassified": False}
    save(root / "PLAN.json", {"protocol": cfg, "freeze": frozen,
                             "benchmark_task_requests_before_plan": 0,
                             "bootstrap_requests_already_observed": 2, "bootstrap_cost_complete": False})
    save(root / "RESULT.json", result)
    try:
        for task, arm in support.cells("calibration"):
            row = run_cell("calibration", task, arm, root, deadline, cfg, frozen, result["qualification"])
            save(root / "RESULT.json", result)
            if not row["correct"]:
                result["status"] = "qualification_failed_stop_rule"
                break
        eligible = (len(result["qualification"]) == 3
                    and all(row["correct"] and row["hidden_evaluated"]
                            and all(a["usage"] is not None and a["process"]["status"] == "exited"
                                    for a in row["attempts"]) for row in result["qualification"]))
        if eligible:
            verify_freeze()
            result["qualification_eligible"] = True
            save(root / "QUALIFICATION.json", result)
            for task, arm in support.cells("main"):
                if deadline-time.monotonic() <= 0:
                    result["status"] = "experiment_wall_timeout"
                    break
                row = run_cell("main", task, arm, root, deadline, cfg, frozen, result["main"])
                save(root / "RESULT.json", result)
                if row["status"] in {"terminal_protocol_or_runtime_failure",
                                      "infrastructure_failure", "evaluation_infrastructure_failure", "experiment_wall_timeout"}:
                    result["status"] = "main_protocol_or_runtime_stop"
                    break
            else:
                result["status"] = "main_all_16_cells_attempted"
        verify_freeze()
        result["frozen_identity_unchanged"] = True
    except Exception as exc:
        result["status"] = "infrastructure_failure"
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        attempts = [a for row in result["qualification"]+result["main"] for a in row["attempts"]]
        known = [a["observed_usage"] for a in attempts if a.get("observed_usage") is not None]
        result.update(requests=sum(a.get("cli_launch_attempted", False)
                                   and a.get("request_started") is not False for a in attempts),
                      confirmed_cli_starts=sum(a.get("request_started") is True for a in attempts),
                      cli_start_outcome_unknown=sum(a.get("cli_launch_attempted", False)
                                                    and a.get("request_started") is None for a in attempts),
                      cli_launch_attempts=sum(a.get("cli_launch_attempted", False) for a in attempts),
                      requests_counter_scope="Confirmed or indeterminate CLI launches; indeterminate launch cost is never zeroed. Provider service acceptance is not separately attested.",
                      actual_generation_observed=sum(a.get("actual_generation_observed", False) for a in attempts),
                      unknown_usage_requests=sum(a.get("cli_launch_attempted", False)
                                                and a.get("request_started") is not False
                                                and a.get("unknown_usage", True) for a in attempts),
                      reported_input_tokens=sum(u["input_tokens"] for u in known),
                      reported_cached_input_tokens=sum(u["cached_input_tokens"] for u in known),
                      reported_output_tokens=sum(u["output_tokens"] for u in known),
                      reported_reasoning_output_tokens=sum(u["reasoning_output_tokens"] for u in known),
                      charged_tokens=sum(usage_charge(u) for u in known),
                      experiment_wall_ns=time.monotonic_ns()-started,
                      main_cells_started=len(result["main"]),
                      general_agent_productivity_proved=False, statistical_advantage_claimed=False,
                      historical_main_eligibility_inherited=False)
        result["total_reported_input_plus_output"] = (result["reported_input_tokens"]+result["reported_output_tokens"]
                                                      if not result["unknown_usage_requests"] else None)
        save(root / "RESULT.json", result)
    print(json.dumps({k:result[k] for k in ("status", "qualification_eligible", "requests",
                                          "unknown_usage_requests", "main_cells_started")}), flush=True)
    return 0 if result["status"] in {"qualification_failed_stop_rule", "main_all_16_cells_attempted"} else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    controls = sub.add_parser("controls")
    controls.add_argument("--output", required=True)
    run = sub.add_parser("run")
    run.add_argument("--output", required=True)
    run.add_argument("--review", required=True)
    run.add_argument("--controls", required=True)
    worker = sub.add_parser("_evaluate")
    worker.add_argument("--stage", choices=("calibration", "main"), required=True)
    worker.add_argument("--task", required=True)
    worker.add_argument("--arm", required=True)
    worker.add_argument("--query", required=True)
    worker.add_argument("--response")
    worker.add_argument("--reference", action="store_true")
    worker.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "controls":
        return prepare_controls(args.output)
    if args.command == "run":
        return experiment(args.output, args.review, args.controls)
    return evaluate_worker(args)


if __name__ == "__main__":
    raise SystemExit(main())
