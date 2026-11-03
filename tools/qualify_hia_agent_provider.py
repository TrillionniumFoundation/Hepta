#!/usr/bin/env python3
"""Provider diagnostics, separate from every frozen coding cohort.

Catalog metadata does not establish account entitlement. One availability
request is not a coding task. Known quota stops the rest of a probe batch;
missing usage stays unknown. No retry, account change or config edit occurs.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from hepta.hia_program_tools import decode_json, read_bounded
from tools.hia_agent_codex_transport import canonical, checked_usage, identity, run_owned, save
from tools.qualify_hia_agent_preflight import initialization_wire, process_ok, startup_response
from tools.qualify_hia_agent_repository_maintenance_v2 import CohortEvents

MAX_STREAM = 16 * 1024 * 1024
MAX_LINE = 1024 * 1024
PROMPT = b"Do not use tools. Reply with exactly the single word AVAILABLE. This is an availability probe, not a coding task.\n"


def event_lines(raw):
    if type(raw) is not bytes or len(raw) > MAX_STREAM:
        raise ValueError("bounded raw event stream required")
    lines = raw.splitlines()
    if len(lines) > 1024 or any(not line or len(line) > MAX_LINE for line in lines):
        raise ValueError("bounded nonempty JSONL events required")
    events = [decode_json(line) for line in lines]
    if any(type(e) is not dict for e in events):
        raise ValueError("object events required")
    return lines, events


def classify(process, raw):
    if type(process) is not dict or type(raw) is not bytes:
        raise ValueError("plain process record and raw bytes required")
    result = {"diagnosis": "protocol_failure", "available": False,
              "account_block_observed": False, "usage": None,
              "coding_task_requests": 0, "task_successes": 0,
              "stdout_sha256": sha256(raw).hexdigest(), "provider_messages": []}
    try:
        lines, events = event_lines(raw)
    except (ValueError, UnicodeError, RecursionError) as error:
        return {**result, "error": str(error)}
    result["generation_turn_observed"] = any(e.get("type") == "turn.started" for e in events)
    usages, messages = [], []
    for event in events:
        if event.get("type") == "turn.completed":
            try:
                usages.append(checked_usage(event.get("usage")))
            except ValueError:
                usages.append(None)
        message = (event.get("message") if event.get("type") == "error" else
                   event.get("error", {}).get("message")
                   if event.get("type") == "turn.failed" and type(event.get("error")) is dict else None)
        if type(message) is str and message not in messages:
            messages.append(message)
    result["usage"] = usages[0] if len(usages) == 1 else None
    result["provider_messages"] = messages
    unsupported = False
    for message in messages:
        if message.startswith("You've hit your usage limit."):
            result["account_block_observed"] = True
        try:
            error = decode_json(message)
        except (ValueError, UnicodeError, RecursionError):
            continue
        if (type(error) is dict and type(error.get("status")) is int and error["status"] == 400
                and type(error.get("error")) is dict and error["error"].get("code") == "model_not_found"):
            unsupported = True
    cleaned = all(process.get(k) is True for k in ("cleanup_confirmed", "leader_reaped", "streams_complete"))
    if not cleaned:
        result["diagnosis"] = "cleanup_uncertain"
    elif result["account_block_observed"]:
        result["diagnosis"] = "account_quota"
    elif unsupported:
        result["diagnosis"] = "unsupported_selector"
    elif not process_ok(process):
        result["diagnosis"] = "transport_or_provider_failure"
    else:
        try:
            parsed = CohortEvents([])
            for line in lines:
                parsed.line(line)
            answer = parsed.complete()
            if answer["text"] != "AVAILABLE" or answer["usage"] != result["usage"]:
                raise ValueError("availability sentinel or complete usage differs")
            result.update(diagnosis="available", available=True)
        except (ValueError, TypeError, RecursionError) as error:
            result["error"] = str(error)
    return result


def catalog_response(raw):
    lines, events = event_lines(raw)
    if len(events) != 2:
        raise ValueError("exactly one initialization ACK and one catalog response required")
    startup_response(lines[0])
    response = events[1]
    if (set(response) != {"id", "result"} or type(response["id"]) is not int or response["id"] != 2
            or type(response["result"]) is not dict or set(response["result"]) != {"data", "nextCursor"}):
        raise ValueError("unexpected catalog envelope")
    payload = response["result"]
    if payload["nextCursor"] is not None:
        raise ValueError("incomplete catalog page")
    rows = payload["data"]
    if type(rows) is not list or not 1 <= len(rows) <= 128:
        raise ValueError("bounded nonempty catalog required")
    models = []
    for row in rows:
        if (type(row) is not dict or any(type(row.get(k)) is not str or not 0 < len(row[k]) <= 128
                                        for k in ("id", "model")) or type(row.get("isDefault")) is not bool):
            raise ValueError("catalog identity or default flag is malformed")
        models.append({k: row[k] for k in ("id", "model", "isDefault")})
    if len({m["id"] for m in models}) != len(models) or len({m["model"] for m in models}) != len(models):
        raise ValueError("duplicate catalog identity")
    return {"models": models, "model_generation_requests": 0, "account_entitlement_attested": False}


def _catalog_worker(codex, logs):
    # Child inherits the outer run_owned process group and its hard deadline.
    child = subprocess.Popen([codex, "-c", "log_dir=" + json.dumps(logs), "app-server", "--stdio"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr.buffer)
    def send(raw):
        child.stdin.write(raw)
        child.stdin.flush()
    def receive():
        raw = child.stdout.readline(MAX_LINE + 1)
        if not raw or len(raw) > MAX_LINE or not raw.endswith(b"\n"):
            raise ValueError("incomplete or oversized catalog response")
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return raw
    initialize, initialized = initialization_wire().splitlines(keepends=True)
    send(initialize)
    startup_response(receive())
    send(initialized)
    send(canonical({"id": 2, "method": "model/list", "params": {}}) + b"\n")
    receive()
    child.stdin.close()
    while True:
        extra = child.stdout.read(65536)
        if not extra:
            break
        sys.stdout.buffer.write(extra)
        sys.stdout.buffer.flush()
    return child.wait(timeout=5)


def _guard(raw):
    _, events = event_lines(raw)
    event = events[0]
    kind = event.get("type")
    if kind in {"item.started", "item.updated", "item.completed"}:
        if type(event.get("item")) is not dict or event["item"].get("type") not in {"agent_message", "reasoning", "error"}:
            raise ValueError("tool or unknown availability item")
    elif kind not in {"thread.started", "turn.started", "turn.completed", "turn.failed", "error"}:
        raise ValueError("unknown availability event")


def probe_batch(codex, models, folder, seconds, *, execute=run_owned):
    if type(seconds) is not int or not 1 <= seconds <= 90:
        raise ValueError("probe deadline must be an integer in 1..90")
    if (type(models) is not list or not 1 <= len(models) <= 8
            or any(type(m) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", m) is None for m in models)
            or len(set(models)) != len(models)):
        raise ValueError("one to eight distinct explicit model selectors required")
    rows, stop = [], None
    for index, model in enumerate(models):
        if stop is not None:
            rows.append({"model": model, "attempted": False, "diagnosis": stop,
                         "usage": None, "available": False})
            continue
        work = folder / ("probe-" + str(index))
        work.mkdir()
        cwd = work / "cwd"
        cwd.mkdir()
        process = execute([codex, "exec", "--json", "--ephemeral", "--sandbox", "read-only",
                           "--skip-git-repo-check", "-c", 'model_reasoning_effort="low"', "-m", model, "-"],
                          cwd, work / "process", input_bytes=PROMPT, wall_seconds=seconds, on_line=_guard)
        result = classify(process, read_bounded(work / "process/stdout.raw", MAX_STREAM))
        row = {"model": model, "attempted": True, "process": process, **result}
        rows.append(row)
        save(work / "RESULT.json", row)
        if result["account_block_observed"]:
            stop = "not_attempted_after_account_quota"
        elif result["diagnosis"] == "cleanup_uncertain":
            stop = "not_attempted_after_uncertain_cleanup"
    return rows


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "_catalog-worker":
        return _catalog_worker(sys.argv[2], sys.argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("catalog", "probe", "replay"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--codex", type=Path)
    parser.add_argument("--models", nargs="+", default=[])
    parser.add_argument("--input", type=Path, nargs="+", default=[])
    parser.add_argument("--wall-seconds", type=int, default=60)
    args = parser.parse_args()
    if not 1 <= args.wall_seconds <= 90 or not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        parser.error("bounded deadline and fresh absolute output outside source required")
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.agent-provider-preflight.v1", "mode": args.mode,
              "status": "blocked", "coding_task_requests": 0, "task_successes": 0,
              "prior_results_replaced": False, "productivity_advantage_established": False}
    try:
        if args.mode == "replay":
            if not 1 <= len(args.input) <= 8:
                raise ValueError("one to eight diagnostic files required")
            rows = []
            for path in args.input:
                raw = read_bounded(path, 1024 * 1024)
                value = decode_json(raw)
                if type(value) is not dict or value.get("schema") != "hepta.hia.agent-availability-diagnostic.v1":
                    raise ValueError("unknown recorded diagnostic schema")
                if type(value.get("coding_task_requests")) is not int or value["coding_task_requests"] != 0:
                    raise ValueError("coding tasks cannot be relabelled as availability probes")
                if type(value.get("rows")) is not list or not 1 <= len(value["rows"]) <= 8:
                    raise ValueError("bounded diagnostic rows required")
                for row in value["rows"]:
                    if type(row.get("coding_task_requests")) is not int or row["coding_task_requests"] != 0:
                        raise ValueError("recorded row is not a zero-coding probe")
                    raw_events = b"".join(canonical(event) + b"\n" for event in row["events"])
                    rows.append({"model": row["model"], "input_sha256": sha256(raw).hexdigest(),
                                 **classify(row["process"], raw_events)})
            report.update(rows=rows, status="replayed", live_probe_performed=False,
                          scope="recorded JSON classification; no new entitlement or raw-file attestation")
        else:
            if args.codex is None or not args.codex.is_absolute() or not os.access(args.codex, os.X_OK):
                raise ValueError("absolute executable Codex path required")
            tool = identity(args.codex)
            report["cli_identity"] = tool
            if args.mode == "catalog":
                process = run_owned([sys.executable, "-B", str(Path(__file__).resolve()), "_catalog-worker",
                                     str(args.codex), str(args.output / "logs")],
                                    args.output, args.output / "process", wall_seconds=args.wall_seconds)
                report["process"] = process
                if not process_ok(process):
                    raise ValueError("catalog transport or cleanup failed")
                report.update(catalog_response(read_bounded(args.output / "process/stdout.raw", MAX_STREAM)), status="catalog_observed")
            else:
                rows = probe_batch(str(args.codex), args.models, args.output, args.wall_seconds)
                report.update(rows=rows, all_requested_models_available_at_probe=all(r["available"] for r in rows))
                report["status"] = "available" if report["all_requested_models_available_at_probe"] else "blocked"
            if identity(args.codex) != tool:
                raise ValueError("CLI identity changed during probe")
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as error:
        report.update(status="blocked", error={"type": type(error).__name__, "message": str(error)})
    save(args.output / "RESULT.json", report)
    print(json.dumps({k: report.get(k) for k in ("status", "mode", "coding_task_requests", "error")}, sort_keys=True))
    return 0 if report["status"] in {"replayed", "catalog_observed", "available"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
