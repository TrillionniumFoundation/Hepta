"""Record one authorized Codex repository-maintenance session without cost invention.

This is a separate event profile from hia_agent_fresh_session: repository command
and file-change items are expected here. The frozen argv is supplied by a
coordinator after checking the installed CLI. This module neither chooses an
account/model nor changes permissions. Importing or settling calls no provider.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
import re
import stat
from pathlib import Path
import subprocess
import tempfile
import time

from tools.hia_agent_codex_transport import EventFailure, identity, run_owned, save, strict_json

PROFILE = "hepta.hia.repository-agent-events.v1"
ITEM_TYPES = frozenset(("agent_message", "reasoning", "error", "command_execution",
                        "file_change", "todo_list", "mcp_tool_call", "web_search"))
LIMITS = {"stdout_limit_bytes": 32 * 1024 * 1024,
          "stderr_limit_bytes": 8 * 1024 * 1024,
          "max_jsonl_line_bytes": 4 * 1024 * 1024}
CANCEL_SCHEMA = "hepta.hia.repository-agent-cancel.v1"


def _read_cancel_request(output, registration_sha256):
    """Read an owner request; a foreign or malformed record is never a stop."""
    path = Path(output) / "CANCEL_REQUEST.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return {"valid": False, "reason": "request_read_error", "errno": exc.errno}
    try:
        with os.fdopen(fd, "rb") as stream:
            observed = os.fstat(stream.fileno())
            if not stat.S_ISREG(observed.st_mode) or observed.st_size > 4096:
                return {"valid": False, "reason": "invalid_request_file"}
            raw = stream.read(4097)
            if len(raw) > 4096:
                return {"valid": False, "reason": "request_size_changed"}
    except OSError as exc:
        return {"valid": False, "reason": "request_read_error", "errno": exc.errno}
    try:
        value = strict_json(raw)
    except (ValueError, UnicodeError, RecursionError):
        return {"valid": False, "reason": "invalid_request_json",
                "sha256": hashlib.sha256(raw).hexdigest()}
    valid = (type(value) is dict
             and set(value) == {"schema", "registration_sha256", "reason", "requested_unix_ns"}
             and value["schema"] == CANCEL_SCHEMA
             and value["registration_sha256"] == registration_sha256
             and type(value["reason"]) is str and 0 < len(value["reason"]) <= 512
             and type(value["requested_unix_ns"]) is int and value["requested_unix_ns"] > 0)
    return {"valid": valid, "request": value, "sha256": hashlib.sha256(raw).hexdigest(),
            "reason": "bound_original_registration" if valid else "invalid_request_binding"}


def request_trial_cancel(output, reason):
    """Request a stop by exact trial identity; only its original owner signals it."""
    directory = Path(output).resolve(strict=True)
    if type(reason) is not str or not 0 < len(reason) <= 512:
        raise ValueError("E_HIA_REPOSITORY_CANCEL_REASON")
    registration = (directory / "REGISTRATION.original.json").read_bytes()
    registration_sha = hashlib.sha256(registration).hexdigest()
    trial = strict_json((directory / "TRIAL.json").read_bytes())
    if (type(trial) is not dict
            or trial.get("schema") != "hepta.hia.repository-agent-trial.v1"
            or trial.get("registration", {}).get("sha256") != registration_sha):
        raise ValueError("E_HIA_REPOSITORY_CANCEL_TRIAL_BINDING")
    existing = _read_cancel_request(directory, registration_sha)
    if existing is not None:
        if not existing["valid"]:
            raise ValueError("E_HIA_REPOSITORY_CANCEL_EXISTING_REQUEST")
        return {"status": "already_requested", "request": existing,
                "effect": "observe original TRIAL.json; a request is not confirmed termination"}
    if trial.get("status") != "preflight":
        return {"status": "already_terminal", "trial_status": trial.get("status"),
                "effect": "no request written; no process signalled"}
    request = {"schema": CANCEL_SCHEMA, "registration_sha256": registration_sha,
               "reason": reason, "requested_unix_ns": time.time_ns()}
    raw = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    # Publish complete bytes atomically and without replacement. The temporary
    # name belongs only to this invocation; readers never see a partial request.
    descriptor, temporary_name = tempfile.mkstemp(prefix=".hia-cancel-", dir=directory)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, directory / "CANCEL_REQUEST.json")
        except FileExistsError:
            existing = _read_cancel_request(directory, registration_sha)
            if existing is None or not existing["valid"]:
                raise ValueError("E_HIA_REPOSITORY_CANCEL_EXISTING_REQUEST")
            return {"status": "already_requested", "request": existing,
                    "effect": "observe original TRIAL.json; a request is not confirmed termination"}
    finally:
        temporary.unlink(missing_ok=True)
    return {"status": "requested", "request": request, "sha256": hashlib.sha256(raw).hexdigest(),
            "effect": "cooperative request only; no process signalled by this command"}


class RepositoryEvents:
    """Original CLI observations, not authority to execute arbitrary actions."""
    def __init__(self, allowed_mcp_servers=()):
        self.allowed_mcp_servers = frozenset(allowed_mcp_servers)
        self.events = []
        self.threads = self.turns = self.terminals = 0

    def line(self, raw):
        event = strict_json(raw)
        if type(event) is not dict:
            raise EventFailure("E_HIA_REPOSITORY_EVENT_SHAPE")
        self.events.append(event)
        kind = event.get("type")
        if kind == "thread.started":
            self.threads += 1
            if self.threads != 1 or self.turns:
                raise EventFailure("E_HIA_REPOSITORY_THREAD_SEQUENCE")
        elif kind == "turn.started":
            self.turns += 1
            if self.threads != 1 or self.turns != 1:
                raise EventFailure("E_HIA_REPOSITORY_TURN_SEQUENCE")
        elif kind in ("turn.completed", "turn.failed"):
            self.terminals += 1
            if self.turns != 1 or self.terminals != 1:
                raise EventFailure("E_HIA_REPOSITORY_TERMINAL_SEQUENCE")
        elif kind in ("item.started", "item.updated", "item.completed"):
            item = event.get("item")
            if type(item) is not dict or self.turns != 1 or self.terminals:
                raise EventFailure("E_HIA_REPOSITORY_ITEM_SEQUENCE")
            if item.get("type") not in ITEM_TYPES:
                raise EventFailure("E_HIA_REPOSITORY_UNKNOWN_ITEM")
            if (item.get("type") == "mcp_tool_call"
                    and item.get("server") not in self.allowed_mcp_servers):
                raise EventFailure("E_HIA_REPOSITORY_FOREIGN_MCP_SERVER")
        elif kind != "error":
            raise EventFailure("E_HIA_REPOSITORY_UNKNOWN_EVENT")


def _valid_usage(usage):
    if type(usage) is not dict:
        return False
    if any(type(usage.get(k)) is not int or usage[k] < 0
           for k in ("input_tokens", "output_tokens")):
        return False
    for key in ("cached_input_tokens", "cache_write_input_tokens", "reasoning_output_tokens"):
        if key in usage and (type(usage[key]) is not int or usage[key] < 0):
            return False
    return not ("cached_input_tokens" in usage and usage["cached_input_tokens"] > usage["input_tokens"])


def settle_stream(path, *, allowed_mcp_servers=(), streams_complete, transport_receipt=None):
    """Reparse every original line, including usage following a rejected item.

    A nonzero process return does not erase reported usage. Missing, malformed
    or multiple terminal usage records remain unknown; cached/reasoning fields
    are retained but never added again to input+output. This is not a bill.
    """
    source = Path(path).resolve(strict=True)
    raw_stream = source.read_bytes()
    stream_identity = {"path": str(source), "sha256": hashlib.sha256(raw_stream).hexdigest(),
                       "bytes": len(raw_stream)}
    capture = {"pipe_eof_attested": streams_complete is True,
               "basis": "caller_attestation", "complete": streams_complete is True}
    if transport_receipt is not None:
        # EOF only describes drained pipes. The transport can reach EOF after
        # its byte cap dropped later events, including another usage record.
        # Bind the very bytes parsed here to the original transport inventory.
        saved = transport_receipt.get("files", {}).get("stdout.raw", {})
        observed = transport_receipt.get("bytes_observed", {}).get("stdout")
        same_bytes = (type(saved) is dict and type(saved.get("bytes")) is int
                      and saved["bytes"] == len(raw_stream)
                      and saved.get("sha256") == stream_identity["sha256"])
        untruncated = type(observed) is int and observed == len(raw_stream)
        capture.update(basis="original_transport_receipt", transport_stdout_matches=same_bytes,
                       observed_stdout_bytes=observed, untruncated=untruncated,
                       complete=bool(streams_complete is True
                                     and transport_receipt.get("streams_complete") is True
                                     and same_bytes and untruncated))
    parser, errors, terminals, failures = RepositoryEvents(allowed_mcp_servers), [], [], []
    item_ids = {kind: set() for kind in ITEM_TYPES}
    unkeyed = invalid_json_lines = 0
    for number, raw in enumerate(raw_stream.splitlines(), 1):
        try:
            event = strict_json(raw)
        except (ValueError, UnicodeError, RecursionError) as exc:
            invalid_json_lines += 1
            errors.append({"line": number, "error": type(exc).__name__,
                           "raw_sha256": hashlib.sha256(raw).hexdigest()})
            continue
        if type(event) is dict and event.get("type") in ("turn.completed", "turn.failed"):
            terminals.append({"line": number, "event_type": event["type"],
                              "usage": event.get("usage"),
                              "raw_sha256": hashlib.sha256(raw).hexdigest()})
        item = event.get("item") if type(event) is dict else None
        if type(item) is dict:
            if type(item.get("id")) is str:
                if type(item.get("type")) is str and item["type"] in item_ids:
                    item_ids[item["type"]].add(item["id"])
            else:
                unkeyed += 1
            if (item.get("status") in ("failed", "cancelled")
                    or type(item.get("exit_code")) is int and item["exit_code"] != 0):
                failures.append({"line": number, "raw_sha256": hashlib.sha256(raw).hexdigest(),
                                 "item_id": item.get("id"), "type": item.get("type"),
                                 "status": item.get("status"), "exit_code": item.get("exit_code"),
                                 "error": item.get("error")})
        try:
            parser.line(raw)
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            errors.append({"line": number, "error": str(exc),
                           "raw_sha256": hashlib.sha256(raw).hexdigest()})
    usable = bool(capture["complete"] and invalid_json_lines == 0 and len(terminals) == 1
                  and _valid_usage(terminals[0]["usage"]))
    usage = terminals[0]["usage"] if usable else None
    counts = {kind: len(item_ids[kind]) for kind in sorted(ITEM_TYPES)}
    return {"event_profile": PROFILE, "raw_stream": stream_identity, "capture": capture,
            "parse_errors": errors, "invalid_json_lines": invalid_json_lines, "terminal_observations": terminals,
            "reported_usage_settled": usable, "reported_usage": usage,
            "input_plus_output_tokens": None if usage is None else usage["input_tokens"] + usage["output_tokens"],
            "auxiliary_usage": {k: None if usage is None else usage.get(k) for k in
                                ("cached_input_tokens", "cache_write_input_tokens", "reasoning_output_tokens")},
            "auxiliary_counters_added_again": False,
            "unique_item_counts": counts, "unidentified_item_events": unkeyed,
            "failed_or_cancelled_items": failures,
            "failure_count_scope": "every original failed/cancelled/nonzero item event; repeated item IDs are retained, not added to token usage",
            "provider_http_request_count": None, "billed_cost": None,
            "tariff_or_invoice": None, "full_monetary_cost_complete": False,
            "tool_count_scope": "unique original CLI item IDs per item type; reused IDs can appear in multiple types; not provider or server physical requests"}


def _git(cwd, *args):
    result = subprocess.run(["git", "-C", str(cwd), *args], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if result.returncode:
        raise ValueError("E_HIA_REPOSITORY_GIT_READ: " + result.stderr.decode("utf-8", "replace")[:512])
    if len(result.stdout) > 32 * 1024 * 1024:
        raise ValueError("E_HIA_REPOSITORY_SNAPSHOT_TOO_LARGE")
    return result.stdout


def _snapshot_new_file(cwd, relative, remaining):
    """Read a bounded ordinary file through retained non-symlink directories."""
    with ExitStack() as opened:
        directory = os.open(cwd, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.callback(os.close, directory)
        for part in relative.parts[:-1]:
            directory = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
            opened.callback(os.close, directory)
        descriptor = os.open(relative.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                             dir_fd=directory)
        opened.callback(os.close, descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("E_HIA_REPOSITORY_UNTRACKED_NONREGULAR")
        if before.st_size > remaining:
            raise ValueError("E_HIA_REPOSITORY_UNTRACKED_LIMIT")
        # Bound actual bytes, rather than trusting a size observed before the
        # read. A growing file cannot make the original snapshot exceed its cap.
        body = bytearray()
        while len(body) <= remaining:
            block = os.read(descriptor, min(65536, remaining + 1 - len(body)))
            if not block:
                break
            body.extend(block)
        if len(body) > remaining:
            raise ValueError("E_HIA_REPOSITORY_UNTRACKED_LIMIT")
        after = os.fstat(descriptor)
        fingerprint = lambda value: (value.st_dev, value.st_ino, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(body) != before.st_size or fingerprint(before) != fingerprint(after):
            raise ValueError("E_HIA_REPOSITORY_UNTRACKED_CHANGED")
        return bytes(body)


def snapshot_repository(cwd, directory, *, baseline):
    """Keep the exact tracked diff and bytes of new ordinary files."""
    cwd, directory = Path(cwd).resolve(strict=True), Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    head = _git(cwd, "rev-parse", "HEAD").decode().strip()
    tree = _git(cwd, "rev-parse", "HEAD^{tree}").decode().strip()
    status = _git(cwd, "status", "--porcelain=v1", "--untracked-files=all")
    patch = _git(cwd, "diff", "--no-ext-diff", "--no-textconv", "--binary", baseline, "--")
    (directory / "status.raw").write_bytes(status)
    (directory / "tracked.patch").write_bytes(patch)
    untracked = _git(cwd, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    new_files, total = [], 0
    for raw_name in untracked:
        if not raw_name:
            continue
        name = raw_name.decode("utf-8", "strict")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("E_HIA_REPOSITORY_UNTRACKED_PATH")
        # Any source or parent symlink would make the capture follow another scope.
        if any((cwd / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)):
            raise ValueError("E_HIA_REPOSITORY_UNTRACKED_SYMLINK")
        body = _snapshot_new_file(cwd, relative, 32 * 1024 * 1024 - total)
        total += len(body)
        destination = directory / "new-files" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        new_files.append({"path": name, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)})
    return {"head": head, "tree": tree, "clean": not bool(status),
            "status": identity(directory / "status.raw"), "tracked_patch": identity(directory / "tracked.patch"),
            "new_files": new_files, "new_files_total_bytes": total}


def run_trial(registration_path, output):
    """One explicit launch; never retries or upgrades an outcome to task success."""
    started, started_unix = time.monotonic_ns(), time.time_ns()
    registration_path, output = Path(registration_path).resolve(strict=True), Path(output).resolve()
    raw_registration = registration_path.read_bytes()
    reg = strict_json(raw_registration)
    required = {"schema", "argv", "repository", "source_commit", "source_tree", "public_prompt",
                "public_prompt_sha256", "executable_sha256", "requested_model", "requested_profile",
                "wall_limit_seconds", "token_review_limit", "allowed_mcp_servers", "session_freshness_attestation"}
    if type(reg) is not dict or set(reg) != required or reg["schema"] != "hepta.hia.repository-agent-launch.v1":
        raise ValueError("E_HIA_REPOSITORY_REGISTRATION")
    argv, cwd = reg["argv"], Path(reg["repository"]).resolve(strict=True)
    if (type(argv) is not list or not argv or any(type(x) is not str for x in argv)
            or not Path(argv[0]).is_absolute() or not reg["requested_model"]
            or type(reg["wall_limit_seconds"]) is not int or not 1 <= reg["wall_limit_seconds"] <= 1800
            or type(reg["token_review_limit"]) is not int or reg["token_review_limit"] <= 0
            or type(reg["allowed_mcp_servers"]) is not list
            or any(type(x) is not str for x in reg["allowed_mcp_servers"])
            or any(type(reg[k]) is not str or re.fullmatch(r"[0-9a-f]{40}", reg[k]) is None
                   for k in ("source_commit", "source_tree"))
            or any(type(reg[k]) is not str or re.fullmatch(r"[0-9a-f]{64}", reg[k]) is None
                   for k in ("public_prompt_sha256", "executable_sha256"))
            or output == cwd or cwd in output.parents):
        raise ValueError("E_HIA_REPOSITORY_FROZEN_LAUNCH")
    if identity(argv[0])["sha256"] != reg["executable_sha256"]:
        raise ValueError("E_HIA_REPOSITORY_EXECUTABLE_CHANGED")
    prompt = Path(reg["public_prompt"]).read_bytes()
    if len(prompt) > 1024 * 1024 or hashlib.sha256(prompt).hexdigest() != reg["public_prompt_sha256"]:
        raise ValueError("E_HIA_REPOSITORY_PROMPT_CHANGED")
    output.mkdir(parents=True, exist_ok=False)
    (output / "REGISTRATION.original.json").write_bytes(raw_registration)
    (output / "PUBLIC_PROMPT.original.txt").write_bytes(prompt)
    record = {"schema": "hepta.hia.repository-agent-trial.v1", "status": "preflight",
              "registration": identity(output / "REGISTRATION.original.json"),
              "started_unix_ns": started_unix, "requested_model": reg["requested_model"],
              "requested_profile": reg["requested_profile"], "model_identity_attested": False,
              "session_freshness_attestation": reg["session_freshness_attestation"],
              "session_freshness_independently_verified": False,
              "wall_limit_seconds": reg["wall_limit_seconds"], "token_review_limit": reg["token_review_limit"],
              "hard_mid_turn_token_limit": False, "cli_sessions_started": 0,
              "task_acceptance": "HOLD", "native_verification_observed": False,
              "adoption_observed": False, "consumer_observed": False,
              "full_cost_complete": False, "economic_advantage_established": False,
              "isolation_scope": "event profile only; effective CLI config and filesystem isolation need independent evidence"}
    save(output / "TRIAL.json", record)
    def cancellation_requested():
        observation = _read_cancel_request(output, record["registration"]["sha256"])
        if observation is not None:
            record["cancellation_observation"] = observation
        return bool(observation is not None and observation["valid"])
    try:
        before = snapshot_repository(cwd, output / "before", baseline=reg["source_commit"])
        record["before"] = before
        if not before["clean"] or before["head"] != reg["source_commit"] or before["tree"] != reg["source_tree"]:
            raise ValueError("E_HIA_REPOSITORY_BASELINE_CHANGED")
        if cancellation_requested():
            record["status"] = "cancelled_before_launch"
            return record
        deadline = started_unix + reg["wall_limit_seconds"] * 1_000_000_000
        remaining = reg["wall_limit_seconds"] - (time.monotonic_ns() - started) / 1e9
        events = RepositoryEvents(reg["allowed_mcp_servers"])
        process = run_owned(argv, cwd, output / "provider", input_bytes=prompt,
                            wall_seconds=remaining, absolute_deadline_unix_ns=deadline,
                            on_line=events.line, transport_limits=LIMITS,
                            stop_requested=cancellation_requested)
        record["process"] = process
        record["cli_sessions_started"] = int("pid" in process)
        record["metering"] = settle_stream(output / "provider/stdout.raw",
                                           allowed_mcp_servers=reg["allowed_mcp_servers"],
                                           streams_complete=process["streams_complete"],
                                           transport_receipt=process)
        total = record["metering"]["input_plus_output_tokens"]
        record["within_token_review_limit"] = None if total is None else total <= reg["token_review_limit"]
        record["executable_unchanged"] = identity(argv[0])["sha256"] == reg["executable_sha256"]
        record["after"] = snapshot_repository(cwd, output / "after", baseline=reg["source_commit"])
        record["status"] = "observed"
    except BaseException as exc:
        record["status"] = "failed_or_unknown"
        record["error"] = {"type": type(exc).__name__, "message": str(exc)[:1024]}
        raise
    finally:
        record["whole_trial_wall_ns"] = time.monotonic_ns() - started
        record["wall_accounting"] = "whole trial includes preflight, provider and final snapshot; nested process/tool times are not added"
        save(output / "TRIAL.json", record)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--registration", required=True)
    run.add_argument("--output", required=True)
    cancel = commands.add_parser("cancel")
    cancel.add_argument("--output", required=True)
    cancel.add_argument("--reason", required=True)
    settle = commands.add_parser("settle")
    settle.add_argument("--stdout", required=True)
    settle.add_argument("--streams-complete", action="store_true")
    settle.add_argument("--process-receipt")
    settle.add_argument("--allowed-mcp-server", action="append", default=[])
    settle.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.command == "run":
        result = run_trial(args.registration, args.output)
    elif args.command == "cancel":
        result = request_trial_cancel(args.output, args.reason)
    else:
        target = Path(args.output)
        if target.exists():
            raise ValueError("E_HIA_REPOSITORY_OUTPUT_EXISTS")
        result = settle_stream(args.stdout, allowed_mcp_servers=args.allowed_mcp_server,
                               streams_complete=args.streams_complete,
                               transport_receipt=None if args.process_receipt is None else
                               strict_json(Path(args.process_receipt).read_bytes()))
        save(target, result)
    print(json.dumps({"status": result.get("status", "settled"),
                      "task_acceptance": result.get("task_acceptance", "HOLD"),
                      "full_cost_complete": False}))


if __name__ == "__main__":
    main()
