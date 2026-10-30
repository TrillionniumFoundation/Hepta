"""Bounded owned-process and strict Codex JSONL transport.

The transport is preserved from the independently exercised frontier pilot;
there is no benchmark task, model answer, credential or old eligibility here.
"""
from __future__ import annotations
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
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
    return json.loads((ROOT / "benchmarks/hia_agent_public_tools/PROTOCOL.json").read_text())


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


def run_owned(argv, cwd, output, *, input_bytes=b"", wall_seconds, on_line=None,
              transport_config=None):
    """Own a new process group. Kill that group before reaping its leader."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    cfg = protocol() if transport_config is None else {"transport": copy.deepcopy(transport_config)}
    limits = cfg["transport"]
    if (type(limits) is not dict or set(limits) != {
            "stdout_limit_bytes", "stderr_limit_bytes", "max_jsonl_line_bytes"}
            or any(type(value) is not int or not 1 <= value <= 64 * 1024 * 1024
                   for value in limits.values())):
        raise ValueError("E_PILOT_TRANSPORT_LIMITS")
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
