"""Separate 20261030b dialogue with a validated passive metadata notification.

One ephemeral thread per cell. The host sends only public prompts/feedback.
This module never executes a model-selected tool or evaluates hidden cases.
The process ownership controls do not claim hermetic isolation of the service.
"""
from __future__ import annotations

from collections import deque
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import threading
import time

from tools.hia_agent_codex_transport import canonical, identity, save, strict_json

USAGE_FIELDS = ("inputTokens", "cachedInputTokens", "cacheWriteInputTokens",
                "outputTokens", "reasoningOutputTokens", "totalTokens")
REQUIRED_USAGE_FIELDS = frozenset(USAGE_FIELDS) - {"cacheWriteInputTokens"}


class DialogueRejected(ValueError):
    pass


def usage_record(value):
    if type(value) is not dict or not REQUIRED_USAGE_FIELDS <= set(value):
        raise DialogueRejected("missing provider usage fields")
    result = {}
    for key in USAGE_FIELDS:
        item = value.get(key)
        if (key in REQUIRED_USAGE_FIELDS and item is None) or (item is not None and (type(item) is not int or item < 0)):
            raise DialogueRejected("invalid provider usage count: " + key)
        result[key] = item
    if result["cachedInputTokens"] > result["inputTokens"]:
        raise DialogueRejected("cached input is not a subset of input")
    return result


def usage_delta(previous, current):
    result = {}
    for key in USAGE_FIELDS:
        before, after = previous.get(key), current.get(key)
        if before is None or after is None:
            result[key] = None
        elif after < before:
            raise DialogueRejected("cumulative provider usage decreased: " + key)
        else:
            result[key] = after - before
    return result




def moderation_notification(event, *, expected_thread, expected_turn=None, allowed_turns=None):
    """Validate passive local-schema metadata; never execute or answer it."""
    if (type(event) is not dict or event.get("method")!="turn/moderationMetadata"
            or "id" in event):
        raise DialogueRejected("moderation metadata must be a notification, never a server request")
    params=event.get("params")
    if (type(params) is not dict or not {"metadata","threadId","turnId"}<=set(params)
            or type(params["threadId"]) is not str or type(params["turnId"]) is not str
            or expected_thread is None or params["threadId"]!=expected_thread):
        raise DialogueRejected("moderation metadata lacks its registered thread binding")
    if expected_turn is not None and params["turnId"]!=expected_turn:
        raise DialogueRejected("moderation metadata crosses the active turn")
    if allowed_turns is not None and params["turnId"] not in allowed_turns:
        raise DialogueRejected("moderation metadata has no acknowledged turn")
    # Local schema deliberately leaves metadata opaque JSON. Serialize solely
    # to bind retained evidence and reject non-JSON numeric extensions.
    digest=sha256(canonical(params["metadata"])).hexdigest()
    return {"method":"turn/moderationMetadata","thread_id":params["threadId"],
        "turn_id":params["turnId"],"metadata_sha256":digest,
        "informational_only":True,"authority_granted":False,
        "response_sent":False,"moderation_or_hooks_disabled":False}


def audit_raw_stdout(path, *, expected_thread=None):
    """Final complete-stream tool/identity audit, including queued tail frames.

    This trusts the service's event telemetry. It does not prove that an absent
    event means no unreported host or provider access occurred.
    """
    forbidden=[]; errors=[]; usage=[]; known_turns=set(); passive_pending=[]; passive=[]
    with Path(path).open("rb") as stream:
        for number,raw in enumerate(stream,1):
            try:
                if not raw.endswith(b"\n"):raise DialogueRejected("incomplete final JSONL frame")
                event=strict_json(raw)
                if type(event) is not dict:raise DialogueRejected("non-object final frame")
                method=event.get("method")
                params=event.get("params",{})
                response=event.get("result")
                if type(response) is dict and type(response.get("turn")) is dict and type(response["turn"].get("id")) is str:
                    known_turns.add(response["turn"]["id"])
                if method=="turn/moderationMetadata":passive_pending.append((number,event))
                if method is not None and "id" in event:
                    forbidden.append({"line":number,"kind":"server_request","method":method})
                if method in {"item/started","item/completed"}:
                    kind=params.get("item",{}).get("type") if type(params) is dict else None
                    if kind not in {"userMessage","agentMessage","reasoning","hookPrompt"}:
                        forbidden.append({"line":number,"kind":"direct_tool_or_unregistered_item","item_type":kind})
                if type(params) is dict and expected_thread is not None and "threadId" in params and params["threadId"]!=expected_thread:
                    errors.append({"line":number,"error":"cross-thread final stream"})
                if method=="thread/tokenUsage/updated" and type(params) is dict:
                    record=params.get("tokenUsage",{})
                    usage.append({"line":number,"total":usage_record(record.get("total")),
                                  "last":usage_record(record.get("last"))})
            except Exception as error:
                errors.append({"line":number,"error":type(error).__name__+": "+str(error)})
    for number,event in passive_pending:
        try:passive.append({"line":number,**moderation_notification(event,expected_thread=expected_thread,allowed_turns=known_turns)})
        except Exception as error:errors.append({"line":number,"error":type(error).__name__+": "+str(error)})
    return {"schema":"hepta.agent.v8b.full-stream-admission.v1",
        "eligible":not forbidden and not errors,"forbidden_activity":forbidden,"errors":errors,
        "raw_usage_events":usage,"passive_moderation_notifications":passive,"service_telemetry_trusted":True,"os_isolation_proved":False,
        "scope":"all retained stdout frames, including frames after turn/completed"}


class AppServerDialogue:
    """One owned, non-resumable subprocess and explicit-turn state machine."""
    def __init__(self, *, executable, cwd, output, cfg, deadline, argv=None):
        if (threading.active_count() != 1 or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
                or not hasattr(os, "WNOWAIT")):
            raise DialogueRejected("single-owner waitid admission required")
        if not math.isfinite(deadline) or deadline <= time.monotonic():
            raise DialogueRejected("expired cell before process launch")
        self.cfg = cfg
        self.deadline = deadline
        self.root = Path(output)
        self.root.mkdir(parents=True, exist_ok=False)
        self.cwd = Path(cwd)
        self.thread_id = None
        self.next_id = 0
        self.next_turn = 0
        self.pending = deque()
        self.notifications = []
        self.usage_total = {key: 0 for key in USAGE_FIELDS}
        self.closed = False
        self.failed = False
        self.selector = selectors.DefaultSelector()
        self.buffer = b""
        self.streams = {name: (self.root / (name + ".raw")).open("xb")
                        for name in ("stdin", "stdout", "stderr")}
        default_argv=[str(executable)]
        for feature in cfg.get("disabled_features",[]):default_argv.extend(["--disable",feature])
        default_argv.extend(["app-server","--stdio"])
        self.record = {"schema": "hepta.agent.v8-owned-dialogue.v1",
                       "argv": argv or default_argv,
                       "requested_disabled_features":list(cfg.get("disabled_features",[])),
                       "tool_isolation_claim":False,
                       "cwd": str(self.cwd), "started_unix_ns": time.time_ns(),
                       "status": "starting", "bytes": {"stdin": 0, "stdout": 0, "stderr": 0},
                       "observed_bytes": {"stdin": 0, "stdout": 0, "stderr": 0},
                       "generation_turns_started": 0, "cleanup_confirmed": False,
                       "leader_reaped": False, "signal_attempted": False,
                       "ownership_uncertain": False, "replay_permitted": False}
        self.process = None
        before = time.monotonic_ns()
        try:
            try:
                os.waitid(os.P_PID, os.getpid(), os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                pass
            else:
                raise DialogueRejected("waitid capability probe returned a self child")
            self.process = subprocess.Popen(self.record["argv"], cwd=self.cwd,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                bufsize=0, start_new_session=True)
            self.record.update(pid=self.process.pid, pgid=self.process.pid, status="launched")
            for name in ("stdin", "stdout", "stderr"):
                os.set_blocking(getattr(self.process, name).fileno(), False)
            for name in ("stdout", "stderr"):
                self.selector.register(getattr(self.process, name), selectors.EVENT_READ, name)
            initialized = self.rpc("initialize", {"clientInfo": {
                "name": "hepta-prospective-v8-dialogue", "version": "1"},
                "capabilities": {"experimentalApi": True}},
                deadline=min(deadline, time.monotonic() + 30))
            self.send({"method": "initialized"}, deadline=min(deadline, time.monotonic() + 5))
            self.record["initialize_response"] = initialized
            self.record["startup_wall_ns"] = time.monotonic_ns() - before
            save(self.root / "PROCESS.json", self.record)
        except BaseException:
            self.failed = True
            self.close()
            raise

    def _check_time(self, deadline):
        if self.closed or self.failed:
            raise DialogueRejected("closed or failed dialogue cannot resume")
        if time.monotonic() >= min(deadline, self.deadline):
            raise TimeoutError("bounded dialogue deadline exhausted")

    def _observe_owner(self):
        if self.record["leader_reaped"] or self.record["ownership_uncertain"]:
            raise DialogueRejected("process ownership already lost")
        try:
            return os.waitid(os.P_PID, self.process.pid,
                             os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except BaseException:
            self.record["ownership_uncertain"] = True
            raise

    def send(self, value, *, deadline):
        raw = canonical(value) + b"\n"
        if len(raw) > self.cfg["stream_limits"]["line_bytes"]:
            raise DialogueRejected("outbound RPC exceeds line budget")
        self.streams["stdin"].write(raw)
        self.streams["stdin"].flush()
        self.record["bytes"]["stdin"] += len(raw)
        self.record["observed_bytes"]["stdin"] += len(raw)
        offset = 0
        while offset < len(raw):
            self._check_time(deadline)
            try:
                count = os.write(self.process.stdin.fileno(), raw[offset:])
            except BlockingIOError:
                self._read(min(deadline, time.monotonic() + 0.05), empty_ok=True)
                continue
            if count <= 0:
                raise DialogueRejected("closed app-server input")
            offset += count

    def _read(self, deadline, *, empty_ok=False):
        self._check_time(deadline)
        events = self.selector.select(min(0.05, max(0.0, deadline - time.monotonic())))
        for key, _ in events:
            name = key.data
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            self.record["observed_bytes"][name] += len(chunk)
            limit = self.cfg["stream_limits"][name + "_bytes_per_cell"]
            remaining = max(0, limit - self.record["bytes"][name])
            retained = chunk[:remaining]
            self.streams[name].write(retained)
            self.streams[name].flush()
            self.record["bytes"][name] += len(retained)
            if len(retained) != len(chunk):
                self.record["raw_stream_truncated_at_registered_cap"] = True
                raise DialogueRejected(name + " stream exceeds registered cap")
            if name == "stdout":
                self.buffer += chunk
                while b"\n" in self.buffer:
                    line, self.buffer = self.buffer.split(b"\n", 1)
                    if len(line) > self.cfg["stream_limits"]["line_bytes"]:
                        raise DialogueRejected("JSONL line exceeds registered cap")
                    event = strict_json(line)
                    if type(event) is not dict:
                        raise DialogueRejected("non-object JSON-RPC event")
                    self.pending.append(event)
                if len(self.buffer) > self.cfg["stream_limits"]["line_bytes"]:
                    raise DialogueRejected("unterminated oversized JSONL line")
        if not self.selector.get_map():
            raise DialogueRejected("app-server output closed before lifecycle completion")
        if not empty_ok and not self.pending and self._observe_owner() is not None:
            raise DialogueRejected("app-server exited before lifecycle completion")

    def receive(self, *, deadline):
        while not self.pending:
            self._read(deadline)
        return self.pending.popleft()

    def rpc(self, method, params, *, deadline):
        self.next_id += 1
        request_id = self.next_id
        self.send({"id": request_id, "method": method, "params": params}, deadline=deadline)
        while True:
            event = self.receive(deadline=deadline)
            if "method" in event:
                if "id" in event:
                    raise DialogueRejected("unregistered server request: " + str(event["method"]))
                self.notifications.append(event)
                continue
            if event.get("id") != request_id or ("result" in event) == ("error" in event):
                raise DialogueRejected("mismatched or malformed RPC response")
            if "error" in event:
                raise DialogueRejected("app-server RPC failed: " + str(event["error"]))
            return event["result"]

    def start_thread(self, model):
        if self.thread_id is not None:
            raise DialogueRejected("a dialogue cannot start a second thread")
        started = time.monotonic_ns()
        result = self.rpc("thread/start", {"model": model, "cwd": str(self.cwd),
            "sandbox": "read-only", "ephemeral": True, "environments": [],
            "allowProviderModelFallback": False,"config":self.cfg.get("thread_config",{})},
            deadline=min(self.deadline, time.monotonic() + 30))
        thread = result.get("thread")
        if (type(thread) is not dict or type(thread.get("id")) is not str
                or result.get("model") != model or thread.get("turns", []) != []):
            raise DialogueRejected("unexpected model, thread identity or inherited history")
        if result.get("sandbox", {}).get("type") != "readOnly":
            raise DialogueRejected("thread did not retain requested read-only sandbox")
        self.thread_id = thread["id"]
        self.record["thread_start_response"] = result
        self.record["thread_start_wall_ns"] = time.monotonic_ns() - started
        save(self.root / "PROCESS.json", self.record)
        return result

    def turn(self, text):
        if self.thread_id is None or type(text) is not str:
            raise DialogueRejected("one started thread and textual public input required")
        if self.next_turn >= self.cfg["max_turns_per_cell"]:
            raise DialogueRejected("explicit-turn limit exhausted")
        index = self.next_turn
        self.next_turn += 1
        deadline = min(self.deadline, time.monotonic() + self.cfg["max_turn_wall_seconds"])
        before = time.monotonic_ns()
        record = {"index": index, "public_input_sha256": sha256(text.encode()).hexdigest(),
                  "status": "started", "usage_events": [], "messages": [],
                  "item_ids": [], "notification_methods": [], "usage_complete": False}
        save(self.root / f"turn-{index}.json", record)
        # Any previous-turn usage must already have been retained. Notifications
        # remain raw, but cannot become this turn's answer or usage.
        self.notifications.clear()
        try:
            response = self.rpc("turn/start", {"threadId": self.thread_id,
                "input": [{"type": "text", "text": text, "text_elements": []}],
                "environments": []}, deadline=deadline)
            turn = response.get("turn")
            if type(turn) is not dict or type(turn.get("id")) is not str:
                raise DialogueRejected("missing started turn identity")
            turn_id = turn["id"]
            record["turn_id"] = turn_id
            self.record["generation_turns_started"] += 1
            queued = deque(self.notifications)
            self.notifications.clear()
            completed = False
            seen_items = set()
            while not completed:
                event = queued.popleft() if queued else self.receive(deadline=deadline)
                if "method" not in event:
                    raise DialogueRejected("unsolicited RPC response during model turn")
                method, params = event["method"], event.get("params", {})
                record["notification_methods"].append(method)
                if "id" in event:
                    raise DialogueRejected("model requested a forbidden direct tool: " + str(method))
                if type(params) is not dict:
                    raise DialogueRejected("non-object notification params")
                if "threadId" in params and params["threadId"] != self.thread_id:
                    raise DialogueRejected("cross-thread notification")
                if "turnId" in params and params["turnId"] != turn_id:
                    raise DialogueRejected("cross-turn notification")
                if method in {"item/started", "item/completed"}:
                    item = params.get("item")
                    if type(item) is not dict:
                        raise DialogueRejected("missing turn item")
                    kind = item.get("type")
                    if kind not in {"userMessage", "agentMessage", "reasoning", "hookPrompt"}:
                        raise DialogueRejected("unregistered model item/tool: " + str(kind))
                    if method == "item/completed" and kind == "agentMessage":
                        if type(item.get("id")) is not str or item["id"] in seen_items:
                            raise DialogueRejected("duplicate or missing agent item identity")
                        if type(item.get("text")) is not str:
                            raise DialogueRejected("agent message is not text")
                        seen_items.add(item["id"])
                        record["item_ids"].append(item["id"])
                        record["messages"].append(item["text"])
                elif method == "turn/moderationMetadata":
                    receipt=moderation_notification(event,expected_thread=self.thread_id,expected_turn=turn_id)
                    record.setdefault("passive_moderation_notifications",[]).append(receipt)
                elif method == "thread/tokenUsage/updated":
                    u = params.get("tokenUsage")
                    if type(u) is not dict:
                        raise DialogueRejected("missing cumulative usage")
                    last, total = usage_record(u.get("last")), usage_record(u.get("total"))
                    usage_delta(self.usage_total, total)
                    if record["usage_events"]:
                        usage_delta(record["usage_events"][-1]["total"], total)
                    record["usage_events"].append({"last": last, "total": total,
                                                  "model_context_window": u.get("modelContextWindow")})
                elif method == "turn/completed":
                    finished = params.get("turn")
                    if (type(finished) is not dict or finished.get("id") != turn_id
                            or finished.get("status") != "completed" or finished.get("error") is not None):
                        raise DialogueRejected("turn failed, interrupted or changed identity")
                    completed = True
                elif method in {"turn/started", "thread/started", "thread/status/changed",
                    "item/agentMessage/delta", "item/reasoning/textDelta",
                    "item/reasoning/summaryTextDelta", "item/reasoning/summaryPartAdded",
                    "item/reasoning/summaryDelta", "thread/name/updated",
                    "warning", "configWarning", "deprecationNotice", "guardianWarning",
                    "hook/started", "hook/completed", "mcpServer/startupStatus/updated"}:
                    pass
                else:
                    raise DialogueRejected("unregistered turn notification: " + str(method))
            if not record["usage_events"]:
                raise DialogueRejected("terminal turn lacks provider usage")
            total = record["usage_events"][-1]["total"]
            record["usage_delta"] = usage_delta(self.usage_total, total)
            record["last_usage"] = record["usage_events"][-1]["last"]
            record["last_equals_cumulative_delta"] = record["last_usage"] == record["usage_delta"]
            record["cumulative_usage"] = total
            record["usage_required_fields_complete"] = all(total[k] is not None for k in REQUIRED_USAGE_FIELDS)
            record["all_raw_usage_categories_known"] = all(v is not None for v in total.values())
            record["usage_complete"] = record["usage_required_fields_complete"] and record["last_equals_cumulative_delta"]
            self.usage_total = total
            if not record["last_equals_cumulative_delta"]:
                raise DialogueRejected("last provider usage differs from explicit-turn cumulative delta; fair-turn admission refused")
            if (total["totalTokens"] > self.cfg["max_provider_total_tokens_per_cell"]
                    or record["usage_delta"]["inputTokens"] > self.cfg["max_provider_input_tokens_per_turn"]
                    or record["usage_delta"]["outputTokens"] > self.cfg["max_provider_output_tokens_per_turn"]):
                raise DialogueRejected("observed provider token budget exceeded")
            if len(record["messages"]) != 1:
                raise DialogueRejected("exactly one completed JSON-RPC answer required")
            record.update(status="completed", text=record["messages"][0])
            return record
        except BaseException as exc:
            self.failed = True
            record.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
            raise
        finally:
            record["wall_ns"] = time.monotonic_ns() - before
            save(self.root / f"turn-{index}.json", record)
            save(self.root / "PROCESS.json", self.record)

    def close(self):
        if self.closed:
            return self.record
        started = time.monotonic_ns()
        errors = []
        try:
            if self.process is not None:
                try:
                    self._observe_owner()
                    self.record["signal_attempted"] = True
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.record["signal_delivered_before_reap"] = True
                except BaseException as exc:
                    errors.append("signal: " + type(exc).__name__ + ": " + str(exc))
                # Never signal a reused numeric process group after reaping.
                if not self.record["ownership_uncertain"]:
                    try:
                        self._observe_owner()
                        self.record["returncode"] = self.process.wait(timeout=5)
                        self.record["leader_reaped"] = True
                    except BaseException as exc:
                        errors.append("reap: " + type(exc).__name__ + ": " + str(exc))
                drain_deadline = time.monotonic() + 2
                while self.selector.get_map() and time.monotonic() < drain_deadline:
                    for key, _ in self.selector.select(0.05):
                        name = key.data
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            self.selector.unregister(key.fileobj)
                            continue
                        self.record["observed_bytes"][name] += len(chunk)
                        remaining = self.cfg["stream_limits"][name + "_bytes_per_cell"] - self.record["bytes"][name]
                        if remaining < len(chunk):
                            self.record["raw_stream_truncated_at_registered_cap"] = True
                        retained = chunk[:max(0, remaining)]
                        self.streams[name].write(retained)
                        self.record["bytes"][name] += len(retained)
                self.record["streams_drained"] = not self.selector.get_map()
                if not self.record["streams_drained"]:
                    errors.append("bounded output drain incomplete")
                for name in ("stdin", "stdout", "stderr"):
                    stream = getattr(self.process, name)
                    if stream is not None:
                        stream.close()
                self.record["cleanup_confirmed"] = bool(
                    self.record.get("signal_delivered_before_reap")
                    and self.record["leader_reaped"] and self.record["streams_drained"] and not errors)
            else:
                self.record["cleanup_confirmed"] = True
        finally:
            self.closed = True
            self.selector.close()
            for stream in self.streams.values():
                stream.close()
            self.record["final_stream_audit"] = audit_raw_stdout(self.root / "stdout.raw",expected_thread=self.thread_id)
            if not self.record["final_stream_audit"]["eligible"] or self.record.get("raw_stream_truncated_at_registered_cap"):
                self.failed=True
            self.record["status"] = "failed_closed" if self.failed or errors else "closed"
            self.record["cleanup_errors"] = errors
            self.record["cleanup_wall_ns"] = time.monotonic_ns() - started
            self.record["closed"] = True
            save(self.root / "PROCESS.json", self.record)
        return self.record
