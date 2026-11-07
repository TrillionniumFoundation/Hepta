"""One explicitly started fresh CLI session over an already qualified MCP bridge.

This component has no task generator, hidden oracle, setup operation or retry.
The coordinator separately freezes the executable, argv, public prompt, bridge,
context deadline and budget. A completed CLI is not an accepted maintenance task.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import time

from tools.hia_agent_codex_transport import EventFailure, identity, run_owned, save, strict_json

TOOLS = frozenset("hia_describe hia_artifact hia_read hia_context hia_inspect hia_candidate "
    "hia_verify hia_emit hia_evaluate hia_adopt hia_rollback".split())


class FreshEvents:
    def __init__(self, server):
        self.server, self.events = server, []
        self.threads = self.turns = self.completions = 0

    def line(self, raw):
        event = strict_json(raw)
        if type(event) is not dict:
            raise EventFailure("E_HIA_FRESH_EVENT_SHAPE")
        self.events.append(event)
        kind = event.get("type")
        if kind == "thread.started":
            self.threads += 1
            if self.threads != 1 or self.turns:
                raise EventFailure("E_HIA_FRESH_THREAD_SEQUENCE")
        elif kind == "turn.started":
            self.turns += 1
            if self.threads != 1 or self.turns != 1:
                raise EventFailure("E_HIA_FRESH_TURN_SEQUENCE")
        elif kind in {"turn.completed", "turn.failed"}:
            self.completions += 1
            if self.turns != 1 or self.completions != 1:
                raise EventFailure("E_HIA_FRESH_COMPLETION_SEQUENCE")
        elif kind in {"item.started", "item.updated", "item.completed"}:
            item = event.get("item")
            if type(item) is not dict or self.turns != 1 or self.completions:
                raise EventFailure("E_HIA_FRESH_ITEM_SEQUENCE")
            if item.get("type") == "mcp_tool_call":
                if item.get("server") != self.server or item.get("tool") not in TOOLS:
                    raise EventFailure("E_HIA_FRESH_FOREIGN_TOOL")
            elif item.get("type") not in {"agent_message", "reasoning", "error"}:
                raise EventFailure("E_HIA_FRESH_FOREIGN_ITEM")
        elif kind != "error":
            raise EventFailure("E_HIA_FRESH_UNKNOWN_EVENT")

    def summary(self):
        usage = [e.get("usage") for e in self.events if e.get("type") == "turn.completed"]
        total = None
        if (len(usage) == 1 and type(usage[0]) is dict
                and all(type(usage[0].get(k)) is int and usage[0][k] >= 0
                        for k in ("input_tokens", "output_tokens"))):
            total = usage[0]["input_tokens"] + usage[0]["output_tokens"]
        attempts, cancelled, unidentified = {}, [], 0
        for event in self.events:
            item = event.get("item")
            if type(item) is not dict or item.get("type") != "mcp_tool_call":
                continue
            if type(item.get("id")) is not str:
                unidentified += 1
                continue
            attempts[item["id"]] = item
            if (event["type"] == "item.completed" and type(item.get("error")) is dict
                    and item["error"].get("message") == "user cancelled MCP tool call"):
                cancelled.append({"item_id": item["id"], "original_error": item["error"],
                    "actor": None, "cause": None,
                    "server_dispatch_known": False, "new_attempt_authorized": False})
        return {"thread_started_count": self.threads, "turn_started_count": self.turns,
            "terminal_event_count": self.completions, "usage_records": usage,
            "input_plus_output_tokens": total,
            "cached_and_reasoning_added_again": False,
            "model_mcp_attempts": len(attempts), "bridge_received_calls": None,
            "tool_events_without_identity": unidentified,
            "actual_hia_wire_calls": None, "cancellation_observations": cancelled,
            "tool_count_scope": "original CLI item identities; bridge and physical HTTP counts require their own ledgers"}


def run_session(argv, cwd, output, *, public_prompt, executable_sha256,
                deadline_unix_ns, deadline_monotonic_ns, max_wall_seconds=1800,
                token_review_limit=500000, server="hia_trial", bridge_frozen=None):
    """Invoke once. No model is invoked by importing or inspecting this module."""
    if (type(public_prompt) is not bytes or len(public_prompt) > 1024 * 1024
            or not argv or not Path(argv[0]).is_absolute()
            or identity(argv[0])["sha256"] != executable_sha256
            or type(token_review_limit) is not int or token_review_limit <= 0
            or type(max_wall_seconds) not in (float, int) or not 0 < max_wall_seconds <= 1800
            or any(type(n) is not int or n <= 0 for n in (deadline_unix_ns, deadline_monotonic_ns))):
        raise ValueError("E_HIA_FRESH_FROZEN_INPUTS")
    remaining = min(max_wall_seconds, (deadline_unix_ns - time.time_ns()) / 1e9,
                    (deadline_monotonic_ns - time.monotonic_ns()) / 1e9)
    events = FreshEvents(server)
    result = run_owned(argv, cwd, output, input_bytes=public_prompt, wall_seconds=remaining,
        absolute_deadline_unix_ns=deadline_unix_ns, on_line=events.line,
        stop_requested=(lambda: Path(bridge_frozen).exists()) if bridge_frozen else None,
        transport_limits={"stdout_limit_bytes": 32 * 1024 * 1024,
                          "stderr_limit_bytes": 8 * 1024 * 1024,
                          "max_jsonl_line_bytes": 4 * 1024 * 1024})
    # Reparse all captured originals so a parser failure does not discard later
    # reported usage. No malformed line or event becomes accepted by this pass.
    observed, errors = FreshEvents(server), []
    for index, line in enumerate((Path(output) / "stdout.raw").read_bytes().splitlines(), 1):
        try:
            observed.line(line)
        except (ValueError, UnicodeError, TypeError, KeyError) as exc:
            errors.append({"line": index, "type": type(exc).__name__, "message": str(exc)[:512],
                           "sha256": hashlib.sha256(line).hexdigest()})
    summary = observed.summary()
    total = summary["input_plus_output_tokens"]
    executable_after = identity(argv[0])
    record = {"schema": "hepta.hia.agent.fresh-session.v2", "process": result,
        "cli_sessions_started": int("pid" in result), "provider_http_request_count": None,
        "public_prompt_sha256": hashlib.sha256(public_prompt).hexdigest(),
        "original_deadline_unix_ns": deadline_unix_ns,
        "original_deadline_monotonic_ns": deadline_monotonic_ns,
        "model_wall_limit_seconds": max_wall_seconds, "actual_remaining_seconds": remaining,
        "token_review_limit": token_review_limit, "hard_mid_turn_token_limit": False,
        "within_token_review_limit": None if total is None else total <= token_review_limit,
        "parse_errors": errors, "requested_model_is_response_identity": False,
        "executable_identity_after": executable_after,
        "executable_unchanged": executable_after["sha256"] == executable_sha256,
        "model_weights_attested": False, "billed_cost": None,
        "p1_acceptance": "HOLD", "task_judge_executed": False,
        "isolation_scope": "actual event allowlist only; effective CLI configuration requires separate qualification",
        **summary}
    save(Path(output) / "SESSION_RESULT.json", record)
    return record
