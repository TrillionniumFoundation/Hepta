"""Owned retained-SSE generation with prospective real-edit response syntax.

The response grammar contains no reference implementation or selected node ID.
Model-code text is retained verbatim and never completed or repaired by the host.
"""
from __future__ import annotations
import hashlib
import http.client
import os
import socket
import struct
import time

from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical
from experiments.hia_agent_factorial_v4_20261028 import fixtures
from experiments.hia_agent_factorial_v5_20261028.engine import StreamRecord
from experiments.hia_agent_toolstudy_v8_20261029.budget import BudgetFailure


def response_schema(language, interface):
    if language not in {"hia", "rust"} or interface not in {"full", "node"}:
        raise ValueError("registered response interface required")
    if interface == "full":
        return fixtures.response_schema(language)
    return {"type": "object", "properties": {"edits": {
        "type": "array", "minItems": 1, "maxItems": 16, "items": {
            "type": "object", "properties": {"node": {"type": "string"}, "changes": {"type": "object"}},
            "required": ["node", "changes"], "additionalProperties": False}}},
        "required": ["edits"], "additionalProperties": False}


class ToolStudyEngine(LlamaCppEngine):
    def __init__(self, **kwargs):
        self.service_calls = []
        self.preparation_count = 0
        super().__init__(json_object=True, **kwargs)
        self.identity["decoder"] = {
            "mode": "syntax-only-files-or-real-node-edits-envelope",
            "schemas": {arm: response_schema(*arm.split("_")) for arm in ("hia_full", "hia_node", "rust_full", "rust_node")},
            "correct_operations_or_values_embedded": False,
        }
        self.identity["stream_protocol"] = "llama.cpp b11669 native /completion SSE"
        (self.output / "identity.json").write_bytes(canonical(self.identity) + b"\n")
        self.last_usage_receipt = None

    def request(self, endpoint, payload=None, timeout=10):
        started = time.monotonic_ns()
        success = False
        try:
            result = super().request(endpoint, payload, timeout)
            success = True
            return result
        finally:
            self.service_calls.append({"endpoint": endpoint, "wall_ns": time.monotonic_ns()-started, "success": success})

    def generate(self, messages, *, language, interface, limit=1536, wall_seconds=900):
        self.last_usage_receipt = None
        rendered = self.request("/apply-template", {"messages": messages}).get("prompt")
        if type(rendered) is not str:
            raise ValueError("E_STREAM_TEMPLATE")
        ids = self.tokenize(rendered, special=True)
        self.preparation_count += 1
        fits = bool(ids) and len(ids) + limit <= self.context
        (self.output / ("preparation-" + str(self.preparation_count).zfill(3) + ".json")).write_bytes(canonical({
            "messages": messages, "rendered_prompt": rendered, "input_token_ids": ids,
            "reserved_output_tokens": limit, "context": self.context, "fits": fits,
            "actual_generation_submitted": fits}) + b"\n")
        if not fits:
            raise BudgetFailure("E_TOOLSTUDY_CONTEXT: complete request plus full output reserve exceeds context; cell ends without truncation")
        schema = response_schema(language, interface)
        payload = {"prompt": ids, "n_predict": limit, "temperature": 0, "seed": 0,
                   "top_k": 0, "top_p": 1, "min_p": 0, "repeat_penalty": 1,
                   "cache_prompt": False, "return_tokens": True, "stream": True,
                   "stop": [], "ignore_eos": False, "json_schema": schema}
        self.generation_count += 1
        stem = "transport-" + str(self.generation_count).zfill(3)
        (self.output / (stem + ".request.json")).write_bytes(canonical({
            "messages": messages, "rendered_prompt": rendered, "payload": payload}) + b"\n")
        record = StreamRecord(limit)
        started = time.monotonic_ns()
        deadline = time.monotonic() + wall_seconds
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection = http.client.HTTPConnection("localhost", timeout=wall_seconds)
        error = None
        usage = None
        raw = None
        received = 0
        self.last_usage_receipt = None
        try:
            if self.process is None or self.process.poll() is not None:
                raise RuntimeError("E_STREAM_OWNER_EXITED")
            sock.settimeout(wall_seconds)
            sock.connect(self.socket_path)
            pid, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid != self.process.pid or uid != os.geteuid():
                raise RuntimeError("E_STREAM_OWNER_IDENTITY")
            connection.sock = sock
            connection.request("POST", "/completion", body=canonical(payload),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status != 200 or "text/event-stream" not in response.getheader("Content-Type", ""):
                raise RuntimeError("E_STREAM_HTTP")
            with (self.output / (stem + ".response.sse")).open("xb", buffering=0) as output:
                while record.final is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("E_STREAM_WALL_BUDGET")
                    sock.settimeout(remaining)
                    chunk = response.read1(65536)
                    if not chunk:
                        raise ValueError("E_STREAM_EOF_BEFORE_FINAL")
                    output.write(chunk)
                    received += len(chunk)
                    if received > 4 * 1024**2:
                        raise ValueError("E_STREAM_RESPONSE_SIZE")
                    record.feed(chunk)
            raw, usage = record.completed(ids)
            self.response_count += 1
            (self.output / (stem + ".response.json")).write_bytes(canonical(raw) + b"\n")
        except Exception as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            connection.close()
            sock.close()
            receipt = {
                "schema": "hepta.agent.stream-usage.v1", "complete": usage is not None,
                "input_tokens": len(ids), "observed_output_token_ids": record.tokens,
                "observed_output_token_lower_bound": len(record.tokens),
                "output_tokens": usage["output_tokens"] if usage else None,
                "total_tokens": usage["total_tokens"] if usage else None,
                "unknown_output_tokens": usage is None,
                "unknown_reason": None if usage else "No validated final event; unreceived tokens and terminal EOS remain unknown.",
                "events": record.events, "response_bytes": received,
                "wall_ns": time.monotonic_ns() - started, "error": error,
            }
            (self.output / (stem + ".usage.json")).write_bytes(canonical(receipt) + b"\n")
            self.last_usage_receipt = receipt
        return {"schema": "hepta.agent.toolstudy.generation.v8", "text": raw["content"],
                "usage": usage, "input_token_ids": ids, "output_token_ids": record.tokens,
                "wall_ns": time.monotonic_ns()-started,
                "decoder_sha256": hashlib.sha256(canonical(schema)).hexdigest()}
