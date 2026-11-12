"""Bounded, retained SSE completions from the existing owned llama.cpp process.

The v4 transport only retained a response after HTTP EOF. This adapter retains
every received byte and reports exact request tokens plus the observed output
token lower bound on interruption. It never calls a partial response complete.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import struct
import time

from tools.provider_adapter.llama_cpp_engine import (
    LlamaCppEngine, canonical, valid_tokens, validate_completion,
)
from experiments.hia_agent_factorial_v4_20261028 import fixtures


def response_schema(language):
    files = fixtures.response_schema(language)["properties"]["files"]
    return {"type": "object", "properties": {
        "check": {"type": "string", "maxLength": 1536}, "files": files},
        "required": ["check", "files"], "additionalProperties": False}


class StreamRecord:
    """Parse bounded SSE events without discarding a complete partial prefix."""
    def __init__(self, limit):
        self.limit = limit
        self.buffer = b""
        self.text = []
        self.tokens = []
        self.final = None
        self.events = 0

    def feed(self, chunk):
        if self.final is not None and chunk.strip():
            raise ValueError("E_STREAM_AFTER_FINAL")
        self.buffer += chunk
        if len(self.buffer) > 4 * 1024**2:
            raise ValueError("E_STREAM_EVENT_SIZE")
        # llama.cpp emits LF-delimited SSE; CRLF is also accepted.
        self.buffer = self.buffer.replace(b"\r\n", b"\n")
        while b"\n\n" in self.buffer:
            event, self.buffer = self.buffer.split(b"\n\n", 1)
            lines = [line[5:].lstrip(b" ") for line in event.split(b"\n") if line.startswith(b"data:")]
            if not lines:
                continue  # SSE comments/pings are not model tokens.
            if self.final is not None:
                raise ValueError("E_STREAM_AFTER_FINAL")
            value = json.loads(b"\n".join(lines))
            if (type(value) is not dict or type(value.get("content")) is not str
                    or not valid_tokens(value.get("tokens")) or type(value.get("stop")) is not bool):
                raise ValueError("E_STREAM_EVENT")
            self.events += 1
            self.text.append(value["content"])
            self.tokens.extend(value["tokens"])
            if len(self.tokens) > self.limit:
                raise ValueError("E_STREAM_TOKEN_BUDGET")
            if value["stop"]:
                self.final = value

    def completed(self, input_ids):
        if self.final is None or self.buffer.strip():
            raise ValueError("E_STREAM_INCOMPLETE")
        raw = {**self.final, "content": "".join(self.text), "tokens": self.tokens}
        usage = validate_completion(raw, input_ids, self.limit, json_object=True)
        return raw, usage


class StreamingEnvelopeEngine(LlamaCppEngine):
    def __init__(self, **kwargs):
        super().__init__(json_object=True, **kwargs)
        self.identity["decoder"] = {
            "mode": "syntax-only-check-and-file-envelope",
            "schemas": {lang: response_schema(lang) for lang in ("hia", "rust")},
            "correct_operations_or_values_embedded": False,
        }
        self.identity["stream_protocol"] = "llama.cpp b11669 native /completion SSE"
        (self.output / "identity.json").write_bytes(canonical(self.identity) + b"\n")
        self.last_usage_receipt = None

    def generate(self, messages, *, language, limit=2048, wall_seconds=300):
        self.last_usage_receipt = None
        rendered = self.request("/apply-template", {"messages": messages}).get("prompt")
        if type(rendered) is not str:
            raise ValueError("E_STREAM_TEMPLATE")
        ids = self.tokenize(rendered, special=True)
        if not ids or len(ids) + limit > self.context:
            raise ValueError("E_STREAM_CONTEXT")
        schema = response_schema(language)
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
        return {"schema": "hepta.agent.factorial.generation.v5", "text": raw["content"],
                "usage": usage, "input_token_ids": ids, "output_token_ids": record.tokens,
                "wall_ns": time.monotonic_ns()-started,
                "decoder_sha256": hashlib.sha256(canonical(schema)).hexdigest()}
