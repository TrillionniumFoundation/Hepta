"""Bounded stdio MCP transport used by HIA qualification and fresh clients.

This module carries no HIA grammar, examples, optimizer or task fixture.
"""
from __future__ import annotations

import json
import os
import select
import subprocess
import tempfile
import time


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class QualificationFailure(AssertionError):
    pass


class MCPStdio:
    """An actual newline-delimited MCP client with bounded waits and readback.

    The server command is administrator supplied on this CLI, never a HIA tool
    argument. A nonterminal HIA operation is observed by replaying its exact
    original call; a fresh request key is never manufactured for a retry.
    """

    def __init__(self, command, *, cwd=None, env=None, timeout=180):
        self.timeout = timeout
        self.stderr_file = tempfile.TemporaryFile(mode="w+b")
        self.process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.stderr_file,
                                        bufsize=0, start_new_session=True)
        self.counter = 0
        self.pending_bytes = b""
        self.protocol_records = []
        try:
            self.initialized = self.rpc("initialize", {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "clientInfo": {"name": "hia-agent-native-qualification", "version": "1"}})
            self.notify("notifications/initialized", {})
        except BaseException:
            self.close()
            raise

    def notify(self, method, params):
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        self.process.stdin.write(json_bytes(message) + b"\n")
        self.process.stdin.flush()

    def _read_message(self, deadline):
        while True:
            if b"\n" in self.pending_bytes:
                line, self.pending_bytes = self.pending_bytes.split(b"\n", 1)
                if line.strip():
                    return json.loads(line)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("MCP response deadline expired; operation outcome is unknown")
            ready, _, _ = select.select([self.process.stdout], [], [], min(remaining, 1))
            if not ready:
                if self.process.poll() is not None:
                    raise QualificationFailure("MCP server exited: " + self.stderr())
                continue
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise QualificationFailure("MCP stream closed: " + self.stderr())
            self.pending_bytes += chunk
            if len(self.pending_bytes) > 4 * 1024 * 1024:
                raise QualificationFailure("MCP response exceeded qualification client limit")

    def rpc(self, method, params):
        self.counter += 1
        request = {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params}
        self.process.stdin.write(json_bytes(request) + b"\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            response = self._read_message(deadline)
            self.protocol_records.append({"request": request, "response": response})
            if response.get("id") != request["id"]:
                continue
            if "error" in response:
                raise QualificationFailure(f"MCP {method} error: {response['error']}")
            return response["result"]

    @staticmethod
    def _domain_result(result):
        structured = result.get("structuredContent")
        if isinstance(structured, dict) and "contract_version" in structured:
            return structured
        for content in result.get("content", []):
            if content.get("type") == "text":
                try:
                    value = json.loads(content["text"])
                except (ValueError, TypeError):
                    continue
                if isinstance(value, dict) and "contract_version" in value:
                    return value
        raise QualificationFailure("MCP tool returned no typed HIA envelope: " + json.dumps(result))

    def call(self, tool, arguments):
        deadline = time.monotonic() + self.timeout
        while True:
            result = self._domain_result(self.rpc("tools/call", {"name": tool, "arguments": arguments}))
            if result.get("status") != "accepted":
                return result
            if time.monotonic() >= deadline:
                return result  # accepted remains accepted; never manufacture completion
            time.sleep(0.05)

    def list_tools(self):
        result = self.rpc("tools/list", {})
        tools = list(result.get("tools", []))
        while result.get("nextCursor"):
            result = self.rpc("tools/list", {"cursor": result["nextCursor"]})
            tools.extend(result.get("tools", []))
        return tools

    def stderr(self):
        self.stderr_file.flush()
        return os.pread(self.stderr_file.fileno(), 65536, 0).decode("utf-8", errors="replace")

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.stderr_file.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

