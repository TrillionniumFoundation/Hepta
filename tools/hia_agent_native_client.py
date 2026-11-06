"""Thin, recorded stdio MCP client; no HIA grammar or task answers are embedded.

Example administrator invocation:
  python tools/hia_agent_native_client.py \
    --mcp-command-json '["/path/hepta-runtime", "mcp", "--runtime-config", "/path/config.toml"]' \
    --request-json-stdin --transcript /path/client-transcript.jsonl

Standard input is one JSON object with exactly ``method`` and ``params``. Long
tools may return an accepted operation. The caller observes the original tool
with its unchanged arguments; this client never invents a retry or request key.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time

# This script also works when installed beside its transport helper without the
# compiler package, language sources, examples or qualification fixtures.
if __package__:
    from .hia_agent_native_transport import MCPStdio, json_bytes
else:
    from hia_agent_native_transport import MCPStdio, json_bytes


MAX_REQUEST_BYTES = 512 * 1024
METHODS = frozenset({"tools/list", "tools/call", "resources/list", "resources/templates/list", "resources/read"})


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field: " + key)
            result[key] = value
        return result

    def bad_constant(value):
        raise ValueError("nonfinite JSON value: " + value)

    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)


def append_transcript(path, record):
    import fcntl
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "ab", buffering=0) as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        data = json_bytes(record) + b"\n"
        offset = 0
        while offset < len(data):
            offset += stream.write(data[offset:])
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcp-command-json", required=True,
                        help="Administrator-provided nonempty JSON array of executable and argv")
    parser.add_argument("--request-json-stdin", action="store_true", required=True)
    parser.add_argument("--transcript", type=Path)
    parser.add_argument("--cwd", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be between 1 and 600")
    command = strict_json(args.mcp_command_json)
    if (type(command) is not list or not command
            or any(type(item) is not str or "\0" in item for item in command)):
        parser.error("--mcp-command-json requires nonempty argv strings without NUL")
    data = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(data) > MAX_REQUEST_BYTES:
        parser.error("request exceeds 512 KiB")
    request = strict_json(data)
    if (type(request) is not dict or set(request) != {"method", "params"}
            or request["method"] not in METHODS or type(request["params"]) is not dict):
        parser.error("request requires exactly an allowed MCP method and object params")
    started = time.monotonic_ns()
    record = {"schema": "hepta.hia.agent.mcp-client-transcript.v1",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "endpoint_command_sha256": sha256(json_bytes(command)).hexdigest(),
        "request_sha256": sha256(json_bytes(request)).hexdigest(), "request": request,
        "client_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "request_key_changed_by_client": False, "automatic_domain_retry": False}
    client = None
    exit_code = 0
    try:
        client = MCPStdio(command, cwd=args.cwd, timeout=args.timeout_seconds)
        result = client.rpc(request["method"], request["params"])
        response = {"schema": "hepta.hia.agent.mcp-client-result.v1", "status": "received",
                    "method": request["method"], "result": result}
    except Exception as error:
        exit_code = 1
        response = {"schema": "hepta.hia.agent.mcp-client-result.v1", "status": "transport_error",
            "method": request["method"], "error": {"type": type(error).__name__, "message": str(error)[:65536]},
            "operation_completion_established": False,
            "retry_instruction": "Keep the original tool arguments and request key; observe original state."}
    finally:
        record["elapsed_ns"] = str(time.monotonic_ns() - started)
        if client is not None:
            record["initialize"] = client.initialized
            record["protocol"] = client.protocol_records
            stderr = client.stderr()
            if stderr:
                record["server_stderr_bounded"] = stderr
            client.close()
    record["response"] = response
    if args.transcript:
        append_transcript(args.transcript, record)
    print(json.dumps(response, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
