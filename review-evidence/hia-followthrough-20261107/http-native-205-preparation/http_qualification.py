#!/usr/bin/env python3
"""HTTP wire adapter for the unmodified Hepta 205 scripted integration loop.

This is an isolated transport qualification, not an Agent economics experiment.
The only application argument substitution is a newly registered target slot.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
from hia_agent_native_qualification import Session, ToolClient, scripted_loop
from hia_agent_native_transport import MCPStdio, QualificationFailure, json_bytes

HEPTA_COMMIT = "205f94ec811018f89fbf68c987c6ab8e826bb15b"
PINS = {
    "worker_sha256": "cb5933bb1d08bd18b13a26e522b0d7c040db9597b49cf926874b44f9684aee6f",
    "backend_sha256": "1fd7feedfd68a0cc4f1aec1ba053d7066505817bfe2366a0ca8db1dfb7617873",
    "catalog_sha256": "8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e",
}
SLOT_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}"


def require(condition, message):
    if not condition:
        raise QualificationFailure(message)


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def dump(path, value):
    write_new(path, json_bytes(value) + b"\n")


def token_bytes(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                "token file is not an owned private regular file")
        raw = source.read(8193)
    require(0 < len(raw) <= 8192, "token file length is invalid")
    token = raw.decode("ascii").strip()
    require(token and not any(c.isspace() for c in token), "token format is invalid")
    return token


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def response_messages(raw):
    text = raw.decode("utf-8")
    if text.lstrip().startswith("{"):
        return [json.loads(text)]
    messages, data = [], []
    for line in text.splitlines() + [""]:
        if line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif not line and data:
            messages.append(json.loads("\n".join(data)))
            data = []
    require(bool(messages), "HTTP response contained no JSON-RPC message")
    return messages


class MCPHTTP(MCPStdio):
    """Reuse original HIA decoding/listing and bind every pending original job."""

    def __init__(self, url, token, output, timeout=180):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
                and parsed.port in (8790, 8791) and parsed.path == "/mcp"
                and not parsed.query and not parsed.fragment and not parsed.username,
                "only the explicitly selected loopback MCP endpoint is allowed")
        self.url, self.token, self.output, self.timeout = url, token, output, timeout
        self.counter, self.session, self.wire_counter = 0, None, 0
        self.protocol_records = []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.events = output / "http-events.jsonl"
        write_new(self.events, b"")
        self.initialized = self.rpc("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "hia-agent-native-http-qualification", "version": "1"}})
        require(self.initialized.get("protocolVersion") == "2025-06-18",
                "unexpected negotiated MCP protocol")
        self.notify("notifications/initialized", {})

    def event(self, value):
        raw = json_bytes(value) + b"\n"
        require(self.token.encode() not in raw, "credential reflection refused")
        with self.events.open("ab") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())

    def _post(self, request, notify=False):
        self.wire_counter += 1
        wire_id = self.wire_counter
        started = time.monotonic_ns()
        self.event({"stage": "intent", "wire_id": wire_id, "url": self.url,
                    "request": request, "notify": notify, "started_monotonic_ns": started})
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "X-Hepta-Runtime-Token": self.token, "MCP-Protocol-Version": "2025-06-18"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        try:
            try:
                response = self.opener.open(urllib.request.Request(
                    self.url, data=json_bytes(request), headers=headers), timeout=self.timeout)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.status
                raw = response.read(4 * 1024 * 1024 + 1)
                require(len(raw) <= 4 * 1024 * 1024, "HTTP response exceeded the original transport bound")
                require(self.token.encode() not in raw, "credential reflection refused")
                self.session = response.headers.get("Mcp-Session-Id", self.session)
            name = f"http-body-{wire_id:05d}.bin"
            write_new(self.output / name, raw)
            self.event({"stage": "response", "wire_id": wire_id, "http_status": status,
                        "body": name, "body_bytes": len(raw), "body_sha256": sha256(raw).hexdigest(),
                        "elapsed_ns": time.monotonic_ns() - started})
            require(200 <= status < 300, f"HTTP status {status}; original outcome retained")
            if notify and not raw:
                return []
            return response_messages(raw)
        except BaseException as error:
            self.event({"stage": "error", "wire_id": wire_id, "error_type": type(error).__name__,
                        "elapsed_ns": time.monotonic_ns() - started,
                        "outcome": "unknown; no automatic HTTP retry or fresh request key"})
            raise

    def notify(self, method, params):
        self._post({"jsonrpc": "2.0", "method": method, "params": params}, notify=True)

    def rpc(self, method, params):
        self.counter += 1
        request = {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params}
        messages = self._post(request)
        matches = []
        for response in messages:
            self.protocol_records.append({"request": request, "response": response})
            if response.get("id") == request["id"]:
                matches.append(response)
        require(len(matches) == 1, "HTTP result must identify exactly one original JSON-RPC request")
        response = matches[0]
        require(response.get("jsonrpc") == "2.0", "invalid JSON-RPC version")
        require("error" not in response, "JSON-RPC error; exact response retained")
        return response["result"]

    @staticmethod
    def pending_identity(response):
        require(response.get("contract_version") == "hepta.hia.agent-native.v1"
                and response.get("status") in ("accepted", "unknown"), "not an original pending HIA result")
        operation = response["operation"]
        require(operation["host"] == "x230" and re.fullmatch(r"[a-zA-Z0-9_-]+", operation["job_id"])
                and re.fullmatch(r"[0-9a-f]{64}", operation["request_sha256"])
                and operation["report_artifact"] is None
                and response["request_id"] == "hia_" + operation["request_sha256"],
                "pending HIA result lacks its bound original worker identity")
        return operation["host"], operation["job_id"], operation["request_sha256"]

    def owner_observation(self, name, arguments):
        require(name in ("process_wait", "process_read"), "only original job observations are allowed")
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        require(result.get("isError") is not True, "original job observation was rejected")
        return json.loads("\n".join(p.get("text", "") for p in result.get("content", [])
                                    if p.get("type") == "text"))

    def original_report(self, identity, tool):
        host, job_id, request_sha = identity
        deadline = time.monotonic() + self.timeout
        while True:
            terminal = self.owner_observation("process_wait", {
                "host": host, "job_id": job_id, "timeout_seconds": 10})
            require(terminal["job_id"] == job_id, "original job identity changed")
            if terminal["state"] in ("queued", "pending", "starting", "running"):
                require(time.monotonic() < deadline, "original worker did not settle within observation bound")
                continue
            require(terminal["state"] == "succeeded" and terminal["exit_code"] == 0,
                    "original worker did not succeed")
            require(all(terminal.get(k) is True for k in
                        ("output_complete", "output_durable", "terminal_publication_confirmed")),
                    "original worker output is not complete and durable")
            break
        streams, sizes = {"stdout": bytearray(), "stderr": bytearray()}, None
        for _ in range(65):
            page = self.owner_observation("process_read", {
                "host": host, "job_id": job_id, "limit": 16384,
                "stdout_offset": len(streams["stdout"]), "stderr_offset": len(streams["stderr"])})
            require(page["job_id"] == job_id, "original output job identity changed")
            current = {name: page[name]["size"] for name in streams}
            require(all(type(v) is int and v >= 0 for v in current.values())
                    and sum(current.values()) <= 512 * 1024, "original output exceeded its bound")
            if sizes is None:
                sizes = current
            require(sizes == current, "terminal output size changed")
            progress = False
            for name, output in streams.items():
                part = page[name]
                require(type(part["offset"]) is int and part["offset"] == len(output), "original cursor changed")
                encoded = part["bytes_hex"]
                require(type(encoded) is str and re.fullmatch("[0-9a-f]*", encoded)
                        and len(encoded) % 2 == 0, "malformed original output bytes")
                raw = bytes.fromhex(encoded)
                require(len(raw) <= 16384 and part["text"] == raw.decode("utf-8", "replace"),
                        "original output bytes/text disagree")
                require(type(part["next_offset"]) is int and part["next_offset"] == len(output) + len(raw)
                        and part["next_offset"] <= sizes[name]
                        and type(part["eof"]) is bool and part["eof"] == (part["next_offset"] == sizes[name]),
                        "original output cursor/EOF disagree")
                output.extend(raw)
                progress = progress or bool(raw)
            if all(len(streams[n]) == sizes[n] for n in streams):
                break
            require(progress, "original output pagination made no progress")
        else:
            raise QualificationFailure("original output pagination did not complete")
        report = json.loads(bytes(streams["stdout"]))
        require(set(report) == {"schema", "tool", "request_sha256", "profile_sha256", "catalog_sha256",
                                "worker_sha256", "backend_sha256", "complete", "response"}
                and report["schema"] == "hia-agent-worker-report-v1" and report["complete"] is True
                and report["tool"] == tool and report["request_sha256"] == request_sha
                and re.fullmatch("[0-9a-f]{64}", report["profile_sha256"])
                and {key: report[key] for key in PINS} == PINS
                and report["response"]["status"] in ("completed", "rejected"),
                "original worker report binding or terminal status differs")
        return report

    def call(self, tool, arguments):
        response = self._domain_result(self.rpc("tools/call", {"name": tool, "arguments": arguments}))
        if response.get("status") not in ("accepted", "unknown"):
            return response
        identity = self.pending_identity(response)
        report = self.original_report(identity, tool)
        # Observe only the identical binding after its original durable report.
        # This never substitutes the raw report for provider schema admission.
        observed = self._domain_result(self.rpc("tools/call", {"name": tool, "arguments": arguments}))
        if observed.get("status") in ("accepted", "unknown"):
            require(self.pending_identity(observed) == identity, "original HIA binding changed")
            raise QualificationFailure("original worker result remains unadmitted; preserve original job")
        require(observed == report["response"], "provider result differs from original worker report")
        return observed

    def close(self):
        # No process or service is owned by this client. Never signal/restart it.
        self.token = ""


class OwnedSlotSession(Session):
    def __init__(self, client, *, prefix, target_slot):
        require(target_slot != "qualification" and re.fullmatch(SLOT_PATTERN, target_slot),
                "target slot must be a newly registered schema-valid label")
        self.target_slot = target_slot
        super().__init__(client, prefix=prefix)

    def arguments(self, *, mutable=True, context=True, **fields):
        if "target_slot" in fields:
            require(fields["target_slot"] == "qualification", "unexpected scripted target label")
            fields["target_slot"] = self.target_slot
        return super().arguments(mutable=mutable, context=context, **fields)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-commit", required=True)
    parser.add_argument("--target-slot", required=True)
    parser.add_argument("--prefix", required=True)
    args = parser.parse_args(argv)
    require(not sys.flags.optimize, "assertions must remain enabled")
    require(re.fullmatch("[0-9a-f]{40}", args.runtime_commit), "invalid runtime source identity")
    require(args.target_slot.startswith(f"qualification-http-{args.runtime_commit[:12]}-372e7da9-"),
            "target slot does not identify this isolated qualification")
    require(re.fullmatch(SLOT_PATTERN, args.target_slot), "invalid target slot")
    require(re.fullmatch(SLOT_PATTERN, args.prefix) and args.prefix != "qualification", "invalid prefix")
    source = json.loads((ROOT / "EXACT_SOURCE.json").read_bytes())
    require(source["source_commit"] == HEPTA_COMMIT, "unexpected original qualification source")
    for row in source["files"]:
        require(sha256((ROOT / row["path"]).read_bytes()).hexdigest() == row["sha256"],
                "original source/catalog bytes changed")
    args.output.mkdir(mode=0o700)  # Exclusive registration; never resume by rerunning the loop.
    started = time.monotonic_ns()
    registration = {"schema": "hia-http-qualification-registration-v1", "hepta_commit": HEPTA_COMMIT,
                    "runtime_commit": args.runtime_commit, "source": source,
                    "runtime_identity_scope": "caller-supplied commit; actual binary/PID/listener must be bound by separate before/after shadow receipts",
                    "adapter_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
                    "url": args.url, "prefix": args.prefix,
                    "target_slot_mapping": {"original": "qualification", "owned": args.target_slot},
                    "initial_expected_current": {"generation": "0", "epoch": "0"},
                    "ownership": "exclusive local registration; server creates only through original conditional adoption",
                    "dependencies": {name: importlib.metadata.version(name) for name in
                                     ("jsonschema", "jsonschema-specifications", "referencing", "rpds-py", "attrs")}}
    dump(args.output / "registration.json", registration)
    transport = client = session = None
    report = {"schema": "hepta.hia.agent.http-qualification.v1", "status": "failed",
              "mode": "actual_hepta_runtime_http_mcp", "registration": registration,
              "claims": {"scripted_integration_observed": False, "fresh_model_learning_test_performed": False,
                         "model_training_exposure_known": False, "universal_backend_refinement_proved": False,
                         "net_optimization_benefit_proved": False}}
    try:
        transport = MCPHTTP(args.url, token_bytes(args.token_file), args.output)
        listing = transport.list_tools()
        client = ToolClient(transport.call, validate=True)
        observed = {tool["name"]: tool for tool in listing}
        require(len(listing) == len(observed) == 113, "whole tool catalog count differs")
        require(set(client.tools) == {n for n in observed if n.startswith("hia_")}, "HIA tool inventory differs")
        for name, expected in client.tools.items():
            for schema in ("inputSchema", "outputSchema"):
                require(observed[name][schema] == expected[schema], "HIA schema differs: " + name)
        session = OwnedSlotSession(client, prefix=args.prefix, target_slot=args.target_slot)
        require(session.catalog_sha256 == PINS["catalog_sha256"], "worker catalog pin differs")
        require({k: session.manifest["installation"][k] for k in PINS} == PINS, "worker installation pins differ")
        result = scripted_loop(session)
        require(len(client.records) == 39, "application call count differs from the registered 39-call loop")
        require({r["tool"] for r in client.records} == set(client.tools), "full eleven-tool lifecycle incomplete")
        slots = [r for r in client.records if "target_slot" in r["arguments"]]
        require([r["tool"] for r in slots] == ["hia_adopt", "hia_adopt", "hia_rollback"], "slot call order differs")
        require(all(r["arguments"]["target_slot"] == args.target_slot for r in slots), "target isolation failed")
        require(result["adoption"]["previous"] == {"generation": "0", "epoch": "0"}, "initial target state differs")
        require(result["rollback"]["current"] == {"generation": "0", "epoch": "2"}, "rollback did not restore baseline")
        report.update(status="passed", scenario=result, tools_list=listing, catalog_sha256=session.catalog_sha256)
        report["claims"]["scripted_integration_observed"] = True
    except BaseException as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error),
                             "fresh_loop_retry_allowed": False}
        raise
    finally:
        report["elapsed_ns"] = str(time.monotonic_ns() - started)
        report["calls"] = client.records if client else []
        report["tool_call_count"] = len(report["calls"])
        report["tool_names_observed"] = sorted({r["tool"] for r in report["calls"]})
        if transport:
            report["mcp_initialize"] = transport.initialized
            report["mcp_protocol_records"] = transport.protocol_records
            transport.close()
        dump(args.output / "result.json", report)
        print(json.dumps({"status": report["status"], "tool_calls": report["tool_call_count"],
                          "output": str(args.output)}), flush=True)


if __name__ == "__main__":
    main()
