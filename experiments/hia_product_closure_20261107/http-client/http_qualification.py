#!/usr/bin/env python3
"""HTTP wire adapter for the exact Hepta 894 scripted integration loop.

This is an isolated transport qualification, not an Agent economics experiment.
The upstream campaign binding owns both request keys and the adoption slot.
No compiler, worker, native loader, server restart, or fresh-key retry is here.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import http.client
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
from hia_agent_native_qualification import Session, ToolClient, campaign_binding, scripted_loop
from hia_agent_native_transport import MCPStdio, QualificationFailure, json_bytes

HEPTA_COMMIT = "894d2dfce54ff25271b8de2c18c902394484d5cc"
RUNTIME_COMMIT = "c81a938150d2e533843a42af77739cb888812338"
PINS = {
    "worker_sha256": "b75a689c159beab75d3af985badede167c247f482dd7dc86dfe99973a5aab079",
    "backend_sha256": "1fd7feedfd68a0cc4f1aec1ba053d7066505817bfe2366a0ca8db1dfb7617873",
    "catalog_sha256": "8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e",
}
SLOT_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}"
ENDPOINTS = ("http://127.0.0.1:8792/mcp", "http://127.0.0.1:8790/mcp")


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


def append_event(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "ab") as stream:
        stream.write(json_bytes(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def read_private(path, maximum=16 * 1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_size <= maximum, "unsafe or oversized evidence file")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) and len(raw) == before.st_size,
            "evidence changed while reading")
    return raw


def selected_campaign(campaign_id):
    binding = campaign_binding(campaign_id)
    require(campaign_id.startswith("faa85-v4-"), "campaign must use this task's independent faa85-v4 namespace")
    return binding


def verify_source():
    source = json.loads((ROOT / "EXACT_SOURCE.json").read_bytes())
    require(source["source_commit"] == HEPTA_COMMIT, "unexpected original qualification source")
    require({r["path"] for r in source["files"]} == {
        "tools/hia_agent_native_qualification.py", "tools/hia_agent_native_transport.py",
        "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json"}, "exact-source file set differs")
    for row in source["files"]:
        raw = (ROOT / row["path"]).read_bytes()
        require(len(raw) == row["bytes"] and sha256(raw).hexdigest() == row["sha256"],
                "original source/catalog bytes changed")
    return source


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
            payload = "\n".join(data)
            if payload.strip():
                messages.append(json.loads(payload))
            data = []
    require(bool(messages), "HTTP response contained no JSON-RPC message")
    return messages


class MCPHTTP(MCPStdio):
    """Reuse original HIA decoding/listing and bind every pending original job."""

    def __init__(self, url, token, output, timeout=180):
        require(url in ENDPOINTS,
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

    def connection_receipt(self):
        return {"url": self.url, "initialize": self.initialized,
                "session_id_observed": self.session is not None,
                "session_id_sha256": sha256(self.session.encode()).hexdigest() if self.session else None,
                "wire_requests": self.wire_counter,
                "server_process_owned": False}

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
                read_error = None
                try:
                    raw = response.read(4 * 1024 * 1024 + 1)
                except http.client.IncompleteRead as error:
                    raw, read_error = error.partial[:4 * 1024 * 1024 + 1], error
                require(self.token.encode() not in raw, "credential reflection refused")
                self.session = response.headers.get("Mcp-Session-Id", self.session)
            name = f"http-body-{wire_id:05d}.bin"
            write_new(self.output / name, raw)
            self.event({"stage": "response", "wire_id": wire_id, "http_status": status,
                        "body": name, "body_bytes": len(raw), "body_sha256": sha256(raw).hexdigest(),
                        "read_complete": read_error is None and len(raw) <= 4 * 1024 * 1024,
                        "elapsed_ns": time.monotonic_ns() - started})
            if read_error is not None:
                raise read_error
            require(len(raw) <= 4 * 1024 * 1024, "HTTP response exceeded the original transport bound")
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

    def call(self, tool, arguments, original=None):
        response = (self._domain_result(self.rpc("tools/call", {"name": tool, "arguments": arguments}))
                    if original is None else original)
        if response.get("status") not in ("accepted", "unknown"):
            return response
        identity = self.pending_identity(response)
        self.event({"stage": "pending_operation", "tool": tool, "arguments": arguments,
                    "response": response, "policy": "observe this original job; no fresh request key"})
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


def verify_listing(transport):
    listing = transport.list_tools()
    client = ToolClient(transport.call, validate=True)
    observed = {tool["name"]: tool for tool in listing}
    require(len(listing) == len(observed) == 113, "whole tool catalog count differs")
    require(len(client.tools) == 11 and set(client.tools) == {n for n in observed if n.startswith("hia_")},
            "HIA tool inventory differs")
    for name, expected in client.tools.items():
        for schema in ("inputSchema", "outputSchema"):
            require(observed[name][schema] == expected[schema], "HIA schema differs: " + name)
    return listing


def verify_session(session):
    require(session.catalog_sha256 == PINS["catalog_sha256"], "worker catalog pin differs")
    require({k: session.manifest["installation"][k] for k in PINS} == PINS,
            "worker installation pins differ")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-commit", required=True)
    parser.add_argument("--campaign-id", required=True)
    args = parser.parse_args(argv)
    require(not sys.flags.optimize, "assertions must remain enabled")
    require(args.runtime_commit == RUNTIME_COMMIT, "runtime source identity differs from c81")
    require(args.url in ENDPOINTS, "only the selected 8792/8790 loopback endpoints are allowed")
    binding = selected_campaign(args.campaign_id)
    source = verify_source()
    args.output.mkdir(mode=0o700)  # Exclusive registration; never resume by rerunning the loop.
    started = time.monotonic_ns()
    registration = {"schema": "hia-http-qualification-registration-v4", "hepta_commit": HEPTA_COMMIT,
                    "runtime_commit": args.runtime_commit, "source": source,
                    "runtime_identity_scope": "caller-supplied commit; actual binary/PID/listener must be bound by separate before/after shadow receipts",
                    "adapter_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
                    "url": args.url, "campaign": binding, "pins": PINS,
                    "initial_expected_current": {"generation": "0", "epoch": "0"},
                    "ownership": "exclusive local registration; server creates only through original conditional adoption",
                    "dependencies": {name: importlib.metadata.version(name) for name in
                                     ("jsonschema", "jsonschema-specifications", "referencing", "rpds-py", "attrs")}}
    dump(args.output / "registration.json", registration)
    journal = args.output / "application-events.jsonl"
    write_new(journal, b"")
    transport = client = session = None
    report = {"schema": "hepta.hia.agent.http-qualification.v1", "status": "failed",
              "mode": "actual_hepta_runtime_http_mcp", "registration": registration,
              "formal_endpoint_qualified": False, "current_agent_tool_discovery_established": False,
              "coverage": {"eleven_tool_flow": False, "stale_generation_rejection": False,
                           "rollback": False, "cancel": False, "reconnect": False,
                           "remaining_lifecycle_client": "http_lifecycle.py"},
              "claims": {"scripted_integration_observed": False, "fresh_model_learning_test_performed": False,
                         "model_training_exposure_known": False, "universal_backend_refinement_proved": False,
                         "net_optimization_benefit_proved": False}}
    try:
        transport = MCPHTTP(args.url, token_bytes(args.token_file), args.output)
        listing = verify_listing(transport)
        client = ToolClient(transport.call, validate=True, journal=lambda event: append_event(journal, event))
        session = Session(client, prefix=binding["request_prefix"])
        verify_session(session)
        result = scripted_loop(session, target_slot=binding["target_slot"])
        require(len(client.records) == 39, "application call count differs from the registered 39-call loop")
        require({r["tool"] for r in client.records} == set(client.tools), "full eleven-tool lifecycle incomplete")
        slots = [r for r in client.records if "target_slot" in r["arguments"]]
        require([r["tool"] for r in slots] == ["hia_adopt", "hia_adopt", "hia_rollback"], "slot call order differs")
        require(all(r["arguments"]["target_slot"] == binding["target_slot"] for r in slots), "target isolation failed")
        require(result["adoption"]["previous"] == {"generation": "0", "epoch": "0"}, "initial target state differs")
        require(result["rollback"]["current"] == {"generation": "0", "epoch": "2"}, "rollback did not restore baseline")
        report.update(status="passed", scenario=result, tools_list=listing, catalog_sha256=session.catalog_sha256)
        report["coverage"].update(eleven_tool_flow=True, stale_generation_rejection=True, rollback=True)
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
            report["connection"] = transport.connection_receipt()
            transport.close()
        report["application_events_sha256"] = sha256(journal.read_bytes()).hexdigest()
        report["wire_files"] = {p.name: {"bytes": p.stat().st_size, "sha256": sha256(p.read_bytes()).hexdigest()}
                                for p in args.output.glob("http-*") if p.is_file()}
        dump(args.output / "result.json", report)
        print(json.dumps({"status": report["status"], "tool_calls": report["tool_call_count"],
                          "output": str(args.output)}), flush=True)


if __name__ == "__main__":
    main()
