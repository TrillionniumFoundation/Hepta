"""Bind the scripted MCP qualification to a frozen deployment and fresh state.

Administrator arguments identify the existing endpoint, approved roots, runtime
binary, and staged source manifest. No worker source or host policy is changed.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import select
import sys
import time
import traceback


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def publish_once(path, data, *, private=False):
    if path.exists():
        if path.read_bytes() != data:
            raise RuntimeError("Existing qualification control file changed: " + str(path))
        return
    path.write_bytes(data)
    if private:
        path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--runtime-binary", type=Path, required=True)
    parser.add_argument("--expected-runtime-sha256", required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    if not args.label.isalnum():
        parser.error("label must be a short alphanumeric namespace")
    root = args.root
    qualification = root / "qualification"
    evidence = root / "evidence"
    evidence.mkdir(exist_ok=True)
    sys.path.insert(0, str(qualification / "tools"))
    import hia_agent_native_qualification as q

    config = json.loads((root / "runtime-config.json").read_bytes())
    config["state_dir"] = str(root / ("qualification-controller-state-" + args.label))
    config["hia_worker"]["state_root"] = str(Path(config["hia_worker"]["state_root"]) / ("qualification-" + args.label))
    for host in config["hosts"].values():
        host["remote_state_dir"] = str(Path(host["remote_state_dir"]) / ("qualification-" + args.label))
    config_path = root / ("qualification-runtime-config-" + args.label + ".json")
    config_wire = (json.dumps(config, indent=2) + "\n").encode()
    publish_once(config_path, config_wire, private=True)
    command = json.loads((root / "mcp-command.json").read_bytes())
    command[0] = str(args.runtime_binary)
    command[command.index("--runtime-config") + 1] = str(config_path)
    command_path = root / ("qualification-mcp-command-" + args.label + ".json")
    command_wire = (json.dumps(command) + "\n").encode()
    publish_once(command_path, command_wire)
    source_copy = evidence / ("runtime-source-manifest-" + args.label + ".json")
    publish_once(source_copy, args.source_manifest.read_bytes())
    json.loads(source_copy.read_bytes())  # A source manifest is data, never code.

    output = evidence / ("mcp-qualification-" + args.label + ".json")
    calls = evidence / ("mcp-qualification-calls-" + args.label + ".jsonl")
    identity_path = evidence / ("mcp-qualification-binding-" + args.label + ".json")
    before = digest(args.runtime_binary)
    if before != args.expected_runtime_sha256:
        raise RuntimeError("Runtime binary differs from administrator-provided deployment pin")
    identity = {"schema": "hepta.hia.agent.qualification-binding.v1", "status": "running",
                "label": args.label, "runtime_binary": str(args.runtime_binary),
                "runtime_sha256_before": before, "runtime_sha256_after": None,
                "runtime_source_commit": args.source_commit,
                "runtime_source_manifest_file": source_copy.name,
                "runtime_source_manifest_sha256": digest(source_copy),
                "command": command, "command_file_sha256": digest(command_path),
                "configuration_sha256": digest(config_path),
                "qualification_driver_sha256": digest(__file__),
                "qualification_helper_sha256": digest(qualification / "tools" / "hia_agent_native_qualification.py"),
                "transport_sha256": digest(qualification / "tools" / "hia_agent_native_transport.py"),
                "expected_installation": {key: value for key, value in config["hia_worker"].items() if key.endswith("sha256")},
                "python_version": sys.version, "source_manifest_is_staged_build_input": True,
                "shared_configuration_modified": False, "host_permissions_broadened": False}

    def save():
        identity_path.write_text(json.dumps(identity, indent=2) + "\n")

    def append(value):
        with calls.open("ab") as handle:
            handle.write(q.json_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    original = q.ToolClient.call
    counter = 0

    def recorded(self, tool, arguments, **kwargs):
        nonlocal counter
        counter += 1
        sequence = counter
        started = time.monotonic_ns()
        append({"event": "request", "sequence": sequence, "tool": tool,
                "arguments": deepcopy(arguments)})
        offset = len(self.records)
        try:
            return original(self, tool, arguments, **kwargs)
        finally:
            records = self.records[offset:]
            append({"event": "response", "sequence": sequence, "records": records,
                    "elapsed_ns": str(time.monotonic_ns() - started)})
            print(json.dumps({"sequence": sequence, "tool": tool,
                "status": records[-1]["response"].get("status") if records else "transport_error"}), flush=True)

    q.ToolClient.call = recorded
    save()
    try:
        q.main(["--mcp-command-json", json.dumps(command), "--cwd", str(qualification),
                "--output", str(output)])
        report = json.loads(output.read_bytes())
        manifest = json.loads(next(record["response"]["result"]["content"]
                                   for record in report["calls"] if record["tool"] == "hia_read"))
        assert manifest["installation"] == identity["expected_installation"]
        catalog = json.loads((qualification / "docs" / "HIA_AGENT_NATIVE_TOOL_CATALOG.json").read_bytes())
        expected = {tool["name"]: tool for tool in catalog["tools"]}
        observed = {tool["name"]: tool for tool in report["tools_list"] if tool["name"].startswith("hia_")}
        assert set(observed) == set(expected)
        for name, tool in expected.items():
            # The published runtime facade adds this exact title to the
            # language catalog, which deliberately carries no title field.
            reviewed = {**tool, "title": name.replace("_", " ").upper()}
            for field in ("name", "title", "description", "inputSchema", "outputSchema", "annotations"):
                assert observed[name].get(field) == reviewed.get(field), (name, field)
        identity["catalog_exact_11_tools_verified"] = True
        identity["observed_installation"] = manifest["installation"]

        # The final runtime changed a serialized-input boundary. Exercise its
        # maximum legal Unicode-character count and record actual incoming wire
        # lines, while leaving the ordinary qualification transport unchanged.
        q.ToolClient.call = original
        from hia_agent_native_transport import MCPStdio, QualificationFailure

        class WireMCP(MCPStdio):
            def __init__(self, *positional, **keywords):
                self.wire_messages = []
                super().__init__(*positional, **keywords)

            def _read_message(self, deadline):
                while True:
                    if b"\n" in self.pending_bytes:
                        line, self.pending_bytes = self.pending_bytes.split(b"\n", 1)
                        if line.strip():
                            value = json.loads(line)
                            self.wire_messages.append({"id": value.get("id"),
                                "bytes_including_newline": len(line) + 1,
                                "sha256_including_newline": hashlib.sha256(line + b"\n").hexdigest(),
                                "raw_utf8": line.decode("utf-8") + "\n"})
                            return value
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Boundary MCP read deadline expired; original request outcome is unknown")
                    ready, _, _ = select.select([self.process.stdout], [], [], min(remaining, 1))
                    if not ready:
                        if self.process.poll() is not None:
                            raise QualificationFailure("Boundary MCP server exited: " + self.stderr())
                        continue
                    chunk = os.read(self.process.stdout.fileno(), 65536)
                    if not chunk:
                        raise QualificationFailure("Boundary MCP stream closed: " + self.stderr())
                    self.pending_bytes += chunk
                    if len(self.pending_bytes) > 4 * 1024 * 1024:
                        raise QualificationFailure("Boundary MCP response exceeded the declared client limit")

        boundary_path = evidence / ("mcp-serialization-boundary-" + args.label + ".json")
        boundary = {"schema": "hepta.hia.agent.serialization-boundary.v1", "status": "running",
                    "runtime_binary_sha256": before, "cases": []}
        endpoint = WireMCP(command, cwd=qualification)
        boundary_client = q.ToolClient(endpoint.call)
        try:
            boundary_session = q.Session(boundary_client, prefix=args.label + "/serialization-boundary")
            cases = [("nul_maximum", "\0" * 65536),
                     ("mixed_quote_backslash_control_maximum", '"' * 50000 + "\\" * 256 + "\0" * 256 + "x" * 15024)]
            for name, content in cases:
                assert len(content) == 65536
                first_record = len(endpoint.protocol_records)
                first_wire = len(endpoint.wire_messages)
                artifact = boundary_session.artifact(content)
                received = boundary_session.read(artifact)
                assert received == content.encode("utf-8")
                assert hashlib.sha256(received).hexdigest() == artifact["sha256"]
                request_sizes = [len(q.json_bytes(item["request"])) + 1
                                 for item in endpoint.protocol_records[first_record:]]
                response_sizes = [item["bytes_including_newline"]
                                  for item in endpoint.wire_messages[first_wire:]]
                # This is the worker's conservative response budget, below the
                # runtime's larger transport result maximum.
                assert max(response_sizes) <= 262144
                boundary["cases"].append({"name": name, "unicode_characters": len(content),
                    "utf8_bytes": len(received), "artifact": artifact, "round_trip_exact": True,
                    "request_wire_bytes_including_newline": request_sizes,
                    "response_wire_bytes_including_newline": response_sizes,
                    "maximum_response_wire_bytes": max(response_sizes)})
                print(json.dumps({"serialization_boundary": name, "status": "passed",
                                  "maximum_request_wire_bytes": max(request_sizes),
                                  "maximum_response_wire_bytes": max(response_sizes)}), flush=True)
            boundary["status"] = "passed"
        except BaseException as exc:
            boundary["status"] = "failed"
            boundary["error"] = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            boundary["calls"] = boundary_client.records
            boundary["mcp_protocol_records"] = endpoint.protocol_records
            boundary["actual_incoming_wire_messages"] = endpoint.wire_messages
            boundary["bounded_stderr"] = endpoint.stderr()
            endpoint.close()
            boundary_path.write_text(json.dumps(boundary, ensure_ascii=False, indent=2) + "\n")
        identity["maximum_escaped_input_round_trips"] = boundary["cases"]
        identity["serialization_boundary_report_sha256"] = digest(boundary_path)
        identity["runtime_sha256_after"] = digest(args.runtime_binary)
        assert identity["runtime_sha256_after"] == before
        assert digest(config_path) == identity["configuration_sha256"]
        assert digest(command_path) == identity["command_file_sha256"]
        assert digest(args.source_manifest) == identity["runtime_source_manifest_sha256"]
        identity["runtime_binary_unchanged_through_run"] = True
        identity["qualification_report_sha256"] = digest(output)
        identity["qualification_calls_sha256"] = digest(calls)
        identity["status"] = "passed"
    except BaseException as exc:
        identity["status"] = "failed"
        identity["runtime_sha256_after"] = digest(args.runtime_binary)
        identity["error"] = {"type": type(exc).__name__, "message": str(exc),
                             "traceback": traceback.format_exc()}
        raise
    finally:
        save()
        print(json.dumps({"binding_status": identity["status"], "binding": str(identity_path),
                          "runtime_sha256_before": before,
                          "runtime_sha256_after": identity["runtime_sha256_after"]}), flush=True)


if __name__ == "__main__":
    main()
