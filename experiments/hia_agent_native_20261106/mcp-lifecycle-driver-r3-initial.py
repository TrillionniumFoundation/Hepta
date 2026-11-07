"""Actual MCP lifecycle checks; administrator supplies an already isolated endpoint.

This is a replayable integration harness, not a fresh-agent learning experiment.
It touches only the supplied qualification state and a child bad-pin namespace.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--command", type=Path, required=True)
    parser.add_argument("--qualification-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    sys.path.insert(0, str(options.root / "qualification" / "tools"))
    import hia_agent_native_qualification as q
    from hia_agent_native_transport import MCPStdio, QualificationFailure

    command = json.loads(options.command.read_bytes())
    previous = json.loads(options.qualification_report.read_bytes())
    config_path = Path(command[command.index("--runtime-config") + 1])
    config = json.loads(config_path.read_bytes())
    log_path = options.output.with_suffix(".jsonl")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema": "hepta.hia.agent.mcp-lifecycle.v1", "status": "running",
              "mode": "actual_hepta_runtime_stdio_mcp", "checks": {},
              "qualification_report_sha256": hashlib.sha256(options.qualification_report.read_bytes()).hexdigest(),
              "runtime_binary_sha256": hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(),
              "catalog_sha256": config["hia_worker"]["catalog_sha256"],
              "worker_sha256": config["hia_worker"]["worker_sha256"],
              "backend_sha256": config["hia_worker"]["backend_sha256"],
              "claims": {"fresh_model_learning_test_performed": False,
                         "universal_backend_refinement_proved": False,
                         "net_optimization_benefit_proved": False}}
    current = None

    def log(event):
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def save():
        options.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    def check(name, detail):
        report["checks"][name] = detail
        save()
        print(json.dumps({"check": name, "status": "passed"}), flush=True)

    def open_endpoint(label, argv=command):
        endpoint = MCPStdio(argv, cwd=options.root / "qualification", timeout=180)
        log({"kind": "open", "session": label, "command": argv,
             "protocol": deepcopy(endpoint.protocol_records)})
        original = endpoint.rpc

        def recorded(method, params):
            start = time.monotonic_ns()
            offset = len(endpoint.protocol_records)
            log({"kind": "request", "session": label, "method": method, "params": params})
            try:
                result = original(method, params)
            except BaseException as exc:
                log({"kind": "failure", "session": label, "method": method,
                     "error": str(exc), "elapsed_ns": str(time.monotonic_ns() - start),
                     "protocol": deepcopy(endpoint.protocol_records[offset:])})
                raise
            log({"kind": "response", "session": label, "method": method,
                 "elapsed_ns": str(time.monotonic_ns() - start),
                 "protocol": deepcopy(endpoint.protocol_records[offset:])})
            return result

        endpoint.rpc = recorded
        return endpoint

    def close_endpoint(endpoint, label):
        log({"kind": "close", "session": label, "bounded_stderr": endpoint.stderr()})
        endpoint.close()

    def native_result(endpoint, name, arguments):
        raw = endpoint.rpc("tools/call", {"name": name, "arguments": arguments})
        if raw.get("isError"):
            raise QualificationFailure("native tool error: " + json.dumps(raw))
        if isinstance(raw.get("structuredContent"), dict):
            return raw["structuredContent"]
        for item in raw.get("content", []):
            if item.get("type") == "text":
                try:
                    return json.loads(item["text"])
                except ValueError:
                    pass
        raise QualificationFailure("native tool omitted JSON result")

    def observe_terminal(endpoint, operation):
        arguments = {"host": operation["host"], "job_id": operation["job_id"]}
        deadline = time.monotonic() + 90
        while True:
            state = native_result(endpoint, "process_status", arguments)
            if state.get("state") in {"succeeded", "failed", "cancelled", "timed_out"}:
                return state
            if time.monotonic() >= deadline:
                raise QualificationFailure("original operation has no confirmed terminal state: " + json.dumps(state))
            time.sleep(0.1)

    try:
        current = open_endpoint("recovery-a")
        client = q.ToolClient(current.call)
        session = q.Session(client, prefix="transport-lifecycle")
        reference = session.discovery["manifest"]
        deadline = time.monotonic() + 90
        pending_operations = []
        while True:
            try:
                resource = current.rpc("resources/read", {"uri": reference["uri"]})
                break
            except QualificationFailure:
                error = current.protocol_records[-1]["response"].get("error", {})
                domain = error.get("data", {})
                if domain.get("status") != "accepted" or time.monotonic() >= deadline:
                    raise
                pending_operations.append(domain["operation"])
                time.sleep(0.05)
        contents = resource["contents"]
        assert len(contents) == 1 and contents[0]["uri"] == reference["uri"]
        page = json.loads(contents[0]["text"])
        assert page["artifact"] == reference and page["next_cursor"] is None
        data = page["content"].encode("utf-8") if page["encoding"] == "utf8" else base64.b64decode(page["content"], validate=True)
        assert hashlib.sha256(data).hexdigest() == reference["sha256"]
        assert data == session.read(reference)
        check("resource_uri_read", {"artifact": reference, "bytes": len(data),
              "pending_operations": pending_operations, "digest_verified": True})

        original = next(item for item in previous["calls"] if item["tool"] == "hia_artifact")
        replay_before = current.call(original["tool"], original["arguments"])
        assert replay_before == original["response"]
        close_endpoint(current, "recovery-a")
        current = None
        current = open_endpoint("recovery-b")
        replay_after = current.call(original["tool"], original["arguments"])
        assert replay_after == replay_before
        check("exact_key_replay_across_server_restart", {"request": original,
              "response_equal_before_and_after": True})

        changed = deepcopy(original["arguments"])
        changed["source"] = {"kind": "utf8", "text": "same key, deliberately different artifact body"}
        changed_raw = current.rpc("tools/call", {"name": "hia_artifact", "arguments": changed})
        if changed_raw.get("isError"):
            changed_result = {"transport_tool_error": changed_raw}
        else:
            changed_result = MCPStdio._domain_result(changed_raw)
            assert changed_result["status"] == "rejected"
        assert current.call(original["tool"], original["arguments"]) == replay_before
        check("changed_body_same_key_rejected", {"arguments": changed, "result": changed_result,
              "original_response_preserved": True})

        stale_catalog = deepcopy(next(item for item in previous["calls"] if item["tool"] == "hia_read")["arguments"])
        stale_catalog["catalog_sha256"] = "0" * 64
        stale = current.call("hia_read", stale_catalog)
        assert stale["status"] == "rejected" and stale["error"]["code"] == "HIA_CATALOG_CHANGED"
        check("stale_catalog_rejected", {"arguments": stale_catalog, "response": stale})

        session = q.Session(q.ToolClient(current.call), prefix="transport-cancellation")
        baseline = q.add_program(redundant_additions=128, module="cancellation_verification")
        candidate = q.add_program(optimized=True, module="cancellation_verification")
        for program in (baseline, candidate):
            extra = [{"name": "ignored_" + str(index), "type": "bool"} for index in range(4)]
            params = program["functions"][0]["params"] + extra
            program["functions"][0]["params"] = deepcopy(params)
            program["functions"][0]["blocks"][0]["params"] = deepcopy(params)
        session.freeze({"schema": "hepta.hia.agent.workload.v1", "cases": [
            {"function": "transform", "arguments": [0, False, False, False, False],
             "expected": {"status": "returned", "values": [7]}}],
            "warmup_iterations": 0, "repetitions": 1})
        baseline_ref = session.import_program(baseline)
        candidate_ref = session.import_program(candidate)
        verify_args = session.arguments(candidate=candidate_ref, base_program=baseline_ref,
            validation_profile=session.profiles["validation"], subject={"kind": "core"},
            claims=["core_admission", "behavior_equivalence"])
        accepted = MCPStdio._domain_result(current.rpc("tools/call", {"name": "hia_verify", "arguments": verify_args}))
        assert accepted["status"] == "accepted", "verification finished before cancellation could be tested"
        operation = accepted["operation"]
        cancellation = native_result(current, "process_cancel", {"host": operation["host"],
            "job_id": operation["job_id"], "grace_seconds": 0})
        terminal = observe_terminal(current, operation)
        assert terminal.get("cancelled") is True or terminal.get("state") == "cancelled"
        cancelled_report = current.call("hia_verify", verify_args)
        assert cancelled_report["status"] == "unknown" and cancelled_report["operation"] == operation
        log_read = native_result(current, "process_read", {"host": operation["host"],
            "job_id": operation["job_id"], "limit": 16384})
        close_endpoint(current, "recovery-b")
        current = None
        current = open_endpoint("recovery-c")
        repeated_cancelled = current.call("hia_verify", verify_args)
        assert repeated_cancelled == cancelled_report
        check("cancelled_operation_remains_unknown_across_restart", {
            "arguments": verify_args, "accepted": accepted, "cancellation": cancellation,
            "terminal": terminal, "response": cancelled_report, "process_read": log_read,
            "same_original_operation_after_restart": True})
        close_endpoint(current, "recovery-c")
        current = None

        bad_config = deepcopy(config)
        bad_config["state_dir"] = str(Path(config["state_dir"]) / "bad-pin-controller")
        host = bad_config["hia_worker"]["host"]
        bad_config["hosts"][host]["remote_state_dir"] = str(Path(config["hosts"][host]["remote_state_dir"]) / "bad-pin-jobs")
        bad_config["hia_worker"]["state_root"] = str(Path(config["hia_worker"]["state_root"]) / "bad-pin-state")
        bad_config["hia_worker"]["worker_sha256"] = "0" * 64
        bad_path = options.output.with_suffix(".bad-pin-config.json")
        bad_path.write_text(json.dumps(bad_config))
        bad_path.chmod(0o600)
        bad_command = list(command)
        bad_command[bad_command.index("--runtime-config") + 1] = str(bad_path)
        current = open_endpoint("bad-pin", bad_command)
        bad_response = current.call("hia_describe", {"section": "manifest"})
        assert bad_response["status"] == "unknown"
        bad_operation = bad_response["operation"]
        bad_terminal = observe_terminal(current, bad_operation)
        assert bad_terminal["state"] == "failed" and bad_terminal["exit_code"] != 0
        bad_read = native_result(current, "process_read", {"host": bad_operation["host"],
            "job_id": bad_operation["job_id"], "limit": 16384})
        assert current.call("hia_describe", {"section": "manifest"}) == bad_response
        check("wrong_worker_pin_fails_closed", {"configured_worker_sha256": "0" * 64,
            "actual_worker_sha256": config["hia_worker"]["worker_sha256"],
            "response": bad_response, "terminal": bad_terminal, "process_read": bad_read,
            "exact_replay_preserves_original_operation": True})
        report["status"] = "passed"
    except BaseException as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc),
                           "traceback": traceback.format_exc()}
        raise
    finally:
        if current is not None:
            close_endpoint(current, "final")
        save()
        print(json.dumps({"status": report["status"], "checks": list(report["checks"]),
                          "output": str(options.output)}), flush=True)


if __name__ == "__main__":
    main()
