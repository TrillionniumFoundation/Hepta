#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Reconcile retained original HIA operations without dispatching any effects.

Inputs are original native process_status/process_read receipts, plus the
operator's pre-existing job/nonce binding. The output attests consistency of
these supplied records; authentication remains the responsibility of the
transport that captured them. A known failed operation is never called a
successful deployment, and a completed worker does not authorize a retry.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


class ReconciliationError(ValueError):
    pass


def require(value, message):
    if not value:
        raise ReconciliationError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def unwrap(value):
    """Accept a native JSON object or its unmodified MCP envelope."""
    require(type(value) is dict, "receipt must be an object")
    if "content" not in value:
        return value
    require(value.get("isError") is not True, "MCP receipt is an error")
    if type(value.get("structuredContent")) is dict and "job_id" in value["structuredContent"]:
        return value["structuredContent"]
    rows = []
    for item in value.get("content", []):
        if item.get("type") == "text":
            try:
                row = json.loads(item["text"])
            except (ValueError, TypeError):
                continue
            if type(row) is dict and "job_id" in row:
                rows.append(row)
    require(len(rows) == 1, "exactly one native job receipt required")
    return rows[0]


def active_identity(status, expected_job):
    """Interpret the c81 systemd projection without weakening owner checks.

    c81 validates the frozen request, supervisor PID/start/UID and systemd
    InvocationID/Description before returning running. It does not project the
    nonce at the top level. Only this exact verified projection is admitted;
    owner_unknown, terminal, detached and malformed states are refused.
    """
    status = unwrap(status)
    require(status.get("job_id") == expected_job and status.get("state") == "running"
            and status.get("audit_recorded") is True
            and ("status_authoritative" not in status or status["status_authoritative"] is True),
            "original job is not authoritatively running")
    require(status.get("backend") == "systemd", "unsupported live owner projection")
    systemd = status.get("systemd", {})
    require(systemd.get("LoadState") == "loaded" and systemd.get("ActiveState") == "active"
            and systemd.get("SubState") == "running", "unit is not active and running")
    prefix = "Hepta Runtime job " + expected_job + " "
    description = systemd.get("Description")
    require(type(description) is str and description.startswith(prefix), "unit job binding differs")
    nonce = description[len(prefix):]
    invocation = systemd.get("InvocationID")
    require(re.fullmatch(r"[0-9a-f]{32}", nonce) is not None
            and type(invocation) is str and re.fullmatch(r"[0-9a-f]{32}", invocation) is not None,
            "unit incarnation is malformed")
    require("launch_nonce" not in status or status["launch_nonce"] == nonce,
            "top-level and verified unit nonces disagree")
    require(type(systemd.get("ExecMainPID")) is str
            and systemd["ExecMainPID"].isdigit() and int(systemd["ExecMainPID"]) > 0,
            "unit PID is missing")
    return {"job_id": expected_job, "launch_nonce": nonce,
            "invocation_id": invocation, "pid": systemd["ExecMainPID"],
            "source": "c81_verified_systemd_projection"}


def reconcile(binding, status, output, result_file=None):
    require(type(binding) is dict and set(binding) == {"host", "job_id", "launch_nonce", "kind"},
            "explicit original host/job/nonce/kind binding required")
    require(binding["kind"] in ("deployment", "hia_worker", "sentinel"), "unknown original kind")
    require(all(type(binding[k]) is str and binding[k] for k in binding), "invalid original binding")
    require(re.fullmatch(r"[0-9a-f]{32}", binding["launch_nonce"]) is not None, "invalid original nonce")
    state, logs = unwrap(status), unwrap(output)
    require(state.get("job_id") == logs.get("job_id") == binding["job_id"], "original job mismatch")
    require(state.get("launch_nonce") == binding["launch_nonce"], "original nonce mismatch")
    require("launch_nonce" not in logs or logs["launch_nonce"] == binding["launch_nonce"],
            "output original nonce mismatch")
    require(state.get("audit_recorded") is True and logs.get("audit_recorded") is True,
            "native audit receipt missing")
    require("status_authoritative" not in state or state["status_authoritative"] is True,
            "explicitly non-authoritative original status")
    require(state.get("state") in ("succeeded", "failed", "cancelled", "timed_out"),
            "original terminal is still unresolved")
    require(type(state.get("exit_code")) is int, "integer exit code required")
    require(type(state.get("terminal_publication_protocol")) is int
            and state["terminal_publication_protocol"] == 1, "unsupported terminal publication")
    require(all(state.get(k) is True for k in (
        "output_complete", "output_durable", "terminal_publication_confirmed")),
        "terminal/output publication is incomplete")
    require(state.get("automatic_retry") is False, "original retry policy is not retained")
    require((state["state"] == "succeeded") == (state["exit_code"] == 0), "state and exit code disagree")
    require(type(state.get("cancelled")) is bool and type(state.get("timed_out")) is bool,
            "terminal cancellation/timeout flags missing")
    require(state["cancelled"] == (state["state"] == "cancelled")
            and state["timed_out"] == (state["state"] == "timed_out"), "terminal flags contradict state")
    streams = {}
    for name in ("stdout", "stderr"):
        part = logs.get(name, {})
        require(type(part.get("bytes_hex")) is str, "exact original output bytes required")
        try:
            raw = bytes.fromhex(part["bytes_hex"])
        except ValueError as error:
            raise ReconciliationError("malformed original output hex") from error
        require(type(part.get("offset")) is int and part["offset"] == 0
                and type(part.get("size")) is int and part["size"] == len(raw)
                and type(part.get("next_offset")) is int and part["next_offset"] == len(raw)
                and part.get("eof") is True and part.get("text") == raw.decode("utf-8", "replace"),
                "complete original output/cursor mismatch")
        counts = state.get("log_bytes", {}).get(name, {})
        require(type(counts) is dict and set(counts) == {"seen", "stored"}
                and all(type(counts[k]) is int for k in counts)
                and counts == {"seen": len(raw), "stored": len(raw)}
                and state.get("log_synced", {}).get(name) is True
                and state.get("log_truncated", {}).get(name) is False
                and state.get("log_errors", {}).get(name, "missing") is None,
                "terminal and output accounting disagree")
        streams[name] = raw
    report = {"schema": "hepta.hia.original-reconciliation.v1", "original": binding,
        "terminal_reconciled": True, "state": state["state"], "exit_code": state["exit_code"],
        "automatic_retry_authorized": False, "new_operation_dispatched": False,
        "transport_authentication_in_scope": False, "production_qualification_granted": False,
        "input_sha256": {"binding": sha(canonical(binding)), "status": sha(canonical(status)),
                         "output": sha(canonical(output))},
        "output": {k: {"bytes": len(v), "sha256": sha(v)} for k, v in streams.items()},
        "model_tokens": None, "money_cost": None, "economic_costs_complete": False}
    if binding["kind"] == "deployment":
        outcome = json.loads(streams["stdout"])
        require(outcome.get("schema") == "hepta.hia.mac-controller-deployment.v1", "deployment schema differs")
        require(outcome.get("status") == ("passed" if state["state"] == "succeeded" else "failed"),
                "deployment and native terminal disagree")
        if result_file is not None:
            require(outcome == result_file, "result file and original stdout differ")
            report["input_sha256"]["result_file"] = sha(canonical(result_file))
        rollback = outcome.get("rollback", {})
        report.update(deployment_status=outcome["status"],
            operation_hepta_commit=outcome.get("hepta_commit"),
            operation_runtime_commit=outcome.get("runtime_commit"),
            production_deployed=outcome.get("production_deployed"),
            rollback_files_restored=all(rollback.get(k) is True for k in
                ("config_restored", "plist_restored", "link_restored")),
            rollback_complete=rollback.get("complete") is True,
            error=outcome.get("error"),
            later_live_state_establishes_original_success=False)
    elif binding["kind"] == "hia_worker" and state["state"] == "succeeded":
        outcome = json.loads(streams["stdout"])
        require(outcome.get("schema") == "hia-agent-worker-report-v1" and outcome.get("complete") is True,
                "complete original HIA worker report required")
        response = outcome.get("response", {})
        require(response.get("contract_version") == "hepta.hia.agent-native.v1"
                and response.get("status") in ("completed", "rejected"), "unresolved HIA domain report")
        report.update(tool=outcome.get("tool"), request_sha256=outcome.get("request_sha256"),
            profile_sha256=outcome.get("profile_sha256"),
            installation={k: outcome.get(k) for k in ("worker_sha256", "backend_sha256", "catalog_sha256")},
            domain_status=response["status"], domain_outcome=response.get("result", {}).get("outcome"),
            domain_result=response.get("result"), no_duplicate_operation_proved=False)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("binding", "status", "output"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--result-file", type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args(argv)
    values = [json.loads(getattr(args, key).read_bytes()) for key in ("binding", "status", "output")]
    result = json.loads(args.result_file.read_bytes()) if args.result_file else None
    try:
        report = reconcile(*values, result)
    except (ValueError, TypeError, KeyError) as error:
        report = {"schema": "hepta.hia.original-reconciliation.v1", "terminal_reconciled": False,
                  "automatic_retry_authorized": False, "error": str(error)}
    with args.receipt.open("xb") as stream:
        stream.write(canonical(report) + b"\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["terminal_reconciled"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
