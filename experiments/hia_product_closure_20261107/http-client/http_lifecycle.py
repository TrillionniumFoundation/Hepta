#!/usr/bin/env python3
"""Observe/cancel one real HIA evaluate job through a reinitialized HTTP client.

This is a scripted transport lifecycle check. It neither starts arbitrary test
processes nor owns/restarts the runtime. Only the returned x230 evaluate job may
be cancelled. A failed or uncertain attempt is retained, never replaced.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

import http_qualification as h
from hia_original_reconcile import active_identity, reconcile
from hia_agent_native_qualification import exhaustive_u8_workload

WORKER_HOST = "x230"
OWNER_TOOLS = {"process_status", "process_cancel", "process_read", "process_list_page"}
ACTIVE = {"running", "starting"}


def owner_call(connection, tool, arguments):
    h.require(tool in OWNER_TOOLS and arguments.get("host") == WORKER_HOST,
              "only selected native-owner observations/cancellation are allowed")
    result = connection.rpc("tools/call", {"name": tool, "arguments": arguments})
    h.require(result.get("isError") is not True, "native owner tool rejected the request")
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    for item in result.get("content", []):
        if item.get("type") == "text":
            try:
                value = json.loads(item["text"])
            except (ValueError, TypeError):
                continue
            if isinstance(value, dict):
                return value
    raise h.QualificationFailure("native owner omitted a JSON object")


def inventory(connection, output, filename):
    rows, pages, cursor, cursors = [], [], None, set()
    try:
        for _ in range(32):
            arguments = {"host": WORKER_HOST, "limit": 128}
            if cursor is not None:
                arguments["cursor"] = cursor
            page = owner_call(connection, "process_list_page", arguments)
            pages.append(page)
            rows.extend(page["jobs"])
            cursor = page["next_cursor"]
            h.require(len({r["id"] for r in rows}) == len(rows), "job inventory repeats an identity")
            if cursor is None:
                h.require(page["inventory_complete"] is True, "job inventory lacks its complete flag")
                result = {"complete": True, "rows": rows, "pages": pages}
                break
            h.require(isinstance(cursor, str) and cursor not in cursors, "inventory cursor repeated")
            cursors.add(cursor)
        else:
            raise h.QualificationFailure("job inventory exceeded 32 pages")
    except Exception as error:
        result = {"complete": False, "rows": rows, "pages": pages,
                  "error_type": type(error).__name__, "error": str(error)}
    h.dump(output / filename, result)
    return result


def prepare_evaluation(connection, scenario, binding, output):
    journal = output / "cancel-setup.calls.jsonl"
    h.write_new(journal, b"")
    client = h.ToolClient(connection.call, journal=lambda event: h.append_event(journal, event))
    session = h.Session(client, prefix=binding["request_prefix"] + "/cancel")
    h.verify_session(session)
    workload = exhaustive_u8_workload()
    workload["cases"] *= 2
    workload["repetitions"], workload["warmup_iterations"] = 10000, 100
    session.freeze(workload, baseline=scenario["baseline"], budget={
        "max_native_wall_ms": 60000, "max_total_wall_ms": 600000})
    core = session.verify(scenario["baseline"])
    build = session.emit(scenario["baseline"], receipts=[core["verification_receipt"]])
    encoding = session.encoding(scenario["baseline"], build)
    arguments = session.arguments(baseline_artifact=build["native_artifact"],
        candidate_artifact=build["native_artifact"], build_receipt=build["build_receipt"],
        verification_receipts=[core["verification_receipt"], encoding["verification_receipt"]])
    # The final submit deliberately uses raw RPC so the accepted job can be
    # observed while live; MCPHTTP.call would wait for its complete report.
    from jsonschema import Draft202012Validator
    Draft202012Validator(client.tools["hia_evaluate"]["inputSchema"]).validate(arguments)
    h.dump(output / "LIFECYCLE-REQUEST.json", {"tool": "hia_evaluate", "arguments": arguments,
        "request_key": arguments["request_key"], "workload": workload,
        "policy": "one real HIA evaluate attempt; reuse this original request and job only"})
    h.dump(output / "cancel-setup-result.json", {"calls": client.records,
        "manifest_installation": session.manifest["installation"]})
    return arguments


def evaluate_raw(connection, arguments):
    return connection._domain_result(connection.rpc("tools/call", {
        "name": "hia_evaluate", "arguments": arguments}))


def read_cancelled_output(connection, owner, output, launch_nonce=None):
    pages, streams, sizes = [], {"stdout": bytearray(), "stderr": bytearray()}, None
    for _ in range(65):
        page = owner_call(connection, "process_read", {**owner, "limit": 16384,
            "stdout_offset": len(streams["stdout"]), "stderr_offset": len(streams["stderr"])})
        pages.append(page)
        h.require(page["job_id"] == owner["job_id"], "cancelled output changed job identity")
        h.require("launch_nonce" not in page or page["launch_nonce"] == launch_nonce,
                  "cancelled output changed original launch nonce")
        current = {name: page[name]["size"] for name in streams}
        h.require(all(type(v) is int and v >= 0 for v in current.values())
                  and sum(current.values()) <= 512 * 1024, "cancelled output exceeded its bound")
        if sizes is None:
            sizes = current
        h.require(sizes == current, "cancelled output size changed after terminal publication")
        progress = False
        for name, raw in streams.items():
            part = page[name]
            data = bytes.fromhex(part["bytes_hex"])
            h.require(type(part["offset"]) is int and part["offset"] == len(raw)
                      and len(data) <= 16384 and part["text"] == data.decode("utf-8", "replace")
                      and type(part["next_offset"]) is int and part["next_offset"] == len(raw) + len(data)
                      and part["next_offset"] <= sizes[name]
                      and type(part["eof"]) is bool and part["eof"] == (part["next_offset"] == sizes[name]),
                      "cancelled output cursor/bytes/EOF disagree")
            raw.extend(data)
            progress = progress or bool(data)
        if all(len(streams[name]) == sizes[name] for name in streams):
            result = {"pages": pages, "complete": True, "streams": {
                name: {"bytes": len(raw), "sha256": sha256(raw).hexdigest()} for name, raw in streams.items()}}
            result["native_output"] = {"audit_recorded": all(p.get("audit_recorded") is True for p in pages),
                "job_id": owner["job_id"], **{name: {"offset": 0, "next_offset": len(raw),
                "size": len(raw), "eof": True, "bytes_hex": raw.hex(),
                "text": raw.decode("utf-8", "replace")} for name, raw in streams.items()}}
            if launch_nonce is not None:
                result["native_output"]["launch_nonce"] = launch_nonce
            h.dump(output / "cancelled-job-output.json", result)
            return result
        h.require(progress, "cancelled output made no progress")
    raise h.QualificationFailure("cancelled output pagination did not complete")


def run_lifecycle(scenario, binding, output, open_client):
    connection = open_client()
    admission = inventory(connection, output, "jobs-before-setup.json")
    h.require(admission["complete"], "complete inventory required before lifecycle setup")
    arguments = prepare_evaluation(connection, scenario, binding, output)
    before_inventory = inventory(connection, output, "jobs-before-evaluate.json")
    h.require(before_inventory["complete"],
              "complete original inventory required before dispatching the cancellable evaluation")
    first = evaluate_raw(connection, arguments)
    h.dump(output / "evaluate-first.json", first)
    h.require(first.get("status") == "accepted", "evaluate did not return accepted; preserve this attempt")
    host, job_id, _ = h.MCPHTTP.pending_identity(first)
    operation = first["operation"]
    owner = {"host": host, "job_id": job_id}
    before = owner_call(connection, "process_status", owner)
    h.dump(output / "status-before-disconnect.json", before)
    identity = active_identity(before, job_id)
    h.dump(output / "original-active-identity.json", identity)
    old_connection = connection.connection_receipt()
    connection.close()  # Discard this client/session; never stop the HTTP server.
    connection = open_client()
    new_connection = connection.connection_receipt()
    replay = evaluate_raw(connection, arguments)
    h.dump(output / "evaluate-after-reconnect.json", replay)
    h.require(replay.get("operation") == operation and replay.get("request_id") == first["request_id"]
              and replay.get("status") == "accepted", "reinitialized client did not observe the accepted original job")
    reconnected = owner_call(connection, "process_status", owner)
    h.dump(output / "status-after-reconnect.json", reconnected)
    h.require(active_identity(reconnected, job_id) == identity,
              "original job, nonce, PID or unit incarnation changed before cancellation")
    cancelled = owner_call(connection, "process_cancel", {**owner, "grace_seconds": 1})
    h.dump(output / "cancel-response.json", cancelled)
    observations = output / "cancel-status-observations.jsonl"
    h.write_new(observations, b"")
    terminal, deadline = None, time.monotonic() + 90
    while time.monotonic() < deadline:
        observed = owner_call(connection, "process_status", owner)
        h.append_event(observations, observed)
        if observed.get("state") == "running":
            h.require(active_identity(observed, job_id) == identity,
                      "cancellation observation changed the live original owner")
        else:
            h.require(observed.get("job_id") == job_id
                      and observed.get("launch_nonce") == identity["launch_nonce"],
                      "cancellation status changed original job identity or launch nonce")
        if (observed.get("state") == "cancelled" and observed.get("cancelled") is True
                and all(observed.get(k) is True for k in
                        ("output_complete", "output_durable", "terminal_publication_confirmed"))):
            terminal = observed
            break
        if observed.get("state") in ("succeeded", "failed", "timed_out"):
            break
        time.sleep(0.25)
    h.require(terminal is not None, "authoritative cancelled/durable terminal absent; retain original attempt")
    output_receipt = read_cancelled_output(connection, owner, output, identity["launch_nonce"])
    reconciled = reconcile({**owner, "launch_nonce": identity["launch_nonce"], "kind": "hia_worker"},
                           terminal, output_receipt["native_output"])
    h.dump(output / "cancelled-original-reconciliation.json", reconciled)
    replay_journal = output / "evaluate-after-cancel.jsonl"
    h.write_new(replay_journal, b"")
    for _ in range(2):
        response = evaluate_raw(connection, arguments)
        h.append_event(replay_journal, response)
        h.require(response.get("status") == "unknown" and response.get("operation") == operation
                  and response.get("request_id") == first["request_id"]
                  and response.get("error", {}).get("retry_action") == "observe_original"
                  and response.get("error", {}).get("code") == "HIA_WORKER_TERMINATED",
                  "cancelled replay did not preserve the unknown original operation")
    after_inventory = inventory(connection, output, "jobs-after-cancel-replay.json")
    no_duplicates, added, removed = False, [], []
    if before_inventory["complete"] and after_inventory["complete"]:
        before_ids = {r["id"] for r in before_inventory["rows"]}
        after_ids = {r["id"] for r in after_inventory["rows"]}
        added, removed = sorted(after_ids - before_ids), sorted(before_ids - after_ids)
        no_duplicates = added == [job_id] and not removed
    connection.close()
    result = {"status": "passed" if no_duplicates else "incomplete", "operation": operation,
        "original_arguments_sha256": sha256(h.json_bytes(arguments)).hexdigest(),
        "old_connection": old_connection, "new_connection": new_connection,
        "client_reinitialized": True, "server_restarted": False,
        "same_job_after_reconnect": True, "same_launch_nonce_after_reconnect": True,
        "authoritative_cancelled": True, "durable_terminal": True,
        "cancelled_output_complete": output_receipt["complete"],
        "unknown_original_after_cancel": True, "no_duplicate_native_job_proved": no_duplicates,
        "inventory_predicate": "complete global before/after ID sets; added equals only this job; removed is empty",
        "inventory_added": added, "inventory_removed": removed,
        "concurrent_unrelated_jobs_policy": "incomplete; never cancel any unrelated job",
        "current_agent_discovery_established": False, "real_model_experiment": False}
    h.dump(output / "LIFECYCLE.json", result)
    return result


def verify_workflow_scenario(scenario, binding):
    adoption, stale, rollback = (scenario[key] for key in ("adoption", "stale_adoption", "rollback"))
    h.require(stale.get("status") == "rejected" and stale.get("error", {}).get("code") == "E_HIA_GENERATION_STALE",
              "stale-generation step was rejected for a different reason")
    h.require(adoption["target_slot"] == binding["target_slot"]
              and adoption["previous"] == {"generation": "0", "epoch": "0"}
              and adoption["current"] == {"generation": "1", "epoch": "1"}
              and adoption["active_artifact"] == scenario["candidate_build"]["native_artifact"],
              "adoption did not publish the selected candidate to its owned slot")
    h.require(rollback["target_slot"] == binding["target_slot"]
              and rollback["previous"] == adoption["current"]
              and rollback["current"] == {"generation": "0", "epoch": "2"}
              and rollback["active_artifact"] == scenario["baseline_build"]["native_artifact"]
              and rollback["future_calls_only"] is True and rollback["past_effects_reversed"] is False,
              "rollback did not restore the retained baseline with its stated scope")


def load_workflow(path, url, binding):
    raw = h.read_private(path)
    workflow = json.loads(raw)
    registration = workflow["registration"]
    h.require(workflow["status"] == "passed" and workflow["tool_call_count"] == 39
              and len(workflow["tool_names_observed"]) == 11, "full eleven-tool workflow has not passed")
    h.require(registration["url"] == url and registration["campaign"] == binding
              and registration["pins"] == h.PINS and registration["hepta_commit"] == h.HEPTA_COMMIT
              and registration["runtime_commit"] == h.RUNTIME_COMMIT
              and registration["source"] == h.verify_source()
              and registration["adapter_sha256"] == sha256((h.ROOT / "http_qualification.py").read_bytes()).hexdigest(),
              "workflow belongs to a different endpoint/campaign/source/worker")
    verify_workflow_scenario(workflow["scenario"], binding)
    h.require(sha256(h.read_private(path.parent / "application-events.jsonl")).hexdigest()
              == workflow["application_events_sha256"], "workflow application journal changed")
    for name, receipt in workflow["wire_files"].items():
        h.require(Path(name).name == name and name.startswith("http-"), "unsafe workflow wire filename")
        data = h.read_private(path.parent / name)
        h.require(len(data) == receipt["bytes"] and sha256(data).hexdigest() == receipt["sha256"],
                  "workflow wire evidence changed")
    return workflow, sha256(raw).hexdigest()


def check_predecessor(directory, digest, reconciliation, workflow_sha, lifecycle_binding):
    """Bind a new validation trial to the actual retained previous operation."""
    raw = h.read_private(directory / "result.json")
    h.require(sha256(raw).hexdigest() == digest, "preceding attempt result pin differs")
    prior = json.loads(raw)
    registration = prior["registration"]
    h.require(prior["status"] == "failed" and registration["pins"] == h.PINS
              and registration["hepta_commit"] == h.HEPTA_COMMIT
              and registration["runtime_commit"] == h.RUNTIME_COMMIT
              and registration["workflow_sha256"] == workflow_sha,
              "preceding failed attempt belongs to another release/workflow")
    consumed = {"evaluate-first.json", "status-before-disconnect.json", "LIFECYCLE-REQUEST.json"}
    h.require(consumed <= set(prior["files"]), "preceding attempt manifest omits consumed evidence")
    verified = {}
    for name, pin in prior["files"].items():
        relative = Path(name)
        h.require(not relative.is_absolute() and ".." not in relative.parts, "unsafe original evidence path")
        data = h.read_private(directory / relative)
        h.require(len(data) == pin["bytes"] and sha256(data).hexdigest() == pin["sha256"],
                  "preceding attempt evidence differs")
        if name in consumed:
            verified[name] = json.loads(data)
    accepted = verified["evaluate-first.json"]
    host, job, request_sha = h.MCPHTTP.pending_identity(accepted)
    active = verified["status-before-disconnect.json"]
    identity = active_identity(active, job)
    h.require(reconciliation["original"] == {"host": host, "job_id": job,
                  "launch_nonce": identity["launch_nonce"], "kind": "hia_worker"}
              and reconciliation.get("request_sha256") == request_sha
              and reconciliation.get("installation") == h.PINS,
              "unrelated reconciliation cannot discharge this original operation")
    old = registration.get("lifecycle_campaign", registration["campaign"])
    request = verified["LIFECYCLE-REQUEST.json"]
    arguments = request["arguments"]
    h.require(request["tool"] == "hia_evaluate" and reconciliation.get("tool") == "hia_evaluate"
              and isinstance(request["request_key"], str)
              and request["request_key"] == arguments["request_key"]
              and request["request_key"].startswith(old["request_prefix"] + "/cancel/")
              and arguments["catalog_sha256"] == h.PINS["catalog_sha256"],
              "preceding request belongs to another namespace or tool")
    original_body = {"schema": "hia-agent-worker-request-v1", "tool": request["tool"],
        "arguments": arguments, "profile_sha256": reconciliation.get("profile_sha256"),
        "catalog_sha256": h.PINS["catalog_sha256"]}
    h.require(sha256(h.json_bytes(original_body)).hexdigest() == request_sha,
              "preceding request bytes do not bind the original worker request")
    h.require(lifecycle_binding["request_prefix"] != old["request_prefix"]
              and lifecycle_binding["target_slot"] != old["target_slot"],
              "a new trial cannot reuse the preceding lifecycle namespace")
    return {"url": registration["url"], "original": reconciliation["original"],
            "request_sha256": request_sha, "old_campaign": old}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--workflow-result", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--lifecycle-id", required=True,
                        help="distinct registered trial after reconciling the preceding attempt")
    parser.add_argument("--predecessor-reconciliation", required=True, type=Path)
    parser.add_argument("--predecessor-attempt", required=True, type=Path)
    parser.add_argument("--predecessor-attempt-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    h.require(not sys.flags.optimize and args.url in h.ENDPOINTS, "disabled checks or unselected endpoint")
    binding = h.selected_campaign(args.campaign_id)
    workflow, workflow_sha = load_workflow(args.workflow_result, args.url, binding)
    lifecycle_binding = h.selected_campaign(args.lifecycle_id)
    h.require(lifecycle_binding != binding, "new validation trial must not reuse the core campaign's lifecycle keys")
    predecessor_raw = h.read_private(args.predecessor_reconciliation)
    predecessor = json.loads(predecessor_raw)
    h.require(predecessor.get("schema") == "hepta.hia.original-reconciliation.v1"
              and predecessor.get("terminal_reconciled") is True
              and predecessor.get("original", {}).get("kind") == "hia_worker"
              and predecessor.get("state") in ("succeeded", "failed", "cancelled", "timed_out")
              and predecessor.get("automatic_retry_authorized") is False,
              "preceding original operation must be reconciled; this is a separately registered trial")
    predecessor_binding = check_predecessor(args.predecessor_attempt, args.predecessor_attempt_sha256,
                                           predecessor, workflow_sha, lifecycle_binding)
    h.require(predecessor_binding["url"] == args.url, "preceding attempt endpoint differs")
    args.output.mkdir(mode=0o700)
    registration = {"schema": "hia-http-v4-lifecycle-registration.v1", "url": args.url,
        "campaign": binding, "worker_host": WORKER_HOST, "pins": h.PINS,
        "lifecycle_campaign": lifecycle_binding,
        "predecessor_reconciliation_sha256": sha256(predecessor_raw).hexdigest(),
        "predecessor_original": predecessor["original"],
        "predecessor_attempt_sha256": args.predecessor_attempt_sha256,
        "predecessor_binding": predecessor_binding,
        "hepta_commit": h.HEPTA_COMMIT, "runtime_commit": h.RUNTIME_COMMIT,
        "workflow_result": str(args.workflow_result), "workflow_sha256": workflow_sha,
        "source": h.verify_source(), "client_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "automatic_retry": False, "controller_identity_scope": "parent's before/after mapped binary/PID/listener receipts"}
    h.dump(args.output / "registration.json", registration)
    connections, started = [], time.monotonic_ns()
    report = {"schema": "hia-http-v4-lifecycle-result.v1", "status": "failed", "registration": registration,
              "current_agent_discovery_established": False, "real_model_experiment": False,
              "formal_endpoint_qualified": False, "server_restart_performed": False}
    token = h.token_bytes(args.token_file)
    def open_client():
        directory = args.output / ("connection-" + str(len(connections) + 1))
        directory.mkdir(mode=0o700)
        client = h.MCPHTTP(args.url, token, directory)
        connections.append(client)
        h.verify_listing(client)
        return client
    try:
        result = run_lifecycle(workflow["scenario"], lifecycle_binding, args.output, open_client)
        report.update(status=result["status"], lifecycle=result)
    except BaseException as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error),
                             "preserve_original_attempt": True, "fresh_replacement_allowed": False}
        raise
    finally:
        report["connections"] = []
        for client in connections:
            report["connections"].append({"directory": str(client.output), **client.connection_receipt()})
            client.close()
        report["elapsed_ns"] = str(time.monotonic_ns() - started)
        report["files"] = {str(p.relative_to(args.output)): {"bytes": p.stat().st_size,
                            "sha256": sha256(p.read_bytes()).hexdigest()}
                           for p in args.output.rglob("*") if p.is_file()}
        h.dump(args.output / "result.json", report)
        print(json.dumps({"status": report["status"], "output": str(args.output)}), flush=True)
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
