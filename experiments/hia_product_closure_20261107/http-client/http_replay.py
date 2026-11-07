#!/usr/bin/env python3
"""Observe one retained HTTP HIA operation; never rerun its complete campaign.

If a pending worker identity was durably recorded, observe that original job
before any HIA replay. Otherwise dispatch only the identical original tool/body
and request key. No new campaign, candidate, target slot, or key is accepted.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import time

import http_qualification as h


def wire_attempts(events, url):
    """Reconstruct the exact core adapter's ordered logical HIA calls.

    A pending marker is emitted only after that call's first HTTP response. It
    binds its sole subsequent HIA replay, even when native-owner observations
    intervene. The application body never selects or filters this sequence.
    """
    attempts, wire_ids = [], set()
    pending_repeat, latest, latest_kind = None, None, None
    catalog = json.loads((h.ROOT / "docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json").read_bytes())
    known = {tool["name"] for tool in catalog["tools"]}
    for event in events:
        if event.get("stage") == "intent":
            h.require(("url" not in event or event["url"] == url) and type(event.get("wire_id")) is int
                      and event["wire_id"] > 0 and event["wire_id"] not in wire_ids,
                      "original HTTP intent endpoint or wire identity differs")
            wire_ids.add(event["wire_id"])
            request = event["request"]
            if request.get("method") != "tools/call":
                continue
            params = request["params"]
            if params.get("name") not in known:
                h.require(params.get("name") in ("process_wait", "process_read"),
                          "original core wire contains an unexpected tool call")
                continue
            intent = {"tool": params["name"], "arguments": params["arguments"]}
            if pending_repeat is not None:
                h.require(intent == pending_repeat["intent"],
                          "pending original HTTP call was followed by a different HIA body")
                pending_repeat["replay_wire_id"] = event["wire_id"]
                latest, latest_kind, pending_repeat = pending_repeat, "replay", None
            else:
                latest = {"intent": intent, "first_wire_id": event["wire_id"],
                          "first_jsonrpc_id": request.get("id"), "original_pending": None}
                attempts.append(latest)
                latest_kind = "first"
        elif event.get("stage") == "pending_operation":
            h.require(latest is not None and latest_kind == "first"
                      and latest["original_pending"] is None
                      and {"tool": event.get("tool"), "arguments": event.get("arguments")} == latest["intent"],
                      "pending wire evidence contradicts its original outbound HIA intent")
            h.MCPHTTP.pending_identity(event["response"])
            latest["original_pending"] = event["response"]
            pending_repeat = latest
    return attempts


def load_attempt(directory, sequence, expected_intent_sha256=None):
    registration_raw = h.read_private(directory / "registration.json")
    registration = json.loads(registration_raw)
    h.require(registration["hepta_commit"] == h.HEPTA_COMMIT
              and registration["runtime_commit"] == h.RUNTIME_COMMIT
              and registration["url"] in h.ENDPOINTS and registration["pins"] == h.PINS
              and registration["source"] == h.verify_source()
              and registration["adapter_sha256"] == sha256((h.ROOT / "http_qualification.py").read_bytes()).hexdigest(),
              "original registration identity differs")
    h.require(registration["campaign"] == h.selected_campaign(registration["campaign"]["id"]),
              "original campaign binding differs")
    raw = h.read_private(directory / "application-events.jsonl")
    h.require(not raw or raw.endswith(b"\n"), "partial application journal; retain it for exact recovery")
    events = [json.loads(line) for line in raw.splitlines()]
    all_intents = [event for event in events if event.get("phase") == "intent"]
    sequences = [event.get("sequence") for event in all_intents]
    h.require(all(type(value) is int and value >= 1 for value in sequences)
              and sequences == sorted(set(sequences)), "ordered unique original application sequences are required")
    selected = [event for event in events if event.get("sequence") == sequence]
    intents = [event for event in selected if event.get("phase") == "intent"]
    h.require(type(sequence) is int and sequence >= 1 and len(intents) == 1,
              "one exact original application intent is required")
    intent = {k: intents[0][k] for k in ("tool", "arguments")}
    h.require(all({k: event[k] for k in intent} == intent for event in selected),
              "original journal contains a changed tool or body")
    terminals = [event["response"] for event in selected if event.get("phase") == "response"]
    h.require(len(terminals) <= 1, "original sequence has multiple terminal responses")
    wire_raw = h.read_private(directory / "http-events.jsonl")
    h.require(not wire_raw or wire_raw.endswith(b"\n"), "partial HTTP journal; retain exact evidence")
    wire_events = [json.loads(line) for line in wire_raw.splitlines()]
    attempts = wire_attempts(wire_events, registration["url"])
    position = sequences.index(sequence)
    h.require(len(attempts) <= len(all_intents) and position < len(attempts),
              "selected application intent has no corresponding retained outbound HTTP attempt")
    for application, actual in zip(all_intents, attempts):
        h.require({k: application[k] for k in ("tool", "arguments")} == actual["intent"],
                  "application intent contradicts the corresponding original HTTP attempt")
    actual = attempts[position]
    intent_sha = sha256(h.json_bytes(actual["intent"])).hexdigest()
    if expected_intent_sha256 is not None:
        h.require(re.fullmatch("[0-9a-f]{64}", expected_intent_sha256) is not None
                  and intent_sha == expected_intent_sha256,
                  "original outbound intent differs from the externally fixed SHA-256")
    # A complete/failed final report, when present, is an additional immutable
    # binding. A crash may leave only the two fsynced journals; their cross-check
    # above remains mandatory and never falls back to an unbound new dispatch.
    result_path = directory / "result.json"
    if result_path.exists():
        report = json.loads(h.read_private(result_path))
        h.require(report["registration"] == registration
                  and report["application_events_sha256"] == sha256(raw).hexdigest()
                  and report["wire_files"]["http-events.jsonl"]["sha256"] == sha256(wire_raw).hexdigest(),
                  "original journals differ from their final report hashes")
    # ToolClient validates the retained original body against the exact catalog
    # before the callback can dispatch anything.
    return {"registration": registration, "registration_sha256": sha256(registration_raw).hexdigest(),
            "application_journal_sha256": sha256(raw).hexdigest(),
            "http_journal_sha256": sha256(wire_raw).hexdigest(), "sequence": sequence,
            "wire_endpoint_fields_present": all("url" in e for e in wire_events if e.get("stage") == "intent"),
            "intent": intent, "original_pending": actual["original_pending"],
            "original_outbound_intent_sha256": intent_sha, "wire_attempt": actual,
            "original_terminal": terminals[0] if terminals else None}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="original_directory", type=Path, required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--intent-sha256", help="Optional externally retained SHA-256 of the original tool/arguments object")
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    h.require(not sys.flags.optimize, "checks must remain enabled")
    attempt = load_attempt(args.original_directory, args.sequence, args.intent_sha256)
    args.output.mkdir(mode=0o700)
    registration = {"schema": "hia-http-v4-original-replay-registration.v1", **attempt,
        "original_directory": str(args.original_directory), "client_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "policy": "replay only this original tool/body; never resume or restart a complete loop"}
    h.dump(args.output / "registration.json", registration)
    journal = args.output / "replay-events.jsonl"
    h.write_new(journal, b"")
    transport, client, started = None, None, time.monotonic_ns()
    report = {"schema": "hia-http-v4-original-replay-result.v1", "status": "failed",
              "registration": registration, "whole_campaign_completed": False,
              "current_agent_discovery_established": False}
    try:
        transport = h.MCPHTTP(attempt["registration"]["url"], h.token_bytes(args.token_file), args.output)
        h.verify_listing(transport)
        def original_call(tool, arguments):
            h.require({"tool": tool, "arguments": arguments} == attempt["intent"], "replay body changed")
            return transport.call(tool, arguments, original=attempt["original_pending"])
        client = h.ToolClient(original_call, journal=lambda event: h.append_event(journal, event))
        response = client.call(attempt["intent"]["tool"], attempt["intent"]["arguments"], expected_status=None)
        if attempt["original_terminal"] is not None:
            h.require(response == attempt["original_terminal"], "original terminal changed during replay")
        h.require(response["status"] in ("completed", "rejected"), "original operation remains unresolved")
        report.update(status="observed", response=response, request_body_unchanged=True)
    except BaseException as error:
        report["failure"] = {"type": type(error).__name__, "message": str(error),
                             "fresh_request_key_allowed": False, "original_attempt_retained": True}
        raise
    finally:
        report["calls"] = client.records if client else []
        report["elapsed_ns"] = str(time.monotonic_ns() - started)
        if transport:
            report["connection"] = transport.connection_receipt()
            transport.close()
        report["files"] = {p.name: {"bytes": p.stat().st_size, "sha256": sha256(p.read_bytes()).hexdigest()}
                           for p in args.output.iterdir() if p.is_file()}
        h.dump(args.output / "result.json", report)
        print(json.dumps({"status": report["status"], "output": str(args.output)}), flush=True)


if __name__ == "__main__":
    main()
