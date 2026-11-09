#!/usr/bin/env python3
"""Independent standard-library replay of original framed NDU observations.

This rechecks bytes, scalar decisions, lifecycle completion and cost arithmetic.
It does not execute NDU, attest clocks, prove the machine or establish economics.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import itertools
import json
from pathlib import Path
import re
import statistics

ARMS = ("prepared_ndu", "persistent_ndu", "ordinary_scalar")
HORIZONS = (1, 4, 16, 64)
PROFILE = "hepta.hia.ndu-ranking-persistent-framed.v1"
EXPECTED_SOURCE = {
    "hepta/hia_ndu_prepared_ranker.py", "hepta/hia_ndu_persistent_ranker.py",
    "hepta/hia_ndu_optimizer.py", "hepta/hia_ndu_scalar_selection.py",
    "hepta/hia_rust_crosscheck.py", "tools/build_hia_ndu_bridge.py",
    "tools/qualify_hia_ndu_prepared_ranker.py", "tools/qualify_hia_ndu_persistent_ranker.py",
    "tools/replay_hia_ndu_persistent_ranker.py", "tests/test_hia_ndu_persistent_ranker.py",
    "rust/hia-ndu-bridge/Cargo.lock", "rust/hia-ndu-bridge/Cargo.toml",
    "rust/hia-ndu-bridge/src/main.rs", "rust/hia-ndu-bridge/upstream.json",
}


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_NDU_PERSISTENT_REPLAY: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def integer(value, *, positive=False):
    require(type(value) is int and value >= (1 if positive else 0), "invalid observed integer")
    return value


def raw_bytes(value):
    require(type(value) is dict and set(value) == {"encoding", "bytes", "sha256", "data"},
            "original byte record shape")
    require(value["encoding"] == "base64" and len(value["data"]) <= 2 * 1024 * 1024,
            "original byte record bound")
    raw = base64.b64decode(value["data"], validate=True)
    require(len(raw) == value["bytes"] and sha256(raw).hexdigest() == value["sha256"],
            "original byte record hash/length")
    return raw


def summary(value):
    result = {}
    for key, item in value.items():
        if type(item) is dict and item.get("encoding") == "base64":
            raw = raw_bytes(item)
            result[key] = {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
        else:
            result[key] = item
    return result


def decode_frame(raw, sequence, session):
    require(len(raw) >= 73 and len(raw) <= 1024 * 1024 + 72,
            "frame memory bound")
    require(int.from_bytes(raw[:4], "big") == len(raw) - 4,
            "complete length-prefixed frame")
    require(int.from_bytes(raw[4:8], "big") == sequence
            and raw[8:72] == session.encode("ascii"), "frame session/sequence")
    return raw[72:]


def choose(request):
    feasible = [row for row in request["candidates"] if row["hard_violation"] is False
                and row["resource_q32"] <= request["resource_cap_q32"]]
    minimum = min(row["cost_q32"] for row in feasible)
    frontier = sorted(row["id"] for row in feasible if row["cost_q32"] == minimum)
    return ("abstain" if "abstain" in frontier else frontier[0]), frontier, len(feasible)


def verify_response(raw, result, request, identity):
    response = json.loads(raw)
    selected, frontier, feasible_count = choose(request)
    require(response == result["native_response"]
            and response["schema"] == "hepta.hia.ndu-response.v1"
            and response["request_sha256"] == sha256(wire(request)).hexdigest()
            and response["objective_sha256"] == request["objective_sha256"]
            and response["generation"] == request["generation"]
            and response["upstream_commit"] == identity["upstream_commit"]
            and response["entry_point"] == "codex_hepta_ndu::evaluate_candidates_with_policy"
            and response["pareto_frontier"] == frontier
            and response["authority"] == "ADVISORY_ONLY"
            and response["proves_program_safety"] is False
            and response["global_optimality_established"] is False, "native response binding or scope")
    for key in ("evaluation_digest_v2", "evaluation_policy_digest", "utility_profile_digest"):
        require(type(response[key]) is str and re.fullmatch("[0-9a-f]{64}", response[key]), "native digest")
    expected_advice = "abstain" if feasible_count == 1 else frontier[0] if len(frontier) == 1 else None
    require(response["advisory_recommendation"] == expected_advice
            and result["selection"]["selected_id"] == selected, "native/caller tie rule")
    require(all(result["native_identity"][key] == value for key, value in identity.items()),
            "returned native image identity")


def expected_analysis(cells):
    values = []
    for horizon in HORIZONS:
        pairs = []
        for pair in range(1, 7):
            rows = {row["arm"]: row for row in cells if row["horizon"] == horizon and row["pair"] == pair}
            cost = {arm: rows[arm]["wall_ns"] for arm in ARMS}
            pairs.append({"pair": pair, "complete": True, "all_attempt_arm_wall_ns": cost,
                          "prepared_minus_persistent_ns": cost["prepared_ndu"] - cost["persistent_ndu"],
                          "ordinary_minus_persistent_ns": cost["ordinary_scalar"] - cost["persistent_ndu"]})
        differences = [row["prepared_minus_persistent_ns"] for row in pairs]
        values.append({"horizon": horizon, "all_registered_cells_completed": True, "pairs": pairs,
                       "persistent_saving_summary_ns": {
                           "observations": 6, "sum": sum(differences), "mean": statistics.mean(differences),
                           "median": statistics.median(differences), "min": min(differences),
                           "max": max(differences), "sample_stdev": statistics.stdev(differences),
                           "positive_pairs": sum(value > 0 for value in differences)}})
    return values


def check_cost_intervals(cells, report):
    """Check the serial campaign's measured intervals as nested bounds.

    Both owners are created before the cell's calls and closed afterwards.
    Bookkeeping occupies unclassified outer time; nested timers must not be
    added to the campaign again or escape their enclosing call/cell interval.
    """
    campaign = integer(report["actual_campaign_wall_ns_to_summary"], positive=True)
    require(report["nested_cell_wall_added_again"] is False,
            "campaign timer must not add nested cell costs again")
    cell_total = 0
    for cell in cells:
        cell_wall = integer(cell["wall_ns"], positive=True)
        cell_total += cell_wall
        call_walls = [integer(row["wall_ns"], positive=True) for row in cell["calls"]]
        require(sum(call_walls) <= cell_wall,
                "serial call intervals exceed their enclosing cell")
        if cell["arm"] != "ordinary_scalar":
            cost = cell["owner_cost"]
            require(len(cost["attempts"]) == len(call_walls),
                    "owner attempts differ from recorded calls")
            preparation = (cost["preparation_wall_ns"] if cell["arm"] == "persistent_ndu"
                           else cost["preparation"]["preparation_wall_ns"])
            serial_cost = integer(preparation, positive=True) + integer(cost["close_wall_ns"], positive=True)
            for attempt, call_wall in zip(cost["attempts"], call_walls):
                service = integer(attempt["wall_ns"], positive=True)
                queued = integer(attempt["queue_wait_ns"])
                caller = integer(attempt["caller_wall_ns"], positive=True)
                require(caller == service + queued and caller <= call_wall,
                        "owner caller interval or queue differs from enclosing call")
                serial_cost += caller
            require(serial_cost <= cell_wall,
                    "owner serial intervals exceed their enclosing cell")
    require(cell_total <= campaign,
            "serial cell intervals exceed the measured campaign")


def replay(directory, registration_sha256):
    root = Path(directory)
    reg_raw = (root / "registration.json").read_bytes()
    require(sha256(reg_raw).hexdigest() == registration_sha256, "explicit registration digest")
    reg = json.loads(reg_raw)
    report = json.loads((root / "result.json").read_bytes())
    require(set(reg["source_files"]) == EXPECTED_SOURCE, "closed frozen-source inventory")
    for name, digest in reg["source_files"].items():
        require(sha256((root / "frozen-source" / name).read_bytes()).hexdigest() == digest,
                "frozen source: " + name)
    receipt_raw = (root / "original-build-receipt.json").read_bytes()
    build = json.loads(receipt_raw)
    identity = reg["native_identity"]
    require(sha256(receipt_raw).hexdigest() == reg["original_build_receipt_sha256"]
            == identity["build_receipt_sha256"]
            and build["binary_sha256"] == identity["binary_sha256"]
            and build["upstream"]["commit"] == identity["upstream_commit"]
            and sha256(wire(build["build_inputs"])).hexdigest() == identity["build_inputs_sha256"],
            "native build/image identity")
    require(build["builder_sha256"] == reg["source_files"]["tools/build_hia_ndu_bridge.py"],
            "builder source identity")
    for name, digest in build["adapter_files"].items():
        require(reg["source_files"].get("rust/hia-ndu-bridge/" + name) == digest,
                "native adapter source identity")
    require(report["registration_sha256"] == registration_sha256
            and report["source_files"] == reg["source_files"]
            and report["source_git"] == reg["source_git"]
            and report["native_identity"] == identity
            and report["source_unchanged"] is True, "source/report binding")
    require(report["p2_acceptance"] == "HOLD" and report["authority"] == "DENY_ALL"
            and report["economic_benefit_established"] is False
            and report["ndu_incremental_value_established"] is False
            and report["whole_lifecycle_cost_complete"] is False
            and report["production_activation_allowed"] is False, "scope promotion")
    schedule = [{"horizon": horizon, "pair": index + 1, "arms": list(order)}
                for horizon in HORIZONS for index, order in enumerate(itertools.permutations(ARMS))]
    require(reg["schedule"] == schedule and len(reg["requests"]) == 64
            and reg["arms"] == list(ARMS) and reg["persistent_profile"] == PROFILE
            and reg["per_call_timeout_s"] == 1.0 and reg["maximum_session_lifetime_s"] == 60.0
            and reg["whole_campaign_wall_budget_ns"] == 120_000_000_000,
            "registered tasks, orders and bounded budget")
    cells = [json.loads(line) for line in (root / "cell-ledger.jsonl").read_bytes().splitlines()]
    expected_cells = [(row["horizon"], row["pair"], arm) for row in schedule for arm in row["arms"]]
    require([(row["horizon"], row["pair"], row["arm"]) for row in cells] == expected_cells,
            "cell order/denominator")
    require(report["planned_cells"] == report["completed_cells"] == len(cells) == 72
            and report["failed_cells"] == report["unstarted_cells"] == 0
            and report["automatic_retries"] == reg["automatic_retries"] == 0
            and report["mechanism_execution_complete"] is True, "campaign completion")
    ordinary_count = native_responses = prepared_processes = persistent_processes = 0
    native_replies = {}
    selected_rows = {}
    observed_pids = []
    for cell in cells:
        horizon, pair, arm = cell["horizon"], cell["pair"], cell["arm"]
        stem = "h%02d-p%02d-%s" % (horizon, pair, arm)
        require(cell["status"] == "completed" and cell["completed_calls"] == horizon
                and len(cell["calls"]) == horizon and cell["unexecuted_calls"] == 0,
                "incomplete cell cannot qualify")
        integer(cell["wall_ns"], positive=True)
        require(json.loads((root / (stem + ".json")).read_bytes()) == cell, "journal/cell mismatch")
        require(cell["originals"]["path"] == stem + "-originals.jsonl", "original path")
        originals_raw = (root / cell["originals"]["path"]).read_bytes()
        require(len(originals_raw) == cell["originals"]["bytes"]
                and sha256(originals_raw).hexdigest() == cell["originals"]["sha256"], "original journal bytes")
        originals = [json.loads(line) for line in originals_raw.splitlines()]
        expected_length = horizon if arm == "ordinary_scalar" else horizon * 2 + (2 if arm == "persistent_ndu" else 0)
        require(len(originals) == expected_length, "missing or extra original event")
        cost = cell.get("owner_cost")
        session = worker_pid = None
        counted_wire = {"stdin": 0, "stdout": 0, "stderr": 0}
        if arm == "persistent_ndu":
            require(cost["session_accepted"] is True and cost["closed"] is True
                    and cost["complete"] is True and cost["profile"] == PROFILE
                    and cost["native_processes_started"] == 1
                    and cost["original_native_requests_completed"] == horizon
                    and cost["max_requests"] == horizon and cost["result_cache_hits"] == 0
                    and cost["native_process_reuse"] is True, "persistent owner completion")
            session = cost["session"]
            require(type(session) is str and re.fullmatch("[0-9a-f]{64}", session), "session nonce")
            worker_pid = integer(cost["worker_pid"], positive=True)
            first, last = originals[0], originals[-1]
            require(first["kind"] == last["kind"] == "original_persistent_transport"
                    and first["index"] == -1 and last["index"] == horizon - 1
                    and first["event"]["phase"] == "startup" and last["event"]["phase"] == "close",
                    "persistent lifecycle event order")
            startup = first["event"]["observation"]
            require(startup["sequence"] == 0 and startup["worker_pid"] == worker_pid
                    and startup["session"] == session and startup["frame_complete"] is True
                    and startup["error"] is None and startup["stdin_bytes_written"] == 0
                    and raw_bytes(startup["stdin_frame"]) == raw_bytes(startup["stderr"]) == b"",
                    "startup transport")
            greeting_raw = raw_bytes(startup["stdout_frame"])
            greeting = json.loads(decode_frame(greeting_raw, 0, session))
            require(greeting == {
                "schema": "hepta.hia.ndu-stream-hello.v1", "transport_profile": PROFILE,
                "upstream_commit": identity["upstream_commit"],
                "entry_point": "codex_hepta_ndu::evaluate_candidates_with_policy",
                "max_requests": horizon, "max_frame_json_bytes": 1048576, "max_session_bytes": 8388608,
                "authority": "ADVISORY_ONLY", "result_cache": False, "evaluates_each_request": True},
                "native stream greeting")
            counted_wire["stdout"] += len(greeting_raw)
            require(wire(summary(startup)) == wire(cost["startup"]), "startup cost observation")
            require(integer(startup["wall_ns"], positive=True)
                    <= integer(cost["preparation_wall_ns"], positive=True),
                    "startup exchange interval exceeds owner preparation")
            close = last["event"]["observation"]
            require(close["cleanup"]["pid"] == worker_pid and close["cleanup"]["cleanup_confirmed"] is True
                    and close["cleanup"]["signal_sent"] is True and close["cleanup"]["returncode"] == 0
                    and close["cleanup"]["reason"] == "explicit_close" and close["cleanup"]["error"] is None
                    and close["protocol_error"] is None and close["pipe_errors"] == []
                    and close["eof"] == {"stdout": True, "stderr": True}
                    and raw_bytes(close["stdout_suffix"]) == raw_bytes(close["stderr_suffix"]) == b"",
                    "persistent final protocol/cleanup")
            require(wire(cost["close"]) == wire({**summary(close), "image_close_error": None}), "close cost binding")
            close_wall = integer(close["wall_ns"], positive=True)
            require(close["cleanup_wall_is_nested"] is True
                    and integer(close["cleanup"]["wall_ns"], positive=True) <= close_wall
                    <= integer(cost["close_wall_ns"], positive=True),
                    "cleanup or transport close interval exceeds its enclosing close")
            persistent_processes += 1
            observed_pids.append(worker_pid)
        elif arm == "prepared_ndu":
            require(cost["closed"] is True and cost["complete"] is True and cost["close_confirmed"] is True
                    and cost["all_native_cleanup_confirmed"] is True and cost["original_native_calls"] == horizon
                    and cost["result_cache_hits"] == 0 and cost["native_process_reuse"] is False,
                    "prepared owner completion")
            require(sha256(wire(cost["preparation"])).hexdigest() == cost["preparation_receipt_sha256"],
                    "prepared receipt identity")
        for index in range(horizon):
            row = cell["calls"][index]
            request = reg["requests"][index]
            requested = wire(request)
            selected, frontier, _ = choose(request)
            require(row["index"] == index and row["status"] == "completed" and row["error"] is None
                    and row["selected_id"] == selected
                    and row["request_sha256"] == sha256(requested).hexdigest(), "call decision/request")
            integer(row["wall_ns"], positive=True)
            result_position = index if arm == "ordinary_scalar" else index * 2 + (2 if arm == "persistent_ndu" else 1)
            result_row = originals[result_position]
            require(result_row["kind"] == "result" and result_row["index"] == index
                    and result_row["request"] == request
                    and sha256(wire(result_row["result"])).hexdigest() == row["result_sha256"],
                    "original result identity")
            result = result_row["result"]
            if arm == "ordinary_scalar":
                require(result["native_ndu_evaluated"] is False and result["selected_id"] == selected
                        and result["frontier"] == frontier and result["request_sha256"] == sha256(requested).hexdigest(),
                        "ordinary control changed")
                ordinary_count += 1
            else:
                event = originals[result_position - 1]
                require(event["index"] == index, "original native event index")
                if arm == "prepared_ndu":
                    require(event["kind"] == "original_prepared_transport", "prepared native event")
                    observed = event["observation"]
                    require(raw_bytes(observed["stdin"]) == requested and observed["response_admitted"] is True
                            and observed["error"] is None
                            and all(observed["native_identity"][key] == value for key, value in identity.items()),
                            "prepared request/admission/identity")
                    pump = observed["pump"]
                    require(pump["started"] is True and pump["cleanup_confirmed"] is True
                            and pump["streams_complete"] is True and pump["returncode"] == 0
                            and pump["error"] is None and raw_bytes(pump["stderr"]) == b"", "prepared process completion")
                    response_bytes = raw_bytes(pump["stdout"])
                    observed_pids.append(integer(pump["pid"], positive=True))
                    prepared_processes += 1
                    attempt = cost["attempts"][index]
                    require(attempt["status"] == "completed" and attempt["native_started"] is True
                            and attempt["cleanup_confirmed"] is True and attempt["response_admitted"] is True
                            and attempt["stdout_sha256"] == sha256(response_bytes).hexdigest(),
                            "prepared attempt cost status")
                    require(integer(pump["wall_ns"], positive=True)
                            <= integer(attempt["wall_ns"], positive=True),
                            "prepared pump interval exceeds owner attempt")
                else:
                    require(event["kind"] == "original_persistent_transport"
                            and event["event"]["phase"] == "round", "persistent round event")
                    observed = event["event"]["observation"]
                    require(observed["worker_pid"] == worker_pid and observed["session"] == session
                            and observed["sequence"] == index + 1 and observed["frame_complete"] is True
                            and observed["error"] is None, "persistent frame completion/owner")
                    input_frame, output_frame = raw_bytes(observed["stdin_frame"]), raw_bytes(observed["stdout_frame"])
                    require(decode_frame(input_frame, index + 1, session) == requested
                            and observed["stdin_bytes_written"] == len(input_frame)
                            and raw_bytes(observed["stderr"]) == b"", "actual persistent input bytes")
                    response_bytes = decode_frame(output_frame, index + 1, session)
                    counted_wire["stdin"] += len(input_frame)
                    counted_wire["stdout"] += len(output_frame)
                    attempt = cost["attempts"][index]
                    require(attempt["status"] == "completed" and attempt["sequence"] == index + 1
                            and attempt["response_sha256"] == sha256(response_bytes).hexdigest()
                            and wire(attempt["transport"]) == wire(summary(observed)), "persistent attempt cost binding")
                    require(integer(observed["wall_ns"], positive=True)
                            <= integer(attempt["wall_ns"], positive=True),
                            "persistent exchange interval exceeds owner attempt")
                    require(result["native_identity"]["worker_pid"] == worker_pid
                            and result["native_identity"]["worker_session"] == session
                            and result["native_identity"]["transport_profile"] == PROFILE, "persistent returned identity")
                verify_response(response_bytes, result, request, identity)
                native_replies[(horizon, pair, arm, index)] = response_bytes
                native_responses += 1
                require(attempt["request_sha256"] == sha256(requested).hexdigest()
                        and attempt["caller_wall_ns"] == attempt["wall_ns"] + attempt["queue_wait_ns"],
                        "request cost or overlapping queue accounting")
                integer(attempt["wall_ns"], positive=True)
                integer(attempt["queue_wait_ns"])
            selected_rows[(horizon, pair, arm, index)] = selected
        expected_processes = 0 if arm == "ordinary_scalar" else 1 if arm == "persistent_ndu" else horizon
        require(cell["native_processes_started"] == expected_processes
                and cell["native_responses_checked"] == (0 if arm == "ordinary_scalar" else horizon),
                "cell native process/evaluation counts")
        if arm != "ordinary_scalar":
            require(len(cost["attempts"]) == horizon and cost["whole_lifecycle_cost_complete"] is False
                    and cost["economic_benefit_established"] is False, "owner cost scope")
            preparation = cost["preparation_wall_ns"] if arm == "persistent_ndu" else cost["preparation"]["preparation_wall_ns"]
            subtotal = integer(preparation, positive=True) + integer(cost["close_wall_ns"], positive=True)
            subtotal += sum(integer(row["wall_ns"], positive=True) for row in cost["attempts"])
            require(subtotal == cost["observed_disjoint_wall_ns"] and subtotal <= cell["wall_ns"],
                    "disjoint cost omissions or duplicate nested totals")
        if arm == "persistent_ndu":
            require(cost["wire_bytes"] == counted_wire and sum(counted_wire.values()) <= 8388608,
                    "persistent session cumulative wire budget")
    paired_count = 0
    for horizon in HORIZONS:
        for pair in range(1, 7):
            for index in range(horizon):
                require(native_replies[(horizon, pair, "prepared_ndu", index)]
                        == native_replies[(horizon, pair, "persistent_ndu", index)],
                        "paired original native JSON bytes differ")
                require(len({selected_rows[(horizon, pair, arm, index)] for arm in ARMS}) == 1,
                        "three-arm scalar decision mismatch")
                paired_count += 1
    require(prepared_processes == 510 and persistent_processes == 24
            and prepared_processes + persistent_processes == report["native_processes_started"]
            == reg["maximum_native_processes"] == 534
            and native_responses == report["native_responses_checked"]
            == reg["maximum_native_evaluations"] == 1020
            and ordinary_count == reg["maximum_ordinary_calls"] == 510, "complete denominator")
    require(wire(report["analysis"]) == wire(expected_analysis(cells)),
            "paired timing/statistics arithmetic or JSON types")
    check_cost_intervals(cells, report)
    return {"schema": "hepta.hia.ndu-persistent-ranking-replay.v1",
            "registration_sha256": registration_sha256,
            "verifier_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "prepared_native_processes": prepared_processes, "persistent_native_processes": persistent_processes,
            "original_native_responses_checked": native_responses, "ordinary_calls": ordinary_count,
            "paired_native_responses_byte_identical": paired_count,
            "distinct_observed_pids": len(set(observed_pids)),
            "source_files_rehashed": len(EXPECTED_SOURCE), "cells_replayed": len(cells),
            "raw_frame_identity_cleanup_and_cost_arithmetic_consistent": True,
            "nested_cost_intervals_reconciled": True,
            "timings_independently_authenticated": False, "machine_refinement_proved": False,
            "economic_benefit_established": False, "authority": "DENY_ALL"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--registration-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    report = replay(args.directory, args.registration_sha256)
    with Path(args.output).open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
