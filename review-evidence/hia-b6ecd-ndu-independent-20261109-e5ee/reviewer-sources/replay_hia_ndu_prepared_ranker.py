#!/usr/bin/env python3
"""Read-only, standard-library replay of retained native ranking observations.

This checks original bytes, registrations, finite decisions, paired native
responses and disjoint cost arithmetic. It does not attest the host or timing,
execute native code, establish full lifecycle economics or grant authority.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import itertools
import json
from pathlib import Path
import statistics

ARMS = ("one_shot_ndu", "prepared_ndu", "ordinary_scalar")
HORIZONS = (1, 4, 16, 64)
EXPECTED_SOURCE = {
    "hepta/hia_ndu_prepared_ranker.py", "hepta/hia_ndu_optimizer.py",
    "hepta/hia_ndu_scalar_selection.py", "hepta/hia_rust_crosscheck.py",
    "tools/build_hia_ndu_bridge.py", "tools/qualify_hia_ndu_prepared_ranker.py",
    "rust/hia-ndu-bridge/Cargo.lock", "rust/hia-ndu-bridge/Cargo.toml",
    "rust/hia-ndu-bridge/src/main.rs", "rust/hia-ndu-bridge/upstream.json",
}


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_NDU_PREPARED_REPLAY: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def exact_integer(value, *, positive=False):
    require(type(value) is int and value >= (1 if positive else 0), "invalid measured integer")
    return value


def raw_bytes(value):
    require(type(value) is dict and set(value) == {"encoding", "bytes", "sha256", "data"},
            "original byte record shape")
    require(value["encoding"] == "base64" and len(value["data"]) <= 2 * 1024 * 1024,
            "bounded original byte record")
    raw = base64.b64decode(value["data"], validate=True)
    require(len(raw) == value["bytes"] and sha256(raw).hexdigest() == value["sha256"],
            "original byte record length or digest")
    return raw


def choose(request):
    rows = request["candidates"]
    feasible = [row for row in rows if row["hard_violation"] is False
                and row["resource_q32"] <= request["resource_cap_q32"]]
    best = min(row["cost_q32"] for row in feasible)
    frontier = sorted(row["id"] for row in feasible if row["cost_q32"] == best)
    return ("abstain" if "abstain" in frontier else frontier[0]), frontier, len(feasible)


def check_analysis(cells, analysis):
    """Rebuild every reported pair and statistic from the checked cell ledger."""
    expected_keys = {(horizon, pair, arm) for horizon in HORIZONS
                     for pair in range(1, 7) for arm in ARMS}
    indexed = {}
    for cell in cells:
        horizon = exact_integer(cell["horizon"], positive=True)
        pair = exact_integer(cell["pair"], positive=True)
        key = (horizon, pair, cell["arm"])
        require(key in expected_keys and key not in indexed,
                "analysis cell identity or duplicate")
        require(cell["status"] == "completed"
                and exact_integer(cell["completed_calls"], positive=True) == horizon,
                "analysis requires every registered cell complete")
        indexed[key] = exact_integer(cell["wall_ns"], positive=True)
    require(set(indexed) == expected_keys, "analysis cell denominator")
    rebuilt = []
    for horizon in HORIZONS:
        pairs = []
        differences = []
        for pair in range(1, 7):
            costs = {arm: indexed[horizon, pair, arm] for arm in ARMS}
            difference = costs["one_shot_ndu"] - costs["prepared_ndu"]
            differences.append(difference)
            pairs.append({"pair": pair, "complete": True,
                          "all_attempt_arm_wall_ns": costs,
                          "one_shot_minus_prepared_ns": difference,
                          "ordinary_minus_prepared_ns": costs["ordinary_scalar"] - costs["prepared_ndu"]})
        rebuilt.append({"horizon": horizon, "all_registered_cells_completed": True,
                        "pairs": pairs, "prepared_saving_summary_ns": {
                            "observations": len(differences), "sum": sum(differences),
                            "mean": statistics.mean(differences), "median": statistics.median(differences),
                            "min": min(differences), "max": max(differences),
                            "sample_stdev": statistics.stdev(differences),
                            "positive_pairs": sum(value > 0 for value in differences)}})
    # Canonical JSON retains the complete shape, list order and number types;
    # Python equality alone would silently equate true/1 and 1.0/1.
    require(wire(analysis) == wire(rebuilt),
            "reported paired analysis or summary differs from cell ledger")


def replay(directory, registration_sha256):
    root = Path(directory)
    registration_raw = (root / "registration.json").read_bytes()
    require(sha256(registration_raw).hexdigest() == registration_sha256,
            "explicit registration digest")
    registration = json.loads(registration_raw)
    report = json.loads((root / "result.json").read_bytes())
    require(set(registration["source_files"]) == EXPECTED_SOURCE, "closed source inventory")
    for name, digest in registration["source_files"].items():
        require(sha256((root / "frozen-source" / name).read_bytes()).hexdigest() == digest,
                "frozen source bytes: " + name)
    require(sha256((root / "original-build-receipt.json").read_bytes()).hexdigest()
            == registration["original_build_receipt_sha256"], "original build receipt")
    build = json.loads((root / "original-build-receipt.json").read_bytes())
    identity = registration["native_identity"]
    require(build["binary_sha256"] == identity["binary_sha256"]
            and build["upstream"]["commit"] == identity["upstream_commit"], "native build identity")
    require(report["registration_sha256"] == registration_sha256
            and report["source_files"] == registration["source_files"]
            and report["source_git"] == registration["source_git"]
            and report["source_unchanged"] is True, "source/report binding")
    require(report["p2_acceptance"] == "HOLD"
            and report["economic_benefit_established"] is False
            and report["ndu_incremental_value_established"] is False
            and report["whole_lifecycle_cost_complete"] is False
            and report["production_activation_allowed"] is False, "scope promotion")
    expected_schedule = [{"horizon": horizon, "pair": index + 1, "arms": list(order)}
                         for horizon in HORIZONS
                         for index, order in enumerate(itertools.permutations(ARMS))]
    require(registration["schedule"] == expected_schedule and len(registration["requests"]) == 64,
            "registered task denominator or order")
    expected_cells = [(row["horizon"], row["pair"], arm)
                      for row in expected_schedule for arm in row["arms"]]
    cells = [json.loads(line) for line in (root / "cell-ledger.jsonl").read_bytes().splitlines()]
    require([(row["horizon"], row["pair"], row["arm"]) for row in cells] == expected_cells,
            "cell order or denominator")
    require(report["planned_cells"] == report["completed_cells"] == len(expected_cells) == 72
            and report["failed_cells"] == report["unstarted_cells"] == 0
            and report["automatic_retries"] == registration["automatic_retries"] == 0,
            "reported completion")
    native_count = ordinary_count = 0
    native_replies = {}
    selected_rows = {}
    pid_values = []
    for cell in cells:
        horizon, pair, arm = cell["horizon"], cell["pair"], cell["arm"]
        require(cell["status"] == "completed" and cell["completed_calls"] == horizon
                and len(cell["calls"]) == horizon and cell["unexecuted_calls"] == 0,
                "incomplete cell cannot qualify")
        exact_integer(cell["wall_ns"], positive=True)
        require(json.loads((root / ("h%02d-p%02d-%s.json" % (horizon, pair, arm))).read_bytes()) == cell,
                "journal/cell mismatch")
        original_path = root / cell["originals"]["path"]
        require(original_path.name == "h%02d-p%02d-%s-originals.jsonl" % (horizon, pair, arm)
                and original_path.parent == root, "unexpected original path")
        original_bytes = original_path.read_bytes()
        require(len(original_bytes) == cell["originals"]["bytes"]
                and sha256(original_bytes).hexdigest() == cell["originals"]["sha256"],
                "original cell bytes")
        originals = [json.loads(line) for line in original_bytes.splitlines()]
        stride = 1 if arm == "ordinary_scalar" else 2
        require(len(originals) == horizon * stride, "missing or extra original event")
        for index in range(horizon):
            row = cell["calls"][index]
            request = registration["requests"][index]
            requested = wire(request)
            expected, frontier, feasible_count = choose(request)
            require(row["index"] == index and row["status"] == "completed"
                    and row["selected_id"] == expected
                    and row["request_sha256"] == sha256(requested).hexdigest(),
                    "observed decision/request identity")
            exact_integer(row["wall_ns"], positive=True)
            result = originals[index * stride + stride - 1]
            require(result["kind"] == "result" and result["index"] == index
                    and result["request"] == request
                    and sha256(wire(result["result"])).hexdigest() == row["result_sha256"],
                    "original result/summary mismatch")
            if arm == "ordinary_scalar":
                ordinary_count += 1
                require(result["result"]["native_ndu_evaluated"] is False
                        and result["result"]["selected_id"] == expected
                        and result["result"]["frontier"] == frontier,
                        "ordinary control altered")
            else:
                native_count += 1
                event = originals[index * stride]
                require(event["kind"] == "original_native_transport" and event["index"] == index,
                        "native original event order")
                observed = event["observation"]
                require(raw_bytes(observed["stdin"]) == requested
                        and observed["response_admitted"] is True and observed["error"] is None,
                        "actual native stdin/admission")
                require(all(observed["native_identity"][key] == value for key, value in identity.items()),
                        "native source/image identity")
                pump = observed["pump"]
                require(pump["started"] is True and pump["cleanup_confirmed"] is True
                        and pump["streams_complete"] is True and pump["returncode"] == 0
                        and pump["error"] is None, "native process incomplete")
                require(raw_bytes(pump["stderr"]) == b"", "native diagnostics present")
                stdout = raw_bytes(pump["stdout"])
                response = json.loads(stdout)
                require(response == result["result"]["native_response"]
                        and response["request_sha256"] == sha256(requested).hexdigest()
                        and response["objective_sha256"] == request["objective_sha256"]
                        and response["generation"] == request["generation"]
                        and response["upstream_commit"] == identity["upstream_commit"]
                        and response["pareto_frontier"] == frontier
                        and response["authority"] == "ADVISORY_ONLY"
                        and response["proves_program_safety"] is False,
                        "native response drift or promotion")
                expected_advice = "abstain" if feasible_count == 1 else frontier[0] if len(frontier) == 1 else None
                require(response["advisory_recommendation"] == expected_advice
                        and result["result"]["selection"]["selected_id"] == expected,
                        "native recommendation or caller tie rule")
                require(row["native_observations"] == 1, "native observation count")
                native_replies[(horizon, pair, arm, index)] = stdout
                pid_values.append(exact_integer(pump["pid"], positive=True))
            selected_rows[(horizon, pair, arm, index)] = expected
        if arm == "prepared_ndu":
            cost = cell["prepared_cost"]
            require(cost["closed"] is True and cost["complete"] is True
                    and cost["close_confirmed"] is True and cost["all_native_cleanup_confirmed"] is True
                    and cost["original_native_calls"] == horizon and cost["result_cache_hits"] == 0
                    and cost["native_process_reuse"] is False and len(cost["attempts"]) == horizon,
                    "prepared ownership/call count")
            require(sha256(wire(cost["preparation"])).hexdigest() == cost["preparation_receipt_sha256"],
                    "preparation receipt")
            subtotal = exact_integer(cost["preparation"]["preparation_wall_ns"], positive=True)
            subtotal += exact_integer(cost["close_wall_ns"], positive=True)
            for index, attempt in enumerate(cost["attempts"]):
                require(attempt["status"] == "completed" and attempt["native_started"] is True
                        and attempt["cleanup_confirmed"] is True and attempt["response_admitted"] is True,
                        "prepared failed attempt hidden")
                require(attempt["request_sha256"] == sha256(wire(registration["requests"][index])).hexdigest(),
                        "prepared request cost rebound")
                subtotal += exact_integer(attempt["wall_ns"], positive=True)
                require(attempt["caller_wall_ns"] == attempt["wall_ns"] + attempt["queue_wait_ns"],
                        "queue waiting counted twice")
            require(subtotal == cost["observed_disjoint_wall_ns"] and subtotal <= cell["wall_ns"],
                    "disjoint costs omitted, duplicated or outside cell")
        require(cell["native_calls_started"] == (0 if arm == "ordinary_scalar" else horizon),
                "cell native count")
    pairs = 0
    for horizon in HORIZONS:
        for pair in range(1, 7):
            for index in range(horizon):
                require(native_replies[(horizon, pair, "one_shot_ndu", index)]
                        == native_replies[(horizon, pair, "prepared_ndu", index)],
                        "paired actual native response bytes differ")
                require(len({selected_rows[(horizon, pair, arm, index)] for arm in ARMS}) == 1,
                        "three-arm decision mismatch")
                pairs += 1
    require(native_count == report["original_native_calls"] == 1020 and ordinary_count == 510,
            "full native/ordinary denominator")
    check_analysis(cells, report["analysis"])
    return {"schema": "hepta.hia.ndu-prepared-ranking-replay.v1",
            "registration_sha256": registration_sha256,
            "verifier_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
            "original_native_calls": native_count, "ordinary_calls": ordinary_count,
            "paired_native_responses_byte_identical": pairs, "distinct_observed_pids": len(set(pid_values)),
            "source_files_rehashed": len(EXPECTED_SOURCE), "cells_replayed": len(cells),
            "raw_identity_and_cost_arithmetic_consistent": True,
            "reported_analysis_recomputed": True,
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
