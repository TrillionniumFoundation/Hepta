#!/usr/bin/env python3
"""Synthetic arithmetic/refusal qualification, never kernel measurements.

The executable is independent Rust. This external test harness additionally
checks a Python integer reference and the frozen actual native NDU executable.
Neither reference executable nor its output is an input to ordinary control.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import time

Q = 1 << 32
BOUND = 1_000_000 * Q


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(wire(value)).hexdigest()


def bind(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def multiply(left, right):
    product = left * right
    value, remainder = divmod(abs(product), Q)
    value += int(remainder > Q // 2 or (remainder == Q // 2 and value % 2 == 1))
    return -value if product < 0 else value


def values(items):
    return {x["axis"]: x["value_q32"] for x in items}


def independent_reference(request, previous):
    pref = request["preference"]
    initial = values(pref["genesis_values"] if previous is None else previous)
    target = values(pref["target"]) if pref["mode"] == "dynamic" else initial.copy()
    weights = initial.copy()
    residual = max(abs(weights[k] - target[k]) for k in weights)
    maximum = residual
    iterations = []
    if residual > 4096:
        for step in range(1, 65):
            weights = {k: v + multiply(target[k] - v, pref["eta_q32"]) for k, v in weights.items()}
            assert all(-Q <= v <= Q for v in weights.values())
            residual = max(abs(weights[k] - target[k]) for k in weights)
            iterations.append({"iteration": step, "residual_raw": residual, "weights": weights.copy()})
            if residual <= 4096:
                break
    assert residual <= 4096
    paths = {}
    feasible = {}
    for candidate in request["candidates"]:
        phase_reports = []
        if candidate["id"] == "abstain":
            recur = [0, 0]
        else:
            for phase in candidate["path"]:
                terms = {k: multiply(weights[k], v) for k, v in values(phase["components"]).items()}
                instant = sum(terms.values()) - phase["cost_q32"]
                phase_reports.append({"terms": terms, "instant": instant})
            recur = [request["terminal_utility_q32"]]
            for phase, calculation in reversed(list(zip(candidate["path"], phase_reports))):
                recur.insert(0, calculation["instant"] + multiply(phase["discount_q32"], recur[0]))
            assert all(-BOUND <= value <= BOUND for value in recur)
        okay = (candidate["verified"] and candidate["resource_cost_q32"] <= request["resource_budget_q32"]
                and candidate["risk_q32"] <= request["risk_ceiling_q32"])
        paths[candidate["id"]] = {"phases": phase_reports, "values": recur, "feasible": okay}
        if okay:
            feasible[candidate["id"]] = recur[0]
    maximum_value = max(feasible.values())
    frontier = sorted(k for k, v in feasible.items() if v == maximum_value)
    firsts = {c["path"][0]["image_id"] for c in request["candidates"] if c["id"] in frontier and c["path"]}
    selected = next(iter(firsts)) if len(firsts) == 1 and "abstain" not in frontier else None
    return {"initial": initial, "weights": weights, "iterations": iterations,
            "residual": residual, "maximum_residual": maximum, "paths": paths,
            "frontier": frontier, "selected": selected}


def fixture(mode="dynamic", horizon=4):
    image_ids = ["original", "fast", "small"]
    images = [{"id": name, "backend": backend, "artifact_sha256": sha(["synthetic-image", name]),
               "verification_digest": sha(["synthetic-correctness-fixture", name])}
              for name, backend in zip(image_ids, ("O2", "O3", "Os"))]
    utilities = {"original": (8, 3), "fast": (9, 0), "small": (1, 9)}
    candidates = []
    for index, seq in enumerate(itertools.product(image_ids, repeat=horizon)):
        phases = []
        for stage, image in enumerate(seq):
            latency, memory = utilities[image]
            phases.append({"image_id": image, "event_digest": sha(["event", index, stage]),
                "support_digest": sha(["support", index, stage]),
                "components": [{"axis": "latency", "value_q32": latency * Q},
                               {"axis": "memory", "value_q32": memory * Q}],
                "cost_q32": Q // 10, "discount_q32": Q * 7 // 8})
        candidates.append({"id": f"path-{index:03d}", "verified": True,
            "verification_digest": sha(["candidate", index]), "support_digest": sha(["path", seq]),
            "resource_cost_q32": horizon * Q, "risk_q32": 0, "uncertainty_q32": 0, "path": phases})
    candidates.append({"id": "abstain", "verified": True,
        "verification_digest": sha("zero-effect-test"), "support_digest": sha("zero-effect-support"),
        "resource_cost_q32": 0, "risk_q32": 0, "uncertainty_q32": 0, "path": []})
    return {"schema": "hepta.hia.kernel-ndu.request.v1", "objective_digest": sha("synthetic-objective"),
        "snapshot_digest": sha("synthetic-snapshot"), "action_registry_digest": sha(images),
        "generation": 1, "horizon": horizon, "utility_unit": "synthetic-test-unit",
        "resource_unit": "modeled-work", "resource_budget_q32": 100 * Q,
        "risk_ceiling_q32": Q, "terminal_utility_q32": 10 * Q,
        "preference": {"mode": mode, "previous_state": None,
            "genesis_values": [{"axis": "latency", "value_q32": Q // 2}, {"axis": "memory", "value_q32": Q // 2}],
            "target": [{"axis": "latency", "value_q32": Q}, {"axis": "memory", "value_q32": 0}],
            "eta_q32": Q // 4}, "images": images, "candidates": candidates}


def envelope(request, previous=None):
    return {"schema": "hepta.hia.kernel-ordinary-control.request.v1",
            "request": request, "previous_weights": previous}


def verify(outer, response):
    request, previous = outer["request"], outer["previous_weights"]
    expected = independent_reference(request, previous)
    assert response["schema"] == "hepta.hia.kernel-ordinary-control.response.v1"
    assert response["input_sha256"] == hashlib.sha256(wire(outer)).hexdigest()
    assert response["request_sha256"] == hashlib.sha256(wire(request)).hexdigest()
    assert response["native_ndu_linked_or_called"] is False
    assert response["native_state_digests_created"] is False
    assert response["measurements_created"] is False
    assert response["kernel_image_verified_by_adapter"] is False
    assert response["authority"] == "DENY_ALL"
    assert response["production_activation_allowed"] is False
    assert isinstance(response["service_before_output_ns"], int) and response["service_before_output_ns"] >= 0
    for key in ("objective_digest", "snapshot_digest", "action_registry_digest", "generation"):
        assert response[key] == request[key]
    pref = response["preference"]
    assert values(pref["initial_weights"]) == expected["initial"]
    assert values(pref["weights"]) == expected["weights"]
    assert pref["termination"] == {"iterations": len(expected["iterations"]),
        "terminal_residual_raw": expected["residual"],
        "maximum_residual_raw": expected["maximum_residual"], "projection_count": 0}
    assert len(pref["iterations"]) == len(expected["iterations"])
    for actual, ref in zip(pref["iterations"], expected["iterations"]):
        assert actual["iteration"] == ref["iteration"] and actual["residual_raw"] == ref["residual_raw"]
        assert values(actual["values"]) == ref["weights"] and actual["projection_count"] == 0
    assert len(response["paths"]) == len(request["candidates"])
    observed = {p["id"]: p for p in response["paths"]}
    for key, ref in expected["paths"].items():
        actual = observed[key]
        assert actual["values_q32"] == ref["values"]
        assert actual["feasible"] == ref["feasible"] and actual["projection_count"] == 0
        assert len(actual["phases"]) == len(ref["phases"])
        for actual_phase, ref_phase in zip(actual["phases"], ref["phases"]):
            assert actual_phase["instant_q32"] == ref_phase["instant"]
            assert {t["axis"]: t["weighted_q32"] for t in actual_phase["terms"]} == ref_phase["terms"]
            assert {t["axis"]: t["weight_q32"] for t in actual_phase["terms"]} == expected["weights"]
    assert sorted(response["pareto_candidate_ids"]) == expected["frontier"]
    assert response["selected_first_image_id"] == expected["selected"]
    assert response["complete_image_paths"] == 3 ** request["horizon"]
    return expected


def crosscheck_native(ordinary, native):
    assert ordinary["preference"]["weights"] == native["preference"]["state"]["values"]
    left, right = ordinary["preference"], native["preference"]
    for key in ("iterations", "terminal_residual_raw", "maximum_residual_raw", "projection_count"):
        assert left["termination"][key] == right["termination"][key], key
    assert len(left["iterations"]) == len(right["iterations"])
    for a, b in zip(left["iterations"], right["iterations"]):
        assert a["iteration"] == b["iteration"] and a["residual_raw"] == b["residual_raw"]
    a = {p["id"]: p for p in ordinary["paths"]}
    b = {p["id"]: p for p in native["paths"]}
    assert set(a) == set(b)
    for key in a:
        assert a[key]["values_q32"] == b[key]["values_q32"]
        assert len(a[key]["phases"]) == len(b[key]["phases"])
        for pa, pb in zip(a[key]["phases"], b[key]["phases"]):
            for field in ("image_id", "terms", "instant_q32", "cost_q32", "discount_q32"):
                assert pa[field] == pb[field], (key, field)
    assert sorted(ordinary["pareto_candidate_ids"]) == sorted(native["pareto_candidate_ids"])
    assert ordinary["selected_first_image_id"] == native["selected_first_image_id"]


def qualify(binary, native, output):
    output.mkdir(parents=True, exist_ok=False)
    identities = {"binary": bind(binary), "native_reference_binary": bind(native), "test_script": bind(__file__)}
    report = {"schema": "hepta.hia.kernel-ordinary-control.mechanism-qualification.v1",
        "status": "RUNNING", "synthetic_arithmetic_fixtures": True, "kernel_performance_observations": False,
        "production_control_calls_ndu": False, **identities, "checks": []}

    def record(name, **detail):
        report["checks"].append({"name": name, "status": "PASS", **detail})
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def invoke(executable, payload, name, reject=False):
        (output / (name + ".input.json")).write_bytes(payload)
        start = time.monotonic_ns()
        p = subprocess.run([str(executable)], input=payload, capture_output=True, timeout=30)
        elapsed = time.monotonic_ns() - start
        (output / (name + ".stdout")).write_bytes(p.stdout)
        (output / (name + ".stderr")).write_bytes(p.stderr)
        if reject:
            assert p.returncode != 0 and not p.stdout, (name, p.returncode)
            return None, elapsed
        assert p.returncode == 0, (name, p.stderr.decode(errors="replace"))
        return json.loads(p.stdout), elapsed

    def pair(request, name, previous=None, native_previous=None):
        outer = envelope(request, previous)
        ordinary, wall = invoke(binary, wire(outer), name + ".ordinary")
        expected = verify(outer, ordinary)
        native_request = copy.deepcopy(request)
        if native_previous is not None:
            native_request["preference"]["previous_state"] = native_previous
            native_request["preference"]["genesis_values"] = []
        actual_ndu, native_wall = invoke(native, wire(native_request), name + ".native")
        crosscheck_native(ordinary, actual_ndu)
        record(name, independently_replayed_paths=len(expected["paths"]),
            preference_iterations=len(expected["iterations"]), selected=expected["selected"],
            ordinary_wall_ns=wall, ordinary_service_ns=ordinary["service_before_output_ns"],
            native_wall_ns=native_wall, native_service_ns=actual_ndu["service_before_output_ns"],
            timing_purpose="mechanism receipt only; no kernel performance inference")
        return ordinary, actual_ndu

    try:
        p = subprocess.run([str(binary), "--identity"], check=True, capture_output=True, timeout=30)
        identity = json.loads(p.stdout)
        assert identity["profile"] == "hepta.hia.kernel-ordinary-control.v1"
        assert identity["native_ndu_linked_or_called"] is False
        report["identity"] = identity
        record("independent_binary_identity")
        fixed, _ = pair(fixture("fixed"), "fixed_complete_81_paths")
        dynamic, actual_ndu = pair(fixture(), "dynamic_complete_81_paths")
        assert fixed["selected_first_image_id"] == "original" and dynamic["selected_first_image_id"] == "fast"
        request = fixture()
        request["generation"] = 2
        request["snapshot_digest"] = sha("synthetic-next")
        request["preference"]["target"] = [{"axis": "latency", "value_q32": 0},
                                            {"axis": "memory", "value_q32": Q}]
        successor, successor_ndu = pair(request, "independent_successor_state", dynamic["preference"]["weights"],
                                       actual_ndu["preference"]["next_request_state"])
        assert successor["selected_first_image_id"] == "small"
        request3 = fixture()
        request3["generation"] = 3
        request3["preference"]["target"] = [{"axis": "latency", "value_q32": -Q // 2 + 1},
                                            {"axis": "memory", "value_q32": Q // 3}]
        pair(request3, "negative_signed_successor", successor["preference"]["weights"],
             successor_ndu["preference"]["next_request_state"])
        for horizon in (1, 2, 3):
            pair(fixture(horizon=horizon), f"complete_horizon_{horizon}")
        ties = fixture("fixed", 2)
        ties["preference"]["genesis_values"] = [{"axis": "latency", "value_q32": Q // 2},
                                               {"axis": "memory", "value_q32": -Q // 2}]
        ties["terminal_utility_q32"] = 1
        for candidate in ties["candidates"]:
            for phase in candidate["path"]:
                raw = {"original": 1, "fast": 3, "small": -3}[phase["image_id"]]
                phase.update(components=[{"axis": "latency", "value_q32": raw},
                                         {"axis": "memory", "value_q32": -raw}],
                             cost_q32=0, discount_q32=Q // 2)
        pair(ties, "positive_negative_halfway_ties_to_even")
        endpoints = fixture("dynamic", 4)
        for candidate in endpoints["candidates"]:
            for k, phase in enumerate(candidate["path"]):
                phase["discount_q32"] = 0 if k % 2 else Q
        pair(endpoints, "discount_zero_and_one")
        all_tied = fixture("fixed", 3)
        all_tied["terminal_utility_q32"] = 0
        for candidate in all_tied["candidates"]:
            for phase in candidate["path"]:
                phase["components"] = [{"axis": "latency", "value_q32": 0},
                                       {"axis": "memory", "value_q32": 0}]
                phase["cost_q32"] = 0
        response, _ = pair(all_tied, "all_frontier_ties_require_baseline")
        assert len(response["pareto_candidate_ids"]) == 28 and response["selected_first_image_id"] is None
        common = copy.deepcopy(all_tied)
        for candidate in common["candidates"]:
            if candidate["path"]:
                candidate["path"][0]["components"][0]["value_q32"] = (
                    Q if candidate["path"][0]["image_id"] == "fast" else -Q)
        response, _ = pair(common, "many_frontier_paths_one_common_first_action")
        assert len(response["pareto_candidate_ids"]) == 9 and response["selected_first_image_id"] == "fast"
        for name, field in [("resource", "resource_cost_q32"), ("risk", "risk_q32"), ("verification", "verified")]:
            request = fixture()
            if name == "risk":
                request["risk_ceiling_q32"] = Q // 2
            for candidate in request["candidates"][:-1]:
                candidate[field] = (False if name == "verification" else Q if name == "risk" else 101 * Q)
            response, _ = pair(request, "all_paths_hard_" + name + "_gate")
            assert response["pareto_candidate_ids"] == ["abstain"]
        for gap in (4096, 4097):
            request = fixture(horizon=1)
            request["preference"]["target"] = copy.deepcopy(request["preference"]["genesis_values"])
            request["preference"]["target"][0]["value_q32"] += gap
            response, _ = pair(request, f"residual_boundary_{gap}")
            assert response["preference"]["termination"]["iterations"] == (0 if gap == 4096 else 1)

        invalidations = [
            ("unknown_outer_field", lambda e: e.update(extra=True)),
            ("unknown_request_field", lambda e: e["request"].update(extra=True)),
            ("native_state_forbidden", lambda e: e["request"]["preference"].update(previous_state={"values": []})),
            ("previous_weights_dimensions", lambda e: e.update(previous_weights=[{"axis": "foreign", "value_q32": 0}])),
            ("previous_weights_range", lambda e: e.update(previous_weights=[{"axis": "latency", "value_q32": Q+1}, {"axis": "memory", "value_q32": 0}])),
            ("missing_candidate", lambda e: e["request"]["candidates"].pop(0)),
            ("duplicate_path", lambda e: e["request"]["candidates"][0].update(path=copy.deepcopy(e["request"]["candidates"][1]["path"]))),
            ("duplicate_candidate", lambda e: e["request"]["candidates"][0].update(id=e["request"]["candidates"][1]["id"])),
            ("registry_tamper", lambda e: e["request"].update(action_registry_digest="a"*64)),
            ("foreign_image", lambda e: e["request"]["candidates"][0]["path"][0].update(image_id="foreign")),
            ("incomplete_horizon", lambda e: e["request"]["candidates"][0]["path"].pop()),
            ("eta_change", lambda e: e["request"]["preference"].update(eta_q32=Q//8)),
            ("abstain_effect", lambda e: e["request"]["candidates"][-1].update(resource_cost_q32=1)),
            ("discount_range", lambda e: e["request"]["candidates"][0]["path"][0].update(discount_q32=Q+1)),
            ("negative_cost", lambda e: e["request"]["candidates"][0]["path"][0].update(cost_q32=-1)),
            ("zero_support", lambda e: e["request"]["candidates"][0]["path"][0].update(event_digest="0"*64)),
            ("target_axes", lambda e: e["request"]["preference"]["target"][0].update(axis="foreign")),
            ("unknown_mode", lambda e: e["request"]["preference"].update(mode="ndu-disguised-ordinary")),
            ("zero_generation", lambda e: e["request"].update(generation=0)),
            ("forbidden_recursive_projection", lambda e: (e["request"].update(terminal_utility_q32=BOUND),
                [p.update(discount_q32=Q) for c in e["request"]["candidates"] for p in c["path"]])),
        ]
        for name, mutate in invalidations:
            outer = envelope(fixture())
            mutate(outer)
            invoke(binary, wire(outer), "reject_" + name, reject=True)
            record("reject_" + name)
        duplicate_json = wire(envelope(fixture())).replace(b'{"previous_weights":null,',
                    b'{"previous_weights":null,"previous_weights":null,', 1)
        assert duplicate_json != wire(envelope(fixture()))
        invoke(binary, duplicate_json, "reject_duplicate_envelope_key", reject=True)
        record("reject_duplicate_envelope_key")
        invoke(binary, b"x" * (1_048_576 + 1), "reject_frame_bound", reject=True)
        record("reject_frame_bound")

        stream_inputs = [envelope(fixture("fixed", 1)), {"schema": "bad"},
                         envelope(fixture("dynamic", 1))]
        payload = b"\n".join(wire(v) for v in stream_inputs) + b"\n"
        proc = subprocess.run([str(binary), "--stream"], input=payload, capture_output=True, timeout=30)
        (output / "stream.input.jsonl").write_bytes(payload)
        (output / "stream.stdout").write_bytes(proc.stdout)
        (output / "stream.stderr").write_bytes(proc.stderr)
        assert proc.returncode == 0, proc.stderr
        rows = [json.loads(x) for x in proc.stdout.splitlines()]
        assert len(rows) == 4 and rows[0]["schema"] == "hepta.hia.kernel-ordinary-control.hello.v1"
        verify(stream_inputs[0], rows[1])
        assert rows[1]["stream_sequence"] == 1
        assert rows[2]["schema"] == "hepta.hia.kernel-ordinary-control.refusal.v1" and rows[2]["sequence"] == 2
        verify(stream_inputs[2], rows[3])
        assert rows[3]["stream_sequence"] == 3
        record("stream_frames_refusal_recovery_and_order")
        for key, identity in identities.items():
            assert bind(identity["path"]) == identity, key
        report["binary_and_reference_unchanged"] = True
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = str(error)
        raise
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--native-reference", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = qualify(args.binary.resolve(strict=True), args.native_reference.resolve(strict=True), args.output.resolve())
    print(json.dumps({"status": result["status"], "checks": len(result["checks"]),
                      "kernel_performance_observations": False, "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()
