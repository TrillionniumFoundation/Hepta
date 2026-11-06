#!/usr/bin/env python3
"""Qualify native kernel NDU mechanics with EXPLICITLY SYNTHETIC fixtures.

These values are arithmetic fixtures, never kernel performance observations.
The independent ordinary reference checks every native preference update,
weighted term and complete recursive path. A measured Linux campaign is a
separate owner with real full-image build/boot/workload admission.
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

Q32 = 1 << 32
UPSTREAM = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d"


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(wire(value)).hexdigest()


def mul_q32(a, b):
    product = a * b
    quotient, remainder = divmod(abs(product), Q32)
    if remainder > Q32 // 2 or (remainder == Q32 // 2 and quotient % 2):
        quotient += 1
    return -quotient if product < 0 else quotient


def preference_reference(preference):
    state = preference["previous_state"]
    values = state["values"] if state else preference["genesis_values"]
    current = {v["axis"]: v["value_q32"] for v in values}
    target = {v["axis"]: v["value_q32"] for v in preference["target"]}
    if preference["mode"] == "fixed":
        target = current.copy()
    steps = []
    residual = max(abs(current[k] - target[k]) for k in current)
    if residual <= (1 << 12):
        return current, steps
    for iteration in range(1, 65):
        current = {k: min(Q32, max(-Q32, v + mul_q32(target[k] - v, preference["eta_q32"])))
                   for k, v in current.items()}
        residual = max(abs(current[k] - target[k]) for k in current)
        steps.append({"iteration": iteration, "residual_raw": residual,
                      "values": current.copy()})
        if residual <= (1 << 12):
            return current, steps
    raise ValueError("independent preference reference exhausted")


def fixture(mode="dynamic", horizon=4):
    images = [{"id": name, "backend": backend,
               "artifact_sha256": digest(["synthetic-image", name]),
               "verification_digest": digest(["arithmetic-fixture-only", name])}
              for name, backend in [("o2", "O2"), ("o3", "O3"), ("os", "Os")]]
    # Signed component utilities in declared synthetic test units.
    numbers = {"o2": (8, 3), "o3": (9, 0), "os": (1, 9)}
    candidates = []
    for index, sequence in enumerate(itertools.product(numbers, repeat=horizon)):
        path = []
        for stage, image in enumerate(sequence):
            latency, memory = numbers[image]
            path.append({"image_id": image,
                "event_digest": digest(["synthetic-event", index, stage]),
                "support_digest": digest(["synthetic-support", image, stage]),
                "components": [{"axis": "latency", "value_q32": latency * Q32},
                               {"axis": "memory", "value_q32": memory * Q32}],
                "cost_q32": Q32 // 10, "discount_q32": Q32 * 7 // 8})
        candidates.append({"id": f"path-{index:03d}", "verified": True,
            "verification_digest": digest(["fixture", index]),
            "support_digest": digest(["fixture-path", sequence]),
            "resource_cost_q32": horizon * Q32, "risk_q32": 0,
            "uncertainty_q32": 0, "path": path})
    candidates.append({"id": "abstain", "verified": True,
        "verification_digest": digest("zero-effect-fixture"),
        "support_digest": digest("zero-effect-fixture-support"),
        "resource_cost_q32": 0, "risk_q32": 0, "uncertainty_q32": 0, "path": []})
    return {"schema": "hepta.hia.kernel-ndu.request.v1",
        "objective_digest": digest("synthetic-objective"),
        "snapshot_digest": digest("synthetic-snapshot"),
        "action_registry_digest": digest(images), "generation": 1, "horizon": horizon,
        "utility_unit": "synthetic-test-unit", "resource_unit": "modeled-work",
        "resource_budget_q32": 100 * Q32, "risk_ceiling_q32": Q32,
        "terminal_utility_q32": 10 * Q32,
        "preference": {"mode": mode, "previous_state": None,
            "genesis_values": [{"axis": "latency", "value_q32": Q32 // 2},
                              {"axis": "memory", "value_q32": Q32 // 2}],
            "target": [{"axis": "latency", "value_q32": Q32},
                       {"axis": "memory", "value_q32": 0}],
            "eta_q32": Q32 // 4}, "images": images, "candidates": candidates}


def verify_response(request, response):
    assert response["schema"] == "hepta.hia.kernel-ndu.response.v1"
    assert response["request_sha256"] == hashlib.sha256(wire(request)).hexdigest()
    for field in ("objective_digest", "snapshot_digest", "action_registry_digest", "generation"):
        assert response[field] == request[field], field
    assert response["upstream_commit"] == UPSTREAM
    assert response["authority"] == "DENY_ALL"
    assert response["safety_certificate"] is False
    assert response["production_activation_allowed"] is False
    assert response["measurements_created"] is False
    assert response["kernel_image_verified_by_adapter"] is False
    assert response["entry_points"] == [
        "codex_hepta_ndu::solve_preference_target",
        "codex_hepta_ndu::evaluate_recursive_utility",
        "codex_hepta_ndu::evaluate_candidates_with_policy"]
    weights, iterations = preference_reference(request["preference"])
    native = response["preference"]
    observed = {v["axis"]: v["value_q32"] for v in native["state"]["values"]}
    assert weights == observed
    assert native["termination"]["iterations"] == len(iterations)
    assert len(native["iterations"]) == len(iterations)
    initial_revision = native["initial"]["revision"]
    for expected, actual in zip(iterations, native["iterations"]):
        assert actual["iteration"] == expected["iteration"]
        assert actual["residual_raw"] == expected["residual_raw"]
        assert actual["predecessor_revision"] == initial_revision + expected["iteration"] - 1
        assert actual["next_revision"] == initial_revision + expected["iteration"]
        assert actual["projection_count"] == 0
    assert native["state"]["revision"] == initial_revision + len(iterations)
    if iterations:
        assert native["iterations"][-1]["state_digest"] == native["state"]["state_digest"]
    assert native["termination"]["terminal_state_digest"] == native["state"]["state_digest"]
    paths = {p["id"]: p for p in response["paths"]}
    assert len(paths) == len(request["candidates"])
    values = {}
    for candidate in request["candidates"]:
        result = paths[candidate["id"]]
        terminal = 0 if candidate["id"] == "abstain" else request["terminal_utility_q32"]
        expected_values = [terminal]
        phases = candidate["path"]
        if candidate["id"] == "abstain":
            expected_values = [0, 0]
        else:
            for phase, actual in zip(reversed(phases), reversed(result["phases"])):
                terms = {c["axis"]: mul_q32(weights[c["axis"]], c["value_q32"])
                         for c in phase["components"]}
                assert {t["axis"]: t["weighted_q32"] for t in actual["terms"]} == terms
                instant = sum(terms.values()) - phase["cost_q32"]
                assert actual["instant_q32"] == instant
                expected_values.insert(0, instant + mul_q32(phase["discount_q32"], expected_values[0]))
        assert result["values_q32"] == expected_values
        assert result["projection_count"] == 0
        if (candidate["verified"] and candidate["resource_cost_q32"] <= request["resource_budget_q32"]
                and candidate["risk_q32"] <= request["risk_ceiling_q32"]):
            values[candidate["id"]] = expected_values[0]
    maximum = max(values.values())
    expected_frontier = sorted(k for k, v in values.items() if v == maximum)
    assert sorted(response["pareto_candidate_ids"]) == expected_frontier
    first_images = {c["path"][0]["image_id"] for c in request["candidates"]
                    if c["id"] in expected_frontier and c["path"]}
    first = next(iter(first_images)) if len(first_images) == 1 and "abstain" not in expected_frontier else None
    assert response["selected_first_image_id"] == first
    assert response["complete_image_paths"] == 3 ** request["horizon"]
    return {"independently_replayed_paths": len(paths),
            "preference_iterations": len(iterations), "selected_first_image": first}


def qualify(binary, output):
    output.mkdir(parents=True, exist_ok=False)
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    report = {"schema": "hepta.hia.kernel-ndu.mechanism-qualification.v1",
        "synthetic_arithmetic_fixtures": True, "kernel_performance_observations": False,
        "status": "RUNNING", "binary": {"path": str(binary), "sha256": before}, "checks": []}
    def record(name, **details):
        report["checks"].append({"name": name, "status": "PASS", **details})
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    def call(request, name, reject=False):
        payload = wire(request)
        (output / (name + ".request.json")).write_bytes(payload + b"\n")
        start = time.monotonic_ns()
        result = subprocess.run([str(binary)], input=payload, capture_output=True, timeout=30)
        (output / (name + ".stdout")).write_bytes(result.stdout)
        (output / (name + ".stderr")).write_bytes(result.stderr)
        if reject:
            assert result.returncode != 0 and not result.stdout, name
            record(name, exit_code=result.returncode)
            return None
        assert result.returncode == 0, (name, result.stderr.decode(errors="replace"))
        response = json.loads(result.stdout)
        checks = verify_response(request, response)
        record(name, wall_ns=time.monotonic_ns() - start, **checks)
        return response
    try:
        p = subprocess.run([str(binary), "--identity"], capture_output=True, check=True, timeout=30)
        identity = json.loads(p.stdout)
        assert identity["profile"] == "hepta.hia.kernel-ndu.v1"
        assert identity["upstream_commit"] == UPSTREAM
        report["identity"] = identity
        record("original_native_profile_identity")
        fixed = call(fixture("fixed"), "fixed_preference_complete_81_paths")
        dynamic_request = fixture("dynamic")
        dynamic = call(dynamic_request, "actual_native_preference_update_and_81_path_recursion")
        assert fixed["selected_first_image_id"] == "o2"
        assert dynamic["selected_first_image_id"] == "o3"
        record("native_preference_state_changes_image_advice", fixed="o2", dynamic="o3")
        successor = fixture("dynamic")
        successor["generation"] = 2
        successor["snapshot_digest"] = digest("synthetic-successor")
        successor["preference"]["previous_state"] = dynamic["preference"]["next_request_state"]
        successor["preference"]["genesis_values"] = []
        successor["preference"]["target"] = [{"axis": "latency", "value_q32": 0},
                                                {"axis": "memory", "value_q32": Q32}]
        next_response = call(successor, "native_preference_revision_chain")
        assert next_response["selected_first_image_id"] == "os"
        record("successor_state_used_for_real_native_advice", selected="os")
        for horizon in (1, 2, 3):
            call(fixture("dynamic", horizon), f"complete_horizon_{horizon}")
        invalidations = [
            ("unknown_root_field", lambda r: r.update(unimplemented=True)),
            ("missing_candidate", lambda r: r["candidates"].pop(0)),
            ("duplicate_candidate_id", lambda r: r["candidates"][0].update(id=r["candidates"][1]["id"])),
            ("duplicate_image_path", lambda r: r["candidates"][0].update(path=copy.deepcopy(r["candidates"][1]["path"]))),
            ("bad_registry_digest", lambda r: r.update(action_registry_digest="a" * 64)),
            ("unregistered_image", lambda r: r["candidates"][0]["path"][0].update(image_id="foreign")),
            ("incomplete_path", lambda r: r["candidates"][0]["path"].pop()),
            ("bad_eta", lambda r: r["preference"].update(eta_q32=Q32 // 8)),
            ("nonzero_abstain", lambda r: r["candidates"][-1].update(resource_cost_q32=1)),
            ("invalid_discount", lambda r: r["candidates"][0]["path"][0].update(discount_q32=Q32 + 1)),
            ("negative_cost", lambda r: r["candidates"][0]["path"][0].update(cost_q32=-1)),
            ("zero_event_digest", lambda r: r["candidates"][0]["path"][0].update(event_digest="0" * 64)),
            ("target_dimension_change", lambda r: r["preference"]["target"][0].update(axis="foreign")),
            ("unknown_preference_mode", lambda r: r["preference"].update(mode="greedy-renamed-ndu")),
            ("forbidden_clipping", lambda r: (r.update(terminal_utility_q32=1_000_000 * Q32), [p.update(discount_q32=Q32) for c in r["candidates"] for p in c["path"]])),
        ]
        for name, mutate in invalidations:
            request = fixture()
            mutate(request)
            call(request, "reject_" + name, reject=True)
        tampered = copy.deepcopy(successor)
        tampered["preference"]["previous_state"]["state_digest"] = "b" * 64
        call(tampered, "reject_tampered_native_preference_state", reject=True)
        over_budget = fixture()
        over_budget["candidates"][0]["resource_cost_q32"] = over_budget["resource_budget_q32"] + 1
        call(over_budget, "native_resource_feasibility_and_independent_frontier")
        refused = fixture()
        refused["candidates"][0]["verified"] = False
        call(refused, "native_unverified_candidate_rejection")
        report["binary_unchanged"] = hashlib.sha256(binary.read_bytes()).hexdigest() == before
        assert report["binary_unchanged"]
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = str(error)
        raise
    finally:
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.binary.resolve(strict=True), args.output.resolve())
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]),
                      "kernel_performance_observations": False,
                      "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()
