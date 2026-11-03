#!/usr/bin/env python3
"""Replay explicit future-decision costs against the original native NDU.

This extends the finite model evidence without rewriting the historical v1
campaign or substituting a Python evaluator for the original Rust algorithms.
It measures protocol/model agreement, not application or economic superiority.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu_session import STREAM_SOURCE_PIN
from hepta.hia_ndu_stateful import SCHEMA_V2, SCHEMA_V3, invocation_gate, validate_model
from tools.qualify_hia_ndu_stateful import (
    SCALE, control_case, fixtures, native_arm, source_identity)

RESIDENCY_PROTOCOL_PATH = ROOT / "benchmarks/hia_ndu_stateful/RESIDENCY_PROTOCOL.json"


def costed_fixtures():
    rows = []
    for index, name, cost, horizon in (
        (1, "holding-cheap-decisions", 1, 4),
        (1, "holding-expensive-decisions", 100, 4),
        (4, "prepared-reuse-stops-now", 100, 4),
        (2, "single-batch-no-future-call", 100, 1),
        (2, "three-batch-resource-cost", 11, 3),
        (3, "rejected-candidate-retained", 11, 4),
    ):
        model = deepcopy(fixtures()[index])
        model.update(schema=SCHEMA_V2, name=name, future_decision_cost_ns=cost * SCALE)
        model["baseline"]["latency_ns"] = model["baseline"]["latency_ns"][:horizon]
        for variant in model["variants"]:
            for field in ("latency_ns", "holding_ns"):
                variant[field] = variant[field][:horizon]
        rows.append(validate_model(model))
    return rows


def residency_fixtures():
    """Declared v3 controls; no fitted/heldout native timing inputs."""
    alternating = deepcopy(fixtures()[2])
    alternating.update(schema=SCHEMA_V3, name="evict-reacquire-alternating",
                       future_decision_cost_ns=SCALE)
    alternating["baseline"]["latency_ns"] = [100 * SCALE] * 4
    for variant, latencies in zip(alternating["variants"], ([1, 100, 1, 100], [100, 1, 100, 1])):
        variant.update(preparation_ns=2 * SCALE, eviction_ns=SCALE,
                       holding_ns=[0] * 4, latency_ns=[v * SCALE for v in latencies])

    delayed = deepcopy(alternating)
    delayed["name"] = "eviction-delayed-payback"
    for variant, setup, latency in zip(delayed["variants"], (150, 100),
                                       ([1, 1, 100, 100], [100, 100, 1, 1])):
        variant.update(preparation_ns=setup * SCALE, eviction_ns=5 * SCALE,
                       latency_ns=[v * SCALE for v in latency])

    expensive = deepcopy(alternating)
    expensive["name"] = "eviction-too-expensive"
    for variant in expensive["variants"]:
        variant["eviction_ns"] = 500 * SCALE

    holding = deepcopy(fixtures()[1])
    holding.update(schema=SCHEMA_V3, name="release-unused-incumbent",
                   future_decision_cost_ns=SCALE, initial_ready=["late"])
    holding["baseline"]["latency_ns"] = [10 * SCALE] * 4
    holding["variants"][0].update(eviction_ns=3 * SCALE, latency_ns=[20 * SCALE] * 4,
                                   holding_ns=[30 * SCALE] * 4)

    refusal = deepcopy(delayed)
    refusal["name"] = "eviction-refused-target"
    refusal["variants"][1]["status"] = "rejected"

    bounded = deepcopy(delayed)
    bounded.update(name="eviction-insufficient-budget", budget_ns=1)
    return [validate_model(model) for model in (alternating, delayed, expensive, holding, refusal, bounded)]


def qualify(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.ndu.costed-model-qualification.v2", "status": "failed",
              "mode": "formal" if args.expected_source else "development",
              "ledger": [], "cases": [], "native_arms": [],
              "residency_cases": [], "residency_native_arms": [],
              "authority": "DENY_ALL", "safety_certificate": False,
              "application_speedup_established": False, "net_ndu_benefit_established": False}
    try:
        report["source_before"] = source_identity(args.expected_source)
        own_relative = str(Path(__file__).resolve().relative_to(ROOT))
        own_bytes = Path(__file__).read_bytes()
        report["qualification_source_sha256"] = sha256(own_bytes).hexdigest()
        residency_protocol_bytes = RESIDENCY_PROTOCOL_PATH.read_bytes()
        residency_protocol = json.loads(residency_protocol_bytes)
        report["residency_protocol"] = residency_protocol
        report["residency_protocol_sha256"] = sha256(residency_protocol_bytes).hexdigest()
        if (residency_protocol["schema"] != "hepta.hia.ndu.residency-study.protocol.v1"
                or residency_protocol["model_schema"] != SCHEMA_V3
                or residency_protocol["native_source_commit"] != STREAM_SOURCE_PIN
                or residency_protocol["cases"] != [model["name"] for model in residency_fixtures()]
                or residency_protocol["native_search"] != "dynamic-frontier"
                or residency_protocol["image_check"] != "sealed"):
            raise ValueError("residency registration differs from the complete source-owned fixture cohort")
        if args.expected_source:
            committed = subprocess.check_output(["git", "cat-file", "blob",
                                                 args.expected_source + ":" + own_relative], cwd=ROOT)
            if committed != own_bytes:
                raise ValueError("qualification source differs from the exact committed blob")
            committed_protocol = subprocess.check_output(["git", "cat-file", "blob",
                args.expected_source + ":" + str(RESIDENCY_PROTOCOL_PATH.relative_to(ROOT))], cwd=ROOT)
            if committed_protocol != residency_protocol_bytes:
                raise ValueError("residency protocol differs from the exact committed blob")
        for model in costed_fixtures():
            row = control_case(model, report["ledger"])
            row["invocation_estimate_cases"] = [invocation_gate(model, invocation_cost_ns=n)
                                                for n in (0, SCALE, 500 * SCALE)]
            report["cases"].append(row)
        for model in residency_fixtures():
            row = control_case(model, report["ledger"])
            row["invocation_estimate_cases"] = [invocation_gate(model, invocation_cost_ns=n)
                                                for n in (0, SCALE, 500 * SCALE)]
            report["residency_cases"].append(row)
        spec = {"native_source_commit": STREAM_SOURCE_PIN, "image_check": "sealed"}
        for search in ("enumerate", "dynamic-frontier"):
            arm = native_arm(report["cases"], args.bridge, args.identity, search, spec)
            report["native_arms"].append(arm)
            if arm["status"] != "passed" or any(row["status"] != "passed" for row in arm["cases"]):
                raise ValueError("costed original native arm failed or refused a declared fixture")
        # The complete reversible 4-batch graph can exceed the original 127
        # uncompressed-path cap. Retain that cap; send the existing exact
        # frontier's complete winning witnesses, checked by independent DP.
        arm = native_arm(report["residency_cases"], args.bridge, args.identity, "dynamic-frontier", spec)
        report["residency_native_arms"].append(arm)
        if arm["status"] != "passed" or any(row["status"] != "passed" for row in arm["cases"]):
            raise ValueError("reversible residency native arm failed or refused a declared fixture")
        report["source_after"] = source_identity(args.expected_source)
        if (report["source_before"] != report["source_after"] or Path(__file__).read_bytes() != own_bytes
                or RESIDENCY_PROTOCOL_PATH.read_bytes() != residency_protocol_bytes):
            raise ValueError("source changed during qualification")
        report["native_calls"] = sum(len(arm["cases"]) for arm in
                                     report["native_arms"] + report["residency_native_arms"])
        report["exact_dp_comparison"] = {
            "all_same_model_values_equal": True,
            "ndu_model_value_superiority_over_exact_dp": False,
            "reason": "same-information exact DP is the optimum of this finite deterministic objective"}
        report["status"] = "passed"
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        report["wall_ns"] = time.monotonic_ns() - started
        (output / "RESULT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-source")
    result = qualify(parser.parse_args())
    print(json.dumps({key: result.get(key) for key in ("status", "native_calls", "error")}, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
