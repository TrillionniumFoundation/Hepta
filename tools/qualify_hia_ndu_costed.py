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
from hepta.hia_ndu_stateful import SCHEMA_V2, invocation_gate, validate_model
from tools.qualify_hia_ndu_stateful import (
    SCALE, control_case, fixtures, native_arm, source_identity)


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


def qualify(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.ndu.costed-model-qualification.v1", "status": "failed",
              "mode": "formal" if args.expected_source else "development",
              "ledger": [], "cases": [], "native_arms": [],
              "authority": "DENY_ALL", "safety_certificate": False,
              "application_speedup_established": False, "net_ndu_benefit_established": False}
    try:
        report["source_before"] = source_identity(args.expected_source)
        own_relative = str(Path(__file__).resolve().relative_to(ROOT))
        own_bytes = Path(__file__).read_bytes()
        report["qualification_source_sha256"] = sha256(own_bytes).hexdigest()
        if args.expected_source:
            committed = subprocess.check_output(["git", "cat-file", "blob",
                                                 args.expected_source + ":" + own_relative], cwd=ROOT)
            if committed != own_bytes:
                raise ValueError("qualification source differs from the exact committed blob")
        for model in costed_fixtures():
            row = control_case(model, report["ledger"])
            row["invocation_estimate_cases"] = [invocation_gate(model, invocation_cost_ns=n)
                                                for n in (0, SCALE, 500 * SCALE)]
            report["cases"].append(row)
        spec = {"native_source_commit": STREAM_SOURCE_PIN, "image_check": "sealed"}
        for search in ("enumerate", "dynamic-frontier"):
            arm = native_arm(report["cases"], args.bridge, args.identity, search, spec)
            report["native_arms"].append(arm)
            if arm["status"] != "passed" or any(row["status"] != "passed" for row in arm["cases"]):
                raise ValueError("costed original native arm failed or refused a declared fixture")
        report["source_after"] = source_identity(args.expected_source)
        if report["source_before"] != report["source_after"] or Path(__file__).read_bytes() != own_bytes:
            raise ValueError("source changed during qualification")
        report["native_calls"] = sum(len(arm["cases"]) for arm in report["native_arms"])
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
