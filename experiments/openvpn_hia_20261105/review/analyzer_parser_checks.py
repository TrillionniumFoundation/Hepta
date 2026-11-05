#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Tiny synthetic software checks only; never produce target/performance results."""
from pathlib import Path
import ast
import copy
import hashlib
import importlib.util
import json
import tempfile
from datetime import datetime, timezone


def main():
    program = Path(__file__).resolve().parents[1] / "analyze_target.py"
    ast.parse(program.read_text())
    spec = importlib.util.spec_from_file_location("offline_analysis", program)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    checks = ["Python syntax and import"]
    plan = json.loads((program.parent / "target_host/plan.json").read_text())
    tasks = module.planned_cases(plan)
    assert len(tasks) == 65 and len({r["id"] for r in tasks}) == 65
    assert all(sum(t["kind"] == "performance" and t["arms"]["client"] == arm for t in tasks) == 18 for arm in module.ARMS)
    checks.append("fixed inventory and planned per-arm counts")
    workload = {"name": "SYNTHETIC-PARSER-ONLY", "transport": "udp"}
    measurement = {"passed": False, "status": "failed", "workload": workload,
                   "client_local_receiver": {"json_path": "end.sum_received_bidir_reverse",
                    "local_receiving_role": "client", "sender": False, "bytes": 100,
                    "seconds": 1, "bits_per_second": 800, "lost_percent": 0,
                    "lost_packets": 0, "packets": 1, "jitter_ms": 0}}
    task = {"id": "SYNTHETIC-PARSER-ONLY", "round": 0, "order": 0, "position": 0,
            "arms": {"server": "c-dco", "client": "c-user"}}
    directions, _ = module.normalize_measurement(task, workload, measurement, "SYNTHETIC-PARSER-ONLY", False, True, [])
    assert directions[0]["lost_percent"] == 0 and directions[1]["lost_percent"] is None
    assert not directions[0]["measurement_reported_passed"] and directions[0]["received_mbps"] > 0
    wrong = copy.deepcopy(measurement)
    wrong["client_local_receiver"]["sender"] = True
    assert module.normalize_measurement(task, workload, wrong, "SYNTHETIC-PARSER-ONLY", False, True, [])[0][0]["received_mbps"] is None
    checks.append("missing versus zero, partial failure retention, receiver identity")
    samples = []
    for order in (0, 1):
        for arm, value in (("c-user", 1 + order), ("hia-user", 3 + order), ("c-dco", 0)):
            samples.append({"round": 0, "order": order, "workload": "SYNTHETIC-PARSER-ONLY",
                            "direction": "server-to-client", "arm": arm, "case_id": "SYNTHETIC-PARSER-ONLY",
                            "metric": value, "case_reported_passed": False, "measurement_reported_passed": False})
    paired = module.pair_samples(list(reversed(samples)), "direction", ("metric",))
    ratios = [r for r in paired if r["numerator_arm"] == "hia-user" and r["denominator_arm"] == "c-user"]
    assert [r["ratio"] for r in ratios] == [3, 2]
    undefined = [r for r in paired if r["numerator_arm"] == "hia-user" and r["denominator_arm"] == "c-dco"]
    assert all(r["ratio"] is None and r["ratio_unavailable_reason"] == "zero denominator" for r in undefined)
    assert module.statistic([0, None, float("nan"), 2])["finite_observations"] == 2
    checks.append("round/order pairing, undefined denominator, nonfinite exclusion")
    with tempfile.TemporaryDirectory(prefix="synthetic-analysis-negative-only-") as temporary:
        root = Path(temporary)
        (root / "build.json").write_text(json.dumps({"ok": False, "failure": "SYNTHETIC PARSER CHECK ONLY: no workload ran"}))
        report, datasets = module.analyze(root)
        assert report["receipt_verdicts"]["build_reported_ok"] is False
        assert report["receipt_verdicts"]["matrix_reported_complete"] is None
        assert report["counts"]["missing_case_receipts"] == 65
        assert report["counts"]["missing_workload_receipts"] == 216
        assert all(r["received_mbps"] is None for r in datasets["direction-samples.csv"])
        assert all(r["total_process_seconds"] is None for r in datasets["process-samples.csv"])
        assert "SYNTHETIC PARSER CHECK ONLY" in module.markdown(report)
        json.loads(module.encoded(report))
    checks.append("failed-build/missing-matrix path and in-memory Markdown/JSON rendering")
    print(json.dumps({"schema": "hepta.openvpn-hia.offline-analyzer-software-checks.v1",
                      "software_checks_passed": True, "synthetic_inputs_only": True,
                      "runtime_qualification": False, "benchmark_executed": False,
                      "analysis_artifacts_written": False, "temporary_input_removed": True,
                      "checked_utc": datetime.now(timezone.utc).isoformat(), "checks": checks,
                      "analyzer_sha256": hashlib.sha256(program.read_bytes()).hexdigest(),
                      "check_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}, indent=2) + "\n")


if __name__ == "__main__":
    main()
