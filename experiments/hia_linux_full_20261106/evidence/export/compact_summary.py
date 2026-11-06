#!/usr/bin/env python3
"""Compact display derivative of frozen raw measurements; no new experiment."""
from fractions import Fraction
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
BASE = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def binding(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def slim_stat(value):
    return {"mean": value["arm_mean"]["value"],
            "stock_or_reference_mean": value["baseline_mean"]["value"],
            "relative_change_percent": value["relative_change_percent"]["value"],
            "relative_change_ci95_percent": [v["value"] for v in value["relative_change_ci95_percent"]],
            "lower_is_better": value["lower_is_better"]}


def main():
    source = module("full_export_derivation", Path(__file__).with_name("finalize_exports.py"))
    driver = module("frozen_comparison", BASE / "comparison-dev/tools/qualify_hia_kernel_comparison.py")
    paths = {n: BASE / "comparison-results" / n for n in source.EXPECTED}
    for name, path in paths.items():
        b = binding(path)
        assert (b["bytes"], b["sha256"]) == source.EXPECTED[name]
    evaluation = json.loads(paths["EVALUATION.json"].read_bytes())
    rows = json.loads(paths["HELDOUT_OBSERVATIONS.json"].read_bytes())
    full = source.derive(evaluation, rows, driver)
    summary = {k: full[k] for k in ("schema", "status", "kind", "campaign_id",
               "durable_campaign_job_id", "successful_driver_calls",
               "calibration_independent_boots", "heldout_independent_boots", "failed_boots",
               "excluded_outliers", "cells_with_active_prediction_budget", "scope",
               "primary_cost", "statistical_unit", "interpretation",
               "artifact_equivalence_groups", "campaign_accounting_ns")}
    summary["schema"] = "hepta.hia.kernel-comparison.compact-derived-summary.v1"
    summary["source_evidence"] = {name: binding(path) for name, path in paths.items()}
    summary["export"] = {
        "directory": "/data/hepta-hia-linux-full-comparison-export-20261106-bedaafad8a2f-r1",
        "job_id": "1a1b24273dd-fc05-7d36",
        "finalized_sha256": "66a929df44dfd56f566cb8c19dd9911c75147751ab3c74280876417d803bfef5",
        "cas_archive_bytes": 21935265,
        "cas_archive_sha256": "c00d028b0632e29e8edc0018b362ca2d8155f161d69b60138fb288aaea5a4e6b",
        "raw_files_omitted": 0,
    }
    summary["display_numbers"] = "Exact raw JSON integers retained in source evidence; exact rational means retained below. Display CI values are copied from the frozen EVALUATION, except the clearly marked direct same-objective contrast derived by its unchanged helper."
    summary["actions"] = {k: v for k, v in full["actions"].items() if k != "case_actions"}
    summary["arms"] = {}
    for arm, values in full["arms"].items():
        item = {k: v for k, v in values.items() if k not in (
            "four_phase_block_statistics_vs_stock", "per_phase_statistics_vs_stock",
            "public_objective_block_statistics_vs_stock")}
        item["four_phase_block_statistics_vs_stock"] = {
            k: slim_stat(v) for k, v in values["four_phase_block_statistics_vs_stock"].items()}
        item["per_phase_statistics_vs_stock"] = {
            phase: {k: slim_stat(v) for k, v in phase_values.items()}
            for phase, phase_values in values["per_phase_statistics_vs_stock"].items()}
        item["public_objective_block_statistics_vs_stock"] = slim_stat(
            values["public_objective_block_statistics_vs_stock"])
        item["setup"] = full["setup_costs"][arm]
        item["amortization"] = {}
        for scenario, value in full["amortization"][arm].items():
            item["amortization"][scenario] = {
                "break_even_vs_stock": value["break_even_vs_stock"],
                "observed_four_phase_cycle_ns": value["observed_four_phase_cycle_ns"]["value"],
                "feedback_extra_cycle_ns": value["feedback_extra_cycle_ns"]["value"],
                "amortized_cycle_ns_by_deployment_count": {
                    str(r["four_phase_cycles"]): r["amortized_cycle_ns"]["value"]
                    for r in value["deployment_counts"]},
            }
        summary["arms"][arm] = item
    contrast = full["dynamic_vs_independent_same_objective_direct_paired"]
    summary["dynamic_vs_independent_same_objective_direct_paired"] = {
        **{k: v for k, v in contrast.items() if k != "statistics"},
        "statistics": {k: slim_stat(v) for k, v in contrast["statistics"].items()},
    }
    out = Path(__file__).with_name("SUMMARY.json")
    out.write_bytes((json.dumps(summary, sort_keys=True, ensure_ascii=True,
                               separators=(",", ":"), allow_nan=False) + "\n").encode())
    for name, path in paths.items():
        data = path.read_bytes()
        compressed = gzip.compress(data, compresslevel=9, mtime=0)
        assert gzip.decompress(compressed) == data
        Path(__file__).with_name(name + ".gz").write_bytes(compressed)
    print(json.dumps({"summary": binding(out), "direct_contrast":
          summary["dynamic_vs_independent_same_objective_direct_paired"],
          "raw_gzip": {n: binding(Path(__file__).with_name(n + ".gz")) for n in paths}}))


if __name__ == "__main__":
    main()
