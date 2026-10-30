#!/usr/bin/env python3
"""New registered holdout with mandatory batch P99 and the existing strong arms.

Reuse the original measurement implementation without changing its frozen
round-3 protocol or results. This entry point has a separate identity, protocol,
registration and output. A failed tail gate remains a failed combined gate.
"""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import qualify_hia_narrowing_bench as bench


def require_batch_p99(result, maximum):
    """Conjoin the registered finite batch tail threshold with every old gate."""
    for row in result["comparisons"]:
        ratio = row.get("empirical_p99_batch_ratio")
        passed = type(ratio) in (int, float) and 0 < ratio <= maximum
        row["batch_p99_gate_passed"] = passed
        row["noninferiority_thresholds_passed"] &= passed
    result["noninferiority_passed"] = result["quality_passed"] and len(result["comparisons"]) == 14 and all(
        row["noninferiority_thresholds_passed"] for row in result["comparisons"])
    strong = [row for row in result["comparisons"] if row["baseline"] not in {"hia_original", "hia_guarded"}]
    result["strong_noninferiority_passed"] = result["quality_passed"] and len(strong) == 10 and all(
        row["noninferiority_thresholds_passed"] for row in strong)
    result["batch_p99_is_mandatory"] = True
    result["batch_p99_is_population_bound"] = False
    return result


def main():
    bench.STUDY = ROOT / "experiments/hia_optimizer_eval/round4_20261030"
    bench.SCHEMA = "hepta.hia.optimizer-bench.round4-20261030.v1"
    original_bindings, original_evaluate = bench.bindings, bench.evaluate

    def bindings():
        values = original_bindings()
        values[str(Path(__file__).relative_to(ROOT))] = bench.identity(Path(__file__))["sha256"]
        return values

    def evaluate(rows, profile):
        return require_batch_p99(original_evaluate(rows, profile), profile["maximum_empirical_p99_batch_ratio"])

    bench.bindings, bench.evaluate = bindings, evaluate
    return bench.main()


if __name__ == "__main__":
    raise SystemExit(main())
