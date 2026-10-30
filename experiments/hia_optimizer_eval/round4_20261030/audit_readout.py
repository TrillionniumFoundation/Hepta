#!/usr/bin/env python3
"""Read-only independent arithmetic/identity audit of an existing round-4 run.

Uses only the Python standard library. It never imports the measured evaluator,
executes a tool/model/native artifact, extracts an archive, or repeats a timing.
The only writes are new audit/readout JSON files in this experiment directory.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import statistics


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def read(path):
    return json.loads(Path(path).read_bytes())


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def identity(path):
    path = Path(path).resolve(strict=True)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest}


def nearest_rank(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def oracle(kernel, size, seed):
    # Independent periodic integer calculation from the registered algorithms.
    period = [((i + seed) & 255) if kernel == "full_lifecycle"
              else (((13 * i + seed) & 255) ^ ((i + (seed ^ 90)) & 255))
              for i in range(256)]
    cycles, rest = divmod(size, 256)
    return cycles * sum(period) + sum(period[:rest])


def checksum(profile, kernel, *, training=False, tails=False):
    prefix = "training" if training else "holdout"
    sizes, seeds = profile[prefix + "_sizes"], profile[prefix + "_seeds"]
    answers = {(n, seed): oracle(kernel, n, seed) for n in sizes for seed in seeds}
    value = 1469598103934665603
    count = profile["request_tail_probes"] if tails else profile["batches"] * profile["calls_per_batch"]
    for i in range(count):
        n = sizes[((i * 7 + 3) if tails else i) % len(sizes)]
        seed = seeds[((i * 3 + 2) if tails else (i * 5 + 1)) % len(seeds)]
        value = ((value ^ answers[n, seed]) * 1099511628211) & ((1 << 64) - 1)
    return value


def matches(actual, expected):
    if type(expected) is float:
        return type(actual) in (int, float) and math.isfinite(actual) and math.isclose(
            actual, expected, rel_tol=1e-12, abs_tol=1e-12)
    if isinstance(expected, dict):
        return isinstance(actual, dict) and actual.keys() == expected.keys() and all(
            matches(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(
            matches(a, b) for a, b in zip(actual, expected))
    return type(actual) is type(expected) and actual == expected


def audit(report_path):
    report_path = Path(report_path).resolve(strict=True)
    run = report_path.parent
    before = identity(report_path)
    report = read(report_path)
    registration = read(HERE / "REGISTRATION.json")
    profile = read(HERE / "PROTOCOL.json")
    prior = read(HERE.parent / "round3_20261028/PROTOCOL.json")
    rows, commands = report["raw_samples"], report["commands"]
    kernels, backends = profile["kernels"], profile["backends"]
    candidate = profile["candidate_backend"]
    checks = {}

    def check(name, passed, **evidence):
        checks[name] = {"passed": bool(passed), **evidence}

    calculated_registration = hashlib.sha256(wire({
        k: v for k, v in registration.items() if k != "registration_sha256"})).hexdigest()
    check("registration_digest", calculated_registration == registration["registration_sha256"],
          calculated_sha256=calculated_registration)
    check("registration_and_protocol_copies", report["registration"] == registration
          and report["protocol"] == profile and registration["protocol"] == profile
          and read(run / "plan.json")["registration_sha256"] == calculated_registration)
    check("corrected_source_base_registered", profile["base_commit"] == registration["source_commit"]
          == "0e1f5dd9bf0f54c492d96bd5dd1ae52e8c804997"
          and profile["original_candidate_base_commit"] == "4fcc2c3735f3637932edd13ded814880743723f5"
          and bool(profile["source_identity_scope"]))
    bindings = registration["source_bindings"]
    changed_current, changed_snapshot = [], []
    source_bytes = 0
    for name, expected in bindings.items():
        current, snapshot = identity(ROOT / name), identity(run / "source_snapshot" / name)
        source_bytes += current["bytes"]
        if current["sha256"] != expected:
            changed_current.append(name)
        if snapshot["sha256"] != expected:
            changed_snapshot.append(name)
    required_sources = {str(path.relative_to(ROOT)) for path in (ROOT / "hepta").glob("*.py")}
    required_sources.update({"tools/qualify_hia_round4_bench.py", "tools/qualify_hia_narrowing_bench.py",
        "tools/qualify_hia_optimizer_bench.py", "experiments/hia_optimizer_eval/round4_20261030/driver.c",
        "experiments/hia_optimizer_eval/round4_20261030/PROTOCOL.json"})
    required_sources.update("experiments/hia_optimizer_eval/kernels." + ext for ext in ("hepta", "c", "cpp", "rs"))
    check("all_135_registered_sources", len(bindings) == 135 and set(bindings) == required_sources
          and not changed_current and not changed_snapshot, count=len(bindings), source_bytes=source_bytes,
          changed_current=changed_current, changed_snapshot=changed_snapshot)
    tool_results = {name: identity(item["path"]) == item for name, item in registration["tools"].items()}
    check("registered_tool_bytes", set(tool_results) == {"clang", "clangxx", "rustc", "linker", "profdata", "profile_runtime"}
          and all(tool_results.values()), tools=tool_results)
    python_identity = registration["python_runtime"]["executable"]
    check("registered_python_bytes", identity(python_identity["path"]) == python_identity)
    solver = registration["solver"]
    package = Path(solver["library_path"]).parent.parent
    binding_hash = hashlib.sha256()
    for path in sorted(package.glob("*.py")):
        binding_hash.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    check("registered_solver_bytes", identity(solver["library_path"])["sha256"] == solver["library_sha256"]
          and binding_hash.hexdigest() == solver["binding_sha256"])
    artifact_results = {name: identity(item["path"]) == item for name, item in report["artifacts_before"].items()}
    check("retained_driver_and_eight_artifacts", len(artifact_results) == 8 and all(artifact_results.values())
          and identity(report["driver_identity"]["path"]) == report["driver_identity"], artifacts=artifact_results)

    original_thresholds = ("maximum_paired_geomean_ratio_upper95", "maximum_empirical_p95_batch_ratio",
        "maximum_empirical_p95_request_ratio", "maximum_empirical_p99_request_ratio", "maximum_peak_rss_ratio",
        "maximum_relative_mad", "minimum_sample_ns", "maximum_sample_ns", "paired_log_t_upper95_critical_df6")
    check("old_thresholds_preserved_and_p99_added", all(profile[k] == prior[k] for k in original_thresholds)
          and profile["maximum_empirical_p99_batch_ratio"] == 1.10
          and profile["backends"] == prior["backends"] and profile["strong_baselines"] == prior["strong_baselines"])
    check("new_disclosed_holdout_is_disjoint", all(not set(profile["holdout_" + key]) & set(values)
          for key in ("sizes", "seeds") for values in (profile["training_" + key], prior["holdout_" + key])))

    schedule = []
    for group in range(profile["groups"]):
        rotated = kernels[group % len(kernels):] + kernels[:group % len(kernels)]
        for kernel in rotated:
            offset = (group + kernels.index(kernel)) % len(backends)
            arms = backends[offset:] + backends[:offset]
            for arm in arms if group % 2 == 0 else list(reversed(arms)):
                schedule.append({"sample_index": len(schedule), "group": group, "kernel": kernel, "backend": arm})
    check("exact_112_sample_schedule", len(rows) == len(schedule) == 112
          and report["scheduled_samples"] == schedule and read(run / "plan.json")["scheduled_samples"] == schedule
          and all(all(row[key] == item[key] for key in item) for row, item in zip(rows, schedule)))
    bulk_checksums = {kernel: checksum(profile, kernel) for kernel in kernels}
    tail_checksums = {kernel: checksum(profile, kernel, tails=True) for kernel in kernels}
    quality_issues, detached_issues, command_issues = [], [], []
    for row in rows:
        i = row["sample_index"]
        if read(run / ("sample-" + str(i).zfill(3) + ".json")) != row:
            detached_issues.append(i)
        numerical_ok = (row["status"] == "measured" and row["mapping_verified"] is True
            and all(type(row[k]) is int and row[k] > 0 for k in
                    ("elapsed_ns", "process_cpu_ns", "process_peak_rss_kib", "outer_wall_ns"))
            and profile["minimum_sample_ns"] <= row["elapsed_ns"] <= profile["maximum_sample_ns"]
            and all(type(row[key]) is list and len(row[key]) == count
                    and all(type(v) is int and v > 0 for v in row[key])
                    for key, count in (("batch_ns", profile["batches"]),
                                       ("request_ns", profile["request_tail_probes"]),
                                       ("clock_ns", profile["clock_overhead_probes"]))))
        if not numerical_ok or sum(row["batch_ns"]) > row["elapsed_ns"] or row["checksum"] != bulk_checksums[row["kernel"]] or row["tail_checksum"] != tail_checksums[row["kernel"]]:
            quality_issues.append(i)
        command = commands[row["command_index"]]
        observation = command.get("observation", {})
        artifact = report["artifacts_before"][row["backend"]]
        expected_row = {**schedule[i], "status": "measured", "command_index": row["command_index"],
            "outer_wall_ns": command["invocation_wall_ns"], "library_sha256": command["sealed_image_sha256"], **observation}
        if not (row == expected_row and command["phase"] == "measurement" and command["returncode"] == 0
                and json.loads(command["stdout"]) == observation and command["argv"][-2:] == [row["kernel"], "holdout"]
                and command["sealed_image_sha256"] == artifact["sha256"]
                and command["sealed_file_identity"] == {k: row[k] for k in ("image_bytes", "image_device", "image_inode")}
                and row["image_bytes"] == artifact["bytes"]):
            command_issues.append(i)
    check("all_detached_samples_match", not detached_issues, count=len(rows), mismatches=detached_issues)
    check("raw_measurements_and_independent_checksums", not quality_issues, mismatches=quality_issues)
    check("sample_command_and_loaded_mapping_bindings", not command_issues, mismatches=command_issues)

    summary = {}
    for kernel in kernels:
        summary[kernel] = {}
        for arm in backends:
            selected = [r for r in rows if r["kernel"] == kernel and r["backend"] == arm]
            elapsed = [r["elapsed_ns"] for r in selected]
            median = statistics.median(elapsed)
            batches = [v for r in selected for v in r["batch_ns"]]
            requests = [v for r in selected for v in r["request_ns"]]
            clocks = [v for r in selected for v in r["clock_ns"]]
            summary[kernel][arm] = {"samples": len(selected), "median_elapsed_ns": median,
                "relative_mad": statistics.median(abs(v - median) for v in elapsed) / median,
                "median_outer_wall_ns": statistics.median(r["outer_wall_ns"] for r in selected),
                "batch_count": len(batches), "batch_p50_ns": nearest_rank(batches, .5),
                "batch_p95_ns": nearest_rank(batches, .95), "batch_p99_ns": nearest_rank(batches, .99),
                "maximum_process_peak_rss_kib": max(r["process_peak_rss_kib"] for r in selected),
                "median_cpu_to_wall_ratio": statistics.median(r["process_cpu_ns"] / r["elapsed_ns"] for r in selected),
                "request_count": len(requests), "request_p50_ns": nearest_rank(requests, .5),
                "request_p95_ns": nearest_rank(requests, .95), "request_p99_ns": nearest_rank(requests, .99),
                "median_clock_overhead_ns": statistics.median(clocks), "clock_overhead_subtracted": False}
    stable = all(v["samples"] == profile["groups"] and v["relative_mad"] <= profile["maximum_relative_mad"]
                 for arms in summary.values() for v in arms.values())
    check("all_group_stability_gates", stable, maximum_relative_mad=max(v["relative_mad"] for arms in summary.values() for v in arms.values()))
    check("all_reported_summary_metrics_recomputed", matches(report["evaluation"]["summary"], summary))

    metrics = {"paired_time_ratio_upper95": "maximum_paired_geomean_ratio_upper95",
        "empirical_p95_batch_ratio": "maximum_empirical_p95_batch_ratio",
        "empirical_p99_batch_ratio": "maximum_empirical_p99_batch_ratio",
        "empirical_p95_request_ratio": "maximum_empirical_p95_request_ratio",
        "empirical_p99_request_ratio": "maximum_empirical_p99_request_ratio",
        "peak_rss_ratio": "maximum_peak_rss_ratio"}
    lookup = {(r["group"], r["kernel"], r["backend"]): r for r in rows}
    comparisons, detailed = [], []
    for kernel in kernels:
        for arm in (a for a in backends if a != candidate):
            ratios = [math.log(lookup[g, kernel, candidate]["elapsed_ns"] / lookup[g, kernel, arm]["elapsed_ns"])
                      for g in range(profile["groups"])]
            mean = statistics.mean(ratios)
            c, b = summary[kernel][candidate], summary[kernel][arm]
            row = {"kernel": kernel, "baseline": arm, "paired_time_geomean_ratio": math.exp(mean),
                "paired_time_ratio_upper95": math.exp(mean + profile["paired_log_t_upper95_critical_df6"] * statistics.stdev(ratios) / math.sqrt(len(ratios))),
                "empirical_p95_batch_ratio": c["batch_p95_ns"] / b["batch_p95_ns"],
                "empirical_p99_batch_ratio": c["batch_p99_ns"] / b["batch_p99_ns"],
                "empirical_p95_request_ratio": c["request_p95_ns"] / b["request_p95_ns"],
                "empirical_p99_request_ratio": c["request_p99_ns"] / b["request_p99_ns"],
                "peak_rss_ratio": c["maximum_process_peak_rss_kib"] / b["maximum_process_peak_rss_kib"]}
            gates = {key: math.isfinite(row[key]) and 0 < row[key] <= profile[limit] for key, limit in metrics.items()}
            row.update(batch_p99_gate_passed=gates["empirical_p99_batch_ratio"], noninferiority_thresholds_passed=all(gates.values()))
            comparisons.append(row)
            detailed.append({**row, "component_gates": gates, "failed_components": [key for key, passed in gates.items() if not passed]})
    check("every_comparison_and_gate_recomputed", matches(report["evaluation"]["comparisons"], comparisons))
    strong = [r for r in comparisons if r["baseline"] in profile["strong_baselines"]]
    numeric_quality = not quality_issues and stable and len(rows) == 112
    all_gate = numeric_quality and len(comparisons) == 14 and all(r["noninferiority_thresholds_passed"] for r in comparisons)
    strong_gate = numeric_quality and len(strong) == 10 and all(r["noninferiority_thresholds_passed"] for r in strong)
    check("mandatory_tail_and_14_10_aggregate_gates", report["evaluation"]["batch_p99_is_mandatory"] is True
          and report["evaluation"]["batch_p99_is_population_bound"] is False
          and report["evaluation"]["quality_passed"] == numeric_quality
          and report["evaluation"]["noninferiority_passed"] == all_gate
          and report["evaluation"]["strong_noninferiority_passed"] == strong_gate
          and report["evaluation"]["samples_excluded"] == 0 and report["evaluation"]["thresholds_adjusted"] is False)

    case_issues = []
    expected_cases = {(k, n, s) for k in kernels for n in sorted({0, 1, 2, 7, 255, 256, 257, *profile["holdout_sizes"]})
                      for s in (0, 1, 255, 256, 2147483648, 4294967295)}
    for arm, result in report["correctness"].items():
        observations = result["observations"]
        case_keys = [(r["kernel"], r["size"], r["seed"]) for r in observations]
        if len(case_keys) != len(expected_cases) or set(case_keys) != expected_cases or result["ok"] is not True or result["failures"]:
            case_issues.append(arm + ":inventory")
        for row in observations:
            command = commands[row["command_index"]]
            if not (row["actual"] == row["expected"] == oracle(row["kernel"], row["size"], row["seed"])
                    and row["mapping_verified"] is True and command["phase"] == "finite_correctness"
                    and command["returncode"] == 0
                    and command["sealed_image_sha256"] == report["artifacts_before"][arm]["sha256"]
                    and command["observation"]["actual"] == row["actual"]):
                case_issues.append(arm + ":" + str(row["command_index"]))
    check("1536_retained_correctness_observations", set(report["correctness"]) == set(backends)
          and not case_issues, count=sum(len(v["observations"]) for v in report["correctness"].values()), mismatches=case_issues)
    training_ok = len(report["training"]) == 4
    for row in report["training"]:
        command = commands[row["command_index"]]
        observed = command["observation"]
        training_ok &= (row["backend"] in {"c_pgo_lto", "cpp_pgo_lto"} and command["returncode"] == 0
            and command["argv"][-2:] == [row["kernel"], "train"] and observed["mapping_verified"] is True
            and observed["checksum"] == checksum(profile, row["kernel"], training=True)
            and observed["tail_checksum"] == checksum(profile, row["kernel"], training=True, tails=True))
    for arm in ("c_pgo_lto", "cpp_pgo_lto"):
        build = report["builds"][arm]
        training_ok &= len(build["profile_inputs"]) == 2 and all(identity(v["path"]) == v for v in [*build["profile_inputs"], build["training_profile"]])
    check("pgo_training_only_and_retained_profiles", training_ok)
    check("all_eight_builds_retained", set(report["builds"]) == set(backends)
          and all(v["status"] == "compiled" for v in report["builds"].values()))
    command_wall = sum(c["wall_ns"] for c in commands)
    check("all_command_costs_retained", all(type(c["wall_ns"]) is int and c["wall_ns"] >= 0 for c in commands)
          and report["costs"]["all_child_command_wall_ns"] == command_wall,
          commands=len(commands), all_child_command_wall_ns=command_wall)
    check("unknown_costs_remain_unknown", report["costs"]["dependency_acquisition_and_manual_engineering_time_ns"] is None
          and registration["manual_preparation_time_ns"] is None and report["costs"]["final_report_write_included"] is False
          and report["costs"]["candidate_preparation_fresh_proofs_included"] is True
          and report["costs"]["pgo_training_rebuild_included"] is True)
    extra = report["builds"][candidate]["production_preparation_wall_ns"] - report["builds"]["hia_original"]["production_preparation_wall_ns"]
    break_even = []
    for kernel in kernels:
        saved = (summary[kernel]["hia_original"]["median_elapsed_ns"] - summary[kernel][candidate]["median_elapsed_ns"]) / (profile["batches"] * profile["calls_per_batch"])
        break_even.append({"kernel": kernel, "extra_production_preparation_ns": extra,
            "point_saved_ns_per_call": saved, "point_calls": math.ceil(max(0, extra) / saved) if saved > 0 else None, "guaranteed": False})
    check("descriptive_break_even_recomputed", matches(report["break_even"], break_even))
    check("final_status_matches_failed_joint_gate", report["quality_passed"] is True
          and report["ok"] is False and report["status"] == "completed_noninferiority_failed"
          and not all_gate and not strong_gate
          and all(report[k] is True for k in ("source_unchanged", "tools_unchanged", "artifacts_unchanged", "environment_unchanged", "python_runtime_unchanged")))
    check("raw_report_unchanged_during_audit", identity(report_path) == before)

    common = {"schema": "hepta.hia.round4-independent-numeric-audit.v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(), "reviewer": "/root/ndu_round4",
        "audit_source": identity(__file__), "raw_report": before,
        "registration_file": identity(HERE / "REGISTRATION.json"), "protocol_file": identity(HERE / "PROTOCOL.json"),
        "registration_content_sha256": calculated_registration,
        "execution_policy": {"new_native_executions": 0, "new_model_completions": 0, "archives_extracted_or_compressed": 0,
                             "raw_observations_written": 0, "producer_evaluator_imported": False},
        "audit_passed": all(value["passed"] for value in checks.values()), "checks": checks,
        "recomputed_summary": summary, "recomputed_comparisons": detailed,
        "recomputed_quality_passed": numeric_quality, "recomputed_all14_gate": all_gate,
        "recomputed_strong10_gate": strong_gate,
        "float_comparison_tolerance": {"relative": 1e-12, "absolute": 1e-12},
        "limits": ["Only this finite disclosed holdout and this shared Linux host were observed; the host was not exclusive.",
                   "Observed nearest-rank tails are not population tail confidence bounds or service SLOs.",
                   "File-byte identity checks do not prove a complete dynamic compiler/sysroot dependency closure.",
                   "Environment unchanged and source registration before sampling are retained producer records, not independent process attestation.",
                   "Dependency acquisition, manual engineering and final report/archive/audit costs are not invented or added as zero."]}
    failed_counts = Counter(key for row in detailed for key in row["failed_components"])
    readout = {"schema": "hepta.hia.optimizer-bench.round4-readout.v1", "status": report["status"],
        "independent_audit_passed": common["audit_passed"], "registration_sha256": calculated_registration,
        "raw_report_sha256": before["sha256"], "source_base_commit": profile["base_commit"],
        "original_candidate_base_commit": profile["original_candidate_base_commit"],
        "quality_passed": numeric_quality, "samples": len(rows), "groups": profile["groups"], "backends": len(backends),
        "correctness_observations": sum(len(v["observations"]) for v in report["correctness"].values()),
        "batch_samples_per_arm_per_kernel": profile["groups"] * profile["batches"],
        "request_samples_per_arm_per_kernel": profile["groups"] * profile["request_tail_probes"],
        "comparisons_passed": sum(r["noninferiority_thresholds_passed"] for r in comparisons), "comparisons_total": 14,
        "strong_comparisons_passed": sum(r["noninferiority_thresholds_passed"] for r in strong), "strong_comparisons_total": 10,
        "all14_gate_passed": all_gate, "strong10_gate_passed": strong_gate, "batch_p99_mandatory": True,
        "failed_component_counts": dict(failed_counts),
        "passing_comparisons": [{"kernel": r["kernel"], "baseline": r["baseline"]} for r in comparisons if r["noninferiority_thresholds_passed"]],
        "rust_comparisons": [r for r in detailed if r["baseline"] == "rust_o3_lto"],
        "largest_batch_p99_ratio": max(detailed, key=lambda r: r["empirical_p99_batch_ratio"]),
        "production_preparation_ns_by_arm": {k: v["production_preparation_wall_ns"] for k, v in report["builds"].items()},
        "experiment_costs": report["costs"], "break_even_vs_hia_original_only": break_even,
        "environment": report["environment"],
        "interpretation": "All measurements passed the registered quality checks, but the mandatory all14 and strong10 noninferiority gates failed. Faster point estimates do not replace confidence/tail gates.",
        "claims": {**report["claims"], "strong_performance_acceptance_established": False,
                   "prior_results_replaced_or_rescored": False, "performance_retimed": False,
                   "whole_economic_cost_measured": False},
        "audit": "ROOT_NUMERIC_AUDIT.json"}
    return common, readout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    result, readout = audit(args.report)
    for name, value in (("ROOT_NUMERIC_AUDIT.json", result), ("READOUT.json", readout)):
        with (HERE / name).open("x") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
    print(json.dumps({"audit_passed": result["audit_passed"], "checks": len(result["checks"]),
        "failed_checks": [k for k, v in result["checks"].items() if not v["passed"]],
        "all14_gate_passed": readout["all14_gate_passed"], "strong10_gate_passed": readout["strong10_gate_passed"],
        "passing_comparisons": readout["comparisons_passed"], "new_native_executions": 0, "new_model_completions": 0}))
    return 0 if result["audit_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
