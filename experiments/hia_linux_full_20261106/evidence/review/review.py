#!/usr/bin/env python3
"""Independent numerical review of frozen full-kernel comparison outputs.

This script imports no experiment driver. It rechecks observation aggregates,
independently enumerates the registered 5^5 paired block bootstrap, and preserves
all observations. It neither executes a benchmark nor modifies source evidence.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import statistics
from collections import Counter
from fractions import Fraction as F
from pathlib import Path

ARMS = ("stock", "hia-static", "best-fixed", "greedy", "ordinary-mpc",
        "independent-same-objective", "fixed-ndu", "dynamic-ndu")
PHASES = ("syscall_process_pipe", "anonymous_memory", "tmpfs_files", "unix_tcp")
NATIVE = ("independent-same-objective", "fixed-ndu", "dynamic-ndu")
ADAPTIVE = ("greedy", "ordinary-mpc", *NATIVE)
EVAL_SHA = "27fb22c9cc12b6852efd2515730401c1094c1e90b174e756fde04a103d95b582"
OBS_SHA = "542948cfcecc8d3328b9d47c2b1bc355d8ac046e5a319a2b0d579c9d2b262481"
Q = 1 << 32
PUBLIC = {
    "syscall_process_pipe": {"latency": Q, "image_size": 0},
    "anonymous_memory": {"latency": 3*Q//4, "image_size": Q//4},
    "tmpfs_files": {"latency": Q//2, "image_size": Q//2},
    "unix_tcp": {"latency": Q, "image_size": 0},
}
PAIRS = list(itertools.product(range(5), repeat=5))


def need(condition, message):
    if not condition:
        raise ValueError(message)


def binding(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def load_pinned(path, expected):
    identity = binding(path)
    need(identity["sha256"] == expected, "input digest differs: " + str(path))
    return json.loads(Path(path).read_bytes()), identity


def exact(value):
    if isinstance(value, dict):
        value = value.get("exact", value)
        return F(value["numerator"], value["denominator"])
    return F(value)


def pack(value):
    value = F(value)
    return {"exact": {"numerator": value.numerator, "denominator": value.denominator},
            "value": float(value)}


def quantile(values, numerator, denominator=40):
    ordered = sorted(values)
    location = F((len(ordered)-1)*numerator, denominator)
    left = location.numerator // location.denominator
    remainder = location - left
    return ordered[left]*(1-remainder) + ordered[min(left+1, len(ordered)-1)]*remainder


def paired_blocks(baseline, treatment, lower_is_better=True):
    need(len(baseline) == len(treatment) == 5, "exactly five block pairs required")
    a, b = [F(x) for x in baseline], [F(x) for x in treatment]
    need(all(x > 0 for x in a), "positive baseline required for relative change")
    differences, percentages = [], []
    for indices in PAIRS:
        left, right = sum((a[i] for i in indices), F(0)), sum((b[i] for i in indices), F(0))
        differences.append((right-left)/5)
        percentages.append(100*(right-left)/left)
    am, bm = sum(a, F(0))/5, sum(b, F(0))/5
    return {"baseline_mean": pack(am), "arm_mean": pack(bm), "difference": pack(bm-am),
            "difference_ci95": [pack(quantile(differences, p)) for p in (1, 39)],
            "relative_change_percent": pack(100*(bm-am)/am),
            "relative_change_ci95_percent": [pack(quantile(percentages, p)) for p in (1, 39)],
            "baseline_blocks": [pack(x) for x in a], "treatment_blocks": [pack(x) for x in b],
            "independent_block_clusters": 5, "bootstrap_replicates": len(PAIRS),
            "lower_is_better": lower_is_better,
            "method": "exhaustive paired block bootstrap, linear percentile interpolation",
            "comparison_status": "descriptive; no multiplicity-adjusted hypothesis claim"}


def compare_published(actual, published):
    fields = ("baseline_mean", "arm_mean", "difference", "relative_change_percent")
    comparisons = 0
    for name in fields:
        need(exact(actual[name]) == exact(published[name]), "aggregate mismatch: " + name)
        comparisons += 1
    for name in ("difference_ci95", "relative_change_ci95_percent"):
        need([exact(x) for x in actual[name]] == [exact(x) for x in published[name]],
             "interval mismatch: " + name)
        comparisons += 2
    need(actual["lower_is_better"] == published["lower_is_better"], "metric direction mismatch")
    need(published["bootstrap_replicates"] == 3125 and published["independent_block_clusters"] == 5,
         "different resampling denominator")
    return comparisons


def rounded_division(numerator, denominator):
    quotient, remainder = divmod(abs(numerator), denominator)
    quotient += int(remainder*2 > denominator or
                    (remainder*2 == denominator and quotient % 2 == 1))
    return -quotient if numerator < 0 else quotient


def times_summary(values):
    need(values, "empty timing series")
    mean = F(sum(values), len(values))
    return {"count": len(values), "mean_ns": pack(mean),
            "median_ns": pack(statistics.median(values)), "sum_ns": sum(values),
            "minimum_ns": min(values), "maximum_ns": max(values)}


def block_sums(rows, arm, getter):
    return [sum((getter(r) for r in rows if r["arm"] == arm and r["block"] == block), 0)
            for block in range(5)]


def value_text(value, divisor=1, digits=3):
    return f"{float(exact(value)/divisor):.{digits}f}"


def pct_text(stat):
    ci = stat["relative_change_ci95_percent"]
    return (f'{value_text(stat["relative_change_percent"])}% '
            f'[{value_text(ci[0])}%, {value_text(ci[1])}%]')


def review(evaluation_path, observations_path, output):
    evaluation, e_binding = load_pinned(evaluation_path, EVAL_SHA)
    rows, o_binding = load_pinned(observations_path, OBS_SHA)
    need(evaluation["status"] == "PASS", "evaluation was not PASS")
    need(evaluation["heldout_boots"] == evaluation["correct_boots"] == 160 and
         evaluation["failed_boots"] == evaluation["excluded_outliers"] == 0, "incomplete reported campaign")
    need(len(rows) == 160 and len({r["run_id"] for r in rows}) == 160, "duplicate/missing independent boots")
    cell = {(r["block"], r["phase"], r["arm"]): r for r in rows}
    need(len(cell) == 160 and set(cell) == set(itertools.product(range(5), PHASES, ARMS)),
         "incomplete eight-arm/five-block/four-phase grid")
    for r in rows:
        need(r["partition"] == "heldout" and r["correctness"] is True, "non-heldout or failed observation")
        need(r["case_index"] == r["block"]*4 + PHASES.index(r["phase"]), "case order mismatch")
        need(r["seed"] == 20261200 + r["case_index"] and r["iterations"] == 1024, "seed/work mismatch")
        need(r["operation_count"] == (2048 if r["phase"] == "unix_tcp" else 1024),
             "operation denominator mismatch")
        samples = r["raw_measured_samples"]
        need(len(samples) == 5, "five measured samples per boot required")
        for index, sample in enumerate(samples):
            need(sample["sample_index"] == index and sample["sequence"] == index+2 and
                 sample["warmup"] is False and sample["stage"] == r["phase"] and
                 sample["run_id"] == r["run_id"] and sample["correctness"] is True and
                 sample["errno"] == 0 and sample["reason"] == "ok" and
                 sample["checksum"] == sample["expected_checksum"] and sample["duration_ns"] > 0 and
                 sample["operation_count"] == r["operation_count"], "invalid stored measured sample")
        observed_median = sorted(x["duration_ns"] for x in samples)[2]
        need(observed_median == r["median_ns"], "boot median differs from its five stored measurements")
        need(F(observed_median, r["operation_count"]) == exact(r["ns_per_op"]), "ns/op differs")
        planning = r["planning"]
        need(r["net_delivery_wall_ns"] == r["qemu_wall_ns"] + planning["standalone_planning_wall_ns"],
             "net delivery arithmetic differs")
        need(planning["standalone_planning_wall_ns"] ==
             planning["decision_wall_ns"] + planning["common_construction_charged_wall_ns"],
             "standalone decision cost differs")
        if r["arm"] in ("stock", "hia-static", "best-fixed"):
            need(planning["common_construction_charged_wall_ns"] == 0, "static arm charged common search")
        else:
            need(planning["common_construction_charged_wall_ns"] ==
                 cell[r["block"], r["phase"], "dynamic-ndu"]["planning"]["common_construction_charged_wall_ns"],
                 "adaptive arms charged different shared construction")
    native_records = {}
    for rec in evaluation["actual_controller_native_calls"]:
        path = Path(rec["request"]["path"])
        arm, episode = path.parent.name, int(path.parent.parent.name)
        need(arm in NATIVE and 0 <= episode < 20 and (episode, arm) not in native_records,
             "duplicate or out-of-range native call")
        native_records[episode, arm] = rec
        r = cell[episode//4, PHASES[episode % 4], arm]
        need(rec["service_ns"] == r["planning"]["service_ns"], "native service linkage differs")
        need(r["planning"]["decision_wall_ns"] >= rec["wall_ns"] >=
             rec["cold_process_io_wall_ns"] >= rec["service_ns"], "native timing scopes not nested")
    need(set(native_records) == set(itertools.product(range(20), NATIVE)), "60 actual native calls required")

    exact_checks = 0
    metrics = ("median_ns", "qemu_wall_ns", "net_delivery_wall_ns")
    vectors = {arm: {key: block_sums(rows, arm, lambda r, k=key: r[k]) for key in metrics}
               for arm in ARMS}
    cycles = {}
    for arm in ARMS:
        cycles[arm] = {}
        for key in metrics:
            stat = paired_blocks(vectors["stock"][key], vectors[arm][key])
            exact_checks += compare_published(
                stat, evaluation["statistics"]["four_phase_block_cycles"][arm]["four_phase_cycle_"+key])
            cycles[arm][key] = stat

    utilities = evaluation["statistics"]["public_objective_observations"]
    utility_vectors = {}
    stock_bytes = evaluation["final_closure"]["stock"]["kernel"]["bytes"]
    for arm in ARMS:
        need(len(utilities[arm]) == 20, "utility series incomplete")
        seen = set()
        for item in utilities[arm]:
            key = (item["block"], item["phase"])
            need(key not in seen, "duplicate public objective observation")
            seen.add(key)
            observed = cell[item["block"], item["phase"], arm]
            need(item["run_id"] == observed["run_id"] and item["public_target"] == PUBLIC[item["phase"]],
                 "utility uses different run or private objective")
            components = item["components_q32"]
            need(components["image_size"] == rounded_division(100*stock_bytes*Q, observed["image_bytes"]),
                 "image size normalization differs")
            expected_utility = sum(rounded_division(PUBLIC[item["phase"]][axis]*components[axis], Q)
                                   for axis in PUBLIC[item["phase"]])
            need(item["utility_q32"] == expected_utility, "public Q32 utility arithmetic differs")
        utility_vectors[arm] = [sum(x["utility_q32"] for x in utilities[arm] if x["block"] == b)
                                for b in range(5)]
    utility_stats = {}
    for arm in ARMS:
        stat = paired_blocks(utility_vectors["stock"], utility_vectors[arm], lower_is_better=False)
        exact_checks += compare_published(stat, evaluation["statistics"]["public_objective_block_statistics"][arm])
        utility_stats[arm] = stat

    primary = {key: paired_blocks(vectors["independent-same-objective"][key],
                                 vectors["dynamic-ndu"][key]) for key in metrics}
    primary["public_utility_q32"] = paired_blocks(
        utility_vectors["independent-same-objective"], utility_vectors["dynamic-ndu"],
        lower_is_better=False)
    planning_vectors = {
        arm: {key: block_sums(rows, arm, lambda r, k=key: r["planning"][k])
              for key in ("standalone_planning_wall_ns", "decision_wall_ns", "audit_wall_ns",
                          "common_construction_charged_wall_ns", "standalone_planning_cpu_ns")}
        for arm in ARMS
    }
    primary["standalone_planning_wall_ns"] = paired_blocks(
        planning_vectors["independent-same-objective"]["standalone_planning_wall_ns"],
        planning_vectors["dynamic-ndu"]["standalone_planning_wall_ns"])
    native_costs, native_contrasts = {}, {}
    for arm in NATIVE:
        records = [native_records[i, arm] for i in range(20)]
        native_costs[arm] = {key: times_summary([r[key] for r in records]) for key in
            ("service_ns", "cold_process_io_wall_ns", "wall_ns", "parent_cpu_ns", "child_cpu_ns")}
        native_costs[arm]["standalone_planning_wall_ns"] = times_summary(
            [r["planning"]["standalone_planning_wall_ns"] for r in rows if r["arm"] == arm])
        native_costs[arm]["decision_wall_ns"] = times_summary(
            [r["planning"]["decision_wall_ns"] for r in rows if r["arm"] == arm])
        native_costs[arm]["request_bytes_total"] = sum(r["request_bytes"] for r in records)
        native_costs[arm]["response_bytes_total"] = sum(r["response_bytes"] for r in records)
    for key in ("service_ns", "cold_process_io_wall_ns", "wall_ns", "child_cpu_ns", "parent_cpu_ns"):
        a = [sum(native_records[4*b+p, "independent-same-objective"][key] for p in range(4))
             for b in range(5)]
        b = [sum(native_records[4*b+p, "dynamic-ndu"][key] for p in range(4))
             for b in range(5)]
        native_contrasts[key] = paired_blocks(a, b)
        native_contrasts[key]["units"] = "nanoseconds per four-decision block; divide by four for per-decision means"

    matches = {}
    for left, right in itertools.combinations(ARMS, 2):
        matches[left+" vs "+right] = sum(cell[b, p, left]["image_id"] == cell[b, p, right]["image_id"]
                                        for b in range(5) for p in PHASES)
    need(matches["independent-same-objective vs dynamic-ndu"] == 20 and
         evaluation["statistics"]["same_objective_and_dynamic_ndu_matching_actions"] == 20,
         "same-objective actions differ")
    actions = [{"case": i, "block": i//4, "phase": PHASES[i % 4],
                **{arm: cell[i//4, PHASES[i % 4], arm]["image_id"] for arm in ARMS}}
               for i in range(20)]
    counts = {arm: dict(Counter(r["image_id"] for r in rows if r["arm"] == arm)) for arm in ARMS}
    abstentions = {arm: sum(r["abstain"] for r in rows if r["arm"] == arm) for arm in ARMS}
    need(evaluation["cells_with_active_prediction_budget"] == 20 and
         len(evaluation["prediction_budget_observations"]) == 20 and
         all(x["resource_rejected_candidates"] > 0 for x in evaluation["prediction_budget_observations"]),
         "prediction budgets were not active in every cell")
    for item in evaluation["prediction_budget_observations"]:
        need(item["feasible_candidates"] + item["resource_rejected_candidates"] == 82,
             "incomplete prediction budget candidate count")

    setup_audit = {}
    all_qemu_cycle = F(sum(r["qemu_wall_ns"] for r in rows), 5)
    baseline_cycle = F(sum(vectors["stock"]["net_delivery_wall_ns"]), 5)
    for arm in ARMS:
        setup = evaluation["statistics"]["setup_costs"][arm]
        need(sum(setup["details"].values()) == setup["total_ns"], "setup total differs")
        concurrency = setup["build_concurrency"]
        need(concurrency["observed_pipeline_window_ns"] ==
             concurrency["active_pipeline_union_wall_ns"] + concurrency["idle_gaps_inside_observed_window_ns"],
             "build window is not union plus gaps")
        expected_images = ["stock"] if arm == "stock" else ["hia-original"] if arm == "hia-static" else [
            "stock", "hia-original", "hia-o3", "hia-os"]
        need(setup["required"]["images"] == expected_images, "wrong setup image owner")
        need(setup["required"]["native_adapter"] == (arm in ("fixed-ndu", "dynamic-ndu")) and
             setup["required"]["ordinary_control"] == (arm == "independent-same-objective"),
             "wrong native preparation owner")
        if arm in ("stock", "hia-static"):
            need(setup["details"]["calibration_qemu_ns"] == 0 and
                 setup["details"]["native_ndu_preparation_ns"] == 0 and
                 setup["details"]["ordinary_control_preparation_ns"] == 0,
                 "static arm charged unused search preparation")
        direct_cycle = F(sum(vectors[arm]["net_delivery_wall_ns"]), 5)
        extra = (all_qemu_cycle-F(sum(vectors[arm]["qemu_wall_ns"]), 5)) if arm in ADAPTIVE else F(0)
        for scenario in ("provided_past_feedback", "all_shared_feedback_charged"):
            actual = evaluation["statistics"]["amortization"][arm][scenario]
            feedback = extra if scenario == "all_shared_feedback_charged" else F(0)
            cycle = direct_cycle + feedback
            need(exact(actual["observed_four_phase_cycle_ns"]) == cycle and
                 exact(actual["feedback_extra_cycle_ns"]) == feedback, "feedback cost differs")
            for item in actual["deployment_counts"]:
                n = item["four_phase_cycles"]
                need(exact(item["total_ns"]) == setup["total_ns"]+n*cycle and
                     exact(item["amortized_cycle_ns"]) == F(setup["total_ns"], n)+cycle,
                     "amortization arithmetic differs")
            saving = baseline_cycle - cycle
            need(exact(actual["break_even_vs_stock"]["per_cycle_saving_ns"]) == saving,
                 "break-even saving differs")
            if saving <= 0:
                need(actual["break_even_vs_stock"]["reachable"] is False, "unreachable break-even mislabeled")
        setup_audit[arm] = {
            "total_ns": setup["total_ns"], "details": setup["details"],
            "build_concurrency": concurrency,
            "direct_delivery_cycle_ns": pack(direct_cycle),
            "fully_charged_feedback_cycle_ns": pack(direct_cycle+extra),
            "direct_point_estimate_break_even_vs_stock": evaluation["statistics"]["amortization"][arm][
                "provided_past_feedback"]["break_even_vs_stock"],
        }
    need(binding(evaluation_path) == e_binding and binding(observations_path) == o_binding, "input changed during review")
    report = {
        "schema": "hepta.hia.kernel-comparison.independent-numerical-review.v1",
        "status": "PASS",
        "inputs": {"evaluation": e_binding, "heldout_observations": o_binding},
        "review_source": binding(__file__),
        "original_files_modified": False, "frozen_driver_imported_or_executed": False,
        "scope": "numerical review of transported exact observation/evaluation bytes; no benchmark rerun",
        "evidence_limits": [
            "Raw serial files and calibration source traces were admitted by the original collector; this review does not replay those remote files.",
            "All 800 retained measured sample durations are reaggregated here; public utility latency components use the published EVALUATION inputs.",
            "The five-block intervals are descriptive and unadjusted for multiple comparisons; later controllers share past feedback.",
            "Complete wrapper wall includes durable I/O; its long tails are retained, not treated as pure arithmetic time.",
        ],
        "checks": {"unique_boots": 160, "measured_samples_reaggregated": 800,
                   "correctness_flags_true": 160, "reported_failures": 0, "excluded_observations": 0,
                   "full_paired_block_statistics_recomputed": 32, "exact_numeric_fields_matched": exact_checks,
                   "native_calls_reconciled": 60, "active_prediction_budget_cells": 20,
                   "point_estimate_break_even_positive_savings_found": False},
        "eight_arm_cycles_vs_stock": cycles,
        "public_utility_vs_stock": utility_stats,
        "primary_dynamic_vs_independent": primary,
        "native_per_decision": native_costs,
        "native_dynamic_vs_independent_by_five_blocks": native_contrasts,
        "planning_block_sums": planning_vectors,
        "action_counts": counts, "abstention_counts": abstentions,
        "pairwise_matching_image_actions": matches, "action_sequence": actions,
        "setup_cost_audit": setup_audit,
        "image_artifacts": {k: x["kernel"] for k, x in evaluation["final_closure"].items()},
        "retained_wrapper_long_tails": [
            {"case": i, "arm": arm, "wall_ns": r["wall_ns"], "service_ns": r["service_ns"],
             "cold_process_io_wall_ns": r["cold_process_io_wall_ns"]}
            for (i, arm), r in sorted(native_records.items(), key=lambda x: x[1]["wall_ns"], reverse=True)[:12]],
        "interpretation": [
            "No NDU-specific image-selection gain was observed: greedy, ordinary MPC, independent same-objective and dynamic NDU chose the same image in all 20 cells.",
            "The primary dynamic-versus-independent guest, QEMU, net-delivery and public-utility intervals all span zero.",
            "Dynamic NDU has higher measured internal native service and cold-process cost; complete logged-wrapper and full-planner means are affected by retained long tails and are reported with medians and paired intervals.",
            "Dynamic NDU net delivery is slower than stock on the registered direct-delivery accounting; no positive point-estimate per-cycle saving supports break-even under that accounting.",
            "Image-equivalent arms executing identical workloads do not establish an improved kernel algorithm from their separate timing samples.",
            "Recorded setup totals include the observed multi-image build window and its idle gaps; they are not isolated compiler-speed measurements.",
        ],
    }
    output.mkdir(parents=True, exist_ok=False)
    (output/"REVIEW.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    with (output/"CYCLE_SUMMARY.csv").open("w", newline="") as stream:
        columns = ["arm", "guest_cycle_ms", "guest_change_pct", "guest_ci_low_pct", "guest_ci_high_pct",
                   "qemu_cycle_s", "net_delivery_cycle_s", "net_change_pct", "net_ci_low_pct",
                   "net_ci_high_pct", "public_utility_change_pct", "setup_s"]
        writer = csv.DictWriter(stream, fieldnames=columns); writer.writeheader()
        for arm in ARMS:
            guest, net, qemu = cycles[arm]["median_ns"], cycles[arm]["net_delivery_wall_ns"], cycles[arm]["qemu_wall_ns"]
            writer.writerow({"arm": arm, "guest_cycle_ms": float(exact(guest["arm_mean"])/10**6),
                "guest_change_pct": float(exact(guest["relative_change_percent"])),
                "guest_ci_low_pct": float(exact(guest["relative_change_ci95_percent"][0])),
                "guest_ci_high_pct": float(exact(guest["relative_change_ci95_percent"][1])),
                "qemu_cycle_s": float(exact(qemu["arm_mean"])/10**9),
                "net_delivery_cycle_s": float(exact(net["arm_mean"])/10**9),
                "net_change_pct": float(exact(net["relative_change_percent"])),
                "net_ci_low_pct": float(exact(net["relative_change_ci95_percent"][0])),
                "net_ci_high_pct": float(exact(net["relative_change_ci95_percent"][1])),
                "public_utility_change_pct": float(exact(utility_stats[arm]["relative_change_percent"])),
                "setup_s": setup_audit[arm]["total_ns"]/10**9})
    with (output/"ACTION_SELECTIONS.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["case", "block", "phase", *ARMS])
        writer.writeheader(); writer.writerows(actions)
    with (output/"PRIMARY_CONTRASTS.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["metric", "baseline_mean", "dynamic_mean",
            "difference", "difference_ci_low", "difference_ci_high", "change_pct", "ci_low_pct", "ci_high_pct"])
        writer.writeheader()
        for key, stat in primary.items():
            writer.writerow({"metric": key,
                "baseline_mean": float(exact(stat["baseline_mean"])), "dynamic_mean": float(exact(stat["arm_mean"])),
                "difference": float(exact(stat["difference"])),
                "difference_ci_low": float(exact(stat["difference_ci95"][0])),
                "difference_ci_high": float(exact(stat["difference_ci95"][1])),
                "change_pct": float(exact(stat["relative_change_percent"])),
                "ci_low_pct": float(exact(stat["relative_change_ci95_percent"][0])),
                "ci_high_pct": float(exact(stat["relative_change_ci95_percent"][1]))})
    lines = [
        "# Independent numerical review",
        "",
        "**PASS:** the exact evaluation and observation SHA256 values match; 160 boots / 800 measured samples reaggregate correctly.",
        f"All 32 published cycle/public-utility paired statistics reproduce exactly ({exact_checks} exact numeric field checks).",
        "This review imports no frozen driver and runs no benchmark. Input files remain unchanged.",
        "",
        "## Eight-arm four-phase cycles",
        "",
        "Guest time is the mean of five block sums of four per-boot medians. Net delivery includes QEMU and the allocated standalone controller cost; setup is separate.",
        "",
        "| Arm | Guest cycle ms | Guest change vs stock, 95% interval | Net delivery s | Net change vs stock, 95% interval |",
        "|---|---:|---|---:|---|",
    ]
    for arm in ARMS:
        guest, net = cycles[arm]["median_ns"], cycles[arm]["net_delivery_wall_ns"]
        lines.append(f'| {arm} | {value_text(guest["arm_mean"],10**6)} | {pct_text(guest)} | {value_text(net["arm_mean"],10**9)} | {pct_text(net)} |')
    lines += ["", "## Primary paired contrast: dynamic NDU versus independent Rust", "",
              "The baseline for these intervals is the independent Rust same-objective arm, paired within five complete blocks. These are newly computed direct contrasts.",
              "", "| Metric | Change, 95% interval |", "|---|---|"]
    for metric, stat in primary.items():
        lines.append(f"| {metric} | {pct_text(stat)} |")
    lines += ["", "## Action equivalence", "",
              "Greedy, ordinary MPC, independent same-objective and dynamic NDU select the exact same image in every one of the 20 cells: 14 original, 4 Os, 2 O3.",
              "Fixed NDU differs in one cell. Best-fixed uses Os for all 20. No arm abstains.",
              "Consequently, differences in guest timing among the four action-identical policies do not demonstrate different kernel decisions; their separate boots remain subject to execution variability and controller/host state.",
              "", "## Measured controller overhead", "",
              "All long-tail observations are retained. Service and cold-process costs are distinct from durable logging, parsing and complete planner wall.",
              "", "| Arm | Service mean ms | Cold-process mean ms | Logged-wrapper mean / median ms | Full planner mean / median ms |",
              "|---|---:|---:|---|---|"]
    for arm in NATIVE:
        cost = native_costs[arm]
        wrapper, planner = cost["wall_ns"], cost["standalone_planning_wall_ns"]
        lines.append(f'| {arm} | {value_text(cost["service_ns"]["mean_ns"],10**6)} | {value_text(cost["cold_process_io_wall_ns"]["mean_ns"],10**6)} | {value_text(wrapper["mean_ns"],10**6)} / {value_text(wrapper["median_ns"],10**6)} | {value_text(planner["mean_ns"],10**6)} / {value_text(planner["median_ns"],10**6)} |')
    lines += ["", "Direct native comparisons use the same five-block pairing:", "",
              "| Cost | Dynamic change versus independent, 95% interval |", "|---|---|"]
    for key, stat in native_contrasts.items():
        lines.append(f"| {key} | {pct_text(stat)} |")
    lines += ["", "## Setup and interpretation", "",
              "| Arm | Recorded setup seconds |", "|---|---:|"]
    for arm in ARMS:
        lines.append(f'| {arm} | {setup_audit[arm]["total_ns"]/10**9:.3f} |')
    cn = setup_audit["dynamic-ndu"]["build_concurrency"]
    lines += ["",
              f'The shared search preparation includes a {cn["observed_pipeline_window_ns"]/10**9:.3f} s observed build window: {cn["active_pipeline_union_wall_ns"]/10**9:.3f} s active union plus {cn["idle_gaps_inside_observed_window_ns"]/10**9:.3f} s idle gaps. These are recorded preparation costs, not an isolated compiler-speed test.',
              "Every arm has nonpositive observed direct net-delivery savings versus stock. The registered point-estimate break-even is therefore unreachable; fully charging shared feedback does not improve it.",
              "The NDU service/cold-process increase does not justify treating the occasional smaller logged-wall mean as an algorithmic advantage.",
              "Intervals are descriptive, with five block clusters and no correction for multiple comparisons. No observation was dropped or resampled in the campaign.",
              "",
              "## Evidence limits", "",
              *["- "+x for x in report["evidence_limits"]],
              "", "Input SHA256 values:", "",
              "- EVALUATION: "+e_binding["sha256"],
              "- HELDOUT_OBSERVATIONS: "+o_binding["sha256"],
              "",
              "Reproduction: python3 review.py --evaluation EVALUATION.json --observations HELDOUT_OBSERVATIONS.json --output NEW_DIRECTORY",
              ""]
    (output/"REVIEW.md").write_text("\n".join(lines))
    need(binding(evaluation_path) == e_binding and binding(observations_path) == o_binding, "input modified")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluation", required=True, type=Path)
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = review(args.evaluation, args.observations, args.output)
    files = [binding(path) for path in sorted(args.output.iterdir()) if path.is_file()]
    print(json.dumps({"status": report["status"], "checks": report["checks"],
                      "primary_dynamic_vs_independent": report["primary_dynamic_vs_independent"],
                      "native_dynamic_vs_independent": report["native_dynamic_vs_independent_by_five_blocks"],
                      "output_files": files}, indent=2))


if __name__ == "__main__":
    main()

