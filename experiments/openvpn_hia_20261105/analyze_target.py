#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline, loss-preserving analysis of the fixed OpenVPN/HIA target receipts.

Reads existing artifacts only. Never provisions a host or runs a workload.
Receipt verdicts remain attributed to their producer; this is not a new runtime
qualification gate. Every planned slot is emitted, including missing/failed
ones. Finite partial observations remain visible and labelled in summaries.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
from collections import defaultdict


HERE = Path(__file__).resolve().parent
ARMS = ("c-user", "hia-user", "c-dco")
COMPARISONS = (("hia-user", "c-user"), ("c-dco", "c-user"), ("hia-user", "c-dco"))
ROLES = ("client", "server")
SCOPE = [
    "Finite observations from one shared hosted VM and two namespace/veth endpoints; no production, WAN, physical-NIC, or cross-host inference.",
    "Only the recorded selected vCPUs are sampled. The VM is not an exclusive physical host and CPU frequency is not locked.",
    "Both traffic generators and OpenVPN share their role's vCPU. Host CPU ticks also include kernel, softirq and unrelated VM work.",
    "OpenVPN process user/system seconds exclude kernel DCO work. They are neither whole-machine CPU nor total DCO CPU cost.",
    "CPU and sampled RSS describe the whole bidirectional interval per endpoint; they cannot be allocated to one traffic direction.",
    "Pairing is by fixed round/order/workload, with direction or process role added; different positions are scheduled sequentially, not simultaneously.",
    "All planned samples and partial finite observations are retained. No warmup removal, outlier removal, best-run selection, or confidence inflation is performed.",
    "Zero loss is a measured zero only when present in the receipt. Missing fields remain null. Ratios with a zero/missing denominator remain undefined.",
    "The analyzer reports existing build/matrix/verifier verdicts; it does not replace the independent verifier or certify runtime acceptance.",
]


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def clean(value):
    """Preserve nonfinite input evidence explicitly without emitting invalid JSON."""
    if isinstance(value, float) and not math.isfinite(value):
        return {"nonfinite_input_number": repr(value)}
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


def encoded(value, *, pretty=False):
    return json.dumps(clean(value), ensure_ascii=False, allow_nan=False,
                      sort_keys=True, indent=2 if pretty else None)


def statistic(values):
    numbers = [v for v in values if finite(v)]
    return {"finite_observations": len(numbers), "unavailable_observations": len(values) - len(numbers),
            "minimum": min(numbers) if numbers else None,
            "median": statistics.median(numbers) if numbers else None,
            "maximum": max(numbers) if numbers else None}


def planned_cases(plan):
    rows = []
    for server, client in plan["behavior"]["epoch_pairs"]:
        rows.append({"id": f"epoch-{server}-{client}", "kind": "behavior", "epoch": True,
                     "arms": {"server": server + "-user", "client": client + "-user"}})
    for client in plan["behavior"]["common_profile_clients"]:
        rows.append({"id": "common-" + client, "kind": "behavior", "epoch": False,
                     "arms": {"server": "c-dco", "client": client}})
    for client in plan["behavior"]["negative_clients"]:
        rows.append({"id": "auth-untrusted-" + client, "kind": "authentication",
                     "arms": {"server": "c-user", "client": client + "-user"}})
    for arm in plan["profile"]["arms"]:
        rows.append({"id": "profile-" + arm, "kind": "profile", "arms": {"server": "c-dco", "client": arm}})
    for round_no in range(plan["performance"]["rounds"]):
        for order_no, order in enumerate(plan["performance"]["orders"]):
            for position, arm in enumerate(order):
                rows.append({"id": f"perf-r{round_no}-o{order_no}-p{position}-{arm}", "kind": "performance",
                             "round": round_no, "order": order_no, "position": position,
                             "arms": {"server": "c-dco", "client": arm}})
    return rows


class Reader:
    def __init__(self, public):
        self.public = public.resolve()
        self.hashes = {}
        self.issues = []

    def path(self, root, relative):
        result = (root / relative).resolve()
        if not result.is_relative_to(root.resolve()):
            raise ValueError("receipt path leaves its evidence root: " + str(relative))
        return result

    def read(self, path, *, missing_ok=False):
        path = path.resolve()
        if not path.is_relative_to(self.public):
            self.issues.append({"issue": "receipt resolves outside artifact root", "path": str(path)})
            return None
        relative = str(path.relative_to(self.public))
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            if not missing_ok:
                self.issues.append({"path": relative, "issue": "missing file"})
            return None
        except OSError as exc:
            self.issues.append({"path": relative, "issue": repr(exc)})
            return None
        self.hashes[relative] = digest_bytes(data)
        try:
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ValueError("top-level receipt must be an object")
            return value
        except (ValueError, UnicodeError) as exc:
            self.issues.append({"path": relative, "issue": "invalid receipt: " + repr(exc)})
            return None


def fields_of_interest(value, case_id, source, path=""):
    """Keep exact per-field values; these overlapping observations are not summed."""
    result = []
    if isinstance(value, dict):
        for key, item in value.items():
            at = path + "." + key if path else key
            lower = key.lower()
            loss = any(x in lower for x in ("missing", "lost", "loss", "jitter", "duplicate", "reordered", "invalid"))
            error = key in ("failure", "failures", "cleanup_errors", "error", "errors", "send_errors", "echo_errors")
            failed_check = path.endswith("checks") and item is not True
            if loss or error or failed_check:
                result.append({"case_id": case_id, "source": source, "field": at,
                               "category": "failed_check" if failed_check else "loss_or_order" if loss else "error",
                               "value": item})
            result.extend(fields_of_interest(item, case_id, source, at))
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, (dict, list)):
                result.extend(fields_of_interest(item, case_id, source, f"{path}[{i}]"))
    return result


def normalize_measurement(task, workload, measurement, source, case_ok, identity_ok, issues):
    m = measurement or {}
    identity_ok = identity_ok and m.get("workload") == workload
    if measurement and m.get("workload") != workload:
        issues = [*issues, "measurement workload identity differs from fixed plan"]
    common = {"case_id": task["id"], "round": task["round"], "order": task["order"],
              "position": task["position"], "arm": task["arms"]["client"],
              "workload": workload["name"], "transport": workload["transport"], "source": source,
              "case_reported_passed": case_ok, "measurement_present": measurement is not None,
              "measurement_reported_passed": m.get("passed") is True,
              "measurement_status": m.get("status", "missing"), "identity_ok": identity_ok,
              "issues": list(issues), "elapsed_seconds": m.get("elapsed_seconds"),
              "reported_failures": m.get("failures", []), "reported_checks": m.get("checks", {})}
    directions, processes = [], []
    for role in ROLES:
        receiver = m.get(role + "_local_receiver", {})
        expected_path = "end.sum_received_bidir_reverse" if role == "client" else "end.sum_received"
        receiver_ok = bool(identity_ok and isinstance(receiver, dict)
                           and receiver.get("json_path") == expected_path
                           and receiver.get("local_receiving_role") == role and receiver.get("sender") is False)
        receiver = receiver if isinstance(receiver, dict) else {}
        row = {**common, "direction": "server-to-client" if role == "client" else "client-to-server",
               "receiver_role": role, "receiver_identity_ok": receiver_ok, "receiver_json_path": receiver.get("json_path"),
               "receiver_raw": receiver}
        for key in ("bytes", "seconds", "bits_per_second", "jitter_ms", "lost_packets", "packets", "lost_percent"):
            value = receiver.get(key)
            row[key] = value if receiver_ok and finite(value) and value >= 0 else None
        # A zero rate in a failed measurement is retained as zero, not fabricated
        # into success. Missing/bad-identity/nonfinite fields remain unavailable.
        row["received_mbps"] = row["bits_per_second"] / 1_000_000 if row["bits_per_second"] is not None else None
        row["numeric_fields_unavailable"] = [key for key in (
            ("bytes", "seconds", "bits_per_second", "jitter_ms", "lost_packets", "packets", "lost_percent")
            if workload["transport"] == "udp" else ("bytes", "seconds", "bits_per_second")) if row[key] is None]
        directions.append(row)
        cpu = m.get("process_cpu_seconds", {}).get(role, {})
        cpu = cpu if isinstance(cpu, dict) else {}
        proc = {**common, "role": role, "endpoint_implementation": task["arms"][role], "cpu_raw": cpu}
        for target, original in (("user_seconds", "user"), ("system_seconds", "system"),
                                 ("maximum_sampled_rss_bytes", "maximum_sampled_rss_bytes")):
            value = cpu.get(original)
            proc[target] = value if identity_ok and finite(value) and value >= 0 else None
        proc["total_process_seconds"] = (proc["user_seconds"] + proc["system_seconds"]
                                         if proc["user_seconds"] is not None and proc["system_seconds"] is not None else None)
        proc["maximum_sampled_rss_mib"] = (proc["maximum_sampled_rss_bytes"] / (1024 * 1024)
                                            if proc["maximum_sampled_rss_bytes"] is not None else None)
        processes.append(proc)
    return directions, processes


def pair_samples(samples, dimension, metrics):
    groups = defaultdict(dict)
    for row in samples:
        key = (row["round"], row["order"], row["workload"], row[dimension])
        if row["arm"] in groups[key]:
            raise ValueError("duplicate normalized performance slot")
        groups[key][row["arm"]] = row
    paired = []
    for (round_no, order_no, workload, detail), group in sorted(groups.items()):
        for numerator_arm, denominator_arm in COMPARISONS:
            a, b = group.get(numerator_arm), group.get(denominator_arm)
            for metric in metrics:
                av, bv = a.get(metric) if a else None, b.get(metric) if b else None
                available = finite(av) and finite(bv)
                ratio = av / bv if available and bv > 0 else None
                overflow = ratio is not None and not finite(ratio)
                if overflow:
                    ratio = None
                paired.append({"round": round_no, "order": order_no, "workload": workload, dimension: detail,
                               "numerator_arm": numerator_arm, "denominator_arm": denominator_arm,
                               "metric": metric, "numerator": av, "denominator": bv,
                               "ratio": ratio, "difference": av - bv if available else None,
                               "ratio_unavailable_reason": None if ratio is not None else
                                   "ratio outside finite numeric range" if overflow else
                                   "zero denominator" if available else "missing, nonfinite or unidentified observation",
                               "numerator_case_id": a["case_id"] if a else None,
                               "denominator_case_id": b["case_id"] if b else None,
                               "both_reported_passed": bool(a and b and all(r["case_reported_passed"] and
                                   r["measurement_reported_passed"] for r in (a, b)))})
    return paired


def summarize(samples, dimension, metrics):
    groups = defaultdict(list)
    for row in samples:
        groups[(row["workload"], row[dimension], row["arm"])].append(row)
    return [{"workload": w, dimension: d, "arm": a, "planned_slots": len(rows),
             "present_measurements": sum(r["measurement_present"] for r in rows),
             "reported_passed_slots": sum(r["case_reported_passed"] and r["measurement_reported_passed"] for r in rows),
             "statistics_include_finite_partial_observations": True,
             "metrics": {metric: statistic([r[metric] for r in rows]) for metric in metrics}}
            for (w, d, a), rows in sorted(groups.items())]


def summarize_pairs(pairs, dimension):
    groups = defaultdict(list)
    for row in pairs:
        groups[(row["workload"], row[dimension], row["numerator_arm"], row["denominator_arm"], row["metric"])].append(row)
    return [{"workload": w, dimension: d, "numerator_arm": a, "denominator_arm": b, "metric": m,
             "planned_pairs": len(rows), "both_reported_passed_pairs": sum(r["both_reported_passed"] for r in rows),
             "ratios": statistic([r["ratio"] for r in rows]), "differences": statistic([r["difference"] for r in rows]),
             "numerator_above_denominator_pairs": sum(finite(r["difference"]) and r["difference"] > 0 for r in rows),
             "numerator_below_denominator_pairs": sum(finite(r["difference"]) and r["difference"] < 0 for r in rows)}
            for (w, d, a, b, m), rows in sorted(groups.items())]


def analyze(public):
    reader = Reader(public)
    target = public / "tunnel"
    if not (public / "build.json").is_file() and not (target / "target-result.json").is_file():
        raise ValueError("no real build or target receipt found; no result will be synthesized")
    build = reader.read(public / "build.json") or {}
    report = reader.read(target / "target-result.json") or {}
    verification = reader.read(public / "target-result-verification.json") or {}
    local_plan = json.loads((HERE / "target_host/plan.json").read_text())
    plan = report.get("plan") or local_plan
    plan_origin = "recorded target plan" if report.get("plan") else "local fixed plan; target receipt missing"
    if plan != local_plan:
        reader.issues.append({"issue": "recorded plan differs from local fixed plan; outputs describe the recorded plan"})
    elif report.get("plan") and report.get("plan_sha256") != digest_bytes((HERE / "target_host/plan.json").read_bytes()):
        reader.issues.append({"issue": "recorded plan digest does not match the local fixed plan file"})
    commits = [build.get("hepta_commit"), report.get("inputs", {}).get("hepta_commit"), verification.get("expected_commit")]
    if not all(isinstance(x, str) and x for x in commits) or len(set(commits)) != 1:
        reader.issues.append({"issue": "build/matrix/verifier source identities are missing or inconsistent", "commits": commits})
    expected = planned_cases(plan)
    rows_by_id = defaultdict(list)
    for row in report.get("cases", []):
        rows_by_id[row.get("id")].append(row)
    expected_ids = {task["id"] for task in expected}
    extra_ids = set(rows_by_id) - expected_ids
    if target.exists():
        extra_ids |= {p.parent.name for p in target.glob("cases/*/case.json")} - expected_ids
    for case_id in sorted(extra_ids, key=str):
        reader.issues.append({"case_id": case_id, "issue": "unexpected case retained outside planned summaries"})
        expected.append({"id": case_id, "kind": "unexpected", "arms": {}})
    inventory, raw_cases, raw_measurements, field_records, directions, processes, payload_probes = [], [], [], [], [], [], []
    for task in expected:
        case_id = task["id"]
        matrix_rows = rows_by_id.get(case_id, [])
        row = matrix_rows[0] if len(matrix_rows) == 1 else {}
        issues = []
        if len(matrix_rows) != 1:
            issues.append("matrix row missing" if not matrix_rows else "duplicate matrix rows")
        identity_ok = len(matrix_rows) == 1 and all(row.get(k) == v for k, v in task.items())
        if not identity_ok:
            issues.append("planned task identity not established")
        try:
            case_path = reader.path(target, row.get("receipt") or f"cases/{case_id}/case.json")
            case = reader.read(case_path)
            case_source = str(case_path.relative_to(public))
        except (ValueError, TypeError) as exc:
            case, case_path, case_source = None, None, None
            issues.append(repr(exc))
        case = case or {}
        identity_ok = identity_ok and case.get("case") == case_id and case.get("arms") == task["arms"]
        if case and not identity_ok:
            issues.append("case receipt identity differs from plan or matrix row")
        case_ok = bool(identity_ok and row.get("passed") is True and row.get("status") == "completed"
                       and case.get("passed") is True and case.get("status") == "completed")
        entry = {"case_id": case_id, "kind": task["kind"], "planned": task["kind"] != "unexpected",
                 "arms": task["arms"], "matrix_status": row.get("status", "missing"),
                 "case_status": case.get("status", "missing"), "case_receipt_present": bool(case),
                 "reported_passed_consistently": case_ok, "identity_ok": identity_ok,
                 "receipt": case_source, "matrix_rows": matrix_rows, "checks": case.get("checks", {}),
                 "failure": case.get("failure") or row.get("failure"), "cleanup_errors": case.get("cleanup_errors", []),
                 "issues": issues, "expected_workloads": [], "missing_workloads": []}
        raw_cases.append({"case_id": case_id, "source": case_source, "matrix_rows": matrix_rows,
                          "receipt": case if case else None})
        field_records.extend(fields_of_interest({k: v for k, v in case.items() if k != "measurements"}, case_id, case_source))
        field_records.extend(fields_of_interest(matrix_rows, case_id, "tunnel/target-result.json"))
        phases = (("old_payload_final", "post_rekey_payload", "post_reconnect_payload", "continuity")
                  if task["kind"] == "behavior" else ("negative_payload",) if task["kind"] == "authentication" else ())
        for phase in phases:
            probe = case.get(phase, {})
            receiver, sender = probe.get("receiver", {}), probe.get("sender", {})
            payload_probes.append({"case_id": case_id, "kind": task["kind"], "phase": phase,
                                   "present": bool(probe), "probe_reported_passed": probe.get("passed"),
                                   "receiver_missing_packets": receiver.get("missing_count"),
                                   "receiver_missing_ranges": receiver.get("missing_ranges_inclusive"),
                                   "receiver_duplicates": receiver.get("duplicate_packets"),
                                   "receiver_invalid": receiver.get("invalid_packets"),
                                   "sender_missing_echoes": sender.get("missing_echo_count"),
                                   "sender_missing_echo_ranges": sender.get("missing_echo_ranges_inclusive"),
                                   "sender_send_errors": sender.get("send_errors"),
                                   "receiver_exit": probe.get("receiver_exit"), "sender_exit": probe.get("sender_exit")})
        inline = case.get("measurements", [])
        seen_files = set()
        if task["kind"] == "performance":
            for index, workload in enumerate(plan["performance"]["workloads"]):
                entry["expected_workloads"].append(workload["name"])
                candidates = [m for m in inline if isinstance(m, dict) and m.get("workload", {}).get("name") == workload["name"]]
                measurement = candidates[0] if len(candidates) == 1 else None
                source = f"{case_source}#measurements[{inline.index(measurement)}]" if measurement is not None else None
                measurement_issues = list(issues)
                if len(candidates) > 1:
                    measurement_issues.append("duplicate inline workload receipts")
                standalone = None
                if case_path:
                    measurement_path = case_path.parent / f"workload-{index}-{workload['name']}-measurement.json"
                    standalone = reader.read(measurement_path, missing_ok=True)
                    seen_files.add(measurement_path)
                    if standalone is not None:
                        if measurement is not None and standalone != measurement:
                            measurement_issues.append("standalone and embedded measurements differ; standalone retained as latest independently written receipt")
                        measurement, source = standalone, str(measurement_path.relative_to(public))
                if measurement is None:
                    entry["missing_workloads"].append(workload["name"])
                    measurement_issues.append("no measurement receipt for planned workload")
                raw_measurements.append({"case_id": case_id, "expected_workload": workload, "source": source,
                                         "issues": measurement_issues, "receipt": measurement,
                                         "inline_candidates": candidates if standalone is not None or len(candidates) != 1 else None})
                if measurement:
                    field_records.extend(fields_of_interest(measurement, case_id, source))
                ds, ps = normalize_measurement(task, workload, measurement, source, case_ok,
                                              identity_ok and len(candidates) <= 1, measurement_issues)
                directions.extend(ds); processes.extend(ps)
        else:
            for index, measurement in enumerate(inline):
                source = f"{case_source}#measurements[{index}]"
                raw_measurements.append({"case_id": case_id, "source": source, "receipt": measurement})
                field_records.extend(fields_of_interest(measurement, case_id, source))
        # A crash can leave a standalone measurement before case.json is updated.
        # Retain orphaned/unexpected files even when they cannot enter pairing.
        if case_path:
            for measurement_path in sorted(case_path.parent.glob("*-measurement.json")):
                if measurement_path in seen_files:
                    continue
                measurement = reader.read(measurement_path)
                source = str(measurement_path.relative_to(public))
                raw_measurements.append({"case_id": case_id, "source": source,
                                         "outside_planned_performance_slots": True, "receipt": measurement})
                field_records.extend(fields_of_interest(measurement, case_id, source))
        inventory.append(entry)
    direction_metrics = ("received_mbps", "lost_percent", "jitter_ms", "lost_packets", "packets")
    process_metrics = ("user_seconds", "system_seconds", "total_process_seconds", "maximum_sampled_rss_mib")
    direction_pairs = pair_samples(directions, "direction", direction_metrics)
    process_pairs = pair_samples(processes, "role", process_metrics)
    analysis = {"schema": "hepta.openvpn-hia.offline-target-analysis.v1", "analyzer_sha256": digest_bytes(Path(__file__).read_bytes()),
                "input_public": str(public), "input_file_sha256": reader.hashes, "plan_origin": plan_origin,
                "plan_matches_local": plan == local_plan, "plan": plan, "scope": SCOPE,
                "receipt_verdicts": {"build_reported_ok": build.get("ok"), "matrix_reported_complete": report.get("complete"),
                                     "verifier_reported_passed": verification.get("passed"),
                                     "matrix_gates": report.get("gates"), "matrix_counts": report.get("counts"),
                                     "build_failure": build.get("failure"), "matrix_failure": report.get("failure"),
                                     "verification_failure": verification.get("failure")},
                "runtime_identity": {"build_commit": build.get("hepta_commit"),
                                     "matrix_commit": report.get("inputs", {}).get("hepta_commit"),
                                     "verifier_expected_commit": verification.get("expected_commit"),
                                     "runner": build.get("runner"), "kernel": build.get("kernel"),
                                     "compiler_sha256": build.get("compiler_sha256"), "link": build.get("link"),
                                     "dco_provider": build.get("dco_provider"), "host": report.get("host"),
                                     "selected_vcpus": report.get("host", {}).get("selected_cpus"),
                                     "started_utc": report.get("started_utc"), "finished_utc": report.get("finished_utc")},
                "case_inventory": inventory, "input_issues": reader.issues,
                "payload_probe_observations": payload_probes,
                "measurement_issues": [{"case_id": row["case_id"], "source": row.get("source"),
                                        "expected_workload": row.get("expected_workload"), "issues": row["issues"]}
                                       for row in raw_measurements if row.get("issues")],
                "counts": {"planned_cases": len(expected_ids), "retained_cases": len(inventory),
                           "consistently_reported_passed_cases": sum(r["reported_passed_consistently"] for r in inventory),
                           "missing_case_receipts": sum(not r["case_receipt_present"] for r in inventory),
                           "planned_direction_slots": len(directions), "planned_process_slots": len(processes),
                           "missing_workload_receipts": sum(len(r["missing_workloads"]) for r in inventory)},
                "direction_summary": summarize(directions, "direction", direction_metrics),
                "process_summary": summarize(processes, "role", process_metrics),
                "direction_pair_summary": summarize_pairs(direction_pairs, "direction"),
                "process_pair_summary": summarize_pairs(process_pairs, "role")}
    datasets = {"raw-cases.jsonl": raw_cases, "raw-measurements.jsonl": raw_measurements,
                "loss-and-error-fields.jsonl": field_records, "direction-samples.csv": directions,
                "process-samples.csv": processes, "direction-pairs.csv": direction_pairs,
                "process-pairs.csv": process_pairs, "payload-probes.csv": payload_probes}
    return analysis, datasets


def fmt(value):
    return f"{value:.4f}" if finite(value) else "—"


def markdown(analysis):
    lines = ["# Offline target experiment analysis", "", "## Recorded status", "",
             "This document describes existing artifacts. It is not a new runtime qualification.", "",
             "```json", encoded(analysis["receipt_verdicts"], pretty=True), "```", "",
             "Recorded source commits (build / matrix / verifier): `" + encoded([
                 analysis["runtime_identity"][key] for key in ("build_commit", "matrix_commit", "verifier_expected_commit")]) + "`.", "",
             "Selected vCPUs: `" + encoded(analysis["runtime_identity"]["selected_vcpus"]) + "`.", "",
             "All statistics below include every finite, identified observation, including partial or failed intervals.",
             "Missing values remain unavailable; passing counts accompany every group.", "",
             "## Complete case inventory", "", "| Case | Kind | Matrix / case status | Consistent pass | Missing workloads |",
             "| --- | --- | --- | --- | --- |"]
    for row in analysis["case_inventory"]:
        lines.append(f"| {row['case_id']} | {row['kind']} | {row['matrix_status']} / {row['case_status']} | {row['reported_passed_consistently']} | {', '.join(row['missing_workloads']) or '—'} |")
    lines += ["", "## Directional throughput and UDP observations", "",
              "Medians are descriptive. Loss is percentage points; jitter is milliseconds. TCP has no UDP loss/jitter entry.", "",
              "| Workload | Direction | Client arm | Slots / present / reported pass | Mbps median [min, max] | UDP loss % median | UDP jitter ms median |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for row in analysis["direction_summary"]:
        m = row["metrics"]; t = m["received_mbps"]
        lines.append(f"| {row['workload']} | {row['direction']} | {row['arm']} | {row['planned_slots']} / {row['present_measurements']} / {row['reported_passed_slots']} | {fmt(t['median'])} [{fmt(t['minimum'])}, {fmt(t['maximum'])}] | {fmt(m['lost_percent']['median'])} | {fmt(m['jitter_ms']['median'])} |")
    lines += ["", "## Paired directional comparison", "",
              "Each ratio uses matching round/order/workload/direction. Above 1 means higher numerator throughput.",
              "No unpaired medians are divided. All individual pair values and undefined-ratio reasons are in direction-pairs.csv.", "",
              "| Workload | Direction | Numerator / denominator | Planned / finite / both pass | Mbps paired ratio median [min, max] | Above / below pairs |",
              "| --- | --- | --- | --- | --- | --- |"]
    for row in analysis["direction_pair_summary"]:
        if row["metric"] != "received_mbps":
            continue
        s = row["ratios"]
        lines.append(f"| {row['workload']} | {row['direction']} | {row['numerator_arm']} / {row['denominator_arm']} | {row['planned_pairs']} / {s['finite_observations']} / {row['both_reported_passed_pairs']} | {fmt(s['median'])} [{fmt(s['minimum'])}, {fmt(s['maximum'])}] | {row['numerator_above_denominator_pairs']} / {row['numerator_below_denominator_pairs']} |")
    lines += ["", "### Paired UDP loss and jitter differences", "",
              "Differences are numerator minus denominator. Positive loss/jitter differences indicate worse observations; zero denominators do not prevent a difference from being shown.", "",
              "| Workload | Direction | Numerator / denominator | Metric | Finite pairs | Median difference [min, max] | Above / below pairs |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for row in analysis["direction_pair_summary"]:
        if row["metric"] not in ("lost_percent", "jitter_ms") or row["workload"] == "tcp":
            continue
        s = row["differences"]
        lines.append(f"| {row['workload']} | {row['direction']} | {row['numerator_arm']} / {row['denominator_arm']} | {row['metric']} | {s['finite_observations']} | {fmt(s['median'])} [{fmt(s['minimum'])}, {fmt(s['maximum'])}] | {row['numerator_above_denominator_pairs']} / {row['numerator_below_denominator_pairs']} |")
    lines += ["", "## OpenVPN process CPU and sampled RSS", "",
              "CPU seconds cover both directions together. The server always uses C-DCO in these performance cases.",
              "These process counters exclude kernel DCO CPU and do not measure total machine energy or CPU cost.", "",
              "| Workload | Endpoint | Client arm | Slots / reported pass | User s median | System s median | Total process s median | Sampled RSS MiB median |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in analysis["process_summary"]:
        m = row["metrics"]
        lines.append(f"| {row['workload']} | {row['role']} | {row['arm']} | {row['planned_slots']} / {row['reported_passed_slots']} | {fmt(m['user_seconds']['median'])} | {fmt(m['system_seconds']['median'])} | {fmt(m['total_process_seconds']['median'])} | {fmt(m['maximum_sampled_rss_mib']['median'])} |")
    lines += ["", "### Paired process CPU and RSS", "",
              "Ratios compare the same endpoint role at the fixed round/order/workload. Process CPU reduction alone is not total DCO efficiency.", "",
              "| Workload | Endpoint | Numerator / denominator | Metric | Planned / finite / both pass | Paired ratio median [min, max] |",
              "| --- | --- | --- | --- | --- | --- |"]
    for row in analysis["process_pair_summary"]:
        s = row["ratios"]
        lines.append(f"| {row['workload']} | {row['role']} | {row['numerator_arm']} / {row['denominator_arm']} | {row['metric']} | {row['planned_pairs']} / {s['finite_observations']} / {row['both_reported_passed_pairs']} | {fmt(s['median'])} [{fmt(s['minimum'])}, {fmt(s['maximum'])}] |")
    lines += ["", "## Payload continuity and rejection observations", "",
              "Each declared phase appears even when its receipt is missing. Lost sequence ranges are retained in payload-probes.csv and analysis.json.",
              "The authentication negative case deliberately attempts blocked traffic: a failed payload probe there is expected, and is distinct from the authentication case verdict.", "",
              "| Case | Phase | Present / probe pass | Receiver missing / duplicates / invalid | Sender missing echoes / send errors |",
              "| --- | --- | --- | --- | --- |"]
    for row in analysis["payload_probe_observations"]:
        show = lambda key: "—" if row[key] is None else str(row[key])
        lines.append(f"| {row['case_id']} | {row['phase']} | {row['present']} / {show('probe_reported_passed')} | {show('receiver_missing_packets')} / {show('receiver_duplicates')} / {show('receiver_invalid')} | {show('sender_missing_echoes')} / {show('sender_send_errors')} |")
    lines += ["", "## Failures, missing evidence, and loss records", "",
              "Every case receipt is preserved in raw-cases.jsonl. Every workload, including missing slots and standalone partial receipts, is preserved in raw-measurements.jsonl.",
              "loss-and-error-fields.jsonl contains exact missing sequence ranges, receiver/echo loss, duplicate/invalid/reordered counts, UDP loss/jitter, and nested errors. Its overlapping raw fields must not be summed as independent events.", ""]
    for row in analysis["case_inventory"]:
        if not row["reported_passed_consistently"] or row["issues"] or row["failure"] or row["cleanup_errors"]:
            lines += ["### " + str(row["case_id"]), "", "```json", encoded(row, pretty=True), "```", ""]
    if analysis["input_issues"]:
        lines += ["### Input issues", "", "```json", encoded(analysis["input_issues"], pretty=True), "```", ""]
    if analysis["measurement_issues"]:
        lines += ["### Measurement receipt issues", "", "```json", encoded(analysis["measurement_issues"], pretty=True), "```", ""]
    lines += ["## Scope and interpretation", ""] + ["- " + x for x in analysis["scope"]]
    return "\n".join(lines) + "\n"


def write_csv(path, rows):
    columns = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: encoded(v) if isinstance(v, (dict, list)) else "" if v is None else v for k, v in row.items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, required=True, help="downloaded artifact's public directory")
    parser.add_argument("--output", type=Path, required=True, help="new directory outside the input artifact")
    args = parser.parse_args()
    public, output = args.public.resolve(), args.output.resolve()
    if output.exists() or output.is_relative_to(public):
        parser.error("output must be new and outside the input artifact; inputs are never modified")
    try:
        analysis, datasets = analyze(public)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    output.mkdir(parents=True)
    (output / "analysis.json").write_text(encoded(analysis, pretty=True) + "\n")
    (output / "summary.md").write_text(markdown(analysis))
    for name, rows in datasets.items():
        path = output / name
        if name.endswith(".csv"):
            write_csv(path, rows)
        else:
            path.write_text("".join(encoded(row) + "\n" for row in rows))
    manifest = {p.name: digest_bytes(p.read_bytes()) for p in sorted(output.iterdir()) if p.is_file()}
    (output / "file-manifest.json").write_text(encoded(manifest, pretty=True) + "\n")
    print(encoded({"analysis_written": True, "output": str(output), "receipt_verdicts": analysis["receipt_verdicts"],
                   "counts": analysis["counts"], "runtime_qualification_performed_by_analyzer": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
