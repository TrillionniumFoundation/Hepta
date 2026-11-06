#!/usr/bin/env python3
"""Reject missing, incomplete, stale or internally inconsistent target evidence.

This is a receipt/source-integrity check, not a replacement for the real kernel,
network, payload and performance experiment. In particular, process exit zero
without a complete recorded matrix is never a pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re


HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def beneath(root, name):
    result = (root / name).resolve()
    if not result.is_relative_to(root.resolve()):
        raise ValueError("evidence path leaves its output directory")
    return result


def require(value, message):
    if not value:
        raise ValueError(message)


def expected_cases(plan):
    rows = []
    for server, client in plan["behavior"]["epoch_pairs"]:
        rows.append({"id": "epoch-" + server + "-" + client, "kind": "behavior", "epoch": True,
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


def verify(public, expected_commit):
    build = read(public / "build.json")
    target = public / "tunnel"
    report = read(target / "target-result.json")
    host = report.get("host", {})
    allowed = host.get("allowed_cpus", [])
    selected = host.get("selected_cpus", [])
    topology = host.get("cpu_topology", {})
    require(host.get("cpu_topology_error") is None, "physical CPU topology could not be established")
    require(len(selected) == 2 and len(set(selected)) == 2 and
            all(cpu in allowed for cpu in selected),
            "two allowed benchmark CPUs were not selected")
    core_keys = []
    for cpu in selected:
        item = topology.get(str(cpu))
        require(isinstance(item, dict) and type(item.get("package_id")) is int
                and type(item.get("core_id")) is int,
                "selected CPU lacks a frozen physical package/core identity")
        core_keys.append((item["package_id"], item["core_id"]))
    require(len(set(core_keys)) == 2, "server/client benchmark CPUs share a physical core")
    require(host.get("selected_physical_cores") == [list(key) for key in core_keys],
            "selected physical-core receipt differs from the topology map")
    plan = read(HERE / "plan.json")
    require(build.get("ok") is True, "target build did not complete")
    require(build.get("hepta_commit") == expected_commit, "build belongs to another commit")
    require(report.get("schema") == "hepta.openvpn-hia.target-matrix.v1", "unknown matrix schema")
    require(report.get("complete") is True, "matrix did not complete")
    require(report.get("inputs", {}).get("hepta_commit") == expected_commit, "matrix belongs to another commit")
    require(report.get("plan_sha256") == digest(HERE / "plan.json") and report.get("plan") == plan,
            "recorded plan differs from the executed source")
    required_gates = {"real_tun", "dco_runtime", "authentication", "encrypted_replay",
                      "rekey", "reconnect", "profile", "fixed_performance_matrix"}
    require(set(report.get("gates", {})) == required_gates and
            all(report["gates"][name] is True for name in required_gates), "an acceptance gate remains open")
    expected_counts = {
        "planned_behavior_cases": 7, "passed_behavior_cases": 7,
        "planned_authentication_cases": 2, "passed_authentication_cases": 2,
        "planned_profile_cases": 2, "passed_profile_cases": 2,
        "planned_performance_cases": 54, "passed_performance_cases": 54,
        "planned_performance_workloads": 216, "completed_performance_workloads": 216,
        "attempted_performance_workloads": 216, "failed_performance_workloads": 0,
    }
    require(report.get("counts") == expected_counts, "planned/completed inventories differ")
    require(report.get("cleanup", {}).get("passed") is True and
            report["cleanup"].get("private_work_removed") is True, "resource/private-output cleanup failed")
    require(report.get("production_performance_qualified") is False,
            "finite VM measurements were broadened into production qualification")
    require(not report.get("failure"), "controller failure remains in the completed result")
    scripts = report["inputs"].get("scripts", {})
    require(set(scripts) == {p.name for p in HERE.glob("*.py")}, "helper identity inventory is incomplete")
    for filename, expected in scripts.items():
        require(digest(beneath(HERE, filename)) == expected, "executed helper changed: " + filename)
    for role, field in (("c", "c_binary_sha256"), ("hia", "hia_binary_sha256"),
                        ("hia_trace", "hia_trace_binary_sha256")):
        item = report["inputs"]["binaries"][role]
        require(item["sha256"] == build["link"][field] == digest(item["path"]),
                "application identity mismatch: " + role)

    cases = report.get("cases", [])
    require(len(cases) == 65 and len({row["id"] for row in cases}) == 65, "missing or duplicate case IDs")
    required_cases = expected_cases(plan)
    require(len(required_cases) == len(cases), "fixed task inventory changed")
    for row, expected in zip(cases, required_cases):
        require(all(row.get(key) == value for key, value in expected.items()),
                "planned case identity, arm or order changed: " + expected["id"])
    kind_counts = {kind: sum(row["kind"] == kind for row in cases)
                   for kind in ("behavior", "authentication", "profile", "performance")}
    require(kind_counts == {"behavior": 7, "authentication": 2, "profile": 2, "performance": 54},
            "case kinds differ from the fixed inventory")
    measurements = 0
    identities = set()
    for row in cases:
        require(row.get("passed") is True and row.get("status") == "completed", "case not completed: " + row["id"])
        case_path = beneath(target, row["receipt"])
        case = read(case_path)
        require(case.get("case") == row["id"] and case.get("passed") is True
                and case.get("status") == "completed",
                "case receipt identity/verdict mismatch")
        require(case.get("arms") == row["arms"] and not case.get("cleanup_errors"),
                "case arm/cleanup mismatch")
        expected_rekey = (plan["behavior"]["rekey_seconds_by_role"] if row["kind"] == "behavior"
                          else {"server": 3600, "client": 3600})
        require(case.get("reneg_seconds_by_role") == expected_rekey,
                "role-specific renegotiation schedule differs from the frozen plan")
        require(case.get("checks") and all(v is True for v in case["checks"].values()),
                "case observation checks are incomplete")
        if row["kind"] == "performance":
            identity = (row["round"], row["order"], row["position"])
            require(identity not in identities, "duplicate performance position")
            identities.add(identity)
            require(0 <= row["round"] < 3 and 0 <= row["order"] < 6 and 0 <= row["position"] < 3,
                    "performance position is outside the fixed design")
            expected_arm = plan["performance"]["orders"][row["order"]][row["position"]]
            require(row["arms"] == {"server": "c-dco", "client": expected_arm}, "performance arm order changed")
            require(case.get("trace") is False and case.get("reneg_seconds") == 3600
                    and case.get("reneg_seconds_by_role") == {"server": 3600, "client": 3600},
                    "diagnostic instrumentation/rekey timing entered the benchmark")
            values = case.get("measurements", [])
            require(len(values) == 4, "a performance workload is missing")
            for value, workload in zip(values, plan["performance"]["workloads"]):
                require(value.get("passed") is True and value.get("workload") == workload,
                        "workload verdict or identity changed")
                require(value.get("duration_requested_seconds") == 5 and value.get("bidirectional") is True,
                        "traffic budget/direction changed")
                require(value.get("checks") and all(v is True for v in value["checks"].values())
                        and value.get("failures") == [], "traffic measurement has failed observations")
                for role in ("client", "server"):
                    receiver = value[role + "_local_receiver"]
                    receiver_path = "end.sum_received_bidir_reverse" if role == "client" else "end.sum_received"
                    require(receiver.get("json_path") == receiver_path and
                            receiver.get("local_receiving_role") == role and receiver.get("sender") is False,
                            "bidirectional receiver identity is incomplete")
                    require(all(isinstance(receiver.get(k), (int, float)) and not isinstance(receiver[k], bool)
                                and math.isfinite(receiver[k]) and receiver[k] > 0
                                for k in ("bytes", "seconds", "bits_per_second")),
                            "a traffic direction has no positive receiver observation")
                    proc = value[role + "_process"]
                    require(proc["exit_code"] == 0 and not proc.get("timed_out"), "traffic process failed")
                    cpu = value["process_cpu_seconds"][role]
                    require(all(isinstance(cpu[k], (int, float)) and math.isfinite(cpu[k]) and cpu[k] >= 0
                                for k in ("user", "system", "maximum_sampled_rss_bytes")), "invalid CPU/RSS observation")
                    delta = value["path_delta"][role]
                    require(all(delta["link_delta"][d][k] > 0 for d in ("rx", "tx") for k in ("bytes", "packets")),
                            "missing real tunnel traffic counters")
                    if row["arms"][role].endswith("dco"):
                        peers = delta.get("kernel_peer_delta", {})
                        require(len(peers) == 1, "DCO kernel peer evidence is missing")
                        require(all(all(k in p and p[k] > 0 for k in (
                            "vpn_rx_bytes", "vpn_tx_bytes", "link_rx_bytes", "link_tx_bytes"))
                            for p in peers.values()),
                                "DCO peer byte counters did not increase")
                measurements += 1
        elif row["kind"] == "profile":
            values = case.get("measurements", [])
            require(len(values) == 1 and values[0].get("profile", {}).get("passed") is True,
                    "actual tunnel profile is missing")
            value = values[0]
            require(value.get("passed") is True and value.get("status") == "completed"
                    and value.get("failures") == [] and value.get("checks")
                    and all(v is True for v in value["checks"].values()),
                    "profile traffic measurement did not complete")
            profile = values[0]["profile"]
            require(profile.get("actual_samples_present") is True, "profile contains no samples")
            require(profile.get("actual_sample_headers", 0) > 0 and profile.get("kernel_symbol_lines", 0) > 0,
                    "profile lacks actual process/kernel sampling")
            if row["arms"]["client"] == "c-user":
                require(profile.get("openvpn_sample_headers_by_role", {}).get("client", 0) > 0,
                        "original C userspace process was not sampled")
            for name in ("report", "samples"):
                record = profile[name]
                path = beneath(target, record["stdout"])
                require(record["exit_code"] == 0 and digest(path) == record["stdout_sha256"],
                        "profile text is incomplete or changed")
    require(measurements == 216, "workload observation inventory is incomplete")

    checked_logs = 0
    for line in (target / "commands.jsonl").read_text().splitlines():
        entry = json.loads(line)
        if entry.get("event") == "finished":
            for stream in ("stdout", "stderr"):
                require(digest(beneath(target, entry[stream])) == entry[stream + "_sha256"],
                        "command output changed after execution")
            checked_logs += 1
    require(checked_logs > 0, "no executed command receipts")
    secret_pattern = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|"
                                rb"-----BEGIN OpenVPN Static key|\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}")
    for path in public.rglob("*"):
        if path.is_file():
            require(path.suffix not in (".key", ".p12", ".pfx") and ".perf.data" not in path.name,
                    "private key or raw stack artifact entered public output")
            require(not secret_pattern.search(path.read_bytes()), "secret-like material in public output")
    return {"cases_verified": len(cases), "workloads_verified": measurements,
            "command_logs_verified": checked_logs, "all_gates": report["gates"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    result = {"schema": "hepta.openvpn-hia.target-result-verification.v1", "passed": False,
              "expected_commit": args.commit, "scope": "fixed finite target experiment; no production qualification"}
    try:
        result.update(verify(args.public.resolve(), args.commit))
        result["passed"] = True
    except Exception as exc:
        result["failure"] = repr(exc)
    args.public.mkdir(parents=True, exist_ok=True)
    (args.public / "target-result-verification.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
