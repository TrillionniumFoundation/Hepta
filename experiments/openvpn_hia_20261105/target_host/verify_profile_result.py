#!/usr/bin/env python3
"""Independently verify the two real target-host profiles without claiming the full matrix."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re

import verify_result as source


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


def verify_profile_sampling(profile, plan_profile):
    expected = {
        "frequency_hz": plan_profile["frequency_hz"],
        "duration_seconds": plan_profile["seconds"],
        "call_graph": plan_profile["call_graph"],
    }
    require(profile.get("sampling") == expected,
            "actual perf sampling differs from the frozen profile plan")


def verify_profile_samples(profile, report_text, client_arm):
    """Require actual process/kernel samples and the exact HIA packet-ID hotspots."""
    require(profile.get("actual_samples_present") is True, "profile contains no actual perf samples")
    require(type(profile.get("actual_sample_headers")) is int
            and profile["actual_sample_headers"] > 0, "profile sample inventory is empty")
    require(type(profile.get("kernel_symbol_lines")) is int
            and profile["kernel_symbol_lines"] > 0, "profile contains no kernel symbols")
    source.verify_profile_process_samples(profile, client_arm)
    source.verify_hia_profile_hotspot(profile, report_text, client_arm)
    if client_arm == "hia-user":
        require(profile.get("hia_profile_symbol_lines") == 2,
                "HIA-user profile must contain both non-epoch packet-ID hotspots")
    elif client_arm == "c-dco":
        require(type(profile.get("ovpn_symbol_lines")) is int
                and profile["ovpn_symbol_lines"] > 0,
                "DCO profile contains no ovpn kernel symbols")
    else:
        raise ValueError("unexpected profile arm: " + str(client_arm))


def verify(public, expected_commit):
    build = read(public / "build.json")
    target = public / "tunnel"
    report = read(target / "target-result.json")
    plan = read(HERE / "plan.json")

    source.verify_p2p_fair_dispatch(build, report, public)
    require(build.get("ok") is True, "pinned C/HIA/DCO build did not complete")
    require(build.get("hepta_commit") == expected_commit
            and build.get("expected_hepta_commit") == expected_commit,
            "build belongs to another Hepta commit")
    require(report.get("schema") == "hepta.openvpn-hia.target-profile.v1",
            "unknown profile-only result schema")
    require(report.get("execution_mode") == "profile-only"
            and report.get("selected_case_kinds") == ["profile"],
            "result is not an explicitly isolated profile-only execution")
    require(report.get("complete") is True, "profile-only target did not complete")
    require(report.get("inputs", {}).get("hepta_commit") == expected_commit,
            "profile receipt belongs to another Hepta commit")
    require(report.get("plan") == plan
            and report.get("plan_sha256") == digest(HERE / "plan.json"),
            "profile execution did not use the frozen source plan")
    require(report.get("production_performance_qualified") is False,
            "profile-only evidence was broadened into performance qualification")
    require("profile-only" in report.get("claim_limit", ""),
            "profile-only scope is not explicit")
    require(not report.get("failure"), "profile controller failure remains in the result")

    required_gates = {"real_tun", "dco_runtime", "authentication", "encrypted_replay",
                      "rekey", "reconnect", "profile", "fixed_performance_matrix"}
    gates = report.get("gates", {})
    require(set(gates) == required_gates and gates.get("profile") is True
            and all(value is False for key, value in gates.items() if key != "profile"),
            "profile-only run changed or closed a non-profile acceptance gate")

    expected_counts = {
        "planned_behavior_cases": 0, "passed_behavior_cases": 0,
        "planned_authentication_cases": 0, "passed_authentication_cases": 0,
        "planned_profile_cases": 2, "passed_profile_cases": 2,
        "planned_performance_cases": 0, "passed_performance_cases": 0,
        "planned_performance_workloads": 0, "attempted_performance_workloads": 0,
        "completed_performance_workloads": 0, "failed_performance_workloads": 0,
    }
    require(report.get("counts") == expected_counts,
            "profile-only inventory contains unplanned behavior or performance work")

    host = report.get("host", {})
    allowed = host.get("allowed_cpus", [])
    selected = host.get("selected_cpus", [])
    topology = host.get("cpu_topology", {})
    require(host.get("cpu_topology_error") is None, "physical CPU topology is unavailable")
    require(len(selected) == 2 and len(set(selected)) == 2
            and all(cpu in allowed for cpu in selected),
            "two allowed physical-core CPUs were not selected")
    core_keys = []
    for cpu in selected:
        item = topology.get(str(cpu))
        require(isinstance(item, dict) and type(item.get("package_id")) is int
                and type(item.get("core_id")) is int,
                "selected CPU lacks a physical package/core identity")
        core_keys.append((item["package_id"], item["core_id"]))
    require(len(set(core_keys)) == 2
            and host.get("selected_physical_cores") == [list(key) for key in core_keys],
            "profile CPUs are not bound to two distinct physical cores")
    require(host.get("dedicated_physical_host") is False,
            "shared-host profile evidence must not be represented as a dedicated-host result")
    require(report.get("preflight", {}).get("passed") is True
            and report["preflight"].get("blockers") == [],
            "real TUN/ovpn/perf target preflight did not pass")
    require(build.get("kernel", {}).get("release") == host.get("uname", {}).get("release"),
            "build and profile target kernels differ")
    require(build.get("tun_exists_after_provisioning") is True,
            "build receipt did not observe the target TUN device")
    require(build.get("loaded_module_file_sha256")
            and build.get("kernel_config_sha256"),
            "kernel DCO module/configuration identity is missing")

    require(report.get("cleanup", {}).get("passed") is True
            and report["cleanup"].get("private_work_removed") is True,
            "namespace or private-work cleanup failed")

    inputs = report.get("inputs", {})
    require(inputs.get("build_receipt_sha256") == digest(public / "build.json"),
            "profile run is not bound to its exact build receipt")
    require(inputs.get("build_config_sha256") == build.get("link", {}).get("config_h_sha256"),
            "profile run and application build config differ")
    require(inputs.get("official_source") == build.get("official_source_freeze"),
            "profile run and pinned OpenVPN source freeze differ")
    require(inputs.get("perf", {}).get("sha256") == build.get("perf", {}).get("sha256"),
            "profile run used a different perf executable")
    require(build.get("source_lock_sha256") == digest(HERE / "source-lock.json"),
            "build source lock differs from the checked-out source")
    for role, field in (("c", "c_binary_sha256"), ("hia", "hia_binary_sha256"),
                        ("hia_trace", "hia_trace_binary_sha256")):
        item = inputs.get("binaries", {}).get(role, {})
        require(item.get("sha256") == build.get("link", {}).get(field)
                and digest(item.get("path", "")) == item.get("sha256"),
                "profile binary identity mismatch: " + role)

    scripts = inputs.get("scripts", {})
    require(set(scripts) == {path.name for path in HERE.glob("*.py")},
            "profile helper source inventory is incomplete")
    for filename, expected in scripts.items():
        require(digest(beneath(HERE, filename)) == expected,
                "executed profile helper changed: " + filename)

    expected_cases = [row for row in source.expected_cases(plan) if row["kind"] == "profile"]
    cases = report.get("cases", [])
    require(len(expected_cases) == 2 and len(cases) == 2,
            "profile-only run did not contain exactly two predeclared profile arms")
    profile_ids = []
    for row, expected in zip(cases, expected_cases):
        require(all(row.get(key) == value for key, value in expected.items()),
                "profile arm identity differs from the frozen plan")
        require(row.get("passed") is True and row.get("status") == "completed",
                "profile case did not complete: " + expected["id"])
        profile_ids.append(row["id"])
        case_path = beneath(target, row["receipt"])
        case = read(case_path)
        require(case.get("case") == row["id"] and case.get("passed") is True
                and case.get("status") == "completed",
                "profile case receipt identity/verdict mismatch")
        require(case.get("arms") == row["arms"] and case.get("trace") is False
                and case.get("reneg_seconds") == 3600
                and case.get("reneg_seconds_by_role") == {"server": 3600, "client": 3600},
                "profile run used an unexpected arm, trace or rekey schedule")
        require(case.get("checks") and all(value is True for value in case["checks"].values()),
                "profile case checks are incomplete")
        values = case.get("measurements", [])
        require(len(values) == 1, "profile case must retain exactly one measured workload")
        value = values[0]
        require(value.get("workload") == {"name": "tcp-profile", "transport": "tcp"}
                and value.get("duration_requested_seconds") == plan["profile"]["seconds"]
                and value.get("bidirectional") is True,
                "profile traffic workload differs from the frozen plan")
        require(value.get("passed") is True and value.get("status") == "completed"
                and value.get("failures") == [],
                "profile traffic or process failed")
        checks = value.get("checks", {})
        required_checks = {"actual_tunnel_and_kernel_counter_progress", "both_openvpn_cpu_receipts",
                           "client_process_succeeded", "server_process_succeeded",
                           "client_received_its_direction", "server_received_its_direction",
                           "same_authenticated_sessions", "actual_process_kernel_profile"}
        require(required_checks.issubset(checks) and all(checks[key] is True for key in required_checks),
                "profile workload lacks real tunnel/process/kernel evidence")

        expected_kinds = {"client": "tun" if row["arms"]["client"] == "hia-user" else "ovpn",
                          "server": "ovpn"}
        for role in ("client", "server"):
            process = value.get(role + "_process", {})
            require(process.get("exit_code") == 0 and not process.get("timed_out"),
                    role + " OpenVPN process failed during profile traffic")
            receiver = value.get(role + "_local_receiver", {})
            require(receiver.get("local_receiving_role") == role
                    and receiver.get("sender") is False
                    and all(isinstance(receiver.get(key), (int, float)) and not isinstance(receiver[key], bool)
                            and math.isfinite(receiver[key]) and receiver[key] > 0
                            for key in ("bytes", "seconds", "bits_per_second")),
                    role + " local bidirectional receiver receipt is incomplete")
            before = value.get("path_before", {}).get(role, {})
            after = value.get("path_after", {}).get(role, {})
            require(before.get("kind") == expected_kinds[role]
                    and after.get("kind") == expected_kinds[role]
                    and before.get("ifindex") == after.get("ifindex")
                    and before.get("netns_inode") == after.get("netns_inode"),
                    role + " actual TUN/ovpn identity changed or is missing")
            delta = value.get("path_delta", {}).get(role, {})
            require(all(delta.get("link_delta", {}).get(direction, {}).get(key, 0) > 0
                        for direction in ("rx", "tx") for key in ("bytes", "packets")),
                    role + " actual tunnel path did not carry bidirectional traffic")
        server_delta = value["path_delta"]["server"]
        peers = server_delta.get("kernel_peer_delta", {})
        require(len(peers) == 1 and all(
            all(peer.get(key, 0) > 0 for key in (
                "vpn_rx_bytes", "vpn_tx_bytes", "vpn_rx_packets", "vpn_tx_packets",
                "link_rx_bytes", "link_tx_bytes", "link_rx_packets", "link_tx_packets"))
            for peer in peers.values()), "kernel DCO peer counters did not progress")

        profile = value.get("profile", {})
        verify_profile_sampling(profile, plan["profile"])
        require(profile.get("raw_stack_file_published") is False,
                "raw DWARF/perf stack data must remain private")
        require(profile.get("record", {}).get("exit_code") == 0
                and not profile["record"].get("timed_out"),
                "perf recorder failed or timed out")
        report_text = None
        for name in ("report", "samples"):
            record = profile.get(name, {})
            require(record.get("exit_code") == 0,
                    "perf " + name + " command failed")
            output = beneath(target, record.get("stdout", ""))
            require(digest(output) == record.get("stdout_sha256"),
                    "perf " + name + " output hash changed")
            if name == "report":
                report_text = output.read_text()
        verify_profile_samples(profile, report_text or "", row["arms"]["client"])

    checked_logs = 0
    commands = target / "commands.jsonl"
    require(commands.is_file(), "profile command ledger is missing")
    for line in commands.read_text().splitlines():
        entry = json.loads(line)
        if entry.get("event") == "finished":
            for stream in ("stdout", "stderr"):
                require(digest(beneath(target, entry[stream])) == entry[stream + "_sha256"],
                        "profile command output changed after execution")
            checked_logs += 1
    require(checked_logs > 0, "no executed profile command receipts")

    secret_pattern = re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|"
        rb"-----BEGIN OpenVPN Static key|\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}"
    )
    for path in public.rglob("*"):
        if path.is_file():
            require(path.suffix not in (".key", ".p12", ".pfx") and ".perf.data" not in path.name,
                    "private key or raw stack artifact entered public output")
            require(not secret_pattern.search(path.read_bytes()),
                    "secret-like material entered public profile evidence")
    return {
        "profile_cases_verified": len(cases),
        "profile_arms": profile_ids,
        "profile_workloads_verified": len(cases),
        "command_logs_verified": checked_logs,
        "profile_gate": True,
        "full_matrix_executed": False,
        "production_performance_qualified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    result = {
        "schema": "hepta.openvpn-hia.profile-verification.v1",
        "passed": False,
        "expected_commit": args.commit,
        "scope": "two real target-host profiles only; no full matrix or production performance qualification",
    }
    try:
        result.update(verify(args.public.resolve(), args.commit))
        result["passed"] = True
    except Exception as exc:
        result["failure"] = repr(exc)
    args.public.mkdir(parents=True, exist_ok=True)
    (args.public / "profile-result-verification.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
