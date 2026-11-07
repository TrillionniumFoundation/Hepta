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
import encrypted_capture


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


def verify_profile_process_samples(profile, client_arm):
    """Require PID-attributed samples for every userspace profile arm."""
    if client_arm in ("c-user", "hia-user"):
        require(profile.get("openvpn_sample_headers_by_role", {}).get("client", 0) > 0,
                client_arm + " userspace process was not sampled")


def verify_hia_profile_hotspot(profile, report_text, client_arm):
    """Independently require both non-epoch HIA packet-ID symbols in the report."""
    if client_arm != "hia-user":
        return
    required = ("ovpn_hia_packet_id_read", "ovpn_hia_packet_id_write")
    found = set()
    for line in report_text.splitlines():
        if not re.search(r"\bopenvpn\b", line):
            continue
        for symbol in required:
            if re.search(r"\b" + re.escape(symbol) + r"\b", line):
                found.add(symbol)
    require(found == set(required),
            "HIA-user profile lacks both exported non-epoch packet-ID hotspots")
    require(profile.get("hia_profile_symbol_lines") == len(found),
            "stored HIA packet-ID symbol count differs from the perf report")


def verify_udp_delivery(value, workload, policy):
    """Independently recompute offered load, receiver goodput and loss from raw iperf receipts."""
    offered_match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMG])",
                                 str(workload.get("offered_rate_each_direction")))
    require(offered_match is not None, "unsupported UDP offered-rate syntax")
    scale = {"K": 1_000, "M": 1_000_000, "G": 1_000_000_000}[offered_match.group(2)]
    offered = float(offered_match.group(1)) * scale
    fraction = policy.get("minimum_offered_rate_fraction")
    max_loss = policy.get("maximum_receiver_loss_percent")
    require(isinstance(fraction, (int, float)) and not isinstance(fraction, bool)
            and math.isfinite(fraction) and 0 < fraction <= 1,
            "invalid minimum offered-rate fraction")
    require(isinstance(max_loss, (int, float)) and not isinstance(max_loss, bool)
            and math.isfinite(max_loss) and 0 <= max_loss <= 100,
            "invalid maximum UDP receiver loss")
    end = value.get("client_iperf", {}).get("end", {})
    senders = {
        "client_to_server": end.get("sum_sent"),
        "server_to_client": end.get("sum_sent_bidir_reverse"),
    }
    receivers = {
        "client_to_server": value.get("server_local_receiver"),
        "server_to_client": value.get("client_local_receiver"),
    }
    minimum = offered * fraction
    directions = {}
    for name in ("client_to_server", "server_to_client"):
        sender, receiver = senders[name], receivers[name]
        require(isinstance(sender, dict) and sender.get("sender") is True,
                name + " lacks an explicit sender receipt")
        require(isinstance(receiver, dict) and receiver.get("sender") is False,
                name + " lacks a local receiver receipt")
        sender_rate = sender.get("bits_per_second")
        receiver_rate = receiver.get("bits_per_second")
        loss = receiver.get("lost_percent")
        for label, number in (("sender rate", sender_rate), ("receiver rate", receiver_rate),
                              ("receiver loss", loss)):
            require(isinstance(number, (int, float)) and not isinstance(number, bool)
                    and math.isfinite(number), name + " has invalid " + label)
        require(sender_rate > 0 and receiver_rate > 0 and 0 <= loss <= 100,
                name + " has non-positive rate or out-of-range loss")
        directions[name] = {
            "sender_bps": sender_rate,
            "receiver_bps": receiver_rate,
            "lost_percent": loss,
        }
    checks = {
        "offered_rate_met": all(item["sender_bps"] >= minimum for item in directions.values()),
        "receiver_rate_met": all(item["receiver_bps"] >= minimum for item in directions.values()),
        "loss_within_limit": all(item["lost_percent"] <= max_loss for item in directions.values()),
    }
    recorded = value.get("udp_delivery")
    require(isinstance(recorded, dict) and recorded.get("passed") is True
            and recorded.get("failures") == [], "UDP acceptance receipt is missing or failed")
    require(recorded.get("offered_rate_bps") == offered
            and recorded.get("minimum_rate_bps") == minimum
            and recorded.get("minimum_offered_rate_fraction") == fraction
            and recorded.get("maximum_receiver_loss_percent") == max_loss,
            "UDP acceptance policy differs from the frozen plan")
    require(recorded.get("checks") == checks and recorded.get("directions") == directions,
            "UDP acceptance summary differs from raw iperf sender/receiver receipts")
    require(all(value.get("checks", {}).get("udp_" + name) is True
                for name in ("offered_rate_met", "receiver_rate_met", "loss_within_limit")),
            "UDP acceptance check is not closed")
    require(all(checks.values()), "UDP workload did not achieve its declared bidirectional load")



def verify_dco_rejection_delta(before, after):
    """Independently require the same DCO peer to receive link traffic but forward no VPN data."""
    for key in ("ifindex", "netns_inode", "family_id"):
        require(before.get(key) == after.get(key), "DCO peer scope changed: " + key)
    first = {row["peer_id"]: row for row in before.get("peers", [])}
    last = {row["peer_id"]: row for row in after.get("peers", [])}
    require(len(first) == 1 and set(first) == set(last),
            "DCO replay witness does not cover the same single peer")
    counters = ("vpn_rx_bytes", "vpn_tx_bytes", "vpn_rx_packets", "vpn_tx_packets",
                "link_rx_bytes", "link_tx_bytes", "link_rx_packets", "link_tx_packets")
    result = {}
    for peer_id, old in first.items():
        require(all(key in old and key in last[peer_id] for key in counters),
                "DCO replay witness omits a peer counter")
        delta = {key: last[peer_id][key] - old[key] for key in counters}
        require(all(isinstance(value, int) and not isinstance(value, bool) and value >= 0
                    for value in delta.values()), "DCO replay peer counter reset or malformed")
        require(delta["link_rx_packets"] > 0 and delta["link_rx_bytes"] > 0,
                "DCO peer did not account incoming encrypted link traffic")
        require(delta["vpn_rx_packets"] == 0 and delta["vpn_rx_bytes"] == 0,
                "DCO peer forwarded the injected packet into the VPN-facing path")
        result[str(peer_id)] = delta
    return result


def verify_frame_inspection_count(witness):
    """Bound AF_PACKET scan work; the count includes nonmatching frames before the exact hash match."""
    inspected = witness.get("frames_inspected")
    require(isinstance(inspected, int) and not isinstance(inspected, bool)
            and 1 <= inspected <= 1_000_000,
            "peer ingress frame scan count is outside the bounded helper budget")
    return inspected


def verify_exact_ciphertext_ingress(case_dir, action, injection, capture, capture_path, original_payload, helper_sha):
    """Verify raw submitted and peer-captured Ethernet frames, not just embedded hashes."""
    submission_dir = beneath(case_dir, action)
    witness_dir = beneath(case_dir, action + "-witness")
    submission_path = beneath(submission_dir, "result.json")
    witness_path = beneath(witness_dir, "result.json")
    submission = read(submission_path)
    witness = read(witness_path)
    require(injection.get("submission") == submission and injection.get("peer_exact_witness") == witness,
            "embedded encrypted injection receipt differs from raw helper output: " + action)
    require(submission.get("status") == "injection_submitted"
            and submission.get("helper_sha256") == helper_sha
            and witness.get("helper_sha256") == helper_sha,
            "encrypted capture/injection helper identity or status is invalid: " + action)
    require(submission.get("capture_metadata_sha256") == digest(capture_path)
            and submission.get("captured_ciphertext_sha256") == capture.get("ciphertext_sha256"),
            "injection is not bound to the previously delivered ciphertext: " + action)
    submitted_frame_path = beneath(submission_dir, "submitted-frame.bin")
    require(digest(submitted_frame_path) == submission.get("submitted_frame_sha256"),
            "submitted encrypted frame digest changed: " + action)
    submitted = encrypted_capture.parse_frame(submitted_frame_path.read_bytes())
    require(submitted is not None and submitted["opcode"] in (6, 9),
            "submitted frame is not a complete OpenVPN data datagram: " + action)
    submitted_payload = submitted["payload"]
    submitted_sha = hashlib.sha256(submitted_payload).hexdigest()
    require(submitted_sha == submission.get("submitted_ciphertext_sha256")
            and injection.get("expected_ciphertext_sha256") == submitted_sha,
            "submitted ciphertext digest differs from the raw datagram: " + action)
    mode = submission.get("mode")
    if mode == "replay":
        require(submitted_payload == original_payload,
                "replay injection is not byte-identical to the previously delivered ciphertext: " + action)
    elif mode == "flip":
        require(len(submitted_payload) == len(original_payload)
                and submitted_payload[:-1] == original_payload[:-1]
                and sum((a ^ b).bit_count() for a, b in zip(submitted_payload, original_payload)) == 1,
                "tag-corruption injection is not the declared one-bit ciphertext mutation: " + action)
    else:
        raise ValueError("unknown encrypted injection mode: " + action)
    witness_frame_name = witness.get("frame")
    require(witness_frame_name == "frame.bin", "peer witness frame path is not canonical: " + action)
    witness_frame_path = beneath(witness_dir, witness_frame_name)
    require(digest(witness_frame_path) == witness.get("frame_sha256"),
            "peer-ingress raw frame digest changed: " + action)
    arrived = encrypted_capture.parse_frame(witness_frame_path.read_bytes())
    verify_frame_inspection_count(witness)
    require(arrived is not None and arrived["payload"] == submitted_payload
            and witness.get("status") == "captured"
            and witness.get("direction") == "incoming"
            and witness.get("exact_ciphertext_match") is True
            and witness.get("ciphertext_sha256") == submitted_sha
            and witness.get("expected_ciphertext_sha256") == submitted_sha,
            "peer ingress did not capture the exact submitted ciphertext: " + action)
    require(all(encrypted_capture.checksum_observation(witness_frame_path.read_bytes()).get(key) is True
                for key in ("ipv4_valid", "udp_present", "udp_valid")),
            "peer ingress outer checksums are invalid: " + action)
    capture_state = witness.get("capture_state", {})
    require(capture_state.get("interface") == "ovpn-us"
            and capture_state.get("network_namespace_inode") != capture_state.get("pid1_network_namespace_inode"),
            "exact ciphertext witness was not captured on the isolated peer underlay: " + action)
    datagram = witness.get("datagram", {})
    require(datagram.get("src") == "192.0.2.2" and datagram.get("dst") == "192.0.2.1"
            and datagram.get("dport") == 1194,
            "peer witness datagram does not match the isolated OpenVPN underlay: " + action)
    submissions = submission.get("submissions", [])
    require(len(submissions) == 1 and isinstance(submissions[0].get("monotonic_ns"), int),
            "injection submission lacks one monotonic send receipt: " + action)
    submit_ns = submissions[0]["monotonic_ns"]
    arrival_ns = witness.get("monotonic_ns")
    observation_ns = injection.get("observation_finished_monotonic_ns")
    require(isinstance(arrival_ns, int) and arrival_ns >= submit_ns
            and isinstance(observation_ns, int) and observation_ns >= arrival_ns,
            "peer ingress and rejection observation are not ordered after submission: " + action)
    require(injection.get("old_receiver_alive_before_and_after_observation") is True,
            "old payload receiver was not live across the injection window: " + action)
    command_rows = (injection.get("injection_command", {}), injection.get("witness_command", {}))
    require(all(row.get("exit_code") == 0 and not row.get("timed_out") for row in command_rows),
            "encrypted injection/witness command failed: " + action)
    require(command_rows[0].get("label") == action + "-submit"
            and command_rows[1].get("label") == action + "-witness",
            "encrypted injection command identity changed: " + action)
    return {"mode": mode, "submit_monotonic_ns": submit_ns, "arrival_monotonic_ns": arrival_ns,
            "observation_finished_monotonic_ns": observation_ns}


def verify_behavior_replay_evidence(target, case_path, case, plan, server_arm):
    """Recompute exact ciphertext ingress, old-plaintext non-delivery and DCO per-injection counters."""
    case_dir = case_path.parent
    actions = plan["behavior"]["encrypted_actions"]
    injections = case.get("injections", [])
    require(len(injections) == len(actions), "encrypted injection inventory is incomplete")
    capture_dir = beneath(case_dir, "capture-old")
    capture_path = beneath(capture_dir, "result.json")
    capture = read(capture_path)
    capture_frame_path = beneath(capture_dir, "frame.bin")
    require(capture.get("status") == "captured"
            and digest(capture_frame_path) == capture.get("frame_sha256"),
            "original delivered ciphertext capture is missing or changed")
    original = encrypted_capture.parse_frame(capture_frame_path.read_bytes())
    require(original is not None and original["opcode"] in (6, 9) and original["payload_bytes"] >= 284,
            "original capture is not a complete OpenVPN data datagram")
    original_payload = original["payload"]
    original_sha = hashlib.sha256(original_payload).hexdigest()
    require(original_sha == capture.get("ciphertext_sha256"),
            "original capture ciphertext digest differs from its raw frame")
    helper_sha = digest(HERE / "encrypted_capture.py")
    initial_sender = case.get("initial_payload_sender", {})
    final = case.get("old_payload_final", {})
    sender = final.get("sender", {})
    receiver = final.get("receiver", {})
    expected_count = plan["behavior"]["strict_probe_count"]
    require(initial_sender.get("passed") is True and initial_sender.get("run_id") == sender.get("run_id"),
            "the original ciphertext was not first delivered in the same payload run")
    require(sender.get("passed") is True and receiver.get("passed") is True
            and sender.get("run_id") == receiver.get("run_id"),
            "old payload sender/receiver did not complete one shared run")
    require(sender.get("send_attempts") == expected_count
            and sender.get("sent_packets") == expected_count
            and sender.get("received_packets") == expected_count
            and sender.get("unique_echoes") == expected_count
            and sender.get("duplicate_echoes") == 0
            and sender.get("invalid_echoes") == 0
            and sender.get("missing_echo_count") == 0
            and sender.get("unexpected_peer_packets") == 0,
            "old payload sender did not retain a complete duplicate-free echo receipt")
    require(receiver.get("expected_count") == expected_count
            and receiver.get("received_packets") == expected_count
            and receiver.get("unique_packets") == expected_count
            and receiver.get("valid_packets") == expected_count
            and receiver.get("duplicate_packets") == 0
            and receiver.get("invalid_packets") == 0
            and receiver.get("foreign_run_packets") == 0
            and receiver.get("missing_count") == 0
            and receiver.get("unexpected_peer_packets") == 0
            and receiver.get("reordered_packets") == 0,
            "old payload receiver observed duplicate, corrupt, foreign, missing or reordered plaintext")
    receiver_events_path = beneath(case_dir / "old-payload-receiver", receiver.get("events", ""))
    sender_events_path = beneath(case_dir / "old-payload-sender", sender.get("events", ""))
    require(digest(receiver_events_path) == receiver.get("events_sha256")
            and digest(sender_events_path) == sender.get("events_sha256"),
            "old payload event logs changed after execution")
    receiver_events = [json.loads(line) for line in receiver_events_path.read_text().splitlines()]
    require(len(receiver_events) == receiver.get("event_count")
            and len(receiver_events) == expected_count + 1
            and receiver_events[0].get("kind") == "ready"
            and receiver_events[0].get("run_id") == receiver.get("run_id"),
            "old payload receiver event inventory is incomplete")
    payload_events = receiver_events[1:]
    require(all(row.get("kind") == "payload" and row.get("duplicate") is False
                and row.get("reordered") is False and row.get("bytes") == plan["behavior"]["strict_probe_size"]
                for row in payload_events),
            "old payload receiver recorded a duplicate or malformed payload event")
    require([row.get("sequence") for row in payload_events] == list(range(expected_count)),
            "old payload receiver sequence inventory is incomplete")
    first_injection_ns = None
    last_observation_ns = 0
    dco_windows = 0
    for action, injection in zip(actions, injections):
        expected_mode = "replay" if action.endswith("replay") else "flip"
        ingress = verify_exact_ciphertext_ingress(
            case_dir, action, injection, capture, capture_path, original_payload, helper_sha)
        require(ingress["mode"] == expected_mode,
                "encrypted injection mode differs from the fixed action: " + action)
        submit_ns = ingress["submit_monotonic_ns"]
        observation_ns = ingress["observation_finished_monotonic_ns"]
        first_injection_ns = submit_ns if first_injection_ns is None else min(first_injection_ns, submit_ns)
        last_observation_ns = max(last_observation_ns, observation_ns)
        if server_arm.endswith("dco"):
            dco = injection.get("dco_peer_rejection")
            require(isinstance(dco, dict) and dco.get("verified") is True
                    and dco.get("interface") == "tunbench-s",
                    "DCO behavior lacks per-injection kernel peer evidence: " + action)
            before_path = beneath(target, dco.get("before_path", ""))
            after_path = beneath(target, dco.get("after_path", ""))
            require(digest(before_path) == dco.get("before_sha256")
                    and digest(after_path) == dco.get("after_sha256"),
                    "DCO peer snapshot digest changed: " + action)
            before = read(before_path);after = read(after_path)
            initial_paths = read(beneath(case_dir, "initial-paths.json"))
            server_path = initial_paths.get("server", {})
            require(server_path.get("kind") == "tun" and server_path.get("ifname") == "tunbench-s"
                    and server_path.get("underlay", {}).get("ifname") == "ovpn-us"
                    and before.get("ifindex") == after.get("ifindex") == server_path.get("ifindex")
                    and before.get("netns_inode") == after.get("netns_inode") == server_path.get("netns_inode"),
                    "DCO peer snapshots do not bind the actual server tunbench-s device and ovpn-us underlay: " + action)
            for command in (dco.get("before_command", {}), dco.get("after_command", {})):
                argv = command.get("argv", [])
                require(command.get("exit_code") == 0 and not command.get("timed_out")
                        and command.get("namespace") == case.get("namespaces", {}).get("server")
                        and "--interface" in argv and "tunbench-s" in argv,
                        "DCO peer Netlink command identity/namespace is invalid: " + action)
            computed = verify_dco_rejection_delta(before, after)
            require(dco.get("delta") == computed,
                    "DCO peer counter delta differs from raw before/after snapshots: " + action)
            pause = dco.get("traffic_sender_pause")
            if action.startswith(("after-rekey", "after-reconnect")):
                require(isinstance(pause, dict), "DCO transition replay lacks an isolated traffic window: " + action)
                if pause.get("paused") is True:
                    require(pause.get("sender_label") == "continuity-sender"
                            and pause.get("stop_monotonic_ns", 0) < submit_ns
                            and pause.get("resume_monotonic_ns", 0) > observation_ns,
                            "DCO continuous sender was not paused around the exact injection: " + action)
                else:
                    require(pause.get("sender_finished_before") is True
                            and pause.get("sender_label") == "continuity-sender"
                            and pause.get("sender_exit_code") == 0
                            and pause.get("observed_finished_monotonic_ns", 0) < submit_ns,
                            "DCO transition replay has no isolated sender-free window: " + action)
            dco_windows += 1
        else:
            require(injection.get("dco_peer_rejection") is None,
                    "userspace server was assigned fabricated kernel DCO evidence: " + action)
            if action == "same-epoch-replay":
                counter = "replay_rejections"
                token = "bad packet ID (may be a replay)"
            elif action == "same-epoch-flip":
                counter = "tag_rejections"
                token = "packet tag authentication failed"
            else:
                counter = None;token = None
            if counter:
                require(injection.get("userspace_rejection_counter") == counter
                        and isinstance(injection.get("userspace_rejection_counter_before"), int)
                        and isinstance(injection.get("userspace_rejection_counter_after"), int)
                        and injection["userspace_rejection_counter_after"] >
                            injection["userspace_rejection_counter_before"]
                        and any(token in line for line in injection.get("server_log_observed_lines", [])),
                        "userspace exact replay/tag rejection log did not advance: " + action)
    require(all(event.get("monotonic_ns", 0) < first_injection_ns for event in payload_events),
            "old plaintext receiver observed a payload during or after an encrypted injection")
    require(receiver.get("finished_monotonic_ns", 0) > last_observation_ns,
            "old payload receiver did not cover every encrypted injection window")
    require(case.get("checks", {}).get("captured_previously_delivered_ciphertext") is True
            and case.get("checks", {}).get("old_receiver_alive_for_all_injections") is True
            and case.get("checks", {}).get("no_replayed_or_corrupted_payload_delivery") is True,
            "behavior case did not close the exact replay/non-delivery observations")
    return {"injections_verified": len(injections), "dco_peer_windows_verified": dco_windows,
            "old_payload_events_verified": len(payload_events)}



def verify_p2p_fair_dispatch_build(build):
    """Bind every target binary to the exact shared userspace dispatch patch."""
    lock = read(HERE / "source-lock.json")
    expected = lock.get("p2p_fair_dispatch")
    require(isinstance(expected, dict), "source lock lacks the P2P fairness patch")
    observed = build.get("p2p_fair_dispatch")
    require(isinstance(observed, dict) and observed.get("enabled") is True,
            "application build did not apply the P2P fairness patch")
    require(observed.get("patch_path") == expected.get("path")
            and observed.get("patch_sha256") == expected.get("sha256"),
            "application build used a different P2P fairness patch")
    require(observed.get("upstream_commit") == lock["openvpn"]["commit"]
            and observed.get("source_archive_sha256") == lock["openvpn"]["archive_sha256"],
            "P2P fairness patch is not bound to the pinned OpenVPN source")
    require(observed.get("policy") == expected.get("policy"),
            "P2P fairness policy differs from the frozen source lock")
    expected_files = set(expected.get("files", []))
    require(expected_files == {"src/openvpn/openvpn.h", "src/openvpn/forward.c"},
            "P2P fairness patch scope is not the two reviewed OpenVPN files")
    original = observed.get("original_files")
    patched = observed.get("patched_files")
    require(isinstance(original, dict) and set(original) == expected_files,
            "original P2P source hashes are incomplete")
    require(isinstance(patched, dict) and set(patched) == expected_files,
            "patched P2P source hashes are incomplete")
    for name in expected_files:
        require(re.fullmatch(r"[0-9a-f]{64}", str(original[name])) is not None
                and re.fullmatch(r"[0-9a-f]{64}", str(patched[name])) is not None,
                "P2P source hash is malformed: " + name)
        require(original[name] != patched[name],
                "P2P patch did not change its declared source file: " + name)
    require(observed.get("context_reset_verified") is True,
            "context-local fairness state is not proven to reset")
    require(observed.get("pending_write_priority_preserved") is True,
            "pending write priority is not preserved")
    require(observed.get("dco_read_branch_present") is True,
            "DCO read dispatch is absent")
    return observed


def verify_p2p_fair_dispatch(build, report, public):
    """Bind the target matrix receipt to the exact patch-bound build receipt."""
    observed = verify_p2p_fair_dispatch_build(build)
    inputs = report.get("inputs", {})
    require(inputs.get("build_receipt_sha256") == digest(public / "build.json"),
            "target matrix does not bind the public build receipt")
    require(inputs.get("p2p_fair_dispatch") == observed,
            "target matrix and build receipt disagree on P2P fairness patch identity")

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
    verify_p2p_fair_dispatch(build, report, public)
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
        if row["kind"] == "behavior":
            verify_behavior_replay_evidence(target, case_path, case, plan, row["arms"]["server"])
        elif row["kind"] == "performance":
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
                if workload.get("transport") == "udp":
                    verify_udp_delivery(value, workload, plan["performance"]["udp_acceptance"])
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
            verify_profile_process_samples(profile, row["arms"]["client"])
            report_text = None
            for name in ("report", "samples"):
                record = profile[name]
                path = beneath(target, record["stdout"])
                require(record["exit_code"] == 0 and digest(path) == record["stdout_sha256"],
                        "profile text is incomplete or changed")
                if name == "report":
                    report_text = path.read_text()
            verify_hia_profile_hotspot(profile, report_text, row["arms"]["client"])
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
