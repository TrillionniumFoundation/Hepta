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
import signal
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
    source_port_override = submission.get("source_port_override")
    if source_port_override is None:
        require(submitted["sport"] == original["sport"],
                "non-reconnect injection changed the captured UDP source port: " + action)
    else:
        require(type(source_port_override) is int and 1 <= source_port_override <= 65535
                and submitted["sport"] == source_port_override,
                "submitted UDP source port differs from its explicit endpoint binding: " + action)
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
            and witness.get("expected_ciphertext_sha256") == submitted_sha
            and arrived["sport"] == submitted["sport"],
            "peer ingress did not capture the exact submitted ciphertext and UDP endpoint: " + action)
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
            "observation_finished_monotonic_ns": observation_ns,
            "source_port": submitted["sport"], "arrival_source_port": arrived["sport"]}


def verify_active_peer_endpoint(status_text, server_log, expected_ip="192.0.2.2",
                                 common_name="OpenVPN-HIA-client"):
    """Independently bind the current status peer to the latest authenticated server endpoint."""
    require(isinstance(status_text, str) and isinstance(server_log, str),
            "active peer status/log is not text")
    header = None
    rows = []
    for line in status_text.splitlines():
        fields = line.split("\t")
        if len(fields) >= 3 and fields[0] == "HEADER" and fields[1] == "CLIENT_LIST":
            header = fields[2:]
        elif fields and fields[0] == "CLIENT_LIST":
            require(header is not None and len(fields) - 1 == len(header),
                    "OpenVPN CLIENT_LIST row has no matching status header")
            row = dict(zip(header, fields[1:]))
            if row.get("Common Name") == common_name:
                rows.append(row)
    require(len(rows) == 1, "server status does not identify exactly one authenticated client")
    remote = rows[0].get("Real Address", "")
    match = re.fullmatch(r"udp4:([0-9.]+):([0-9]+)", remote)
    require(match is not None and match.group(1) == expected_ip,
            "server status authenticated peer endpoint is not the isolated UDP client")
    port = int(match.group(2))
    peer_id_text = rows[0].get("Peer ID", "")
    require(1 <= port <= 65535 and peer_id_text.isdecimal(),
            "server status authenticated peer port/ID is invalid")
    pattern = re.compile(
        r"udp4:" + re.escape(expected_ip) + r":([0-9]+) \[" + re.escape(common_name) +
        r"\] Peer Connection Initiated with \[AF_INET\]" + re.escape(expected_ip) + r":([0-9]+)")
    matches = [(line, pattern.search(line)) for line in server_log.splitlines()]
    matches = [(line, found) for line, found in matches if found]
    require(bool(matches), "server log lacks an authenticated peer initialization endpoint")
    peer_init_line, found = matches[-1]
    require(int(found.group(1)) == port and int(found.group(2)) == port,
            "server status endpoint differs from the latest authenticated peer")
    return {"remote_address": remote, "source_ip": expected_ip, "source_port": port,
            "peer_id": int(peer_id_text), "peer_init_line": peer_init_line}


def inclusive_ranges(values):
    ordered=sorted(set(values));out=[]
    for value in ordered:
        if not out or value>out[-1][1]+1:out.append([value,value])
        else:out[-1][1]=value
    return out


def verify_continuity_loss_evidence(case_dir, case, plan):
    """Independently retain every sequence/error while requiring the full receiver window."""
    result=case.get("continuity")
    require(isinstance(result,dict),"continuous payload receipt is missing")
    expected=plan["behavior"]["continuous_count"]
    sender=result.get("sender",{});receiver=result.get("receiver",{})
    run_id=result.get("run_id")
    require(run_id and sender.get("run_id")==run_id and receiver.get("run_id")==run_id,
            "continuity sender/receiver run identities differ")
    require(sender.get("expected_count")==expected and sender.get("send_attempts")==expected
            and sender.get("all_sends_attempted") is True,
            "continuity sender did not attempt the complete frozen inventory")
    require(sender.get("sent_packets",0)+sender.get("send_errors",0)==expected,
            "continuity sender omitted sent or errored sequence numbers")
    require(receiver.get("expected_count")==expected
            and receiver.get("received_packets",0)+receiver.get("missing_count",0)==expected,
            "continuity receiver omitted received or missing sequence numbers")
    require(sender.get("payload_size")==plan["behavior"]["strict_probe_size"]
            and receiver.get("payload_size")==plan["behavior"]["strict_probe_size"],
            "continuity payload size differs from the frozen plan")
    require(sender.get("deadline_reached") is False and receiver.get("deadline_reached") is True,
            "continuity sender/receiver did not finish their declared observation windows")
    require(sender.get("stop_signal") is None and receiver.get("stop_signal") is None,
            "continuity sender/receiver was externally stopped")
    require(result.get("sender_exit") in (0,1) and result.get("receiver_exit") in (0,1),
            "continuity process exit status is outside the retained-loss contract")
    require(result.get("sender_exit")== (0 if sender.get("passed") is True else 1)
            and result.get("receiver_exit")== (0 if receiver.get("passed") is True else 1),
            "continuity process exits disagree with their retained summaries")
    require(sender.get("received_packets")==sender.get("unique_echoes"),
            "continuity sender received/unique echo counters disagree")
    require(receiver.get("unique_packets")==receiver.get("received_packets")
            and receiver.get("valid_packets")==receiver.get("received_packets")
            and receiver.get("echoed_packets")==receiver.get("received_packets"),
            "continuity receiver valid/unique/echo counters disagree")
    require(sender.get("duplicate_echoes")==0 and sender.get("invalid_echoes")==0
            and sender.get("reordered_echoes")==0 and sender.get("unexpected_peer_packets")==0,
            "continuity sender observed duplicate, invalid, reordered or foreign echoes")
    require(receiver.get("duplicate_packets")==0 and receiver.get("invalid_packets")==0
            and receiver.get("reordered_packets")==0 and receiver.get("foreign_run_packets")==0
            and receiver.get("unexpected_peer_packets")==0 and receiver.get("echo_errors")==0,
            "continuity receiver observed duplicate, invalid, reordered or foreign payloads")

    sender_dir=case_dir/"continuity-sender";receiver_dir=case_dir/"continuity-receiver"
    sender_path=beneath(sender_dir,sender.get("events",""));receiver_path=beneath(receiver_dir,receiver.get("events",""))
    require(digest(sender_path)==sender.get("events_sha256")
            and digest(receiver_path)==receiver.get("events_sha256"),
            "continuity event stream digest changed")
    sender_events=[json.loads(line) for line in sender_path.read_text().splitlines()]
    receiver_events=[json.loads(line) for line in receiver_path.read_text().splitlines()]
    require(len(sender_events)==sender.get("event_count")
            and len(receiver_events)==receiver.get("event_count"),
            "continuity event count differs from its summary")
    require(sender_events and sender_events[0].get("kind")=="ready"
            and receiver_events and receiver_events[0].get("kind")=="ready",
            "continuity event stream lacks its ready record")
    expected_set=set(range(expected))
    require(sender_events[0].get("run_id")==run_id and receiver_events[0].get("run_id")==run_id,
            "continuity ready-record run identity changed")
    sent=[row.get("sequence") for row in sender_events if row.get("kind")=="sent"]
    errors=[row.get("sequence") for row in sender_events if row.get("kind")=="send_error"]
    echoes=[row.get("sequence") for row in sender_events if row.get("kind")=="echo"]
    payloads=[row.get("sequence") for row in receiver_events if row.get("kind")=="payload"]
    require(len(sent)==sender.get("sent_packets") and len(errors)==sender.get("send_errors")
            and len(echoes)==sender.get("unique_echoes"),
            "continuity sender event inventory differs from its summary")
    require(len(payloads)==receiver.get("received_packets") and len(receiver_events)==len(payloads)+1,
            "continuity receiver event inventory differs from its summary")
    require(all(len(values)==len(set(values)) for values in (sent,errors,echoes,payloads)),
            "continuity event stream contains duplicate sequence records")
    require(set(sent)|set(errors)==expected_set and not (set(sent)&set(errors)),
            "continuity sender events do not partition every attempted sequence")
    require(set(echoes).issubset(set(sent)) and set(payloads).issubset(set(sent)),
            "continuity echo/payload sequence lacks a successful send")
    missing_echo=expected_set-set(echoes);missing_payload=expected_set-set(payloads)
    require(sender.get("missing_echo_count")==len(missing_echo)
            and sender.get("missing_echo_ranges_inclusive")==inclusive_ranges(missing_echo),
            "continuity sender missing-echo ranges are not fully retained")
    require(receiver.get("missing_count")==len(missing_payload)
            and receiver.get("missing_ranges_inclusive")==inclusive_ranges(missing_payload),
            "continuity receiver missing-payload ranges are not fully retained")
    require(set(errors).issubset(missing_echo) and set(errors).issubset(missing_payload),
            "continuity send errors are not represented in both missing inventories")
    require(all(isinstance(row.get("error"),str) and row["error"]
                for row in sender_events if row.get("kind")=="send_error"),
            "continuity send error lacks its exact error text")
    require(all(row.get("bytes")==plan["behavior"]["strict_probe_size"]
                for row in sender_events if row.get("kind")=="sent"),
            "continuity sent payload size changed")
    require(all(row.get("duplicate") is False and row.get("reordered") is False
                for row in sender_events if row.get("kind")=="echo"),
            "continuity sender echo event is duplicate or reordered")
    require(all(row.get("duplicate") is False and row.get("reordered") is False
                and row.get("bytes")==plan["behavior"]["strict_probe_size"]
                for row in receiver_events if row.get("kind")=="payload"),
            "continuity receiver payload event is malformed")
    sender_clean=not missing_echo and not errors
    receiver_clean=not missing_payload
    require(sender.get("passed") is sender_clean and receiver.get("passed") is receiver_clean,
            "continuity pass flags disagree with the retained loss inventory")
    require(result.get("passed") is bool(sender_clean and receiver_clean
            and result.get("sender_exit")==0 and result.get("receiver_exit")==0),
            "continuity aggregate pass flag disagrees with its component receipts")
    require(case.get("checks",{}).get("continuity_all_losses_retained") is True,
            "behavior case did not retain its continuity losses/errors")
    return {"sender":sender,"receiver":receiver,"sender_exit":result["sender_exit"],
            "receiver_exit":result["receiver_exit"],"missing_echo_count":len(missing_echo),
            "missing_payload_count":len(missing_payload)}


def verify_behavior_replay_evidence(target, case_path, case, plan, server_arm):
    """Recompute exact ciphertext ingress, old-plaintext non-delivery and DCO per-injection counters."""
    case_dir = case_path.parent
    continuity=verify_continuity_loss_evidence(case_dir,case,plan)
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
        if action == "after-reconnect-replay":
            status_path = beneath(case_dir, "server.status")
            server_process = case.get("observations", {}).get("server", {}).get("process", {})
            server_log_path = beneath(target, server_process.get("stdout", ""))
            current_endpoint = verify_active_peer_endpoint(status_path.read_text(), server_log_path.read_text())
            require(injection.get("active_peer_endpoint") == current_endpoint,
                    "reconnect replay endpoint receipt differs from the authenticated server peer")
            require(ingress["source_port"] == current_endpoint["source_port"]
                    and ingress["arrival_source_port"] == current_endpoint["source_port"],
                    "reconnect replay did not arrive through the current authenticated UDP source port")
            submit_argv = injection.get("injection_command", {}).get("argv", [])
            witness_argv = injection.get("witness_command", {}).get("argv", [])
            require("--source-port" in submit_argv
                    and submit_argv[submit_argv.index("--source-port") + 1] == str(current_endpoint["source_port"])
                    and "--sport" in witness_argv
                    and witness_argv[witness_argv.index("--sport") + 1] == str(current_endpoint["source_port"]),
                    "reconnect replay command did not bind injection and witness to the active UDP port")
        else:
            require(injection.get("active_peer_endpoint") is None
                    and ingress["source_port"] == original["sport"]
                    and ingress["arrival_source_port"] == original["sport"],
                    "pre-reconnect injection changed its original UDP endpoint")
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
                            and pause.get("sender_timed_out") is False
                            and isinstance(pause.get("sender_signals"),list)
                            and pause.get("sender_exit_code") == continuity["sender_exit"]
                            and pause.get("sender_exit_code") in (0,1)
                            and pause.get("observed_finished_monotonic_ns", 0) < submit_ns,
                            "DCO transition replay has no isolated sender-free window: " + action)
                    stopped=False
                    for item in pause["sender_signals"]:
                        require(isinstance(item,dict),"DCO sender signal receipt is malformed: "+action)
                        signum=item.get("signal")
                        if signum==signal.SIGSTOP and not stopped:
                            stopped=True
                        elif signum==signal.SIGCONT and stopped:
                            stopped=False
                        else:
                            raise ValueError("DCO sender signal receipt has an unmatched or unexpected signal: "+action)
                    require(not stopped,"DCO sender remained stopped before injection: "+action)
                    if pause["sender_exit_code"] == 0:
                        require(continuity["sender"].get("passed") is True,
                                "clean DCO sender exit disagrees with continuity summary: " + action)
                    else:
                        require(continuity["sender"].get("passed") is False
                                and (continuity["sender"].get("send_errors",0)>0
                                     or continuity["sender"].get("missing_echo_count",0)>0),
                                "degraded DCO sender exit lacks retained loss/error evidence: " + action)
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



def verify_strict_payload_probe(case_dir, name, case, plan):
    value=case.get(name)
    require(isinstance(value,dict) and value.get("passed") is True,
            "fresh payload probe failed: "+name)
    expected=plan["behavior"]["strict_probe_count"]
    sender=value.get("sender",{});receiver=value.get("receiver",{})
    require(value.get("sender_exit")==0 and value.get("receiver_exit")==0
            and sender.get("passed") is True and receiver.get("passed") is True,
            "fresh payload sender/receiver did not exit cleanly: "+name)
    require(sender.get("send_attempts")==expected and sender.get("sent_packets")==expected
            and sender.get("received_packets")==expected and sender.get("unique_echoes")==expected
            and sender.get("missing_echo_count")==0 and sender.get("duplicate_echoes")==0
            and sender.get("invalid_echoes")==0 and sender.get("reordered_echoes")==0,
            "fresh payload sender did not deliver every sequence exactly once: "+name)
    require(receiver.get("expected_count")==expected and receiver.get("received_packets")==expected
            and receiver.get("unique_packets")==expected and receiver.get("valid_packets")==expected
            and receiver.get("missing_count")==0 and receiver.get("duplicate_packets")==0
            and receiver.get("invalid_packets")==0 and receiver.get("reordered_packets")==0,
            "fresh payload receiver did not deliver every sequence exactly once: "+name)
    deltas=value.get("path_delta",{})
    for role in ("client","server"):
        delta=deltas.get(role,{}).get("link_delta",{})
        require(all(delta.get(direction,{}).get(counter,0)>0
                    for direction in ("rx","tx") for counter in ("bytes","packets")),
                "fresh payload probe lacks bidirectional tunnel link counters: "+name+"/"+role)
        if case["arms"][role].endswith("dco"):
            peers=deltas.get(role,{}).get("kernel_peer_delta",{})
            require(len(peers)==1 and all(all(peer.get(key,0)>0 for key in
                    ("vpn_rx_bytes","vpn_tx_bytes","link_rx_bytes","link_tx_bytes"))
                    for peer in peers.values()),
                    "fresh payload probe lacks actual DCO peer counters: "+name+"/"+role)


def verify_rekey_log_cycles(case_dir, role, observation):
    stdout=case_dir/(role+"-openvpn.stdout");stderr=case_dir/(role+"-openvpn.stderr")
    text=(stdout.read_text(errors="replace") if stdout.is_file() else "")
    text+=(stderr.read_text(errors="replace") if stderr.is_file() else "")
    lines=text.splitlines()
    cycles=observation.get("rekey_cycles",[])
    require(type(observation.get("completed_rekeys")) is int
            and observation["completed_rekeys"]>=2 and len(cycles)==observation["completed_rekeys"],
            "completed rekey count lacks matching key-install cycles: "+role)
    for cycle in cycles:
        reset=cycle.get("reset_line")
        require(type(reset) is int and 1<=reset<=len(lines)
                and ("TLS: soft reset" in lines[reset-1] or "P_CONTROL_SOFT_RESET_V1" in lines[reset-1]),
                "rekey cycle does not point to a real reset event: "+role)
        if cycle.get("outgoing_key_line") is not None:
            tls=cycle.get("tls_line");out=cycle.get("outgoing_key_line");inc=cycle.get("incoming_key_line")
            require(all(type(v) is int and 1<=v<=len(lines) for v in (tls,out,inc)),
                    "userspace rekey cycle omits TLS or key-install line: "+role)
            require("Control Channel: TLS" in lines[tls-1]
                    and ("Outgoing Epoch Data key 1:" in lines[out-1] or "Outgoing Data Channel: Cipher" in lines[out-1])
                    and ("Incoming Epoch Data key 1:" in lines[inc-1] or "Incoming Data Channel: Cipher" in lines[inc-1])
                    and reset<tls<=out<=inc,
                    "userspace rekey TLS/key-install ordering is invalid: "+role)
        else:
            install=cycle.get("dco_install_line");swap=cycle.get("dco_swap_line")
            require(type(install) is int and type(swap) is int and 1<=install<swap<=len(lines),
                    "DCO rekey cycle omits ordered key install/swap lines: "+role)
            require("dco_install_key: peer_id=" in lines[install-1]
                    and "dco_swap_keys: peer-id " in lines[swap-1],
                    "DCO rekey cycle does not point to real kernel key events: "+role)
            promotion=cycle.get("dco_promotion_reset_line")
            if promotion is not None:
                require(type(promotion) is int and 1<=promotion<=len(lines)
                        and "P_CONTROL_SOFT_RESET_V1" in lines[promotion-1],
                        "DCO passive promotion is not bound to the next peer reset: "+role)
    return len(cycles)


def verify_behavior_lifecycle(case_dir, case, row, plan):
    require(case.get("negotiated_epoch") is row.get("epoch"),
            "behavior negotiated epoch mode differs from its frozen case")
    observations=case.get("observations",{})
    for role in ("client","server"):
        observation=observations.get(role,{})
        minimum_initializations=2 if role=="client" else 1
        require(observation.get("initializations",0)>=minimum_initializations
                and observation.get("peer_connections",0)>=2,
                "real OpenVPN session/reconnect lifecycle is incomplete: "+row["id"]+"/"+role)
        if role=="client":
            require(observation.get("hard_restarts",0)>=1,
                    "client did not complete the requested hard reconnect: "+row["id"])
        verify_rekey_log_cycles(case_dir,role,observation)
        latest=observation.get("latest_initialized_session",{})
        protocols=latest.get("protocol_lines",[]);data=latest.get("data_channel_lines",[])
        require(latest.get("initialization_line") and protocols and data
                and all("tls-ekm dyn-tls-crypt" in line for line in protocols)
                and all("AES-256-GCM" in line for line in data),
                "latest session did not retain the common authenticated wire profile: "+row["id"]+"/"+role)
        if row["epoch"]:
            require(all("aead-epoch" in line for line in protocols),
                    "epoch case lost its epoch protocol negotiation: "+row["id"]+"/"+role)
        else:
            require(all("aead-epoch" not in line for line in protocols),
                    "common profile unexpectedly negotiated aead-epoch: "+row["id"]+"/"+role)
        arm=row["arms"][role]
        if arm.startswith("hia"):
            trace=observation.get("hia_trace")
            require(isinstance(trace,dict) and trace.get("abi_failures")==0
                    and trace.get("read",0)>0 and trace.get("write",0)>0,
                    "HIA packet-ID entry trace is missing or has ABI failures: "+row["id"]+"/"+role)
            if row["epoch"]:
                require(trace.get("read_epoch",0)>0 and trace.get("write_epoch",0)>0,
                        "epoch HIA entrypoints were not exercised: "+row["id"]+"/"+role)
            else:
                require(trace.get("read_epoch")==0 and trace.get("write_epoch")==0,
                        "non-epoch common profile entered epoch HIA entrypoints: "+row["id"]+"/"+role)
    event_names=[event.get("name") for event in case.get("events",[])]
    require("completed-rekeys" in event_names and "SIGUSR1-requested" in event_names,
            "behavior receipt omits rekey or requested reconnect event: "+row["id"])
    verify_strict_payload_probe(case_dir,"post_rekey_payload",case,plan)
    verify_strict_payload_probe(case_dir,"post_reconnect_payload",case,plan)


def verify_untrusted_certificate_case(case_dir, case, plan, commands):
    checks=case.get("checks",{})
    require(checks and all(value is True for value in checks.values()),
            "untrusted certificate case checks are incomplete")
    observations=case.get("observations",{})
    client=observations.get("client",{});server=observations.get("server",{})
    errors=server.get("certificate_error_lines",[])
    require(any("VERIFY ERROR" in line and any(token in line for token in
                ("unable to get local issuer certificate","self-signed certificate","unable to verify the first certificate"))
                for line in errors),
            "server did not log an explicit untrusted-chain rejection")
    require(client.get("initializations")==0 and client.get("peer_connections")==0
            and server.get("initializations",0)>=1,
            "untrusted client initialized a VPN session or server was not ready")
    negative=case.get("negative_payload",{})
    sender=negative.get("sender",{});receiver=negative.get("receiver",{})
    expected=plan["behavior"]["negative_probe_count"]
    require(negative.get("run_id") and sender.get("run_id")==negative["run_id"]
            and receiver.get("run_id")==negative["run_id"],
            "negative payload sender/receiver run identities differ")
    require(sender.get("all_sends_attempted") is True and sender.get("send_attempts")==expected
            and sender.get("send_errors")==expected and sender.get("sent_packets")==0
            and sender.get("missing_echo_count")==expected and sender.get("duplicate_echoes")==0
            and sender.get("invalid_echoes")==0,
            "untrusted client did not retain all blocked payload attempts")
    require(receiver.get("expected_count")==expected and receiver.get("received_packets")==0
            and receiver.get("missing_count")==expected and receiver.get("duplicate_packets")==0
            and receiver.get("invalid_packets")==0 and receiver.get("foreign_run_packets")==0
            and receiver.get("deadline_reached") is True and receiver.get("stop_signal") is None,
            "untrusted client delivered plaintext or receiver window was incomplete")
    require(negative.get("sender_exit")==1 and negative.get("receiver_exit")==1
            and negative.get("passed") is False,
            "negative payload attempt was mislabeled as successful")
    addresses=case.get("negative_client_addresses",[])
    require(not any(item.get("local")=="10.77.0.2" for link in addresses
                    for item in link.get("addr_info",[])),
            "untrusted client acquired the VPN address")
    namespace=case.get("namespaces",{}).get("client")
    route=[row for row in commands if row.get("event")=="finished"
           and str(row.get("label","")).endswith("client-negative-route")]
    require(len(route)==1 and route[0].get("namespace")==namespace
            and route[0].get("exit_code")!=0 and not route[0].get("timed_out")
            and "route" in route[0].get("argv",[])
            and "10.77.0.1" in route[0].get("argv",[]),
            "untrusted client retained a plaintext route to the VPN destination")


def verify_security(public, expected_commit):
    build=read(public/"build.json");target=public/"tunnel";report=read(target/"target-result.json")
    verify_p2p_fair_dispatch(build,report,public)
    plan=read(HERE/"plan.json")
    require(build.get("ok") is True and build.get("hepta_commit")==expected_commit
            and build.get("expected_hepta_commit")==expected_commit,
            "security subset build belongs to another Hepta commit")
    require(report.get("schema")=="hepta.openvpn-hia.target-security.v1"
            and report.get("execution_mode")=="security-only"
            and report.get("selected_case_kinds")==["behavior","authentication"],
            "result is not the explicit behavior/certificate security subset")
    require(report.get("complete") is True and report.get("production_performance_qualified") is False
            and "security-only" in report.get("claim_limit",""),
            "security subset completion was broadened into full target/performance qualification")
    require(report.get("inputs",{}).get("hepta_commit")==expected_commit,
            "security subset belongs to another source commit")
    require(report.get("plan")==plan and report.get("plan_sha256")==digest(HERE/"plan.json"),
            "security subset did not use the frozen target plan")
    required_gates={"real_tun","dco_runtime","authentication","encrypted_replay","rekey","reconnect",
                    "profile","fixed_performance_matrix"}
    gates=report.get("gates",{})
    security_gates=("real_tun","dco_runtime","authentication","encrypted_replay","rekey","reconnect")
    require(set(gates)==required_gates and all(gates.get(name) is True for name in security_gates)
            and gates.get("profile") is False and gates.get("fixed_performance_matrix") is False,
            "security subset changed a profile/performance gate or left a security gate open")
    expected_counts={
        "planned_behavior_cases":7,"passed_behavior_cases":7,
        "planned_authentication_cases":2,"passed_authentication_cases":2,
        "planned_profile_cases":0,"passed_profile_cases":0,
        "planned_performance_cases":0,"passed_performance_cases":0,
        "planned_performance_workloads":0,"attempted_performance_workloads":0,
        "completed_performance_workloads":0,"failed_performance_workloads":0}
    require(report.get("counts")==expected_counts,"security subset inventory differs from its nine declared cases")
    require(report.get("cleanup",{}).get("passed") is True
            and report["cleanup"].get("private_work_removed") is True,
            "security subset namespace/private-work cleanup failed")
    require(report.get("preflight",{}).get("passed") is True
            and report["preflight"].get("blockers")==[],
            "security subset did not pass real TUN/DCO target preflight")
    host=report.get("host",{});allowed=host.get("allowed_cpus",[]);selected=host.get("selected_cpus",[])
    topology=host.get("cpu_topology",{})
    require(host.get("cpu_topology_error") is None and len(selected)==2
            and len(set(selected))==2 and all(cpu in allowed for cpu in selected),
            "security target did not bind two allowed physical CPU cores")
    core_keys=[]
    for cpu in selected:
        item=topology.get(str(cpu))
        require(isinstance(item,dict) and type(item.get("package_id")) is int
                and type(item.get("core_id")) is int,
                "security target CPU lacks physical core identity")
        core_keys.append((item["package_id"],item["core_id"]))
    require(len(set(core_keys))==2,"security target CPUs share a physical core")
    require(build.get("kernel",{}).get("release")==host.get("uname",{}).get("release")
            and build.get("tun_exists_after_provisioning") is True
            and build.get("loaded_module_file_sha256") and build.get("kernel_config_sha256"),
            "security build/kernel/TUN identity is incomplete")
    inputs=report.get("inputs",{})
    require(inputs.get("build_receipt_sha256")==digest(public/"build.json")
            and inputs.get("build_config_sha256")==build.get("link",{}).get("config_h_sha256")
            and inputs.get("official_source")==build.get("official_source_freeze"),
            "security target is not bound to its exact build/config/source receipt")
    require(build.get("source_lock_sha256")==digest(HERE/"source-lock.json"),
            "security build source lock differs from the checked-out source")
    for role,field in (("c","c_binary_sha256"),("hia","hia_binary_sha256"),("hia_trace","hia_trace_binary_sha256")):
        item=inputs.get("binaries",{}).get(role,{})
        require(item.get("sha256")==build.get("link",{}).get(field)
                and digest(item.get("path",""))==item.get("sha256"),
                "security target binary identity mismatch: "+role)
    scripts=inputs.get("scripts",{})
    require(set(scripts)=={item.name for item in HERE.glob("*.py")},
            "security target helper source inventory is incomplete")
    for filename,expected_sha in scripts.items():
        require(digest(beneath(HERE,filename))==expected_sha,
                "security target helper changed after execution: "+filename)

    expected_cases=[row for row in expected_cases_for_security(plan)]
    cases=report.get("cases",[])
    require(len(cases)==9 and len(cases)==len(expected_cases),
            "security subset did not execute exactly seven behavior and two authentication cases")
    total_injections=0;dco_windows=0;continuity_sequences=0;commands=[]
    command_path=target/"commands.jsonl"
    for line in command_path.read_text().splitlines():
        entry=json.loads(line)
        if entry.get("event")=="finished":
            for stream in ("stdout","stderr"):
                require(digest(beneath(target,entry[stream]))==entry[stream+"_sha256"],
                        "security command output changed after execution")
        commands.append(entry)
    for row,expected in zip(cases,expected_cases):
        require(all(row.get(key)==value for key,value in expected.items()),
                "security case identity/order differs from the frozen plan: "+expected["id"])
        require(row.get("status")=="completed" and row.get("passed") is True,
                "security case did not complete: "+expected["id"])
        case_path=beneath(target,row["receipt"]);case=read(case_path);case_dir=case_path.parent
        require(case.get("case")==row["id"] and case.get("status")=="completed"
                and case.get("passed") is True and case.get("arms")==row["arms"]
                and not case.get("cleanup_errors"),
                "security case receipt identity/verdict mismatch: "+expected["id"])
        require(case.get("checks") and all(value is True for value in case["checks"].values()),
                "security case checks are incomplete: "+expected["id"])
        expected_rekey=(plan["behavior"]["rekey_seconds_by_role"] if row["kind"]=="behavior"
                        else {"server":3600,"client":3600})
        require(case.get("reneg_seconds_by_role")==expected_rekey,
                "security case rekey schedule differs from the frozen plan: "+expected["id"])
        if row["kind"]=="behavior":
            replay=verify_behavior_replay_evidence(target,case_path,case,plan,row["arms"]["server"])
            lifecycle=verify_behavior_lifecycle(case_dir,case,row,plan)
            total_injections+=replay["injections_verified"]
            dco_windows+=replay["dco_peer_windows_verified"]
            continuity_sequences+=plan["behavior"]["continuous_count"]
        else:
            verify_untrusted_certificate_case(case_dir,case,plan,commands)
    require(total_injections==35 and dco_windows==15,
            "security subset lacks all 35 exact ciphertext injections or 15 DCO peer counter windows")
    secret_pattern=re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|"
                              rb"-----BEGIN OpenVPN Static key|\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}")
    for item in public.rglob("*"):
        if item.is_file():
            require(item.suffix not in (".key",".p12",".pfx") and ".perf.data" not in item.name,
                    "private key or raw stack artifact entered public security output")
            require(not secret_pattern.search(item.read_bytes()),
                    "secret-like material entered public security output")
    return {"cases_verified":9,"behavior_cases_verified":7,"authentication_cases_verified":2,
            "encrypted_injections_verified":total_injections,"dco_peer_windows_verified":dco_windows,
            "continuity_sequences_verified":continuity_sequences,"command_logs_verified":sum(
                1 for row in commands if row.get("event")=="finished"),"all_gates":report["gates"]}


def expected_cases_for_security(plan):
    return [row for row in expected_cases(plan) if row["kind"] in ("behavior","authentication")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--only-kind", choices=("security",),
                        help="verify only the predeclared seven behavior and two certificate cases")
    args = parser.parse_args()
    security_only=args.only_kind=="security"
    result = {"schema": "hepta.openvpn-hia.target-security-verification.v1" if security_only
              else "hepta.openvpn-hia.target-result-verification.v1", "passed": False,
              "expected_commit": args.commit,
              "scope": "security-only subset; no profile/performance qualification" if security_only
                       else "fixed finite target experiment; no production qualification"}
    try:
        result.update(verify_security(args.public.resolve(), args.commit) if security_only
                      else verify(args.public.resolve(), args.commit))
        result["passed"] = True
    except Exception as exc:
        result["failure"] = repr(exc)
    args.public.mkdir(parents=True, exist_ok=True)
    (args.public / "target-result-verification.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
