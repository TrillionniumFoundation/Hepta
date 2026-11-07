#!/usr/bin/env python3
"""Capture one real OpenVPN data datagram on an isolated lab veth and reinject it.

Linux AF_PACKET only. Run through `ip netns exec` inside this experiment's network
namespace. This helper refuses PID 1's network namespace and non-veth interfaces.
It never creates interfaces, modifies routes, decrypts traffic or selects keys.
Capture/injection success means socket operations succeeded; a receiving peer's
replay/authentication decision must be established from independent VPN, kernel
counter and application-payload evidence. An injected frame alone is not a test
pass. Both captured and submitted frames and their hashes remain in the output.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import ipaddress
import json
import math
import os
import re
import select
import socket
import struct
import subprocess
import time
from pathlib import Path

SCHEMA = "hepta.openvpn-hia.encrypted-datagram.v1"
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
PACKET_OUTGOING = 4
PACKET_HOST = 0
LAB_IPS = {"192.0.2.1", "192.0.2.2"}



def save_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def checksum(data):
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def parse_frame(frame: bytes):
    """Parse bounded, unfragmented Ethernet/IPv4/UDP without trusting checksums.

    AF_PACKET outgoing frames can carry unfinished checksum-offload fields. The
    reinjection routine recomputes IPv4/UDP checksums over the actual datagram.
    """
    if len(frame) < 14 + 20 or struct.unpack_from("!H", frame, 12)[0] != ETH_P_IP:
        return None
    off = 14
    version, ihl = frame[off] >> 4, (frame[off] & 15) * 4
    if version != 4 or ihl < 20 or len(frame) < off + ihl + 8:
        return None
    total = struct.unpack_from("!H", frame, off + 2)[0]
    fragment = struct.unpack_from("!H", frame, off + 6)[0]
    if total < ihl + 8 or off + total > len(frame) or fragment & 0x3fff or frame[off + 9] != 17:
        return None
    udp = off + ihl
    sport, dport, length, observed_checksum = struct.unpack_from("!HHHH", frame, udp)
    if length < 9 or length != total - ihl:
        return None
    payload = bytes(frame[udp + 8:udp + length])
    return {"src": socket.inet_ntoa(frame[off + 12:off + 16]),
            "dst": socket.inet_ntoa(frame[off + 16:off + 20]), "sport": sport, "dport": dport,
            "opcode": payload[0] >> 3, "key_id": payload[0] & 7,
            "peer_id": int.from_bytes(payload[1:4], "big")
            if payload[0] >> 3 == 9 and len(payload) >= 4 else None,
            "ip_header_bytes": ihl, "ip_total_bytes": total, "udp_offset": udp,
            "udp_bytes": length, "payload_bytes": len(payload), "payload": payload,
            "frame_bytes": off + total, "observed_udp_checksum": observed_checksum}


def matching(parsed, src, dst, dport, min_data_bytes, sport=None):
    return bool(parsed and parsed["src"] == src and parsed["dst"] == dst
                and parsed["dport"] == dport and (sport is None or parsed["sport"] == sport)
                and parsed["opcode"] in (6, 9) and parsed["payload_bytes"] >= min_data_bytes)


def checksum_observation(frame):
    parsed = parse_frame(frame)
    if parsed is None:
        return {"ipv4_valid": False, "udp_present": False, "udp_valid": False}
    udp = parsed["udp_offset"]
    pseudo = frame[26:34] + struct.pack("!BBH", 0, 17, parsed["udp_bytes"])
    return {"ipv4_valid": checksum(frame[14:14 + parsed["ip_header_bytes"]]) == 0,
            "udp_present": parsed["observed_udp_checksum"] != 0,
            "udp_valid": checksum(pseudo + frame[udp:udp + parsed["udp_bytes"]]) == 0}


def submitted_frame(frame, mode):
    parsed = parse_frame(frame)
    if parsed is None or parsed["opcode"] not in (6, 9):
        raise ValueError("capture does not contain a supported complete OpenVPN data datagram")
    data = bytearray(frame[:parsed["frame_bytes"]])
    udp = parsed["udp_offset"]
    if mode == "flip":
        data[udp + parsed["udp_bytes"] - 1] ^= 1
    elif mode != "replay":
        raise ValueError("unknown injection mode")
    # Never replay CHECKSUM_PARTIAL values observed before veth offload.
    struct.pack_into("!H", data, 14 + 10, 0)
    struct.pack_into("!H", data, 14 + 10, checksum(bytes(data[14:14 + parsed["ip_header_bytes"]])))
    struct.pack_into("!H", data, udp + 6, 0)
    pseudo = bytes(data[14 + 12:14 + 20]) + struct.pack("!BBH", 0, 17, parsed["udp_bytes"])
    value = checksum(pseudo + bytes(data[udp:udp + parsed["udp_bytes"]]))
    struct.pack_into("!H", data, udp + 6, value or 0xffff)
    return bytes(data)


def run_json(command, out, label, timeout=5):
    started = time.monotonic()
    expired = False
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout)
        stdout, stderr, code = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, code = exc.stdout or b"", exc.stderr or b"", 124
        expired = True
    except OSError as exc:
        stdout, stderr, code = b"", str(exc).encode(), 127
    (out / (label + ".stdout")).write_bytes(stdout)
    (out / (label + ".stderr")).write_bytes(stderr)
    save_json(out / (label + ".command.json"), {"argv": command, "exit_code": code,
              "timed_out": expired, "elapsed_seconds": time.monotonic() - started,
              "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)})
    if code:
        raise RuntimeError(f"{label} failed with exit {code}; partial raw output retained")
    return json.loads(stdout)


def preflight(interface, src, out):
    ns = os.stat("/proc/self/ns/net").st_ino
    initial_ns = os.stat("/proc/1/ns/net").st_ino
    if ns == initial_ns:
        raise RuntimeError("raw packet helper requires an isolated network namespace distinct from PID 1")
    links = run_json(["ip", "-details", "-statistics", "-json", "link", "show", "dev", interface], out, "link")
    if len(links) != 1 or links[0].get("linkinfo", {}).get("info_kind") != "veth":
        raise RuntimeError("raw packet helper only accepts the dedicated lab veth")
    addresses = run_json(["ip", "-json", "address", "show", "dev", interface], out, "address")
    if not any(a.get("local") == src for row in addresses for a in row.get("addr_info", [])):
        raise RuntimeError("source address is not assigned to the capture/injection veth")
    return {"network_namespace_inode": ns, "pid1_network_namespace_inode": initial_ns,
            "interface": interface, "ifindex": links[0]["ifindex"], "mac": links[0].get("address"),
            "link": links, "addresses": addresses}


def capture(args, out):
    incoming = args.action == "witness"
    state = preflight(args.interface, args.dst if incoming else args.src, out)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    inspected = 0
    try:
        sock.bind((args.interface, 0)); sock.setblocking(False)
        ready = {"schema": SCHEMA, "phase": "capture_ready", "utc": utc(),
                 "direction": "incoming" if incoming else "outgoing",
                 "expected_ciphertext_sha256": args.ciphertext_sha256 if incoming else None,
                 "monotonic_ns": time.monotonic_ns(), **state}
        save_json(out / "ready.json", ready)
        until = time.monotonic() + args.deadline
        while time.monotonic() < until:
            readable, _, _ = select.select([sock], [], [], min(0.1, max(0, until - time.monotonic())))
            if not readable:
                continue
            frame, addr = sock.recvfrom(65535 + 14)
            inspected += 1
            if inspected > 1_000_000:
                raise RuntimeError("capture frame budget exceeded")
            if addr[2] != (PACKET_HOST if incoming else PACKET_OUTGOING):
                continue
            parsed = parse_frame(frame)
            if not matching(parsed, args.src, args.dst, args.dport, args.min_data_bytes, args.sport):
                continue
            if incoming and sha(parsed["payload"]) != args.ciphertext_sha256:
                continue
            frame = frame[:parsed["frame_bytes"]]
            sums = checksum_observation(frame)
            if incoming and not all(sums.values()):
                (out / "invalid-checksum-frame.bin").write_bytes(frame)
                save_json(out / "invalid-checksum.json", sums)
                raise ValueError("matching incoming ciphertext has invalid IPv4/UDP outer checksums")
            (out / "frame.bin").write_bytes(frame)
            fields = {k: v for k, v in parsed.items() if k != "payload"}
            return {"schema": SCHEMA, "status": "captured", "utc": utc(),
                    "monotonic_ns": time.monotonic_ns(), "frame": "frame.bin", "frame_sha256": sha(frame),
                    "ciphertext_sha256": sha(parsed["payload"]), "datagram": fields,
                    "direction": "incoming" if incoming else "outgoing",
                    "expected_ciphertext_sha256": args.ciphertext_sha256 if incoming else None,
                    "exact_ciphertext_match": incoming,
                    "outer_checksums": sums,
                    "frames_inspected": inspected, "minimum_data_bytes": args.min_data_bytes,
                    "capture_state": state,
                    "claims": {"plaintext_identity_verified": False, "replay_rejection_verified": False,
                               "authentication_failure_verified": False, "tunnel_qualified": False}}
        raise TimeoutError("no matching " + ("incoming exact-ciphertext" if incoming else "outgoing")
                           + " OpenVPN data datagram before capture deadline")
    finally:
        sock.close()


def inject(args, out):
    captured = json.loads(args.capture.read_text())
    if captured.get("schema") != SCHEMA or captured.get("status") != "captured":
        raise ValueError("capture metadata is not a successful capture from this helper")
    if captured.get("direction") != "outgoing":
        raise ValueError("only the original outgoing capture can be used for injection")
    name = captured.get("frame")
    if name != "frame.bin":
        raise ValueError("unexpected capture frame path")
    frame = (args.capture.parent / name).read_bytes()
    if sha(frame) != captured.get("frame_sha256"):
        raise ValueError("capture frame hash changed")
    parsed = parse_frame(frame)
    if not parsed or sha(parsed["payload"]) != captured.get("ciphertext_sha256"):
        raise ValueError("capture datagram identity changed")
    if parsed["src"] not in LAB_IPS or parsed["dst"] not in LAB_IPS or parsed["src"] == parsed["dst"]:
        raise ValueError("capture endpoints are outside this isolated lab")
    state = preflight(args.interface, parsed["src"], out)
    prior = captured["capture_state"]
    if any(state[key] != prior.get(key) for key in ("network_namespace_inode", "interface", "ifindex", "mac")):
        raise ValueError("injection namespace/interface identity differs from the actual capture")
    data = submitted_frame(frame, args.mode)
    (out / "submitted-frame.bin").write_bytes(data)
    output_parsed = parse_frame(data)
    if args.mode == "replay" and output_parsed["payload"] != parsed["payload"]:
        raise AssertionError("exact replay changed the encrypted datagram")
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    submissions = []
    try:
        sock.bind((args.interface, 0)); sock.settimeout(2)
        for n in range(args.count):
            stamp, stamp_utc = time.monotonic_ns(), utc()
            sent = sock.send(data)
            submissions.append({"index": n, "monotonic_ns": stamp, "utc": stamp_utc, "submitted_bytes": sent})
            save_json(out / "submissions.json", submissions)
            if sent != len(data):
                raise OSError("short raw-frame send")
            if n + 1 < args.count:
                time.sleep(args.interval)
    finally:
        sock.close()
    return {"schema": SCHEMA, "status": "injection_submitted", "mode": args.mode,
            "capture_metadata_sha256": sha(args.capture.read_bytes()),
            "captured_ciphertext_sha256": captured["ciphertext_sha256"],
            "submitted_ciphertext_sha256": sha(output_parsed["payload"]),
            "submitted_frame_sha256": sha(data), "submissions": submissions,
            "injection_state": state,
            "claims": {"peer_received_verified": False, "replay_rejection_verified": False,
                       "authentication_failure_verified": False, "tunnel_qualified": False},
            "scope": "Raw-frame submission only; peer and payload evidence must decide acceptance."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("capture", "witness"):
        cap = sub.add_parser(action)
        cap.add_argument("--interface", required=True)
        cap.add_argument("--src", required=True, choices=sorted(LAB_IPS))
        cap.add_argument("--dst", required=True, choices=sorted(LAB_IPS))
        cap.add_argument("--dport", type=int, default=1194)
        cap.add_argument("--sport", type=int)
        cap.add_argument("--min-data-bytes", type=int, default=80,
                         help="exclude short encrypted keepalives; correlate plaintext separately")
        cap.add_argument("--deadline", type=float, default=20)
        cap.add_argument("--out", type=Path, required=True)
        if action == "witness":
            cap.add_argument("--ciphertext-sha256", required=True,
                             help="exact UDP payload digest of the expected replay/corrupted frame")
    inj = sub.add_parser("inject")
    inj.add_argument("--interface", required=True)
    inj.add_argument("--capture", type=Path, required=True, help="capture directory's result.json")
    inj.add_argument("--mode", choices=("replay", "flip"), required=True)
    inj.add_argument("--count", type=int, default=1)
    inj.add_argument("--interval", type=float, default=0.01)
    inj.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", args.interface):
        parser.error("invalid interface name")
    if args.action in ("capture", "witness"):
        if args.action == "witness":
            if not re.fullmatch(r"[a-fA-F0-9]{64}", args.ciphertext_sha256):
                parser.error("ciphertext-sha256 must be exactly 64 hexadecimal characters")
            args.ciphertext_sha256 = args.ciphertext_sha256.lower()
        if args.src == args.dst:
            parser.error("lab source and destination must differ")
        if not 1 <= args.dport <= 65535 or args.sport is not None and not 1 <= args.sport <= 65535:
            parser.error("UDP ports must be 1..65535")
        if not 80 <= args.min_data_bytes <= 65507:
            parser.error("min-data-bytes must be 80..65507")
        if not math.isfinite(args.deadline) or not 0 < args.deadline <= 120:
            parser.error("capture deadline must be finite and in (0,120]")
    elif not 1 <= args.count <= 16 or not math.isfinite(args.interval) or not 0 <= args.interval <= 1:
        parser.error("injection count must be 1..16 and interval finite in [0,1]")
    if args.out.exists() and any(args.out.iterdir()):
        parser.error("output must be new or empty; prior evidence is preserved")
    args.out.mkdir(parents=True, exist_ok=True)
    started = utc()
    try:
        result = capture(args, args.out) if args.action in ("capture", "witness") else inject(args, args.out)
        code = 0
    except Exception as exc:
        result = {"schema": SCHEMA, "status": "FAILED", "action": args.action,
                  "error": str(exc), "claims": {"tunnel_qualified": False}}
        code = 1
    result.update({"started_utc": started, "finished_utc": utc(), "helper_sha256": sha(Path(__file__).read_bytes())})
    save_json(args.out / "result.json", result)
    print(json.dumps(result, sort_keys=True), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
