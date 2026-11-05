#!/usr/bin/env python3
"""Bounded UDP payload/echo evidence for an independently established VPN.

Each invocation has a unique 128-bit run ID and a finite, predeclared sequence.
This probe cannot independently assert authentication, a TUN path, or DCO use.
Receiver events are the authority for duplicate application delivery. Echo RTTs
use the sender's monotonic clock only; receiver timestamps are not one-way delay.
This is a correctness probe with per-packet evidence, not a throughput benchmark.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import select
import signal
import socket
import struct
import time
from pathlib import Path

MAGIC = b"OVPNHIA1"
HEADER = struct.Struct("!8s16sQQII")
MAX_COUNT = 1_000_000
MAX_SIZE = 65_507
SCHEMA = "hepta.openvpn-hia.payload-probe.v1"



def save_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def run_token(value: str) -> bytes:
    if len(value) != 32:
        raise argparse.ArgumentTypeError("run-id must contain exactly 32 hexadecimal characters")
    try:
        token = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("run-id must contain exactly 32 hexadecimal characters") from exc
    if len(token) != 16:
        raise argparse.ArgumentTypeError("run-id must contain exactly 32 hexadecimal characters")
    return token


def ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError("this probe requires an explicit IPv4 address") from exc


def packet(token: bytes, seq: int, sent_ns: int, count: int, size: int) -> bytes:
    head = HEADER.pack(MAGIC, token, seq, sent_ns, count, size)
    seed = hashlib.sha256(token + seq.to_bytes(8, "big")).digest()
    remaining = size - len(head)
    return head + (seed * ((remaining + len(seed) - 1) // len(seed)))[:remaining]


def decode(data: bytes, token: bytes, count: int, size: int):
    if len(data) < HEADER.size:
        return "short", None, None
    magic, observed, seq, sent_ns, declared_count, declared_size = HEADER.unpack_from(data)
    if magic != MAGIC:
        return "magic", None, None
    if observed != token:
        return "foreign_run", None, None
    if declared_count != count or declared_size != size or len(data) != size:
        return "shape", seq, sent_ns
    if seq >= count:
        return "sequence", seq, sent_ns
    if data != packet(token, seq, sent_ns, count, size):
        return "content", seq, sent_ns
    return None, seq, sent_ns


def missing_ranges(count: int, observed: set[int]):
    ranges = []
    first = None
    for seq in range(count):
        if seq not in observed and first is None:
            first = seq
        if seq in observed and first is not None:
            ranges.append([first, seq - 1]); first = None
    if first is not None:
        ranges.append([first, count - 1])
    return ranges


class Evidence:
    def __init__(self, out: Path, args):
        if out.exists() and any(out.iterdir()):
            raise ValueError("output must be a new or empty directory; prior evidence is never overwritten")
        out.mkdir(parents=True, exist_ok=True)
        self.out = out
        self.start_ns = time.monotonic_ns()
        self.events = (out / "events.jsonl").open("x", encoding="utf-8")
        self.event_count = 0
        self.stop_signal = None
        self.args = args

    def event(self, kind, **fields):
        self.events.write(json.dumps({"kind": kind, "monotonic_ns": time.monotonic_ns(), **fields}, sort_keys=True) + "\n")
        self.events.flush()
        self.event_count += 1

    def stopping(self, signum, frame):
        self.stop_signal = signum

    def ready(self, sock):
        data = {"schema": SCHEMA, "role": self.args.role, "run_id": self.args.run_id.hex(),
                "socket": list(sock.getsockname()), "pid": __import__("os").getpid(),
                "monotonic_ns": time.monotonic_ns(), "expected_count": self.args.count,
                "payload_size": self.args.size}
        save_json(self.out / "ready.json", data)
        self.event("ready", **data)

    def finish(self, result):
        self.events.close()
        result.update({"schema": SCHEMA, "role": self.args.role, "run_id": self.args.run_id.hex(),
                       "expected_count": self.args.count, "payload_size": self.args.size,
                       "expected_payload_bytes": self.args.count * self.args.size,
                       "started_monotonic_ns": self.start_ns, "finished_monotonic_ns": time.monotonic_ns(),
                       "stop_signal": self.stop_signal, "events": "events.jsonl", "event_count": self.event_count,
                       "events_sha256": hashlib.sha256((self.out / "events.jsonl").read_bytes()).hexdigest(),
                       "claims": {"tunnel_path_verified": False, "authentication_verified": False,
                                  "dco_verified": False, "throughput_benchmark": False}})
        if self.stop_signal:
            result["passed"] = False
        save_json(self.out / "summary.json", result)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0 if result.get("passed") else 1


def receiver(args, evidence):
    observed = set()
    counters = {"received_packets": 0, "valid_packets": 0, "unique_packets": 0,
                "duplicate_packets": 0, "reordered_packets": 0, "invalid_packets": 0,
                "foreign_run_packets": 0, "unexpected_peer_packets": 0,
                "received_bytes": 0, "unique_payload_bytes": 0, "echoed_packets": 0,
                "echo_errors": 0}
    highest = -1
    reason_counts = {}
    result = {"passed": False}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        sock.bind((args.bind, args.port)); sock.setblocking(False)
        evidence.ready(sock)
        until = time.monotonic() + args.deadline
        while not evidence.stop_signal and time.monotonic() < until:
            ready, _, _ = select.select([sock], [], [], min(0.1, max(0, until - time.monotonic())))
            if not ready:
                continue
            data, addr = sock.recvfrom(MAX_SIZE + 1)
            counters["received_packets"] += 1; counters["received_bytes"] += len(data)
            if counters["received_packets"] > args.count * 4 + 1024:
                raise RuntimeError("bounded receive-event budget exceeded")
            reason, seq, sent_ns = decode(data, args.run_id, args.count, args.size)
            if args.peer is not None and addr[0] != args.peer:
                counters["unexpected_peer_packets"] += 1; reason = "peer"
            if reason:
                counters["invalid_packets"] += 1
                counters["foreign_run_packets"] += int(reason == "foreign_run")
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
                evidence.event("rejected_payload", reason=reason, sequence=seq, peer=list(addr),
                               bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                continue
            duplicate = seq in observed
            reordered = not duplicate and seq < highest
            counters["valid_packets"] += 1
            counters["duplicate_packets"] += int(duplicate)
            counters["reordered_packets"] += int(reordered)
            if not duplicate:
                observed.add(seq); counters["unique_packets"] += 1
                counters["unique_payload_bytes"] += len(data)
            highest = max(highest, seq)
            evidence.event("payload", sequence=seq, duplicate=duplicate, reordered=reordered,
                           peer=list(addr), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
            try:
                n = sock.sendto(data, addr)
                if n != len(data):
                    raise OSError("short UDP echo send")
                counters["echoed_packets"] += 1
            except OSError as exc:
                counters["echo_errors"] += 1; evidence.event("echo_error", sequence=seq, error=str(exc))
        result["deadline_reached"] = not evidence.stop_signal
    except Exception as exc:
        result["failure"] = str(exc); evidence.event("failure", error=str(exc))
    finally:
        sock.close()
    missing = missing_ranges(args.count, observed)
    result.update(counters)
    result.update({"missing_count": args.count - len(observed), "missing_ranges_inclusive": missing,
                   "invalid_reasons": reason_counts,
                   "passed": not result.get("failure") and not evidence.stop_signal
                             and len(observed) == args.count and counters["duplicate_packets"] == 0
                             and counters["invalid_packets"] == 0 and counters["echo_errors"] == 0})
    return result


def sender(args, evidence):
    sent = {}
    echoed = set()
    counters = {"send_attempts": 0, "sent_packets": 0, "sent_payload_bytes": 0, "send_errors": 0,
                "received_packets": 0, "received_bytes": 0, "unique_echoes": 0,
                "duplicate_echoes": 0, "reordered_echoes": 0, "invalid_echoes": 0,
                "unexpected_peer_packets": 0}
    highest = -1
    rtts = []
    result = {"passed": False}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        sock.bind((args.bind, args.bind_port)); sock.setblocking(False)
        evidence.ready(sock)
        start = time.monotonic(); seq = 0
        budget = args.deadline if args.deadline is not None else max(5.0, args.count * args.interval + args.drain + 2.0)
        until = start + budget
        finish_sending = None
        while not evidence.stop_signal and time.monotonic() < until:
            now = time.monotonic()
            if seq < args.count and now >= start + seq * args.interval:
                stamp = time.monotonic_ns()
                data = packet(args.run_id, seq, stamp, args.count, args.size)
                counters["send_attempts"] += 1
                try:
                    n = sock.sendto(data, (args.peer, args.port))
                    if n != len(data):
                        raise OSError("short UDP send")
                    sent[seq] = stamp
                    counters["sent_packets"] += 1; counters["sent_payload_bytes"] += n
                    evidence.event("sent", sequence=seq, bytes=n, sender_monotonic_ns=stamp,
                                   schedule_delay_seconds=now - (start + seq * args.interval),
                                   sha256=hashlib.sha256(data).hexdigest())
                except OSError as exc:
                    counters["send_errors"] += 1; evidence.event("send_error", sequence=seq, error=str(exc))
                seq += 1
                if seq == args.count:
                    finish_sending = time.monotonic()
            if finish_sending is not None and time.monotonic() >= finish_sending + args.drain:
                break
            next_send = start + seq * args.interval if seq < args.count else until
            wait = min(0.05, max(0, next_send - time.monotonic()), max(0, until - time.monotonic()))
            ready, _, _ = select.select([sock], [], [], wait)
            if not ready:
                continue
            data, addr = sock.recvfrom(MAX_SIZE + 1)
            counters["received_packets"] += 1; counters["received_bytes"] += len(data)
            if counters["received_packets"] > args.count * 4 + 1024:
                raise RuntimeError("bounded echo-event budget exceeded")
            reason, echoed_seq, stamp = decode(data, args.run_id, args.count, args.size)
            if addr != (args.peer, args.port):
                counters["unexpected_peer_packets"] += 1; reason = "peer"
            if reason is None and (echoed_seq not in sent or stamp != sent[echoed_seq]):
                reason = "not_sent"
            if reason:
                counters["invalid_echoes"] += 1
                evidence.event("rejected_echo", reason=reason, sequence=echoed_seq, peer=list(addr),
                               bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                continue
            duplicate = echoed_seq in echoed
            reordered = not duplicate and echoed_seq < highest
            counters["duplicate_echoes"] += int(duplicate)
            counters["reordered_echoes"] += int(reordered)
            rtt = (time.monotonic_ns() - stamp) / 1e9
            if not duplicate:
                echoed.add(echoed_seq); counters["unique_echoes"] += 1; rtts.append(rtt)
            highest = max(highest, echoed_seq)
            evidence.event("echo", sequence=echoed_seq, duplicate=duplicate, reordered=reordered,
                           rtt_seconds=rtt, peer=list(addr), bytes=len(data))
        result["all_sends_attempted"] = seq == args.count
        result["deadline_reached"] = time.monotonic() >= until
    except Exception as exc:
        result["failure"] = str(exc); evidence.event("failure", error=str(exc))
    finally:
        sock.close()
    result.update(counters)
    result.update({"missing_echo_count": args.count - len(echoed),
                   "missing_echo_ranges_inclusive": missing_ranges(args.count, echoed),
                   "passed": not result.get("failure") and not evidence.stop_signal
                             and counters["sent_packets"] == args.count and len(echoed) == args.count
                             and counters["duplicate_echoes"] == 0 and counters["invalid_echoes"] == 0,
                   "rtt_seconds": {"minimum": min(rtts) if rtts else None,
                                   "maximum": max(rtts) if rtts else None,
                                   "mean": sum(rtts) / len(rtts) if rtts else None},
                   "late_echo_note": "Receiver evidence may reveal deliveries after this sender's finite drain period."})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="role", required=True)
    for name in ("receiver", "sender"):
        p = sub.add_parser(name)
        p.add_argument("--bind", type=ipv4, required=True)
        p.add_argument("--peer", type=ipv4, required=name == "sender")
        p.add_argument("--port", type=int, required=True)
        p.add_argument("--out", type=Path, required=True)
        p.add_argument("--run-id", type=run_token, required=True)
        p.add_argument("--count", type=int, required=True)
        p.add_argument("--size", type=int, default=256)
        p.add_argument("--deadline", type=float, required=name == "receiver")
        if name == "sender":
            p.add_argument("--interval", type=float, default=0.01)
            p.add_argument("--drain", type=float, default=2.0)
            p.add_argument("--bind-port", type=int, default=0)
    args = parser.parse_args(argv)
    if not 1 <= args.count <= MAX_COUNT:
        parser.error("count must be 1..1,000,000")
    if not HEADER.size <= args.size <= MAX_SIZE:
        parser.error(f"size must be {HEADER.size}..{MAX_SIZE}")
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    if args.deadline is not None and (not math.isfinite(args.deadline) or not 0 < args.deadline <= 3600):
        parser.error("deadline must be finite and in (0, 3600]")
    if args.role == "sender":
        if not math.isfinite(args.interval) or not 0 <= args.interval <= 10:
            parser.error("interval must be finite and in [0, 10]")
        if not math.isfinite(args.drain) or not 0 < args.drain <= 60:
            parser.error("drain must be finite and in (0, 60]")
        if not 0 <= args.bind_port <= 65535:
            parser.error("bind-port must be 0..65535")
        if args.deadline is None and args.count * args.interval + args.drain + 2 > 3600:
            parser.error("implicit send budget exceeds one hour; specify an explicit finite deadline")
    evidence = Evidence(args.out, args)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, evidence.stopping)
    result = receiver(args, evidence) if args.role == "receiver" else sender(args, evidence)
    return evidence.finish(result)


if __name__ == "__main__":
    raise SystemExit(main())
