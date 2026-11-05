#!/usr/bin/env python3
"""Freeze official OpenVPN and exercise real executables without claiming a tunnel.

The self-test and --dev null control session are explicitly separate from TUN
and DCO acceptance. This tool never changes routes, loads modules or escalates.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import socket
import subprocess
import tarfile
import time

OPENVPN_VERSION = "2.7.8"
OPENVPN_COMMIT = "dc1f569087135894ac2703aeabd7a960ee9452d4"
OPENVPN_TAG = "7cf7ae23c051533d42aff2e4fa265d779d422cf1"
OPENVPN_ARCHIVE_SHA256 = "c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def run(command, out, name, timeout=60, cwd=None, env=None):
    started = time.perf_counter()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with (out / (name + ".log")).open("wb") as stream:
        proc = subprocess.Popen([str(x) for x in command], stdout=stream, stderr=subprocess.STDOUT,
                                cwd=cwd, env=env, start_new_session=True)
        expired = False
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
            os.killpg(proc.pid, signal.SIGKILL)
            code = proc.wait()
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"argv": [str(x) for x in command], "cwd": str(cwd) if cwd else None,
            "exit_code": code, "timed_out": expired,
            "wall_seconds": time.perf_counter() - started,
            "children_user_seconds": after.ru_utime - before.ru_utime,
            "children_system_seconds": after.ru_stime - before.ru_stime,
            "log": name + ".log", "log_sha256": sha(out / (name + ".log"))}


def host_probe():
    data = {"kernel": platform.release(), "machine": platform.machine(),
            "platform": platform.platform(), "tun_exists": Path("/dev/net/tun").exists(),
            "dco_modules_visible": {x: Path("/sys/module", x).exists()
                                    for x in ("ovpn", "ovpn_dco", "ovpn_dco_v2")}}
    status = Path("/proc/self/status").read_text()
    data["process_security"] = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                                for line in status.splitlines()
                                if line.startswith(("Cap", "Seccomp"))}
    capabilities = int(data["process_security"]["CapEff"], 16)
    data["cap_net_admin"] = bool(capabilities & (1 << 12))
    data["loopback_sockets"] = {}
    for kind, label in ((socket.SOCK_DGRAM, "udp"), (socket.SOCK_STREAM, "tcp")):
        try:
            with socket.socket(socket.AF_INET, kind) as s:
                s.bind(("127.0.0.1", 0))
                data["loopback_sockets"][label] = {"created_and_bound": True}
        except OSError as e:
            data["loopback_sockets"][label] = {"created_and_bound": False, "errno": e.errno, "error": str(e)}
    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)
        os.close(fd)
        data["tun_open"] = {"opened": True}
    except OSError as e:
        data["tun_open"] = {"opened": False, "errno": e.errno, "error": str(e)}
    return data


def source_freeze(source, archive):
    """Verify every regular file against the release archive before execution.

    The archive hash is the fixed trust anchor. Merely hashing a caller-selected
    source tree does not identify it as the official commit.
    """
    archive_hash = sha(archive)
    if archive_hash != OPENVPN_ARCHIVE_SHA256:
        raise ValueError("official release archive SHA256 mismatch")
    expected = {}
    prefix = "openvpn-" + OPENVPN_VERSION + "/"
    with tarfile.open(archive, "r:gz") as tar:
        for item in tar:
            if not item.isfile():
                continue
            if not item.name.startswith(prefix):
                raise ValueError("unexpected release archive member: " + item.name)
            relative = item.name[len(prefix):]
            if not relative or ".." in Path(relative).parts:
                raise ValueError("invalid release archive member")
            expected[relative] = hashlib.sha256(tar.extractfile(item).read()).hexdigest()
    mismatches = [name for name, digest in expected.items()
                  if not (source / name).is_file() or sha(source / name) != digest]
    if mismatches:
        raise ValueError("official source closure mismatch: " + ", ".join(mismatches))
    manifest = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
    files = ("src/openvpn/packet_id.c", "src/openvpn/packet_id.h", "src/openvpn/buffer.h",
             "configure", "version.m4", "COPYING")
    return {"version": OPENVPN_VERSION, "commit": OPENVPN_COMMIT, "tag_object": OPENVPN_TAG,
            "release_api": "https://api.github.com/repos/OpenVPN/openvpn/releases/latest",
            "release_published_at": "2026-10-07T14:18:17Z",
            "release_url": "https://github.com/OpenVPN/openvpn/releases/tag/v2.7.8",
            "archive_url": "https://github.com/OpenVPN/openvpn/releases/download/v2.7.8/openvpn-2.7.8.tar.gz",
            "archive_sha256": archive_hash, "archive_verified": True,
            "source_closure_files_verified": len(expected),
            "source_closure_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "source_hashes": {name: expected[name] for name in files}}


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def certificates(out):
    secret = out / "ephemeral-pki"
    secret.mkdir(mode=0o700, exist_ok=True)
    commands = []
    commands.append(run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                         "-keyout", secret / "ca.key", "-out", secret / "ca.crt", "-days", "2",
                         "-subj", "/CN=OpenVPN-HIA-Local-Test-CA"], out, "pki-ca"))
    for name, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        ext = secret / (name + ".ext")
        ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=" + usage + "\n")
        commands.append(run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", secret / (name + ".key"),
                             "-out", secret / (name + ".csr"), "-subj", "/CN=OpenVPN-HIA-" + name], out, "pki-" + name))
        commands.append(run(["openssl", "x509", "-req", "-in", secret / (name + ".csr"), "-CA", secret / "ca.crt",
                             "-CAkey", secret / "ca.key", "-CAcreateserial", "-out", secret / (name + ".crt"),
                             "-days", "2", "-extfile", ext], out, "pki-sign-" + name))
    commands.append(run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                         "-keyout", secret / "rogue-ca.key", "-out", secret / "rogue-ca.crt", "-days", "2",
                         "-subj", "/CN=OpenVPN-HIA-Untrusted-CA"], out, "pki-rogue-ca"))
    for key in secret.glob("*.key"):
        key.chmod(0o600)
    if any(row["exit_code"] for row in commands):
        raise RuntimeError("test certificate creation failed; inspect retained PKI command logs")
    return secret, commands


def trace_observation(text):
    entries = re.findall(r"OPENVPN_HIA_CALLS read=(\d+) write=(\d+) read_epoch=(\d+) write_epoch=(\d+) abi_failures=(\d+)", text)
    names = ("read", "write", "read_epoch", "write_epoch", "abi_failures")
    return {"present": bool(entries), "counts": dict(zip(names, map(int, entries[-1]))) if entries else None}


def observe_control(text):
    """Check ordered successful handshake/key-install evidence, not reset counts."""
    lines = text.splitlines()
    reset_positions = [i for i, line in enumerate(lines) if "TLS: soft reset" in line]
    signal_positions = [i for i, line in enumerate(lines) if "SIGUSR1[hard," in line]
    initialized = [i for i, line in enumerate(lines) if "Initialization Sequence Completed" in line]
    # A server can receive the reconnecting peer without a local SIGUSR1. Do
    # not attribute that new session's handshake/key setup to an older reset.
    new_session_positions = [i for i, line in enumerate(lines)
                             if ("TLS: Initial packet" in line
                                 or "initial untrusted session promoted to trusted" in line
                                 or "Initialization Sequence Completed" in line)]
    completed = []
    for pos in reset_positions:
        limit = min([i for i in reset_positions + signal_positions + new_session_positions if i > pos] + [len(lines)])
        fragment = lines[pos:limit]
        # These lines are emitted only after a successful TLS negotiation and
        # data-channel key setup. A soft reset alone is not a successful rekey.
        required = ("Control Channel: TLS", "Outgoing Epoch Data key 1:", "Incoming Epoch Data key 1:")
        indices = [[pos + j + 1 for j, line in enumerate(fragment) if token in line]
                   for token in required]
        if all(indices) and indices[0][0] < indices[1][0] <= indices[2][0]:
            completed.append({"soft_reset_line": pos + 1, "tls_channel_line": indices[0][0],
                              "outgoing_key_line": indices[1][0], "incoming_key_line": indices[2][0]})
    return {"initialization_completed": len(initialized),
            "initialization_lines": [i + 1 for i in initialized],
            "peer_connections": text.count("Peer Connection Initiated"),
            "tls_soft_resets": len(reset_positions),
            "rekey_cycles_completed": len(completed), "rekey_evidence": completed,
            "reconnect_completed_after_signal": bool(signal_positions and any(i > signal_positions[0] for i in initialized)),
            "identity_rejections": text.count("VERIFY X509NAME ERROR"),
            "certificate_chain_rejections": len(re.findall(r"VERIFY ERROR: depth=\d+, error=(?:self-signed certificate|unable to get local issuer certificate)", text)),
            "verification_errors": len(re.findall(r"VERIFY (?:X509NAME |)ERROR", text)),
            "tls_error_lines": [i + 1 for i, line in enumerate(lines) if "TLS Error:" in line],
            "hia_calls": re.findall(r"OPENVPN_HIA_CALLS[^\n]+", text)}


def control_session(server, client, out, pki, name, negative=None, reconnect=True):
    """Use actual OpenVPN --dev null endpoints; no TUN/IP traffic is implied."""
    sp, cp = free_udp_port(), free_udp_port()
    while cp == sp:
        cp = free_udp_port()
    common = ["--dev", "null", "--disable-dco", "--proto", "udp", "--local", "127.0.0.1",
              "--ifconfig-noexec", "--route-noexec", "--verb", "4",
              "--data-ciphers", "AES-256-GCM", "--cipher", "AES-256-GCM",
              "--reneg-sec", "3", "--reneg-bytes", "0", "--reneg-pkts", "0",
              "--ping", "1", "--hand-window", "6", "--tls-timeout", "1"]
    server_args = [server, *common, "--ca", pki / "ca.crt", "--tls-server", "--dh", "none",
                   "--lport", str(sp), "--rport", str(cp), "--remote", "127.0.0.1",
                   "--cert", pki / "server.crt", "--key", pki / "server.key"]
    client_args = [client, *common, "--ca", pki / ("rogue-ca.crt" if negative == "ca" else "ca.crt"),
                   "--tls-client", "--lport", str(cp), "--rport", str(sp), "--remote", "127.0.0.1",
                   "--cert", pki / "client.crt", "--key", pki / "client.key",
                   "--remote-cert-tls", "server", "--verify-x509-name",
                   "wrong-hostname" if negative == "name" else "OpenVPN-HIA-server", "name"]
    procs, streams = [], []
    started = time.perf_counter()
    reconnect_sent = False
    alive_before_cleanup = []
    try:
        for suffix, command in (("server", server_args), ("client", client_args)):
            f = (out / (name + "-" + suffix + ".log")).open("wb")
            streams.append(f)
            procs.append(subprocess.Popen(list(map(str, command)), stdout=f, stderr=subprocess.STDOUT, start_new_session=True))
        duration = 8 if negative else 17
        while time.perf_counter() - started < duration and any(p.poll() is None for p in procs):
            if reconnect and negative is None and not reconnect_sent and time.perf_counter() - started >= 10:
                if procs[1].poll() is None:
                    procs[1].send_signal(signal.SIGUSR1)
                    reconnect_sent = True
            time.sleep(0.05)
        alive_before_cleanup = [p.poll() is None for p in procs]
    finally:
        for p in procs:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
        for f in streams:
            f.close()
    observations = {}
    for suffix in ("server", "client"):
        path = out / (name + "-" + suffix + ".log")
        observations[suffix] = {"log": path.name, "sha256": sha(path),
                                **observe_control(path.read_text(errors="replace"))}
    healthy = all(alive_before_cleanup) and all(p.returncode == 0 for p in procs)
    if negative:
        rejection_field = "identity_rejections" if negative == "name" else "certificate_chain_rejections"
        checks = {"both_processes_survived_probe": healthy,
                  "expected_authentication_rejected": observations["client"][rejection_field] > 0,
                  "neither_peer_established": all(x["initialization_completed"] == 0 for x in observations.values())}
    else:
        checks = {"both_processes_survived_probe": healthy,
                  "both_peers_established": all(x["initialization_completed"] >= 1 for x in observations.values()),
                  "both_peers_rekeyed_with_tls_and_keys": all(x["rekey_cycles_completed"] >= 1 for x in observations.values()),
                  "client_reconnected_after_signal": reconnect_sent and observations["client"]["reconnect_completed_after_signal"],
                  "no_certificate_errors": all(x["verification_errors"] == 0 for x in observations.values())}
    return {"scope": "actual-OpenVPN-loopback-dev-null-control-and-encrypted-ping", "not_a_tun_tunnel": True,
            "authentication_negative": negative, "reconnect_signal_sent": reconnect_sent,
            "duration_seconds": time.perf_counter() - started, "server_argv": list(map(str, server_args)),
            "client_argv": list(map(str, client_args)), "exit_codes": [p.returncode for p in procs],
            "observations": observations, "checks": checks, "passed": all(checks.values())}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--c-binary", type=Path, required=True)
    p.add_argument("--hia-binary", type=Path)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--control", action="store_true")
    p.add_argument("--require-hia-trace", action="store_true", help="require diagnostic entry counters; never use trace binaries for timings")
    args = p.parse_args()
    if args.out.exists() and any(args.out.iterdir()):
        p.error("output must be a new empty directory so earlier failures cannot be overwritten")
    args.out.mkdir(parents=True, exist_ok=True)
    evidence = {"schema": "hepta.openvpn-hia.official-application.v1", "authority": "RESEARCH_ONLY",
                "runner_sha256": sha(Path(__file__)), "hia_trace_required": args.require_hia_trace,
                "source": source_freeze(args.source, args.archive), "host": host_probe(), "commands": [], "binaries": {},
                "real_tun_tunnel_passed": False, "dco_runtime_passed": False,
                "fair_tunnel_performance_qualified": False, "control_sessions": []}
    for label, binary in (("c", args.c_binary), ("hia", args.hia_binary)):
        if binary is None:
            continue
        binary = binary.resolve()
        evidence["binaries"][label] = {"path": str(binary), "sha256": sha(binary)}
        evidence["commands"].append(run([binary, "--version"], args.out, label + "-version"))
        evidence["commands"].append(run(["ldd", binary], args.out, label + "-ldd"))
        for cipher in ("AES-256-GCM", "AES-256-CBC", "CHACHA20-POLY1305"):
            name = label + "-crypto-" + cipher.lower()
            row = run([binary, "--test-crypto", "--cipher", cipher], args.out, name)
            text = (args.out / row["log"]).read_text(errors="replace")
            row["selftest_succeeded"] = row["exit_code"] == 0 and "crypto self-test mode SUCCEEDED" in text
            row["packet_lengths_tested"] = [int(x) for x in re.findall(r"TESTING ENCRYPT/DECRYPT of packet length=(\d+)", text)]
            row["hia_calls"] = re.findall(r"OPENVPN_HIA_CALLS[^\n]+", text)
            row["hia_trace"] = trace_observation(text)
            if label == "hia" and args.require_hia_trace:
                trace = row["hia_trace"]
                row["hia_trace_passed"] = bool(trace["present"] and trace["counts"]["abi_failures"] == 0
                                               and sum(trace["counts"].values()) > 0)
                row["selftest_succeeded"] = row["selftest_succeeded"] and row["hia_trace_passed"]
            evidence["commands"].append(row)
    if args.control:
        pki, commands = certificates(args.out)
        evidence["commands"].extend(commands)
        for server_label, client_label in (("c", "c"), ("c", "hia"), ("hia", "c")):
            if server_label not in evidence["binaries"] or client_label not in evidence["binaries"]:
                continue
            server = evidence["binaries"][server_label]["path"]
            client = evidence["binaries"][client_label]["path"]
            name = "control-" + server_label + "-" + client_label
            evidence["control_sessions"].append(control_session(server, client, args.out, pki, name))
            evidence["control_sessions"].append(control_session(server, client, args.out, pki, name + "-bad-name", "name", False))
            evidence["control_sessions"].append(control_session(server, client, args.out, pki, name + "-bad-ca", "ca", False))
    if args.require_hia_trace:
        if args.hia_binary is None:
            p.error("--require-hia-trace requires --hia-binary")
        for session in evidence["control_sessions"]:
            for role in ("server", "client"):
                if session[role + "_argv"][0] != str(args.hia_binary.resolve()):
                    continue
                record = session["observations"][role]
                trace = trace_observation((args.out / record["log"]).read_text(errors="replace"))
                record["hia_trace"] = trace
                success = bool(trace["present"] and trace["counts"]["abi_failures"] == 0)
                if session["authentication_negative"] is None:
                    success = success and all(trace["counts"][key] > 0 for key in ("read", "write", "read_epoch", "write_epoch"))
                session["checks"][role + "_hia_entry_trace"] = success
                session["passed"] = all(session["checks"].values())
    (args.out / "baseline.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"output": str(args.out), "selftests": [r.get("selftest_succeeded") for r in evidence["commands"]
                     if "selftest_succeeded" in r], "control_sessions": [r["passed"] for r in evidence["control_sessions"]],
                      "real_tun_tunnel_passed": False, "dco_runtime_passed": False}))
    return 0 if (all(r.get("selftest_succeeded", r["exit_code"] == 0) for r in evidence["commands"])
                 and all(r["passed"] for r in evidence["control_sessions"])) else 1

if __name__ == "__main__":
    raise SystemExit(main())
