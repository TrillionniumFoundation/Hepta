#!/usr/bin/env python3
"""One diagnostic real-TUN/DCO smoke trial in an already isolated namespace.

Requires a provisioned peer, real OpenVPN binary/config and iperf3. Never creates
namespaces, grants privileges, loads modules or supplies a fake TUN. The target
interface must not exist before this process launches OpenVPN. The same new
ifindex, assigned source address, source-specific route and positive link counter
deltas must survive the trial. DCO additionally requires complete before/after
peer counters emitted by the frozen official dco_linux.c netlink reply handler.

Verbosity 6 obtains those diagnostic counters; these are NOT no-trace performance
measurements. One smoke trial never qualifies authentication-negative, replay,
reconnect, rekey or fair performance gates. --preflight-only cannot pass a tunnel.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

PEER_FIELDS = ("dco_read_bytes", "dco_write_bytes", "tun_read_bytes", "tun_write_bytes")
PEER_START = re.compile(r"ovpn_handle_peer: parsing message for peer (\d+)\.\.\.")
PEER_VALUE = re.compile(r"dco_update_peer_stat / (dco_read_bytes|dco_write_bytes|tun_read_bytes|tun_write_bytes): (\d+)")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def netns_inode(pid="self"):
    return os.stat(f"/proc/{pid}/ns/net").st_ino


def preflight(mode):
    status = Path("/proc/self/status").read_text()
    caps = int(re.search(r"^CapEff:\s*(\w+)", status, re.M).group(1), 16)
    config = gzip.decompress(Path("/proc/config.gz").read_bytes()).decode() if Path("/proc/config.gz").exists() else ""
    flags = {key: next((line for line in config.splitlines() if line.startswith(key + "=")
                       or line == "# " + key + " is not set"), None)
             for key in ("CONFIG_TUN", "CONFIG_OVPN", "CONFIG_NET_NS")}
    blockers = []
    if not caps & (1 << 12):
        blockers.append("CAP_NET_ADMIN is absent")
    if mode == "userspace" and not Path("/dev/net/tun").exists():
        blockers.append("/dev/net/tun is absent")
    if mode == "dco" and flags["CONFIG_OVPN"] == "# CONFIG_OVPN is not set" and not Path("/sys/module/ovpn").exists():
        blockers.append("running kernel CONFIG_OVPN is disabled and no ovpn module is loaded")
    current_namespace = netns_inode()
    initial_namespace = None
    namespace_error = None
    try:
        initial_namespace = netns_inode(1)
        isolated = current_namespace != initial_namespace
    except OSError as exc:
        isolated = None
        namespace_error = str(exc)
        blockers.append("cannot verify separation from PID 1 network namespace: " + str(exc))
    if isolated is False:
        blockers.append("actual trial requires a dedicated network namespace distinct from PID 1")
    for tool in ("ip", "iperf3"):
        if not shutil.which(tool):
            blockers.append(tool + " is unavailable")
    return {"mode": mode, "cap_eff": hex(caps), "tun_exists": Path("/dev/net/tun").exists(),
            "network_namespace_inode": current_namespace, "pid1_network_namespace_inode": initial_namespace,
            "namespace_probe_error": namespace_error,
            "isolated_network_namespace": isolated, "kernel_flags": flags,
            "kernel_config_sha256": hashlib.sha256(config.encode()).hexdigest() if config else None,
            "blockers": blockers, "available": not blockers}


def peer_snapshots(text):
    """Parse actual official 2.7.8 peer-id + four-field netlink log records.

    A partial group, repeated field, or a counter without its immediately
    preceding peer header cannot provide a complete snapshot. Records include
    line positions so receipt consumers can audit the full unmodified log.
    """
    snapshots = []
    pending = None
    for number, line in enumerate(text.splitlines(), 1):
        start = PEER_START.search(line)
        if start:
            pending = {"peer_id": int(start.group(1)), "counters": {}, "start_line": number}
            continue
        value = PEER_VALUE.search(line)
        if value:
            if pending is None:
                continue
            name, count = value.groups()
            if name in pending["counters"]:
                pending = None
                continue
            pending["counters"][name] = int(count)
            if set(pending["counters"]) == set(PEER_FIELDS):
                pending["end_line"] = number
                snapshots.append(pending)
                pending = None
        elif "dco_update_peer_stat:" in line or "SIGUSR1" in line or "Initialization Sequence Completed" in line:
            pending = None
    return snapshots


def positive_delta(before, after, fields):
    result = {}
    for field in fields:
        first, last = before.get(field), after.get(field)
        if type(first) is not int or type(last) is not int:
            raise RuntimeError(f"missing integer counter: {field}")
        if first < 0 or last <= first:
            raise RuntimeError(f"counter did not strictly increase: {field}: {first} -> {last}")
        result[field] = last - first
    return result



def peer_interval(before, after, text):
    if before["peer_id"] != after["peer_id"]:
        raise RuntimeError("DCO peer identity changed during the smoke trial")
    if re.search(r"dco_new_peer:|dco_del_peer:|CMD_PEER_DEL_NTF|dco_update_peer_stat: no|no peer-id provided in PEER_GET", text):
        raise RuntimeError("peer replacement or incomplete DCO netlink counters occurred during traffic")
    previous = before["counters"]
    for row in [*peer_snapshots(text), after]:
        if row["peer_id"] != before["peer_id"]:
            raise RuntimeError("additional DCO peer appeared during the single-peer trial")
        current = row["counters"]
        if any(current[field] < previous[field] for field in PEER_FIELDS):
            raise RuntimeError("DCO counter reset detected during traffic")
        previous = current
    return positive_delta(before["counters"], after["counters"], PEER_FIELDS)


def link_bytes(link):
    stats = link.get("stats64") or link.get("stats")
    if not isinstance(stats, dict):
        raise RuntimeError("actual ip -statistics link counters are missing")
    return {"rx_bytes": stats.get("rx", {}).get("bytes"), "tx_bytes": stats.get("tx", {}).get("bytes"),
            "rx_packets": stats.get("rx", {}).get("packets"), "tx_packets": stats.get("tx", {}).get("packets")}



def signal_group(proc, signum):
    if proc.poll() is not None:
        return False
    try:
        os.killpg(proc.pid, signum)
        return True
    except ProcessLookupError:
        # The child can finish between poll and killpg. Reap its real status.
        proc.poll()
        return False


def cleanup_process(proc, timeout=5):
    row = {"alive_before_cleanup": proc.poll() is None, "forced_kill": False}
    try:
        if proc.poll() is None:
            if signal_group(proc, signal.SIGTERM):
                row["signal_sent"] = "SIGTERM"
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row["forced_kill"] = signal_group(proc, signal.SIGKILL)
                proc.wait(timeout=3)
    except Exception as exc:
        # Cleanup failure must not suppress the diagnostic receipt.
        row["cleanup_error"] = str(exc)
    row["exit_code"] = proc.poll()
    return row


def run_record(command, out, name, commands, timeout=5):
    """Real subprocess with streamed evidence, bounded process-group cleanup."""
    started = time.monotonic()
    row = {"argv": command, "stdout": name + ".stdout", "stderr": name + ".stderr", "timed_out": False}
    commands.append(row)
    proc = None
    with (out / row["stdout"]).open("xb") as stdout, (out / row["stderr"]).open("xb") as stderr:
        try:
            proc = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                row["timed_out"] = True
                signal_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    row["forced_kill"] = signal_group(proc, signal.SIGKILL)
                    proc.wait(timeout=3)
            row["exit_code"] = proc.returncode
        except Exception as exc:
            row["launch_or_wait_error"] = str(exc)
            raise
        finally:
            if proc and proc.poll() is None:
                row["forced_kill"] = signal_group(proc, signal.SIGKILL)
                proc.wait(timeout=3); row["exit_code"] = proc.returncode
            row["elapsed_seconds"] = time.monotonic() - started
    row["stdout_sha256"] = sha(out / row["stdout"])
    row["stderr_sha256"] = sha(out / row["stderr"])
    return row


def read_json_command(command, out, name, commands):
    row = run_record(command, out, name, commands)
    if row["exit_code"] or row["timed_out"]:
        raise RuntimeError(f"{name} failed; raw output/exit status retained")
    return json.loads((out / row["stdout"]).read_text())


def endpoint_snapshot(args, phase, commands):
    links = read_json_command(["ip", "-details", "-statistics", "-json", "link", "show", "dev", args.interface],
                              args.out, phase + "-link", commands)
    addresses = read_json_command(["ip", "-json", "address", "show", "dev", args.interface],
                                  args.out, phase + "-address", commands)
    routes = read_json_command(["ip", "-json", "route", "get", args.peer_tun, "from", args.local_tun],
                               args.out, phase + "-route", commands)
    if len(links) != 1 or links[0].get("ifname") != args.interface:
        raise RuntimeError("expected exactly the dedicated tunnel interface")
    if not any(a.get("local") == args.local_tun for row in addresses for a in row.get("addr_info", [])):
        raise RuntimeError("bound traffic source is not assigned to the dedicated tunnel interface")
    if not routes or any(row.get("dev") != args.interface or row.get("type") in ("local", "unreachable", "blackhole") for row in routes):
        raise RuntimeError("source-specific traffic route does not use the tunnel interface")
    kind = links[0].get("linkinfo", {}).get("info_kind")
    expected = "ovpn" if args.mode == "dco" else "tun"
    if kind != expected:
        raise RuntimeError(f"actual interface kind is {kind!r}, expected {expected!r}")
    return {"link": links[0], "addresses": addresses, "routes": routes, "ifindex": links[0]["ifindex"],
            "network_namespace_inode": netns_inode(), "counters": link_bytes(links[0])}


def fresh_peer(log, proc, after_byte, timeout=5):
    """Require a complete new status-driven netlink response after this boundary."""
    until = time.monotonic() + timeout
    while time.monotonic() < until and proc.poll() is None:
        raw = log.read_bytes()[after_byte:]
        records = peer_snapshots(raw.decode(errors="replace"))
        ids = {row["peer_id"] for row in records}
        if len(ids) > 1:
            raise RuntimeError("single-peer diagnostic cannot attribute multi-peer counter snapshots")
        if records:
            result = records[-1]
            result["log_byte_boundary"] = after_byte
            result["completed_log_byte"] = after_byte + sum(len(line) for line in raw.splitlines(keepends=True)[:result["end_line"]])
            return result
        time.sleep(0.1)
    raise RuntimeError("missing fresh complete official DCO netlink peer-counter response")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--mode", choices=("userspace", "dco"), required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--interface")
    parser.add_argument("--peer-tun")
    parser.add_argument("--local-tun")
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--expected-cipher", default="AES-256-GCM")
    args = parser.parse_args(argv)
    if args.out.exists() and any(args.out.iterdir()):
        parser.error("output must be a new or empty directory")
    args.out.mkdir(parents=True, exist_ok=True)
    result = {"schema": "hepta.openvpn-hia.real-tunnel-trial.v2", "preflight": preflight(args.mode),
              "runner_sha256": sha(__file__), "commands": [], "scope": "diagnostic single-peer TCP smoke",
              "real_tun_tunnel_passed": False, "dco_runtime_passed": False, "performance_qualified": False,
              "authentication_negative_qualified": False, "replay_qualified": False,
              "reconnect_qualified": False, "rekey_qualified": False}
    def save():
        (args.out / "trial.json").write_text(json.dumps(result, indent=2) + "\n")
    if args.preflight_only or not result["preflight"]["available"]:
        save(); print(json.dumps(result)); return 2 if result["preflight"]["blockers"] else 0
    if not all((args.binary, args.config, args.interface, args.peer_tun, args.local_tun)):
        parser.error("actual trials require binary, config, interface, peer-tun, local-tun")
    if not 1 <= args.seconds <= 120:
        parser.error("seconds must be 1..120")
    for value in (args.peer_tun, args.local_tun):
        try:
            addr = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            parser.error("diagnostic trial requires explicit IPv4 addresses")
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            parser.error("tunnel addresses cannot be loopback, unspecified or multicast")
    if args.peer_tun == args.local_tun:
        parser.error("local and peer tunnel addresses must differ")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", args.interface):
        parser.error("invalid dedicated interface name")
    log = args.out / "openvpn.log"
    launch_log = args.out / "openvpn-launch.log"
    proc = None
    completed = False
    try:
        result["binary_sha256"] = sha(args.binary); result["config_sha256"] = sha(args.config)
        links = read_json_command(["ip", "-json", "link", "show"], args.out, "initial-links", result["commands"])
        result["interface_absent_before_launch"] = all(row.get("ifname") != args.interface for row in links)
        if not result["interface_absent_before_launch"]:
            raise RuntimeError("dedicated interface already exists; cannot attribute it to this OpenVPN process")
        command = [str(args.binary.resolve()), "--config", str(args.config.resolve()), "--dev", args.interface,
                   "--dev-type", "tun", "--verb", "6", "--log", str(log.resolve()),
                   "--status", str((args.out / "status.txt").resolve()), "1", "--status-version", "3"]
        if args.mode == "userspace":
            command += ["--disable-dco"]
        result["openvpn_argv"] = command
        result["traffic_argv"] = ["iperf3", "-c", args.peer_tun, "-B", args.local_tun, "-J", "-t", str(args.seconds), "-P", "1"]
        with launch_log.open("xb") as stream:
            proc = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            result["openvpn_pid"] = proc.pid
            cipher_pattern = r"Data Channel: cipher '" + re.escape(args.expected_cipher) + r"'"
            until = time.monotonic() + 30
            while time.monotonic() < until and proc.poll() is None:
                text = log.read_text(errors="replace") if log.exists() else ""
                if "Initialization Sequence Completed" in text and re.search(cipher_pattern, text):
                    break
                time.sleep(0.1)
            text = log.read_text(errors="replace") if log.exists() else ""
            if proc.poll() is not None or "Initialization Sequence Completed" not in text:
                raise RuntimeError("OpenVPN did not initialize before deadline")
            if netns_inode(proc.pid) != result["preflight"]["network_namespace_inode"]:
                raise RuntimeError("OpenVPN process left the isolated network namespace")
            expected_open = "DCO" if args.mode == "dco" else "TUN/TAP"
            if not re.search(re.escape(expected_open) + r" device " + re.escape(args.interface) + r" opened", text):
                raise RuntimeError("no matching device-open evidence for the exact interface")
            if not re.search(cipher_pattern, text):
                raise RuntimeError("expected negotiated data cipher evidence is absent")
            before = endpoint_snapshot(args, "before", result["commands"])
            result["before"] = before
            if args.mode == "dco":
                result["dco_peer_before"] = fresh_peer(log, proc, log.stat().st_size)
            if (args.out / "status.txt").exists():
                shutil.copy2(args.out / "status.txt", args.out / "status-before.txt")
            traffic_log_start = log.stat().st_size
            result["traffic_log_byte_boundary"] = traffic_log_start
            stat_before = Path("/proc", str(proc.pid), "stat").read_text().rsplit(")", 1)[1].split()
            traffic = run_record(result["traffic_argv"], args.out, "iperf", result["commands"], args.seconds + 15)
            result["traffic"] = traffic
            if traffic["exit_code"] or traffic["timed_out"] or proc.poll() is not None:
                raise RuntimeError("traffic process failed or timed out; complete partial output preserved")
            stat_after = Path("/proc", str(proc.pid), "stat").read_text().rsplit(")", 1)[1].split()
            result["openvpn_cpu_user_seconds"] = (int(stat_after[11]) - int(stat_before[11])) / os.sysconf("SC_CLK_TCK")
            result["openvpn_cpu_system_seconds"] = (int(stat_after[12]) - int(stat_before[12])) / os.sysconf("SC_CLK_TCK")
            measurement = json.loads((args.out / "iperf.stdout").read_text())
            received = measurement.get("end", {}).get("sum_received")
            if "error" in measurement or not received or received.get("bytes", 0) <= 0:
                raise RuntimeError("iperf did not report positive receiver payload bytes")
            result["sum_received"] = received
            after = endpoint_snapshot(args, "after", result["commands"])
            result["after"] = after
            if after["ifindex"] != before["ifindex"] or after["network_namespace_inode"] != before["network_namespace_inode"]:
                raise RuntimeError("tunnel interface or namespace identity changed during traffic")
            result["interface_counter_delta"] = positive_delta(before["counters"], after["counters"],
                                                               ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets"))
            if args.mode == "dco":
                result["dco_peer_after"] = fresh_peer(log, proc, log.stat().st_size)
                first, last = result["dco_peer_before"], result["dco_peer_after"]
                interval_text = log.read_bytes()[first["completed_log_byte"]:last["completed_log_byte"]].decode(errors="replace")
                result["dco_peer_counter_delta"] = peer_interval(first, last, interval_text)
            if (args.out / "status.txt").exists():
                shutil.copy2(args.out / "status.txt", args.out / "status-after.txt")
            text = log.read_text(errors="replace")
            result["negotiation_lines"] = [line for line in text.splitlines() if any(s in line for s in
                                           ("Data Channel:", "protocol-flags", "IV_PROTO=", "NCP negotiation result"))]
            if text.count("Initialization Sequence Completed") != 1:
                raise RuntimeError("unexpected reconnection during single-session diagnostic trial")
            if len(re.findall(re.escape(expected_open) + r" device " + re.escape(args.interface) + r" opened", text)) != 1:
                raise RuntimeError("device reopened during single-interface diagnostic trial")
            completed = True
    except Exception as exc:
        result["failure"] = str(exc)
    finally:
        if proc:
            cleanup = cleanup_process(proc)
            result["openvpn_cleanup"] = cleanup
            if cleanup["forced_kill"] or cleanup["exit_code"] != 0 or cleanup.get("cleanup_error"):
                completed = False
                result.setdefault("failure", "OpenVPN cleanup did not exit cleanly")
        if log.exists():
            result["log_sha256"] = sha(log)
        if launch_log.exists():
            result["launch_log_sha256"] = sha(launch_log)
        try:
            result["inputs_unchanged"] = result.get("binary_sha256") == sha(args.binary) and result.get("config_sha256") == sha(args.config)
        except Exception:
            result["inputs_unchanged"] = False
        if not result["inputs_unchanged"]:
            completed = False
            result.setdefault("failure", "binary/config identity changed or became unavailable")
        result["real_tun_tunnel_passed"] = completed
        result["dco_runtime_passed"] = completed and args.mode == "dco" and bool(result.get("dco_peer_counter_delta"))
        save()
    print(json.dumps({key: result.get(key) for key in ("real_tun_tunnel_passed", "dco_runtime_passed", "failure")}))
    return 0 if completed else 1


if __name__ == "__main__":
    raise SystemExit(main())
