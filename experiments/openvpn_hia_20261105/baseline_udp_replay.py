#!/usr/bin/env python3
"""Duplicate and corrupt encrypted ping datagrams in real loopback dev-null peers.

Consumes a completed baseline.json so executable hashes/configuration/ephemeral
PKI already have provenance. Only UDP loopback traffic is relayed. No TUN, route,
namespace, privilege or DCO claim is made. Never treat this as throughput data.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import time


def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def option(argv, key, value):
    argv[argv.index(key) + 1] = str(value)


def exercise(base, original, out, observe, trace_observation):
    labels = {v['path']: k for k, v in base['binaries'].items()}
    name = labels[original['server_argv'][0]] + '-' + labels[original['client_argv'][0]]
    commands = [list(original[role + '_argv']) for role in ('server', 'client')]
    # Two bound relay sockets retain the source ports each peer expects.
    socks = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(4)]
    for s in socks: s.bind(('127.0.0.1', 0))
    sp, cp, rp, lp = [s.getsockname()[1] for s in socks]
    socks[0].close(); socks[1].close()
    right, left = socks[2:]
    option(commands[0], '--lport', sp); option(commands[0], '--rport', rp)
    option(commands[1], '--lport', cp); option(commands[1], '--rport', lp)
    streams, procs, injections = [], [], []
    injected = set(); forwarded = {'client-to-server': 0, 'server-to-client': 0}
    logs = [out / (name + '-' + role + '.log') for role in ('server', 'client')]
    start = time.monotonic(); alive = []
    try:
        for command, log in zip(commands, logs):
            f = log.open('wb'); streams.append(f)
            procs.append(subprocess.Popen(command, stdout=f, stderr=subprocess.STDOUT, start_new_session=True))
        while time.monotonic() - start < 10 and all(p.poll() is None for p in procs):
            ready, _, _ = select.select([left, right], [], [], 0.05)
            established = all('Initialization Sequence Completed' in log.read_text(errors='replace') for log in logs)
            for incoming in ready:
                data, sender = incoming.recvfrom(65536)
                if incoming is left:
                    expected, outgoing, target, direction = cp, right, sp, 'client-to-server'
                else:
                    expected, outgoing, target, direction = sp, left, cp, 'server-to-client'
                if sender != ('127.0.0.1', expected):
                    raise RuntimeError('unexpected sender in loopback probe')
                outgoing.sendto(data, ('127.0.0.1', target)); forwarded[direction] += 1
                opcode = data[0] >> 3 if data else None
                if established and opcode in (6, 9) and direction not in injected:
                    # First forward the authentic datagram, then an exact replay
                    # and a copy with one ciphertext/tag byte flipped.
                    outgoing.sendto(data, ('127.0.0.1', target))
                    corrupt = bytearray(data); corrupt[-1] ^= 1
                    outgoing.sendto(corrupt, ('127.0.0.1', target))
                    injected.add(direction)
                    injections.append({'direction': direction, 'opcode': opcode, 'length': len(data),
                                       'elapsed_seconds': time.monotonic() - start,
                                       'ciphertext_sha256': hashlib.sha256(data).hexdigest(),
                                       'exact_duplicates': 1, 'corrupted_copies': 1})
        alive = [p.poll() is None for p in procs]
    finally:
        for p in procs:
            if p.poll() is None: os.killpg(p.pid, signal.SIGTERM)
        for p in procs:
            try: p.wait(timeout=3)
            except subprocess.TimeoutExpired: os.killpg(p.pid, signal.SIGKILL); p.wait()
        for f in streams: f.close()
        left.close(); right.close()
    observations = {}
    for role, command, log in zip(('server', 'client'), commands, logs):
        text = log.read_text(errors='replace')
        observations[role] = {'log': log.name, 'log_sha256': digest(log), **observe(text),
                              'exact_replay_rejections': text.count('bad packet ID (may be a replay)'),
                              'tag_authentication_rejections': text.count('packet tag authentication failed')}
        if labels[command[0]] == 'hia': observations[role]['hia_trace'] = trace_observation(text)
    checks = {'both_processes_survived': all(alive) and all(p.returncode == 0 for p in procs),
              'injected_both_directions': len(injected) == 2,
              'both_peers_initialized_once': all(x['initialization_completed'] == 1 for x in observations.values()),
              'both_peers_rekeyed': all(x['rekey_cycles_completed'] >= 1 for x in observations.values()),
              'both_peers_rejected_exact_replay': all(x['exact_replay_rejections'] >= 1 for x in observations.values()),
              'both_peers_rejected_bad_tag': all(x['tag_authentication_rejections'] >= 1 for x in observations.values())}
    for role, row in observations.items():
        if 'hia_trace' in row:
            tr = row['hia_trace']; checks[role + '_hia_no_abi_errors'] = bool(tr['present'] and tr['counts']['abi_failures'] == 0
                and tr['counts']['read_epoch'] > 0 and tr['counts']['write_epoch'] > 0)
    return {'pair': name, 'scope': 'actual-OpenVPN-loopback-dev-null-encrypted-ping', 'passed': all(checks.values()),
            'checks': checks, 'commands': commands, 'injections': injections, 'forwarded_datagrams': forwarded,
            'observations': observations, 'duration_seconds': time.monotonic() - start,
            'exit_codes': [p.returncode for p in procs]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--baseline', type=Path, required=True); p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    if args.out.exists() and any(args.out.iterdir()): p.error('output must be empty')
    args.out.mkdir(parents=True, exist_ok=True)
    base = json.loads(args.baseline.read_text())
    if not all(x['passed'] for x in base['control_sessions']): p.error('baseline control checks must already pass')
    for row in base['binaries'].values():
        if digest(row['path']) != row['sha256']: p.error('binary changed since baseline')
    runner = Path(__file__).resolve().parents[2] / 'tools/openvpn_hia_baseline.py'
    spec = importlib.util.spec_from_file_location('baseline', runner); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    if digest(runner) != base['runner_sha256']: p.error('baseline verifier changed')
    result = {'schema': 'hepta.openvpn-hia.encrypted-udp-adversarial-probe.v1', 'runner_sha256': digest(__file__),
              'baseline_sha256': digest(args.baseline), 'real_tun_tunnel_passed': False, 'dco_runtime_passed': False, 'sessions': []}
    for session in base['control_sessions']:
        if session['authentication_negative'] is None and any(session[k][0] == base['binaries']['hia']['path'] for k in ('server_argv', 'client_argv')):
            result['sessions'].append(exercise(base, session, args.out, module.observe_control, module.trace_observation))
    result['passed'] = len(result['sessions']) == 2 and all(x['passed'] for x in result['sessions'])
    (args.out / 'udp-probe.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'sessions': [x['checks'] for x in result['sessions']]}))
    return 0 if result['passed'] else 1

if __name__ == '__main__': raise SystemExit(main())
