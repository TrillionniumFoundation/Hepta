#!/usr/bin/env python3
"""Bounded real-TUN/ovpn qualification on an explicitly provisioned test VM.

Creates only uniquely named owned namespaces and veths, never a host route/NAT.
No local privilege acquisition, module loading or CI dispatch is performed here.
The frozen plan declares every case before execution. Raw failures are retained.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import traceback
import uuid

HERE = Path(__file__).resolve().parent
BYTE_COUNTERS = ('vpn_rx_bytes', 'vpn_tx_bytes', 'link_rx_bytes', 'link_tx_bytes')
PEER_COUNTERS = BYTE_COUNTERS + ('vpn_rx_packets', 'vpn_tx_packets', 'link_rx_packets', 'link_tx_packets')
ROLES = ('server', 'client')


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def save(path, obj):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.new')
    temp.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n'); temp.replace(path)

def read_json(path): return json.loads(Path(path).read_text())

def read_text(path):
    try: return Path(path).read_text(errors='replace')
    except FileNotFoundError: return ''

def process_stats(pid):
    raw = Path('/proc', str(pid), 'stat').read_text()
    fields = raw[raw.rindex(')')+2:].split()
    return {'user_ticks': int(fields[11]), 'system_ticks': int(fields[12]),
            'starttime_ticks': int(fields[19]), 'rss_bytes': int(fields[21])*os.sysconf('SC_PAGE_SIZE')}


def read_cpu_topology(allowed, root=Path('/sys/devices/system/cpu')):
    """Read physical package/core identity; logical CPU IDs alone are not topology."""
    topology = {}
    for cpu in sorted(set(int(value) for value in allowed)):
        directory = Path(root) / f'cpu{cpu}' / 'topology'
        try:
            package_id = int((directory / 'physical_package_id').read_text().strip())
            core_id = int((directory / 'core_id').read_text().strip())
        except (OSError, ValueError) as exc:
            raise RuntimeError(f'cannot establish physical core identity for CPU {cpu}: {exc}') from exc
        topology[cpu] = (package_id, core_id)
    return topology


def select_distinct_physical_cpus(allowed, topology):
    """Choose one allowed logical CPU from each of two distinct physical cores."""
    selected = []
    seen = set()
    for cpu in sorted(set(int(value) for value in allowed)):
        if cpu not in topology:
            raise RuntimeError(f'physical core identity missing for allowed CPU {cpu}')
        key = tuple(topology[cpu])
        if len(key) != 2 or any(type(value) is not int for value in key):
            raise RuntimeError(f'invalid physical core identity for CPU {cpu}')
        if key not in seen:
            selected.append(cpu)
            seen.add(key)
        if len(selected) == 2:
            return selected
    raise RuntimeError('at least two distinct physical CPU cores are required for fair two-sided measurement')


def resolve_reneg_seconds(default, by_role=None):
    """Resolve an explicit, positive renegotiation interval for both tunnel roles."""
    if type(default) is not int or not 1 <= default <= 86400:
        raise ValueError('default renegotiation seconds must be an integer in [1, 86400]')
    if by_role is None:
        return {role: default for role in ROLES}
    if not isinstance(by_role, dict) or set(by_role) != set(ROLES):
        raise ValueError('role-specific renegotiation schedule must cover server and client')
    resolved = {}
    for role in ROLES:
        value = by_role[role]
        if type(value) is not int or not 1 <= value <= 86400:
            raise ValueError(f'{role} renegotiation seconds must be an integer in [1, 86400]')
        resolved[role] = value
    return resolved


def observe(text):
    lines = text.splitlines()
    # A peer-initiated rekey can complete TLS and install new keys without the
    # responder logging its own 'TLS: soft reset'. A received control reset is
    # only a *candidate*: the segment must still prove TLS + installed keys.
    local_resets = [i for i, line in enumerate(lines) if 'TLS: soft reset' in line]
    peer_resets = [i for i, line in enumerate(lines)
                   if 'P_CONTROL_SOFT_RESET_V1' in line
                   and re.search(r'\bREAD \[\d+\]', line)]
    boundaries = [i for i, line in enumerate(lines) if any(x in line for x in (
        'TLS: Initial packet', 'initial untrusted session promoted to trusted',
        'Initialization Sequence Completed', 'SIGUSR1[hard,'))]
    # The peer that initiates renegotiation logs "TLS: soft reset"; a passive
    # peer may only log the received SOFT_RESET packet. Neither is completion.
    # Bind the response to an explicit reset, and keep retransmissions within
    # the same attempt so they cannot split key evidence or discard an error.
    resets = []
    boundary_set = set(boundaries)
    reset_key = None
    pending_explicit = False
    for i, line in enumerate(lines):
        if i in boundary_set:
            reset_key = None
            pending_explicit = False
        if 'TLS: soft reset' in line:
            resets.append(i)
            reset_key = None
            pending_explicit = True
        else:
            packet = re.search(r'\bUDPv[46] READ \[\d+\] from \S+: '
                               r'P_CONTROL_SOFT_RESET_V1 kid=([0-7])(?:\s|$)', line)
            if packet:
                key = int(packet[1])
                if not pending_explicit and key != reset_key:
                    resets.append(i)
                reset_key = key
                pending_explicit = False
    completed = []
    for begin in resets:
        end = min([i for i in resets + boundaries if i > begin] + [len(lines)])
        segment = lines[begin:end]
        find = lambda token: [begin+i+1 for i, line in enumerate(segment) if token in line]
        tls = find('Control Channel: TLS')
        outgoing = find('Outgoing Epoch Data key 1:') or find('Outgoing Data Channel: Cipher')
        incoming = find('Incoming Epoch Data key 1:') or find('Incoming Data Channel: Cipher')
        install = find('dco_new_key: slot 1,')
        swap = find('dco_swap_keys: peer-id')
        failed = any(any(x in line for x in ('Cannot swap keys', 'Impossible to install key material',
                     'DCO key state mismatch', 'TLS Error:')) for line in segment)
        ordinary = bool(tls and outgoing and incoming and tls[0] < outgoing[0] <= incoming[0])
        offload = bool(tls and install and swap and tls[0] < install[0] <= swap[-1])
        if (ordinary or offload) and not failed:
            completed.append({'reset_line': begin+1, 'tls_line': tls[0],
                              'outgoing_key_line': outgoing[0] if ordinary else None,
                              'incoming_key_line': incoming[0] if ordinary else None,
                              'dco_install_line': install[0] if offload else None,
                              'dco_swap_line': swap[-1] if offload else None})
    # A passive DCO peer can promote the staged key at the next reset. Its
    # dco_swap_keys event may therefore be in the next reset segment, before
    # that segment's new key is installed, and the responder may not log a
    # local TLS: soft reset. Pair the staged key with a later, different
    # control-reset key and the same peer's swap. Initiator-side same-segment
    # DCO receipts remain covered by the offload check above.
    pending_dco = {}
    current_session = None
    for begin in resets:
        # Peer IDs can be reused after a hard restart. A staged key from the
        # previous TLS session must never be promoted by a later session's
        # reset/swap sequence.
        # Count TLS lifecycle boundaries so reused peer IDs cannot cross sessions.
        session_id = sum(boundary < begin for boundary in boundaries)
        if current_session is None:
            current_session = session_id
        elif session_id != current_session:
            pending_dco.clear()
            current_session = session_id
        end = min([i for i in resets + boundaries if i > begin] + [len(lines)])
        segment = lines[begin:end]
        reset_keys = {
            int(match[1])
            for line in segment
            for match in [re.search(r'P_CONTROL_SOFT_RESET_V1 kid=([0-7])(?:\s|$)', line)]
            if match
        }
        reset_key = next(iter(reset_keys)) if len(reset_keys) == 1 else None
        install_lines = {}
        segment_failed = False
        for offset, line in enumerate(segment):
            absolute_line = begin + offset + 1
            if any(token in line for token in (
                'Cannot swap keys', 'Impossible to install key material',
                'DCO key state mismatch', 'TLS Error:'
            )):
                segment_failed = True
                for state in pending_dco.values():
                    state['failed'] = True
            swap_match = re.search(r'dco_swap_keys: peer-id (\d+)', line)
            if swap_match:
                peer_id = int(swap_match[1])
                pending = pending_dco.pop(peer_id, None)
                if (
                    pending
                    and not pending['failed']
                    and reset_key is not None
                    and reset_key != pending['key_id']
                    and begin + 1 > pending['reset_line']
                    and absolute_line > pending['new_key_line']
                ):
                    completed.append({
                        'reset_line': pending['reset_line'],
                        'tls_line': None,
                        'outgoing_key_line': None,
                        'incoming_key_line': None,
                        'dco_install_line': pending['install_line'],
                        'dco_swap_line': absolute_line,
                        'dco_key_id': pending['key_id'],
                        'dco_peer_id': peer_id,
                        'dco_promotion_reset_line': begin + 1
                    })
            install_match = re.search(
                r'dco_install_key: peer_id=(\d+) keyid=([0-7])', line
            )
            if install_match:
                key = (int(install_match[1]), int(install_match[2]))
                install_lines.setdefault(key, []).append(absolute_line)
            new_match = re.search(
                r'dco_new_key: slot 1, key-id ([0-7]), peer-id (\d+)', line
            )
            if new_match:
                key_id = int(new_match[1])
                peer_id = int(new_match[2])
                matching_installs = install_lines.get((peer_id, key_id), [])
                if (
                    not segment_failed
                    and reset_key == key_id
                    and len(matching_installs) == 1
                    and matching_installs[0] < absolute_line
                ):
                    # An unpromoted previous slot must never be overwritten by
                    # a later install and then retroactively treated as valid.
                    if peer_id in pending_dco:
                        pending_dco.pop(peer_id, None)
                    else:
                        pending_dco[peer_id] = {
                            'key_id': key_id,
                            'peer_id': peer_id,
                            'reset_line': begin + 1,
                            'install_line': matching_installs[0],
                            'new_key_line': absolute_line,
                            'failed': False
                        }
    completed.sort(key=lambda cycle: cycle['reset_line'])
    traces = re.findall(r'OPENVPN_HIA_CALLS read=(\d+) write=(\d+) read_epoch=(\d+) write_epoch=(\d+) abi_failures=(\d+)',text)
    trace = dict(zip(('read','write','read_epoch','write_epoch','abi_failures'),map(int,traces[-1]))) if traces else None
    initializations=[i for i,line in enumerate(lines) if 'Initialization Sequence Completed' in line]
    latest_start=initializations[-1]+1 if initializations else len(lines)
    latest_lines=lines[latest_start:]
    return {'initializations':len(initializations),
            'last_initialization_line':initializations[-1]+1 if initializations else None,
            'initial_packets':text.count('TLS: Initial packet'),
            'initial_promotions':text.count('initial untrusted session promoted to trusted'),
            'hard_restarts':text.count('SIGUSR1[hard,'),
            'soft_resets':len(local_resets),
            'peer_soft_resets':len(peer_resets),
            'peer_connections':text.count('Peer Connection Initiated'),
            'rekey_cycles':completed,'completed_rekeys':len(completed),
            'protocol_lines':[line for line in lines if 'Protocol options:' in line],
            'data_channel_lines':[line for line in lines if 'Data Channel: cipher' in line],
            'latest_initialized_session':{
                'initialization_line':initializations[-1]+1 if initializations else None,
                'protocol_lines':[line for line in latest_lines if 'Protocol options:' in line],
                'data_channel_lines':[line for line in latest_lines if 'Data Channel: cipher' in line]},
            'certificate_error_lines':[line for line in lines if re.search(r'VERIFY (?:X509NAME )?ERROR',line)],
            'replay_rejections':text.count('bad packet ID (may be a replay)'),
            'tag_rejections':text.count('packet tag authentication failed'),
            'tls_error_lines':[line for line in lines if 'TLS Error:' in line],
            'hia_trace':trace}


def session_marker(observation):
    return {key:observation[key] for key in ('initializations','initial_packets','initial_promotions','hard_restarts','peer_connections')}


def negotiated_profile(observation, epoch):
    """Only profile lines after the newest completed client initialization count."""
    latest=observation['latest_initialized_session']
    protocols=latest['protocol_lines'];data=latest['data_channel_lines']
    if not latest['initialization_line'] or not protocols or not data:
        raise ValueError('latest initialized session has no complete negotiated profile yet')
    if any('aead-epoch' in line for line in protocols)!=epoch:
        raise ValueError('latest initialized session negotiated the wrong epoch profile')
    if not all("cipher 'AES-256-GCM'" in line for line in data):
        raise ValueError('latest initialized session negotiated an unexpected cipher')
    return latest


def peer_delta(before, after):
    for key in ('ifindex','netns_inode','family_id'):
        if before.get(key) != after.get(key): raise ValueError('DCO peer scope changed: '+key)
    first={p['peer_id']:p for p in before['peers']};last={p['peer_id']:p for p in after['peers']}
    if len(first)!=1 or set(first)!=set(last): raise ValueError('expected the same single DCO peer')
    deltas={}
    for peer_id, old in first.items():
        row={k:last[peer_id][k]-old[k] for k in PEER_COUNTERS}
        if any(v<0 for v in row.values()): raise ValueError('DCO peer counters reset')
        if any(row[k]<=0 for k in BYTE_COUNTERS): raise ValueError('DCO peer byte counters did not all increase')
        deltas[str(peer_id)]=row
    return deltas



def dco_device_drop_delta(before, after):
    """Require one isolated kernel ovpn RX drop and no VPN-facing device delivery."""
    if not isinstance(before, list) or len(before) != 1 or not isinstance(after, list) or len(after) != 1:
        raise ValueError("DCO device snapshot must contain exactly one interface")
    old, new = before[0], after[0]
    if old.get("ifname") != "tunbench-s" or new.get("ifname") != "tunbench-s":
        raise ValueError("DCO device snapshot names the wrong interface")
    if type(old.get("ifindex")) is not int or old.get("ifindex") != new.get("ifindex"):
        raise ValueError("DCO device ifindex changed or is malformed")
    if old.get("linkinfo", {}).get("info_kind") != "ovpn" or new.get("linkinfo", {}).get("info_kind") != "ovpn":
        raise ValueError("DCO device snapshot is not the kernel ovpn interface")
    old_rx = old.get("stats64", {}).get("rx", {})
    new_rx = new.get("stats64", {}).get("rx", {})
    keys = ("dropped", "packets", "bytes")
    if any(type(old_rx.get(key)) is not int or type(new_rx.get(key)) is not int
           for key in keys):
        raise ValueError("DCO device RX counters are missing or malformed")
    delta = {key: new_rx[key] - old_rx[key] for key in keys}
    if any(value < 0 for value in delta.values()):
        raise ValueError("DCO device RX counters reset")
    if delta["dropped"] != 1:
        raise ValueError("DCO device did not record exactly one isolated RX drop")
    if delta["packets"] != 0 or delta["bytes"] != 0:
        raise ValueError("injected packet was delivered to the VPN-facing DCO device")
    return {"rx_dropped": delta["dropped"], "rx_packets": delta["packets"],
            "rx_bytes": delta["bytes"]}


def dco_rejection_delta(before, after, packet_peer_id=None, allow_stale_peer_id=False,
                        device_drop_delta=None):
    """Require peer accounting plus the independent DCO device RX-drop witness."""
    if type(allow_stale_peer_id) is not bool:
        raise ValueError("stale peer-ID allowance must be an explicit boolean")
    if packet_peer_id is not None and (type(packet_peer_id) is not int
                                       or not 0 <= packet_peer_id <= 0xffffff):
        raise ValueError("OpenVPN data-v2 peer ID is malformed")
    if device_drop_delta != {"rx_dropped": 1, "rx_packets": 0, "rx_bytes": 0}:
        raise ValueError("DCO device did not record one isolated receive drop without VPN delivery")
    for key in ("ifindex", "netns_inode", "family_id"):
        if before.get(key) != after.get(key):
            raise ValueError("DCO peer scope changed: " + key)
    first = {p["peer_id"]: p for p in before["peers"]}
    last = {p["peer_id"]: p for p in after["peers"]}
    if len(first) != 1 or set(first) != set(last):
        raise ValueError("expected the same single DCO peer around encrypted injection")
    deltas = {}
    for peer_id, old in first.items():
        row = {key: last[peer_id][key] - old[key] for key in PEER_COUNTERS}
        if any(value < 0 for value in row.values()):
            raise ValueError("DCO peer counters reset during encrypted injection")
        stale_peer = allow_stale_peer_id and packet_peer_id is not None and packet_peer_id != peer_id
        if allow_stale_peer_id and not stale_peer:
            raise ValueError("post-reconnect stale replay does not carry a different prior peer ID")
        if packet_peer_id is not None and not stale_peer and packet_peer_id != peer_id:
            raise ValueError("encrypted datagram peer ID differs from the active DCO peer")
        if stale_peer:
            if any(value != 0 for value in row.values()):
                raise ValueError("stale prior-session peer unexpectedly changed active peer counters")
        else:
            if row["link_rx_packets"] <= 0 or row["link_rx_bytes"] <= 0:
                raise ValueError("DCO kernel peer did not record incoming link traffic")
            if row["vpn_rx_packets"] != 0 or row["vpn_rx_bytes"] != 0:
                raise ValueError("encrypted replay/tamper reached the VPN-facing peer counters")
        deltas[str(peer_id)] = row
    return deltas


def continuity_sender_completion(row):
    """Allow a completed degraded sender, but never a timeout, kill or unbalanced pause."""
    if not isinstance(row, dict) or row.get("timed_out"):
        raise ValueError("continuous payload sender timed out before isolated DCO injection")
    if type(row.get("exit_code")) is not int or row["exit_code"] not in (0, 1):
        raise ValueError("continuous payload sender exited with an unexpected status")
    state = False
    signals = row.get("signals", [])
    if not isinstance(signals, list):
        raise ValueError("continuous payload sender signal receipt is malformed")
    for item in signals:
        if not isinstance(item, dict):
            raise ValueError("continuous payload sender signal receipt is malformed")
        signum = item.get("signal")
        if signum == signal.SIGSTOP and not state:
            state = True
        elif signum == signal.SIGCONT and state:
            state = False
        else:
            raise ValueError("continuous payload sender has an unmatched or unexpected signal")
    if state:
        raise ValueError("continuous payload sender remained stopped before isolated DCO injection")
    return {"sender_exit_code": row["exit_code"], "sender_timed_out": False,
            "sender_signals": signals}


def path_delta(before, after, require_peer=True):
    out={}
    for role in ROLES:
        a,b=before[role],after[role]
        if a['ifindex']!=b['ifindex'] or a['netns_inode']!=b['netns_inode']:
            raise ValueError('tunnel path changed during measured interval')
        if a['kind']!=b['kind']: raise ValueError('tunnel kind changed')
        deltas={}
        for direction in ('rx','tx'):
            aa=a['link'].get('stats64',a['link'].get('stats',{}))[direction]
            bb=b['link'].get('stats64',b['link'].get('stats',{}))[direction]
            deltas[direction]={key:bb[key]-aa[key] for key in ('bytes','packets','errors','dropped') if key in aa and key in bb}
            if deltas[direction].get('bytes',0)<=0 or deltas[direction].get('packets',0)<=0:
                raise ValueError('no bidirectional traffic on actual tunnel link')
            if any(v<0 for v in deltas[direction].values()): raise ValueError('tunnel interface counters reset')
        out[role]={'link_delta':deltas}
        if a['kind']=='ovpn' and require_peer: out[role]['kernel_peer_delta']=peer_delta(a['peer'],b['peer'])
    return out


class Deadline(RuntimeError): pass


class Job:
    def __init__(self, ledger, label, argv, folder, namespace=None):
        ledger.check()
        self.ledger=ledger;self.label=label;self.started=time.monotonic();self.finished=False
        self.folder=Path(folder);self.folder.mkdir(parents=True,exist_ok=True)
        self.stdout=self.folder/(label+'.stdout');self.stderr=self.folder/(label+'.stderr')
        self.outf=self.stdout.open('xb');self.errf=self.stderr.open('xb')
        command=list(map(str,argv))
        if namespace:command=['ip','netns','exec',namespace,*command]
        self.row={'label':label,'argv':command,'namespace':namespace,'started_monotonic_ns':time.monotonic_ns(),
                  'stdout':str(self.stdout.relative_to(ledger.out)),'stderr':str(self.stderr.relative_to(ledger.out)),
                  'signals':[]}
        try:self.proc=subprocess.Popen(command,stdout=self.outf,stderr=self.errf,start_new_session=True)
        except Exception:
            self.outf.close();self.errf.close();raise
        self.row['pid']=self.proc.pid;ledger.jobs.append(self);ledger.record({'event':'spawn',**self.row})
    def signal(self,signum):
        if self.proc.poll() is None:
            self.row['signals'].append({'signal':signum,'monotonic_ns':time.monotonic_ns()})
            try:os.killpg(self.proc.pid,signum)
            except ProcessLookupError:self.proc.poll()
    def finish(self):
        if self.finished:return self.row
        if self.proc.poll() is None:raise RuntimeError('cannot finish a running process')
        self.outf.close();self.errf.close();self.finished=True
        self.row.update(exit_code=self.proc.returncode,elapsed_seconds=time.monotonic()-self.started,
                        stdout_sha256=digest(self.stdout),stderr_sha256=digest(self.stderr))
        self.ledger.record({'event':'finished',**self.row});return self.row
    def wait(self,timeout=10,required=True,monitor=None):
        until=time.monotonic()+timeout
        while self.proc.poll() is None:
            self.ledger.check()
            if monitor:monitor()
            if time.monotonic()>=until:
                self.row['timed_out']=True;self.stop();break
            time.sleep(0.05 if monitor else 0.01)
        row=self.finish()
        if required and (row['exit_code'] or row.get('timed_out')):
            raise RuntimeError(self.label+' failed: '+str(row.get('exit_code')))
        return row
    def stop(self):
        if self.proc.poll() is None:
            self.signal(signal.SIGTERM)
            try:self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.signal(signal.SIGKILL);self.proc.wait(timeout=3)
        return self.finish()
    def text(self):return read_text(self.stdout)+read_text(self.stderr)


def profile_record_grace_seconds(workload_seconds, configured_grace_seconds):
    """Bound recorder finalization after traffic without silently truncating it."""
    for name,value in (("workload_seconds",workload_seconds),
                       ("configured_grace_seconds",configured_grace_seconds)):
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value):
            raise ValueError(name+" must be a finite number")
    if workload_seconds<=0:raise ValueError("workload_seconds must be positive")
    if configured_grace_seconds<5 or configured_grace_seconds>120:
        raise ValueError("configured_grace_seconds must be between 5 and 120 seconds")
    grace=max(float(configured_grace_seconds),float(workload_seconds)+5.0)
    if grace>120:raise ValueError("required profile recorder grace exceeds the 120-second bound")
    return grace


def profile_process_sample_required(arm):
    """Userspace C and HIA profiles must include the measured client process PID."""
    if arm not in ("c-user", "hia-user", "c-dco"):
        raise ValueError("unknown profile arm: " + str(arm))
    return arm in ("c-user", "hia-user")


def hia_profile_symbol_lines(report_text):
    """Count both exported non-epoch HIA packet-ID entrypoints in OpenVPN's perf report."""
    if not isinstance(report_text, str):
        raise ValueError("perf report text must be a string")
    required = ("ovpn_hia_packet_id_read", "ovpn_hia_packet_id_write")
    found = set()
    for line in report_text.splitlines():
        if not re.search(r"\bopenvpn\b", line):
            continue
        for symbol in required:
            if re.search(r"\b" + re.escape(symbol) + r"\b", line):
                found.add(symbol)
    return len(found)


def wait_for_profile_recorder(job, workload_seconds, configured_grace_seconds):
    """Wait after traffic for perf's own shutdown/finalization, preserving timeout."""
    grace=profile_record_grace_seconds(workload_seconds,configured_grace_seconds)
    row=job.wait(timeout=grace,required=False)
    row["workload_seconds"]=workload_seconds
    row["post_workload_wait_timeout_seconds"]=grace
    return row


class Ledger:
    def __init__(self,out,private,budget):
        self.out=out;self.private=private;self.started=time.monotonic();self.deadline=self.started+budget
        self.jobs=[];self.serial=0;self.owned=[];self.cmdlog=(out/'commands.jsonl').open('x')
        self.owned_path=out/'owned-namespaces.json';self.save_owned()
    def check(self):
        if time.monotonic()>=self.deadline:raise Deadline('predeclared total matrix deadline reached')
    def record(self,row):self.cmdlog.write(json.dumps(row,sort_keys=True)+'\n');self.cmdlog.flush()
    def save_owned(self):save(self.owned_path,{'schema':'hepta.openvpn-hia.owned-namespaces.v1','host_boot_id':read_text('/proc/sys/kernel/random/boot_id').strip(),'namespaces':self.owned})
    def run(self,argv,label,folder=None,namespace=None,timeout=10,required=True):
        self.serial+=1;name=f'{self.serial:05d}-{label}'
        job=Job(self,name,argv,folder or self.out/'commands',namespace)
        job.wait(timeout,required);return job
    def pause(self,seconds):
        until=time.monotonic()+seconds
        while time.monotonic()<until:self.check();time.sleep(min(.05,max(0,until-time.monotonic())))
    def close(self):
        for job in reversed(self.jobs):
            if not job.finished:
                try:job.stop()
                except Exception as e:self.record({'cleanup_error':repr(e),'pid':job.proc.pid})
        self.cmdlog.close()


class Pair:
    def __init__(self,ledger,case,binaries,configuration,arms,trace=False,reneg=3600,negative=False,reneg_by_role=None):
        self.l=ledger;self.case=case;self.folder=ledger.out/'cases'/case;self.folder.mkdir(parents=True)
        self.arms=arms;self.trace=trace;self.negative=negative;self.jobs=[];self.processes={};self.names={};self.entries=[]
        self.reneg_seconds_by_role=resolve_reneg_seconds(reneg,reneg_by_role)
        self.result={'case':case,'arms':arms,'trace':trace,'reneg_seconds':reneg,
                     'reneg_seconds_by_role':self.reneg_seconds_by_role,
                     'status':'running','passed':False,'checks':{},'events':[]}
        unique=uuid.uuid4().hex[:10]
        try:
            for role,suffix in (('server','s'),('client','c')):
                name='ohia-'+unique+'-'+suffix
                if Path('/run/netns',name).exists():raise RuntimeError('namespace name already exists')
                entry={'name':name,'inode':None,'case':case,'active':True}
                self.l.owned.append(entry);self.entries.append(entry);self.l.save_owned();self.names[role]=name
                creation=None
                try:
                    creation=Job(self.l,role+'-netns-add',['ip','netns','add',name],self.folder)
                    creation.wait(10)
                finally:
                    # Stop a partially completed creator before recording its
                    # resource. A deadline between spawn and wait must not leave
                    # an unrecorded namespace outside the cleanup ledger.
                    if creation and not creation.finished:creation.stop()
                    if Path('/run/netns',name).exists():entry['inode']=os.stat('/run/netns/'+name).st_ino
                    else:entry['active']=False
                    self.l.save_owned()
                if entry['inode'] is None:raise RuntimeError('namespace creation produced no owned resource')
            self.command('server',['ip','link','add','ovpn-us','type','veth','peer','name','ovpn-uc','netns',self.names['client']],'veth-create')
            for role,ip,dev in (('server','192.0.2.1/30','ovpn-us'),('client','192.0.2.2/30','ovpn-uc')):
                self.command(role,['ip','link','set','lo','up'],'lo-up')
                self.command(role,['ip','addr','add',ip,'dev',dev],'underlay-address')
                self.command(role,['ip','link','set',dev,'up'],'underlay-up')
                before=read_json_output(self.command(role,['ip','-j','-d','link','show'],'links-before'))
                if any(x['ifname']=='tunbench-'+role[0] for x in before):raise RuntimeError('unexpected existing target tunnel device')
                self.command(role,['ethtool','-k',dev],'underlay-offloads',required=False)
            for role in ROLES:
                arm=arms[role];binary=binaries['hia_trace' if trace and arm.startswith('hia') else 'hia' if arm.startswith('hia') else 'c']
                role_reneg=self.reneg_seconds_by_role[role]
                command=['taskset','-c',str(configuration['cpus'][0 if role=='server' else 1]),str(binary),
                         '--config',str(configuration[role]),'--verb','6' if trace else '3','--status',str(self.folder/(role+'.status')),'1',
                         '--status-version','3','--reneg-sec',str(role_reneg),str(role_reneg)]
                if not arm.endswith('dco'):command+=['--disable-dco']
                if role=='client' and negative:command+=['--cert',str(configuration['untrusted_crt']),'--key',str(configuration['untrusted_key']),'--tls-exit']
                job=self.spawn(role,command,role+'-openvpn');self.processes[role]=job
            self.result['namespaces']=self.names;self.result['new_namespace_identities']=self.entries
            save(self.folder/'case.json',self.result)
        except BaseException:
            self.close();raise
    def command(self,role,argv,label,required=True,timeout=10):
        return self.l.run(argv,role+'-'+label,self.folder,self.names[role],timeout,required)
    def spawn(self,role,argv,label):
        job=Job(self.l,label,argv,self.folder,self.names[role]);self.jobs.append(job);return job
    def observation(self,role):return observe(self.processes[role].text())
    def event(self,name,**fields):
        row={'name':name,'monotonic_ns':time.monotonic_ns(),**fields};self.result['events'].append(row);save(self.folder/'case.json',self.result);return row
    def wait_until(self,condition,timeout,label,allow_client_exit=False):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            self.l.check()
            if condition():return
            for role,job in self.processes.items():
                if job.proc.poll() is not None and not (allow_client_exit and role=='client'):
                    raise RuntimeError(role+' OpenVPN exited before '+label)
            self.l.pause(.05)
        raise TimeoutError(label+' deadline expired')
    def connected(self,after_initializations=0):
        self.wait_until(lambda:self.observation('client')['initializations']>after_initializations,30,'authenticated initialization')
        if not any('VERIFY OK: depth=0' in job.text() for job in [self.processes['server']]):
            raise RuntimeError('server has not authenticated the client certificate')
    def snapshot(self,label):
        result={}
        for role in ROLES:
            dev='tunbench-'+role[0];ip='10.77.0.1' if role=='server' else '10.77.0.2';peer='10.77.0.2' if role=='server' else '10.77.0.1'
            links=read_json_output(self.command(role,['ip','-d','-s','-j','link','show','dev',dev],label+'-link'))
            addresses=read_json_output(self.command(role,['ip','-j','address','show','dev',dev],label+'-address'))
            route=read_json_output(self.command(role,['ip','-j','route','get',peer,'from',ip],label+'-route'))
            underlay=read_json_output(self.command(role,['ip','-s','-j','link','show','dev','ovpn-u'+role[0]],label+'-underlay'))
            if len(links)!=1 or len(addresses)!=1:raise RuntimeError('ambiguous tunnel device')
            link=links[0];kind=link.get('linkinfo',{}).get('info_kind');expected='ovpn' if self.arms[role].endswith('dco') else 'tun'
            if kind!=expected:raise RuntimeError('DCO fallback or wrong tunnel type: '+str(kind)+' expected '+expected)
            if link['ifindex']!=addresses[0]['ifindex'] or not any(x.get('local')==ip for x in addresses[0]['addr_info']):raise RuntimeError('source address is not on the measured tunnel ifindex')
            if not route or any(x.get('dev')!=dev for x in route):raise RuntimeError('source-specific route does not use the tunnel')
            text=self.processes[role].text();opening='DCO device '+dev+' opened' if expected=='ovpn' else 'TUN/TAP device '+dev+' opened'
            if opening not in text:raise RuntimeError('missing actual device-open log')
            row={'ifindex':link['ifindex'],'netns_inode':os.stat('/run/netns/'+self.names[role]).st_ino,
                 'kind':kind,'link':link,'address':addresses[0],'route':route,'underlay':underlay[0]}
            if expected=='ovpn':
                path=self.folder/(label+'-'+role+'-peer.json')
                self.command(role,[sys.executable,str(HERE/'dco_peer_stats.py'),'--interface',dev,'--out',str(path)],label+'-kernel-peer')
                row['peer']=read_json(path)
                if row['peer']['ifindex']!=row['ifindex'] or row['peer']['netns_inode']!=row['netns_inode']:raise RuntimeError('netlink and link scope differ')
            result[role]=row
        save(self.folder/(label+'-paths.json'),result);return result
    def protocol_gate(self,epoch):
        self.wait_until(lambda:all(self.observation('client')['latest_initialized_session'][key]
                                  for key in ('protocol_lines','data_channel_lines')),3,'new session profile log')
        obs=self.observation('client');profile=negotiated_profile(obs,epoch)
        self.event('negotiated-profile',epoch=epoch,initializations=obs['initializations'],profile=profile)
        return obs
    def initial_session_gate(self,markers,no_rekey=False):
        observations={role:self.observation(role) for role in ROLES}
        if observations['client']['initializations']!=1:
            raise RuntimeError('behavior action is no longer in the first authenticated client session')
        for role,obs in observations.items():
            if session_marker(obs)!=markers[role]:raise RuntimeError(role+' session changed before its declared transition')
            if no_rekey and (obs['soft_resets'] or obs['peer_soft_resets'] or obs['completed_rekeys']):
                raise RuntimeError(role+' started a rekey during the declared same-epoch action')
        return observations
    def close(self):
        for job in reversed(self.jobs):
            try:job.stop()
            except Exception as e:self.result.setdefault('cleanup_errors',[]).append(repr(e))
        self.result['observations']={role:{**self.observation(role),'process':job.row} for role,job in self.processes.items()}
        for entry in reversed(self.entries):
            name=entry['name'];path=Path('/run/netns',name)
            try:
                if path.exists():
                    if os.stat(path).st_ino!=entry['inode']:raise RuntimeError('namespace identity changed before cleanup')
                    # Direct bounded subprocess: cleanup still runs after global deadline.
                    result=subprocess.run(['ip','netns','del',name],capture_output=True,text=True,timeout=5)
                    entry['delete_returncode']=result.returncode;entry['delete_stdout']=result.stdout;entry['delete_stderr']=result.stderr
                    if result.returncode:raise RuntimeError('namespace deletion failed')
                entry['active']=False
            except Exception as e:self.result.setdefault('cleanup_errors',[]).append(repr(e))
        self.l.save_owned();save(self.folder/'case.json',self.result)


def read_json_output(job):return json.loads(read_text(job.stdout))


def create_pki(ledger,binary):
    p=ledger.private/'pki';p.mkdir(mode=0o700);pub=ledger.out/'pki';pub.mkdir()
    def openssl(label,argv):return ledger.run(['openssl',*argv],label,pub,timeout=20)
    for name in ('ca','rogue-ca'):
        openssl('create-'+name,['req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=OpenVPN-HIA-'+name,
                              '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',
                              '-keyout',str(p/(name+'.key')),'-out',str(p/(name+'.crt'))])
    for name,usage,ca in (('server','serverAuth','ca'),('client','clientAuth','ca'),('untrusted','clientAuth','rogue-ca')):
        cn='OpenVPN-HIA-server' if name=='server' else 'OpenVPN-HIA-client'
        ext=p/(name+'.ext');ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\n')
        openssl('request-'+name,['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+cn,'-keyout',str(p/(name+'.key')),'-out',str(p/(name+'.csr'))])
        openssl('sign-'+name,['x509','-req','-in',str(p/(name+'.csr')),'-CA',str(p/(ca+'.crt')),'-CAkey',str(p/(ca+'.key')),
                            '-CAcreateserial','-days','2','-extfile',str(ext),'-out',str(p/(name+'.crt'))])
    ledger.run([binary,'--genkey','secret',str(p/'ta.key')],'tls-auth-key',pub)
    for key in p.glob('*.key'):key.chmod(0o600)
    for cert in p.glob('*.crt'):shutil.copyfile(cert,pub/cert.name)
    ccd=ledger.private/'ccd';ccd.mkdir();(ccd/'OpenVPN-HIA-client').write_text('ifconfig-push 10.77.0.2 255.255.255.0\n')
    common=f'proto udp4\ndev-type tun\nca {p}/ca.crt\ndata-ciphers AES-256-GCM\ntun-mtu 1400\nallow-compression no\nauth SHA256\nping 1\nping-restart 15\nreneg-bytes 0\nreneg-pkts 0\n'
    server=common+f'local 192.0.2.1\nport 1194\ndev tunbench-s\ntopology subnet\nserver 10.77.0.0 255.255.255.0 nopool\nclient-config-dir {ccd}\ncert {p}/server.crt\nkey {p}/server.key\ndh none\nverify-client-cert require\nremote-cert-tls client\ntls-auth {p}/ta.key 0\n'
    client=common+f'client\nremote 192.0.2.1 1194\nnobind\ndev tunbench-c\ncert {p}/client.crt\nkey {p}/client.key\nremote-cert-tls server\nverify-x509-name OpenVPN-HIA-server name\ntls-auth {p}/ta.key 1\nconnect-retry 1 1\nconnect-retry-max 3\nserver-poll-timeout 5\n'
    for role,text in (('server',server),('client',client)):
        (ledger.private/(role+'.conf')).write_text(text)
        # Configuration paths are public; private key bytes never leave private-work.
        (ledger.out/(role+'-common.conf')).write_text(text)
    return {'server':ledger.private/'server.conf','client':ledger.private/'client.conf',
            'untrusted_crt':p/'untrusted.crt','untrusted_key':p/'untrusted.key'}


def probe_start(pair,label,port,count=40,size=256,interval=.01,receiver_seconds=3,bind='10.77.0.2',run_id=None):
    token=run_id or uuid.uuid4().hex
    receiver_dir=pair.folder/(label+'-receiver');sender_dir=pair.folder/(label+'-sender')
    common=['--port',str(port),'--count',str(count),'--size',str(size),'--run-id',token]
    receiver=pair.spawn('server',[sys.executable,str(HERE/'payload_probe.py'),'receiver','--bind','10.77.0.1','--peer',bind,
                                 *common,'--deadline',str(receiver_seconds),'--out',str(receiver_dir)],label+'-receiver')
    pair.wait_until(lambda:(receiver_dir/'ready.json').is_file(),3,label+' receiver ready',allow_client_exit=pair.negative)
    sender=pair.spawn('client',[sys.executable,str(HERE/'payload_probe.py'),'sender','--bind',bind,'--peer','10.77.0.1',
                               *common,'--interval',str(interval),'--drain','0.6','--deadline',str(count*interval+2),
                               '--out',str(sender_dir)],label+'-sender')
    return {'receiver':receiver,'sender':sender,'receiver_dir':receiver_dir,'sender_dir':sender_dir,
            'run_id':token,'count':count,'size':size,'started_ns':time.monotonic_ns()}


def probe_finish(probe,required=True):
    probe['sender'].wait(45,required=False);probe['receiver'].wait(55,required=False)
    sender=read_json(probe['sender_dir']/'summary.json');receiver=read_json(probe['receiver_dir']/'summary.json')
    result={'run_id':probe['run_id'],'sender':sender,'receiver':receiver,
            'sender_exit':probe['sender'].proc.returncode,'receiver_exit':probe['receiver'].proc.returncode,
            'passed':bool(sender.get('passed') and receiver.get('passed') and probe['sender'].proc.returncode==0 and probe['receiver'].proc.returncode==0)}
    if required and not result['passed']:raise RuntimeError('strict payload/echo probe failed: '+probe['run_id'])
    return result


def inclusive_ranges(values):
    ordered=sorted(set(values));out=[]
    for value in ordered:
        if not out or value>out[-1][1]+1:out.append([value,value])
        else:out[-1][1]=value
    return out


def continuity_loss_receipt(probe,result):
    """Accept only a completed continuity window whose every loss/error remains explicit."""
    sender=result.get('sender',{});receiver=result.get('receiver',{});expected=probe['count']
    if result.get('run_id')!=probe['run_id'] or sender.get('run_id')!=probe['run_id'] or receiver.get('run_id')!=probe['run_id']:
        raise ValueError('continuity run identity changed')
    if sender.get('expected_count')!=expected or sender.get('send_attempts')!=expected or sender.get('all_sends_attempted') is not True:
        raise ValueError('continuity sender did not attempt the frozen sequence inventory')
    if sender.get('sent_packets',0)+sender.get('send_errors',0)!=expected:
        raise ValueError('continuity sender omitted sent or errored sequence numbers')
    if receiver.get('expected_count')!=expected or receiver.get('received_packets',0)+receiver.get('missing_count',0)!=expected:
        raise ValueError('continuity receiver omitted received or missing sequence numbers')
    if sender.get('deadline_reached') is not False or receiver.get('deadline_reached') is not True:
        raise ValueError('continuity sender/receiver did not finish their declared observation windows')
    if sender.get('stop_signal') is not None or receiver.get('stop_signal') is not None:
        raise ValueError('continuity sender/receiver was externally stopped')
    if result.get('sender_exit') not in (0,1) or result.get('receiver_exit') not in (0,1):
        raise ValueError('continuity process exit status is outside the retained-loss contract')
    if result.get('sender_exit') != (0 if sender.get('passed') is True else 1):
        raise ValueError('continuity sender exit does not match its retained summary')
    if result.get('receiver_exit') != (0 if receiver.get('passed') is True else 1):
        raise ValueError('continuity receiver exit does not match its retained summary')
    if sender.get('received_packets')!=sender.get('unique_echoes'):
        raise ValueError('continuity sender received/unique echo counters disagree')
    if receiver.get('unique_packets')!=receiver.get('received_packets') or receiver.get('valid_packets')!=receiver.get('received_packets') or receiver.get('echoed_packets')!=receiver.get('received_packets'):
        raise ValueError('continuity receiver valid/unique/echo counters disagree')
    if sender.get('duplicate_echoes')!=0 or sender.get('invalid_echoes')!=0 or sender.get('reordered_echoes')!=0 or sender.get('unexpected_peer_packets')!=0:
        raise ValueError('continuity sender observed duplicate, invalid, reordered or foreign echoes')
    if receiver.get('duplicate_packets')!=0 or receiver.get('invalid_packets')!=0 or receiver.get('reordered_packets')!=0 or receiver.get('foreign_run_packets')!=0 or receiver.get('unexpected_peer_packets')!=0:
        raise ValueError('continuity receiver observed duplicate, invalid, reordered or foreign payloads')
    sender_events_path=probe['sender_dir']/sender.get('events','')
    receiver_events_path=probe['receiver_dir']/receiver.get('events','')
    if not sender_events_path.is_file() or not receiver_events_path.is_file():
        raise ValueError('continuity event stream is missing')
    if digest(sender_events_path)!=sender.get('events_sha256') or digest(receiver_events_path)!=receiver.get('events_sha256'):
        raise ValueError('continuity event stream digest changed')
    sender_events=[json.loads(line) for line in sender_events_path.read_text().splitlines()]
    receiver_events=[json.loads(line) for line in receiver_events_path.read_text().splitlines()]
    if len(sender_events)!=sender.get('event_count') or len(receiver_events)!=receiver.get('event_count'):
        raise ValueError('continuity event count differs from its summary')
    if not sender_events or sender_events[0].get('kind')!='ready' or not receiver_events or receiver_events[0].get('kind')!='ready':
        raise ValueError('continuity event stream lacks its ready record')
    expected_set=set(range(expected))
    if sender_events[0].get('run_id')!=probe['run_id'] or receiver_events[0].get('run_id')!=probe['run_id']:
        raise ValueError('continuity ready-record run identity changed')
    sent=[row.get('sequence') for row in sender_events if row.get('kind')=='sent']
    errors=[row.get('sequence') for row in sender_events if row.get('kind')=='send_error']
    echoes=[row.get('sequence') for row in sender_events if row.get('kind')=='echo']
    payloads=[row.get('sequence') for row in receiver_events if row.get('kind')=='payload']
    if len(sent)!=sender.get('sent_packets') or len(errors)!=sender.get('send_errors') or len(echoes)!=sender.get('unique_echoes'):
        raise ValueError('continuity sender event inventory differs from its summary')
    if len(payloads)!=receiver.get('received_packets') or len(receiver_events)!=len(payloads)+1:
        raise ValueError('continuity receiver event inventory differs from its summary')
    if any(len(values)!=len(set(values)) for values in (sent,errors,echoes,payloads)):
        raise ValueError('continuity event stream contains duplicate sequence records')
    if set(sent)|set(errors)!=expected_set or set(sent)&set(errors):
        raise ValueError('continuity sender events do not partition all attempted sequences')
    if not set(echoes).issubset(set(sent)) or not set(payloads).issubset(set(sent)):
        raise ValueError('continuity echo/payload sequence lacks a successful send')
    missing_echo=expected_set-set(echoes);missing_payload=expected_set-set(payloads)
    if sender.get('missing_echo_count')!=len(missing_echo) or sender.get('missing_echo_ranges_inclusive')!=inclusive_ranges(missing_echo):
        raise ValueError('continuity sender missing-echo ranges are not fully retained')
    if receiver.get('missing_count')!=len(missing_payload) or receiver.get('missing_ranges_inclusive')!=inclusive_ranges(missing_payload):
        raise ValueError('continuity receiver missing-payload ranges are not fully retained')
    if not set(errors).issubset(missing_echo) or not set(errors).issubset(missing_payload):
        raise ValueError('continuity send errors are not represented in both missing inventories')
    if any(not isinstance(row.get('error'),str) or not row['error'] for row in sender_events if row.get('kind')=='send_error'):
        raise ValueError('continuity send error lacks its exact error text')
    if any(row.get('bytes')!=probe['size'] for row in sender_events if row.get('kind')=='sent'):
        raise ValueError('continuity sent payload size changed')
    if any(row.get('duplicate') is not False or row.get('reordered') is not False
           for row in sender_events if row.get('kind')=='echo'):
        raise ValueError('continuity sender echo event is duplicate or reordered')
    if any(row.get('duplicate') is not False or row.get('reordered') is not False or row.get('bytes')!=probe['size']
           for row in receiver_events if row.get('kind')=='payload'):
        raise ValueError('continuity receiver payload event is malformed')
    sender_clean=not missing_echo and not errors and sender.get('passed') is True
    receiver_clean=not missing_payload and receiver.get('passed') is True
    if sender.get('passed') is not sender_clean or receiver.get('passed') is not receiver_clean:
        raise ValueError('continuity pass flags disagree with the retained loss inventory')
    if result.get('passed') is not bool(sender_clean and receiver_clean and result.get('sender_exit')==0 and result.get('receiver_exit')==0):
        raise ValueError('continuity aggregate pass flag disagrees with its component receipts')
    return True


def strict_probe(pair,label,port):
    before=pair.snapshot(label+'-before')
    probe=probe_start(pair,label,port)
    result=probe_finish(probe)
    after=pair.snapshot(label+'-after')
    result['path_delta']=path_delta(before,after)
    save(pair.folder/(label+'-result.json'),result);return result


def inject(pair,capture,old_receiver,label,mode,traffic_sender=None):
    if old_receiver.proc.poll() is not None:raise RuntimeError('old-payload receiver is no longer alive before '+label)
    spec=importlib.util.spec_from_file_location('encrypted_packet_helper',HERE/'encrypted_capture.py')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    captured=read_json(capture)
    frame=Path(capture).with_name('frame.bin').read_bytes()
    if hashlib.sha256(frame).hexdigest()!=captured['frame_sha256']:
        raise RuntimeError('original ciphertext capture changed before injection')
    expected=hashlib.sha256(helper.parse_frame(helper.submitted_frame(frame,mode))['payload']).hexdigest()
    witness_dir=pair.folder/(label+'-witness')
    witness=pair.spawn('server',[sys.executable,str(HERE/'encrypted_capture.py'),'witness','--interface','ovpn-us',
                      '--src','192.0.2.2','--dst','192.0.2.1','--dport','1194','--ciphertext-sha256',expected,
                      '--deadline','3','--out',str(witness_dir)],label+'-witness')
    pair.wait_until(lambda:(witness_dir/'ready.json').is_file(),3,label+' exact incoming witness ready')
    dco_server=pair.arms['server'].endswith('dco')
    traffic_pause=None
    if dco_server and traffic_sender is not None:
        if traffic_sender.proc.poll() is None:
            stop_ns=time.monotonic_ns()
            traffic_sender.signal(signal.SIGSTOP)
            pair.l.pause(.05)
            traffic_pause={'paused':True,'sender_label':traffic_sender.label,'stop_monotonic_ns':stop_ns}
        else:
            finished=traffic_sender.finish()
            completion=continuity_sender_completion(finished)
            traffic_pause={'paused':False,'sender_finished_before':True,'sender_label':traffic_sender.label,
                           **completion,'observed_finished_monotonic_ns':time.monotonic_ns()}
    server_before=pair.observation('server')
    server_line_before=len(pair.processes['server'].text().splitlines())
    dco_before=None;dco_before_path=None;dco_before_command=None
    if dco_server:
        dco_before_path=pair.folder/(label+'-dco-peer-before.json')
        dco_before_command=pair.command('server',[sys.executable,str(HERE/'dco_peer_stats.py'),'--interface','tunbench-s',
                                      '--out',str(dco_before_path)],label+'-dco-peer-before')
        dco_before=read_json(dco_before_path)
        dco_device_before_command=pair.command('server',['ip','-d','-s','-j','link','show','dev','tunbench-s'],
                                             label+'-dco-device-before')
        dco_device_before=read_json_output(dco_device_before_command)
    out=pair.folder/label
    row=pair.command('client',[sys.executable,str(HERE/'encrypted_capture.py'),'inject','--interface','ovpn-uc',
                              '--capture',str(capture),'--mode',mode,'--count','1','--out',str(out)],label+'-submit')
    metadata=read_json(out/'result.json')
    if metadata.get('status')!='injection_submitted':raise RuntimeError('encrypted injection was not submitted')
    if metadata.get('submitted_ciphertext_sha256')!=expected:raise RuntimeError('submission differs from expected encrypted datagram')
    witness.wait(4);arrival=read_json(witness_dir/'result.json')
    if not (arrival.get('status')=='captured' and arrival.get('direction')=='incoming'
            and arrival.get('exact_ciphertext_match') is True and arrival.get('ciphertext_sha256')==expected
            and all(arrival.get('outer_checksums',{}).get(k) is True for k in ('ipv4_valid','udp_present','udp_valid'))):
        raise RuntimeError('peer did not witness the exact valid outer datagram')
    if arrival['monotonic_ns']<metadata['submissions'][0]['monotonic_ns']:
        raise RuntimeError('peer witness predates controlled injection')
    packet_peer_id=arrival.get('datagram',{}).get('peer_id')
    if dco_server and packet_peer_id is None:
        raise RuntimeError('DCO encrypted witness lacks a parsed OpenVPN data-v2 peer ID')
    pair.l.pause(.2)
    reason=None
    if label.startswith('same-epoch') and not dco_server:
        reason='replay_rejections' if mode=='replay' else 'tag_rejections'
        pair.wait_until(lambda:pair.observation('server')[reason]>server_before[reason],2,label+' fresh userspace rejection log')
    dco_peer_rejection=None
    if dco_server:
        dco_after_path=pair.folder/(label+'-dco-peer-after.json')
        dco_after_command=pair.command('server',[sys.executable,str(HERE/'dco_peer_stats.py'),'--interface','tunbench-s',
                                     '--out',str(dco_after_path)],label+'-dco-peer-after')
        dco_after=read_json(dco_after_path)
        dco_device_after_command=pair.command('server',['ip','-d','-s','-j','link','show','dev','tunbench-s'],
                                              label+'-dco-device-after')
        dco_device_after=read_json_output(dco_device_after_command)
        device_delta=dco_device_drop_delta(dco_device_before,dco_device_after)
        active_peer_id=dco_before['peers'][0]['peer_id']
        allow_stale_peer_id=(label=='after-reconnect-replay' and mode=='replay')
        delta=dco_rejection_delta(dco_before,dco_after,packet_peer_id=packet_peer_id,
                                  allow_stale_peer_id=allow_stale_peer_id,
                                  device_drop_delta=device_delta)
        stale_peer_unaccounted=(allow_stale_peer_id and packet_peer_id!=active_peer_id)
        observation_end=time.monotonic_ns()
        if traffic_pause and traffic_pause.get('paused'):
            resume_ns=time.monotonic_ns()
            traffic_sender.signal(signal.SIGCONT)
            traffic_pause['resume_monotonic_ns']=resume_ns
        dco_peer_rejection={
            'verified':True,'interface':'tunbench-s',
            'before_path':str(dco_before_path.relative_to(pair.l.out)),
            'before_sha256':digest(dco_before_path),
            'after_path':str(dco_after_path.relative_to(pair.l.out)),
            'after_sha256':digest(dco_after_path),
            'before_command':dco_before_command.row,'after_command':dco_after_command.row,
            'device_before_path':str(dco_device_before_command.stdout.relative_to(pair.l.out)),
            'device_before_sha256':digest(dco_device_before_command.stdout),
            'device_after_path':str(dco_device_after_command.stdout.relative_to(pair.l.out)),
            'device_after_sha256':digest(dco_device_after_command.stdout),
            'device_netns_inode':os.stat('/run/netns/'+pair.names['server']).st_ino,
            'device_before_command':dco_device_before_command.row,
            'device_after_command':dco_device_after_command.row,
            'device_delta':device_delta,
            'packet_peer_id':packet_peer_id,'active_peer_id':active_peer_id,
            'peer_accounting':'stale-peer-id-unaccounted' if stale_peer_unaccounted else 'active-peer-link-rx',
            'delta':delta,'traffic_sender_pause':traffic_pause,
            'scope':('exact prior-session data-v2 peer ID reached the server underlay; DCO device RX-dropped advanced once while active peer counters and VPN-facing RX stayed unchanged; no crypto drop reason is inferred'
                     if stale_peer_unaccounted else
                     'per-injection DCO peer link RX advanced and device RX-dropped advanced once while VPN-facing peer/device RX stayed unchanged; no crypto drop reason is inferred')
        }
    else:
        observation_end=time.monotonic_ns()
    if old_receiver.proc.poll() is not None:
        raise RuntimeError('old-payload receiver ended before exact arrival and rejection observation completed')
    server_after=pair.observation('server')
    rejection_lines=pair.processes['server'].text().splitlines()[server_line_before:]
    result={'submission':metadata,'peer_exact_witness':arrival,'expected_ciphertext_sha256':expected,
            'old_receiver_alive_before_and_after_observation':True,'observation_finished_monotonic_ns':observation_end,
            'injection_command':row.row,'witness_command':witness.row,
            'server_log_start_line':server_line_before+1,'server_log_observed_lines':rejection_lines,
            'userspace_rejection_counter':reason,
            'userspace_rejection_counter_before':server_before.get(reason) if reason else None,
            'userspace_rejection_counter_after':server_after.get(reason) if reason else None,
            'dco_peer_rejection':dco_peer_rejection,
            'scope':'exact encrypted datagram witnessed on peer ingress; complete old-payload receiver decides whether duplicate/corrupt plaintext was delivered; DCO Netlink deltas separately prove link RX without VPN RX'}
    pair.event(label,mode=mode,output=str(out.relative_to(pair.l.out)))
    save(pair.folder/(label+'-evidence.json'),result);return result

def run_behavior(pair,plan,epoch):
    pair.connected();pair.protocol_gate(epoch)
    markers={role:session_marker(pair.observation(role)) for role in ROLES}
    pair.initial_session_gate(markers,no_rekey=True)
    before=pair.snapshot('initial')
    spec=plan['behavior']
    capture_dir=pair.folder/'capture-old'
    capture=pair.spawn('client',[sys.executable,str(HERE/'encrypted_capture.py'),'capture','--interface','ovpn-uc',
                                 '--src','192.0.2.2','--dst','192.0.2.1','--dport','1194','--min-data-bytes','284',
                                 '--deadline','10','--out',str(capture_dir)],'capture-old')
    pair.wait_until(lambda:(capture_dir/'ready.json').is_file(),3,'encrypted capture ready')
    old=probe_start(pair,'old-payload',51000,count=spec['strict_probe_count'],size=spec['strict_probe_size'],
                    interval=spec['strict_probe_interval_seconds'],receiver_seconds=spec['old_receiver_seconds'])
    old['sender'].wait(4)
    original_sender=read_json(old['sender_dir']/'summary.json')
    if not original_sender.get('passed'):raise RuntimeError('captured old payload was not delivered and echoed before replay')
    capture.wait(10);captured=read_json(capture_dir/'result.json')
    if captured.get('status')!='captured':raise RuntimeError('no actual encrypted data capture')
    pair.result['initial_payload_sender']=original_sender
    injections=[]
    pair.event('same-epoch-before',observations=pair.initial_session_gate(markers,no_rekey=True))
    injections.append(inject(pair,capture_dir/'result.json',old['receiver'],'same-epoch-replay','replay'))
    pair.initial_session_gate(markers,no_rekey=True)
    injections.append(inject(pair,capture_dir/'result.json',old['receiver'],'same-epoch-flip','flip'))
    pair.event('same-epoch-after',observations=pair.initial_session_gate(markers,no_rekey=True))
    # At this point the only long data records were the successful first probe;
    # start the separate continuous flow only after that capture is fixed.
    continuous=probe_start(pair,'continuity',51001,count=spec['continuous_count'],interval=spec['continuous_interval_seconds'],
                           receiver_seconds=spec['continuous_receiver_seconds'])
    pair.wait_until(lambda:all(pair.observation(role)['completed_rekeys']>=spec['required_completed_rekeys_before_replay'] for role in ROLES),
                    28,'two completed TLS/key rekeys before old-ciphertext replay')
    pair.event('completed-rekeys',observations=pair.initial_session_gate(markers))
    pair.result['post_rekey_payload']=strict_probe(pair,'after-rekey-valid',51002)
    pair.initial_session_gate(markers)
    injections.append(inject(pair,capture_dir/'result.json',old['receiver'],'after-rekey-replay','replay',continuous['sender']))
    injections.append(inject(pair,capture_dir/'result.json',old['receiver'],'after-rekey-flip','flip',continuous['sender']))
    pair.initial_session_gate(markers)
    pair.result['pre_reconnect_path_delta']=path_delta(before,pair.snapshot('before-reconnect'))
    init_count=pair.observation('client')['initializations'];line_count=len(pair.processes['client'].text().splitlines())
    pair.event('SIGUSR1-requested',previous_client_initializations=init_count)
    pair.processes['client'].signal(signal.SIGUSR1)
    pair.wait_until(lambda:pair.observation('client')['initializations']>init_count,10,'new initialization after SIGUSR1')
    suffix='\n'.join(pair.processes['client'].text().splitlines()[line_count:])
    if 'SIGUSR1[hard,' not in suffix or 'Initialization Sequence Completed' not in suffix:
        raise RuntimeError('reconnect success is not ordered after requested hard signal')
    pair.protocol_gate(epoch)
    pair.result['post_reconnect_payload']=strict_probe(pair,'after-reconnect-valid',51003)
    injections.append(inject(pair,capture_dir/'result.json',old['receiver'],'after-reconnect-replay','replay',continuous['sender']))
    pair.result['injections']=injections
    pair.result['continuity']=probe_finish(continuous,required=False)
    cont=pair.result['continuity']
    if not continuity_loss_receipt(continuous,cont):
        raise RuntimeError('continuous payload loss/error inventory is incomplete or its observation window ended early')
    pair.result['old_payload_final']=probe_finish(old)
    if pair.result['old_payload_final']['receiver']['finished_monotonic_ns']<=max(
            item['observation_finished_monotonic_ns'] for item in injections):
        raise RuntimeError('old receiver final receipt does not cover every injection observation window')
    pair.result['checks'].update(real_tunnel_payload=True,source_specific_routes=True,
          captured_previously_delivered_ciphertext=True,old_receiver_alive_for_all_injections=True,
          no_replayed_or_corrupted_payload_delivery=True,rekey_then_fresh_payload=True,reconnect_then_fresh_payload=True,
          negotiated_profile_matches=True)
    pair.result['negotiated_epoch']=epoch
    observations={r:pair.observation(r) for r in ROLES}
    # DCO rejects in kernel; without a kernel error reason, do not relabel a
    # rejected old record as a proven AEAD-tag or replay-window error.
    if not pair.arms['server'].endswith('dco'):
        if observations['server']['replay_rejections']<1 or observations['server']['tag_rejections']<1:
            raise RuntimeError('userspace server lacks same-epoch replay/tag rejection logs')
        pair.result['rejection_scope']='userspace same-epoch replay and tag errors logged; old-session records not delivered after transitions'
    else:
        pair.result['rejection_scope']='actual kernel DCO path, controlled encrypted reinjection and no duplicate/corrupt payload delivery; per-rejection kernel cause not inferred from byte counters'
    pair.result['checks']['continuity_all_losses_retained']=True


def run_negative(pair,plan):
    spec=plan['behavior']
    # A multi-client server initializes its actual device before accepting any
    # peer. This is distinct from a client completing authentication.
    pair.wait_until(lambda:pair.observation('server')['initializations']>=1,10,'negative server ready',allow_client_exit=True)
    probe=probe_start(pair,'blocked-payload-attempts',51100,count=spec['negative_probe_count'],
                      receiver_seconds=spec['negative_deadline_seconds'],bind='192.0.2.2')
    pair.wait_until(lambda:bool(pair.observation('server')['certificate_error_lines']),spec['negative_deadline_seconds'],
                    'explicit untrusted client certificate rejection',allow_client_exit=True)
    result=probe_finish(probe,required=False)
    link_state=read_json_output(pair.command('client',['ip','-j','address','show'],'negative-client-addresses'))
    route_attempt=pair.command('client',['ip','-j','route','get','10.77.0.1','from','192.0.2.2'],'negative-route',required=False)
    observations={r:pair.observation(r) for r in ROLES}
    errors=observations['server']['certificate_error_lines']
    checks={'explicit_untrusted_chain_error':any(any(token in line for token in ('unable to get local issuer certificate','self-signed certificate','unable to verify the first certificate')) for line in errors),
            'client_never_initialized':observations['client']['initializations']==0,
            'client_has_no_tunnel_address':not any(a.get('local')=='10.77.0.2' for row in link_state for a in row.get('addr_info',[])),
            'sender_attempted_all_declared_payloads':result['sender']['send_attempts']==spec['negative_probe_count'],
            'no_payload_received':result['receiver']['received_packets']==0,
            'server_stayed_alive':pair.processes['server'].proc.poll() is None,
            'no_plaintext_route_to_bypass_vpn':route_attempt.proc.returncode!=0}
    pair.result.update(checks=checks,negative_payload=result,negative_client_addresses=link_state,
         rejection_scope='untrusted client certificate was rejected; client acquired no VPN address; real underlay-bound attempts to VPN destination had no route and delivered zero payload')
    if not all(checks.values()):raise RuntimeError('negative certificate/payload gate failed')


def cpu_snapshot(cpus):
    rows={}
    for line in Path('/proc/stat').read_text().splitlines():
        parts=line.split()
        if parts and parts[0] in ['cpu'+str(c) for c in cpus]:rows[parts[0]]=list(map(int,parts[1:]))
    return rows


def numeric_fields(value,path='end'):
    output={}
    if isinstance(value,dict):
        for key,item in value.items():output.update(numeric_fields(item,path+'.'+str(key)))
    elif isinstance(value,list):
        for i,item in enumerate(value):output.update(numeric_fields(item,path+'['+str(i)+']'))
    elif isinstance(value,(int,float)) and not isinstance(value,bool):output[path]=value
    return output


def received_candidates(document):
    values=numeric_fields(document.get('end',{}))
    return {k:v for k,v in values.items() if k.endswith('.bytes') and ('sum_received' in k or '.receiver.' in k)}


def local_bidir_receiver(document,role):
    """iperf3 names the server-to-client half *_bidir_reverse on both ends.

    Read each receiving endpoint's own result, never a sender's copy of the
    other endpoint's statistics. See ESnet iperf 3.16 iperf_api.c summary logic.
    """
    if document.get('start',{}).get('test_start',{}).get('bidir')!=1:
        raise ValueError(role+' did not report an actual bidirectional test')
    key='sum_received_bidir_reverse' if role=='client' else 'sum_received'
    row=document.get('end',{}).get(key)
    if not isinstance(row,dict):raise ValueError(role+' lacks its local receiver summary '+key)
    for field in ('bytes','seconds','bits_per_second'):
        value=row.get(field)
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<=0:
            raise ValueError(role+' local receiver has no finite positive '+field)
    if row.get('sender') is not False:raise ValueError(role+' summary is not a local receiving stream')
    return {'json_path':'end.'+key,'direction':'server-to-client' if role=='client' else 'client-to-server',
            'local_receiving_role':role,**row}


def iperf_rate_bps(value):
    """Parse the decimal K/M/G rate syntax passed to iperf3 --bitrate."""
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)([KMG])', str(value))
    if not match:
        raise ValueError('unsupported iperf offered-rate syntax')
    scale = {'K': 1_000, 'M': 1_000_000, 'G': 1_000_000_000}[match.group(2)]
    rate = float(match.group(1)) * scale
    if not math.isfinite(rate) or rate <= 0:
        raise ValueError('offered rate must be finite and positive')
    return rate


def udp_delivery_evidence(workload, client_document, client_receiver, server_receiver, policy):
    """Require both UDP send directions to offer the declared load and both receivers to sustain it."""
    if workload.get('transport') != 'udp':
        raise ValueError('UDP delivery evidence requested for a non-UDP workload')
    offered = iperf_rate_bps(workload.get('offered_rate_each_direction'))
    fraction = policy.get('minimum_offered_rate_fraction')
    max_loss = policy.get('maximum_receiver_loss_percent')
    if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not math.isfinite(fraction) or not 0 < fraction <= 1:
        raise ValueError('minimum offered-rate fraction must be finite and in (0, 1]')
    if isinstance(max_loss, bool) or not isinstance(max_loss, (int, float)) or not math.isfinite(max_loss) or not 0 <= max_loss <= 100:
        raise ValueError('maximum receiver loss percent must be finite and in [0, 100]')
    end = client_document.get('end', {})
    senders = {
        'client_to_server': end.get('sum_sent'),
        'server_to_client': end.get('sum_sent_bidir_reverse'),
    }
    receivers = {
        'client_to_server': server_receiver,
        'server_to_client': client_receiver,
    }
    minimum = offered * fraction
    directions = {}
    for name in ('client_to_server', 'server_to_client'):
        sender = senders[name]
        receiver = receivers[name]
        if not isinstance(sender, dict) or sender.get('sender') is not True:
            raise ValueError(name + ' lacks an explicit iperf sender summary')
        if not isinstance(receiver, dict) or receiver.get('sender') is not False:
            raise ValueError(name + ' lacks a local iperf receiver summary')
        sender_rate = sender.get('bits_per_second')
        receiver_rate = receiver.get('bits_per_second')
        loss = receiver.get('lost_percent')
        for field, value in (('sender rate', sender_rate), ('receiver rate', receiver_rate),
                             ('receiver loss', loss)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError(name + ' has invalid ' + field)
        if sender_rate <= 0 or receiver_rate <= 0 or not 0 <= loss <= 100:
            raise ValueError(name + ' has non-positive rate or out-of-range loss')
        directions[name] = {
            'sender_bps': sender_rate,
            'receiver_bps': receiver_rate,
            'lost_percent': loss,
        }
    checks = {
        'offered_rate_met': all(item['sender_bps'] >= minimum for item in directions.values()),
        'receiver_rate_met': all(item['receiver_bps'] >= minimum for item in directions.values()),
        'loss_within_limit': all(item['lost_percent'] <= max_loss for item in directions.values()),
    }
    failures = []
    for name, item in directions.items():
        if item['sender_bps'] < minimum:
            failures.append(f'{name} sender offered {item["sender_bps"]:.3f} bps below {minimum:.3f} bps')
        if item['receiver_bps'] < minimum:
            failures.append(f'{name} receiver delivered {item["receiver_bps"]:.3f} bps below {minimum:.3f} bps')
        if item['lost_percent'] > max_loss:
            failures.append(f'{name} receiver loss {item["lost_percent"]:.6f}% exceeds {max_loss:.6f}%')
    return {
        'offered_rate_bps': offered,
        'minimum_rate_bps': minimum,
        'minimum_offered_rate_fraction': fraction,
        'maximum_receiver_loss_percent': max_loss,
        'directions': directions,
        'checks': checks,
        'passed': all(checks.values()),
        'failures': failures,
    }


def profile_record_argv(perf, cpus, output, seconds, profile):
    """Build perf record from the frozen profile budget; never silently use defaults."""
    if not isinstance(profile, dict):
        raise ValueError("profile sampling configuration is required")
    frequency = profile.get("frequency_hz")
    call_graph = profile.get("call_graph")
    if type(seconds) is not int or seconds <= 0:
        raise ValueError("profile duration must be a positive integer")
    if type(frequency) is not int or not 1 <= frequency <= 1000:
        raise ValueError("profile frequency must be an integer in [1, 1000]")
    if not isinstance(call_graph, str) or not call_graph:
        raise ValueError("profile call graph must be a non-empty string")
    if not isinstance(cpus, (list, tuple)) or len(cpus) != 2 or len(set(cpus)) != 2:
        raise ValueError("profile sampling requires two distinct selected CPUs")
    return [str(perf), "record", "--all-cpus", "--cpu", ",".join(map(str, cpus)),
            "--freq", str(frequency), "--event", "cpu-clock", "--call-graph", call_graph,
            "--output", str(output), "--", "sleep", str(seconds + 1)]


def throughput(pair,workload,seconds,cpus,label,perf=None,udp_acceptance=None,record_grace_seconds=15,profile_config=None):
    output=pair.folder/(label+'-measurement.json')
    result={'workload':workload,'bidirectional':True,'duration_requested_seconds':seconds,'omit_seconds':0,
            'status':'started','passed':False,'checks':{},'failures':[],
            'started_monotonic_ns':time.monotonic_ns(),
            'process_cpu_scope':'OpenVPN process user/system ticks only; kernel offload and generators also appear in host CPU totals',
            'host_cpu_scope':'all activity on assigned vCPUs, including traffic generators, softirq and runner background work; not exclusive OpenVPN attribution'}
    pair.result.setdefault('measurements',[]).append(result);save(output,result)
    server=client=perf_job=None;perf_file=None;before=after=None
    cpu_before={};cpu_after={};maxrss={};started=None;deadline_error=None
    def failure(stage,exc):result['failures'].append({'stage':stage,'failure':repr(exc)})
    try:
        server=pair.spawn('server',['taskset','-c',str(cpus[0]),'iperf3','-4','--server','--one-off','--json','--bind','10.77.0.1','--port','5201'],label+'-iperf-server')
        before=pair.snapshot(label+'-before');result['path_before']=before
        result['tls_sessions_before']={role:session_marker(pair.observation(role)) for role in ROLES}
        cpu_before={r:process_stats(pair.processes[r].proc.pid) for r in ROLES}
        result['host_cpu_ticks_before']=cpu_snapshot(cpus);maxrss={r:cpu_before[r]['rss_bytes'] for r in ROLES}
        command=['taskset','-c',str(cpus[1]),'iperf3','-4','--client','10.77.0.1','--bind','10.77.0.2','--port','5201',
                 '--json','--time',str(seconds),'--bidir','--parallel','1','--connect-timeout','3000']
        if workload['transport']=='udp':command+=['--udp','--length',str(workload['payload_bytes']),'--bitrate',workload['offered_rate_each_direction']]
        if perf:
            perf_folder=pair.l.private/'perf'/pair.case;perf_folder.mkdir(parents=True,exist_ok=True)
            perf_file=perf_folder/(label+'.perf.data')
            if not isinstance(profile_config, dict):
                raise ValueError('perf recording requires the frozen profile sampling configuration')
            perf_job=Job(pair.l,label+'-perf-record',
                         profile_record_argv(perf,cpus,perf_file,seconds,profile_config),pair.folder)
            pair.jobs.append(perf_job)
        started=time.monotonic();result['traffic_started_monotonic_ns']=time.monotonic_ns()
        client=pair.spawn('client',command,label+'-iperf-client')
        def monitor():
            for role in ROLES:
                if pair.processes[role].proc.poll() is not None:raise RuntimeError(role+' OpenVPN died during traffic')
                maxrss[role]=max(maxrss[role],process_stats(pair.processes[role].proc.pid)['rss_bytes'])
        client.wait(seconds+12,required=False,monitor=monitor);server.wait(5,required=False)
        result['elapsed_seconds']=time.monotonic()-started
        result['traffic_finished_monotonic_ns']=time.monotonic_ns()
        cpu_after={r:process_stats(pair.processes[r].proc.pid) for r in ROLES}
        result['host_cpu_ticks_after']=cpu_snapshot(cpus)
        after=pair.snapshot(label+'-after');result['path_after']=after
        result['path_delta']=path_delta(before,after);result['checks']['actual_tunnel_and_kernel_counter_progress']=True
        result['tls_sessions_after']={role:session_marker(pair.observation(role)) for role in ROLES}
        result['checks']['same_authenticated_sessions']=result['tls_sessions_before']==result['tls_sessions_after']
    except Exception as exc:
        failure('traffic-and-path',exc)
        if isinstance(exc,Deadline):deadline_error=exc
    finally:
        # Even malformed JSON, failed counter queries, early process death and
        # deadlines retain a concrete measurement receipt and partial CPU data.
        for role,job in (('client',client),('server',server)):
            if not job:continue
            try:
                if not job.finished:job.stop()
                result[role+'_process']=job.row
                result['checks'][role+'_process_succeeded']=job.row.get('exit_code')==0 and not job.row.get('timed_out')
                document=json.loads(read_text(job.stdout));result[role+'_iperf']=document
                result[role+'_numeric_end_fields']=numeric_fields(document.get('end',{}))
                result[role+'_received_byte_candidates']=received_candidates(document)
                if document.get('error'):raise RuntimeError(role+' iperf error: '+str(document['error']))
                result[role+'_local_receiver']=local_bidir_receiver(document,role)
                result['checks'][role+'_received_its_direction']=True
            except Exception as exc:failure(role+'-receipt',exc)
        if workload.get('transport') == 'udp':
            try:
                evidence = udp_delivery_evidence(
                    workload, result['client_iperf'], result['client_local_receiver'],
                    result['server_local_receiver'], udp_acceptance)
                result['udp_delivery'] = evidence
                result['checks'].update(
                    udp_offered_rate_met=evidence['checks']['offered_rate_met'],
                    udp_receiver_rate_met=evidence['checks']['receiver_rate_met'],
                    udp_loss_within_limit=evidence['checks']['loss_within_limit'])
                if not evidence['passed']:
                    failure('udp-delivery-acceptance', RuntimeError('; '.join(evidence['failures'])))
            except Exception as exc:
                result['udp_delivery'] = {'passed': False, 'failures': [repr(exc)]}
                result['checks'].update(udp_offered_rate_met=False,
                    udp_receiver_rate_met=False, udp_loss_within_limit=False)
                failure('udp-delivery-acceptance', exc)
        if started is not None and 'elapsed_seconds' not in result:
            result['elapsed_seconds']=time.monotonic()-started
            result['traffic_finished_monotonic_ns']=time.monotonic_ns()
        for role in ROLES:
            if role not in cpu_after:
                try:cpu_after[role]=process_stats(pair.processes[role].proc.pid)
                except Exception as exc:failure(role+'-final-process-cpu',exc)
        result['process_cpu_ticks_before']=cpu_before;result['process_cpu_ticks_after']=cpu_after
        result['process_cpu_seconds']={}
        for role in ROLES:
            if role not in cpu_before or role not in cpu_after:continue
            a,b=cpu_before[role],cpu_after[role]
            try:
                if a['starttime_ticks']!=b['starttime_ticks']:raise ValueError('OpenVPN PID identity changed')
                if b['user_ticks']<a['user_ticks'] or b['system_ticks']<a['system_ticks']:raise ValueError('process CPU counters reset')
                result['process_cpu_seconds'][role]={'user':(b['user_ticks']-a['user_ticks'])/os.sysconf('SC_CLK_TCK'),
                   'system':(b['system_ticks']-a['system_ticks'])/os.sysconf('SC_CLK_TCK'),
                   'maximum_sampled_rss_bytes':max(maxrss.get(role,0),b['rss_bytes'])}
            except Exception as exc:failure(role+'-cpu-delta',exc)
        if 'host_cpu_ticks_after' not in result:
            try:result['host_cpu_ticks_after']=cpu_snapshot(cpus)
            except Exception as exc:failure('host-cpu-after',exc)
        result['checks']['both_openvpn_cpu_receipts']=len(result['process_cpu_seconds'])==2
        if perf:
            profile={'passed':False,'raw_stack_file_published':False,
                     'sampling':{'frequency_hz':profile_config['frequency_hz'],
                                 'duration_seconds':seconds,'call_graph':profile_config['call_graph']},
                     'scope':'system-wide sampling on the two test vCPUs; includes kernel/shared VM activity; only bounded symbol fields published; raw DWARF stack memory is private and deleted'}
            result['profile']=profile
            try:
                if not perf_job:raise RuntimeError('perf record was never started')
                profile['record']=wait_for_profile_recorder(perf_job,seconds,record_grace_seconds)
                profile['data_sha256']=digest(perf_file) if perf_file.exists() else None
                report=pair.l.run([str(perf),'report','--stdio','--no-children','--sort','comm,dso,symbol','--input',str(perf_file)],label+'-perf-report',pair.folder,timeout=30,required=False)
                samples=pair.l.run([sys.executable,'-B',HERE/'perf_sample_summary.py',
                                    '--perf',str(perf),'--input',str(perf_file),
                                    '--client-pid',str(pair.processes['client'].proc.pid),
                                    '--server-pid',str(pair.processes['server'].proc.pid)],
                                   label+'-perf-samples',pair.folder,timeout=30,required=False)
                profile.update(report=report.row,samples=samples.row)
                summary=json.loads(read_text(samples.stdout))
                if summary.get('schema')!='hepta.openvpn-hia.perf-sample-summary.v1':
                    raise RuntimeError('perf sample summary schema mismatch')
                if summary.get('raw_sample_content_published') is not False:
                    raise RuntimeError('raw perf sample stacks must remain private')
                profile.update(actual_samples_present=bool(
                        summary.get('sample_headers') and samples.proc.returncode==0
                        and summary.get('perf_exit_code')==0 and summary.get('perf_timed_out') is False),
                     actual_sample_headers=summary.get('sample_headers',0),
                     openvpn_sample_headers_by_role=summary.get('openvpn_sample_headers_by_role',{}),
                     kernel_symbol_lines=summary.get('kernel_symbol_lines',0),
                     ovpn_symbol_lines=summary.get('ovpn_symbol_lines',0),
                     raw_sample_content_published=False,
                     raw_samples_sha256=summary.get('raw_stdout_sha256'),
                     raw_samples_bytes=summary.get('raw_stdout_bytes'))
                report_text=read_text(report.stdout)
                hia_symbols=hia_profile_symbol_lines(report_text)
                profile['hia_profile_symbol_lines']=hia_symbols
                required_process_visible=(not profile_process_sample_required(pair.arms['client'])
                                            or profile['openvpn_sample_headers_by_role']['client']>0)
                required_hia_hotspot=(pair.arms['client']!='hia-user' or hia_symbols==2)
                profile['passed']=bool(perf_job.proc.returncode==0 and report.proc.returncode==0 and samples.proc.returncode==0
                                       and summary.get('sample_headers') and summary.get('kernel_symbol_lines') and required_process_visible and required_hia_hotspot)
            except Exception as exc:
                if perf_job and not perf_job.finished:
                    try:perf_job.stop();profile['record']=perf_job.row
                    except Exception as stop_exc:failure('perf-stop',stop_exc)
                failure('profile',exc)
                if isinstance(exc,Deadline):deadline_error=exc
            if perf_file and perf_file.exists():
                try:profile['data_sha256']=digest(perf_file)
                except Exception as exc:failure('private-profile-hash',exc)
            result['checks']['actual_process_kernel_profile']=profile['passed']
        required={'actual_tunnel_and_kernel_counter_progress','client_process_succeeded','server_process_succeeded',
                  'client_received_its_direction','server_received_its_direction','both_openvpn_cpu_receipts','same_authenticated_sessions'}
        if perf:required.add('actual_process_kernel_profile')
        result['passed']=not result['failures'] and all(result['checks'].get(key) is True for key in required)
        result['status']='completed' if result['passed'] else 'failed'
        result['finished_monotonic_ns']=time.monotonic_ns();save(output,result)
    if deadline_error:raise deadline_error
    return result


def cleanup_state(path):
    state=read_json(path)
    if state.get('schema')!='hepta.openvpn-hia.owned-namespaces.v1':raise ValueError('unrecognized namespace ownership record')
    if state.get('host_boot_id')!=read_text('/proc/sys/kernel/random/boot_id').strip():raise ValueError('ownership record belongs to a different boot')
    results=[]
    for entry in reversed(state['namespaces']):
        if not entry.get('active'):continue
        name=entry['name'];row={'name':name,'passed':False};results.append(row)
        try:
            if not re.fullmatch(r'ohia-[0-9a-f]{10}-[sc]',name):raise ValueError('unexpected owned namespace name')
            ns=Path('/run/netns',name)
            if not ns.exists():row['already_absent']=True;row['passed']=True;entry['active']=False;continue
            if os.stat(ns).st_ino!=entry['inode']:raise ValueError('namespace inode no longer matches the owned resource')
            listing=subprocess.run(['ip','netns','pids',name],capture_output=True,text=True,timeout=5,check=True)
            pids=[int(x) for x in listing.stdout.split()]
            row['recorded_namespace_pids']=pids
            for pid in pids:
                proc_ns=Path('/proc',str(pid),'ns/net')
                if proc_ns.exists() and os.stat(proc_ns).st_ino==entry['inode']:os.kill(pid,signal.SIGTERM)
            time.sleep(.1)
            for pid in pids:
                proc_ns=Path('/proc',str(pid),'ns/net')
                if proc_ns.exists() and os.stat(proc_ns).st_ino==entry['inode']:os.kill(pid,signal.SIGKILL)
            deletion=subprocess.run(['ip','netns','del',name],capture_output=True,text=True,timeout=5)
            row.update(exit_code=deletion.returncode,stdout=deletion.stdout,stderr=deletion.stderr)
            row['passed']=deletion.returncode==0 and not ns.exists()
            if row['passed']:entry['active']=False
        except Exception as exc:row['failure']=repr(exc)
    save(path,state)
    result={'schema':'hepta.openvpn-hia.target-cleanup.v1','passed':all(x['passed'] for x in results),'namespaces':results}
    save(Path(path).parent/'cleanup-report.json',result);return result


def build_tasks(plan):
    """Build the immutable 65-case inventory from the frozen plan."""
    tasks=[]
    for server,client in plan['behavior']['epoch_pairs']:
        tasks.append({'id':'epoch-'+server+'-'+client,'kind':'behavior','epoch':True,
                      'arms':{'server':server+'-user','client':client+'-user'}})
    for client in plan['behavior']['common_profile_clients']:
        tasks.append({'id':'common-'+client,'kind':'behavior','epoch':False,
                      'arms':{'server':'c-dco','client':client}})
    for client in plan['behavior']['negative_clients']:
        tasks.append({'id':'auth-untrusted-'+client,'kind':'authentication',
                      'arms':{'server':'c-user','client':client+'-user'}})
    for arm in plan['profile']['arms']:
        tasks.append({'id':'profile-'+arm,'kind':'profile',
                      'arms':{'server':'c-dco','client':arm}})
    for round_no in range(plan['performance']['rounds']):
        for order_no,order in enumerate(plan['performance']['orders']):
            for position,arm in enumerate(order):
                tasks.append({'id':f'perf-r{round_no}-o{order_no}-p{position}-{arm}',
                              'kind':'performance','round':round_no,'order':order_no,
                              'position':position,'arms':{'server':'c-dco','client':arm}})
    return tasks


def select_tasks(tasks,only_kind=None):
    """Permit only the predeclared diagnostic subsets; never weaken full mode."""
    if only_kind is None:
        return list(tasks)
    if only_kind=='profile':
        selected=[task for task in tasks if task['kind']=='profile']
    elif only_kind=='security':
        selected=[task for task in tasks if task['kind'] in ('behavior','authentication')]
    else:
        raise ValueError('unsupported target subset')
    if not selected:
        raise ValueError('predeclared target subset is empty')
    return selected

def profile_claim_limit(profile_only):
    """State the diagnostic-only boundary explicitly in every profile-only receipt."""
    if type(profile_only) is not bool:
        raise ValueError("profile_only must be a boolean")
    if profile_only:
        return ("profile-only: two actual tunnel/profile cases on one shared hosted VM; diagnostic only, "
                "not full target, not production and not performance qualification")
    return "finite single hosted VM namespace/veth observations only; every failed/lost/slow sample retained"

def security_claim_limit(security_only):
    if type(security_only) is not bool:
        raise ValueError("security_only must be a boolean")
    if security_only:
        return ("security-only: seven real behavior and two untrusted-certificate cases; "
                "not profile qualification, not the 54-case/216-workload matrix, "
                "not production and not performance qualification")
    return "finite single hosted VM namespace/veth observations only; every failed/lost/slow sample retained"


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for flag in ('c','hia','hia-trace','source','build','out','private-work','perf'):
        parser.add_argument('--'+flag,type=Path)
    parser.add_argument('--budget-seconds',type=int,default=3600)
    parser.add_argument('--cleanup-state',type=Path)
    parser.add_argument('--preflight-only',action='store_true')
    parser.add_argument('--only-kind',choices=('profile','security'),
                        help='run only the two profile cases or the seven behavior plus two certificate cases; not a full matrix')
    args=parser.parse_args(argv)
    if args.cleanup_state:
        result=cleanup_state(args.cleanup_state);print(json.dumps(result));return 0 if result['passed'] else 1
    for name in ('c','hia','hia_trace','source','build','out','private_work'):
        if getattr(args,name) is None:parser.error('--'+name.replace('_','-')+' is required')
        setattr(args,name,getattr(args,name).resolve())
    plan=read_json(HERE/'plan.json')
    if args.budget_seconds!=plan['budget_seconds']:parser.error('budget must equal the predeclared plan')
    if args.out.exists() and any(args.out.iterdir()):parser.error('evidence output must be new or empty')
    if args.private_work.exists():parser.error('private-work must be a new directory')
    args.out.mkdir(parents=True,exist_ok=True);args.private_work.mkdir(parents=True,mode=0o700)
    os.umask(0o077)
    ledger=Ledger(args.out,args.private_work,args.budget_seconds)
    def stop_requested(signum,frame):
        ledger.record({'event':'controller-stop-requested','signal':signum,'monotonic_ns':time.monotonic_ns()})
        ledger.deadline=time.monotonic()
    signal.signal(signal.SIGTERM,stop_requested);signal.signal(signal.SIGINT,stop_requested)
    allowed=sorted(os.sched_getaffinity(0))
    cpu_topology_error=None
    try:
        cpu_topology=read_cpu_topology(allowed)
        selected_cpus=select_distinct_physical_cpus(allowed,cpu_topology)
    except Exception as exc:
        cpu_topology={}
        selected_cpus=[]
        cpu_topology_error=repr(exc)
    tasks=select_tasks(build_tasks(plan),args.only_kind)
    profile_only=args.only_kind=='profile'
    security_only=args.only_kind=='security'
    planned={kind:sum(task['kind']==kind for task in tasks)
             for kind in ('behavior','authentication','profile','performance')}
    report={'schema':'hepta.openvpn-hia.target-profile.v1' if profile_only else
                'hepta.openvpn-hia.target-security.v1' if security_only else 'hepta.openvpn-hia.target-matrix.v1',
            'execution_mode':'profile-only' if profile_only else 'security-only' if security_only else 'full-matrix',
            'selected_case_kinds':['profile'] if profile_only else
                ['behavior','authentication'] if security_only else
                ['behavior','authentication','profile','performance'],
            'complete':False,'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            'plan':plan,'plan_sha256':digest(HERE/'plan.json'),'inputs':{},'host':{
                'uname':platform.uname()._asdict(),
                'allowed_cpus':allowed,
                'selected_cpus':selected_cpus,
                'cpu_topology':{str(cpu):{'package_id':key[0],'core_id':key[1]} for cpu,key in sorted(cpu_topology.items())},
                'selected_physical_cores':[list(cpu_topology[cpu]) for cpu in selected_cpus],
                'cpu_topology_source':'/sys/devices/system/cpu/cpu*/topology/{physical_package_id,core_id}',
                'cpu_topology_error':cpu_topology_error,
                'dedicated_physical_host':False,
                'frequency_locked':False},
            'cases':[{**task,'status':'planned','passed':False} for task in tasks],
            'gates':{k:False for k in ('real_tun','dco_runtime','authentication','encrypted_replay','rekey','reconnect','profile','fixed_performance_matrix')},
            'counts':{'planned_behavior_cases':planned['behavior'],'passed_behavior_cases':0,
                      'planned_authentication_cases':planned['authentication'],'passed_authentication_cases':0,
                      'planned_performance_cases':planned['performance'],'passed_performance_cases':0,
                      'planned_performance_workloads':planned['performance']*len(plan['performance']['workloads']),
                      'attempted_performance_workloads':0,'completed_performance_workloads':0,
                      'failed_performance_workloads':0,
                      'planned_profile_cases':planned['profile'],'passed_profile_cases':0},
            'cleanup':{'passed':False},'production_performance_qualified':False,
            'claim_limit':profile_claim_limit(profile_only) if profile_only else security_claim_limit(security_only)}

    receipt=args.out/'target-result.json';save(receipt,report)
    binaries={'c':args.c,'hia':args.hia,'hia_trace':args.hia_trace}
    try:
        # Freeze exact inputs before any namespace or traffic is created.
        report['inputs']['binaries']={name:{'path':str(path),'sha256':digest(path)} for name,path in binaries.items()}
        report['inputs']['scripts']={p.name:digest(p) for p in sorted(HERE.glob('*.py'))}
        report['inputs']['build_config_sha256']=digest(args.build/'config.h')
        build_receipt_path = args.build.parent.parent/'public'/'build.json'
        if not build_receipt_path.is_file():
            raise RuntimeError('patch-bound build receipt is missing')
        build_receipt = json.loads(build_receipt_path.read_text())
        report['inputs']['build_receipt_sha256'] = digest(build_receipt_path)
        report['inputs']['p2p_fair_dispatch'] = build_receipt.get('p2p_fair_dispatch')
        for name in ('c','hia'):
            if b'OPENVPN_HIA_CALLS' in binaries[name].read_bytes():raise RuntimeError('performance input contains diagnostic trace: '+name)
        if b'OPENVPN_HIA_CALLS' not in args.hia_trace.read_bytes():raise RuntimeError('diagnostic HIA input lacks entry tracer')
        repo=HERE.parents[2]
        head=ledger.run(['git','-C',str(repo),'rev-parse','HEAD'],'source-head',timeout=10)
        report['inputs']['hepta_commit']=head.text().strip()
        spec=importlib.util.spec_from_file_location('official_baseline',repo/'tools/openvpn_hia_baseline.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        report['inputs']['official_source']=module.source_freeze(args.source,args.source.parent/'openvpn-2.7.8.tar.gz')
        report['inputs']['perf']={'path':str(args.perf),'sha256':digest(args.perf)} if args.perf else None
        status=read_text('/proc/self/status');caps=int(re.search(r'^CapEff:\s*(\w+)',status,re.M).group(1),16)
        report['host']['process_status']=status;report['host']['cpuinfo']=read_text('/proc/cpuinfo')
        report['host']['perf_event_paranoid']=read_text('/proc/sys/kernel/perf_event_paranoid').strip()
        blockers=[]
        if os.geteuid()!=0 or not caps&(1<<12) or not caps&(1<<21):blockers.append('requires provisioned target CAP_NET_ADMIN and CAP_SYS_ADMIN; no escalation is attempted')
        if not Path('/dev/net/tun').exists():blockers.append('/dev/net/tun absent')
        if not Path('/sys/module/ovpn').exists():blockers.append('actual ovpn kernel implementation absent')
        if len(selected_cpus)<2:blockers.append('at least two distinct physical CPU cores required for fair two-sided measurement')
        for command in ('ip','iperf3','openssl','taskset'):
            if not shutil.which(command):blockers.append(command+' unavailable')
        report['preflight']={'blockers':blockers,'passed':not blockers};save(receipt,report)
        if blockers or args.preflight_only:
            report['preflight_only']=True
            return 2 if blockers else 0
        configuration=create_pki(ledger,args.c);configuration['cpus']=selected_cpus
        report['inputs']['configuration_sha256']={r:digest(configuration[r]) for r in ROLES}
        report['inputs']['public_cert_sha256']={p.name:digest(p) for p in (args.out/'pki').glob('*.crt')}
        save(receipt,report)
        for row in report['cases']:
            ledger.check();pair=None;row['status']='running';save(receipt,report)
            try:
                if row['kind']=='profile' and not args.perf:raise RuntimeError('actual perf collector unavailable; no synthetic substitute')
                behavior=row['kind']=='behavior';negative=row['kind']=='authentication'
                pair=Pair(ledger,row['id'],binaries,configuration,row['arms'],trace=behavior or negative,
                          reneg=plan['behavior']['rekey_seconds'] if behavior else 3600,negative=negative,
                          reneg_by_role=plan['behavior'].get('rekey_seconds_by_role') if behavior else None)
                if behavior:run_behavior(pair,plan,row['epoch'])
                elif negative:run_negative(pair,plan)
                else:
                    pair.connected();pair.protocol_gate(False)
                    if row['kind']=='profile':
                        measurement=throughput(pair,{'name':'tcp-profile','transport':'tcp'},plan['profile']['seconds'],selected_cpus,
                                               'tcp-profile',perf=args.perf,record_grace_seconds=plan['profile']['post_workload_grace_seconds'],
                                               profile_config=plan['profile'])
                        if not measurement['passed'] or not measurement.get('profile',{}).get('passed'):
                            raise RuntimeError('actual tunnel traffic or perf profile failed')
                        pair.result['checks']={'actual_tunnel_profile':True}
                    else:
                        pair.result['measurements']=[]
                        for index,workload in enumerate(plan['performance']['workloads']):
                            measurement=throughput(pair,workload,plan['performance']['seconds_per_workload'],selected_cpus,
                                                   f'workload-{index}-'+workload['name'],
                                                   udp_acceptance=plan['performance']['udp_acceptance'])
                            save(pair.folder/'case.json',pair.result)
                        pair.result['checks']={'four_workloads_completed':len(pair.result['measurements'])==4 and all(m['passed'] for m in pair.result['measurements']),
                                               'trace_excluded':True,'common_non_epoch_profile':True}
                        if not pair.result['checks']['four_workloads_completed']:
                            raise RuntimeError('one or more fixed workloads failed; every attempted measurement is retained')
                pair.result['status']='completed';pair.result['passed']=True
            except Deadline:
                row.update(status='deadline_exceeded',passed=False)
                if pair:pair.result.update(status='deadline_exceeded',passed=False)
                raise
            except Exception as exc:
                row.update(status='failed',failure=repr(exc),passed=False)
                if pair:pair.result.update(status='failed',failure=repr(exc),passed=False)
                (args.out/'cases'/row['id']).mkdir(parents=True,exist_ok=True)
                (args.out/'cases'/row['id']/'failure.txt').write_text(traceback.format_exc())
            finally:
                if pair:
                    pair.close()
                    # Entry traces are emitted at exit, so assess them only now.
                    if row['kind']=='behavior' and pair.result['passed']:
                        for role in ROLES:
                            if row['arms'][role].startswith('hia'):
                                trace=pair.result['observations'][role]['hia_trace']
                                good=bool(trace and trace['abi_failures']==0 and trace['read']>0 and trace['write']>0)
                                if row['epoch']:good=good and trace['read_epoch']>0 and trace['write_epoch']>0
                                else:good=good and trace['read_epoch']==0 and trace['write_epoch']==0
                                pair.result['checks'][role+'_hia_profile_trace']=good
                                pair.result['passed']=pair.result['passed'] and good
                    if pair.result.get('cleanup_errors'):pair.result['passed']=False
                    if not pair.result['passed'] and pair.result['status']=='completed':pair.result['status']='gate_failed'
                    save(pair.folder/'case.json',pair.result)
                    row.update(status=pair.result['status'],passed=pair.result['passed'],receipt=str((pair.folder/'case.json').relative_to(args.out)))
                    if 'failure' in pair.result:row['failure']=pair.result['failure']
                    if 'measurements' in pair.result:
                        row['attempted_workloads']=len(pair.result['measurements'])
                        row['completed_workloads']=sum(m['passed'] for m in pair.result['measurements'])
                save(receipt,report)
            print(json.dumps({'case':row['id'],'status':row['status'],'passed':row['passed']}),flush=True)
    except BaseException as exc:
        report['failure']=repr(exc)
        (args.out/'controller-failure.txt').write_text(traceback.format_exc())
    finally:
        ledger.close()
        try:report['cleanup']=cleanup_state(ledger.owned_path)
        except Exception as exc:report['cleanup']={'passed':False,'failure':repr(exc)}
        # Only this new directory is removed. Public artifacts never include
        # PKI private keys or raw DWARF stack bytes.
        try:
            shutil.rmtree(args.private_work);report['cleanup']['private_work_removed']=True
        except Exception as exc:report['cleanup']['private_work_removed']=False;report['cleanup']['private_error']=repr(exc);report['cleanup']['passed']=False
        bykind={kind:[r for r in report['cases'] if r['kind']==kind] for kind in ('behavior','authentication','performance','profile')}
        report['counts'].update(passed_behavior_cases=sum(r['passed'] for r in bykind['behavior']),
              passed_authentication_cases=sum(r['passed'] for r in bykind['authentication']),
              passed_performance_cases=sum(r['passed'] for r in bykind['performance']),
              attempted_performance_workloads=sum(r.get('attempted_workloads',0) for r in bykind['performance']),
              completed_performance_workloads=sum(r.get('completed_workloads',0) for r in bykind['performance']),
              failed_performance_workloads=sum(r.get('attempted_workloads',0)-r.get('completed_workloads',0) for r in bykind['performance']),
              passed_profile_cases=sum(r['passed'] for r in bykind['profile']))
        if profile_only:
            report['gates']['profile']=(len(bykind['profile'])==report['counts']['planned_profile_cases']>0
                                        and all(r['passed'] for r in bykind['profile']))
            report['complete']=bool(report['gates']['profile'] and report['cleanup']['passed']
                                    and report['cleanup'].get('private_work_removed') is True
                                    and not report.get('failure'))
        elif security_only:
            behavior_ok=len(bykind['behavior'])==7 and all(r['passed'] for r in bykind['behavior'])
            common=[r for r in bykind['behavior'] if not r['epoch']]
            authentication_ok=len(bykind['authentication'])==2 and all(r['passed'] for r in bykind['authentication'])
            report['gates'].update(real_tun=behavior_ok,dco_runtime=len(common)==3 and all(r['passed'] for r in common),
                     authentication=authentication_ok,encrypted_replay=behavior_ok,rekey=behavior_ok,reconnect=behavior_ok,
                     profile=False,fixed_performance_matrix=False)
            report['complete']=bool(all(report['gates'][name] for name in
                                    ('real_tun','dco_runtime','authentication','encrypted_replay','rekey','reconnect'))
                                    and report['cleanup']['passed']
                                    and report['cleanup'].get('private_work_removed') is True
                                    and not report.get('failure'))
        else:
            behavior_ok=len(bykind['behavior'])==7 and all(r['passed'] for r in bykind['behavior'])
            common=[r for r in bykind['behavior'] if not r['epoch']]
            report['gates'].update(real_tun=behavior_ok,dco_runtime=len(common)==3 and all(r['passed'] for r in common),
                     authentication=len(bykind['authentication'])==2 and all(r['passed'] for r in bykind['authentication']),
                     encrypted_replay=behavior_ok,rekey=behavior_ok,reconnect=behavior_ok,
                     profile=len(bykind['profile'])==2 and all(r['passed'] for r in bykind['profile']),
                     fixed_performance_matrix=len(bykind['performance'])==54 and all(r['passed'] for r in bykind['performance'])
                         and report['counts']['completed_performance_workloads']==216)
            report['complete']=bool(all(report['gates'].values()) and report['cleanup']['passed']
                                    and not report.get('failure'))
        report['elapsed_seconds']=time.monotonic()-ledger.started
        report['finished_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        save(receipt,report)
    print(json.dumps({'receipt':str(receipt),'complete':report['complete'],'gates':report['gates'],'counts':report['counts']}),flush=True)
    return 0 if report['complete'] else 1


if __name__=='__main__':raise SystemExit(main())
