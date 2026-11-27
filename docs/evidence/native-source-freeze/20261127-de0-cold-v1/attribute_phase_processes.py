"""Read actual retained receipts and SIGCHLD parent chains without execution."""
from pathlib import Path
from collections import Counter, defaultdict
from hashlib import sha256
import argparse
import json
import re
import struct


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--original', type=Path, required=True,
                   help='Directory containing the unchanged extracted original evidence archive')
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--signal-profile', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    trace = (a.original / 'cold-data-v1/evidence/full-cold.exec.trace').read_bytes()
    raw = a.profile.read_bytes()
    profile = json.loads(raw)
    signal = json.loads(a.signal_profile.read_bytes())
    owner = (a.original / 'cold-data-v1/cold/process-owner.receipt').read_bytes()
    master = struct.unpack_from('<32Q', owner)[8]
    ticks = signal['clock_ticks_per_second']
    assert signal['observed_master_pid'] == master
    assert profile['full_cold_passed'] is False
    assert profile['source_or_receipt_modified'] is False
    events = {}
    children = defaultdict(set)
    for line in trace.decode().splitlines():
        m = re.match(r'([0-9]+) --- SIGCHLD .*?si_pid=([0-9]+).*?si_status=([0-9]+), si_utime=([0-9]+).*?si_stime=([0-9]+)', line)
        if m:
            parent, pid, status, utime, stime = map(int, m.groups())
            children[parent].add(pid)
            events[pid] = {'parent': parent, 'pid': pid, 'status': status,
                           'user_seconds': utime/ticks, 'system_seconds': stime/ticks,
                           'cpu_seconds': (utime+stime)/ticks}
    rows = []
    for phase in profile['phases']:
        mapped = Counter()
        witnesses = []
        for sub in phase['subprocess_top']:
            pid = sub['child_pid']
            chain = [pid]
            event = events.get(pid)
            seen = set()
            while event and event['parent'] != master:
                assert event['pid'] not in seen, 'cyclic observed process ancestry'
                seen.add(event['pid'])
                chain.append(event['parent'])
                event = events.get(event['parent'])
            if event and event['parent'] == master:
                chain.append(master)
                mapped[event['pid']] += 1
                witnesses.append({'node': sub['node'], 'receipt_sha256': sub['receipt_sha256'],
                                  'child_pid': pid, 'observed_parent_chain': chain})
        row = {'phase': phase['phase'], 'observed_nodes': phase['observed_nodes'],
               'expected_nodes': phase['expected_nodes'], 'journal_complete': phase['complete'],
               'journal_bytes': phase['journal_bytes'],
               'actual_subprocess_seconds': phase['subprocess_elapsed_ns']/1e9,
               'mapped_driver_candidates': dict(mapped),
               'child_receipt_and_signal_witnesses': witnesses}
        if len(mapped) == 1:
            pid = next(iter(mapped))
            row['driver'] = events[pid]
            row['driver_observed_children'] = len(children[pid])
        rows.append(row)
    report = {
        'schema': 'hepta.hia.failed-cold-receipt-signal-attribution.v1',
        'source_head': profile['source_head'],
        'scope': 'Read-only process attribution by actual HIASBR01 journal receipt PID and observed SIGCHLD parent chain. CPU signal accounting is not a complete profiler.',
        'full_cold_passed': False, 'original_budget_seconds': 180,
        'source_or_receipts_modified': False,
        'trace': {'bytes': len(trace), 'sha256': sha256(trace).hexdigest()},
        'journal_profile': {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()},
        'clock_ticks_per_second_from_original_target_readback': ticks,
        'master_pid_from_original_owner_receipt': master,
        'phases': rows,
    }
    with a.output.open('x') as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'output': str(a.output), 'sha256': sha256(a.output.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
