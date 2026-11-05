#!/usr/bin/env python3
"""Re-evaluate preserved raw logs with the current observer, without rerunning peers."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--baseline', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
if a.output.exists(): p.error('review output already exists')
h = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
runner = Path(__file__).resolve().parents[2] / 'tools/openvpn_hia_baseline.py'
spec = importlib.util.spec_from_file_location('baseline', runner)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
j = json.loads(a.baseline.read_text())
j['review'] = {'scope': 'derived-from-same-raw-logs; no new execution',
               'original_baseline_sha256': h(a.baseline), 'original_file': a.baseline.name,
               'observer_sha256': h(runner),
               'correction': 'Require positive calls to all four HIA exports for positive epoch sessions. Treat Initial packet, initial trusted-session promotion and Initialization Sequence Completed as new-session boundaries; exclude reconnect key installs from rekey cycles.'}
for session in j['control_sessions']:
    for role, old in session['observations'].items():
        log = a.baseline.parent / old['log']
        if h(log) != old['sha256']: raise RuntimeError('raw log changed: ' + str(log))
        before = old['rekey_cycles_completed']
        old.update(m.observe_control(log.read_text(errors='replace')))
        old['pre_review_rekey_count'] = before
        if session[role + '_argv'][0] == j['binaries'].get('hia', {}).get('path'):
            trace = m.trace_observation(log.read_text(errors='replace'))
            old['hia_trace'] = trace
            good = bool(trace['present'] and trace['counts']['abi_failures'] == 0)
            if session['authentication_negative'] is None:
                good = good and all(trace['counts'][key] > 0 for key in ('read', 'write', 'read_epoch', 'write_epoch'))
            session['checks'][role + '_hia_entry_trace'] = good
    if session['authentication_negative'] is None:
        session['checks']['both_peers_rekeyed_with_tls_and_keys'] = all(
            row['rekey_cycles_completed'] >= 1 for row in session['observations'].values())
    session['passed'] = all(session['checks'].values())
j['review']['all_control_sessions_passed'] = all(s['passed'] for s in j['control_sessions'])
a.output.write_text(json.dumps(j, indent=2, sort_keys=True) + '\n')
print(json.dumps({'output': str(a.output), 'all_control_sessions_passed': j['review']['all_control_sessions_passed'],
                  'normal_pair_rekey_counts': [[s['observations'][role]['rekey_cycles_completed'] for role in ('server','client')]
                                              for s in j['control_sessions'] if s['authentication_negative'] is None]}))
raise SystemExit(0 if j['review']['all_control_sessions_passed'] else 1)
