#!/usr/bin/env python3
"""Summarize paired diagnostic observations without computing a release verdict."""
from collections import defaultdict
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.diagnose_hia_reduction_tails import inspect_response


def summarize(directory):
    directory = Path(directory)
    registration_raw = (directory / 'REGISTRATION.json').read_bytes()
    registration = json.loads(registration_raw)
    result = json.loads((directory / 'RESULT.json').read_bytes())
    if (result['status'] != 'completed' or result['inputs_unchanged'] is not True
            or result['driver_unchanged'] is not True
            or result['registration_sha256'] != sha256(registration_raw).hexdigest()):
        raise ValueError('incomplete or changed diagnostic campaign')
    requests = registration['requests']
    if len(result['observations']) != len(requests):
        raise ValueError('incomplete campaign inventory')
    grouped = defaultdict(list)
    for expected, observation in zip(requests, result['observations']):
        if observation['request'] != expected or observation['returncode'] != 0:
            raise ValueError('changed diagnostic request or process failure')
        response = inspect_response(json.loads(observation['stdout']), expected)
        if response != observation['response']:
            raise ValueError('raw and parsed response differ')
        for index, sample in enumerate(response['observations']):
            grouped[expected['backend']].append({**sample, 'request': expected, 'sample_index': index,
                'wall_minus_cpu_envelope_ns': sample['wall_ns'] - sample['cpu_envelope_ns']})
    arms = {}
    for arm, samples in grouped.items():
        arms[arm] = {'samples': len(samples),
            'positive_wall_minus_cpu_count': sum(s['wall_minus_cpu_envelope_ns'] > 0 for s in samples),
            'wall_minus_cpu_over_10us_count': sum(s['wall_minus_cpu_envelope_ns'] > 10000 for s in samples),
            'largest_wall_minus_cpu': max(samples, key=lambda s: s['wall_minus_cpu_envelope_ns']),
            'largest_wall': max(samples, key=lambda s: s['wall_ns']),
            'longest_20_wall_samples': sorted(samples, key=lambda s: s['wall_ns'], reverse=True)[:20]}
    return {'schema': 'hepta.hia.reduction-tail-summary.v1', 'requests': len(requests),
        'samples': sum(a['samples'] for a in arms.values()), 'arms': arms,
        'authority': 'DENY_ALL', 'performance_qualified': False,
        'historical_gates_changed': False,
        'interpretation': 'Descriptive only. Positive wall-minus-CPU-envelope is a lower-bound indication of off-CPU time under trusted clocks. Nonpositive values do not prove absence of descheduling. No sample exclusion, CPU replacement, or historical causal attribution.'}


if __name__ == '__main__':
    print(json.dumps(summarize(sys.argv[1]), indent=2, sort_keys=True, allow_nan=False))
