"""Cost decomposition of one unchanged full source scan; no candidate change."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    sys.path.insert(0, str(root))
    from tools import hia_selfhost_contract as policy
    definition = (root / 'tools/hia_selfhost_contract.py').read_bytes()
    contract_bytes = (root / policy.CONTRACT_PATH).read_bytes()
    expected = json.loads(contract_bytes)['source_identity']['files']
    report = {'schema': 'hia.fresh-source-scan-cost.v1', 'scope': 'INSTRUMENTED_HOSTED_DIAGNOSTIC',
        'python': sys.version, 'source_root': str(root), 'source_packet': '58a156d6bfda0104362e5c9655b1ca4cfb984150',
        'function_sha256': sha256(definition).hexdigest(),
        'contract_sha256': sha256(contract_bytes).hexdigest(),
        'function_body_changed': False, 'fresh_source_domain_reduced': False,
        'cross_call_cache_added': False, 'HIA_policy_execution': False,
        'current_cold': False, 'original_budget_case_rerun': False,
        'calls': [], 'read_observations': [], 'hash_observations': [], 'discovery_observations': []}

    def invoke(label):
        wall, cpu = time.monotonic_ns(), time.process_time_ns()
        value = policy.file_digests(root)
        cpu = time.process_time_ns() - cpu
        wall = time.monotonic_ns() - wall
        report['calls'].append({'label': label, 'elapsed_ns': wall, 'cpu_ns': cpu,
            'count': len(value), 'ordered_map_equals_contract': list(value.items()) == list(sorted(expected.items()))})
        (output / (label + '-map.json')).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
        if value != expected:
            raise AssertionError('fresh complete source map differs')
        return value

    invoke('before-uninstrumented')
    read_bytes = Path.read_bytes
    original_sha256 = policy.sha256
    rglob = Path.rglob

    def observed_read(path):
        wall, cpu = time.monotonic_ns(), time.process_time_ns()
        value = read_bytes(path)
        cpu = time.process_time_ns() - cpu
        wall = time.monotonic_ns() - wall
        report['read_observations'].append({'path': path.relative_to(root).as_posix(),
            'bytes': len(value), 'elapsed_ns': wall, 'cpu_ns': cpu})
        return value

    def observed_hash(value):
        wall, cpu = time.monotonic_ns(), time.process_time_ns()
        result = original_sha256(value)
        cpu = time.process_time_ns() - cpu
        wall = time.monotonic_ns() - wall
        report['hash_observations'].append({'bytes': len(value), 'elapsed_ns': wall, 'cpu_ns': cpu})
        return result

    def observed_rglob(path, pattern):
        iterator = iter(rglob(path, pattern))
        count, elapsed, cpu_total = 0, 0, 0
        while True:
            wall, cpu = time.monotonic_ns(), time.process_time_ns()
            try:
                item = next(iterator)
            except StopIteration:
                cpu_total += time.process_time_ns() - cpu
                elapsed += time.monotonic_ns() - wall
                break
            cpu_total += time.process_time_ns() - cpu
            elapsed += time.monotonic_ns() - wall
            count += 1
            yield item
        report['discovery_observations'].append({'path': str(path), 'pattern': pattern,
            'yielded': count, 'elapsed_ns': elapsed, 'cpu_ns': cpu_total})

    with patch.object(Path, 'read_bytes', observed_read), \
         patch.object(policy, 'sha256', observed_hash), \
         patch.object(Path, 'rglob', observed_rglob):
        invoke('instrumented')
    invoke('after-uninstrumented')
    report['observed_read_count'] = len(report['read_observations'])
    report['observed_bytes'] = sum(row['bytes'] for row in report['read_observations'])
    report['ordered_paths_unchanged'] = [row['path'] for row in report['read_observations']] == sorted(expected)
    report['same_lengths_in_read_and_hash_order'] = ([row['bytes'] for row in report['read_observations']]
        == [row['bytes'] for row in report['hash_observations']])
    report['components'] = {name: {key: sum(row[key] for row in rows) for key in ('elapsed_ns', 'cpu_ns')}
        for name, rows in (('read_bytes_open_read_close', report['read_observations']),
                           ('sha256_constructor', report['hash_observations']),
                           ('rglob_next_only', report['discovery_observations']))}
    report['unattributed_instrumented_ns'] = report['calls'][1]['elapsed_ns'] - sum(
        row['elapsed_ns'] for row in report['components'].values())
    report['unattributed_includes'] = ['Path construction/relative conversion', 'set/sort/dict',
        'digest hex encoding', 'byte/object cleanup', 'timer and observer bookkeeping']
    report['input_definition_and_contract_unchanged'] = (
        (root / 'tools/hia_selfhost_contract.py').read_bytes() == definition
        and (root / policy.CONTRACT_PATH).read_bytes() == contract_bytes)
    report['status'] = 'OBSERVATION_COMPLETE' if (report['ordered_paths_unchanged']
        and report['same_lengths_in_read_and_hash_order'] and report['input_definition_and_contract_unchanged']) else 'HOLD'
    with (output / 'REPORT.json').open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({key: report[key] for key in ('status', 'calls', 'components',
        'observed_bytes', 'observed_read_count', 'unattributed_instrumented_ns')}), flush=True)
    return 0 if report['status'] == 'OBSERVATION_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
