"""Read existing fixed diagnostics; execute no product, tests, or benchmarks."""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path('/workspace/scratch/dda74a4fae35')
BASE = ROOT / 'v94-native-namespace-budget-r1'
HERE = Path(__file__).resolve().parent


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw),
            'mode': oct(path.stat().st_mode & 0o777),
            'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def count_delta(row, key):
    return row['counter_after'].get(key, 0) - row['counter_before'].get(key, 0)


def window(rows, begin, end):
    selected = [r for r in rows if begin <= r['start_ns'] and r['end_ns'] <= end]
    by_kind = defaultdict(lambda: {'count': 0, 'inclusive_wall_ns': 0,
                                  'inclusive_process_cpu_ns': 0,
                                  'exclusive_timed_children_wall_ns': 0})
    for r in selected:
        item = by_kind[r['kind']]
        item['count'] += 1
        for field in ('inclusive_wall_ns', 'inclusive_process_cpu_ns',
                      'exclusive_timed_children_wall_ns'):
            item[field] += r[field]
    calls = [r for r in selected if r['kind'] == 'public-store']
    scans = [r for r in selected if r['kind'] == 'fresh-admission']
    effects = [r for r in selected if r['kind'] == 'publication-effect']
    adjacent = []
    for left, right in zip(scans, scans[1:]):
        between = [r for r in effects if left['end_ns'] <= r['start_ns']
                   and r['end_ns'] <= right['start_ns']]
        adjacent.append({'left_scan': left['id'], 'right_scan': right['id'],
                         'publication_effect_ids': [r['id'] for r in between]})
    return {'start_ns': begin, 'end_ns': end, 'wall_ns': end - begin,
            'inclusive_by_kind': dict(by_kind),
            'fresh_scans': len(scans), 'public_store_calls': len(calls),
            'public_store_labels': dict(Counter(r['label'] for r in calls)),
            'each_public_call_exactly_one_fresh_scan': all(count_delta(r, 'fresh_scans') == 1 for r in calls),
            'public_calls': [{'id': r['id'], 'parent': r['parent'], 'label': r['label'],
                             'start_ns': r['start_ns'], 'end_ns': r['end_ns'],
                             'inclusive_wall_ns': r['inclusive_wall_ns'],
                             'fresh_scans': count_delta(r, 'fresh_scans'),
                             'publication_effects': count_delta(r, 'publication_effects')}
                            for r in calls],
            'adjacent_scan_effect_boundaries': adjacent,
            'all_adjacent_scans_have_intervening_publication_effect':
                all(r['publication_effect_ids'] for r in adjacent),
            'unattributed_wall_after_fresh_scans_ns':
                end - begin - sum(r['inclusive_wall_ns'] for r in scans),
            'warning': 'Inclusive kinds overlap and must not be summed. The residual includes all uninstrumented work and instrumentation. These are existing diagnostic times, not new measurements or qualification.'}


def main():
    component_path = BASE / 'ci-components-r1/actual/raw/evidence/REPORT.json'
    sizes_path = component_path.with_name('FILE-SIZES.json')
    component = json.loads(component_path.read_bytes())
    sizes = json.loads(sizes_path.read_bytes())
    inputs = [pin(component_path), pin(sizes_path)]
    sections = []
    for index in range(3):
        path = BASE / f'ci-phase-r1/actual/raw/evidence/case-{index}/observations/REPORT.json'
        inputs.append(pin(path))
        report = json.loads(path.read_bytes())
        rows = report['profile']['rows']
        freezes = [r for r in rows if r['kind'] == 'client-stage' and r['label'] == 'freeze']
        assert len(freezes) == 2
        second = freezes[1]
        remaining = [r for r in rows if r['kind'] == 'remaining-budget' and r['start_ns'] >= second['end_ns']]
        assert remaining
        stages = [r for r in rows if r['kind'] == 'client-stage' and r['start_ns'] >= second['end_ns']]
        item = {'case': index, 'method': report['method'], 'original_outcome': report['original_outcome'],
                'source_commit': report['source_commit'], 'selection': report['selection'],
                'second_freeze_return_to_first_remaining': window(rows, second['end_ns'], remaining[0]['start_ns']),
                'context_created_observations': report['profile']['extra_observations'],
                'post_freeze_stages': [{'label': r['label'], 'id': r['id'], 'parent': r['parent'],
                                       'wall_ns': r['inclusive_wall_ns'],
                                       'fresh_scans': count_delta(r, 'fresh_scans'),
                                       'publication_effects': count_delta(r, 'publication_effects')}
                                      for r in stages]}
        encodings = [r for r in stages if r['label'] == 'encoding']
        if encodings:
            assert len(encodings) == 1
            item['second_freeze_return_to_encoding_return'] = window(rows, second['end_ns'], encodings[0]['end_ns'])
        sections.append(item)
    extension_bytes = defaultdict(lambda: {'paths': 0, 'bytes': 0})
    for row in sizes:
        stat = extension_bytes[Path(row['path']).suffix]
        stat['paths'] += 1
        stat['bytes'] += row['bytes']
    assert len(sizes) == 1429 and sum(r['bytes'] for r in sizes) == 51971962
    openssl_runs = [r for r in component['owned_byte_hash_runs'] if r['provider'] == 'hashlib.sha256']
    after_freeze = sections[2]['second_freeze_return_to_encoding_return']
    estimate = [{'single_owned_map_wall_ns': r['wall_ns'],
                 'observed_scan_count': after_freeze['fresh_scans'],
                 'multiplication_ns': r['wall_ns'] * after_freeze['fresh_scans']}
                for r in openssl_runs]
    result = {'schema': 'hepta.namespace-budget-existing-cost-analysis.v1',
              'status': 'ANALYSIS_COMPLETE_NO_PRODUCT_CHANGE', 'inputs': inputs,
              'qualification': False, 'whole_native': False,
              'new_product_executions': 0, 'new_benchmarks': 0,
              'original_budgets_changed': False, 'candidate_implemented': False,
              'source_commit': 'abeef212e34023534d91f8f952280e2a8d0cbde6',
              'sections': sections,
              'fresh_domain': {'paths': len(sizes), 'bytes': sum(r['bytes'] for r in sizes),
                               'extension_distribution': dict(extension_bytes)},
              'original_component_capabilities': component['capabilities'],
              'original_owned_byte_hash_runs': component['owned_byte_hash_runs'],
              'original_scans': component['scans'],
              'cost_estimates_not_hard_lower_bounds': estimate,
              'scope_limits': [
                  'The phase run and isolated components run are separate exact-source diagnostics; their timings are not interchangeable observations.',
                  'Case 2 completes build_pair with its original default total budget. Its 98 post-freeze scans do not prove either 3000ms method completed that path.',
                  'Original qualification failed two preparation methods at the FIRST baseline emit and timed out at 5.721897753s; the phase run reached SECOND and timeout passed. Both original outcomes remain unchanged.',
                  'All original fresh read/hash/provider and callback boundaries remain required. The source domain is not reduced.',
                  'Memo R1-R4 and metadata-loop micro prototypes remain NOT_ADOPTED. This report does not revive them.',
                  'Native StoreLifecycle observer counts include a separately recorded duplicate observer correction; no new entry-count claim is made here.',
                  'The publication bridge exclusive timer still includes kernel/provider work and diagnostic overhead; it is not an exact removable-cost measurement.',
              ]}
    output = HERE / 'REPORT.json'
    with output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps({'report': pin(output),
                      'case_windows': [{'case': r['case'], 'original_outcome': r['original_outcome'],
                                        'first': {k: r['second_freeze_return_to_first_remaining'][k] for k in
                                                  ('wall_ns', 'fresh_scans', 'public_store_calls', 'unattributed_wall_after_fresh_scans_ns')},
                                        'encoding': {k: r['second_freeze_return_to_encoding_return'][k] for k in
                                                     ('wall_ns', 'fresh_scans', 'public_store_calls', 'unattributed_wall_after_fresh_scans_ns')}
                                                    if 'second_freeze_return_to_encoding_return' in r else None}
                                       for r in sections],
                      'pure_hash_cost_estimates': estimate}, sort_keys=True))


if __name__ == '__main__':
    main()
