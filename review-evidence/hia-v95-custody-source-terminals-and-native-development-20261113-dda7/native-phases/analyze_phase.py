"""Read immutable phase reports; no product imports or execution."""
from collections import Counter
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / 'actual/raw/evidence'


def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'computed_git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def summarize_window(rows, start, end):
    chosen = [row for row in rows if row['start_wallclock_ns'] >= start and row['end_wallclock_ns'] <= end]
    by = {}
    for kind in ('fresh-admission', 'code-admission', 'public-store', 'publication-effect', 'subprocess'):
        selected = [row for row in chosen if row['kind'] == kind]
        by[kind] = {'count': len(selected), 'inclusive_wall_ns': sum(row['inclusive_wall_ns'] for row in selected),
                    'inclusive_process_cpu_ns': sum(row['inclusive_process_cpu_ns'] for row in selected)}
    scans = [row for row in chosen if row['kind'] == 'fresh-admission']
    scan_rows = []
    for row in scans:
        chain, parent = [], row['parent']
        while parent is not None:
            item = rows[parent]
            chain.append({'id': item['id'], 'kind': item['kind'], 'label': item['label'], 'metadata': item['metadata']})
            parent = item['parent']
        public = next((item for item in chain if item['kind'] == 'public-store'), None)
        scan_rows.append({'id': row['id'], 'wall_ns': row['inclusive_wall_ns'],
                          'map_paths': row['fresh_map_paths'], 'map_matches': row['fresh_map_matches_exact_original'],
                          'public_owner': public, 'call_chain': chain})
    boundaries = []
    for left, right in zip(scans, scans[1:]):
        effects = [row for row in rows if row['kind'] == 'publication-effect'
            and row['start_ns'] >= left['end_ns'] and row['end_ns'] <= right['start_ns']]
        boundaries.append({'after_scan': left['id'], 'before_scan': right['id'],
                           'effects': [{'id': item['id'], 'operation': item['metadata']['operation'],
                                        'outcome': item['outcome']} for item in effects]})
    return {'start_wallclock_ns': start, 'end_wallclock_ns': end, 'elapsed_ns': end - start,
            'components_are_inclusive_and_may_overlap': True, 'components': by,
            'scans': scan_rows, 'adjacent_scan_boundaries': boundaries,
            'unique_nearest_public_calls': len({row['public_owner']['id'] for row in scan_rows if row['public_owner']}),
            'public_names': dict(Counter(row['public_owner']['label'] for row in scan_rows if row['public_owner'])),
            'all_adjacent_intervals_have_actual_publication_effects': all(row['effects'] for row in boundaries)}


def main():
    outer = json.loads((EVIDENCE / 'REPORT.json').read_bytes())
    cases = []
    for selection in outer['cases']:
        path = EVIDENCE / selection['report_path']
        report = json.loads(path.read_bytes())
        profile = report['profile']
        rows = profile['rows']
        assert all(row['id'] == index for index, row in enumerate(rows))
        remaining = [row for row in rows if row['kind'] == 'remaining-budget']
        context = profile['extra_observations'][-1]
        first = next(row for row in remaining if row['context_id'] == context['context_id'])
        window = summarize_window(rows, int(context['created_ns']), first['start_wallclock_ns'])
        stages = []
        for row in rows:
            if row['kind'] != 'client-stage':
                continue
            stages.append({'label': row['label'], 'occurrence': row['occurrence'], 'outcome': row['outcome'],
                'inclusive_wall_ns': row['inclusive_wall_ns'], 'inclusive_process_cpu_ns': row['inclusive_process_cpu_ns'],
                'scans': row['counter_after'].get('fresh_scans', 0) - row['counter_before'].get('fresh_scans', 0),
                'effects': row['counter_after'].get('publication_effects', 0) - row['counter_before'].get('publication_effects', 0)})
        evaluations = [row for row in rows if row['kind'] == 'client-stage' and row['label'] == 'evaluate']
        evaluation = summarize_window(rows, evaluations[0]['start_wallclock_ns'], evaluations[0]['end_wallclock_ns']) if evaluations else None
        cases.append({'method': report['method'], 'actual_original_outcome': report['original_outcome'],
            'failures': report['failures'], 'errors': report['errors'],
            'original_report': {'path': selection['report_path'], **identity(path)},
            'last_context_to_first_remaining': window, 'first_remaining_ms': first['remaining_ms'],
            'client_stages': stages, 'evaluation': evaluation,
            'store_original_complete_receipt_entries': report['original_store_receipt_entries'],
            'store_sampled_counter_not_usable_as_direct_machine_call_count': True,
            'all_fresh_maps_equal_original': all(row['fresh_map_matches_exact_original'] for row in rows if row['kind'] == 'fresh-admission')})
    result = {'schema': 'hepta.original-namespace-sections-readback.v1',
        'status': 'READBACK_COMPLETE', 'run': 43475015584, 'job': 132056496180,
        'head': '6ef7266b6c539e2c6f0cb7d45eef81aac5e3a9a2',
        'source_commit': outer['source_commit'], 'source_tree': outer['source_tree'],
        'source_unchanged': outer['source_unchanged'], 'retained_inputs_unchanged': outer['retained_inputs_unchanged'],
        'original_43459534648_failures_preserved': True, 'cases': cases,
        'scope_notes': [
            'Current instrumented expired/loop fail at second emit line68; original uninstrumented group failed first emit line67.',
            'The instrumented timeout test passes its unchanged <5 assertion. Its Session.evaluate span is not the exact assertion argument. Original5.721897753 failure remains.',
            'All three fresh processes are a selected diagnostic, not a repeat of the original complete35 in its original warm order.',
            'A first-context observer query took116186ns; all other added SELECT observations are explicitly retained in original reports.',
            'Nested NativeStoreLifecycleImage/NativeHiaJsonImage observer wrappers count the same underlying invocation twice. The unmodified original per-return receipt observer remains single. No claimed exact Store C-entry count or CPU total can use the duplicated diagnostic statistic.',
            'Inclusive source/public/effect categories overlap and must not be added as a partition.',
        ], 'qualification': False, 'whole_native': False}
    (ROOT / 'PHASE-READBACK.json').open('x').write(json.dumps(result, sort_keys=True, indent=2) + '\n')
    concise = []
    for case in cases:
        window = case['last_context_to_first_remaining']
        concise.append({'method': case['method'], 'outcome': case['actual_original_outcome'],
            'window_ns': window['elapsed_ns'], 'scans': window['components']['fresh-admission'],
            'unique_public_calls': window['unique_nearest_public_calls'], 'public_names': window['public_names'],
            'boundaries': len(window['adjacent_scan_boundaries']),
            'all_have_effects': window['all_adjacent_intervals_have_actual_publication_effects'],
            'evaluation_components': case['evaluation']['components'] if case['evaluation'] else None})
    print(json.dumps(concise, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
