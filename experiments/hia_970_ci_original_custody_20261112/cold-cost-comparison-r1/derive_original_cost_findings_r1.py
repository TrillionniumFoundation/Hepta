"""Exact arithmetic and same-workload joins over two already observed CI runs."""
import hashlib
import json
import pathlib
import zipfile

R = pathlib.Path(__file__).resolve().parent
source = R / 'causal-cost-readback-r1/ORIGINAL-COSTS.json'
raw = source.read_bytes()
report = json.loads(raw)
runs = report['runs']
rows = [r for r in report['paired_phase_deltas'] if 'wall_elapsed_ns' in r]
metrics = ('wall_elapsed_ns', 'phase_body_and_final_input_recheck_ns', 'process_wall_outside_phase_body_ns',
           'embedded_call_wall_ns_sum', 'embedded_call_native_ns_sum', 'phase_elapsed_minus_embedded_call_wall_ns')
totals = {k: {part: sum(r[k][part] for r in rows) for part in ('970', 'bde', 'delta')} for k in metrics}

def receipt_key(v):
    return tuple(v.get(k) for k in ('case', 'format', 'status', 'input_sha256', 'image_sha256',
                                  'output_sha256', 'produced_sha256', 'core_u32', 'abi_status'))

def native_values(value):
    found = []
    def walk(v):
        if isinstance(v, dict):
            if 'native_elapsed_ns' in v and 'wall_elapsed_ns' in v and 'case' in v and 'format' in v:
                found.append(v)
                return
            for child in v.values(): walk(child)
        elif isinstance(v, list):
            for child in v: walk(child)
    walk(value)
    by_invocation = {}
    for v in found:
        # Match the first reader's identity rule. Do not merge repeated calls
        # that have distinct measured invocation times.
        key = tuple(v.get(k) for k in ('case', 'format', 'status', 'input_sha256', 'image_sha256', 'wall_elapsed_ns', 'native_elapsed_ns'))
        by_invocation.setdefault(key, v)
    return list(by_invocation.values())

joins = []
with zipfile.ZipFile(runs['970']['input_before']['path']) as a, zipfile.ZipFile(runs['bde']['input_before']['path']) as b:
    for row in rows:
        name = 'hia-cold.cold/qualification.evidence/phase-' + row['key'] + '.json'
        ar, br = a.read(name), b.read(name)
        assert hashlib.sha256(ar).hexdigest() == runs['970']['read_original_member_identities'][name]['sha256']
        assert hashlib.sha256(br).hexdigest() == runs['bde']['read_original_member_identities'][name]['sha256']
        ad, bd = json.loads(ar), json.loads(br)
        av, bv = native_values(ad['observations']), native_values(bd['observations'])
        # Full byte identity fields, with multiplicity; no timing value is used
        # as evidence that different inputs or outputs are the same.
        ak = sorted((receipt_key(v) for v in av), key=repr)
        bk = sorted((receipt_key(v) for v in bv), key=repr)
        join = {'phase': row['key'], 'checks': len(ad['checks']), 'checks_identical': ad['checks'] == bd['checks'],
                'native_invocation_count_970': len(av), 'native_invocation_count_bde': len(bv),
                'all_call_input_image_output_result_identity_fields_equal': ak == bk,
                'original_report_sha256': hashlib.sha256(ar).hexdigest(), 'new_report_sha256': hashlib.sha256(br).hexdigest()}
        assert join['checks_identical'] and join['all_call_input_image_output_result_identity_fields_equal'], join
        joins.append(join)

intervals = {}
for label, run in runs.items():
    phases = [p for p in run['phases'] if p['family'] not in ('names', 'exports') and 'wall_elapsed_ns' in p]
    assert len(phases) == 34
    lo = min(p['start_since_owner_ns'] for p in phases)
    hi = max(p['finish_since_owner_ns'] for p in phases)
    execution = sum(p['completed_monotonic_ns'] - p['started_monotonic_ns'] for p in phases)
    previous, service_upper = 0, 0
    for p in sorted((p for p in run['phases'] if 'archive_finish_since_owner_ns' in p), key=lambda p: p['archive_finish_since_owner_ns']):
        service_upper += p['archive_finish_since_owner_ns'] - max(previous, p['finish_since_owner_ns'])
        previous = p['archive_finish_since_owner_ns']
    intervals[label] = {'first_34_start_ns': lo, 'first_34_finish_ns': hi, 'first_34_window_ns': hi - lo,
                        'first_34_actual_worker_interval_ns_sum': execution, 'two_slot_time_without_live_worker_ns': 2*(hi-lo)-execution,
                        'single_archive_lane_service_time_upper_bound_ns': service_upper,
                        'archive_upper_bound_includes_submission_report_validation_delay': True}

generations = {}
for label, run in runs.items():
    chosen = [run['build_invocations'][k] for k in ('B1', 'B2', 'B3', 'M1', 'M2', 'M3')]
    generations[label] = {'wall_elapsed_ns_sum': sum(r['wall_elapsed_ns'] for r in chosen),
                          'native_elapsed_ns_sum': sum(r['native_elapsed_ns'] for r in chosen)}

result = {
    'schema': 'hia.cold-original-causal-findings.v1',
    'status': 'READ_ONLY_PAIRED_ORIGINAL_REPORTS_JOINED',
    'original_cost_report_sha256': hashlib.sha256(raw).hexdigest(),
    'script_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    'scope_correction': {'original_key': 'same_180_seconds_two_workers_38_families',
                         'intended_precise_meaning': '180 seconds, 2 workers, 38 phases = 19 families times 2 compiler variants',
                         'original_report_and_script_bytes_preserved': True},
    'matched_full_phase_reports': len(rows), 'same_workload_joins': joins, 'paired_totals_ns': totals,
    'first_34_stage_intervals': intervals, 'six_generation_timings': generations,
    'references_same_payload_hash_for_all_17': all(runs['970']['references'][k]['reference_sha256'] == runs['bde']['references'][k]['reference_sha256'] for k in runs['970']['references']),
    'limits': ['Parallel duration sums are not critical-path elapsed time.',
               'New run has no final qualification JSON: parent reference-process start/end and B0 start were not reconstructed.',
               'Native elapsed is the observer clock interval around the native call, not process CPU time; the original receipts do not identify the cause of changed scheduling or machine service rate.',
               'Names 46 prior overwritten companion histories remain missing; their retained phase-report observations are original and are explicitly distinct from recovered physical receipts.',
               'Workspace byte totals count retained normal observer responses only; bytes outside recorded header positions are still required by the current observer protocol.',
               'No product, limit, input, worker count, case denominator or original outcome was changed.'],
}
assert result['references_same_payload_hash_for_all_17']
out = R / 'causal-cost-readback-r1/PAIRED-FINDINGS.json'
wire = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
out.write_bytes(wire)
print(json.dumps({'status': result['status'], 'bytes': len(wire), 'sha256': hashlib.sha256(wire).hexdigest(),
                  'matched_phases': len(rows), 'matched_native_invocations': sum(j['native_invocation_count_970'] for j in joins)}))
