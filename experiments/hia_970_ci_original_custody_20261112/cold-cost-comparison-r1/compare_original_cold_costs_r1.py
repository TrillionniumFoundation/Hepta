"""Read exact historical CI receipts; never import or execute project code."""
from __future__ import annotations
import collections
import hashlib
import io
import json
import pathlib
import re
import sys
import time
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent
P = 'hia-cold.cold/qualification.evidence/'
WORKSPACE_FIELDS = (0, 8, 16, 24, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 224, 248, 1024)
INPUTS = {
    '970': (ROOT / 'full-zip-two-parts-r1/actual-local-readback-r1/artifact-13911977275.original.zip',
            599427251, '40e81308484173d36153f6a3014293a78705aa28e8f8f7718dcdd3d87c03f580'),
    'bde': (ROOT.parent / 'root/combined-ci-r1-actual/artifact-13923066412.original.zip',
            57968775, '93ae4fb92ef517667b04cc38d7b1dc0064d690297a597ca8aeb654d565d2134a'),
}

def sha(b):
    return hashlib.sha256(b).hexdigest()

def sealed(path, size, expected):
    st = path.stat()
    h = hashlib.sha256()
    total = 0
    with path.open('rb') as stream:
        while block := stream.read(1 << 20):
            h.update(block)
            total += len(block)
    after = path.stat()
    assert (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    assert total == size and h.hexdigest() == expected
    return {'path': str(path), 'bytes': total, 'sha256': h.hexdigest(),
            'identity': [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]}

def document(z, name, ledger):
    raw = z.read(name)
    assert len(raw) == z.getinfo(name).file_size
    ledger[name] = {'bytes': len(raw), 'sha256': sha(raw)}
    return json.loads(raw)

def scalar_invocation(d, path):
    return {key: d[key] for key in ('case', 'format', 'status', 'transport', 'wall_elapsed_ns', 'native_elapsed_ns',
            'input_bytes', 'image_sha256', 'input_sha256', 'produced_bytes', 'produced_sha256') if key in d} | {'receipt_member': path}

def calls_from_members(z, names, ledger, prefix=''):
    calls = []
    for name in sorted(n for n in names if n.endswith('.receipt.json')):
        d = document(z, name, ledger)
        if not isinstance(d, dict) or not isinstance(d.get('wall_elapsed_ns'), int) or 'format' not in d:
            continue
        row = scalar_invocation(d, prefix + name)
        request_name = name[:-len('.receipt.json')] + '.request.json'
        row['request_present'] = request_name in names
        if request_name in names:
            req = document(z, request_name, ledger)
            row['request_sha256'] = ledger[request_name]['sha256']
            row['request_capacity'] = req.get('capacity')
            row['request_workspace_size'] = req.get('workspace_size')
            row['request_transport'] = req.get('transport')
            if d.get('transport') and d.get('status') == 'returned':
                capacity, workspace = req['capacity'], req['workspace_size']
                source_bytes = d['input_bytes']
                assert type(capacity) is int and type(workspace) is int and type(source_bytes) is int
                assert list(sorted(int(k) for k in d['workspace_header'])) == [n for n in WORKSPACE_FIELDS if workspace >= n + 8]
                row['complete_response_bytes_required_by_current_protocol'] = 24 + source_bytes + capacity + workspace
                row['workspace_response_bytes'] = workspace
                row['workspace_observed_header_bytes'] = 8 * len(d['workspace_header'])
                row['workspace_bytes_not_selected_into_header'] = workspace - row['workspace_observed_header_bytes']
                row['source_response_bytes'] = source_bytes
                row['output_response_bytes'] = capacity
        calls.append(row)
    return calls

def summarize_calls(rows):
    out = {'physical_receipts': len(rows), 'wall_elapsed_ns_sum': 0, 'native_elapsed_ns_sum': 0,
           'observer_returned_count': 0, 'complete_response_bytes_required_by_current_protocol': 0,
           'workspace_response_bytes': 0, 'workspace_observed_header_bytes': 0,
           'workspace_bytes_not_selected_into_header': 0, 'source_response_bytes': 0, 'output_response_bytes': 0}
    transports = collections.Counter()
    sizes = collections.Counter()
    for r in rows:
        out['wall_elapsed_ns_sum'] += r.get('wall_elapsed_ns', 0)
        out['native_elapsed_ns_sum'] += r.get('native_elapsed_ns', 0)
        transports[r.get('transport', 'retained-Python-child')] += 1
        if 'complete_response_bytes_required_by_current_protocol' in r:
            out['observer_returned_count'] += 1
            sizes[r['request_workspace_size']] += 1
            for key in ('complete_response_bytes_required_by_current_protocol', 'workspace_response_bytes',
                        'workspace_observed_header_bytes', 'workspace_bytes_not_selected_into_header',
                        'source_response_bytes', 'output_response_bytes'):
                out[key] += r[key]
    out['transports'] = dict(transports)
    out['observer_returned_workspace_size_counts'] = {str(k): v for k, v in sorted(sizes.items())}
    out['wall_minus_native_ns_sum'] = out['wall_elapsed_ns_sum'] - out['native_elapsed_ns_sum']
    return out

def owner_start(owner):
    return next(e['monotonic_ns'] for e in owner['events'] if e['kind'] == 'qualification_started')

def report_calls(value):
    found = []
    def visit(v):
        if isinstance(v, dict):
            if 'native_elapsed_ns' in v and 'wall_elapsed_ns' in v and 'case' in v and 'format' in v:
                found.append(v)
                return
            for x in v.values():
                visit(x)
        elif isinstance(v, list):
            for x in v:
                visit(x)
    visit(value)
    # A report can repeat a receipt as both a build and an observation. Count
    # the same original invocation only once, without discarding differing calls.
    unique = {}
    for d in found:
        key = tuple(d.get(k) for k in ('case', 'format', 'status', 'input_sha256', 'image_sha256', 'wall_elapsed_ns', 'native_elapsed_ns'))
        unique.setdefault(key, d)
    return list(unique.values())

def read_run(label, path, size, expected):
    before = sealed(path, size, expected)
    ledger, inner_ledgers = {}, {}
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        assert len(names) == len(z.infolist())
        cold = document(z, 'hia-cold.json', ledger)
        owner = document(z, 'hia-cold.cold/process-owner.json', ledger)
        start = owner_start(owner)
        refs = {}
        for name in sorted(n for n in names if n.startswith(P + 'reference-') and n.endswith('.worker.json') and n.count('/') == 2):
            d = document(z, name, ledger)
            refs[d['family']] = {k: d[k] for k in ('family', 'wall_elapsed_ns', 'worker_pid', 'reference_sha256', 'source_manifest_sha256')}
        assert len(refs) == 17
        seed = document(z, P + 'B0.receipt.json', ledger)
        builds = {}
        for tag in ('B1', 'B2', 'B3', 'M1', 'M2', 'M3', 'native-observer-packer', 'native-observer-emit', 'linked-observer-policy', 'linked-observer-packer', 'linked-observer-emit'):
            d = document(z, P + tag + '.receipt.json', ledger)
            builds[tag] = scalar_invocation(d, P + tag + '.receipt.json')
        root_names = {n for n in names if n.startswith(P) and n.count('/') == 2}
        root_calls = calls_from_members(z, root_names, ledger)
        phases = []
        all_calls = list(root_calls)
        for name in sorted(n for n in names if n.startswith(P + 'phase-') and n.endswith('.request.json') and n.count('/') == 2):
            request = document(z, name, ledger)
            stem = name[:-len('.request.json')]
            key = request['family'] + '-' + request['compiler_label']
            item = {'key': key, 'family': request['family'], 'compiler_label': request['compiler_label'], 'request_member': name,
                    'process_receipt_present': stem + '.process.json' in names, 'report_present': stem + '.json' in names}
            proc = document(z, stem + '.process.json', ledger) if item['process_receipt_present'] else None
            report = document(z, stem + '.json', ledger) if item['report_present'] else None
            if proc:
                item.update({k: proc[k] for k in ('returncode', 'started_monotonic_ns', 'completed_monotonic_ns', 'wall_elapsed_ns')})
                item['start_since_owner_ns'] = proc['started_monotonic_ns'] - start
                item['finish_since_owner_ns'] = proc['completed_monotonic_ns'] - start
                if 'archive_completed_monotonic_ns' in proc:
                    item['archive_delay_after_worker_ns'] = proc['archive_completed_monotonic_ns'] - proc['completed_monotonic_ns']
                    item['archive_finish_since_owner_ns'] = proc['archive_completed_monotonic_ns'] - start
            if report:
                item['phase_report_status'] = report['status']
                item['phase_body_and_final_input_recheck_ns'] = report['elapsed_ns']
                if proc:
                    item['process_wall_outside_phase_body_ns'] = proc['wall_elapsed_ns'] - report['elapsed_ns']
                embedded = report_calls(report['observations'])
                item['unique_embedded_native_calls'] = len(embedded)
                item['embedded_call_wall_ns_sum'] = sum(d['wall_elapsed_ns'] for d in embedded)
                item['embedded_call_native_ns_sum'] = sum(d['native_elapsed_ns'] for d in embedded)
                item['phase_elapsed_minus_embedded_call_wall_ns'] = report['elapsed_ns'] - item['embedded_call_wall_ns_sum']
                item['largest_embedded_native_calls'] = sorted([scalar_invocation(d, 'embedded-original-phase-report') for d in embedded], key=lambda r: r['native_elapsed_ns'], reverse=True)[:8]
            archive_name = P + 'phase-runs/' + key + '.zip'
            if archive_name in names:
                raw = z.read(archive_name)
                assert proc and proc['raw_artifacts']['archive_sha256'] == sha(raw)
                item['raw_archive'] = {k: proc['raw_artifacts'][k] for k in ('files', 'packed_bytes', 'unpacked_bytes', 'archive_sha256')}
                inner_ledger = {}
                with zipfile.ZipFile(io.BytesIO(raw)) as az:
                    calls = calls_from_members(az, set(az.namelist()), inner_ledger, archive_name + '!')
                inner_ledgers[key] = inner_ledger
            else:
                raw_prefix = P + 'phase-runs/' + key + '/'
                calls = calls_from_members(z, {n for n in names if n.startswith(raw_prefix)}, ledger)
                item['unarchived_members_present'] = sum(n.startswith(raw_prefix) for n in names)
            item['actual_retained_call_costs'] = summarize_calls(calls)
            all_calls.extend(calls)
            phases.append(item)
        scheduling = None
        if label == '970':
            q = document(z, 'hia-cold.cold/qualification.json', ledger)
            scheduling = q['qualification_scheduling']
            # Retain only already-original timing and inventory data, not the
            # repeated 53 MB observation tree.
            scheduling = {k: scheduling[k] for k in ('seed_started_monotonic_ns', 'reference_processes', 'maximum_host_oracle_workers', 'maximum_archive_workers', 'maximum_pending_archives')}
        data = {'input_before': before, 'cold_status': cold['status'], 'cold_wall_elapsed_ns': cold['wall_elapsed_ns'],
                'owner_returncode': owner['returncode'], 'owner_timed_out': owner['timed_out'],
                'owner_start_monotonic_ns': start, 'owner_cleanup': owner['cleanup'],
                'references': refs, 'reference_worker_wall_ns_sum': sum(d['wall_elapsed_ns'] for d in refs.values()),
                'B0_identity': {k: seed[k] for k in ('artifact_bytes', 'artifact_sha256', 'core_sha256', 'object_sha256', 'machine_text_sha256')},
                'build_invocations': builds, 'root_call_costs': summarize_calls(root_calls),
                'phase_requests_present': len(phases), 'phases': phases,
                'all_retained_call_costs': summarize_calls(all_calls),
                'root_calls': root_calls, 'original_final_scheduling': scheduling,
                'read_original_member_identities': ledger,
                'read_phase_member_identities': inner_ledgers}
    data['input_after'] = sealed(path, size, expected)
    assert data['input_before'] == data['input_after']
    return data

def main():
    out = ROOT / 'causal-cost-readback-r1'
    out.mkdir(exist_ok=False)
    start = time.monotonic_ns()
    data = {label: read_run(label, *args) for label, args in INPUTS.items()}
    old, new = data['970'], data['bde']
    comparisons = []
    oldp = {p['key']: p for p in old['phases']}
    for n in new['phases']:
        o = oldp[n['key']]
        row = {'key': n['key']}
        for k in ('start_since_owner_ns', 'wall_elapsed_ns', 'phase_body_and_final_input_recheck_ns', 'process_wall_outside_phase_body_ns',
                  'embedded_call_wall_ns_sum', 'embedded_call_native_ns_sum', 'phase_elapsed_minus_embedded_call_wall_ns', 'archive_delay_after_worker_ns'):
            if k in o and k in n:
                row[k] = {'970': o[k], 'bde': n[k], 'delta': n[k] - o[k]}
        comparisons.append(row)
    result = {'schema': 'hia.cold-original-causal-cost-readback.v1', 'status': 'ORIGINAL_TIMING_AND_BYTE_COUNTS_READ_NOT_A_PRODUCT_BENCHMARK',
              'reader_sha256': sha(pathlib.Path(__file__).read_bytes()), 'reader_python': sys.version, 'reader_elapsed_ns': time.monotonic_ns() - start,
              'scope': {'project_imported': False, 'product_reexecuted': False, 'hardware_cause_measured': False,
                        'same_180_seconds_two_workers_38_families': True, 'missing_bde_final_scheduling_not_reconstructed': True,
                        'per_call_wall_excludes_preparation_and_final_file_writes': True,
                        'summed_parallel_receipt_times_are_not_makespan': True,
                        'retained_names_companion_overwrites_46_not_recovered': True},
              'runs': data, 'paired_phase_deltas': comparisons}
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    (out / 'ORIGINAL-COSTS.json').write_bytes(raw)
    summary = {'status': result['status'], 'bytes': len(raw), 'sha256': sha(raw), 'reader_elapsed_ns': result['reader_elapsed_ns'],
               'runs': {label: {k: d[k] for k in ('cold_status', 'cold_wall_elapsed_ns', 'reference_worker_wall_ns_sum', 'root_call_costs', 'all_retained_call_costs', 'phase_requests_present')} for label, d in data.items()}}
    (out / 'SUMMARY.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
    print(json.dumps(summary, sort_keys=True))

if __name__ == '__main__':
    main()
