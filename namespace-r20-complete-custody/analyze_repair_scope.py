"""Aggregate frozen observations only; no product imports, runs or edits."""
from pathlib import Path
from collections import Counter, defaultdict
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    inputs = {
        'readback': ROOT / 'actual/ACTUAL-READBACK.json',
        'case': ROOT / 'actual/raw/Hepta/Hepta/evidence/case-0/observations/REPORT.json',
        'manifest': ROOT / 'prepared-r2/harness/inputs/SOURCE-MANIFEST.json',
        'old_components': WORK / 'v94-native-namespace-budget-r1/ci-components-r1/actual/raw/evidence/REPORT.json',
        'old_guard': WORK / 'v94-native-namespace-budget-r1/ci-guard-r2/actual/raw/evidence/REPORT.json',
        'old_memo': WORK / 'v94-native-namespace-budget-r1/memo-handoff-r1/SUMMARY.json',
    }
    before = {key: {'path': str(p), **identity(p.read_bytes())} for key, p in inputs.items()}
    data = {key: json.loads(p.read_bytes()) for key, p in inputs.items()}
    summary, case = data['readback'], data['case']
    assert before['case']['git_blob'] == summary['case_report']['git_blob']
    assert summary['original_outcome'] == case['original_outcome'] == 'FAIL'
    wanted = {
        'hepta/artifact_publication_native.py': ['_admitted_code', '_validated_code', 'admit_artifact_store', '_execute_native'],
        'tools/build_hia_json_preflight.py': ['current_sources'],
        'tools/hia_selfhost_contract.py': ['_source_capture_protocol', '_source_protocol_current', '_source_relative_name', '_source_lexical_read', 'file_digests', 'support_contract', 'validate_contract'],
        'hepta/hia_artifact_namespace_native.py': ['_operate', '_invoke', '_drive'],
        'hepta/hia_agent_store.py': ['_native_artifact_admission', '_native_artifact_file', '_put_reference'],
        'hepta/hia_agent_service.py': ['_remaining_ms', '_compile_reference', '_hia_emit_reference'],
        'tests/test_hia_agent_native_tools.py': ['build_pair', 'test_expired_evaluation_is_rejected_before_any_reference_or_native_runner'],
    }
    source = WORK / 'v120-union-r20/source'
    sources = {}
    for name, names in wanted.items():
        raw = (source / name).read_bytes()
        observed = identity(raw)
        assert observed == {k: data['manifest'][name][k] for k in observed}, name
        functions = defaultdict(list)
        for node in ast.walk(ast.parse(raw)):
            if isinstance(node, ast.FunctionDef) and node.name in names:
                functions[node.name].append([node.lineno, node.end_lineno])
        assert set(functions) == set(names), (name, functions)
        sources[name] = {**observed, 'function_lines': dict(functions)}

    rows = case['profile']['rows']
    assert len(rows) == 1036 and [r['id'] for r in rows] == list(range(1036))
    routes, counts, ancestry = Counter(), Counter(), []
    for row in rows:
        if row['kind'] != 'code-admission':
            continue
        parent = row['parent']
        while parent is not None and rows[parent]['kind'] != 'public-store':
            parent = rows[parent]['parent']
        label = rows[parent]['label'] if parent is not None else 'initial_without_public_store'
        routes[label] += 1
        if parent is not None:
            counts[parent] += 1
        ancestry.append({'admission': row['id'], 'public_span': parent, 'label': label})
    assert len(ancestry) == 110 and len(counts) == 109 and max(counts.values()) == 1
    timeline = summary['deadline_timeline']
    start, stop = timeline['created_ns'], timeline['remaining_check_start_wallclock_ns']
    totals = defaultdict(lambda: {'calls': 0, 'wall_ns': 0})
    for row in rows:
        if start <= row['start_wallclock_ns'] and row['end_wallclock_ns'] <= stop:
            totals[row['kind']]['calls'] += 1
            totals[row['kind']]['wall_ns'] += row['inclusive_wall_ns']
    assert totals['fresh-admission'] == {'calls': 47, 'wall_ns': 2845171254}
    assert totals['code-admission'] == {'calls': 47, 'wall_ns': 2990008460}
    assert totals['publication-effect'] == {'calls': 112, 'wall_ns': 117299469}
    elapsed = stop - start
    gap = elapsed - timeline['budget']['max_total_wall_ms'] * 1000000
    assert elapsed == 3542386194 and gap == 542386194
    fresh = totals['fresh-admission']['wall_ns']
    result = {
        'schema': 'hepta.namespace-r20-readonly-repair-scope.v1',
        'status': 'NO_ADOPTABLE_SUFFICIENT_PATCH_PROVEN',
        'product_executions': 0, 'product_edits': [], 'new_experiments': [],
        'qualification': False, 'whole_native': False,
        'inputs': before, 'source_function_ranges': sources,
        'source_commit': summary['source_commit'], 'source_tree': summary['source_tree'],
        'run': summary['run'], 'job': summary['job'],
        'original_test_id': summary['original_method'], 'original_outcome': 'FAIL',
        'public_admissions': {'routes': dict(routes), 'mapping': ancestry,
                              'distinct_public_calls': 109, 'calls_with_duplicate_admission': 0},
        'deadline': {'timeline': timeline, 'complete_span_totals': dict(totals),
                     'nested_totals_must_not_be_added': True,
                     'gap_ns': gap, 'fresh_reduction_fraction_lower_bound': gap / fresh,
                     'total_reduction_fraction_lower_bound': gap / elapsed,
                     'required_mean_fresh_saving_ns': gap / 47,
                     'current_mean_fresh_ns': fresh / 47,
                     'maximum_mean_fresh_at_exact_deadline_ns': (fresh - gap) / 47,
                     'logical_fresh_bytes': 47 * summary['one_fresh_source_byte_extent'],
                     'admission_overhead_outside_fresh_ns': totals['code-admission']['wall_ns'] - fresh,
                     'scope': 'First remaining-time check only. First compile, second emission and encoding were not reached; no complete-method success estimate.'},
        'old_results_not_rerun': {
            'component_scope': '1429 paths / 51971962 bytes, not an R20 per-component profile',
            'scans': data['old_components']['scans'],
            'pure_hash': data['old_components']['owned_byte_hash_runs'],
            'capabilities': data['old_components']['capabilities'],
            'guard_means': data['old_guard']['comparison']['means_ns'],
            'memo_summary': data['old_memo'],
            'hardware_flags_do_not_prove_dispatch': True,
        },
        'reviewable_ranges': [
            {'functions': '_source_capture_protocol / _source_protocol_current',
             'scope': 'Immutable bookkeeping only; every per-read mutable-provider check, fallback, exact bytes lifetime and read-close-hash ordering must remain.',
             'limit': 'No new candidate. Prior guard whole-scan gain 2.27485 percent is already known and cannot establish the required R20 gain.'},
            {'functions': 'support_contract / validate_contract / current_sources',
             'scope': 'Internal construction only, preserving fresh dictionaries and both temporally separate contract reads with all provider semantics.',
             'limit': 'Entire measured non-fresh admission overhead is 144837206 ns, less than the 542386194 ns first-check gap.'},
            {'functions': 'Implementation behind the same admitted _hashlib.openssl_sha256 callable',
             'scope': 'A runtime/library issue would require separate exact binary/dispatch evidence while preserving callable identity, argument/refcount boundary and ordering.',
             'limit': 'No backend defect or disabled dispatch is established. No provider substitution or new hash/ABBA experiment is proposed.'},
        ],
        'excluded': ['cross-public-call memo/cache', 'prior rejected memo R1/R2/R3 or renamed carrier',
                     'manifest pruning or previous cold hashes', 'hoisted mutable provider/SHA binding',
                     'read/hash reordering, parallel batch or hashing before close',
                     'memoryview/mmap replacing the bytes argument', 'one admission per Session instead of public Store call',
                     'changing created_ns or deadlines', '_sha2 provider substitution'],
        'conclusion': 'The existing call-local admission already removes repeated admission inside each public Store call. No safe and sufficiently fast product patch follows from these observations alone.',
    }
    assert {key: {'path': str(p), **identity(p.read_bytes())} for key, p in inputs.items()} == before
    for name, row in sources.items():
        assert identity((source / name).read_bytes()) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
    result['small_inputs_before_after_exact'] = True
    output = ROOT / 'analysis-r1'
    output.mkdir(exist_ok=False)
    raw = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with (output / 'REPAIR-SCOPE.json').open('xb') as stream:
        stream.write(raw)
    print(json.dumps({'path': str(output / 'REPAIR-SCOPE.json'), **identity(raw),
                      'product_executions': 0, 'status': result['status']}))


if __name__ == '__main__':
    main()
