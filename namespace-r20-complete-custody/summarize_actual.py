"""Offline checks and exact aggregation of the one original CI observation."""
from pathlib import Path
from collections import defaultdict
import ast
import base64
import hashlib
import json
import stat
import zlib

ROOT = Path(__file__).resolve().parent
ACTUAL = ROOT / 'actual'
RAW = ACTUAL / 'raw/Hepta/Hepta'
EVIDENCE = RAW / 'evidence'


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def read(path):
    return json.loads(path.read_bytes())


def write(path, value):
    path.open('x').write(json.dumps(value, indent=2, sort_keys=True) + '\n')


def tree_sha(files):
    root = {}
    for name, row in files.items():
        parts = name.split('/')
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        assert parts[-1] not in node
        node[parts[-1]] = (row['mode'], row['git_blob'])
    def descend(node):
        rows = []
        for name, value in node.items():
            mode, sha = ('40000', descend(value)) if isinstance(value, dict) else value
            rows.append((name.encode() + (b'/' if mode == '40000' else b''),
                         mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)))
        raw = b''.join(body for key, body in sorted(rows))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return descend(root)


def main():
    expected = read(ROOT / 'prepared-r2/harness/inputs/INPUTS.json')
    outer = read(EVIDENCE / 'REPORT.json')
    case_path = EVIDENCE / 'case-0/observations/REPORT.json'
    case = read(case_path)
    assert identity(case_path.read_bytes()) == outer['cases'][0]['report_identity']
    assert outer['status'] == case['status'] == 'OBSERVATIONS_COMPLETE'
    assert case['original_test_id'] == expected['test_id'] and case['tests_run'] == 1
    assert case['original_outcome'] == 'FAIL' and len(case['failures']) == 1
    assert case['failures'][0][0] == expected['test_id']
    assert 'line 67, in build_pair' in case['failures'][0][1]
    assert 'frozen context deadline expired before emission' in case['failures'][0][1]
    for key in ('errors', 'skipped', 'expected_failures', 'unexpected_successes', 'forbidden_calls'):
        assert case[key] == []
    assert outer['qualification'] is case['qualification'] is False
    assert outer['whole_native'] is case['whole_native'] is False
    assert outer['new_fixture_compilations'] == case['new_fixture_compilations'] == 0
    assert outer['source_unchanged'] is outer['retained_inputs_unchanged'] is True
    process = read(EVIDENCE / 'case-0/PROCESS.json')
    assert process == outer['cases'][0]['process']
    assert process['returncode'] == 0 and process['timed_out'] is False and process['same_process_group_absent'] is True
    assert process['original_group_seconds'] == 1800 and process['cleanup_seconds'] == 3
    assert outer['group_elapsed_ns'] <= 1800 * 10**9
    assert outer['python'].startswith('3.14.4 ') and case['python'] == outer['python']

    before, after = read(EVIDENCE / 'SOURCE-BEFORE.json'), read(EVIDENCE / 'SOURCE-AFTER.json')
    assert before == after and len(before['files']) == expected['source_files'] == 3177
    original_manifest_raw = (ROOT / 'prepared-r2/harness/inputs/SOURCE-MANIFEST.json').read_bytes()
    assert identity(original_manifest_raw) == expected['source_manifest']
    original_manifest = json.loads(original_manifest_raw)
    normalized = {name: {'mode': row['git_mode'], **{key: row[key] for key in ('bytes', 'sha256', 'git_blob')}}
                  for name, row in original_manifest.items()}
    assert before['files'] == normalized
    assert before['head'] == outer['source_commit'] == case['source_commit'] == expected['source_commit']
    assert before['tree'] == outer['source_tree'] == case['source_tree'] == expected['source_tree'] == tree_sha(normalized)
    test_path = ROOT.parent / 'v120-union-r20/source/tests/test_hia_agent_native_tools.py'
    test_raw = test_path.read_bytes()
    assert identity(test_raw) == expected['original_test_file'] == outer['original_test_file']
    test_module = ast.parse(test_raw)
    cls = next(node for node in test_module.body if isinstance(node, ast.ClassDef) and node.name == 'NativeLifecycleTests')
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == case['method'])
    assert outer['original_method_ast'] == {method.name: ast.dump(method, include_attributes=False)}

    harness_rows = read(ROOT / 'prepared-r2/HARNESS-MANIFEST.json')
    assert len(harness_rows) == 16
    for row in harness_rows:
        name = row['path']
        actual = RAW / 'harness' / name
        assert actual.read_bytes() == (ROOT / 'prepared-r2/harness' / name).read_bytes()
        assert identity(actual.read_bytes()) == {'bytes': row['bytes'], 'sha256': row['sha256'], 'git_blob': row['sha']}
        assert stat.S_IMODE(actual.stat().st_mode) == int(row['mode'][-3:], 8)

    part_index = read(RAW / 'harness/inputs/RETAINED-PARTS.json')
    packet_raw = b''.join((RAW / 'harness/inputs' / row['path']).read_bytes() for row in part_index['parts'])
    assert identity(packet_raw) == expected['retained_packet'] == part_index['complete']
    wrapper = json.loads(packet_raw)
    decoded = zlib.decompress(base64.b64decode(wrapper['payload'], validate=True))
    assert identity(decoded) == wrapper['decoded']
    packet = json.loads(decoded)
    retained = EVIDENCE / 'retained-original-inputs'
    retained_rows = {}
    for name, row in packet['files'].items():
        raw = base64.b64decode(row['base64'], validate=True)
        assert (retained / name).read_bytes() == raw
        assert identity(raw) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}
        assert stat.S_IMODE((retained / name).stat().st_mode) == row['mode']
        retained_rows[name] = {**identity(raw), 'mode': row['mode']}
    assert len(retained_rows) == 16
    assert read(EVIDENCE / 'RETAINED-AFTER.json') == retained_rows
    declared = read(EVIDENCE / 'RETAINED-INPUT-READBACK.json')
    assert set(declared) == set(retained_rows)
    assert {name: {key: row[key] for key in ('bytes', 'sha256', 'git_blob', 'mode')} for name, row in declared.items()} == retained_rows
    assert sorted(path.relative_to(retained).as_posix() for path in retained.rglob('*') if path.is_file()) == sorted(retained_rows)

    joint = read(retained / 'original-nested-evidence/ArtifactNamespaceNativeTests/joint-build.json')
    current_sources = joint['source_manifest']
    assert len(current_sources) == 1552
    assert all(normalized[name]['sha256'] == sha for name, sha in current_sources.items())
    fresh_expected = {name: sha for name, sha in current_sources.items() if name != 'docs/HIA_SELFHOST_CORE_SUPPORT.json'}
    assert len(fresh_expected) == 1551
    assert sum(normalized[name]['bytes'] for name in fresh_expected) == expected['expected_fresh_file_bytes_without_contract']
    assert read(EVIDENCE / 'case-0/observations/EXPECTED-FRESH-MAP.json') == fresh_expected

    profile = case['profile']
    rows = profile['rows']
    assert [row['id'] for row in rows] == list(range(len(rows)))
    for row in rows:
        assert row['outcome'] in ('RETURNED', 'RAISED') and row['end_ns'] >= row['start_ns']
        assert row['inclusive_wall_ns'] == row['end_ns'] - row['start_ns']
        if row['parent'] is not None:
            parent = rows[row['parent']]
            assert parent['start_ns'] <= row['start_ns'] <= row['end_ns'] <= parent['end_ns']
    fresh = [row for row in rows if row['kind'] == 'fresh-admission']
    admissions = [row for row in rows if row['kind'] == 'code-admission']
    effects = [row for row in rows if row['kind'] == 'publication-effect']
    children = [row for row in rows if row['kind'] == 'subprocess']
    assert len(fresh) == profile['counters']['fresh_scans'] == 110
    assert len(admissions) == profile['counters']['code_admissions'] == 110
    assert len(effects) == profile['counters']['publication_effects'] == len(children) == 311
    assert all(row['fresh_map_paths'] == 1551 and row['fresh_map_matches_exact_original'] is True for row in fresh)
    assert all(rows[row['parent']]['kind'] == 'code-admission' for row in fresh)
    assert case['store_modes'] == {'1': 1, '2': 1}
    assert case['original_store_receipt_entries'] == {'1': 1090, '2': 120}
    assert profile['native']['NativeStoreLifecycleImage']['calls'] == 1210
    assert profile['counters']['native:NativeStoreLifecycleImage'] == 1210
    for name, record in profile['native'].items():
        assert record['calls'] == profile['counters']['native:' + name]
        assert record['calls'] == sum(row['calls'] for row in record['shapes']) and record['raises'] == 0
    assert len(case['selection']) == 5
    assert {Path(value).relative_to('/home/runner/work/Hepta/Hepta/evidence/retained-original-inputs').as_posix()
            for value in case['selection'].values()}.issubset(retained_rows)

    sums = defaultdict(lambda: {'calls': 0, 'inclusive_wall_ns': 0, 'inclusive_process_cpu_ns': 0,
                               'exclusive_timed_children_wall_ns': 0})
    for row in rows:
        group = sums[row['kind'] + ':' + row['label']]
        group['calls'] += 1
        for key in ('inclusive_wall_ns', 'inclusive_process_cpu_ns', 'exclusive_timed_children_wall_ns'):
            group[key] += row[key]
    tools = []
    for row in rows:
        if row['kind'] != 'tool-call':
            continue
        within = [item for item in fresh if row['start_ns'] <= item['start_ns'] and item['end_ns'] <= row['end_ns']]
        tools.append({'id': row['id'], 'tool': row['metadata']['tool'], 'outcome': row['outcome'],
                      'wall_ns': row['inclusive_wall_ns'], 'fresh_scans': len(within),
                      'fresh_wall_ns': sum(item['inclusive_wall_ns'] for item in within),
                      'publication_effects': row['counter_after'].get('publication_effects', 0) - row['counter_before'].get('publication_effects', 0),
                      'start_wallclock_ns': row['start_wallclock_ns'], 'end_wallclock_ns': row['end_wallclock_ns']})
    operation_counts = defaultdict(lambda: {'calls': 0, 'wall_ns': 0})
    for row in children:
        assert row['metadata']['argv'][0].startswith('/proc/self/fd/')
        group = operation_counts[row['metadata']['argv'][1]]
        group['calls'] += 1
        group['wall_ns'] += row['inclusive_wall_ns']
    remaining = [row for row in rows if row['kind'] == 'remaining-budget']
    assert len(remaining) == 1 and remaining[0]['remaining_ms'] == 0
    remaining = remaining[0]
    assert remaining['budget']['max_total_wall_ms'] == 3000 and remaining['budget']['max_native_wall_ms'] == 1000
    context = next(row for row in profile['extra_observations'] if row['context_id'] == remaining['context_id'])
    created_ns = int(context['created_ns'])
    expiry_scans = [row for row in fresh if created_ns <= row['start_wallclock_ns'] and row['end_wallclock_ns'] <= remaining['start_wallclock_ns']]
    first_emit = next(row for row in tools if row['tool'] == 'hia_emit')
    timeline = {'context_id': context['context_id'], 'created_ns': created_ns,
                'first_emit_start_wallclock_ns': first_emit['start_wallclock_ns'],
                'remaining_check_start_wallclock_ns': remaining['start_wallclock_ns'],
                'created_to_first_emit_ns': first_emit['start_wallclock_ns'] - created_ns,
                'created_to_remaining_zero_ns': remaining['start_wallclock_ns'] - created_ns,
                'complete_fresh_scans_after_created_before_remaining': len(expiry_scans),
                'those_fresh_spans_wall_ns': sum(row['inclusive_wall_ns'] for row in expiry_scans),
                'source_of_created_ns': 'unchanged stored value read by the two original diagnostic SELECT observers',
                'budget': remaining['budget'], 'remaining_ms': remaining['remaining_ms']}
    artifact = read(ACTUAL / 'TRANSFER.json')
    custody = read(ACTUAL / 'CUSTODY-READBACK.json')
    summary = {'schema': 'hepta.namespace-r20-one-method-actual-readback.v1',
               'status': 'PASS_CUSTODY_AND_DIAGNOSTIC_INTEGRITY_ORIGINAL_METHOD_FAILED',
               'run': 43569339563, 'job': 132370075133,
               'harness_commit': '8b6481c1a2d784d3c590291957c5268866d8d8bd',
               'source_commit': before['head'], 'source_tree': before['tree'],
               'source_paths': len(normalized), 'source_before_after_exact': True,
               'retained_original_files': len(retained_rows), 'retained_files_before_after_exact': True,
               'harness_files_from_zip_equal_frozen_and_published': len(harness_rows),
               'fresh_source_paths': 1551, 'current_sources_paths': 1552,
               'one_fresh_source_byte_extent': expected['expected_fresh_file_bytes_without_contract'],
               'original_test_file': outer['original_test_file'], 'original_method': case['original_test_id'],
               'original_outcome': case['original_outcome'], 'tests_run': case['tests_run'],
               'failures': case['failures'], 'errors': [], 'skips': [], 'expected_failures': [], 'unexpected_successes': [],
               'case_report': identity(case_path.read_bytes()), 'original_log': identity((case_path.parent / 'ORIGINAL-TEST.log').read_bytes()),
               'outer_report': identity((EVIDENCE / 'REPORT.json').read_bytes()),
               'full_job_log': identity((ACTUAL / 'FULL-JOB.log').read_bytes()),
               'artifact': {key: artifact[key] for key in ('artifact_id', 'bytes', 'sha256', 'git_blob')},
               'zip_members': custody['members'], 'raw_bytes': custody['raw_bytes'], 'raw_member_modes': custody['regular_file_modes'],
               'zip_has_original_directory_modes': False, 'raw_directory_modes_are_constructed': True,
               'prerequisites': outer['prerequisites'], 'process': process,
               'group_elapsed_ns': outer['group_elapsed_ns'], 'group_limit_seconds': 1800, 'cleanup_seconds': 3,
               'supervision_scope': 'child wait and same process-group absence; no ECHILD or subreaper assertion in this inherited diagnostic supervisor',
               'profile_spans': len(rows), 'counters': profile['counters'], 'row_aggregations': dict(sums),
               'unexpanded_aggregates': profile['aggregates'], 'tool_stages': tools,
               'subprocess_operations': dict(operation_counts), 'deadline_timeline': timeline,
               'original_store_receipt_entries': case['original_store_receipt_entries'],
               'store_modes': case['store_modes'], 'forbidden_calls': [],
               'extra_observations': profile['extra_observations'],
               'after_timer_fresh_map_comparison_ns': sum(row['observer_after_timer_ns'] for row in fresh),
               'native_sample_scope': 'all calls counted after admission; only ordinals 1 modulo 64 timed, no extrapolated total',
               'original_limitations': profile['limitations'],
               'additional_limitations': [
                   'Nested inclusive spans and aggregate-only methods overlap; totals must not be added.',
                   'The unchanged original method failed before its first baseline emission and did not reach later assertions.',
                   'The complete source identities are the actual CI before/after snapshot and exact checked-out Git tree; no second local product source was executed.',
                   'No new cold qualification, no replacement bytes, no memo, no cached digest, no time-budget changes.',
                   'The Store generic observer was intentionally corrected; cross-run wall-time changes are not an optimization comparison.',
                   'Two bounded Clang/ld prerequisite probes occur before the 1800-second observed group.',
                   'The original runner retains unittest outcome/log and fixed suite identity, not independent loaded/start/stop JSONL events.'
               ], 'qualification': False, 'whole_native': False,
               'local_product_executions_during_readback': 0, 'deleted_inputs': []}
    write(ACTUAL / 'ACTUAL-READBACK.json', summary)
    print(json.dumps({'status': summary['status'], 'summary': identity((ACTUAL / 'ACTUAL-READBACK.json').read_bytes()),
                      'deadline_timeline': timeline, 'subprocess_operations': dict(operation_counts)}))


if __name__ == '__main__':
    main()
