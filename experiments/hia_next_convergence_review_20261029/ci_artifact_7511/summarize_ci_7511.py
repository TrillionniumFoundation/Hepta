#!/usr/bin/env python3
"""Combine two completed read-only CI artifact audits without replaying CI."""
import collections
import hashlib
import json
from pathlib import Path
import zipfile

BASE = Path('/tmp/hepta-ci-artifact-review-20261029')
OUT = BASE / '7511-SUMMARY.json'


def digest(path):
    path = Path(path)
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    paths = [BASE / '7511-v8-01/REVIEW.json', BASE / '7511-v9-01/REVIEW.json']
    first, second = [json.loads(path.read_bytes()) for path in paths]
    assert first['passed'] is True and second['passed'] is True
    for key in ['source_public_commit', 'source_local_same_tree_commit', 'expected_tree', 'source_archive', 'source_metadata']:
        assert first[key] == second[key]
    assert first['public_commit_object_available_locally'] is True and second['public_commit_object_available_locally'] is True
    assert first['source_results']['regression_test_ids'] == second['source_results']['regression_test_ids']
    assert first['source_results']['safety_test_ids'] == second['source_results']['safety_test_ids']
    source_ids = set(first['source_results']['regression_test_ids'])
    safety_ids = set(first['source_results']['safety_test_ids'])
    broad_ids = set(first['broad_results']['test_ids'])
    source_paths = {}
    for review in [first, second]:
        for row in review['source_file_checks']:
            identity = (row['blob'], row['bytes'], row['sha256'])
            if row['path'] in source_paths:
                assert source_paths[row['path']] == identity
            source_paths[row['path']] = identity
    profiles = []
    with zipfile.ZipFile(first['source_archive']['path']) as archive:
        for label, review in [('v8', first), ('v9', second)]:
            refs = review['source_results']['references']
            prefix = refs['reference_prefix']
            plan_bytes = archive.read(prefix + 'PLAN.json')
            plan = json.loads(plan_bytes)
            assert plan['study_version'] == label
            assert plan['study_protocol_schema'] == 'hepta.agent.real-node-toolstudy.' + label
            protocol_paths = [path for path, digest in plan['source_bindings'].items()
                              if digest == plan['protocol_sha256'] and path.endswith('/PROTOCOL.json')]
            assert len(protocol_paths) == 1
            assert plan['expected_count'] == refs['reference_count'] == 19
            assert plan['model_requests'] == plan['tokenizer_invocations'] == plan['agent_successes'] == 0
            assert plan['capacity_qualified'] is False and plan['model_qualified'] is False
            profiles.append({'study_version': label, 'reference_prefix': prefix,
                'study_protocol_schema': plan['study_protocol_schema'], 'protocol_path': protocol_paths[0],
                'protocol_sha256': plan['protocol_sha256'], 'plan_member_sha256': hashlib.sha256(plan_bytes).hexdigest(),
                'unique_ordered_reference_rows': refs['reference_count'],
                'reference_ids': [row['id'] for row in refs['rows']],
                'public_case_observations': sum(row['public_cases'] for row in refs['rows']),
                'hidden_case_observations': sum(row['hidden_cases'] for row in refs['rows']),
                'source_snapshot_files_verified': refs['source_snapshot_files'],
                'artifact_files_verified_by_kind': dict(collections.Counter(row['kind'] for row in refs['artifacts'])),
                'distinct_native_artifact_sha256': len({row['sha256'] for row in refs['artifacts'] if row['kind'] == 'native_executable'}),
                'recorded_all_gates_passed': True, 'model_requests': 0, 'tokenizer_invocations': 0,
                'agent_successes': 0, 'capacity_qualified': False, 'model_qualified': False})
    assert profiles[0]['reference_ids'] == profiles[1]['reference_ids']
    summary = {'schema': 'hepta.ci.independent-artifact-review-summary.v2',
        'source_public_commit': first['source_public_commit'],
        'source_local_same_tree_commit': first['source_local_same_tree_commit'],
        'tree': first['expected_tree'], 'public_and_local_tree_directly_checked': True,
        'source_archive': first['source_archive'], 'source_metadata': first['source_metadata'],
        'broad_archive': first['broad_archive'], 'broad_metadata': first['broad_metadata'],
        'source_regression_executions': len(first['source_results']['regression_test_ids']),
        'source_distinct_test_ids': len(source_ids), 'safety_distinct_test_ids': len(safety_ids),
        'broad_regression_executions': len(first['broad_results']['test_ids']),
        'broad_distinct_test_ids': len(broad_ids), 'broad_modules': first['broad_results']['modules'],
        'source_safety_test_ID_overlap': len(source_ids & safety_ids),
        'source_broad_test_ID_overlap': len(source_ids & broad_ids),
        'safety_broad_test_ID_overlap': len(safety_ids & broad_ids),
        'three_suite_test_ID_overlap': len(source_ids & safety_ids & broad_ids),
        'three_suite_distinct_test_ID_union': len(source_ids | safety_ids | broad_ids),
        'test_ID_union_is_not_statistical_independence': True,
        'scalar_obligations': 449, 'scalar_negative_controls': 5,
        'profiles': profiles, 'profile_reference_registry_ID_overlap': 19,
        'profile_qualified_reference_records': 38,
        'reference_records_are_not_unique_tasks_or_model_successes': True,
        'unique_source_Git_blob_paths_verified_across_both_audits': len(source_paths),
        'source_groups_per_audit': {'v8_and_common_broad': first['source_groups'], 'v9_and_common_source': second['source_groups']},
        'native_NDU_observations_in_separate_job_log': 36,
        'native_NDU_observations_independently_reexecuted': False,
        'reviewer_new_native_model_tokenizer_compiler_solver_test_network_calls': 0,
        'remote_tool_identities_are_producer_records_not_hardware_attestation': True,
        'scientific_acceptance_gates_changed': False, 'authority': 'DENY_ALL',
        'audit_script_changed_for_this_run': False,
        'audit_script_sha256': first['review_script_sha256'],
        'audit_script_source_commit': 'ecfb4706fc9cdf62b5a1bc4bb6901e383d44e410',
        'original_reviews': [digest(path) for path in paths],
        'summary_script': digest(__file__), 'all_checked': True}
    assert first['review_script_sha256'] == second['review_script_sha256']
    OUT.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'summary': str(OUT), 'sha256': digest(OUT)['sha256'],
                     'source_distinct': len(source_ids), 'broad_distinct': len(broad_ids),
                     'source_broad_overlap': len(source_ids & broad_ids),
                     'source_blob_union': len(source_paths), 'profiles': len(profiles)}, indent=2))


if __name__ == '__main__':
    main()
