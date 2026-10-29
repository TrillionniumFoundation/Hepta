#!/usr/bin/env python3
"""Read source artifacts once, then add a separate broad-artifact review.

Reuse the unchanged 7511 review functions; never import project/runtime code.
"""
import argparse
import collections
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

PUBLIC = 'b1fc801320c1ea8d0bca4708721cad49fd591c58'
LOCAL = 'ed7958626ef213b6e9445954402e7e7ab65f3ebf'
TREE = '9c638e9506eaa08ee59c8901ebb2a44378f93af4'
REPOSITORY = Path('/workspace/scratch/220b9d034358/Hepta')
BASE = Path('/tmp/hepta-next-convergence-review-20261029/experiments/hia_next_convergence_review_20261029/ci_artifact_7511/review_ci_artifacts.py')


def digest(path):
    path = Path(path)
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': h.hexdigest()}


def load_base():
    spec = importlib.util.spec_from_file_location('existing_read_only_CI_auditor', BASE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def metadata(path, archive, expected_sha, download_path):
    raw = json.loads(Path(path).read_bytes())
    # b1fc records retain raw GitHub metadata and a separate downloader result.
    # Neither producer record is rewritten to mimic a prior wrapper schema.
    actual = digest(archive)
    assert actual['sha256'] == expected_sha
    assert raw['digest'] == 'sha256:' + expected_sha and raw['size_in_bytes'] == actual['bytes']
    assert raw['workflow_run']['head_sha'] == PUBLIC
    download = json.loads(Path(download_path).read_bytes())
    assert download['sha256'] == expected_sha and download['bytes'] == actual['bytes']
    assert download['path'] == str(archive) and download['artifact_id'] == raw['id']
    return {'archive': actual, 'metadata_receipt': digest(path), 'download_receipt': digest(download_path),
            'artifact_id': raw['id'], 'workflow_run_id': raw['workflow_run']['id'],
            'head_sha': PUBLIC, 'GitHub_digest_and_bytes_match_actual_archive': True,
            'raw_metadata_preserved_without_wrapper_rewriting': True,
            'temporary_signed_download_url_recorded_by_reviewer': False}


def tree_check(module):
    for ref in (PUBLIC, LOCAL):
        actual = module.git_output(REPOSITORY, ['rev-parse', ref + '^{tree}']).stdout.decode().strip()
        assert actual == TREE


def profile(module, archive, label, refs):
    prefix = refs['reference_prefix']
    plan_bytes = module.read_member(archive, prefix + 'PLAN.json')
    plan = json.loads(plan_bytes)
    assert plan['study_version'] == label
    assert plan['study_protocol_schema'] == 'hepta.agent.real-node-toolstudy.' + label
    matches = [name for name, value in plan['source_bindings'].items()
               if name.endswith('/PROTOCOL.json') and value == plan['protocol_sha256']]
    assert len(matches) == 1
    assert matches[0] == 'experiments/hia_agent_toolstudy_' + label + '_20261029/PROTOCOL.json'
    assert plan['expected_count'] == refs['reference_count'] == 19
    assert plan['model_requests'] == plan['tokenizer_invocations'] == plan['agent_successes'] == 0
    assert plan['capacity_qualified'] is False and plan['model_qualified'] is False
    module.register_group('reference_source_' + label, module.GROUPS.pop('reference_source'))
    return {'study_version': label, 'study_protocol_schema': plan['study_protocol_schema'],
            'protocol_path': matches[0], 'protocol_sha256': plan['protocol_sha256'],
            'plan_member_sha256': hashlib.sha256(plan_bytes).hexdigest(), 'review': refs,
            'public_case_observations': sum(row['public_cases'] for row in refs['rows']),
            'hidden_case_observations': sum(row['hidden_cases'] for row in refs['rows']),
            'artifact_files_verified_by_kind': dict(collections.Counter(row['kind'] for row in refs['artifacts'])),
            'distinct_native_artifact_sha256': len({row['sha256'] for row in refs['artifacts'] if row['kind'] == 'native_executable'})}


def source(module, args, report):
    info = metadata(args.metadata, args.archive, args.sha256, args.download)
    assert digest(args.log)['sha256'] == args.log_sha256
    report['source_archive_metadata'] = info
    report['source_log'] = digest(args.log)
    with zipfile.ZipFile(args.archive) as archive:
        report['source_zip'] = module.check_zip(archive)
        inputs = SimpleNamespace(source_tests=262, source_log=args.log, public_source=PUBLIC,
                                 reference_count=19, reference_prefix='agent-tool-native-references')
        common = module.check_source(archive, inputs)
        profiles = [profile(module, archive, 'v8', common.pop('references'))]
        for label in ('v9', 'v10'):
            refs = module.check_references(archive, PUBLIC, 19, 'agent-tool-native-references-' + label)
            profiles.append(profile(module, archive, label, refs))
        identities = [[row['id'] for row in item['review']['rows']] for item in profiles]
        assert identities[0] == identities[1] == identities[2]
        report.update(source_results=common, profiles=profiles,
                      source_and_scalar_review_executions=1,
                      profile_reference_registry_ID_overlap=19,
                      profile_qualified_reference_records=57,
                      reference_records_are_not_unique_tasks_or_model_successes=True)
    assert digest(args.archive) == info['archive']


def broad(module, args, report):
    prior_raw = Path(args.source_review).read_bytes()
    assert hashlib.sha256(prior_raw).hexdigest() == args.source_review_sha256
    prior = json.loads(prior_raw)
    assert prior['passed'] is True and prior['stage'] == 'source'
    assert prior['source_public_commit'] == PUBLIC and prior['source_local_same_tree_commit'] == LOCAL and prior['expected_tree'] == TREE
    assert prior['base_review_script'] == digest(BASE)
    assert prior['source_and_scalar_review_executions'] == 1
    report['source_review'] = digest(args.source_review)
    info = metadata(args.metadata, args.archive, args.sha256, args.download)
    assert digest(args.log)['sha256'] == args.log_sha256
    report['broad_archive_metadata'] = info
    report['broad_log'] = digest(args.log)
    module.register_group('previously_reviewed_source_stage', {row['path']: row['sha256'] for row in prior['source_file_checks']})
    with zipfile.ZipFile(args.archive) as archive:
        report['broad_zip'] = module.check_zip(archive)
        inputs = SimpleNamespace(broad_tests=args.broad_tests, broad_log=args.log, public_source=PUBLIC)
        result = module.check_broad(archive, inputs)
        report['broad_results'] = result
    source_ids = set(prior['source_results']['regression_test_ids'])
    safety_ids = set(prior['source_results']['safety_test_ids'])
    broad_ids = set(result['test_ids'])
    report['cross_suite_overlap'] = {
        'source_safety': len(source_ids & safety_ids), 'source_broad': len(source_ids & broad_ids),
        'safety_broad': len(safety_ids & broad_ids), 'triple': len(source_ids & safety_ids & broad_ids),
        'distinct_test_ID_union': len(source_ids | safety_ids | broad_ids),
        'statistical_independence_claimed': False}
    report['source_and_scalar_replayed_by_broad_stage'] = False
    assert digest(args.archive) == info['archive']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('source', 'broad'))
    for name in ('archive', 'sha256', 'metadata', 'download', 'log', 'log-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--source-review')
    parser.add_argument('--source-review-sha256')
    parser.add_argument('--broad-tests', type=int)
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    module = load_base()
    report = {'schema': 'hepta.ci.b1fc.independent-staged-artifact-review.v1', 'stage': args.stage,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'passed': False,
              'source_public_commit': PUBLIC, 'source_local_same_tree_commit': LOCAL, 'expected_tree': TREE,
              'base_review_script': digest(BASE), 'stage_driver_script': digest(__file__), 'input_arguments': vars(args),
              'reviewer_execution': dict(native=0, model=0, tokenizer=0, compiler=0, tests=0, solver=0, network_fetches=0)}
    try:
        tree_check(module)
        report['public_and_local_tree_directly_checked'] = True
        if args.stage == 'source':
            source(module, args, report)
        else:
            assert args.source_review and args.source_review_sha256 and args.broad_tests is not None
            broad(module, args, report)
        checked = module.verify_git_sources(REPOSITORY, LOCAL)
        report['git_source_blobs_verified'] = len(checked)
        report['source_file_checks'] = checked
        report['source_groups'] = {name: len(value) for name, value in module.GROUPS.items()}
        report['passed'] = True
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
    report['completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['limits'] = [
        'Existing byte/log/source checks are reused; this stage driver does not run tests, compiler, native code, solver, model, tokenizer or network fetches.',
        'Model requests, tokenizer invocations and Agent successes from CI reference controls are zero; neither capacity nor model qualification is established by CI.',
        'Tool identities and source stability are producer records, not independent remote hardware or binary attestations.',
        'Recorded scalar obligations and mutation checks are inspected without a new solver run or a whole-language refinement proof.',
        'Distinct IDs within suites and their set overlaps are not statistically independent tests.',
        'The same nineteen reference registry IDs across three profiles are fifty-seven profile-tagged controls, not fifty-seven different tasks.',
        'The source phase does not establish broad CI success. The broad supplement reads its own artifact and reuses the hash-bound source review without repeating source/scalar checks.'
    ]
    (output / 'REVIEW.json').write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    (output / 'READ_MEMBERS.json').write_text(json.dumps({'schema': 'hepta.ci.review-read-members.v1', 'files': list(module.READS.values())}, indent=2) + '\n')
    print(json.dumps({'stage': args.stage, 'passed': report['passed'], 'error': report.get('error'),
                      'source_test_ids': report.get('source_results', {}).get('distinct_regression_ids'),
                      'profile_counts': {item['study_version']: item['review']['reference_count'] for item in report.get('profiles', [])},
                      'broad_test_ids': report.get('broad_results', {}).get('distinct_test_ids'),
                      'git_source_blobs_verified': report.get('git_source_blobs_verified'), 'review': str(output / 'REVIEW.json')}, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
