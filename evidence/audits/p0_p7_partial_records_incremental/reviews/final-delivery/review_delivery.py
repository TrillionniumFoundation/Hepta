"""Read-only review of frozen delivery files; never executes archived code."""
import collections
import datetime
import difflib
import hashlib
import json
import os
import re
import stat
import subprocess
import tarfile
from pathlib import Path, PurePosixPath

STAGE = Path('/tmp/hepta-next-evidence-staging-20261028')
BASE = STAGE / 'evidence/audits/p0_p7_partial_records_incremental'
REPO = Path('/workspace/scratch/4bc91e0ee48c/hepta-followup-integration')
OUT = Path(__file__).resolve().parent
COMMIT = 'd942f18b07c8811aa1418b6f67fabc23212317d1'
TREE = '44823c1858d52e9043edebb83f2414d91087d743'
TESTED = '4a64e1a353585d0ee88985e4942c008bd82ec1482be7ce1158a60f24f550e8db'
DELIVERY = '02048763eb93a39418e5ae2b64f3b1ce8acae9bb92dccb45cdd95f70a6f57e22'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def stable_read(path, *, allow_symlink=False):
    path = Path(path)
    if not allow_symlink:
        assert stat.S_ISREG(path.lstat().st_mode), ('not a regular file', str(path))
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), ('changed while reading', str(path))
    assert len(data) == after.st_size
    return data


def descriptor(path, *, allow_symlink=False):
    data = stable_read(path, allow_symlink=allow_symlink)
    return {'path': str(path), 'bytes': len(data), 'sha256': sha(data)}


def load(relative):
    return json.loads(stable_read(BASE / relative))


def safe_relative(value):
    assert type(value) is str and value and '\\' not in value and ':' not in value
    assert not any(ord(c) < 32 for c in value)
    path = PurePosixPath(value)
    assert not path.is_absolute() and path.as_posix() == value
    assert all(part not in {'', '.', '..'} for part in path.parts)
    return value


def inventory():
    files = []
    for path in sorted(STAGE.rglob('*')):
        if path.is_dir():
            assert not path.is_symlink()
            continue
        entry = descriptor(path)
        entry['relative_path'] = safe_relative(path.relative_to(STAGE).as_posix())
        files.append(entry)
    return files


def git_identity():
    environment = dict(os.environ, GIT_OPTIONAL_LOCKS='0')
    def run(*args):
        result = subprocess.run(['git', '--no-optional-locks', *args], cwd=REPO,
                                env=environment, capture_output=True, timeout=30, check=True)
        assert not result.stderr
        return result.stdout.decode().strip()
    return {'commit': run('rev-parse', 'HEAD'), 'tree': run('rev-parse', 'HEAD^{tree}'),
            'status': run('status', '--porcelain')}


report = {'schema': 'hepta.final-delivery-readonly-review.v1', 'passed': False,
          'stage': str(STAGE), 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'applications_tests_compilers_executed': False, 'archived_code_executed': False,
          'stage_or_original_files_written': False, 'checks': [], 'failures': []}
archive_bytes = {}


def check(name, operation):
    try:
        details = operation()
        report['checks'].append({'name': name, 'passed': True, 'details': details})
    except Exception as exc:
        issue = {'name': name, 'type': type(exc).__name__, 'message': str(exc)}
        report['checks'].append({'name': name, 'passed': False})
        report['failures'].append(issue)


before = inventory()
repo_before = git_identity()
report['stage_before'], report['repo_before'] = before, repo_before


def source_check():
    assert len(before) == 40
    outside = [x['relative_path'] for x in before if not x['relative_path'].startswith('evidence/audits/p0_p7_partial_records_incremental/')]
    assert outside == ['docs/HIA_INCREMENTAL_VERIFICATION.md']
    assert repo_before == {'commit': COMMIT, 'tree': TREE, 'status': ''}
    executed = load('source/executed-source.json')
    local = load('source/local-freeze.json')
    expected = executed['source_snapshot']
    assert executed['remote_commit'] == COMMIT and executed['remote_tree'] == TREE
    assert executed['tree_equal'] and executed['clean']
    assert local['source_snapshot'] == expected
    assert len(expected['files']) == 1065
    assert sha(wire(expected['files'])) == expected['sha256'] == TESTED
    actual = {}
    for relative, digest in expected['files'].items():
        safe_relative(relative)
        actual[relative] = sha(stable_read(REPO / relative))
        assert actual[relative] == digest, relative
    assert sha(wire(actual)) == TESTED
    docplan = load('source/documentation-clarification-plan.json')
    relative = 'docs/HIA_INCREMENTAL_VERIFICATION.md'
    old = stable_read(REPO / relative)
    new = stable_read(STAGE / relative)
    assert sha(old) == docplan['before_sha256'] and sha(new) == docplan['after_sha256']
    old_phrase = ("intermediate candidates are not admitted. A session serializes its operations,\n"
                  "so two patches for one expected baseline cannot both commit different results:\n"
                  "the later attempt observes a stale digest. Multiple sessions are independent.")
    new_phrase = ("intermediate candidates are not admitted. A session serializes its operations\n"
                  "and checks each patch's expected digest against the current baseline under the\n"
                  "same lock. If the first accepted patch changes the digest, the next patch naming\n"
                  "the old digest is rejected as stale; an accepted canonical no-op leaves that\n"
                  "digest valid. Multiple sessions are independent.")
    assert old.decode().count(old_phrase) == 1
    assert old.decode().replace(old_phrase, new_phrase) == new.decode()
    overlay = dict(actual)
    overlay[relative] = sha(new)
    assert sha(wire(overlay)) == docplan['expected_delivery_snapshot_sha256'] == DELIVERY
    assert TESTED != DELIVERY and not docplan['applied_to_tested_worktree']
    assert not docplan['executable_source_changes']
    return {'files_read': 1065, 'tested_snapshot': TESTED, 'documentation_overlay_snapshot': DELIVERY,
            'only_changed_source_path': relative, 'executable_source_changed': False}


check('source and one-paragraph documentation overlay', source_check)


def archive_check():
    summaries = []
    all_omissions = []
    manifests = sorted((BASE / 'archives').glob('*.manifest.json'))
    assert len(manifests) == 6
    total_members = total_bytes = 0
    for path in manifests:
        data = json.loads(stable_read(path))
        assert data['schema'] == 'hepta.evidence.text-archive.v1'
        archived = BASE / safe_relative(data['archive'])
        desc = descriptor(archived)
        assert desc['bytes'] == data['bytes'] and desc['sha256'] == data['sha256']
        expected = {safe_relative(x['member']): x for x in data['members']}
        assert len(expected) == len(data['members'])
        observed = []
        with tarfile.open(archived, 'r:gz') as bundle:
            for member in bundle:
                safe_relative(member.name)
                assert member.isfile() and not member.issym() and not member.islnk(), member.name
                assert member.name not in observed and member.name in expected, member.name
                assert 0 <= member.size <= 16 * 1024 * 1024, member.name
                entry = expected[member.name]
                assert member.size == entry['bytes'], member.name
                stream = bundle.extractfile(member)
                assert stream is not None
                content = stream.read()
                assert len(content) == entry['bytes'] and sha(content) == entry['sha256'], member.name
                assert not content.startswith(b'\x7fELF') and b'\x00' not in content, member.name
                content.decode('utf-8')
                original = Path(entry['original_path'])
                assert original.is_absolute() and str(original).startswith('/tmp/')
                assert stable_read(original) == content, str(original)
                old = archive_bytes.get(str(original))
                assert old is None or old == content
                archive_bytes[str(original)] = content
                observed.append(member.name)
                total_members += 1
                total_bytes += len(content)
        assert set(observed) == set(expected)
        included_originals = {x['original_path'] for x in data['members']}
        omission_paths = []
        for item in data['omitted']:
            original = Path(item['original_path'])
            assert str(original) not in included_originals
            assert str(original) not in omission_paths
            assert item['reason'] and 'excluded' in item['reason']
            if 'symlink_target' in item:
                assert original.is_symlink() and os.readlink(original) == item['symlink_target']
            else:
                assert not original.is_symlink()
            desc = descriptor(original, allow_symlink='symlink_target' in item)
            assert desc['bytes'] == item['bytes'] and desc['sha256'] == item['sha256']
            assert stable_read(original, allow_symlink='symlink_target' in item).startswith(b'\x7fELF')
            omission_paths.append(str(original))
            all_omissions.append(item)
        assert data['roundtrip_bytes_verified'] and not data['original_receipts_rewritten']
        assert not data['raw_model_payload_included'] and not data['original_108762ba_archive_included']
        summaries.append({'manifest': path.name, 'members': len(observed), 'omissions': len(omission_paths),
                          'archive_bytes': data['bytes'], 'archive_sha256': data['sha256']})
    assert total_members == 1172 and len(all_omissions) == 22
    return {'archives': summaries, 'member_count': total_members, 'member_bytes': total_bytes,
            'omission_count': len(all_omissions), 'safe_regular_file_members_only': True,
            'each_member_matches_manifest_and_original': True, 'omitted_binaries_match_originals': True}


check('six archive inventories and source bytes', archive_check)


def exact_copy_check():
    mapping = load('source/exact-copy-map.json')
    assert len(mapping['files']) == 24
    seen, late = set(), []
    for item in mapping['files']:
        relative = safe_relative(item['published_relative_path'])
        assert relative not in seen and item['copied_without_rewriting']
        seen.add(relative)
        source = item['original']
        original = stable_read(Path(source['path']))
        copied = stable_read(BASE / relative)
        assert original == copied
        assert len(copied) == source['bytes'] and sha(copied) == source['sha256']
        if item.get('added_after_full_archive_snapshot'):
            late.append(relative)
    assert late == ['integrated/progress-observer-clarification.json']
    clarification = load(late[0])
    assert clarification['formal_and_independent_canonical_count'] == 2548
    assert clarification['live_observer_final_strict_start_count'] == 2547
    assert not clarification['additional_tests_executed']
    assert not clarification['original_reports_logs_manifests_or_completion_modified']
    assert clarification['source_commit'] == COMMIT
    return {'exact_copies': 24, 'late_copy_explicitly_labeled': late, 'all_equal_to_original_and_stage': True}


check('24 exact-copy records', exact_copy_check)


def integrated_check():
    status = load('current-status.json')
    completion = load('integrated/execution-completion.json')
    summary = load('integrated/summary.json')
    assert completion['git_commit'] == summary['git_commit'] == COMMIT
    for key in ['source_before', 'source_after']:
        source = completion[key]
        assert source['git_commit'] == COMMIT and source['git_tree'] == TREE
        assert source['snapshot_sha256'] == TESTED and source['snapshot_file_count'] == 1065
        assert source['git_status'] == '' and source['capture_errors'] == []
        assert summary[key]['official_snapshot']['sha256'] == TESTED
    assert completion['source_unchanged'] and completion['tools_unchanged'] and summary['ok']
    assert completion['observed_runner_returncode'] == 0
    stderr = stable_read(BASE / 'integrated/unit.stderr.log').decode()
    footer = re.search(r'^Ran (\d+) tests in ([0-9.]+)s\n\nOK\n?\Z', stderr, re.M)
    assert footer and int(footer[1]) == 2548 and float(footer[2]) == 2187.813
    matched = re.findall(r'^(test[^\s(]+) \(([^()\r\n]+)\)(?:[ \t].*)?$', stderr, re.M)
    methods = []
    for short, qualified in matched:
        assert qualified.endswith('.' + short)
        methods.append(qualified)
    retained = stable_read(BASE / 'integrated/canonical-unittest-ids.txt').decode().splitlines()
    assert len(methods) == len(set(methods)) == len(retained) == len(set(retained)) == 2548
    assert methods == retained
    assert not re.search(r'\.\.\. (?:skipped|FAIL|ERROR|expected failure|unexpected success)', stderr)
    cargo = stable_read(BASE / 'integrated/cargo.stdout.log').decode()
    harnesses = re.findall(r'^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$', cargo, re.M)
    assert len(harnesses) == 9
    assert sum(int(row[1]) for row in harnesses) == 54
    assert all(row[0] == 'ok' and all(int(x) == 0 for x in row[2:6]) for row in harnesses)
    assert len(re.findall(r'^test .* \.\.\. ok$', cargo, re.M)) == 54
    assert completion['unit']['tests_run'] == completion['unit']['unique_canonical_method_count'] == 2548
    assert completion['cargo_test']['passed'] == 54 and completion['cargo_test']['harness_summary_count'] == 9
    for key in ['skipped', 'failures', 'errors']:
        assert completion['unit'][key] == 0
    assert len(completion['preflights_separate_from_formal_tests']) == 2
    assert all(x['classification'] == 'preflight' and x['passed'] for x in completion['preflights_separate_from_formal_tests'])
    frozen = '/tmp/hepta-next-integrated-d942f18b-20261028/'
    for name, limit in [('unit-discovery', 3600), ('cargo-test', 240)]:
        plan = json.loads(archive_bytes[frozen + name + '/plan.json'])
        result = json.loads(archive_bytes[frozen + name + '/report.json'])
        assert plan['timeout_seconds'] == result['timeout_seconds'] == limit
        assert result['ok'] and not result['timed_out'] and result['returncode'] == 0
    integrated = status['integrated_validation']
    assert integrated['python_tests'] == integrated['python_unique_methods'] == 2548
    assert integrated['rust_passed'] == 54 and integrated['rust_harnesses'] == 9
    assert integrated['python_footer_seconds'] == float(footer[2])
    assert integrated['python_command_seconds'] == completion['unit']['command_duration_seconds']
    assert integrated['rust_command_seconds'] == completion['cargo_test']['command_duration_seconds']
    assert not completion['all_19_gates_requalified'] and not completion['performance_requalified']
    return {'python_tests_and_unique_methods': 2548, 'python_skips_failures_errors': 0,
            'rust_passed': 54, 'rust_harnesses': 9, 'rust_failures_ignored_filtered': 0,
            'python_footer_seconds': 2187.813, 'commit': COMMIT, 'snapshot': TESTED,
            'preflights_counted_as_tests': False, 'tests_executed_by_review': False}


check('full-suite terminal logs and d942 identity', integrated_check)


def native_and_claims_check():
    status = load('current-status.json')
    partial = load('native/partial-records.json')
    cpp = load('native/cpp-constexpr.json')
    two = load('native/two-owner-cancel.json')
    assert partial['passed'] and len(partial['cases']) == len(partial['differential']) == 94
    assert len(partial['budgets']) == 11
    budget_outcomes = collections.Counter(x['python']['status'] for x in partial['budgets'])
    assert budget_outcomes == {'budget_exceeded': 10, 'returned': 1}
    assert sum(len(x['cases']) for x in partial['native'].values()) == 188
    assert len(partial['negative_controls']) == 2 and all(x['detected'] for x in partial['negative_controls'])
    n, c = [partial['native'][x]['compilation'] for x in ['nominal', 'core']]
    assert n['artifact_bytes'] == c['artifact_bytes'] == 2056
    assert n['artifact_sha256'] == c['artifact_sha256'] and n['llvm_ir_sha256'] == c['llvm_ir_sha256']
    controls = {x['name']: x['observed'] for x in partial['negative_controls']}
    assert controls['missing_free']['result'] == 177 and controls['missing_free']['live'] == 3
    assert controls['missing_free']['live_bytes'] == 21
    assert controls['wrong_byte']['result'] == 178 and controls['wrong_byte']['live_bytes'] == 0
    assert partial['git_commit'] == COMMIT
    for relative in ['native/partial-records-outer.json', 'native/cpp-constexpr-outer.json']:
        outer = load(relative)
        assert outer['passed'] and outer['source_unchanged'] and outer['tools_unchanged']
        for key in ['source_before', 'source_after']:
            assert outer[key]['commit'] == COMMIT and outer[key]['snapshot']['sha256'] == TESTED
    assert cpp['ok'] and cpp['case_count'] == len(cpp['cases']) == 80
    assert cpp['native_result_executions'] == 160
    assert cpp['observed']['original_cpp'] == cpp['observed']['standalone_hia'] == cpp['expected']
    assert len(cpp['capture']['configurations']) == 2
    instances = {instance for group in cpp['template_instances'] for instance in group['instances']}
    assert len(instances) == 7 and len(cpp['constexpr_selections']) == 13
    assert cpp['original_cpp_link_inputs_in_target'] == []
    assert not cpp['claims']['original_cpp_implementation_in_target']
    assert two['passed'] and two['source_unchanged'] and two['tools_unchanged']
    assert not two['production_compile_api_used']
    assert two['counts'] == {'requests': 32, 'python_executions': 64, 'rust_executions': 32,
                             'positive_native_executions': 64, 'negative_native_executions': 4}
    assert len(two['python']) == 64 and len(two['differential']) == 32
    orders = collections.Counter(tuple(x['observed']['free_order']) for group in two['native'].values() for x in group['cases'])
    assert orders == {(2, 1): 24, (1,): 32, (): 8}
    for control in two['negative_controls']:
        assert control['detected'] and control['valid_core'] and not control['equivalent_to_original']
        observed, expected = control['observed'], control['expected']
        assert observed['free_order'] == [1, 2] and expected['free_order'] == [2, 1]
        assert {k:v for k,v in observed.items() if k != 'free_order'} == {k:v for k,v in expected.items() if k != 'free_order'}
    for key in ['source_before', 'source_after']:
        assert two[key]['commit'] == COMMIT and two[key]['snapshot']['sha256'] == TESTED
    assert status['tested_implementation']['commit'] == COMMIT
    assert status['tested_implementation']['source_snapshot_sha256'] == TESTED
    assert status['delivery_source']['expected_snapshot_sha256'] == DELIVERY
    assert not status['delivery_source']['full_suite_relabelled_to_delivery_commit']
    assert not status['all_p0_p7_stages_complete'] and not status['whole_project_blockers_closed']
    assert len(status['stages']) == 8 and all(not s['complete'] and s['remaining_conditions'] for s in status['stages'])
    assert not any(status['claims'].values())
    readme = stable_read(BASE / 'README.md').decode()
    assert '@@' not in readme
    assert 'The 24 positive\nnative executions with two successfully allocated payloads observe `[2,1]`' in readme
    assert 'For the tested pair of valid conflicting patches that change the same baseline' in readme
    assert 'not represented\nas the original full-suite snapshot' in readme
    return {'partial_cases': 94, 'partial_budgets': dict(budget_outcomes), 'partial_positive_native': 188,
            'partial_controls': 2, 'cpp_cases': 80, 'cpp_native_calls': 160, 'cpp_template_instances': 7,
            'cpp_constexpr_selections': 13, 'two_owner_counts': two['counts'],
            'two_owner_positive_native_orders': {str(k):v for k,v in orders.items()},
            'all_complete_claims_false': True, 'eight_remaining_stage_obligations_preserved': True}


check('native finite counts and bounded delivery claims', native_and_claims_check)

after = inventory()
repo_after = git_identity()
report['stage_unchanged'] = before == after
report['repo_after'] = repo_after
report['repository_identity_unchanged'] = repo_before == repo_after
if not report['stage_unchanged'] or not report['repository_identity_unchanged']:
    report['failures'].append({'name': 'read-only invariant', 'message': 'stage or repository changed during review'})
report['stage_file_count'] = len(before)
report['stage_bytes'] = sum(x['bytes'] for x in before)
report['stage_inventory_sha256'] = sha(wire(before))
report['passed'] = not report['failures']
report['status'] = 'ready_for_publication_with_stated_scope' if report['passed'] else 'issues_found'
report['completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
with (OUT / 'review.json').open('x', encoding='utf-8') as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps({'status': report['status'], 'checks': len(report['checks']), 'failures': report['failures'],
                  'stage_files': len(before), 'stage_bytes': report['stage_bytes'],
                  'report': descriptor(OUT / 'review.json')}, sort_keys=True))
if not report['passed']:
    raise SystemExit(1)
