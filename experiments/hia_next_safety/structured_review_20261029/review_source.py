"""Read-only evidence audit. Does not import or run the editor/VM/native tools."""
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess

ROOT = Path('/tmp/hepta-next-agent-structured-20261029')
OUT = Path('/tmp/hepta-structured-independent-review-677a159')
FINAL = '677a15928c1dd3b236c7bee8cf4b3e6041177f6c'
INTERMEDIATE = 'a22d6fe5910e8f9cc08713d7bf9e1194e8644484'
EARLIER = 'e5b0766400970a3bacc38aea5f4dfbcb7f903f43'
BASE = 'f695384324d2de784f727d349bd67891f7f45bd3'


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, timeout=15)


def identity(path):
    path = Path(path)
    assert path.is_file() and path.stat().st_size <= 128 * 1024 * 1024
    with path.open('rb') as stream:
        value = sha256()
        while data := stream.read(1024 * 1024):
            value.update(data)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': value.hexdigest()}


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def load(path):
    return json.loads(Path(path).read_bytes())


def check_query(query):
    content = dict(query)
    expected = content.pop('query_sha256')
    assert digest(content) == expected
    if 'edit_query' in content:
        check_query(content['edit_query'])


def audit_run(folder, revision, current=False):
    folder = Path(folder)
    report = load(folder / 'CONTROLS.json')
    plan = load(folder / 'PLAN.json')
    assert report['source_commit'] == plan['source_commit'] == revision
    assert report['source_bindings'] == plan['source_bindings']
    assert report['count'] == report['passed'] == 9
    assert report['source_unchanged'] and report['tools_unchanged']
    assert report['model_requests'] == report['main_cells_started'] == 0
    bindings = report['source_bindings']
    for name, expected in bindings.items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        assert sha256(git('show', revision + ':' + name)).hexdigest() == expected
        assert identity(folder / 'source_snapshot' / name)['sha256'] == expected
        if current:
            assert identity(ROOT / name)['sha256'] == expected
    rows = []
    by_id = {}
    for row in report['rows']:
        ident = row['id']
        assert '/' not in ident and '..' not in ident
        location = folder / ident
        t = load(location / 'TRANSACTION.json')
        assert t == row['transaction'] and row['passed']
        assert not row['model_answer'] and not t['hidden_evaluated'] and not t['source_published']
        assert t['failed_transaction_left_source_unchanged']
        if not t['accepted']:
            assert t['before_revision'] == t['after_revision']
        query = load(location / 'QUERY.json')
        response = load(location / 'RESPONSE.json')
        check_query(query)
        assert query['source_revision'] == t['before_revision']
        if ident != 'rust_stale_revision_replay':
            assert response['source_revision'] == query['source_revision']
            assert response['query_sha256'] == query['query_sha256']
        else:
            assert response['source_revision'] != query['source_revision']
            assert 'build' not in t
        item = {'id': ident, 'accepted': t['accepted'], 'status': t['status'],
                'transaction': identity(location / 'TRANSACTION.json'),
                'query': identity(location / 'QUERY.json'),
                'response': identity(location / 'RESPONSE.json')}
        if 'build' in t:
            built = t['build']
            candidate = Path(built['folder'])
            assert candidate == location / 'candidate'
            language = built['language']
            names = ('api.rs', 'client.rs', 'audit.rs', 'utility.rs') if language == 'rust' else (
                'api.hia.json', 'client.hia.json', 'audit.hia.json', 'utility.hia.json')
            files = {name: (candidate / name).read_bytes().decode() if language == 'rust'
                     else load(candidate / name) for name in names}
            assert digest({name: files[name] for name in names[:2]}) == built['receipt']['replacement_sha256']
            assert digest({name: files[name] for name in names[2:]}) == built['receipt']['unchanged_files_sha256']
            item['actual_written_candidate_revision'] = digest(files)
            if t['accepted']:
                assert item['actual_written_candidate_revision'] == t['after_revision']
            structural = t['structural_edit']
            if language == 'rust':
                assert digest(files) == structural['after_sha256']
                assert structural['whole_functions_supplied_by_model'] == 0
                assert not structural['source_published'] and not structural['type_or_ownership_admitted']
            else:
                edited_core = {'schema': 'hepta.hia.program.v6', 'module': built['task'],
                               'exports': ['entrypoint'], 'functions': [files[name] for name in names]}
                assert digest(edited_core) == structural['after_sha256']
                assert structural['structured_editor']['whole_functions_supplied_by_model'] == 0
                assert not structural['structured_editor']['source_published']
                core = Path(built['core_path'])
                assert core == candidate / 'candidate.hia.json'
                assert identity(core)['sha256'] == built['core_sha256'] == built['native_compile']['core_sha256']
                item['core'] = identity(core)
            if built['native_built']:
                assert built['status'] == 'compiled'
                artifact = identity(built['artifact']['path'])
                assert artifact == built['artifact']
                item['native_artifact'] = artifact
            public = t.get('public')
            if public:
                assert built['status'] == 'compiled' and built['native_built']
                assert public['artifact_unchanged']
                item['public_native_observed_by_producer'] = public['native_executed']
                assert len(t['feedback']['public_cases']) == len(public['expected'])
            if row['hidden_control'] is not None:
                hidden = load(location / 'CONTROL_HIDDEN.json')
                assert hidden == row['hidden_control'] and t['accepted']
                assert hidden['status'] == 'correct' and hidden['artifact_unchanged']
                item['terminal_hidden_record'] = identity(location / 'CONTROL_HIDDEN.json')
        rows.append(item)
        by_id[ident] = t
    assert by_id['rust_two_file_scalar_nodes']['after_revision'] == by_id['rust_stale_revision_replay']['before_revision']
    assert len({by_id[name]['before_revision'] for name in (
        'rust_borrow_error_keeps_revision', 'rust_public_semantic_error_keeps_revision', 'rust_owner_and_value_nodes')}) == 1
    assert by_id['hia_observable_bug_keeps_revision']['before_revision'] == by_id['hia_real_ssa_batch_native']['before_revision']
    return {'source_commit': revision, 'source_tree': git('rev-parse', revision + '^{tree}').decode().strip(),
            'control_report': identity(folder / 'CONTROLS.json'), 'plan': identity(folder / 'PLAN.json'),
            'source_bindings_checked_against_git_and_snapshot': len(bindings),
            'current_source_also_checked': current, 'source_bindings': bindings if current else None,
            'accepted_transactions': sum(row['accepted'] for row in rows),
            'expected_refusals': sum(not row['accepted'] for row in rows), 'rows': rows}


assert git('rev-parse', 'HEAD').decode().strip() == FINAL
assert not git('status', '--porcelain=v1').strip()
tests_path = Path('/tmp/hepta-next-agent-structured-tests-677a159.json')
tests = load(tests_path)
assert tests['source_commit'] == FINAL and tests['test_count'] == 51
assert tests['returncode'] == 0 and tests['source_unchanged']
assert tests['model_requests'] == tests['native_compilations'] == 0
assert identity(tests['log']['path']) == tests['log']
assert b'Ran 51 tests' in Path(tests['log']['path']).read_bytes()
assert Path(tests['log']['path']).read_bytes().rstrip().endswith(b'OK')
old = audit_run('/tmp/hepta-next-agent-structured-controls-01', EARLIER)
intermediate = audit_run('/tmp/hepta-next-agent-structured-controls-02', INTERMEDIATE)
new = audit_run('/tmp/hepta-next-agent-structured-controls-03', FINAL, current=True)
unchanged_prior_paths = [f'experiments/hia_agent_factorial_v{version}_20261028' for version in (4, 5, 6)]
assert not git('diff', '--name-only', BASE, FINAL, '--', *unchanged_prior_paths).strip()
assert git('rev-parse', 'HEAD').decode().strip() == FINAL
assert not git('status', '--porcelain=v1').strip()
result = {'schema': 'hepta.hia.structured-editor-independent-review.v1',
          'reviewed_utc': datetime.now(timezone.utc).isoformat(),
          'status': 'source_and_producer_evidence_integrity_checked_see_independent_review_document',
          'source_unchanged_during_review': True, 'final_source': new,
          'earlier_source_retained_without_relabeling': old,
          'intermediate_source_retained_without_relabeling': intermediate,
          'producer_static_test_receipt': identity(tests_path), 'producer_static_test_log': tests['log'],
          'old_v4_v5_v6_source_unchanged_against': BASE,
          'reviewer_native_builds': 0, 'reviewer_native_executions': 0, 'reviewer_model_requests': 0,
          'reviewer_vm_or_editor_invocations': 0, 'reviewer_test_suite_reruns': 0,
          'compiler_images_freshly_rehashed_by_reviewer': False,
          'environment': 'shared-cloud-scratch-not-user-dot',
          'claims': {'independent_source_and_receipt_integrity_checked': True,
                     'actual_candidate_files_match_accepted_revision': True,
                     'actual_native_artifact_bytes_match_producer_receipts': True,
                     'general_rust_parser_or_language_soundness_proved': False,
                     'native_backend_refinement_proved': False,
                     'agent_efficiency_measured': False}}
OUT.mkdir(exist_ok=False)
(OUT / 'REVIEW.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
(OUT / 'PRODUCER_STATIC_TESTS.json').write_bytes(tests_path.read_bytes())
(OUT / 'PRODUCER_STATIC_TESTS.log').write_bytes(Path(tests['log']['path']).read_bytes())
print(json.dumps({'source': FINAL, 'source_files': len(new['source_bindings']),
                  'producer_tests': 51, 'producer_controls': len(new['rows']),
                  'accepted_transactions': new['accepted_transactions'],
                  'expected_refusals': new['expected_refusals'], 'output': str(OUT)}, indent=2))
