"""Bind all final working bytes to the proposed pure source Git tree."""
from hashlib import sha1, sha256
from pathlib import Path
import json
import subprocess

ROOT = Path('/workspace/scratch/e26ed3e2edcf/combined-ci-fixes-r3')
OUT = Path(__file__).resolve().parent
BASE_COMMIT = '83a0c59e9e2268cd0b80f3dd2752dc175e2db36a'
BASE_TREE = '0c64c55c6aaee3febe88fbaaec91dee3d5bfe195'
FILES = sorted((
    'docs/HIA_SELFHOST_CORE_SUPPORT.json',
    'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json',
    'tests/test_hia_core_only.py',
    'tests/test_hia_selfhost_names.py',
    'tools/check_hia_core_only.py',
    'tools/hia_selfhost_contract.py',
    'tools/hia_selfhost_names.py',
))
def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)
def leaves(tree):
    result = []
    for row in git('ls-tree', '-rz', tree).split(b'\0'):
        if not row:
            continue
        meta, name = row.split(b'\t', 1)
        mode, kind, digest = meta.decode().split()
        result.append({'path': name.decode(), 'mode': mode, 'type': kind, 'sha': digest})
    return result
assert git('diff', '--name-only', BASE_TREE).decode().splitlines() == FILES
assert not git('ls-files', '--others', '--exclude-standard')
git('diff', '--check', BASE_TREE)
git('add', '--', *FILES)
tree = git('write-tree').decode().strip()
before, after = leaves(BASE_TREE), leaves(tree)
old = {x['path']: x for x in before}
assert len(before) == len(after) == 4034
assert set(old) == {x['path'] for x in after}
changed, total = [], 0
for entry in after:
    path = ROOT / entry['path']
    assert path.is_file() and not path.is_symlink() and entry['type'] == 'blob'
    raw = path.read_bytes()
    digest = sha1(('blob ' + str(len(raw)) + '\0').encode() + raw).hexdigest()
    assert digest == entry['sha'], entry['path']
    entry['bytes'] = len(raw)
    total += len(raw)
    if entry['sha'] != old[entry['path']]['sha'] or entry['mode'] != old[entry['path']]['mode']:
        changed.append({**entry, 'sha256': sha256(raw).hexdigest(), 'content': raw.decode()})
assert [x['path'] for x in changed] == FILES
result = json.loads((OUT / 'TEST-RESULT.json').read_bytes())
guardian = json.loads((OUT / 'guard/guardian.json').read_bytes())
request_raw = (OUT / 'guard/request.json').read_bytes()
request = json.loads(request_raw)
life = guardian['lifecycle']
assert result['status'] == 'SOURCE_GATE_AND_CONTRACT_TESTS_PASS'
assert result['expected_ids'] == result['loaded_ids'] == result['executed_ids']
assert result['tests_run'] == 47 and not any(result['anomaly_counts'].values())
assert guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
assert guardian['command'] == request['command'] and guardian['cwd'] == str(ROOT)
assert guardian['input_identity_preserved'] is True
assert guardian['source_identities_before'] == guardian['source_identities_after'] == request['source_identities']
assert life['returncode'] == 0 and life['timed_out'] is False
assert life['exit_observed_before_deadline'] is True
assert life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3
assert life['cleanup']['observed_echild'] is True and life['cleanup']['complete'] is True
assert life['cleanup']['remaining_direct_children'] == [] and life['cleanup']['errors'] == []
assert life['event_overflow'] is False and life['interrupted_signals'] == []
assert [e['kind'] for e in life['events']] == [
    'qualification_started', 'owned_child_observed', 'qualification_exit_observed', 'owned_child_reaped']
for path, digest in request['source_identities'].items():
    assert sha256(Path(path).read_bytes()).hexdigest() == digest, path
for path, digest in guardian['logs'].items():
    assert sha256(Path(path).read_bytes()).hexdigest() == digest, path
profile = json.loads((ROOT / 'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes())['profile']
validation = {
    'schema': 'hia.combined-ci-custody-publication-source.v1',
    'status': 'PURE_SOURCE_AND_47_SOURCE_TESTS_VERIFIED_NOT_NATIVE_QUALIFICATION',
    'parent_commit': BASE_COMMIT, 'parent_tree': BASE_TREE,
    'tree': tree, 'leaves': len(after), 'physical_bytes': total,
    'all_working_files_match_git_blobs': True,
    'unchanged_parent_leaves': 4027, 'changed_leaves': 7,
    'new_paths': 0, 'deleted_paths': 0, 'profile': profile,
    'request_sha256': sha256(request_raw).hexdigest(),
    'source_test_count': 47, 'source_identities': len(request['source_identities']),
    'qualification_seconds': 180, 'cleanup_seconds': 3,
    'actual_natural_elapsed_ns': life['events'][2]['monotonic_ns'] - life['events'][0]['monotonic_ns'],
    'natural_zero_exit_and_ECHILD': True,
    'native_or_cold_qualification_executed': False,
    'earlier_incomplete_new_test_collector_failure_preserved': True,
    'changes': [{k: v for k, v in row.items() if k != 'content'} for row in changed],
}
for name, value in (
        ('SOURCE-VALIDATION.json', validation), ('FINAL-LEAVES.json', after),
        ('PUBLISH-SOURCE.json', {**validation, 'files': changed})):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
print(json.dumps(validation))
