"""Verify the owned source result and every byte of the proposed four-file tree."""
from hashlib import sha1, sha256
from pathlib import Path
import json
import subprocess

ROOT = Path('/workspace/scratch/e26ed3e2edcf/installed-resource-v79-r1')
OUT = Path(__file__).resolve().parent
def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)

test = json.loads((OUT / 'TEST-RESULT.json').read_bytes())
expected = json.loads((OUT / 'EXPECTED-IDS.json').read_bytes())
assert test['expected_ids'] == test['loaded_ids'] == test['executed_ids'] == expected
assert len(expected) == test['tests_run'] == 11
assert not any(test['anomaly_counts'].values()) and not test['loader_errors']
guardian = json.loads((OUT / 'guard/guardian.json').read_bytes())
assert guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
assert guardian['input_identity_preserved'] is True
assert guardian['source_identities_before'] == guardian['source_identities_after']
assert len(guardian['source_identities_before']) == 802
owner = guardian['lifecycle']
assert owner['status'] == 'OWNED_PROCESS_COMPLETED' and owner['returncode'] == 0
assert owner['qualification_seconds'] == 180 and owner['cleanup_seconds'] == 3
assert owner['exit_observed_before_deadline'] is True and owner['timed_out'] is False
assert owner['cleanup']['observed_echild'] is True and owner['cleanup']['complete'] is True
assert not owner['cleanup']['errors'] and not owner['cleanup']['remaining_direct_children']
events = owner['events']
assert [x['kind'] for x in events] == [
    'qualification_started', 'owned_child_observed',
    'qualification_exit_observed', 'owned_child_reaped']
elapsed = events[2]['monotonic_ns'] - events[0]['monotonic_ns']
assert elapsed < 180_000_000_000
paths = git('diff', '--name-only').decode().splitlines()
assert set(paths) == {'tests/test_hia_agent_installed_resources.py',
    'tools/hia_selfhost_contract.py', 'docs/HIA_SELFHOST_CORE_SUPPORT.json',
    'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json'}
git('add', '--', *paths)
tree = git('write-tree').decode().strip()
rows = []
for record in git('ls-files', '-s', '-z').split(b'\0'):
    if not record:
        continue
    header, path = record.split(b'\t', 1)
    mode, digest, stage = header.split()
    assert stage == b'0'
    raw = (ROOT / path.decode()).read_bytes()
    assert sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest() == digest.decode(), path
    rows.append({'path': path.decode(), 'mode': mode.decode(), 'type': 'blob',
                 'sha': digest.decode(), 'size': len(raw)})
parent = json.loads(Path('/workspace/scratch/e26ed3e2edcf/root/rehydration-r1/V78-TARGET-LEAVES.json').read_bytes())
before = {x['path']: x for x in parent}
after = {x['path']: x for x in rows}
assert set(before) == set(after) and len(rows) == 4034
changed = [name for name in before if before[name]['sha'] != after[name]['sha']]
assert sorted(changed) == sorted(paths)
assert all(before[name]['mode'] == after[name]['mode'] for name in before)
workflow = (ROOT / '.github/workflows/hia-core.yml').read_bytes()
assert sha256(workflow).hexdigest() == '268602ba9fc9bc9bb6b4eeb73502808fc58dc45d7ffcbf77f72fd016cf52e843'
report = {'schema': 'hia.installed-resource-pure-source-publication.v1',
    'status': 'ALL_SOURCE_TEST_IDS_OWNER_AND_EXACT_TREE_VERIFIED',
    'parent_commit': 'd0e110e19f9433baaf202a0f605671c7205b4cff',
    'parent_tree': '6381daf9beb11d873d4608c26facc0b9e5bc747f',
    'tree': tree, 'leaves': len(rows), 'changed_paths': sorted(changed),
    'unchanged_leaves': len(rows) - len(changed), 'new_paths': [], 'deleted_paths': [],
    'all_working_bytes_match_Git_blobs': True, 'physical_bytes': sum(x['size'] for x in rows),
    'expected_loaded_executed_source_tests': 11, 'anomaly_counts': test['anomaly_counts'],
    'original_installation_method_population_unchanged': 21,
    'source_identities_preserved': 802, 'natural_elapsed_ns': elapsed,
    'qualification_seconds': 180, 'cleanup_seconds': 3,
    'natural_zero_exit_ECHILD': True, 'original_workflow_sha256': sha256(workflow).hexdigest(),
    'native_installation_executed': False, 'cold_qualification_executed': False,
    'whole_native_delivery_qualified': False}
with (OUT / 'SOURCE-VALIDATION.json').open('x') as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write('\n')
with (OUT / 'FINAL-LEAVES.json').open('x') as stream:
    json.dump(rows, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps(report))
