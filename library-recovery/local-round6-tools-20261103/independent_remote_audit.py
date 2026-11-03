#!/usr/bin/env python3
"""Read saved official GitHub GET responses; never execute project or archive code."""
from pathlib import Path
import hashlib
import json
import shutil
from datetime import datetime, timezone

BASE = Path('/workspace/scratch/bf7d454bbc83/round6-recovered-ci-publication')
RAW = BASE / 'independent-remote-readback'
COMMIT = 'ae391617e983b04d21b65f7915151623e8b45ba1'
SOURCE = '9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b'
PREFIX = 'evidence/hia_round6_ci_recovered_20261029'
PLAN_SHA = '207594bf51374ee337f886ca8aac845bac668f423dbbe261ac9260176616497d'
RESPONSES = {}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def bound(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': sha256(data)}


def read(name, is_json=True):
    path = RAW / (name + '.json')
    saved = json.loads(path.read_bytes())
    result = saved['result']
    assert not result.get('isError', False), name
    body = result['structuredContent']['content']
    assert isinstance(body, str), name
    assert body == result['structuredContent']['structuredContent']['content'], name
    RESPONSES[name] = {
        **bound(path), 'request_url': saved['url'],
        'started_at': saved['started_at'], 'finished_at': saved['finished_at'],
        'returned_content_utf8_bytes': len(body.encode('utf-8')),
        'returned_content_utf8_sha256': sha256(body.encode('utf-8')),
    }
    return json.loads(body) if is_json else body.encode('utf-8')


def entries(tree):
    assert tree['truncated'] is False
    rows = tree['tree']
    result = {x['path']: x for x in rows}
    assert len(result) == len(rows)
    return result


def essential(row):
    return {key: row[key] for key in ('path', 'mode', 'type', 'sha')}


def tree_hash(rows):
    ordered = sorted(rows, key=lambda x: x['path'].encode('utf-8') + (b'/' if x['type'] == 'tree' else b''))
    payload = b''.join(
        format(int(x['mode'], 8), 'o').encode('ascii') + b' ' + x['path'].encode('utf-8') + b'\0' + bytes.fromhex(x['sha'])
        for x in ordered
    )
    return hashlib.sha1(b'tree ' + str(len(payload)).encode('ascii') + b'\0' + payload).hexdigest()


plan_path = BASE / 'UPLOAD-PLAN.json'
plan_bytes = plan_path.read_bytes()
assert sha256(plan_bytes) == PLAN_SHA
plan = json.loads(plan_bytes)
commit = read('published-commit')
ref = read('published-ref')
source = read('source-commit')
assert commit['sha'] == COMMIT
assert [x['sha'] for x in commit['parents']] == [SOURCE]
assert commit['tree']['sha'] == plan['expected_root_tree_sha1'] == '784db49f1dcf3cb59344049b3bd4a15cfd612aa5'
assert source['sha'] == SOURCE
assert source['tree']['sha'] == plan['base_tree'] == 'debee7040ed2ffac2cbaf953c28c1e2ca3fc8407'
assert ref['ref'] == 'refs/heads/' + plan['branch']
assert ref['object']['type'] == 'commit' and ref['object']['sha'] == COMMIT

tree_names = {'': 'tree-root', 'evidence': 'tree-evidence', PREFIX: 'tree-prefix', PREFIX + '/parts': 'tree-parts'}
actual_trees = {path: read(name) for path, name in tree_names.items()}
for planned in plan['trees_bottom_up']:
    actual = actual_trees[planned['path']]
    assert actual['sha'] == planned['expected_tree_sha1']
    assert tree_hash(actual['tree']) == actual['sha']
    assert {k: essential(v) for k, v in entries(actual).items()} == {x['path']: essential(x) for x in planned['entries']}

old_root = read('old-tree-root')
old_evidence = read('old-tree-evidence')
assert old_root['sha'] == source['tree']['sha'] and tree_hash(old_root['tree']) == old_root['sha']
assert old_evidence['sha'] == 'dd273595567cb4e1c96019f05b185343c08c49de'
assert tree_hash(old_evidence['tree']) == old_evidence['sha']
old_root_entries, new_root_entries = entries(old_root), entries(actual_trees[''])
assert old_root_entries['evidence']['sha'] == old_evidence['sha']
assert new_root_entries['evidence']['sha'] == actual_trees['evidence']['sha']
assert len(old_root_entries) == len(new_root_entries) == 19
old_non_evidence = {k: v for k, v in old_root_entries.items() if k != 'evidence'}
new_non_evidence = {k: v for k, v in new_root_entries.items() if k != 'evidence'}
assert old_non_evidence == new_non_evidence and len(old_non_evidence) == 18
old_evidence_entries, new_evidence_entries = entries(old_evidence), entries(actual_trees['evidence'])
assert len(old_evidence_entries) == 56
assert len(new_evidence_entries) == 57
assert {k: new_evidence_entries[k] for k in old_evidence_entries} == old_evidence_entries
assert set(new_evidence_entries) - set(old_evidence_entries) == {PREFIX.split('/')[-1]}
assert new_evidence_entries[PREFIX.split('/')[-1]]['sha'] == actual_trees[PREFIX]['sha']
assert entries(actual_trees[PREFIX])['parts']['sha'] == actual_trees[PREFIX + '/parts']['sha']

remote_blobs = {}
for directory in (PREFIX, PREFIX + '/parts'):
    for item in entries(actual_trees[directory]).values():
        if item['type'] == 'blob':
            remote_blobs[directory + '/' + item['path']] = item
assert len(remote_blobs) == len(plan['blobs']) == 21
assert set(remote_blobs) == {x['path'] for x in plan['blobs']}
blob_results = []
for expected in plan['blobs']:
    actual = remote_blobs[expected['path']]
    assert actual['mode'] == expected['mode'] == '100644'
    assert actual['sha'] == expected['git_blob_sha1']
    assert actual['size'] == expected['bytes']
    blob_results.append({
        'path': expected['path'], 'mode': actual['mode'],
        'git_blob_sha1': actual['sha'], 'bytes': actual['size'],
        'local_frozen_sha256': expected['sha256'],
        'remote_verification': 'official_tree_blob_identity_mode_and_size',
    })
assert sum(x['bytes'] for x in blob_results) == 66646636

readme = read('published-readme', is_json=False)
local_readme = BASE / 'evidence/hia_round6_ci_recovered_20261029/README.md'
expected_readme = next(x for x in plan['blobs'] if x['relative'] == 'README.md')
assert readme == local_readme.read_bytes()
assert len(readme) == expected_readme['bytes'] == 11305
assert sha256(readme) == expected_readme['sha256'] == 'a2c1c137fb9a3d68de382910391b0b049062b52073eb669a2166a9493dcafd7b'
assert hashlib.sha1(b'blob ' + str(len(readme)).encode('ascii') + b'\0' + readme).hexdigest() == expected_readme['git_blob_sha1']

receipt_path = BASE / 'INDEPENDENT-REMOTE-READBACK.json'
backup = Path('/tmp/hepta-round6-independent-remote-readback-ae391617')
backup.mkdir(exist_ok=True)
report = {
    'schema': 'hepta.round6.recovered-ci-independent-remote-readback.v1',
    'reviewed_utc': datetime.now(timezone.utc).isoformat(),
    'reviewer': 'migration_guard_integration',
    'status': 'passed', 'blockers': [],
    'repository': 'TrillionniumFoundation/Hepta',
    'immutable_commit': COMMIT,
    'immutable_readme_url': f'https://github.com/TrillionniumFoundation/Hepta/blob/{COMMIT}/{PREFIX}/README.md',
    'branch_observed': ref['ref'],
    'branch_commit_at_observation': ref['object']['sha'],
    'sole_parent': SOURCE,
    'source_tree': source['tree']['sha'],
    'published_root_tree': commit['tree']['sha'],
    'published_prefix_tree': actual_trees[PREFIX]['sha'],
    'all_four_complete_tree_entries_equal_frozen_plan': True,
    'all_six_new_and_base_tree_object_hashes_independently_recomputed': True,
    'unchanged_original_non_evidence_root_entries': 18,
    'unchanged_original_evidence_entries': 56,
    'only_added_evidence_prefix': PREFIX,
    'original_6410_paths_preserved_by_unchanged_subtree_blob_and_mode_identity': True,
    'public_files': 21, 'public_bytes': 66646636,
    'all21_remote_blob_identities_modes_and_sizes_match_plan': True,
    'blobs': blob_results,
    'readme_remote_content_matches_original_bytes': {
        'bytes': len(readme), 'sha256': sha256(readme),
        'git_blob_sha1': expected_readme['git_blob_sha1'],
        'fetched_at_immutable_commit': COMMIT,
    },
    'frozen_plan': bound(plan_path),
    'prepublication_independent_audit': bound(BASE / 'INDEPENDENT-FINAL-REVIEW.json'),
    'audit_script': bound(Path(__file__)),
    'official_GET_responses': RESPONSES,
    'limitations': [
        'This readback fetched immutable commit/tree metadata and README text; it did not redownload the 65 MB archive. Binary payload identity is verified through published Git blob IDs, sizes and modes already byte-checked in the prepublication audit.',
        'The branch ref is a timestamped observation and may move later; the commit and README links use the immutable published commit.',
        'Connector response strings are retained exactly inside local JSON envelopes; no independent HTTP wire-byte or content-length claim is made.',
        'No project tests, compilers, archived programs or RESTORE execution; no source/index/frozen-package mutation or remote write.',
        'The package is the new257-file recovery, not a reconstruction of the lost unpublished397-file package.',
    ],
    'backup_directory': str(backup),
}
receipt = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8')
receipt_path.write_bytes(receipt)
shutil.copyfile(receipt_path, backup / receipt_path.name)
shutil.copyfile(Path(__file__), backup / Path(__file__).name)
for name in RESPONSES:
    shutil.copyfile(RAW / (name + '.json'), backup / (name + '.json'))
assert (backup / receipt_path.name).read_bytes() == receipt
print(json.dumps({'status': 'passed', 'receipt': str(receipt_path), 'bytes': len(receipt), 'sha256': sha256(receipt), 'backup': str(backup / receipt_path.name), 'remote_GETs': len(RESPONSES), 'files': len(blob_results), 'root': commit['tree']['sha'], 'blockers': []}))
