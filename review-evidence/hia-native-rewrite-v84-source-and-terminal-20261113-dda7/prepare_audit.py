"""Append exact v84 source and terminal evidence without changing prior audit subtrees."""
from hashlib import sha1, sha256
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
WORK = HERE.parent
sys.path.insert(0, str(WORK / 'v80-joint-audit-publication-r1'))
from prepare_audit import tree_hash

LEAF = 'hia-native-rewrite-v84-source-and-terminal-20261113-dda7'


def read(path):
    return json.loads(path.read_bytes())


def main():
    entries, new = {}, []

    def add(name, digest, mode='100644', kind='blob'):
        assert re.fullmatch('[0-9a-f]{40}', digest)
        assert not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/'))
        row = {'path': name, 'sha': digest, 'mode': mode, 'type': kind}
        assert name not in entries or entries[name] == row
        entries[name] = row

    def local(name, path, known=None):
        raw = path.read_bytes()
        digest = sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        identity = {'bytes': len(raw), 'chars': len(raw.decode()),
                    'sha256': sha256(raw).hexdigest(), 'sha': digest}
        if known:
            assert digest == known, (name, digest, known)
        else:
            new.append({'path': name, 'local': str(path), **identity})
        add(name, digest)

    def recipe(name, path, known, prefix=''):
        local('recipes/' + name, path, known)
        value = read(path)
        rows = value if isinstance(value, list) else value['entries']
        for row in rows:
            add((prefix + '/' if prefix else '') + row['path'], row['sha'], row['mode'], row['type'])

    recipe('ROOT-EMITTER-AND-PUBLICATION.json', WORK / 'v84-root-emitter-evidence-r1/MOUNT-RECIPE.json',
           '548aec34d19fd99b3a380b63328d207c73ef41b5', 'root-originals')
    recipe('ASSEMBLY-DEFAULT-SCOPE.json', WORK / 'v83-assembly-default-fallback-r1/MOUNT-RECIPE.json',
           'cdcbab8cb7067662e901607467f6979a09f21fb3')
    recipe('INDEPENDENT-EMITTER-VM.json', WORK / 'v83-selfhost-emit-private-vm-r1/MOUNT-RECIPE.json',
           'c166f2ae3510f36aa82459f6d8177e98a01b3ae3')
    contract = WORK / 'v82-agent-contract-service-development-r1'
    for name, directory, digest in (
        ('CONTRACT-SERVICE-LOCAL.json', 'local-service-r3-custody', '6da3bccac0a08c9491cfe572f506dd5f728d6941'),
        ('CONTRACT-SERVICE-DEFAULT311.json', 'actual-default311-custody-r1', 'b818733bc8f565ef5d1a704083270f778ef634c3'),
        ('CONTRACT-SERVICE-NATIVE314.json', 'actual-native314-custody-r1', 'c7d678365bb360bd6f85555e3091b77c1a09d409')):
        recipe(name, contract / directory / 'AUDIT-TREE-ENTRIES.json', digest)
    local('contract/CLOSE-R2-R3-EXACT-DELTA.zlib.json', contract / 'CLOSE-R2-R3-EXACT-DELTA.zlib.json',
          '5cec0c7e4d8090d6f5d7a0c44f7700fed6f988f6')
    local('joint-4925/TERMINAL-OBSERVATIONS.json',
          WORK / 'v83-native-receipt-joint-publication-r1/TERMINAL-OBSERVATIONS-r1.json',
          '9e9b7d6462ee0d249d8491121e56fff23eda4409')
    cold = WORK / 'v83-normal-core-4925-terminal-r1'
    for path, digest in (
        ('raw-minimal/hia-cold.json', 'bfeca29a9613f156e2df77deccd06b274e39400e'),
        ('raw-minimal/process-owner.json', '7a9ed513d98ee94db31ef625b54c8d36c1f5c7c9'),
        ('verification-r3/VERIFICATION.json', 'd71c777f5d7559e122a8322db25ac50021355160'),
        ('verification-r3/TERMINAL.json', 'a3d3f7c7e7c141cc96e280e832808114cae43e76'),
        ('archive/DOWNLOAD.json', '1a2b2bca05d5a7318b4cd7f6fe1e7d1a999ea4ea'),
        ('analysis-r1/REPORT.md', 'b6890dbfc0d07a7e4d50cc6be1ec0f7f8f79b5cb')):
        local('cold-4925/' + path, cold / path, digest)
    optional = HERE / 'ADDITIONAL-RECIPES.json'
    if optional.is_file():
        for row in read(optional):
            recipe(row['name'], Path(row['local']), row['sha'], row.get('prefix', ''))
    source = WORK / 'v84-assembly-scope-union-r1'
    for path in ('SOURCE-RELEASE.json', 'SOURCE-TREE-VERIFIED.json', 'SOURCE-COMMIT-READBACK.json',
                 'SOURCE-BRANCH-READBACK.json', 'preflight-r1/REPORT.json',
                 'PR889-CURRENT.md', 'PR889-CURRENT-READBACK.json'):
        local('source-a733/' + path, source / path)
    for path in ('README.md', 'prepare_audit.py', 'AUDIT-REF.json', 'AUDIT-COMMIT.json',
                 'PREVIOUS-ROOT.json', 'PREVIOUS-REVIEW.json'):
        local(path, HERE / path)
    if optional.is_file():
        local(optional.name, optional)

    clean = lambda rows: [{k: row[k] for k in ('path', 'mode', 'type', 'sha')} for row in rows]
    root = read(HERE / 'PREVIOUS-ROOT.json')
    review = read(HERE / 'PREVIOUS-REVIEW.json')
    assert root['sha'] == tree_hash(clean(root['tree'])) == '7413e5152561857cb20cde89bc3c0f42a79f16b4'
    assert review['sha'] == tree_hash(clean(review['tree'])) == '1da0f8f8c1d2bb0021dc6c79fd89702d33038b54'
    assert len(root['tree']) == 20 and len(review['tree']) == 29
    assert read(HERE / 'AUDIT-REF.json')['object']['sha'] == 'dfa0cd2a116d787d868b814056c9b36e35c3f7d8'
    ordered = [entries[name] for name in sorted(entries)]
    leaf_sha = tree_hash(ordered)
    next_review = clean(review['tree']) + [{'path': LEAF, 'mode': '040000', 'type': 'tree', 'sha': leaf_sha}]
    review_sha = tree_hash(next_review)
    next_root = [{**row, 'sha': review_sha if row['path'] == 'review-evidence' else row['sha']}
                 for row in clean(root['tree'])]
    plan = {'schema': 'hia.source-and-terminal.additive-audit.v84.r1',
            'previous_commit': 'dfa0cd2a116d787d868b814056c9b36e35c3f7d8',
            'previous_root': root['sha'], 'previous_review': review['sha'],
            'leaf_name': LEAF, 'leaf_entries': ordered, 'leaf_sha': leaf_sha,
            'leaf_steps': [{'count': min(i + 12, len(ordered)), 'sha': tree_hash(ordered[:i + 12])}
                           for i in range(0, len(ordered), 12)],
            'review_entries': next_review, 'review_sha': review_sha,
            'root_entries': next_root, 'root_sha': tree_hash(next_root),
            'prior_audit_subtrees_preserved': 29, 'non_audit_root_entries_unchanged': True,
            'new_blobs': new, 'whole_native': False, 'production_files_deleted': 0}
    with (HERE / 'AUDIT-PLAN.json').open('x') as stream:
        json.dump(plan, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'leaf_sha': leaf_sha, 'review_sha': review_sha, 'root_sha': plan['root_sha'],
                      'leaf_entries': len(ordered), 'new_blobs': len(new)}, sort_keys=True))


if __name__ == '__main__':
    main()
