"""Append verified v83 records without modifying a previous audit or product entry."""
from hashlib import sha1, sha256
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
WORK = HERE.parent
sys.path.insert(0, str(WORK / 'v80-joint-audit-publication-r1'))
from prepare_audit import tree_hash

LEAF = 'hia-native-rewrite-v83-receipts-and-cold-20261113-dda7'


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
            assert known == digest, (name, known, digest)
        else:
            new.append({'path': name, 'local': str(path), **identity})
        add(name, digest)

    def recipe(name, path, known, prefix):
        local('recipes/' + name, path, known)
        value = read(path)
        rows = value if isinstance(value, list) else value['entries']
        for row in rows:
            add(prefix + '/' + row['path'], row['sha'], row['mode'], row['type'])

    recipe('ROOT-DEVELOPMENT.json', WORK / 'v83-root-development-evidence-r1/MOUNT-RECIPE.json',
           '8fb7b3f4898ad7a1ef81ce97d515e88f6dc96c5d', 'root-development')
    recipe('R4-COMPLETE-TERMINAL.json', WORK / 'v83-joint-current-observation-r1/R4-TERMINAL-MOUNT-RECIPE.json',
           'b3f502cbc727e9eaae2fe44afbe06501e22ea5c0', 'artifacts')
    recipe('EVALUATION-PHASE-DIAGNOSTIC.json', WORK / 'v82-evaluation-budget-profile-r1/actual-originals/custody-r1/MOUNT-RECIPE.json',
           '8e4ed5caad816ae41f18c7675726e73d7ce91f7a', 'evaluation')
    recipe('CONTRACT-R7-ACTUAL314.json', HERE / 'CONTRACT-R7-ACTUAL314-RECIPE.json',
           'c1a2a8f2e93b9cc8949b30d97a82101c4bd54d2b', 'contract')
    recipe('COLD-PATH-AND-ABBA.json', HERE / 'COLD-PATH-AND-ABBA-RECIPE.json',
           'd301960594b4693e880edc93758fee1fe7e42542', 'cold-audit')

    local('direct-packets/NEW-SOURCE-AND-HARNESS-PUBLICATION.zlib.json',
          WORK / 'v83-native-receipt-joint-publication-r1/PUBLICATION-CUSTODY-PACKET.zlib.json',
          '41183d59052cc24376bf8971a2137c8cdebe3136')
    for name in ('README.md', 'prepare_audit.py', 'inventory_source.py', 'verify_harness.py',
                 'SOURCE-SURFACE-INVENTORY.json', 'AUDIT-COMMIT.json', 'PREVIOUS-ROOT.json',
                 'PREVIOUS-REVIEW.json', 'AUDIT-REF.json', 'NEW-HARNESS-COMMIT.json',
                 'NEW-HARNESS-TREE.json', 'OLD-HARNESS-TREE.json', 'NEW-HARNESS-ROOT-VERIFIED.json',
                 'NEW-JOBS-OBSERVATION.json', 'PR889-BEFORE-UPDATE.json'):
        local(name, HERE / name)
    for name in ('OPTIMIZED-SOURCE-COMMIT.json', 'OPTIMIZED-SOURCE-ROOT-READBACK.json'):
        local('source-readback/' + name, WORK / 'v83-joint-current-observation-r1' / name)
    default = WORK / 'v83-native-receipt-joint-publication-r1/actual-r1/default311'
    for name in ('OBSERVATION.json', 'OBSERVATION-PARSER-R1-FAILURE.json'):
        local('new-default311/' + name, default / name)
    for relative in ('REPORT.json', 'default-control-observations/REPORT.json',
                     'default-front-64/REPORT.json', 'compatibility/REPORT.json',
                     'evaluation-compatibility/REPORT.json'):
        local('new-default311/raw/' + relative, default / 'raw' / relative)

    root, review = read(HERE / 'PREVIOUS-ROOT.json'), read(HERE / 'PREVIOUS-REVIEW.json')
    clean = lambda rows: [{k: row[k] for k in ('path', 'mode', 'type', 'sha')} for row in rows]
    assert root['sha'] == 'c26ba4c8a6a48544033400af06ca1a46d653327b'
    assert review['sha'] == 'bac1e85b9a085fd219684b2c20f8e34011385d4b'
    assert tree_hash(clean(root['tree'])) == root['sha']
    assert tree_hash(clean(review['tree'])) == review['sha'] and len(review['tree']) == 28
    ordered = [entries[name] for name in sorted(entries)]
    leaf_sha = tree_hash(ordered)
    next_review = clean(review['tree']) + [{'path': LEAF, 'mode': '040000', 'type': 'tree', 'sha': leaf_sha}]
    review_sha = tree_hash(next_review)
    next_root = [{**row, 'sha': review_sha if row['path'] == 'review-evidence' else row['sha']}
                 for row in clean(root['tree'])]
    assert len(next_root) == len(root['tree']) == 20
    plan = {'schema': 'hia.receipt-cold.additive-audit.v83.r1',
            'previous_commit': '74528cb113fecc59e58857fae72e82b87c640863',
            'previous_root': root['sha'], 'previous_review': review['sha'],
            'leaf_name': LEAF, 'leaf_entries': ordered, 'leaf_sha': leaf_sha,
            'leaf_steps': [{'count': min(i + 12, len(ordered)), 'sha': tree_hash(ordered[:i + 12])}
                           for i in range(0, len(ordered), 12)],
            'review_entries': next_review, 'review_sha': review_sha,
            'root_entries': next_root, 'root_sha': tree_hash(next_root),
            'prior_audit_subtrees_preserved': 28, 'non_audit_root_entries_unchanged': True,
            'new_blobs': new, 'whole_native': False, 'production_files_deleted': 0}
    with (HERE / 'AUDIT-PLAN.json').open('x') as stream:
        json.dump(plan, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({key: plan[key] for key in ('leaf_sha', 'review_sha', 'root_sha')}, sort_keys=True))
    print(json.dumps({'leaf_files': len(ordered), 'new_blobs': len(new), 'tree_batches': len(plan['leaf_steps'])}))


if __name__ == '__main__':
    main()
