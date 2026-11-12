"""Append verified exact originals while preserving every prior audit and product entry."""
from pathlib import Path
from hashlib import sha1, sha256
import json
import re
import sys

HERE = Path(__file__).resolve().parent
WORK = HERE.parent
sys.path.insert(0, str(WORK/'v80-joint-audit-publication-r1'))
from prepare_audit import tree_hash

LEAF = 'hia-native-rewrite-v82-terminal-and-joint-20261112-dda7'


def read(path):
    return json.loads(path.read_bytes())


def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'chars': len(raw.decode('utf-8')), 'sha256': sha256(raw).hexdigest(),
            'sha': sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def main():
    entries, new = {}, []
    def add(path, digest, mode='100644', kind='blob'):
        assert re.fullmatch('[0-9a-f]{40}', digest)
        assert not path.startswith('/') and all(p not in ('', '.', '..') for p in path.split('/'))
        row = {'path': path, 'sha': digest, 'mode': mode, 'type': kind}
        if path in entries:
            assert entries[path] == row
        entries[path] = row
    def local(path, source, known=None):
        row = identity(source)
        if known is None:
            new.append({'path': path, 'local': str(source), **row})
        else:
            assert row['sha'] == known, (path, row['sha'], known)
        add(path, row['sha'])
    def recipe(path, source, known, prefix):
        local('recipes/'+path, source, known)
        data = read(source)
        rows = data if isinstance(data, list) else data['entries']
        for row in rows:
            add(prefix+'/'+row['path'], row['sha'], row['mode'], row['type'])

    for name, known, prefix in (
        ('SOURCE-R2-COMPLETE-ZIP-RECIPE.json', 'dd34b22090ef82d9215d4dcb11d573fba7decac2', 'source-65ce/complete-source-r2-zip'),
        ('CORE-AND-FULL-TERMINAL-RECIPE.json', 'c7ede8ce4f5824c406bf316429a23c8ec9287c67', 'source-65ce'),
        ('FRONT-JOINT-R3-RECIPE.json', '62d35b8bece9bdcaa6b92dcb0d079e71c2af508f', 'front-union'),
        ('EVALUATION-R8-ACTUAL-RECIPE.json', '2e075c1b0564e3118e262fc49b09601fa7cc5d23', 'evaluation'),
        ('CONTRACT-R7-DEVELOPMENT-RECIPE.json', '1f2e113837c3536020efa4d54f3fd26ea6156c9d', 'contract'),
        ('CONTRACT-R7-ACTUAL311-RECIPE.json', '9fedde4feae0c10ca59029ad6144795b0b5eb8bd', 'contract'),
    ):
        recipe(name, HERE/name, known, prefix)
    recipe('ROOT-INTEGRATION-RECIPE.json', WORK/'v82-root-owner-integration-evidence-r1/MOUNT-RECIPE.json',
           'c2c27bebaba8023d5a362746f888df2d18f960a7', 'root/integration-originals')
    recipe('ROOT-TERMINAL-RECIPE.json', WORK/'v82-root-terminal-evidence-r1/MOUNT-RECIPE.json',
           '9ff3ee2a59f11c537364a5ee698c553935b0efcc', 'root/terminal-originals')

    for name, known in (
        ('ARTIFACT-R4-NARROW-REPAIR.json', '550977adc5cb3b4f8a040a0dc716631ced864952'),
        ('ARTIFACT-R4-SOURCE-PUBLICATION.json', '1097652b4bf23170ea150dc0bc288a107d5b54a1'),
        ('EVALUATION-R8-INTEGRATION-PROPOSAL.json', '8966ff180a70e900e59c663bb49e6edd78c9032d'),
        ('FRONT-NORMAL-CORE-SOURCE-TERMINAL.json', '03c2e09332d5936b83ce917d9c4cc6762e2b944c'),
        ('CONTRACT-R7-SOURCE-CAPSULE.json', 'd5b3d199b7d9f50d4bc31a7e3b975e5cc6c04fff'),
    ):
        local('direct-packets/'+name, HERE/name, known)

    for name in (
        'README.md', 'prepare_audit.py', 'inventory_source.py', 'SOURCE-SURFACE-INVENTORY.json',
        'AUDIT-REF.json', 'PRODUCT-REF.json', 'MAIN-REF.json', 'PR889-BEFORE-UPDATE.json',
        'PR889-BEFORE-UPDATE.md', 'ARTIFACT-R4-ACTUAL-JOBS.json', 'CONTRACT-R7-ACTUAL-JOBS.json',
        'ARTIFACT-R4-SOURCE-COMMIT.json', 'ARTIFACT-R4-SOURCE-TREE.json',
        'ARTIFACT-R4-SOURCE-VERIFIED.json', 'OBSERVATION.json',
    ):
        local(name, HERE/name)
    for profile in ('actual311-r1', 'actual314-r1', 'actual-source314-r1'):
        root = WORK/'v82-service-artifacts-development-r3/ci-r1'/profile
        for name in ('ACTUAL-SUMMARY.json', 'SOURCE-ARCHIVE-COVERAGE.json', 'DOWNLOAD.json'):
            local('artifacts-r3-readable/'+profile+'/'+name, root/name)
    for profile in ('actual311-r2', 'actual314-r2'):
        root = WORK/'v81-service-requests-development-r2/ci-r2'/profile
        for name in ('ACTUAL-SUMMARY.json', 'SOURCE-ARCHIVE-COVERAGE.json'):
            local('requests-r2-readable/'+profile+'/'+name, root/name)
    for revision in ('r1', 'r2', 'r3'):
        root = WORK/('v82-inactive-root-base-reclamation-'+revision)
        local('inactive-recovery/'+revision+'/COMPLETE.json', root/'COMPLETE.json')

    previous_root, previous_review = read(HERE/'PREVIOUS-ROOT.json'), read(HERE/'PREVIOUS-REVIEW.json')
    assert previous_root['sha'] == '72ef9b57ff06d4c91d5999f06657d715fba06a59'
    assert previous_review['sha'] == 'cca37dc6c77e1259013449b7fcb97507dbaa06d3'
    clean = lambda rows: [{k: row[k] for k in ('path','mode','type','sha')} for row in rows]
    assert tree_hash(clean(previous_root['tree'])) == previous_root['sha']
    assert tree_hash(clean(previous_review['tree'])) == previous_review['sha']
    assert len(previous_review['tree']) == 27
    ordered = [entries[name] for name in sorted(entries)]
    leaf_sha = tree_hash(ordered)
    review = clean(previous_review['tree'])+[{'path': LEAF, 'mode': '040000', 'type': 'tree', 'sha': leaf_sha}]
    review_sha = tree_hash(review)
    root = [{**row, 'sha': review_sha if row['path'] == 'review-evidence' else row['sha']}
            for row in clean(previous_root['tree'])]
    assert len(root) == len(previous_root['tree'])
    plan = {'schema': 'hia.actual-terminal-joint.additive-audit.v82.r1',
        'previous_commit': 'd39f48e3d79253ca2c7c041320bc4ef3f659e966',
        'previous_root': previous_root['sha'], 'previous_review': previous_review['sha'],
        'leaf_name': LEAF, 'leaf_entries': ordered, 'leaf_sha': leaf_sha,
        'leaf_steps': [{'count': min(i+12, len(ordered)), 'sha': tree_hash(ordered[:i+12])}
                       for i in range(0, len(ordered), 12)],
        'review_entries': review, 'review_sha': review_sha,
        'root_entries': root, 'root_sha': tree_hash(root),
        'prior_audit_subtrees_preserved': 27, 'non_audit_root_entries_unchanged': True,
        'new_blobs': new, 'whole_native': False, 'production_files_deleted': 0}
    with (HERE/'AUDIT-PLAN.json').open('x') as stream:
        json.dump(plan, stream, sort_keys=True, indent=2); stream.write('\n')
    print(json.dumps({key: plan[key] for key in ('leaf_sha','review_sha','root_sha')}, sort_keys=True))
    print(json.dumps({'leaf_files': len(ordered), 'new_blobs': len(new), 'tree_batches': len(plan['leaf_steps'])}))


if __name__ == '__main__':
    main()
