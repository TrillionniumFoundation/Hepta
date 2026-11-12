"""Prepare an additive evidence tree from actual immutable object receipts."""
from pathlib import Path
from hashlib import sha1, sha256
import json
import re

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent
GLOBAL = WORK / 'v80-global-resolution-development-r2'
LEAF = 'hia-native-rewrite-v80-global-joint-closure-20261112-dda7'


def read(path):
    return json.loads(path.read_bytes())


def ident(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'chars': len(raw.decode()), 'sha256': sha256(raw).hexdigest(),
            'sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def tree_hash(entries):
    root = {}
    for entry in entries:
        parts = entry['path'].split('/')
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = (entry['mode'].lstrip('0'), entry['sha'], entry['type'])
    def visit(node):
        raw = bytearray()
        for name, value in sorted(node.items(), key=lambda pair: (pair[0] + ('/' if isinstance(pair[1], dict) or pair[1][2] == 'tree' else '')).encode()):
            mode, digest = ('40000', visit(value)) if isinstance(value, dict) else value[:2]
            raw += mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)
        return sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return visit(root)


def main():
    entries = {}
    new = []
    def add(path, digest, mode='100644', kind='blob'):
        assert re.fullmatch('[0-9a-f]{40}', digest), (path, digest)
        assert not path.startswith('/') and all(part not in ('', '.', '..') for part in path.split('/')), path
        item = {'path': path, 'sha': digest, 'mode': mode, 'type': kind}
        if path in entries:
            assert entries[path] == item, path
        entries[path] = item
    def local(path, source, known=None):
        row = ident(source)
        if known is not None:
            assert row['sha'] == known, path
        else:
            new.append({'path': path, 'local': str(source), **row})
        add(path, row['sha'])

    index = read(GLOBAL / 'git-custody-r1/INDEX.json')
    receipts = read(GLOBAL / 'git-custody-r1/ACK-RECEIPTS.json')
    assert receipts['completed'] == receipts['expected'] == 17
    for row, receipt in zip(index['parts'], receipts['receipts'], strict=True):
        assert row['blob'] == receipt['create_ack_sha'] and receipt['full_text_readback']
        local('global/evidence/' + row['path'], GLOBAL / 'git-custody-r1' / row['path'], row['blob'])
    names = {
        'SOURCE-CHECKPOINT.zlib.json': 'c32a398f344e10149d629b064356469baeaa32da',
        'R1-REPRODUCIBLE-SOURCE.zlib.json': 'a000c48498c802816b2d965cc66700d47a0c39b9',
        'git-custody-r1/INDEX.json': 'e90fa283cd39be7a3c0e5df6ca1915df25526500',
        'git-custody-r1/ACK-RECEIPTS.json': '4ce3b7101246db378a8117d37f1f55e86f55c443',
        'CHECKPOINT-IDENTITIES.json': '4efdbd5fe9170d141c239a7f443e1ff3e5fc5fad',
        'PERMANENT-TEST-ADDITIONS.json': '32b105ae29b6450741506ba3dfdaeffc9527908c',
        'new-controls-r1/REPORT.json': '4f24fe0a82c3bd6db3266208819a29ed24e5953a',
        'package_git_custody.py': '1a5a1ca13647c19f950b99cbefb4026a37638985',
        'PR889-BEFORE-UPDATE.md': '2304a6287df600fc5ac8b712e2790bac45d3c02d',
    }
    for name, digest in names.items():
        local('global/' + name, GLOBAL / name, digest)
    for row in read(ROOT / 'ROOT-EXTRA-ACKS.json'):
        assert row['create_ack'] and row['full_readback']
        local(row['path'], Path(row['local']), row['sha'])
    local('global/R2-EXPORT-RECLAMATION.json', GLOBAL / 'R2-EXPORT-RECLAMATION.json')

    for name, digest in (
            ('proof-joint-r1-failure-index.json', 'e48ebd6fcc534d3fbb9924c9726b3b07a53d58b6'),
            ('proof-joint-r1-crc-index.json', 'db5a801d18b982e443e1dcc12ac9ca1cbae4ad04'),
            ('proof-joint-r2-original-index.json', 'a7a094437233ab100e2b6b25299bd79acae6472e'),
            ('full-harness-r2-index.json', '0039d3b5a41cb2be570253dd9137d9e1380b84f0'),
            ('joint-source-publication.json', '856641b9c3ba3c1a3743948d278c05d0bf088bb1')):
        local('joint/' + name, ROOT / name, digest)
    r1 = read(ROOT / 'proof-joint-r1-failure-index.json')
    for row in r1['complete_original_log']['parts']:
        add('joint/r1-original/' + row['path'], row['blob'])
    crc = read(ROOT / 'proof-joint-r1-crc-index.json')
    add('joint/r1-original/crc-readonly-job.log', crc['complete_read_only_job_log']['blob'])
    add('joint/r1-original/source-controls.stderr', crc['original_failure']['blob'])
    r2 = read(ROOT / 'proof-joint-r2-original-index.json')
    for row in r2['log']['parts']:
        add('joint/r2-original/' + row['path'], row['blob'])
    full = read(ROOT / 'full-harness-r2-index.json')
    for row in full['receipts']:
        assert row['ack_sha'] == row['git_blob_sha1'] and row['full_readback_exact']
        add('full-harness/' + row['path'], row['ack_sha'])
    add('joint/automatic-original-source-job.log', full['current_source_automatic_log']['git_blob'])

    for name, digest in (
            ('EVALUATION-RECIPE-R2.json', 'bde85d42e2e0ee4ebd40dd2affd5ed8de714c300'),
            ('EVALUATION-R5-APPEND-RECIPE.json', 'c91ba164a4274c83c36bc8fff58216e5fede673c'),
            ('PUBLIC-FRONT-RECIPE.json', '4bdef85b6999d867773b278e348fc3f5b3f3a877')):
        local('recipes/' + name, ROOT / name, digest)
        for row in read(ROOT / name)['entries']:
            path = row['path']
            if name == 'PUBLIC-FRONT-RECIPE.json':
                prefix = 'review-evidence/hia-native-rewrite-v81-front-20261112-dda7/'
                assert path.startswith(prefix)
                path = 'public-front/' + path[len(prefix):]
            add(path, row['sha'], row['mode'], row['type'])
    for name in ('README.md', 'prepare_audit.py', 'ORIGINAL-JOINT-CI-JOBS-OBSERVATION.json'):
        local(name, ROOT / name)
    ordered = [entries[name] for name in sorted(entries)]
    old_root = read(ROOT / 'PREVIOUS-ROOT.json')
    old_review = read(ROOT / 'PREVIOUS-REVIEW.json')
    assert old_root['sha'] == '1f528389cc7737dd561e7d55683ee79ace275c10'
    assert old_review['sha'] == '85e014f5fac5364640a97488a3b9ae768543dcd8'
    clean = lambda tree: [{k: row[k] for k in ('path', 'mode', 'type', 'sha')} for row in tree]
    assert tree_hash(clean(old_root['tree'])) == old_root['sha']
    assert tree_hash(clean(old_review['tree'])) == old_review['sha']
    leaf_hash = tree_hash(ordered)
    review = clean(old_review['tree']) + [{'path': LEAF, 'mode': '040000', 'type': 'tree', 'sha': leaf_hash}]
    review_hash = tree_hash(review)
    root = [{**row, 'sha': review_hash if row['path'] == 'review-evidence' else row['sha']}
            for row in clean(old_root['tree'])]
    plan = {'schema': 'hia.global-joint.additive-audit-plan.v80.r1',
            'previous_commit': 'cb1eec11f7fb4221deda2fc29604cd299aad6321',
            'previous_root': old_root['sha'], 'previous_review': old_review['sha'],
            'leaf_name': LEAF, 'leaf_entries': ordered, 'leaf_sha': leaf_hash,
            'leaf_steps': [{'count': min(i + 12, len(ordered)), 'sha': tree_hash(ordered[:i + 12])}
                           for i in range(0, len(ordered), 12)],
            'review_entries': review, 'review_sha': review_hash, 'root_entries': root,
            'root_sha': tree_hash(root), 'prior_audit_subtrees_preserved': len(old_review['tree']),
            'new_blobs': new, 'whole_native': False}
    with (ROOT / 'AUDIT-PLAN.json').open('x') as stream:
        json.dump(plan, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({key: plan[key] for key in ('leaf_sha', 'review_sha', 'root_sha', 'prior_audit_subtrees_preserved')}, sort_keys=True))
    print(json.dumps({'leaf_files': len(ordered), 'new_blobs': len(new), 'batches': len(plan['leaf_steps'])}))


if __name__ == '__main__':
    main()
