#!/usr/bin/env python3
"""Verify the frozen evidence bytes and compute a Git tree without changing Git."""
from pathlib import Path
import hashlib
import json
import subprocess

ROOT = Path('/workspace/scratch/372e7da9bde9')
REPOSITORY = ROOT / 'Hepta'
EVIDENCE = ROOT / 'evidence-branch'
PREFIX = 'review-evidence/hia-followthrough-20261107/'
PARENT = '205f94ec811018f89fbf68c987c6ab8e826bb15b'
BASE_TREE = 'd57b1f75e4ca05e5a2fd018906b5e2c32e2fa70e'


def object_id(kind, body):
    return hashlib.sha1(kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body).hexdigest()


def tree_id(entries):
    root = {}
    for path, value in entries.items():
        node = root
        parts = path.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        assert parts[-1] not in node
        node[parts[-1]] = value

    def walk(node):
        body = bytearray()
        for name, value in sorted(node.items(), key=lambda item: (item[0] + ('/' if isinstance(item[1], dict) else '')).encode()):
            mode, digest = ('40000', walk(value)) if isinstance(value, dict) else value
            body.extend(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest))
        return object_id('tree', body)

    return walk(root)


def main():
    mapping_raw = (ROOT / 'evidence-uploaded-blobs.json').read_bytes()
    mapping = json.loads(mapping_raw)
    assert mapping['repository'] == 'TrillionniumFoundation/Hepta'
    records = mapping['files']
    actual = {}
    for path in (EVIDENCE / PREFIX).rglob('*'):
        assert not path.is_symlink(), path
        if path.is_file():
            relative = path.relative_to(EVIDENCE).as_posix()
            raw = path.read_bytes()
            actual[relative] = {
                'git_blob_sha': object_id('blob', raw),
                'sha256': hashlib.sha256(raw).hexdigest(),
                'bytes': len(raw),
            }
    assert actual and set(actual) == set(records), {
        'missing_upload': sorted(set(actual) - set(records)),
        'stale_upload': sorted(set(records) - set(actual)),
    }
    for path, facts in actual.items():
        assert all(records[path][key] == value for key, value in facts.items()), path
    entries = {}
    raw_tree = subprocess.check_output(['git', '-C', str(REPOSITORY), 'ls-tree', '-r', '-z', PARENT])
    for item in raw_tree.split(b'\0'):
        if item:
            metadata, path = item.split(b'\t', 1)
            mode, kind, digest = metadata.decode().split()
            assert kind in ('blob', 'commit')
            path = path.decode()
            assert not path.startswith(PREFIX), path
            entries[path] = (mode, digest)
    assert tree_id(entries) == BASE_TREE
    original_count = len(entries)
    elements = []
    for path, facts in sorted(actual.items()):
        entries[path] = ('100644', facts['git_blob_sha'])
        elements.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': facts['git_blob_sha']})
    payload = json.dumps(elements, separators=(',', ':')).encode()
    result = {
        'schema': 'hepta.hia.evidence-publication-plan.v1',
        'repository': mapping['repository'],
        'parent_commit': PARENT,
        'base_tree': BASE_TREE,
        'expected_tree': tree_id(entries),
        'base_leaf_count': original_count,
        'evidence_file_count': len(actual),
        'evidence_bytes': sum(row['bytes'] for row in actual.values()),
        'complete_leaf_count': len(entries),
        'upload_map_sha256': hashlib.sha256(mapping_raw).hexdigest(),
        'tree_elements_sha256': hashlib.sha256(payload).hexdigest(),
        'git_index_or_commit_mutated': False,
        'source_files_changed': False,
    }
    (ROOT / 'evidence-publish-elements.json').write_bytes(payload)
    (ROOT / 'evidence-publish-plan.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
