#!/usr/bin/env python3
"""Verify qualification-only changes before projecting exact historical bytes."""
from pathlib import Path
import hashlib
import json
from verify_rust_fixture_repairs import project_original as upstream_original

ROOT = Path(__file__).resolve().parents[1]
PARENT = '0594a85f2f1e05ef50a61bf9c5a18ae191499502'
UPSTREAM = '021c0731e6105dcda7fe0fcafc4b62836e81657e'
UPSTREAM_IDENTITIES = {'tools/verify_rust_fixture_repairs.py': {'git_blob': 'f827f4d37a42c4e8019b9bc29502f04b1e8f6f53', 'sha256': 'f1d08a9b40dbdd5542a69e5fecbf74921d9845ef6b7b5bb5ee32d89ad22644bb'}, 'tools/rust_fixture_repairs.json': {'git_blob': '9cd941a2a2500b3ba73a042b4736a9e0aa8587c0', 'sha256': '6651438da732145c4f8486580d22e92e71e06746a444fac3293030334e314d6e'}}
EXPECTED_EDITS = ('tools/qualify_typed_stdlib.py', 'tools/typed_stdlib_inventory.json', 'tools/typed_stdlib_rust_inventory.json', 'tools/verify_typed_stdlib_sources.py')

def identity(data):
    return {'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()}

def manifest(root):
    for name, expected in UPSTREAM_IDENTITIES.items():
        if identity((root / name).read_bytes()) != expected:
            raise ValueError('Changed exact upstream fixture repair: ' + name)
    doc = json.loads((root / 'tools/typed_fixture_repairs.json').read_bytes())
    if doc['parent'] != PARENT or doc['upstream'] != UPSTREAM or set(doc['files']) != set(EXPECTED_EDITS):
        raise ValueError('Changed qualification repair scope')
    return doc

def project_original(name, data, root=ROOT):
    entry = manifest(root)['files'].get(name)
    if entry is None:
        return upstream_original(name, data)
    if not name.startswith(('tools/', 'docs/')):
        raise ValueError('Downstream repair cannot change production or test bodies')
    if identity(data) != entry['repaired']:
        raise ValueError('Changed downstream qualification source: ' + name)
    text = data.decode('utf-8')
    last = len(text)
    for edit in reversed(entry['edits']):
        start, end = edit['start'], edit['end']
        if not 0 <= start <= end <= last or text[start:end] != edit['after']:
            raise ValueError('Changed downstream inverse edit: ' + name)
        text = text[:start] + edit['before'] + text[end:]
        last = start
    restored = text.encode('utf-8')
    if identity(restored) != entry['original']:
        raise ValueError('Downstream original bytes not recovered: ' + name)
    return restored

def verify(root=ROOT):
    doc = manifest(root)
    upstream = json.loads((root / 'tools/rust_fixture_repairs.json').read_bytes())
    recovered = {}
    for name in sorted(set(upstream['files']) | set(doc['files'])):
        recovered[name] = identity(project_original(name, (root / name).read_bytes(), root))
    return {'complete_pass': True, 'parent': PARENT, 'upstream': UPSTREAM,
            'recovered_files': recovered, 'native_rust_evidence': False}

if __name__ == '__main__':
    print(json.dumps(verify(), sort_keys=True))
