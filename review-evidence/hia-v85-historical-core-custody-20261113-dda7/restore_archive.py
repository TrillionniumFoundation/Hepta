"""Reassemble the exact archived bytes; do not extract or execute their contents."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

def restore(index_path: Path, wrappers: Path, output: Path) -> dict:
    index = json.loads(index_path.read_text())
    expected = index['archive']
    rows = index['chunks']
    if len(rows) != 84 or output.exists():
        raise ValueError('unexpected chunk count or existing destination')
    offset = 0
    digest = hashlib.sha256()
    git_digest = hashlib.sha1(b'blob ' + str(expected['bytes']).encode() + b'\0')
    with output.open('xb') as stream:
        for number, row in enumerate(rows):
            name = 'chunk-%03d.json' % number
            if row['name'] != name or row['index'] != number or row['offset'] != offset:
                raise ValueError('noncanonical order, filename, or offset')
            raw = (wrappers / name).read_bytes()
            if len(raw) != row['wrapper_bytes'] or hashlib.sha256(raw).hexdigest() != row['wrapper_sha256']:
                raise ValueError('wrapper byte mismatch')
            if hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != row['git_blob']:
                raise ValueError('wrapper Git identity mismatch')
            record = json.loads(raw)
            block = base64.b64decode(record['data'], validate=True)
            if record['index'] != number or record['offset'] != offset or len(block) != row['bytes']:
                raise ValueError('chunk position mismatch')
            if hashlib.sha256(block).hexdigest() != row['sha256'] or record['sha256'] != row['sha256']:
                raise ValueError('chunk digest mismatch')
            if record['archive_bytes'] != expected['bytes'] or record['archive_sha256'] != expected['sha256']:
                raise ValueError('archive binding mismatch')
            stream.write(block)
            digest.update(block)
            git_digest.update(block)
            offset += len(block)
        stream.flush()
        os.fsync(stream.fileno())
    if offset != expected['bytes'] or digest.hexdigest() != expected['sha256'] or git_digest.hexdigest() != expected['computed_git_identity']:
        raise ValueError('complete archive identity mismatch')
    return {'status': 'COMPLETE', 'bytes': offset, 'sha256': digest.hexdigest(),
            'computed_git_identity': git_digest.hexdigest(), 'archive_contents_executed': False}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--wrappers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(restore(args.index, args.wrappers, args.output), sort_keys=True))
