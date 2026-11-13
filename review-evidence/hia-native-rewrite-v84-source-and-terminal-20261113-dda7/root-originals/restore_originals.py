"""Restore the exact logical evidence files from the verified Git fragments."""
from __future__ import annotations

import argparse
import base64
from hashlib import sha1, sha256
import io
import json
from pathlib import Path, PurePosixPath
import tarfile


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'blob': sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def safe_name(name):
    p = PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '.' in p.parts or str(p) != name:
        raise ValueError('noncanonical evidence path')
    return p


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fragments', type=Path)
    parser.add_argument('--output', type=Path,
                        help='New directory for exact restored logical files; omit to verify only')
    args = parser.parse_args()
    index = json.loads((args.fragments/'REMOTE-INDEX.json').read_bytes())
    chunks = []
    for number, row in enumerate(index['parts']):
        if row['number'] != number:
            raise ValueError('fragment order differs')
        encoded = (args.fragments/safe_name(row['path'])).read_bytes()
        if identity(encoded) != {k: row[k] for k in ('bytes', 'sha256', 'blob')}:
            raise ValueError('fragment identity differs')
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != row['raw_bytes'] or sha256(raw).hexdigest() != row['raw_sha256']:
            raise ValueError('decoded fragment identity differs')
        chunks.append(raw)
    archive = b''.join(chunks)
    if identity(archive) != index['archive']:
        raise ValueError('complete original archive differs')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as stream:
        objects = {}
        for member in stream:
            safe_name(member.name)
            if not member.isfile() or member.name in objects:
                raise ValueError('unexpected archive member')
            objects[member.name] = stream.extractfile(member).read()
    contents_raw = objects.pop('CONTENTS.json')
    if identity(contents_raw) != index['manifest']:
        raise ValueError('logical manifest differs')
    contents = json.loads(contents_raw)
    for name, row in contents['members'].items():
        safe_name(name)
        if identity(objects[row['object']]) != {k: row[k] for k in ('bytes', 'sha256', 'blob')}:
            raise ValueError('logical member differs')
        if row['mode'] not in ('100644', '100755'):
            raise ValueError('ordinary Git file mode required')
    if set(objects) != {row['object'] for row in contents['members'].values()}:
        raise ValueError('unexpected content object')
    if args.output is not None:
        args.output.mkdir(parents=False, exist_ok=False)
        for name, row in contents['members'].items():
            path = args.output/safe_name(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as target:
                target.write(objects[row['object']])
            path.chmod(0o755 if row['mode'] == '100755' else 0o644)
    print(json.dumps({'verified_logical_files': len(contents['members']),
                      'archive_sha256': sha256(archive).hexdigest(),
                      'restored': args.output is not None, 'whole_native': False}, sort_keys=True))


if __name__ == '__main__':
    main()
