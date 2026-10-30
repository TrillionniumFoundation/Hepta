#!/usr/bin/env python3
"""Reassemble downloaded exact archive parts without extracting the archive."""
import argparse
from hashlib import sha1, sha256
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=Path('archive-parts.json'))
    parser.add_argument('--parts-directory', type=Path, default=Path('.'))
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    document = json.loads(options.manifest.read_text())
    expected = document['archive']
    if options.output.exists():
        raise ValueError('output already exists; preserve previous restorations')
    digest, blob = sha256(), sha1(b'blob ' + str(expected['bytes']).encode() + b'\0')
    offset = 0
    with options.output.open('xb') as output:
        for row in document['parts']:
            if row['offset'] != offset or Path(row['name']).name != row['name']:
                raise ValueError('invalid ordered part path or offset')
            raw = (options.parts_directory / row['name']).read_bytes()
            if len(raw) != row['bytes'] or sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('part size or SHA256 mismatch: ' + row['name'])
            if sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != row['git_blob']:
                raise ValueError('part Git blob mismatch: ' + row['name'])
            output.write(raw)
            digest.update(raw)
            blob.update(raw)
            offset += len(raw)
    if (offset != expected['bytes'] or digest.hexdigest() != expected['sha256']
            or blob.hexdigest() != expected['git_blob']):
        raise ValueError('complete reconstructed archive identity mismatch; partial output retained')
    print(json.dumps({'output': str(options.output), 'bytes': offset,
                      'sha256': digest.hexdigest(), 'git_blob': blob.hexdigest(), 'ok': True}))


if __name__ == '__main__':
    main()
