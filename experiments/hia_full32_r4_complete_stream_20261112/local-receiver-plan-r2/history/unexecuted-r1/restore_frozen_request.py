"""Restore only this request's exact frozen bytes into a new empty directory.

No restored Python is imported or executed. This bundle holds static controls
and previously authenticated metadata, not the original 3 GB provider ZIP.
"""
from pathlib import Path, PurePosixPath
import argparse
import base64
import hashlib
import io
import json
import os
import tarfile


def require(value, message):
    if not value:
        raise RuntimeError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.manifest.read_bytes())
    require(document['schema'] == 'hia.full32.stream-request-complete-source-bundle.v1', 'wrong bundle schema')
    require(document['files_count'] == len(document['files']) == 36, 'complete frozen denominator differs')
    require(not os.path.lexists(args.destination), 'fresh destination required; never overwrite originals')
    chunks = []
    offset = 0
    for ordinal, row in enumerate(document['parts']):
        require(row['ordinal'] == ordinal and row['offset'] == offset, 'noncontiguous request bundle')
        text = (args.manifest.parent / row['path']).read_bytes()
        require(pin(text) == row['text'] and text.endswith(b'\n'), 'complete base64 original differs')
        raw = base64.b64decode(text[:-1], validate=True)
        require(base64.b64encode(raw) + b'\n' == text and pin(raw) == row['raw'], 'noncanonical request part')
        chunks.append(raw)
        offset += len(raw)
    raw_archive = b''.join(chunks)
    require(pin(raw_archive) == document['archive'], 'complete request archive differs')
    expected = {r['path']: r for r in document['files']}
    require(len(expected) == len(document['files']), 'duplicate frozen path')
    args.destination.mkdir(mode=0o700)
    actual = []
    with tarfile.open(fileobj=io.BytesIO(raw_archive), mode='r:gz') as archive:
        for item in archive:
            name = PurePosixPath(item.name)
            require(item.isfile() and not name.is_absolute() and all(x not in ('', '.', '..') for x in name.parts)
                    and str(name) == item.name and item.name in expected, 'unsafe or unexpected frozen member')
            require(item.name not in [r['path'] for r in actual], 'duplicate archive member')
            row = expected[item.name]
            require(item.size == row['bytes'] <= 16 << 20, 'bounded whole frozen file differs')
            body = archive.extractfile(item).read(item.size + 1)
            require(pin(body) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}, 'frozen member body differs')
            path = args.destination.joinpath(*name.parts)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            require(pin(path.read_bytes()) == pin(body), 'restored whole file differs')
            actual.append({'path': item.name, **pin(body)})
    require(actual == document['files'] and sum(x['bytes'] for x in actual) == document['raw_bytes'],
            'complete restored request denominator differs')
    print(json.dumps({'status': 'FROZEN_STATIC_BYTES_RESTORED_ONLY', 'files': len(actual),
                      'raw_bytes': document['raw_bytes'], 'executed': False}))


if __name__ == '__main__':
    main()
