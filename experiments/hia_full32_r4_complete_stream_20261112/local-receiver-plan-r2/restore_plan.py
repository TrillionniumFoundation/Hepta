"""Restore the complete unexecuted r2 source from its r1 bundle plus exact deltas.

This only writes verified original text/metadata into a new directory. No
supplier, receiver, source controls, or restored Python is executed.
"""
from pathlib import Path, PurePosixPath
import argparse
import base64
import hashlib
import io
import json
import os
import tarfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--frozen-root', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    require(not os.path.lexists(args.destination), 'new destination required')
    manifest = json.loads((args.frozen_root / 'SOURCE-BUNDLE.json').read_bytes())
    require(manifest['schema'] == 'hia.full32.complete-stream-static-r2-source.v1', 'wrong request bundle')
    original_manifest_path = args.frozen_root / manifest['root_old_request_archive_manifest']
    original = json.loads(original_manifest_path.read_bytes())
    expected = {row['path']: row for row in original['files']}
    require(len(expected) == manifest['old_complete_file_count'] == 36, 'old frozen denominator differs')
    chunks, offset = [], 0
    for ordinal, row in enumerate(original['parts']):
        text = (original_manifest_path.parent / row['path']).read_bytes()
        require(row['ordinal'] == ordinal and row['offset'] == offset and pin(text) == row['text'], 'old part identity differs')
        require(text.endswith(b'\n'), 'canonical base64 newline absent')
        raw = base64.b64decode(text[:-1], validate=True)
        require(base64.b64encode(raw) + b'\n' == text and pin(raw) == row['raw'], 'old part body differs')
        chunks.append(raw)
        offset += len(raw)
    archive_bytes = b''.join(chunks)
    require(pin(archive_bytes) == original['archive']
            and pin(archive_bytes)['sha256'] == manifest['old_archive_sha256'], 'old complete archive differs')
    bodies = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:gz') as archive:
        for item in archive:
            require(item.isfile() and item.name in expected and item.name not in bodies, 'unexpected old member')
            row = expected[item.name]
            require(item.size == row['bytes'] <= 16 << 20, 'old member bound differs')
            raw = archive.extractfile(item).read(item.size + 1)
            require(pin(raw) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}, 'old member body differs')
            bodies[item.name] = raw
    require(set(bodies) == set(expected), 'missing old whole file')
    for row in manifest['overlays']:
        raw = (args.frozen_root / row['path']).read_bytes()
        require(pin(raw) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}, 'new exact overlay differs')
        bodies[row['path']] = raw
    require(len(bodies) == manifest['files_count'] == len(manifest['files']), 'new complete population differs')
    args.destination.mkdir(mode=0o700)
    total = 0
    for row in manifest['files']:
        name = PurePosixPath(row['path'])
        require(not name.is_absolute() and str(name) == row['path'] and all(x not in ('', '.', '..') for x in name.parts), 'unsafe relative source path')
        raw = bodies[row['path']]
        require(pin(raw) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}, 'complete new source identity differs')
        path = args.destination.joinpath(*name.parts)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        require(pin(path.read_bytes()) == pin(raw), 'new full file readback differs')
        total += len(raw)
    require(total == manifest['raw_bytes'], 'new complete raw byte count differs')
    print(json.dumps({'status': 'STATIC_R2_BYTES_RESTORED_ONLY', 'files': len(bodies), 'bytes': total, 'executed': False}))


if __name__ == '__main__':
    main()
