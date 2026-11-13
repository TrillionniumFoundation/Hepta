"""Restore only the exact original files listed by this source8 evidence package."""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import tarfile


def require(value, message):
    if not value:
        raise ValueError(message)


def sealed(raw, pin):
    require(len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256'], 'byte/SHA seal')
    if 'git_blob' in pin:
        require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == pin['git_blob'], 'Git blob seal')


def decode(package):
    manifest = json.loads((package / 'ARCHIVE-MANIFEST.json').read_bytes())
    pieces = []
    for index, item in enumerate(manifest['parts']):
        require(item['index'] == index, 'ordered complete part population')
        text = (package / item['path']).read_bytes()
        sealed(text, item['text'])
        require(text.endswith(b'\n') and b'\n' not in text[:-1], 'single canonical base64 line')
        raw = base64.b64decode(text[:-1], validate=True)
        require(base64.b64encode(raw) + b'\n' == text, 'canonical base64')
        sealed(raw, item['raw'])
        pieces.append(raw)
    compressed = b''.join(pieces)
    sealed(compressed, manifest['gzip'])
    require(manifest['tar']['bytes'] <= 128 << 20, 'bounded original archive')
    tar_raw = gzip.decompress(compressed)
    sealed(tar_raw, manifest['tar'])
    expected = {row['name']: row for row in manifest['files']}
    require(len(expected) == len(manifest['files']), 'unique original manifest')
    observed = {}
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode='r:') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            require(member.isfile() and not name.is_absolute() and all(p not in ('', '.', '..') for p in name.parts), 'regular relative member')
            require(member.name in expected and member.name not in observed, 'exact whole member set')
            row = expected[member.name]
            require(member.size == row['bytes'] and member.mode == row['identity'][2] & 0o7777
                    and member.uid == row['identity'][3] and member.gid == row['identity'][4], 'original metadata')
            raw = archive.extractfile(member).read()
            sealed(raw, row)
            observed[member.name] = raw
    require(set(observed) == set(expected) and sum(map(len, observed.values())) == manifest['original_bytes'], 'complete whole originals')
    return manifest, observed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    manifest, observed = decode(args.package)
    if args.output is not None:
        args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
        rows = {r['name']: r for r in manifest['files']}
        for name, raw in observed.items():
            path = args.output / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                offset = 0
                while offset < len(raw):
                    count = os.write(fd, raw[offset:])
                    require(count > 0, 'positive write progress')
                    offset += count
                os.fchmod(fd, rows[name]['identity'][2] & 0o7777)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.utime(path, ns=(rows[name]['identity'][7], rows[name]['identity'][7]), follow_symlinks=False)
            sealed(path.read_bytes(), rows[name])
        require({str(p.relative_to(args.output)) for p in args.output.rglob('*') if p.is_file()} == set(observed), 'complete restored namespace')
    print(json.dumps({'status': 'COMPLETE_ORIGINAL_BYTES_RESTORED_OR_VERIFIED',
                      'files': len(observed), 'bytes': manifest['original_bytes'],
                      'gzip_sha256': manifest['gzip']['sha256'], 'output_created': args.output is not None}, sort_keys=True))


if __name__ == '__main__':
    main()
