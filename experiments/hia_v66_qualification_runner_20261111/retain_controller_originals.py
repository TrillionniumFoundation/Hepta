"""Retain controller observations; independently read every archive member.

This script archives existing observations. It executes no HIA product or
qualification and never changes an original receipt or prior status.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import stat
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    workspace = args.workspace.resolve(strict=True)
    output = args.output.resolve(strict=True)
    archive = output / 'controller-originals.tar.gz'
    receipt = output / 'controller-originals-retention.json'
    if archive.exists() or receipt.exists():
        raise ValueError('preserve existing archive and retention receipt')
    paths = []
    for pattern in ('rog-v7-gate-controls-r*', 'rog-v7-suite-controls-r*'):
        for path in sorted(workspace.glob(pattern)):
            if path.is_dir():
                paths.extend(p for p in sorted(path.rglob('*')) if not p.is_dir())
            else:
                paths.append(path)
    if not paths or len(paths) != len(set(paths)):
        raise ValueError('missing or duplicate controller observation paths')
    members = {}
    for path in sorted(paths):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('controller evidence must be a regular file: ' + str(path))
        data = path.read_bytes()
        members[path.relative_to(workspace).as_posix()] = {
            'bytes': len(data), 'sha256': sha256(data).hexdigest(),
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
        }
    with tarfile.open(archive, 'x:gz') as stream:
        for name in sorted(members):
            stream.add(workspace / name, arcname=name, recursive=False)
    observed = {}
    total = 0
    with tarfile.open(archive, 'r:gz') as stream:
        for member in stream:
            if not member.isfile() or member.name in observed:
                raise ValueError('unexpected or duplicate archive member')
            reader = stream.extractfile(member)
            assert reader is not None
            digest = sha256()
            size = 0
            while block := reader.read(65536):
                size += len(block)
                digest.update(block)
            actual = {'bytes': size, 'sha256': digest.hexdigest(),
                      'mode': member.mode, 'uid': member.uid, 'gid': member.gid}
            if actual != members.get(member.name) or size != member.size:
                raise ValueError('archived controller bytes or metadata differ')
            if (workspace / member.name).read_bytes() != stream.extractfile(member).read():
                raise ValueError('original controller file changed during retention')
            observed[member.name] = actual
            total += size
    if observed != members:
        raise ValueError('archive membership differs')
    result = {
        'schema': 'hia.v7-controller-original-retention.v1',
        'status': 'ALL_ARCHIVED_MEMBERS_READ_AND_MATCH',
        'archive': archive.name, 'archive_bytes': archive.stat().st_size,
        'archive_sha256': sha256(archive.read_bytes()).hexdigest(),
        'member_count': len(observed), 'uncompressed_bytes_read': total,
        'independent_every_member_read': True,
        'bytes_sha256_mode_uid_gid_checked': True,
        'originals_preserved': True, 'members': members,
        'product_or_cold_qualification_claimed': False,
    }
    receipt.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'members'}, sort_keys=True))


if __name__ == '__main__':
    main()
