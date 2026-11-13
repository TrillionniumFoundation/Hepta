"""Restore one exact derived transport ZIP from retained source and four literals.

Requires a fresh output path. Does not download, execute the product, or remove
any file. Original inode/ctime are never represented as those of a new copy.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat

CHUNK = 1 << 20


def identity(s):
    return tuple(getattr(s, 'st_' + n) for n in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns'))


def literal(root, row):
    path = root / row['path']
    assert path.parent == root and path.name.endswith('.base64')
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    raw = path.read_bytes()
    assert identity(path.lstat()) == identity(before)
    assert len(raw) == row['encoded']['bytes'] and hashlib.sha256(raw).hexdigest() == row['encoded']['sha256']
    assert raw.endswith(b'\n') and b'\n' not in raw[:-1]
    decoded = base64.b64decode(raw[:-1], validate=True)
    assert len(decoded) == row['raw_bytes'] and hashlib.sha256(decoded).hexdigest() == row['raw_sha256']
    return decoded


def pieces(source_fd, recipe, literal_root):
    yield literal(literal_root, recipe['prefix'])
    span = recipe['source_range']
    digest = hashlib.sha256()
    for offset in range(0, span['bytes'], CHUNK):
        size = min(CHUNK, span['bytes'] - offset)
        raw = os.pread(source_fd, size, span['offset'] + offset)
        assert len(raw) == size
        digest.update(raw)
        yield raw
    assert digest.hexdigest() == span['sha256']
    yield literal(literal_root, recipe['suffix'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--ordinal', type=int, choices=(0, 1), required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.recipe.read_bytes())
    assert document['schema'] == 'hia.root.lossless-derived-v89-part-recipe.v1'
    expected = document['source_original']; recipe = document['parts'][args.ordinal]
    assert recipe['ordinal'] == args.ordinal and not os.path.lexists(args.destination)
    before = args.source.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == expected['bytes']
    source_fd = os.open(args.source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert identity(os.fstat(source_fd)) == identity(before)
        digest = hashlib.sha256()
        for offset in range(0, expected['bytes'], CHUNK):
            raw = os.pread(source_fd, min(CHUNK, expected['bytes'] - offset), offset)
            assert len(raw) == min(CHUNK, expected['bytes'] - offset)
            digest.update(raw)
        assert digest.hexdigest() == expected['sha256']
        output_fd = os.open(args.destination, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        whole = hashlib.sha256(); count = 0
        try:
            created = os.fstat(output_fd)
            assert stat.S_ISREG(created.st_mode) and created.st_nlink == 1
            for raw in pieces(source_fd, recipe, args.recipe.parent):
                remaining = memoryview(raw)
                while remaining:
                    written = os.write(output_fd, remaining)
                    assert written > 0
                    remaining = remaining[written:]
                whole.update(raw); count += len(raw)
            os.fsync(output_fd)
            assert count == recipe['transport_bytes'] and whole.hexdigest() == recipe['transport_sha256']
            assert identity(os.fstat(source_fd)) == identity(before) == identity(args.source.lstat())
            closed_write = os.fstat(output_fd)
            assert (closed_write.st_dev, closed_write.st_ino) == (created.st_dev, created.st_ino)
            assert identity(args.destination.lstat()) == identity(closed_write)
            assert stat.S_ISREG(closed_write.st_mode) and closed_write.st_nlink == 1 and closed_write.st_size == count
            readback = hashlib.sha256()
            for offset in range(0, count, CHUNK):
                raw = os.pread(output_fd, min(CHUNK, count - offset), offset)
                assert len(raw) == min(CHUNK, count - offset)
                readback.update(raw)
            assert readback.hexdigest() == recipe['transport_sha256']
            assert identity(os.fstat(output_fd)) == identity(closed_write) == identity(args.destination.lstat())
            os.fchmod(output_fd, stat.S_IMODE(recipe['transport_identity']['mode']))
            os.utime(output_fd, ns=(recipe['transport_identity']['mtime_ns'], recipe['transport_identity']['mtime_ns']))
            os.fsync(output_fd)
            assert identity(os.fstat(output_fd)) == identity(args.destination.lstat())
            parent_fd = os.open(args.destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            os.close(output_fd)
        print(json.dumps({'status': 'COMPLETE_EXACT_BYTES_RESTORED_TO_NEW_IDENTITY', 'path': str(args.destination), 'bytes': count, 'sha256': whole.hexdigest(), 'original_inode_or_ctime_claimed': False}))
    finally:
        os.close(source_fd)


if __name__ == '__main__':
    main()
