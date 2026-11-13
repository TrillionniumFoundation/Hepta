"""Restore one of four redundant transport copies to a fresh destination."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parent


def identity(s):
    return {k: getattr(s, 'st_' + k) for k in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def read(p):
    before = p.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert identity(os.fstat(fd)) == identity(before)
        chunks = []
        while True:
            part = os.read(fd, 1 << 20)
            if not part:
                break
            chunks.append(part)
        assert identity(os.fstat(fd)) == identity(before) == identity(p.lstat())
        result = b''.join(chunks)
        assert len(result) == before.st_size
        return result
    finally:
        os.close(fd)


def checked(row):
    p = Path(row['path']); raw = read(p)
    assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
    if 'git_blob' in row:
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob']
    # Restoring from an exact recovered source may have a new inode; full bytes
    # are binding, while source stability is checked within each read above.
    return raw


def records():
    proof = json.loads(read(ROOT / 'CANDIDATES-READBACK.json'))
    recipe = json.loads(read(ROOT / 'V83-RESTORE-RECIPE.json'))
    return proof, recipe, proof['workspace_candidates'] + proof['tmp_candidates']


def pieces(index):
    proof, recipe, targets = records()
    assert type(index) is int and 0 <= index < 4
    if index == 0:
        files = [{'path': row['canonical_path'], 'text': checked(row).decode('utf-8')}
                 for row in recipe['retained_files_in_exact_bundle_order']]
        manifest = json.loads(recipe['ordered_manifest_json'])
        assert manifest == json.loads(checked(proof['v83']['manifest']))
        assert recipe['serialization'] == {'ensure_ascii': False, 'sort_keys': False, 'separators': [',', ':'], 'trailing_newline': True}
        encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=False, separators=(',', ':'))
        for text in encoder.iterencode({'files': files, 'manifest': manifest}):
            yield text.encode('utf-8')
        yield b'\n'
        return
    if index == 1:
        manifest = json.loads(checked(proof['v83']['manifest']))
        remaining = {r['canonical_path'][len(recipe['canonical_prefix']):]: r for r in recipe['retained_files_in_exact_bundle_order']}
        rows = [remaining[p['path']] for p in manifest['parts']]
    elif index == 2:
        rows = proof['checkpoint']['all16_remaining_parts']
    else:
        rows = proof['integer']['all42_remaining_parts']
    for row in rows:
        encoded = checked(row)
        assert encoded.endswith(b'\n')
        raw = base64.b64decode(encoded[:-1], validate=True)
        assert base64.b64encode(raw) + b'\n' == encoded
        yield raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('index', type=int, choices=range(4))
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    _, _, targets = records(); target = targets[args.index]
    destination = args.destination.absolute()
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for component in destination.parent.parts[1:]:
            new = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = new
        fd = os.open(destination.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        sha = hashlib.sha256(); size = 0
        for raw in pieces(args.index):
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError('short restore write')
                view = view[count:]
            size += len(raw); sha.update(raw)
        assert size == target['bytes'] and sha.hexdigest() == target['sha256']
        os.fsync(fd)
        expected = identity(os.fstat(fd)); actual = hashlib.sha256()
        for offset in range(0, size, 1 << 20):
            raw = os.pread(fd, min(1 << 20, size - offset), offset)
            assert len(raw) == min(1 << 20, size - offset)
            actual.update(raw)
        assert actual.hexdigest() == target['sha256'] and identity(os.fstat(fd)) == expected
        os.fchmod(fd, stat.S_IMODE(target['identity']['mode']))
        os.fsync(fd); os.fsync(parent)
        assert os.fstat(fd).st_ino == os.stat(destination.name, dir_fd=parent, follow_symlinks=False).st_ino
        print(json.dumps({'status': 'EXACT_DERIVED_FILE_RESTORED_AND_REREAD', 'path': str(destination),
            'bytes': size, 'sha256': actual.hexdigest(), 'original_inode_or_ctime_claimed': False}))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


if __name__ == '__main__':
    main()
