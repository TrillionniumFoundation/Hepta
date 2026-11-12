"""Fixed source-only snapshot helpers; no product import or execution."""
from __future__ import annotations
from hashlib import sha256, sha1
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(path):
    path = Path(path).absolute()
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'regular input required before reading: ' + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        held = os.fstat(descriptor)
        require(identity(before) == identity(held), 'input changed before open: ' + str(path))
        data = bytearray()
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        require(identity(before) == identity(after) == identity(path.lstat()),
                'input changed during read: ' + str(path))
        raw = bytes(data)
        require(len(raw) == before.st_size, 'input length differs: ' + str(path))
        return {'path': str(path), 'size': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid, 'gid': before.st_gid,
            'nlink': before.st_nlink, 'device': before.st_dev, 'inode': before.st_ino,
            'mtime_ns': before.st_mtime_ns, 'ctime_ns': before.st_ctime_ns}
    finally:
        os.close(descriptor)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def snapshot(root):
    root = Path(root).resolve(strict=True)
    rows = []
    for current, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            require(stat.S_ISDIR((Path(current) / name).lstat().st_mode), 'source directory link refused')
        for name in files:
            path = Path(current) / name
            row = pin(path)
            require(row['uid'] == os.geteuid() and row['nlink'] == 1
                    and row['mode'] & 0o022 == 0, 'source ownership/mode differs: ' + str(path))
            rows.append({'relative_path': path.relative_to(root).as_posix(), **row})
    return sorted(rows, key=lambda row: row['relative_path'])


def content(rows):
    return [{key: row[key] for key in ('relative_path', 'size', 'sha256', 'git_blob_sha1', 'mode')}
            for row in rows]


def save(path, value):
    path = Path(path)
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def request():
    path = HERE / 'REQUEST.json'
    value = json.loads(path.read_bytes())
    require(value['schema'] == 'hepta.hia.core-integer-integration-source-request.v1', 'request schema')
    return value


def runtime(expected):
    import sys
    actual = pin(Path(sys.executable).resolve(strict=True))
    require(actual == expected, 'already-pinned interpreter identity differs')
    require(actual['path'] == str(Path(actual['path']).resolve(strict=True))
            and actual['nlink'] == 1 and actual['mode'] & 0o022 == 0,
            'pinned system interpreter alias, link count or writable mode differs')
    return actual
