"""Only the frozen eight inert Rustup-command source controls use this module."""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import json
import os
import stat

MAX_INPUT = 64 << 20

def require(value, message):
    if not value:
        raise RuntimeError(message)

def identity(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]

@contextmanager
def held_parent(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute fixed input required')
    descriptors = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    edges = []
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(descriptor)
            current = os.fstat(descriptor)
            edges.append((parent, name, descriptor, (current.st_dev, current.st_ino)))
        yield descriptors[-1], path.name
        for parent, name, descriptor, expected in edges:
            a = os.fstat(descriptor)
            b = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(b.st_mode) and (a.st_dev, a.st_ino) == expected
                    == (b.st_dev, b.st_ino), 'parent directory identity changed')
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def read(path, maximum=MAX_INPUT):
    with held_parent(path) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= maximum, 'fixed single-link regular file required')
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            require(identity(os.fstat(descriptor)) == identity(before), 'open identity differs')
            pieces, count, digest = [], 0, hashlib.sha256()
            while True:
                block = os.read(descriptor, min(1 << 20, maximum + 1 - count))
                if not block:
                    break
                count += len(block)
                require(count <= maximum, 'whole original exceeds bound')
                digest.update(block); pieces.append(block)
            require(count == before.st_size and identity(os.fstat(descriptor)) == identity(before)
                    == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'original identity changed during full read')
        finally:
            os.close(descriptor)
    raw = b''.join(pieces)
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(count).encode() + b'\0' + raw).hexdigest(),
            'identity': identity(before)}, raw

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def create(path, value, raw=False):
    body = value if raw else wire(value)
    with held_parent(path) as (parent, name):
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.fsync(parent)
    record, actual = read(path, max(len(body), 1))
    require(actual == body, 'new original independent readback differs')
    return record

def input_records(root, request):
    records = {}
    for name, expected in request['inputs'].items():
        require(type(name) is str and not name.startswith('/') and '..' not in Path(name).parts,
                'fixed relative source pin required')
        actual, _ = read(root / name)
        require(all(actual[key] == expected[key] for key in ('bytes', 'sha256', 'git_blob')),
                'frozen input byte pin differs: ' + name)
        records[name] = actual
    return records
