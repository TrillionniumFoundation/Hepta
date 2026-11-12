"""Fixed-path receipts for one finite comparison development request.

No product/compiler execution occurs on import. Filesystem identity is checked
at the actual read points, without claiming immutability between observations.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256, sha1
import json
import os
from pathlib import Path
import stat


def require(value, message):
    if not value:
        raise ValueError(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def identity(information):
    return {key: getattr(information, 'st_' + key) for key in
            ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def directory_identity(information):
    return tuple(getattr(information, 'st_' + key) for key in ('dev', 'ino', 'mode', 'uid', 'gid'))


@contextmanager
def parent_fd(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'fixed path must be absolute')
    held = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    links = []
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=held[-1])
            held.append(child)
            info = os.fstat(child)
            require(stat.S_ISDIR(info.st_mode), 'path parent is not a directory')
            linked = os.stat(component, dir_fd=held[-2], follow_symlinks=False)
            require(directory_identity(info) == directory_identity(linked), 'parent link changed')
            links.append((held[-2], component, child, directory_identity(info)))
        yield held[-1], path.name
        for parent, component, child, expected in links:
            require(directory_identity(os.fstat(child)) == expected
                    == directory_identity(os.stat(component, dir_fd=parent, follow_symlinks=False)),
                    'held parent identity changed')
    finally:
        for fd in reversed(held):
            os.close(fd)


def read_file(path, maximum, *, raw_required=True):
    """Reject special leaves before reading; retain all ancestor descriptors."""
    digest = sha256()
    chunks = []
    with parent_fd(path) as (parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            initial = os.fstat(fd)
            require(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1,
                    'input must be a singly linked regular file: ' + str(path))
            require(initial.st_uid in (0, os.geteuid()) and not initial.st_mode & 0o022,
                    'input ownership or writable mode differs: ' + str(path))
            require(initial.st_size <= maximum, 'input exceeds its declared bound: ' + str(path))
            require(identity(initial) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'leaf link changed before read')
            remaining = initial.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 65536))
                require(bool(chunk), 'input was truncated')
                digest.update(chunk)
                if raw_required:
                    chunks.append(chunk)
                remaining -= len(chunk)
            require(not os.read(fd, 1), 'input grew during read')
            require(identity(initial) == identity(os.fstat(fd))
                    == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'leaf changed during read')
        finally:
            os.close(fd)
    result = {'path': str(path), 'size': initial.st_size,
              'mode': stat.S_IMODE(initial.st_mode), 'sha256': digest.hexdigest(),
              'identity': identity(initial)}
    return (b''.join(chunks) if raw_required else None), result


def pin(path, maximum=32 << 20):
    return read_file(path, maximum, raw_required=False)[1]


def create(path, raw):
    """Create only; existing files, symlink parents and future mutations refuse."""
    require(type(raw) is bytes, 'creation requires exact bytes')
    with parent_fd(path) as (parent, name):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=parent)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                require(count > 0, 'short file write')
                view = view[count:]
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            digest = sha256()
            remaining = len(raw)
            while remaining:
                observed = os.read(fd, min(remaining, 65536))
                require(bool(observed), 'short creation readback')
                digest.update(observed)
                remaining -= len(observed)
            info = os.fstat(fd)
            require(not os.read(fd, 1) and info.st_size == len(raw)
                    and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
                    and digest.hexdigest() == sha256(raw).hexdigest()
                    and identity(info) == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'creation identity or bytes differ')
        finally:
            os.close(fd)
    return pin(path, max(1, len(raw)))


def save(path, value):
    return create(path, wire(value))


def frozen(root, policy):
    records = []
    for row in policy['frozen_files']:
        path = root / row['path']
        raw, actual = read_file(path, row['size'])
        require((actual['size'], actual['sha256'], actual['mode'])
                == (row['size'], row['sha256'], row['mode']), 'frozen file differs: ' + row['path'])
        require(sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                == row['git_blob_sha1'], 'frozen Git blob differs: ' + row['path'])
        records.append(actual)
    for row in policy['external_files']:
        actual = pin(Path(row['path']), row['size'])
        require((actual['size'], actual['sha256'], actual['mode'])
                == (row['size'], row['sha256'], row['mode']), 'external input differs: ' + row['path'])
        records.append(actual)
    return records


def natural_owner(wrapper, raw):
    life = json.loads(raw)
    extra = {'receipt_sha256', 'supervisor_returncode'}
    require({key: value for key, value in wrapper.items() if key not in extra} == life,
            'owner wrapper projection differs from the original receipt')
    require(wrapper.get('receipt_sha256') == sha256(raw).hexdigest()
            and wrapper.get('supervisor_returncode') == 0, 'supervisor or receipt identity differs')
    require(life.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
            and life.get('status') == 'OWNED_PROCESS_COMPLETED'
            and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3
            and life.get('returncode') == 0 and life.get('exit_observed_before_deadline') is True
            and life.get('timed_out') is False and not life.get('interrupted_signals')
            and not life.get('event_overflow') and life.get('owner_error') is None,
            'finite development did not complete naturally within the original owner budget')
    cleanup = life['cleanup']
    require(cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True and not cleanup.get('errors')
            and not cleanup.get('remaining') and not cleanup.get('deadline_exceeded'),
            'finite development cleanup is incomplete')
    require([event['kind'] for event in life['events']] == [
        'qualification_started', 'owned_child_observed',
        'qualification_exit_observed', 'owned_child_reaped'], 'owner event sequence differs')
    return life


def physical_files(root):
    """List a private fixture without following links or ignoring extra leaves."""
    root = Path(root)
    require(stat.S_ISDIR(root.lstat().st_mode), 'private fixture root is not a directory')
    files, directories = [], []
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in sorted(directory.iterdir()):
            information = path.lstat()
            name = path.relative_to(root).as_posix()
            if stat.S_ISDIR(information.st_mode):
                directories.append(name)
                pending.append(path)
            else:
                require(stat.S_ISREG(information.st_mode), 'private fixture contains a special leaf')
                files.append(name)
    return sorted(files), sorted(directories)
