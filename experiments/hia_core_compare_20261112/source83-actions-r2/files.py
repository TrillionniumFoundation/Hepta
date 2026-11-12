"""Descriptor-based fixed-file custody helpers for the source83 adapter.

This module imports no project code. Parent directories are opened without
following links and retained through each operation; only private new files
are created. These are observations at each operation, not future immutability.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid,
            row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)


def directory_identity(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid)


def absolute(path):
    path = Path(path).absolute()
    require(path.is_absolute() and all(part not in (".", "..") for part in path.parts),
            "absolute non-traversing path required")
    return path


@contextmanager
def parent(path, create=False):
    path = absolute(path)
    require(path.name not in ("", ".", ".."), "file leaf required")
    descriptors = []
    links = []
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(root)
        current = root
        for part in path.parts[1:-1]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=current)
            except FileNotFoundError:
                require(create, "fixed parent directory is missing")
                os.mkdir(part, 0o700, dir_fd=current)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=current)
            descriptors.append(child)
            held = os.fstat(child)
            named = os.stat(part, dir_fd=current, follow_symlinks=False)
            require(stat.S_ISDIR(held.st_mode)
                    and directory_identity(held) == directory_identity(named),
                    "parent directory binding differs")
            links.append((current, part, child, directory_identity(held)))
            current = child
        yield current, path.name
        for previous, name, child, expected in links:
            require(directory_identity(os.fstat(child)) == expected
                    and directory_identity(os.stat(name, dir_fd=previous,
                                                   follow_symlinks=False)) == expected,
                    "parent directory changed during operation")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def metadata(path, raw, row):
    return {"path": str(absolute(path)), "size": len(raw),
            "sha256": sha256(raw).hexdigest(),
            "git_blob_sha1": sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
            "mode": stat.S_IMODE(row.st_mode), "uid": row.st_uid, "gid": row.st_gid,
            "nlink": row.st_nlink, "device": row.st_dev, "inode": row.st_ino,
            "mtime_ns": row.st_mtime_ns, "ctime_ns": row.st_ctime_ns}


def read(path, expected=None, owned=False):
    path = absolute(path)
    with parent(path) as (directory, name):
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_mode & 0o022 == 0, "regular unaliased nonwritable input required: " + str(path))
        if owned:
            require(before.st_uid == os.geteuid(), "private input owner differs: " + str(path))
        if expected is not None and "size" in expected:
            require(type(expected["size"]) is int and before.st_size == expected["size"],
                    "input size differs before reading: " + str(path))
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            require(identity(os.fstat(descriptor)) == identity(before), "opened input differs")
            blocks = []
            remaining = before.st_size
            while remaining:
                block = os.read(descriptor, min(65536, remaining))
                require(block, "input ended before its fixed size")
                blocks.append(block)
                remaining -= len(block)
            require(os.read(descriptor, 1) == b"", "input grew while read")
            raw = b"".join(blocks)
            require(identity(os.fstat(descriptor)) == identity(before)
                    and identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity(before),
                    "input changed while read")
        finally:
            os.close(descriptor)
        observed = metadata(path, raw, before)
        if expected is not None:
            for key, value in expected.items():
                if key in observed:
                    require(observed[key] == value, "input field differs: " + key + ": " + str(path))
        return raw, observed


def put(path, raw, mode=0o600):
    require(type(raw) is bytes and mode & 0o022 == 0, "new fixed bytes/mode required")
    path = absolute(path)
    with parent(path, create=True) as (directory, name):
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             mode, dir_fd=directory)
        try:
            os.fchmod(descriptor, mode)
            view = memoryview(raw)
            offset = 0
            while offset < len(view):
                count = os.write(descriptor, view[offset:])
                require(count > 0, "new file write made no progress")
                offset += count
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            blocks = []
            remaining = len(raw)
            while remaining:
                block = os.read(descriptor, min(65536, remaining))
                require(block, "new file readback ended early")
                blocks.append(block)
                remaining -= len(block)
            require(b"".join(blocks) == raw and os.read(descriptor, 1) == b"",
                    "new file readback differs")
            observed = os.fstat(descriptor)
            require(stat.S_ISREG(observed.st_mode) and observed.st_uid == os.geteuid()
                    and observed.st_nlink == 1 and stat.S_IMODE(observed.st_mode) == mode
                    and observed.st_size == len(raw)
                    and identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity(observed),
                    "new file identity differs")
            result = metadata(path, raw, observed)
        finally:
            os.close(descriptor)
        return result


def mkdir_new(path):
    path = absolute(path)
    with parent(path) as (directory, name):
        os.mkdir(name, 0o700, dir_fd=directory)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            held = os.fstat(descriptor)
            require(stat.S_ISDIR(held.st_mode) and held.st_uid == os.geteuid()
                    and stat.S_IMODE(held.st_mode) == 0o700
                    and directory_identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
                    == directory_identity(held), "fresh directory binding differs")
        finally:
            os.close(descriptor)


def save(path, value):
    return put(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def json_read(path, expected=None, owned=False):
    raw, pin = read(path, expected, owned=owned)
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate JSON key refused")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs), raw, pin
