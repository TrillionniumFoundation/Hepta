"""Linux-only crash-durable, no-replace HIA L1 bundle directory publication.

The migrator must fully validate staged Hepta, native code and manifest first.
This is the filesystem publication boundary, not a safety proof for C/C++.
No fallback to piecemeal hardlinks or rename-over-existing is authorized.
"""
from __future__ import annotations

import ctypes
import errno
from hashlib import sha256
import os
from pathlib import Path
import stat
import sys
from typing import Callable


class AtomicBundleRejected(ValueError):
    """No destination was knowingly published (precommit failure)."""


class AtomicBundleUncertain(AtomicBundleRejected):
    """The atomic rename occurred: the directory MUST NOT be auto-deleted."""


def _reject(reason: str) -> None:
    raise AtomicBundleRejected("E_HIA_BUNDLE: " + reason)


def _rename_noreplace(parent_fd: int, old: str, new: str) -> None:
    """Linux renameat2(RENAME_NOREPLACE); fail closed on unavailable hosts."""
    if sys.platform != "linux":
        _reject("atomic no-replace directory rename is Linux-only")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise AtomicBundleRejected("E_HIA_BUNDLE: renameat2 unavailable") from exc
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    rc = rename(parent_fd, os.fsencode(old), parent_fd, os.fsencode(new), 1)
    if rc != 0:
        err = ctypes.get_errno()
        if err in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            _reject("filesystem lacks atomic no-replace rename")
        if err == errno.EEXIST:
            _reject("destination exists; refusing to replace")
        raise OSError(err, os.strerror(err))


def _check_regular(directory_fd: int, name: str, expected: bytes) -> None:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_size != len(expected):
            _reject("staged file is not an exact regular file: " + name)
        # O_NONBLOCK prevents a concurrent regular-file -> FIFO swap from
        # blocking the verification process between lstat and fstat. It is a
        # no-op for legitimate regular files and is mandatory for this gate.
        handle = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=directory_fd)
        try:
            opened = os.fstat(handle)
            identity = lambda st: (st.st_dev, st.st_ino, st.st_size,
                                   st.st_mtime_ns, st.st_ctime_ns)
            if (not stat.S_ISREG(opened.st_mode)
                    or identity(opened) != identity(before)):
                _reject("staged file changed while opening: " + name)
            # A changing/appending file must not hold the verifier in an
            # unbounded read loop. Read at most expected-length + 1 bytes to
            # detect growth; no new file data is trusted after that point.
            limit = len(expected) + 1
            read_bytes = 0
            digest = sha256()
            while read_bytes < limit:
                chunk = os.read(handle, min(1024 * 1024, limit - read_bytes))
                if not chunk:
                    break
                read_bytes += len(chunk)
                digest.update(chunk)
            if (read_bytes != len(expected)
                    or digest.digest() != sha256(expected).digest()):
                _reject("staged size/bytes do not match checked artifact: " + name)
            os.fsync(handle)
            after = os.fstat(handle)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            # Comparing only the fd to its *current* pathname misses an
            # in-place same-inode write after the digest but before fsync.
            # Require both snapshots still equal the pre-read identity.
            if (not stat.S_ISREG(named.st_mode)
                    or identity(after) != identity(opened)
                    or identity(named) != identity(opened)):
                _reject("staged file changed after byte verification: " + name)
        finally:
            os.close(handle)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError) as exc:
        raise AtomicBundleRejected("E_HIA_BUNDLE: missing or invalid staged file") from exc


def publish_hia_bundle(stage: Path, destination: Path,
                       expected: dict[str, bytes],
                       source_guard: Callable[[], bool]) -> dict:
    """Publish complete staged directory atomically without replacing names.

    Before the linearization point, fail without creating the destination.
    After renameat2 succeeds, any exception means recovery/inspection required;
    do not try to unlink an already visible immutable bundle. Same-user hostile
    filesystem writers and underlying storage hardware faults are out of scope.
    """
    if (not isinstance(stage, Path) or not isinstance(destination, Path)
            or type(expected) is not dict
            or set(expected) not in ({"candidate.hepta", "candidate.so", "migration-hia.json"},
                                     {"candidate.hepta", "candidate.o", "migration-hia.json"})
            or any(type(data) is not bytes or not data for data in expected.values())
            or not callable(source_guard)):
        _reject("exact three-file bundle and source replay callback required")
    if (stage.name in ("", ".", "..") or destination.name in ("", ".", "..")
            or stage.parent != destination.parent or stage == destination):
        _reject("staged and final directories must be distinct siblings")
    if (sys.platform != "linux" or
            any(not hasattr(os, flag) for flag in
                ("O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW"))):
        _reject("Linux host and no-follow directory descriptors required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    committed = False
    parent_fd = -1
    stage_fd = -1
    try:
        parent_fd = os.open(stage.parent, flags)
        stage_fd = os.open(stage, flags)
        stage_stat = os.fstat(stage_fd)
        named_stage = os.stat(stage.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(named_stage.st_mode)
                or (stage_stat.st_dev, stage_stat.st_ino) !=
                   (named_stage.st_dev, named_stage.st_ino)):
            _reject("staged path identity differs from parent directory")
        if stage_stat.st_dev != os.fstat(parent_fd).st_dev:
            _reject("staging and destination must reside on one filesystem")
        if set(os.listdir(stage_fd)) != set(expected):
            _reject("staged directory contains missing or unreviewed entries")
        for name in sorted(expected):
            _check_regular(stage_fd, name, expected[name])
        os.fsync(stage_fd)
        if source_guard() is not True:
            _reject("source changed before atomic publication")
        current_stage = os.stat(stage.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(current_stage.st_mode)
                or (current_stage.st_dev, current_stage.st_ino) !=
                   (stage_stat.st_dev, stage_stat.st_ino)):
            _reject("staged directory was rebound before atomic rename")
        _rename_noreplace(parent_fd, stage.name, destination.name)
        committed = True
        # The rename is atomic now; persistence additionally requires the
        # containing parent directory to be fsynced successfully.
        os.fsync(parent_fd)
        final_fd = os.open(destination.name, flags, dir_fd=parent_fd)
        try:
            if (os.fstat(final_fd).st_dev, os.fstat(final_fd).st_ino) != (
                    os.fstat(stage_fd).st_dev, os.fstat(stage_fd).st_ino):
                raise AtomicBundleUncertain("E_HIA_BUNDLE: final directory identity changed")
            for name in sorted(expected):
                _check_regular(final_fd, name, expected[name])
        finally:
            os.close(final_fd)
        if source_guard() is not True:
            raise AtomicBundleUncertain("E_HIA_BUNDLE: source changed after atomic publication")
        return {"method": "linux_renameat2_noreplace_fsync_v1",
                "files": sorted(expected), "atomic_directory_visible": True,
                "parent_directory_fsynced": True}
    except Exception as exc:
        if committed:
            raise AtomicBundleUncertain(
                "E_HIA_BUNDLE: directory may be published; inspect/recover, do not delete"
            ) from exc
        raise
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
