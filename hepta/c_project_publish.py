"""Atomic, no-replace C migration bundle publication on qualified Linux hosts.

The migration pipeline already stages files in a private temporary directory
under the output parent. The old hardlink-by-file publisher exposed partially
populated directories. This publisher validates the *whole* staged directory,
fsyncs its contents, then atomically renames the directory using Linux
renameat2(RENAME_NOREPLACE) relative to a no-follow opened parent FD.

Publication has one visibility instant for cooperating readers. It is NOT a
security boundary against an attacker with write access to the stage or parent
and it does not prove the migrated program correct or crash recovery on every
filesystem. Existing destination paths, including dangling symlinks, reject.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import stat
import sys


class PublicationRejected(ValueError):
    code = "E_C_PROJECT_PUBLISH"


class PublicationRecoveryRequired(OSError):
    """Commit may be visible; caller must inspect destination before retry."""
    code = "E_C_PROJECT_RECOVERY_REQUIRED"
    publication_may_have_committed = True


_REQUIRED = frozenset({"source.hepta", "bridge.rs", "generated.rs", "migration.json"})
_NO_REPLACE = 1


def _reject(reason: str) -> None:
    raise PublicationRejected("E_C_PROJECT_PUBLISH: " + reason)


def _same_inode(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _rename_noreplace(parent_fd: int, source: str, target: str) -> None:
    # Linux syscall availability is a precondition. No fallback to ordinary
    # rename (which may silently replace a planted empty output directory).
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
    except (OSError, AttributeError):
        _reject("atomic no-replace renameat2 unavailable")
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    src = os.fsencode(source)
    dst = os.fsencode(target)
    if rename(parent_fd, src, parent_fd, dst, _NO_REPLACE) != 0:
        err = ctypes.get_errno()
        if err in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.ENOTSUP):
            _reject("atomic no-replace rename unsupported by host filesystem")
        if err in (errno.EEXIST, errno.ENOTEMPTY):
            _reject("destination already exists")
        raise OSError(err, os.strerror(err), target)


def publish_no_replace(stage: Path, destination: Path) -> None:
    """Publish a fully staged bundle atomically without following leaf links.

    Stage and destination MUST be siblings on the same filesystem. The caller
    must separately validate source/project/compiler identities. No operation
    on a partial/unverified stage may produce a visible destination directory.
    """
    if sys.platform != "linux":
        _reject("this atomic publisher requires Linux renameat2")
    if not (hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and
            os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd and
            os.listdir in os.supports_fd):
        _reject("no-follow directory FD support unavailable")
    stage = Path(os.path.abspath(os.fspath(stage)))
    destination = Path(os.path.abspath(os.fspath(destination)))
    if (stage.parent != destination.parent or stage.name == destination.name or
            stage.name in ("", ".", "..") or destination.name in ("", ".", "..")):
        _reject("stage and destination must be distinct direct siblings")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    parent_fd = os.open(destination.parent, flags)
    stage_fd = None
    published = False
    try:
        stage_fd = os.open(stage.name, flags, dir_fd=parent_fd)
        original = os.fstat(stage_fd)
        if not stat.S_ISDIR(original.st_mode):
            _reject("stage is not an ordinary directory")
        names = os.listdir(stage_fd)
        if not _REQUIRED.issubset(names):
            _reject("mandatory migration outputs are missing")
        if len(names) > 4096:
            _reject("too many staged artifacts")
        for name in names:
            if name in ("", ".", "..") or "/" in name or "\x00" in name:
                _reject("invalid stage entry")
            # O_NOFOLLOW also ensures a race cannot turn a reviewed regular
            # artifact into an external symlink between stat and open.
            try:
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                                getattr(os, "O_CLOEXEC", 0), dir_fd=stage_fd)
            except OSError as exc:
                raise PublicationRejected("E_C_PROJECT_PUBLISH: staged artifact is not an accessible regular file") from exc
            try:
                if not stat.S_ISREG(os.fstat(child).st_mode):
                    _reject("stage contains nonregular artifact")
                os.fsync(child)
            finally:
                os.close(child)
        os.fsync(stage_fd)
        live_stage = os.stat(stage.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(live_stage.st_mode) or not _same_inode(original, live_stage):
            _reject("stage path changed during preparation")
        # A changed destination, including dangling symlink or empty planted
        # directory, cannot be overwritten by RENAME_NOREPLACE.
        _rename_noreplace(parent_fd, stage.name, destination.name)
        published = True
        live_destination = os.stat(destination.name, dir_fd=parent_fd,
                                   follow_symlinks=False)
        if not stat.S_ISDIR(live_destination.st_mode) or not _same_inode(original, live_destination):
            # This can only arise from a non-cooperating writer after publish;
            # never perform unsafe cleanup of a path whose ownership is lost.
            _reject("published destination identity changed; manual recovery required")
        os.fsync(parent_fd)
    except (OSError, PublicationRejected) as exc:
        if published:
            raise PublicationRecoveryRequired(
                "E_C_PROJECT_RECOVERY_REQUIRED: directory rename may have committed; "
                "inspect and recover destination before retrying") from exc
        raise
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        os.close(parent_fd)
