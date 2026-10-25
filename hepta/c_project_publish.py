"""No-follow publication of a staged C migration bundle, POSIX dirfd profile.

All file links are relative to stable, open source and destination directories.
An independent actor can still rename the directory after final checks; this
is not a malicious-filesystem or power-loss-atomicity guarantee.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat


class PublicationRejected(ValueError):
    code = "E_C_PROJECT_PUBLISH"


def _reject(reason: str) -> None:
    raise PublicationRejected(reason)


def _same_file(first, second) -> bool:
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def publish_no_replace(stage: Path, destination: Path) -> None:
    """Publish only into the new directory object; never follow its leaf.

    Files must already be fully staged and verified by the caller. The manifest
    is linked last, not atomically with its siblings. POSIX dirfd availability
    is mandatory rather than silently falling back to path-based publication.
    """
    if not (os.open in os.supports_dir_fd and os.link in os.supports_dir_fd and
            os.stat in os.supports_dir_fd and os.unlink in os.supports_dir_fd and
            os.rmdir in os.supports_dir_fd and os.listdir in os.supports_fd):
        _reject("Required POSIX directory-fd publication primitives unavailable")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        _reject("O_NOFOLLOW/O_DIRECTORY required")
    stage, destination = Path(stage).absolute(), Path(destination).absolute()
    if destination.is_symlink() or destination.exists():
        _reject("Output directory must not exist")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(destination.parent, directory_flags)
    source_fd = None
    destination_fd = None
    created = False
    published = []
    try:
        source_fd = os.open(stage, directory_flags)
        names = os.listdir(source_fd)
        required = {"source.hepta", "bridge.rs", "generated.rs", "migration.json"}
        if not required.issubset(names):
            _reject("Stage missing mandatory migration outputs")
        for name in names:
            if not stat.S_ISREG(os.stat(name, dir_fd=source_fd, follow_symlinks=False).st_mode):
                _reject("Stage contains nonregular artifact")
        os.mkdir(destination.name, dir_fd=root_fd)
        created = True
        destination_fd = os.open(destination.name, directory_flags, dir_fd=root_fd)
        identity = os.fstat(destination_fd)
        for name in sorted(names, key=lambda name: name == "migration.json"):
            # Both directories are anchored; a changed destination path cannot
            # silently turn into an external symlink target.
            os.link(name, name, src_dir_fd=source_fd,
                    dst_dir_fd=destination_fd, follow_symlinks=False)
            published.append(name)
        os.fsync(destination_fd)
        current = os.stat(destination.name, dir_fd=root_fd, follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode) or not _same_file(current, identity):
            _reject("Destination path changed during publication")
        os.fsync(root_fd)
    except BaseException:
        if destination_fd is not None and source_fd is not None:
            for name in reversed(published):
                try:
                    source_stat = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
                    dest_stat = os.stat(name, dir_fd=destination_fd, follow_symlinks=False)
                    if stat.S_ISREG(dest_stat.st_mode) and _same_file(source_stat, dest_stat):
                        os.unlink(name, dir_fd=destination_fd)
                except OSError:
                    pass
        if created and destination_fd is not None:
            try:
                same = _same_file(os.stat(destination.name, dir_fd=root_fd,
                                          follow_symlinks=False), os.fstat(destination_fd))
                if same:
                    os.rmdir(destination.name, dir_fd=root_fd)
            except OSError:
                pass
        raise
    finally:
        for fd in (destination_fd, source_fd, root_fd):
            if fd is not None:
                os.close(fd)
