"""Verified local hard-link publication for Hepta compiler artifacts.

The invariant is a single ordinary staged file, stable byte-for-byte from the
pre-publication check until the published entry is observed. This does not
promise immunity against later edits or malicious same-user filesystem access.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import stat


class PublicationRejected(ValueError):
    pass


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_exact(path: Path, expected: bytes, *, identity=None):
    try:
        original = path.lstat()
        if not stat.S_ISREG(original.st_mode) or (identity is not None and
                _identity(original) != identity):
            raise PublicationRejected("E_PUBLISH_IDENTITY: ordinary file identity mismatch")
        before = _identity(original)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if _identity(os.fstat(stream.fileno())) != before:
                raise PublicationRejected("E_PUBLISH_RACE: file changed before read")
            data = stream.read(len(expected) + 1)
            if data != expected or _identity(os.fstat(stream.fileno())) != before:
                raise PublicationRejected("E_PUBLISH_BYTES: staged/published content changed")
        if _identity(path.lstat()) != before:
            raise PublicationRejected("E_PUBLISH_RACE: pathname changed during verification")
        return before
    except OSError as exc:
        raise PublicationRejected("E_PUBLISH_IO: file not available for exact read") from exc


def publish_verified(stage: str | Path, destination: str | Path, expected: bytes) -> dict:
    """No-replace link and exact-byte receipt, removing only our link on failure.

    The caller owns the staging file and must provide the bytes it previously
    checked. This module never accepts a digest in place of those bytes.
    """
    stage, destination = Path(stage), Path(destination)
    if type(expected) is not bytes or not expected or stage.absolute() == destination.absolute():
        raise PublicationRejected("E_PUBLISH_INPUT: distinct file and nonempty exact bytes required")
    staged = _read_exact(stage, expected)
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise PublicationRejected("E_PUBLISH_EXISTS: output must be a new file")
    try:
        os.link(stage, destination)
    except OSError as exc:
        raise PublicationRejected("E_PUBLISH_LINK: no-replace link failed") from exc
    try:
        # Hard-link creation legitimately updates the staged inode's ctime.
        # Replay its full byte identity, compare stable inode/type/size/mtime,
        # and require the newly published path to match the post-link state.
        relinked = _read_exact(stage, expected)
        if relinked[:5] != staged[:5]:
            raise PublicationRejected("E_PUBLISH_RACE: staged identity or payload changed")
        _read_exact(destination, expected, identity=relinked)
    except PublicationRejected:
        # Do not remove an unrecognized competing writer's replacement.
        try:
            published = destination.lstat()
            if stat.S_ISREG(published.st_mode) and (published.st_dev, published.st_ino) == staged[:2]:
                destination.unlink()
        except OSError:
            pass
        raise
    return {"sha256": sha256(expected).hexdigest(), "bytes": len(expected)}


def verify_published(stage: str | Path, destination: str | Path, expected: bytes) -> dict:
    """Independently re-read both exact inodes after a source-level gate.

    The stage and destination must still be the *same* ordinary inode with
    the byte-for-byte payload validated before publication. A matching hash
    in a prior receipt is deliberately insufficient. This is point-in-time
    local consistency, not immunity from later noncooperating writers.
    """
    stage, destination = Path(stage), Path(destination)
    if type(expected) is not bytes or not expected or stage.absolute() == destination.absolute():
        raise PublicationRejected("E_PUBLISH_INPUT: exact nonempty bytes and distinct paths required")
    staged = _read_exact(stage, expected)
    _read_exact(destination, expected, identity=staged)
    return {"sha256": sha256(expected).hexdigest(), "bytes": len(expected)}


def withdraw_own_link(stage: str | Path, destination: str | Path) -> bool:
    """Withdraw only the hardlink that still refers to our own staging inode.

    A concurrent writer's *replacement path* must never be removed. A shared
    inode may have changed in place; deleting only our destination pathname
    does not destroy another linked copy or a competitor's separate inode.
    """
    try:
        staged = Path(stage).lstat()
        published = Path(destination).lstat()
        if (stat.S_ISREG(staged.st_mode) and stat.S_ISREG(published.st_mode)
                and (staged.st_dev, staged.st_ino) == (published.st_dev, published.st_ino)):
            Path(destination).unlink()
            return True
    except OSError:
        pass
    return False
