"""Bounded streaming identity for actual native compiler executables.

A native build must not read a potentially enormous compiler image into
memory to calculate its SHA-256. Every native LLVM path uses this one helper.
The digest is a content identity, not cryptographic toolchain attestation:
executable provenance, compiler correctness and binary trust remain external.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import stat

MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


class ToolIdentityRejected(ValueError):
    """A compiler executable could not be identified as a stable regular file."""


def _identity(st: os.stat_result) -> tuple[int, int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def update_stable_regular_hash(hasher, path: str | Path, *,
                               max_bytes: int = MAX_EXECUTABLE_BYTES,
                               allow_empty: bool = False) -> None:
    """Stream stable raw file bytes into an existing digest without following links.

    Shared by real compiler binary identity and the source-byte compiler hash;
    callers may preserve their original byte envelope around the streamed data.
    """
    if type(max_bytes) is not int or max_bytes < 1 or type(allow_empty) is not bool:
        raise ToolIdentityRejected("E_TOOL_IDENTITY: invalid source-size policy")
    path = Path(path)
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode)
                or not (0 if allow_empty else 1) <= before.st_size <= max_bytes):
            raise ToolIdentityRejected("E_TOOL_IDENTITY: expected bounded ordinary file")
        if os.name == "posix" and (not hasattr(os, "O_NOFOLLOW")
                                  or not hasattr(os, "O_NONBLOCK")):
            raise ToolIdentityRejected("E_TOOL_IDENTITY: no-follow nonblocking gate missing")
        flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_BINARY", 0))
        fd = os.open(path, flags)
        try:
            stream = os.fdopen(fd, "rb")
        except Exception:
            os.close(fd)
            raise
        with stream:
            initial = os.fstat(stream.fileno())
            if not stat.S_ISREG(initial.st_mode) or _identity(initial) != _identity(before):
                raise ToolIdentityRejected("E_TOOL_IDENTITY: file replaced before read")
            total = 0
            limit = before.st_size + 1
            while total < limit:
                block = stream.read(min(CHUNK_BYTES, limit - total))
                if not block:
                    break
                total += len(block)
                hasher.update(block)
            after = os.fstat(stream.fileno())
            if total != before.st_size or _identity(after) != _identity(before):
                raise ToolIdentityRejected("E_TOOL_IDENTITY: file mutated during read")
        final = path.lstat()
        if not stat.S_ISREG(final.st_mode) or _identity(final) != _identity(before):
            raise ToolIdentityRejected("E_TOOL_IDENTITY: file path replaced")
    except ToolIdentityRejected:
        raise
    except (OSError, ValueError, OverflowError) as exc:
        raise ToolIdentityRejected("E_TOOL_IDENTITY: unable to hash stable ordinary file") from exc


def digest_executable(path: str | Path) -> str:
    """Stable compiler executable SHA-256 using the shared bounded reader."""
    h = sha256()
    update_stable_regular_hash(h, path, max_bytes=MAX_EXECUTABLE_BYTES,
                               allow_empty=False)
    return h.hexdigest()
