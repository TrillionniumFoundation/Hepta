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


def digest_executable(path: str | Path) -> str:
    """Hash a regular compiler file in bounded RAM, verifying its file identity.

    The same stable inode and metadata must be observed before and after
    reading, both through the opened descriptor and the named path. A compiler
    replacement, truncated executable, symlink redirection or special-file
    path fails closed. Calling this before AND after native compilation helps
    detect a changed compiler without reading the entire binary into memory.
    """
    path = Path(path)
    try:
        # Callers already resolve the selected compiler executable before
        # calling. Here lstat explicitly rejects a later path re-binding.
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or
                not 0 < before.st_size <= MAX_EXECUTABLE_BYTES):
            raise ToolIdentityRejected("E_TOOL_IDENTITY: compiler must be a bounded regular file")
        digest = sha256()
        # Never do a blocking Path.open after a regular-file lstat: a path
        # rebinding to a FIFO can hang before fstat gets to reject it.
        # O_BINARY preserves raw image bytes on Windows; other flags are
        # available on qualified POSIX/Linux native hosts.
        flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_BINARY", 0))
        if os.name == "posix" and not hasattr(os, "O_NONBLOCK"):
            raise ToolIdentityRejected("E_TOOL_IDENTITY: nonblocking regular-file gate unavailable")
        fd = os.open(path, flags)
        try:
            stream = os.fdopen(fd, "rb")
        except Exception:
            os.close(fd)
            raise
        with stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
                raise ToolIdentityRejected("E_TOOL_IDENTITY: compiler file changed before hashing")
            total = 0
            limit = before.st_size + 1
            while total < limit:
                block = stream.read(min(CHUNK_BYTES, limit - total))
                if not block:
                    break
                total += len(block)
                digest.update(block)
            after_fd = os.fstat(stream.fileno())
            if total != before.st_size or _identity(after_fd) != _identity(before):
                raise ToolIdentityRejected("E_TOOL_IDENTITY: compiler file changed while hashing")
        after_path = path.lstat()
        if not stat.S_ISREG(after_path.st_mode) or _identity(after_path) != _identity(before):
            raise ToolIdentityRejected("E_TOOL_IDENTITY: compiler path changed while hashing")
        return digest.hexdigest()
    except ToolIdentityRejected:
        raise
    except (OSError, ValueError, OverflowError) as exc:
        raise ToolIdentityRejected("E_TOOL_IDENTITY: unable to verify compiler regular-file identity") from exc
