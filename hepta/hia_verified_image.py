"""Bounded, stable file capture before independent final-ELF validation.

This reader admits an ordinary file snapshot, not its ELF semantics. The
independent consumer must still validate these exact bytes, and publication
must recheck the staged and destination files against them.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat


MAX_VERIFIED_IMAGE_BYTES = 8 * 1024 * 1024


class VerifiedImageRejected(ValueError):
    pass


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read_bounded_elf_image(path: str | Path) -> bytes:
    """Capture at most 8 MiB without following a symlink or waiting on a FIFO."""
    path = Path(path)
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")):
        raise VerifiedImageRejected("no-follow nonblocking image descriptors are required")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or not 64 <= before.st_size <= MAX_VERIFIED_IMAGE_BYTES:
                raise VerifiedImageRejected("linked image must be a bounded regular ELF file")
            # Keep descriptor ownership here even if fdopen/read raises.
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(MAX_VERIFIED_IMAGE_BYTES + 1)
            after = os.fstat(descriptor)
            if (len(data) != before.st_size or
                    _identity(before) != _identity(after) or
                    _identity(after) != _identity(path.lstat())):
                raise VerifiedImageRejected("linked image changed during bounded read")
            return data
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise VerifiedImageRejected("linked image is unavailable or not an ordinary file") from exc

# Bind this executing module, including its top-level constants, to retained source.
from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
