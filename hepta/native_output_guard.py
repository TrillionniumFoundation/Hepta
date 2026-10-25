"""Fail-closed bounded reads of native compiler and output artifacts.

The native LLVM backend owns a private temporary output directory, but a
compiler executable can still return a symlink, pipe, empty file or oversized
object. Check the actual file descriptor before decoding/recording bytes.
This is not a filesystem sandbox or a guarantee against hostile same-user
writers replacing already-published paths.
"""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import stat

MAX_NATIVE_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_COMPILER_BINARY_BYTES = 1024 * 1024 * 1024


class NativeOutputRejected(ValueError):
    pass


def _open_regular_bounded(path: str | Path, max_bytes: int):
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_COMPILER_BINARY_BYTES:
        raise NativeOutputRejected("E_NATIVE_OUTPUT_BUDGET: invalid file-size budget")
    file_path = Path(path)
    if file_path.is_symlink() or not file_path.is_file():
        raise NativeOutputRejected("E_NATIVE_OUTPUT_PATH: expected a nonsymlink regular file")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(file_path, flags)
    except OSError as exc:
        raise NativeOutputRejected("E_NATIVE_OUTPUT_PATH: cannot safely open binary") from exc
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= max_bytes):
            raise NativeOutputRejected("E_NATIVE_OUTPUT_SIZE: empty, nonregular or oversized binary")
        return os.fdopen(fd, "rb", closefd=True), metadata.st_size
    except BaseException:
        os.close(fd)
        raise


def read_native_artifact(path: str | Path,
                         max_bytes: int = MAX_NATIVE_ARTIFACT_BYTES) -> bytes:
    """Read one nonempty, regular, bounded artifact through a checked fd."""
    stream, length = _open_regular_bounded(path, max_bytes)
    with stream:
        contents = stream.read(length + 1)
        after = os.fstat(stream.fileno())
        if (len(contents) != length or after.st_size != length
                or not stat.S_ISREG(after.st_mode)):
            raise NativeOutputRejected("E_NATIVE_OUTPUT_RACE: file changed while reading")
    return contents


def digest_regular_binary(path: str | Path,
                          max_bytes: int = MAX_COMPILER_BINARY_BYTES) -> str:
    """Hash a native compiler without materializing its whole image in RAM."""
    stream, length = _open_regular_bounded(path, max_bytes)
    h = sha256()
    consumed = 0
    with stream:
        while consumed < length:
            block = stream.read(min(1024 * 1024, length - consumed))
            if not block:
                raise NativeOutputRejected("E_NATIVE_OUTPUT_RACE: binary truncated during hashing")
            consumed += len(block)
            h.update(block)
        after = os.fstat(stream.fileno())
        if after.st_size != length:
            raise NativeOutputRejected("E_NATIVE_OUTPUT_RACE: binary changed during hashing")
    return h.hexdigest()
