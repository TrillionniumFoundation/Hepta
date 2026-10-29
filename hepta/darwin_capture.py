"""Live Darwin process-group owner and a bounded private exit-status channel.

The guardian is the direct child/session leader. It waits for the compiler,
reports that compiler's status, closes the private writer, and remains alive
until the capture owner terminates its group. This avoids relying on Darwin
accepting a signal to a group containing only an unreaped zombie.

Only the guardian is reaped by the capture parent. Compiler descendants that
create new sessions, privilege changes and filesystem effects remain outside
this process-budget mechanism. This module is also executable with Python -I;
the child-side path uses only the standard library, not an importable package.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys


_MAGIC = b"HDG1"
_EXIT = 1
_EXEC_ERROR = 2
_INTERNAL_ERROR = 3
_FRAME = struct.Struct("!4sBBHii")
_GUARDIAN_SCRIPT = Path(__file__).resolve()


class GuardianOwner:
    """Own only the parent's private pipe reader and the compiler's status."""

    def __init__(self, status_fd: int) -> None:
        self._status_fd = status_fd
        self._buffer = bytearray()
        self._complete = False
        self.returncode: int | None = None
        self.startup_error: BaseException | None = None

    def raise_startup_error(self) -> None:
        from .clang_capture import CaptureRejected

        if self.startup_error is not None:
            if isinstance(self.startup_error, OSError):
                raise CaptureRejected("E_CAPTURE_GUARDIAN",
                                      f"Darwin parent status writer close failed: {self.startup_error}") from self.startup_error
            # Keep interruption identity and semantics, but propagate only
            # after the caller owns this guardian inside its cleanup finally.
            raise self.startup_error

    def poll_status(self) -> bool:
        from .clang_capture import CaptureRejected

        self.raise_startup_error()
        if self._complete:
            return True
        try:
            while True:
                chunk = os.read(self._status_fd, _FRAME.size + 1 - len(self._buffer))
                if not chunk:
                    break
                self._buffer.extend(chunk)
                if len(self._buffer) > _FRAME.size:
                    raise CaptureRejected("E_CAPTURE_GUARDIAN", "Darwin guardian status exceeds its fixed frame")
        except BlockingIOError:
            return False
        except OSError as error:
            raise CaptureRejected("E_CAPTURE_GUARDIAN", f"Darwin status read failed: {error}") from error
        # EOF is required. A writer cannot append another frame after success.
        if len(self._buffer) != _FRAME.size:
            raise CaptureRejected("E_CAPTURE_GUARDIAN", "Darwin guardian status frame is incomplete")
        magic, kind, flags, reserved, status, error_number = _FRAME.unpack(self._buffer)
        if magic != _MAGIC or flags or reserved:
            raise CaptureRejected("E_CAPTURE_GUARDIAN", "Darwin guardian status frame is invalid")
        if kind == _EXIT and error_number == 0 and -signal.NSIG < status <= 255:
            self.returncode = status
            self._complete = True
            return True
        if kind in {_EXEC_ERROR, _INTERNAL_ERROR} and status == 0 and 0 < error_number < 65536:
            cause = OSError(error_number, os.strerror(error_number))
            code = "E_CAPTURE_EXEC" if kind == _EXEC_ERROR else "E_CAPTURE_GUARDIAN"
            phase = "Compiler launch" if kind == _EXEC_ERROR else "Guardian completion"
            raise CaptureRejected(code, f"{phase} failed in Darwin guardian: {cause}") from cause
        raise CaptureRejected("E_CAPTURE_GUARDIAN", "Darwin guardian status values are invalid")

    def close(self) -> None:
        # Revoke numeric descriptor ownership before close; never retry an
        # ambiguous close failure against a potentially reused descriptor.
        descriptor, self._status_fd = self._status_fd, -1
        if descriptor >= 0:
            os.close(descriptor)


def launch(argv, *, cwd, stdin, stdout, stderr):
    status_read, status_write = os.pipe()
    try:
        os.set_blocking(status_read, False)
        owner = GuardianOwner(status_read)
        proc = subprocess.Popen(
            [sys.executable, "-I", str(_GUARDIAN_SCRIPT), str(status_write), *argv],
            cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr, shell=False,
            close_fds=True, pass_fds=(status_write,), start_new_session=True,
        )
    except BaseException as error:
        for descriptor in (status_read, status_write):
            try:
                os.close(descriptor)
            except OSError as close_error:
                error.add_note(f"Private status descriptor close failed: {close_error}")
        raise
    # Popen succeeded: ownership must reach run_bounded even if closing this
    # parent-side writer fails after an effect. Do not throw away the child.
    try:
        os.close(status_write)
    except BaseException as error:
        owner.startup_error = error
    return proc, owner


def _guardian_main() -> None:
    descriptor = int(sys.argv[1])
    command = sys.argv[2:]
    os.set_inheritable(descriptor, False)
    kind, status, error_number = _INTERNAL_ERROR, 0, errno.EIO
    compiler = None
    try:
        # 0/1/2 are the existing capture files. The compiler does not inherit
        # the private status FD or acquire a different session/process group.
        compiler = subprocess.Popen(command, close_fds=True, shell=False)
    except OSError as error:
        kind, status, error_number = _EXEC_ERROR, 0, error.errno or errno.EIO
    except BaseException:
        kind, status, error_number = _INTERNAL_ERROR, 0, errno.EIO
    # Streaming consumers must be able to see compiler EOF while this owner
    # and even the compiler itself still run. The spawned compiler already has
    # independent 0/1/2 descriptors; immediately drop only the guardian's copies
    # before waiting. The private status descriptor survives. Failed launch
    # still closes every standard descriptor; a failed close refuses capture.
    standard_close_failed = False
    for standard_descriptor in (0, 1, 2):
        try:
            os.close(standard_descriptor)
        except BaseException as error:
            standard_close_failed = True
            kind, status = _INTERNAL_ERROR, 0
            error_number = (error.errno or errno.EIO) if isinstance(error, OSError) else errno.EIO
    if compiler is not None:
        try:
            compiler_status = compiler.wait()
        except BaseException:
            # Do not turn an unknown child status into a successful exit code.
            kind, status, error_number = _INTERNAL_ERROR, 0, errno.EIO
        else:
            if not standard_close_failed:
                kind, status, error_number = _EXIT, compiler_status, 0
    try:
        os.write(descriptor, _FRAME.pack(_MAGIC, kind, 0, 0, status, error_number))
    except OSError:
        pass
    finally:
        os.close(descriptor)
    # There is deliberately no successful/normal return after a status frame.
    # The parent must signal this still-owned, living group leader exactly once.
    while True:
        signal.pause()


if __name__ == "__main__":
    _guardian_main()
