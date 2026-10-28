"""Bounded, shell-free compiler capture for Hepta's Clang migration frontends.

Stdin/stdout/stderr are file-backed, so even a noisy child cannot force an
unbounded in-memory communicate() buffer. A poller checks output quotas while
Clang is active; on POSIX each command is in a new process group so escaped
compiler descendants are killed on failure, timeout and parent completion.

This is a process budget, not a sandbox: privileged children, child-created
sessions and filesystem side effects are outside this control mechanism.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import math
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time


class CaptureRejected(ValueError):
    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.capture: CaptureFailure | None = None
        self.capture_error: str | None = None
        super().__init__(reason)


@dataclass(frozen=True)
class CaptureResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class CaptureFailure:
    """Bounded raw evidence retained after the existing process cleanup.

    Prefix lengths never exceed the caller's original stream limits. Total
    lengths describe the file snapshots and can exceed those retained limits.
    The capture error code remains separate from the actual child exit code.
    """
    command: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    stdout_total_bytes: int
    stderr_total_bytes: int


@dataclass
class CaptureDeadline:
    """One synchronous, context-local deadline; elapsed time is not preemption."""

    seconds: int | float | None
    expires_at: float | None
    expired: bool = False


_DEADLINES: ContextVar[tuple[CaptureDeadline, ...]] = ContextVar(
    "hepta_capture_deadlines", default=())


def _refresh_deadlines() -> bool:
    deadlines = _DEADLINES.get()
    if not deadlines:
        return False
    now = time.monotonic()
    for deadline in deadlines:
        if deadline.expires_at is not None and now >= deadline.expires_at:
            deadline.expired = True
    return any(deadline.expired for deadline in deadlines)


def check_capture_deadline() -> None:
    """Check at a tool poll or explicit phase boundary, never asynchronously."""
    if _refresh_deadlines():
        raise CaptureRejected("E_CAPTURE_TOTAL_DEADLINE", "Cooperative capture deadline expired")


@contextmanager
def scoped_capture_deadline(seconds: int | float | None):
    """Apply a deadline to tools in this execution context and restore on exit.

    None adds no limit; an enclosing deadline still applies. Nested scopes
    cannot extend their parent's budget. No signal handler or timer interrupts
    Python, process creation, or cleanup. A scope exit records expiry even when
    no tool poll or phase check ran, so callers can reject a late result.
    """
    if seconds is not None and (type(seconds) not in (int, float)
            or not math.isfinite(seconds) or not 0 < seconds <= 3600):
        raise ValueError("capture deadline must be None or finite seconds in (0,3600]")
    deadline = CaptureDeadline(seconds, None if seconds is None else time.monotonic() + seconds)
    token = _DEADLINES.set((*_DEADLINES.get(), deadline))
    try:
        yield deadline
    finally:
        _refresh_deadlines()
        _DEADLINES.reset(token)


def _terminate(proc: subprocess.Popen[bytes]) -> None:
    # start_new_session=True gives this child its own group on POSIX.
    # The parent may have exited while one of its descendants is still alive.
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass


def _decode(data: bytes, stream: str) -> str:
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CaptureRejected("E_CAPTURE_ENCODING", f"Compiler {stream} was not UTF-8") from exc
    # Match subprocess text=True universal-newline behavior.
    return value.replace("\r\n", "\n").replace("\r", "\n")


def run_bounded(
    argv: list[str], *, cwd: str | Path | None = None,
    input_text: str | None = None, timeout: float = 30,
    stdout_limit: int = 32_000_000, stderr_limit: int = 1_000_000,
    stdin_limit: int = 1_000_000,
) -> CaptureResult:
    """Run a real tool with wall-time/byte budgets and POSIX descendant cleanup.

    Limits and tool invocation are caller-owned. No shell, environment rewrite,
    network access control, or runtime filesystem containment is implied.
    """
    if (not isinstance(argv, list) or not argv
            or any(not isinstance(a, str) or not a or "\0" in a for a in argv)):
        raise CaptureRejected("E_CAPTURE_ARGV", "Expected a nonempty executable argv")
    # Reject NaN/Infinity, booleans, wrong types and impractically long
    # wall-time budgets before launching a compiler. NaN used to bypass the
    # deadline comparison and could leave a live process running indefinitely.
    if (type(timeout) not in (int, float) or not (0 < timeout <= 3600)
            or not math.isfinite(timeout)
            or any(type(limit) is not int or limit < 0 for limit in
                   (stdout_limit, stderr_limit, stdin_limit))):
        raise CaptureRejected("E_CAPTURE_BUDGET",
                              "Capture limits must be nonnegative integer bytes and finite time in (0,3600]s")
    try:
        payload = b"" if input_text is None else input_text.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise CaptureRejected("E_CAPTURE_INPUT", "Compiler stdin must be UTF-8 text") from exc
    if len(payload) > stdin_limit:
        raise CaptureRejected("E_CAPTURE_INPUT_SIZE", "Compiler stdin exceeds byte budget")

    with (tempfile.TemporaryFile() as input_file,
          tempfile.TemporaryFile() as output_file,
          tempfile.TemporaryFile() as error_file):
        input_file.write(payload)
        input_file.seek(0)
        proc = None
        failure = None
        try:
            check_capture_deadline()
            try:
                proc = subprocess.Popen(
                    argv, cwd=cwd, stdin=input_file, stdout=output_file,
                    stderr=error_file, shell=False,
                    start_new_session=(os.name == "posix"),
                )
            except OSError as exc:
                raise CaptureRejected("E_CAPTURE_EXEC", "Compiler launch failed: " + str(exc)) from exc
            deadline = time.monotonic() + timeout
            while proc.poll() is None:
                check_capture_deadline()
                if (os.fstat(output_file.fileno()).st_size > stdout_limit
                        or os.fstat(error_file.fileno()).st_size > stderr_limit):
                    raise CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "Compiler exceeded stdout/stderr byte budget")
                if time.monotonic() >= deadline:
                    raise CaptureRejected("E_CAPTURE_TIMEOUT", "Compiler exceeded wall-time budget")
                time.sleep(min(.01, max(.001, deadline - time.monotonic())))
            check_capture_deadline()
            # Parent exit does not mean descendants have exited: kill its group.
            _terminate(proc)
            stdout_size = os.fstat(output_file.fileno()).st_size
            stderr_size = os.fstat(error_file.fileno()).st_size
            if stdout_size > stdout_limit or stderr_size > stderr_limit:
                raise CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "Compiler output exceeded byte budget")
            output_file.seek(0)
            error_file.seek(0)
            result = CaptureResult(
                proc.returncode, _decode(output_file.read(), "stdout"),
                _decode(error_file.read(), "stderr"),
            )
            check_capture_deadline()
            return result
        except CaptureRejected as error:
            failure = error
            raise
        finally:
            if proc is not None:
                _terminate(proc)
            if failure is not None and proc is not None:
                try:
                    stdout_size = os.fstat(output_file.fileno()).st_size
                    stderr_size = os.fstat(error_file.fileno()).st_size
                    output_file.seek(0)
                    error_file.seek(0)
                    failure.capture = CaptureFailure(
                        tuple(argv), proc.returncode,
                        output_file.read(stdout_limit), error_file.read(stderr_limit),
                        stdout_size, stderr_size,
                    )
                except OSError as error:
                    # Preserve the original rejection/code even when the
                    # capture files themselves cannot be read.
                    failure.capture_error = str(error)
