"""Bounded, shell-free compiler capture for Hepta's Clang migration frontends.

Stdin/stdout/stderr are file-backed, so even a noisy child cannot force an
unbounded in-memory communicate() buffer. A poller checks output quotas while
Clang is active. POSIX commands own a process group. Windows commands start
behind a gate assigned to a kill-on-close Job Object before compiler launch.
Those descendants are terminated on failure, timeout and parent completion.

This is a process budget, not a sandbox: privileged children, child-created
sessions and filesystem side effects are outside this control mechanism.
"""
from __future__ import annotations

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


def _terminate(proc: subprocess.Popen[bytes], job=None) -> None:
    if job is not None:
        try:
            if job.cleanup(proc):
                return
            reason = "Windows compiler job cleanup remains pending"
        except OSError as error:
            reason = "Windows compiler job cleanup failed: " + str(error)
        job.retain(proc)
        raise CaptureRejected("E_CAPTURE_CLEANUP", reason)
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
    """Run a real tool with wall-time/byte budgets and descendant cleanup.

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
        job = None
        try:
            if os.name == "nt":
                from .windows_capture import launch
                proc, job = launch(argv, cwd=cwd, stdin=input_file,
                                   stdout=output_file, stderr=error_file)
            else:
                proc = subprocess.Popen(
                    argv, cwd=cwd, stdin=input_file, stdout=output_file,
                    stderr=error_file, shell=False,
                    start_new_session=(os.name == "posix"),
                )
        except OSError as exc:
            raise CaptureRejected("E_CAPTURE_EXEC", "Compiler launch failed: " + str(exc)) from exc
        deadline = time.monotonic() + timeout
        failure = None
        try:
            while proc.poll() is None:
                if (os.fstat(output_file.fileno()).st_size > stdout_limit
                        or os.fstat(error_file.fileno()).st_size > stderr_limit):
                    raise CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "Compiler exceeded stdout/stderr byte budget")
                if time.monotonic() >= deadline:
                    raise CaptureRejected("E_CAPTURE_TIMEOUT", "Compiler exceeded wall-time budget")
                time.sleep(min(.01, max(.001, deadline - time.monotonic())))
            # Parent exit does not mean descendants have exited.
            _terminate(proc, job)
            stdout_size = os.fstat(output_file.fileno()).st_size
            stderr_size = os.fstat(error_file.fileno()).st_size
            if stdout_size > stdout_limit or stderr_size > stderr_limit:
                raise CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "Compiler output exceeded byte budget")
            output_file.seek(0)
            error_file.seek(0)
            return CaptureResult(
                proc.returncode, _decode(output_file.read(), "stdout"),
                _decode(error_file.read(), "stderr"),
            )
        except CaptureRejected as error:
            failure = error
            raise
        finally:
            cleanup_failure = None
            try:
                _terminate(proc, job)
            except CaptureRejected as error:
                cleanup_failure = error
                if failure is not None:
                    failure.capture_error = str(error)
            if failure is not None:
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
            if cleanup_failure is not None and failure is None:
                raise cleanup_failure
