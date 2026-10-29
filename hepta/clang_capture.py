"""Bounded, shell-free compiler capture for Hepta's Clang migration frontends.

Stdin/stdout/stderr are file-backed, so even a noisy child cannot force an
unbounded in-memory communicate() buffer. A poller checks output quotas while
Clang is active. POSIX commands retain an unreaped leader until their one group
termination attempt, then require a confirmed leader reap. Windows commands
start behind a gate assigned to a kill-on-close Job Object before launch.
Final stream reads have independent bounds: a group signal does not establish
that every descendant has already stopped or that this parent can reap it.

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
    # Optional raw streams preserve CRLF and exact bytes for evidence writers.
    # Text consumers retain their original normalized UTF-8 interface. These
    # byte fields are never automatically inserted into public JSON reports.
    raw_stdout: bytes | None = None
    raw_stderr: bytes | None = None


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


def _require_posix_ownership() -> None:
    """Require the actual non-reaping interface before launching a child.

    CPython exposes waitid on macOS from 3.13 onward. Do not substitute a
    reaping poll on older/unsupported hosts. The trusted caller must keep the
    default SIGCHLD disposition and must not independently reap our children.
    """
    if (not callable(getattr(os, "waitid", None))
            or not callable(getattr(os, "killpg", None))
            or any(not hasattr(os, name) for name in
                   ("P_PID", "WEXITED", "WNOWAIT", "WNOHANG",
                    "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED"))):
        raise CaptureRejected("E_CAPTURE_OWNERSHIP",
                              "POSIX compiler capture requires waitid(WNOWAIT); macOS CPython requires 3.13+")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise CaptureRejected("E_CAPTURE_OWNERSHIP", "Default SIGCHLD disposition is required")
    try:
        # Our own PID cannot be our child. ECHILD checks support for these
        # flags without waiting for or consuming another caller's child.
        os.waitid(os.P_PID, os.getpid(), os.WEXITED | os.WNOWAIT | os.WNOHANG)
    except ChildProcessError:
        return
    except OSError as error:
        raise CaptureRejected("E_CAPTURE_OWNERSHIP", "Non-reaping child observation unavailable") from error
    raise CaptureRejected("E_CAPTURE_OWNERSHIP", "Could not confirm non-reaping child observation")


def _posix_observe(proc: subprocess.Popen[bytes]):
    """Observe only this still-owned child, without releasing its PID."""
    if proc.returncode is not None:
        raise CaptureRejected("E_CAPTURE_OWNERSHIP", "Compiler leader was already reaped")
    try:
        info = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
    except OSError as error:
        raise CaptureRejected("E_CAPTURE_OWNERSHIP", "Compiler leader ownership is no longer confirmed") from error
    if info is not None and info.si_pid != proc.pid:
        raise CaptureRejected("E_CAPTURE_OWNERSHIP", "Child observation names another process")
    return info


def _child_exited(proc: subprocess.Popen[bytes], job) -> bool:
    if os.name == "posix" and job is None:
        info = _posix_observe(proc)
        # Some Darwin versions also report stopped children for WEXITED.
        # A stop is not completion; the existing deadline still applies.
        return info is not None and info.si_code in {os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED}
    # The existing Windows Job Object retains ownership independently of PID.
    return proc.poll() is not None


def _terminate(proc: subprocess.Popen[bytes], job=None) -> None:
    """One owned termination attempt; only the direct child is reaped here."""
    if job is not None:
        try:
            if job.cleanup(proc):
                return
            reason = "Windows compiler job cleanup remains pending"
        except OSError as error:
            reason = "Windows compiler job cleanup failed: " + str(error)
        job.retain(proc)
        raise CaptureRejected("E_CAPTURE_CLEANUP", reason)
    group_error = None
    if os.name == "posix":
        # Check that our original leader remains waitable before using its
        # numeric PGID. No wait/poll/kill method may reap it before this signal.
        observed = _posix_observe(proc)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError as error:
            # A terminal, unreaped leader can outlive an empty process group
            # on a supported host. A missing group for a live leader cannot
            # be reported as successful cleanup.
            if observed is None or observed.si_code not in {
                    os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED}:
                group_error = error
        except OSError as error:
            group_error = error
    try:
        # The final group signal has already been attempted. Popen.kill may
        # now reap a terminal leader; it preserves that original exit status.
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CaptureRejected("E_CAPTURE_CLEANUP", "Compiler leader reap was not confirmed") from error
    if group_error is not None:
        raise CaptureRejected("E_CAPTURE_CLEANUP", "Compiler process-group termination failed") from group_error


def _read_final(stream, limit: int) -> bytes:
    # A child/descendant write can race the preceding fstat even after a group
    # signal. Never make the in-memory allocation depend on a stable file size.
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "Compiler output grew beyond byte budget")
    return data


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
    if os.name == "posix":
        _require_posix_ownership()
    elif os.name != "nt":
        raise CaptureRejected("E_CAPTURE_OWNERSHIP", "Unsupported compiler process owner")

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
        cleanup_attempted = False
        try:
            while not _child_exited(proc, job):
                if (os.fstat(output_file.fileno()).st_size > stdout_limit
                        or os.fstat(error_file.fileno()).st_size > stderr_limit):
                    raise CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "Compiler exceeded stdout/stderr byte budget")
                if time.monotonic() >= deadline:
                    raise CaptureRejected("E_CAPTURE_TIMEOUT", "Compiler exceeded wall-time budget")
                time.sleep(min(.01, max(.001, deadline - time.monotonic())))
            # Consume permission to signal before cleanup can reap the leader
            # or fail after an effect. Never retry a numeric group identity.
            cleanup_attempted = True
            _terminate(proc, job)
            stdout_size = os.fstat(output_file.fileno()).st_size
            stderr_size = os.fstat(error_file.fileno()).st_size
            if stdout_size > stdout_limit or stderr_size > stderr_limit:
                raise CaptureRejected("E_CAPTURE_OUTPUT_SIZE", "Compiler output exceeded byte budget")
            output_file.seek(0)
            error_file.seek(0)
            raw_stdout = _read_final(output_file, stdout_limit)
            raw_stderr = _read_final(error_file, stderr_limit)
            return CaptureResult(
                proc.returncode, _decode(raw_stdout, "stdout"),
                _decode(raw_stderr, "stderr"), raw_stdout, raw_stderr,
            )
        except CaptureRejected as error:
            failure = error
            raise
        finally:
            cleanup_failure = None
            try:
                # A failed cleanup may already have signalled/reaped. Preserve
                # that failure and never retry its numeric process group. The
                # Windows owner retains pending jobs through its existing API.
                if not cleanup_attempted:
                    cleanup_attempted = True
                    _terminate(proc, job)
            except CaptureRejected as error:
                cleanup_failure = error
                if failure is not None:
                    failure.capture_error = f"{error.code}: {error}"
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
                    # capture files themselves cannot be read. A later read
                    # failure must not erase an earlier cleanup refusal.
                    previous = failure.capture_error
                    failure.capture_error = (f"{previous}; capture evidence: {error}"
                                             if previous else str(error))
            if cleanup_failure is not None and failure is None:
                raise cleanup_failure
