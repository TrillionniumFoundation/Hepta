"""Bounded, process-group-isolated subprocess capture for C migration.

On unsupported non-POSIX hosts fail closed rather than silently omitting the
process-group guarantee. The C migration pilot is currently Linux-qualified.
"""
from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time


class ClangOutputLimit(subprocess.SubprocessError):
    """A compiler exceeded the combined bounded stdout/stderr budget."""


def run_clang(
    args: list[str], *, timeout: float, text: bool = False, check: bool = False,
    input: bytes | None = None, max_output: int = 8_000_000,
) -> subprocess.CompletedProcess:
    """Capture a Clang subprocess without unbounded output or orphaned timeouts.

    Only empty stdin is supported (the caller's -dM probe requires it).
    A dedicated POSIX session keeps descendant termination out of our own
    process group. Timeout/size/error cleanup kills the *whole* group.
    """
    if os.name != "posix":
        raise subprocess.SubprocessError("isolated Clang capture requires POSIX")
    if input not in (None, b""):
        raise ValueError("only empty compiler stdin is supported")
    if max_output < 1 or timeout <= 0:
        raise ValueError("positive capture limits are required")
    proc = subprocess.Popen(
        args, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    cleanup_group = True
    try:
        if proc.stdin is not None:
            proc.stdin.close()
        chunks = {proc.stdout: bytearray(), proc.stderr: bytearray()}
        budget = 0
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for pipe in chunks:
                selector.register(pipe, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(args, timeout)
                for event, _ in selector.select(min(remaining, 0.1)):
                    block = os.read(event.fileobj.fileno(), min(65_536, max_output - budget + 1))
                    if not block:
                        selector.unregister(event.fileobj)
                    else:
                        budget += len(block)
                        if budget > max_output:
                            raise ClangOutputLimit("Clang combined output exceeded byte limit")
                        chunks[event.fileobj].extend(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(args, timeout)
        status = proc.wait(timeout=remaining)
        stdout = bytes(chunks[proc.stdout])
        stderr = bytes(chunks[proc.stderr])
        if text:
            stdout, stderr = stdout.decode("utf-8"), stderr.decode("utf-8")
        result = subprocess.CompletedProcess(args, status, stdout, stderr)
        if check:
            result.check_returncode()
        cleanup_group = False
        return result
    finally:
        if cleanup_group:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()
