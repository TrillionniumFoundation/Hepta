"""Bounded stdout capture for compiler subprocesses; no unbounded communicate().

Consumes both pipes concurrently and retains only a bounded stderr tail.
Used for compiler diagnostics and AST/dependency capture, not a general shell.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import threading


class BoundedProcessError(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__("E_BOUNDED_PROCESS_" + reason.upper())


@dataclass(frozen=True)
class BoundedResult:
    returncode: int
    stdout: str
    stderr_tail: str


def run_bounded(args: list[str], cwd: Path, *, stdin: str | None = None,
                timeout: float = 45, stdout_limit: int = 32_000_000,
                input_limit: int = 1_000_000, stderr_tail_limit: int = 6000) -> BoundedResult:
    if not isinstance(args, list) or not args or not all(isinstance(x, str) for x in args):
        raise BoundedProcessError("arguments")
    if (timeout <= 0 or stdout_limit < 1 or input_limit < 0 or stderr_tail_limit < 0):
        raise BoundedProcessError("limits")
    try:
        incoming = None if stdin is None else stdin.encode("utf-8")
    except (AttributeError, UnicodeError) as exc:
        raise BoundedProcessError("stdin_encoding") from exc
    if incoming is not None and len(incoming) > input_limit:
        raise BoundedProcessError("stdin_limit")
    try:
        proc = subprocess.Popen(args, cwd=cwd, stdin=subprocess.PIPE if incoming is not None
                                else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    except OSError as exc:
        raise BoundedProcessError("spawn") from exc
    chunks: list[bytes] = []
    tail = bytearray()
    oversized = threading.Event()
    failures: list[OSError] = []

    def stop() -> None:
        try:
            proc.kill()
        except OSError:
            pass

    def reader(pipe, stdout: bool) -> None:
        retained = 0
        try:
            while True:
                part = pipe.read(64 * 1024)
                if not part:
                    break
                if stdout:
                    retained += len(part)
                    if retained > stdout_limit:
                        oversized.set()
                        stop()
                        break
                    chunks.append(part)
                elif stderr_tail_limit:
                    tail.extend(part)
                    if len(tail) > stderr_tail_limit:
                        del tail[:-stderr_tail_limit]
        except OSError as exc:
            failures.append(exc)
        finally:
            pipe.close()

    readers = [threading.Thread(target=reader, args=(proc.stdout, True), daemon=True),
               threading.Thread(target=reader, args=(proc.stderr, False), daemon=True)]
    for thread in readers:
        thread.start()

    def writer():
        try:
            if incoming:
                proc.stdin.write(incoming)
                proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            proc.stdin.close()

    input_thread = None
    if incoming is not None:
        input_thread = threading.Thread(target=writer, daemon=True)
        input_thread.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            raise BoundedProcessError("unreaped")
    finally:
        if proc.poll() is None:
            stop()
        for thread in readers:
            thread.join(timeout=2)
        if input_thread is not None:
            input_thread.join(timeout=2)
    if timed_out:
        raise BoundedProcessError("timeout")
    if oversized.is_set():
        raise BoundedProcessError("stdout_limit")
    if failures or any(thread.is_alive() for thread in readers):
        raise BoundedProcessError("pipe_io")
    try:
        stdout = b"".join(chunks).decode("utf-8", "strict")
    except UnicodeError as exc:
        raise BoundedProcessError("stdout_encoding") from exc
    return BoundedResult(proc.returncode, stdout, tail.decode("utf-8", "replace"))
