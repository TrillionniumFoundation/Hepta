"""Windows process-tree ownership for the bounded compiler capture.

The trusted launcher waits on a private inherited pipe. The parent assigns it
to a kill-on-close Job Object before allowing it to launch the real command.
Descendants inherit that job; neither launcher requests breakaway. A job that
has not drained keeps its handles and blocks subsequent capture admission.

This is process lifetime control, not an untrusted-code or filesystem sandbox.
Windows 8+ nested jobs are required when the caller already belongs to a job.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import sys
import threading
import time


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32)]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_int64),
                ("TotalKernelTime", ctypes.c_int64),
                ("ThisPeriodTotalUserTime", ctypes.c_int64),
                ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                ("TotalPageFaultCount", ctypes.c_uint32),
                ("TotalProcesses", ctypes.c_uint32),
                ("ActiveProcesses", ctypes.c_uint32),
                ("TotalTerminatedProcesses", ctypes.c_uint32)]


_PENDING: list[tuple["WindowsJob", subprocess.Popen[bytes]]] = []
_PENDING_LOCK = threading.Lock()


class WindowsJob:
    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows Job Object capture requires Windows")
        api = self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        handle, dword, pointer = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p
        for name, restype, args in (
            ("CreateJobObjectW", handle, [pointer, ctypes.c_wchar_p]),
            ("SetInformationJobObject", ctypes.c_int,
             [handle, ctypes.c_int, pointer, dword]),
            ("AssignProcessToJobObject", ctypes.c_int, [handle, handle]),
            ("TerminateJobObject", ctypes.c_int, [handle, dword]),
            ("QueryInformationJobObject", ctypes.c_int,
             [handle, ctypes.c_int, pointer, dword, pointer]),
            ("CloseHandle", ctypes.c_int, [handle]),
        ):
            function = getattr(api, name)
            function.restype, function.argtypes = restype, args
        self.handle = api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        if not api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits),
                                           ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            api.CloseHandle(self.handle)
            self.handle = None
            raise error

    def assign(self, proc: subprocess.Popen[bytes]) -> None:
        # CPython's retained process handle pins the identity; never reopen by
        # PID after the process may have exited. Supported host Python is 3.11.
        if not self.api.AssignProcessToJobObject(self.handle, int(proc._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def active(self) -> int:
        if self.handle is None:
            return 0
        accounting = _Accounting()
        if not self.api.QueryInformationJobObject(
                self.handle, 1, ctypes.byref(accounting),
                ctypes.sizeof(accounting), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return accounting.ActiveProcesses

    def cleanup(self, proc: subprocess.Popen[bytes], timeout: float = 3) -> bool:
        if self.handle is None:
            return True
        if not self.api.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        deadline = time.monotonic() + timeout
        while self.active():
            if time.monotonic() >= deadline:
                return False
            time.sleep(.005)
        try:
            proc.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return False
        if not self.api.CloseHandle(self.handle):
            raise ctypes.WinError(ctypes.get_last_error())
        self.handle = None
        return True

    def retain(self, proc: subprocess.Popen[bytes]) -> None:
        with _PENDING_LOCK:
            if not any(owner is self for owner, _ in _PENDING):
                _PENDING.append((self, proc))


def _drain_pending() -> None:
    with _PENDING_LOCK:
        remaining = []
        for job, proc in _PENDING:
            try:
                finished = job.cleanup(proc, timeout=0)
            except OSError:
                finished = False
            if not finished:
                remaining.append((job, proc))
        _PENDING[:] = remaining
        if remaining:
            raise OSError("Previous Windows compiler job cleanup is still pending")


def launch(argv, *, cwd, stdin, stdout, stderr):
    """Launch only after actual job assignment; return the process and owner."""
    import msvcrt

    _drain_pending()
    job = WindowsJob()
    read_fd = write_fd = None
    proc = None
    assigned = False
    try:
        read_fd, write_fd = os.pipe()
        read_handle = msvcrt.get_osfhandle(read_fd)
        os.set_handle_inheritable(read_handle, True)
        startup = subprocess.STARTUPINFO(
            lpAttributeList={"handle_list": [read_handle]})
        command = [sys.executable, "-I", str(Path(__file__).resolve()),
                   "--job-child", str(read_handle), "--", *argv]
        proc = subprocess.Popen(
            command, cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr,
            shell=False, close_fds=True, startupinfo=startup)
        # No compiler has started: the trusted launcher is waiting for this
        # byte, and pipe EOF is refusal. Assignment failure never opens the gate.
        job.assign(proc)
        assigned = True
        if os.write(write_fd, b"G") != 1:
            raise OSError("Could not release the assigned compiler launcher")
        return proc, job
    except BaseException as original:
        # EOF also releases an unassigned launcher into refusal. Close it before
        # cleanup so even failure to terminate that launcher cannot strand it.
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None
        if proc is not None:
            try:
                if not assigned:
                    try:
                        proc.kill()
                    except OSError:
                        if proc.poll() is None:
                            raise
                if not job.cleanup(proc):
                    job.retain(proc)
                    original.add_note("Windows compiler launcher cleanup remains pending")
            except OSError as cleanup_error:
                job.retain(proc)
                original.add_note("Windows compiler launcher cleanup failed: " + str(cleanup_error))
        elif job.handle is not None:
            job.api.CloseHandle(job.handle)
            job.handle = None
        raise
    finally:
        for fd in (read_fd, write_fd):
            if fd is not None:
                os.close(fd)


def _child() -> int:
    import msvcrt

    if len(sys.argv) < 5 or sys.argv[1] != "--job-child" or sys.argv[3] != "--":
        raise ValueError("Expected an assigned Windows compiler launcher")
    gate = msvcrt.open_osfhandle(int(sys.argv[2]), os.O_RDONLY)
    try:
        if os.read(gate, 1) != b"G":
            raise ValueError("Compiler launch refused before job assignment")
    finally:
        os.close(gate)
    # Inherit the assigned job and the file-backed standard handles. Waiting is
    # explicit: Windows execv does not supply POSIX process replacement semantics.
    return subprocess.Popen(sys.argv[4:], shell=False).wait()


if __name__ == "__main__":
    try:
        raise SystemExit(_child())
    except Exception as error:
        print(f"Windows compiler launcher failed: {error}", file=sys.stderr)
        raise SystemExit(1)
