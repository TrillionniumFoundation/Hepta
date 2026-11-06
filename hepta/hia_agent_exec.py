"""Fixed Linux parent-death guardian for the already selected native linker.

This is an internal process-launch component, not an Agent tool. The trusted
native compiler supplies its previously resolved/pinned executable and argv.
Exec preserves the PID, process group and parent-death signal for that tool.
"""
from __future__ import annotations

import ctypes
import os
import signal
import sys


def main():
    if sys.platform != "linux" or len(sys.argv) < 3:
        return 125
    try:
        parent = int(sys.argv[1])
    except ValueError:
        return 125
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        return 125
    executable = sys.argv[2]
    if not os.path.isabs(executable):
        return 125
    os.execv(executable, sys.argv[2:])
    return 125


if __name__ == "__main__":
    raise SystemExit(main())
