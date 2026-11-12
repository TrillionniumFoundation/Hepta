"""Disposable qualification setup, replaced by the actual ELF via execve.

No compilation occurs here. The kernel executes the successor directly after
this harness pins its input and arranges negative file-descriptor/resource
conditions. Ordinary CLI users do not need this Python test harness.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import resource


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    raw = args.request.read_bytes()
    if len(raw) > 16384 or sha256(raw).hexdigest() != args.sha256:
        raise ValueError("CLI child request identity differs")
    request = json.loads(raw)
    if (set(request) != {"executable", "executable_sha256", "input", "input_sha256", "mode", "arguments"}
            or request["mode"] not in {"ordinary", "closed-stdin", "full-stdout", "mmap-failure"}
            or request["arguments"] not in ([], ["unexpected"])):
        raise ValueError("unknown CLI child request")
    executable, source = Path(request["executable"]), Path(request["input"])
    if (not executable.is_absolute() or not source.is_absolute()
            or sha256(executable.read_bytes()).hexdigest() != request["executable_sha256"]
            or sha256(source.read_bytes()).hexdigest() != request["input_sha256"]):
        raise ValueError("CLI child executable or input identity differs")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb", closefd=False) as stream:
        if sha256(stream.read()).hexdigest() != request["input_sha256"]:
            raise ValueError("CLI input was rebound before open")
        stream.seek(0)
        os.dup2(fd, 0)
    os.close(fd)
    if request["mode"] == "closed-stdin":
        os.close(0)
    if request["mode"] == "full-stdout":
        fd = os.open("/dev/full", os.O_WRONLY | os.O_NOFOLLOW)
        os.dup2(fd, 1)
        os.close(fd)
    # No crash-collector activation or global setting changes.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) or libc.prctl(3, 0, 0, 0, 0) != 0:
        raise RuntimeError("CLI child dumpability setup failed")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    argv = [str(executable), *request["arguments"]]
    if request["mode"] == "mmap-failure":
        resource.setrlimit(resource.RLIMIT_AS, (2 << 20, 2 << 20))
    os.execv(executable, argv)


if __name__ == "__main__":
    main()
