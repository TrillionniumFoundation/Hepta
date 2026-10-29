#!/usr/bin/env python3
"""Finite correctness calls for filecheck; native faults terminate this child.

This is a diagnostic process boundary for already built, trusted experiment
libraries. It does not sandbox hostile libraries or grant qualification authority.
The parent owns expected results and the final qualification report.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

SCHEMA = "hepta.hia.filecheck.native-validation.v1"
ABI = {"parameters": ["size_t", "u64", "u32", "u32"], "result": "u64"}
MAX_CASES = 96
MAX_LIBRARIES = 8


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_FILECHECK_WORKER: " + message)


def identity(path):
    path = Path(path).absolute()
    descriptor, before = open_regular(path)
    digest = hashlib.sha256()
    count = 0
    with os.fdopen(descriptor, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            count += len(chunk)
        after = os.fstat(stream.fileno())
    require(stamp(before) == stamp(after) and count == before.st_size,
            "library changed while capturing identity")
    return {"path": str(path), "bytes": count, "sha256": digest.hexdigest()}


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def open_regular(path):
    """Reject special files before a read can wait for a FIFO writer."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ValueError("E_HIA_FILECHECK_WORKER: regular no-follow file required") from error
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "regular no-follow file required")
        return descriptor, before
    except BaseException:
        os.close(descriptor)
        raise


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_request(path):
    descriptor, before = open_regular(path)
    with os.fdopen(descriptor, "rb") as stream:
        require(before.st_size <= 128 * 1024, "request exceeds finite input bound")
        data = stream.read(128 * 1024 + 1)
        after = os.fstat(stream.fileno())
    require(len(data) <= 128 * 1024, "request exceeds finite input bound")
    require(stamp(before) == stamp(after) and len(data) == before.st_size,
            "request changed while reading")
    request = json.loads(data, object_pairs_hook=_pairs)
    require(type(request) is dict and set(request) == {"schema", "libraries", "arguments"}, "request shape")
    require(request["schema"] == SCHEMA, "request schema")
    libraries = request["libraries"]
    require(type(libraries) is list and 1 <= len(libraries) <= MAX_LIBRARIES, "finite library list")
    arms = set()
    for library in libraries:
        require(type(library) is dict and set(library) == {"arm", "symbol", "path", "bytes", "sha256"}, "library shape")
        for key in ("arm", "symbol"):
            require(type(library[key]) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", library[key]), key + " identifier")
        require(library["arm"] not in arms, "duplicate library arm")
        arms.add(library["arm"])
        require(type(library["path"]) is str and Path(library["path"]).is_absolute(), "absolute library path")
        require(type(library["bytes"]) is int and library["bytes"] > 0, "library byte count")
        require(type(library["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", library["sha256"]), "library digest")
    arguments = request["arguments"]
    require(type(arguments) is list and 1 <= len(arguments) <= MAX_CASES, "finite case list")
    widths = (ctypes.sizeof(ctypes.c_size_t) * 8, 64, 32, 32)
    for values in arguments:
        require(type(values) is list and len(values) == 4, "four ABI arguments required")
        require(all(type(value) is int and 0 <= value < (1 << width) for value, width in zip(values, widths)),
                "exact unsigned ABI argument required")
    return request


def emit(value):
    print(json.dumps(value, separators=(",", ":"), allow_nan=False), flush=True)


def execute(request):
    # Preserve the original CDLL/function lifetimes and original case -> arm
    # order. The only relocated work is correctness validation, never timing.
    bindings = []
    for item in request["libraries"]:
        expected = {key: item[key] for key in ("path", "bytes", "sha256")}
        require(identity(item["path"]) == expected, "library changed before load")
        library = ctypes.CDLL(item["path"])
        function = library[item["symbol"]]
        function.argtypes = [ctypes.c_size_t, ctypes.c_ulonglong, ctypes.c_uint, ctypes.c_uint]
        function.restype = ctypes.c_ulonglong
        bindings.append((item["arm"], library, function))
    emit({"event": "ready", "libraries": request["libraries"], "abi": ABI})
    calls = 0
    for index, arguments in enumerate(request["arguments"]):
        for arm, library, function in bindings:
            emit({"event": "call", "index": index, "arm": arm, "arguments": arguments})
            result = int(function(*arguments))
            emit({"event": "returned", "index": index, "arm": arm, "result": result})
            calls += 1
    for item in request["libraries"]:
        expected = {key: item[key] for key in ("path", "bytes", "sha256")}
        require(identity(item["path"]) == expected, "library changed during execution")
    emit({"event": "complete", "calls": calls})


def main(argv=None):
    import resource
    argv = sys.argv[1:] if argv is None else argv
    require(len(argv) == 2 and argv[0] == "--request", "--request FILE required")
    # A fatal instruction remains a real process signal, without a potentially
    # enormous core dump. The supervising parent retains the flushed prefix.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    execute(read_request(argv[1]))


if __name__ == "__main__":
    main()
