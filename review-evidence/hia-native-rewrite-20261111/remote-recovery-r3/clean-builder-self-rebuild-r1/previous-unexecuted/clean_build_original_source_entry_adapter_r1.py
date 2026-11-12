"""Exact-source entry adapter for the complete R13 clean-builder readback.

The parent entry router owns push/head/tag/job/caller/helper/adapter identity.
This adapter binds the two reader inputs and invokes only the stdlib reader.
It never imports or executes any recovered HIA authoring, installer or target.
"""
from __future__ import annotations

import time
START_NS = time.monotonic_ns()
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import resource
import runpy
import stat
import sys

PINS = [
    {
        "path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/clean-builder-self-rebuild-r1/ci/read_original_clean_build_r1.py",
        "mode": 420,
        "bytes": 22753,
        "gitsha": "000e69637368430989638dda6cfa3cab767fe9cd",
        "sha256": "8339257f6031e5eea44dcf088f65ab494994194645b71dfea62755702f291b3e"
    },
    {
        "path": "review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/clean-builder-self-rebuild-r1/ci/original-inputs.json",
        "mode": 420,
        "bytes": 11485,
        "gitsha": "c78665dee0eac5c7d9bbf03f5ae77359bebacab9",
        "sha256": "61a08494ceeb3b3142ecd312881375d206e0fe0ed8d5d685fd90a69f8051d9f5"
    }
]
OUTPUT_CHILD = "clean-build-r13-originals-r1"
CPU_LIMIT = 90
WALL_NS = 180000000000


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def capture(repo, expected):
    relative = expected["path"]
    pure = PurePosixPath(relative)
    if (not relative or pure.is_absolute() or pure.as_posix() != relative
            or any(part in ("", ".", "..") for part in pure.parts)):
        raise ValueError("noncanonical pinned reader path")
    path = repo
    for component in pure.parts:
        path = path / component
        if path.is_symlink():
            raise ValueError("symlink in pinned reader path: " + relative)
    if not path.resolve(strict=True).is_relative_to(repo):
        raise ValueError("pinned reader path escaped checkout")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("pinned reader input is not a regular file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read()
        closed = os.fstat(stream.fileno())
    after = path.lstat()
    if not (identity(before) == identity(opened) == identity(closed) == identity(after)):
        raise RuntimeError("reader input changed while captured")
    observed = {
        "path": relative, "mode": stat.S_IMODE(after.st_mode), "bytes": len(raw),
        "sha256": sha256(raw).hexdigest(),
        "gitsha": sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest(),
    }
    if observed != expected or len(raw) != after.st_size:
        raise RuntimeError("pinned reader input identity differs: " + relative)
    return raw, observed


def budget():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = {
        "aggregate_cpu_seconds": own.ru_utime + own.ru_stime + children.ru_utime + children.ru_stime,
        "elapsed_ns": time.monotonic_ns() - START_NS,
    }
    if not 0 <= result["aggregate_cpu_seconds"] < CPU_LIMIT:
        raise RuntimeError("R13 adapter aggregate CPU budget exceeded: " + repr(result))
    if not 0 <= result["elapsed_ns"] < WALL_NS:
        raise RuntimeError("R13 adapter full output wall budget exceeded: " + repr(result))
    return result


def failure(exc):
    return {"class": type(exc).__name__, "message": str(exc)}


def main():
    repo = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    before = {}
    after_rows = []
    errors = []
    primary = None
    primary_traceback = None
    reader_returned_zero = False
    old_argv = sys.argv
    sys.dont_write_bytecode = True
    try:
        for expected in PINS:
            raw, row = capture(repo, expected)
            before[expected["path"]] = (raw, row)
        raw_base = Path(os.environ["HIA_CI_OUTPUT"])
        if not raw_base.is_absolute():
            raise ValueError("HIA_CI_OUTPUT must be an absolute path")
        base = raw_base.resolve()
        if base == repo or base.is_relative_to(repo):
            raise ValueError("R13 recovery output must be outside the checkout")
        out = base / OUTPUT_CHILD
        if out.exists() or out.is_symlink():
            raise ValueError("R13 adapter requires a fresh output child")
        reader = repo / PINS[0]["path"]
        # The pinned reader chooses the pinned sibling original-inputs.json.
        # Its own complete member and final budget checks remain unchanged.
        sys.argv = [str(reader), "--repo", str(repo), "--out", str(out)]
        try:
            runpy.run_path(str(reader), run_name="__main__")
        except SystemExit as exc:
            if exc.code not in (None, 0):
                raise
        reader_returned_zero = True
    except BaseException as exc:
        primary, primary_traceback = exc, exc.__traceback__
    finally:
        sys.argv = old_argv
        # Always attempt both full inputs independently, even after an early
        # failure. The first target error is preserved if cleanup also fails.
        for expected in PINS:
            try:
                raw, row = capture(repo, expected)
                previous = before.get(expected["path"])
                if previous is None:
                    raise RuntimeError("reader input had no complete before capture")
                if (raw, row) != previous:
                    raise RuntimeError("reader input full bytes or mode changed")
                after_rows.append(row)
            except BaseException as exc:
                errors.append((exc, exc.__traceback__))
        receipt = {
            "schema": "hia-clean-builder-r13-source-entry-adapter-r1",
            "scope": "SOURCE_RECOVERY_ONLY_NO_TARGET_EXECUTION",
            "reader_returned_zero": reader_returned_zero,
            "source_before": [before[row["path"]][1] for row in PINS if row["path"] in before],
            "source_after": after_rows,
            "complete_both_source_checks": len(before) == len(PINS) and len(after_rows) == len(PINS),
            "primary_error": None if primary is None else failure(primary),
            "after_errors": [failure(exc) for exc, _ in errors],
            "native_qualification_claimed": False,
            "source_rebuild_or_installation_claimed": False,
            "whole_Worker_closed": False,
        }
        try:
            receipt["usage_before_adapter_output"] = budget()
            print("HIA_CLEAN_BUILD_R13_ENTRY_ADAPTER " + json.dumps(receipt, sort_keys=True), flush=True)
        except BaseException as exc:
            errors.append((exc, exc.__traceback__))
        try:
            budget()
        except BaseException as exc:
            errors.append((exc, exc.__traceback__))
    if primary is not None:
        for exc, _ in errors:
            primary.add_note("Additional R13 adapter finalization failure: " + repr(exc))
        raise primary.with_traceback(primary_traceback)
    if errors:
        first, first_traceback = errors[0]
        for exc, _ in errors[1:]:
            first.add_note("Additional R13 adapter finalization failure: " + repr(exc))
        raise first.with_traceback(first_traceback)
    if not reader_returned_zero:
        raise RuntimeError("R13 reader did not complete with a zero return")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
