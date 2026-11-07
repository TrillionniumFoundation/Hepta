#!/usr/bin/env python3
"""Explicit macro-policy advice / full-cost assessment; never execute advice."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_macro_policy import (MAX_INPUT_BYTES, MacroPolicyRejected,
    advise_macro, advise_ordinary, assess_macro_comparison)


def _read_input(path):
    """Bound allocation and reject FIFOs/symlinks before reading evidence."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_INPUT_BYTES:
            raise MacroPolicyRejected("E_HIA_MACRO: evidence input must be a bounded regular file")
        raw = stream.read(MAX_INPUT_BYTES + 1)
        after = os.fstat(stream.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or len(raw) != before.st_size:
            raise MacroPolicyRejected("E_HIA_MACRO: evidence input changed while being read")
        return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("advise", "ordinary", "assess"))
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-binary", type=Path)
    parser.add_argument("--native-build-receipt", type=Path)
    parser.add_argument("--timeout-ns", type=int, default=1_000_000_000)
    args = parser.parse_args(argv)
    if bool(args.native_binary) != bool(args.native_build_receipt):
        parser.error("native binary and exact source-bound build receipt must be supplied together")
    if args.mode != "advise" and args.native_binary:
        parser.error("only advise uses a native evaluator")
    try:
        raw = _read_input(args.input)
        if args.mode == "advise":
            bridge = {"binary": str(args.native_binary), "build_receipt": str(args.native_build_receipt)} if args.native_binary else None
            result = advise_macro(raw, bridge=bridge, timeout_ns=args.timeout_ns)
            succeeded = result["status"] == "ADVISORY"
        elif args.mode == "ordinary":
            result = advise_ordinary(raw)
            succeeded = result["status"] == "ADVISORY"
        else:
            result = assess_macro_comparison(raw)
            succeeded = result["observed_scope_positive"]
        content = (json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(args.output, flags, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        print(json.dumps({"output": str(args.output), "passed": succeeded, "authority": "DENY_ALL"}, sort_keys=True))
        return 0 if succeeded else 2
    except (OSError, MacroPolicyRejected) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
