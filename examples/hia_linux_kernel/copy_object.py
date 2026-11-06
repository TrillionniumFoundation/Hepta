#!/usr/bin/env python3
"""Kbuild-only copy of a hash-bound precompiled HIA input, before objtool.

This script performs no compilation or fallback. Kbuild appends its ordinary
cmd_objtool gate (or the normal delayed final-link gate) to this command.
"""
from hashlib import sha256
import os
from pathlib import Path
import sys
import tempfile


def main():
    source, output, expected = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    data = source.read_bytes()
    if sha256(data).hexdigest() != expected:
        raise SystemExit("HIA kernel object identity mismatch; no fallback")
    descriptor, name = tempfile.mkstemp(prefix=".hia-copy-", dir=output.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, output)
    finally:
        if Path(name).exists():
            Path(name).unlink()


if __name__ == "__main__":
    main()
