#!/usr/bin/env python3
"""Publish a fail-closed, non-authorizing paired HIA/NDU cost diagnostic."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_full_cost_gate import MAX_INPUT_BYTES, FullCostRejected
from hepta.hia_paired_holdout import assess_paired_holdout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-paired", action="store_true")
    args = parser.parse_args(argv)
    stage = None
    try:
        fd = os.open(args.input, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise OSError("input must be an ordinary regular file")
            raw = source.read(MAX_INPUT_BYTES + 1)
        result = assess_paired_holdout(raw)
        payload = (json.dumps(result, sort_keys=True, indent=2,
                              allow_nan=False) + "\n").encode("utf-8")
        # Publish complete, fsynced bytes through an exclusive hard link.
        # No other process can observe an incomplete final JSON pathname.
        out_dir = args.output.parent
        stage_fd, stage_name = tempfile.mkstemp(prefix=".hia-paired-",
                                                dir=out_dir)
        stage = Path(stage_name)
        with os.fdopen(stage_fd, "wb") as target:
            os.fchmod(target.fileno(), 0o600)
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.link(stage, args.output, follow_symlinks=False)
        stage.unlink()
        stage = None
        dir_fd = os.open(out_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        print(json.dumps({"output": str(args.output),
                          "paired_evidence_supported": result["paired_evidence_supported"],
                          "authority": result["authority"]}, sort_keys=True))
        return 0 if not args.require_paired or result["paired_evidence_supported"] else 2
    except (OSError, ValueError, FullCostRejected) as error:
        print("E_HIA_PAIRED_HOLDOUT: " + str(error), file=sys.stderr)
        return 2
    finally:
        if stage is not None:
            try:
                stage.unlink(missing_ok=True)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
