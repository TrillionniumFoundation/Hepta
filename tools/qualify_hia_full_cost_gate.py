#!/usr/bin/env python3
"""Read immutable observed-cost evidence; never grant code execution authority."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_full_cost_gate import (MAX_INPUT_BYTES, FullCostRejected,
                                     assess_full_cost)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-positive", action="store_true")
    args = parser.parse_args(argv)
    try:
        with args.input.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        result = assess_full_cost(raw)
        content = (json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(args.output, flags, 0o600)
        with os.fdopen(descriptor, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        print(json.dumps({"result": str(args.output),
                          "economic_scope_positive": result["economic_scope_positive"],
                          "authority": result["authority"]}, sort_keys=True))
        return 0 if not args.require_positive or result["economic_scope_positive"] else 2
    except (OSError, FullCostRejected) as error:
        print("E_HIA_FULL_COST_GATE: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
