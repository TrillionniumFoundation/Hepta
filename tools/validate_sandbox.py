#!/usr/bin/env python3
"""Run the mandatory real namespace/native qualification without an AI provider."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from experiments.agent_eval.sandbox_qualification import qualify_sandbox


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc")
    parser.add_argument("--output", type=Path, required=True, help="new JSON evidence path; never overwritten")
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("output already exists")
    report = qualify_sandbox(args.rustc)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as destination:
        json.dump(report, destination, indent=2, sort_keys=True)
        destination.write("\n")
    print(json.dumps({"status": report["status"], "qualified": report["qualified"],
                      "checks": report["checks"], "output": str(args.output)}))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
