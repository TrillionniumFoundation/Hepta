#!/usr/bin/env python3
"""Qualify a real native Linux pthread/eventfd host and optionally actual Hepta code."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hepta.hia_linux_interfaces import qualify_linux_interfaces


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("host-reference", "hepta"), required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--native-host", choices=("x86_64", "aarch64"))
    args = parser.parse_args(argv)
    result = qualify_linux_interfaces(args.output, mode=args.mode, cc=args.cc, clang=args.clang,
                                      expected_machine=args.native_host)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
