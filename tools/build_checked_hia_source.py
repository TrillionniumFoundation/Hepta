"""Build a pinned-Rust-checked Hepta scalar source through existing HIA Core.

This is the source-qualified CLI, not the standalone `hepta hia build` API. It never
silently substitutes Rust/C machine code for the verified HIA LLVM emitter.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hepta.hia_source_bridge import build_checked_hepta_hia_native


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--target", choices=(
        "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"),
        default="x86_64-unknown-linux-gnu")
    parser.add_argument("--kind", choices=("shared", "object"), default="shared")
    parser.add_argument("--locked", action="store_true")
    args = parser.parse_args(argv)
    result = build_checked_hepta_hia_native(
        args.source, args.output, rustc=args.rustc, clang=args.clang,
        target=args.target, kind=args.kind, locked=args.locked)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
