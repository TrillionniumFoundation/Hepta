#!/usr/bin/env python3
"""Build the separate raw-model adapter against unchanged, pinned NDU crates."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_hia_ndu_bridge import build


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--debug", action="store_true", help="use an explicit unoptimized development build")
    args = parser.parse_args()
    receipt = build(args.upstream, args.output, cargo=args.cargo,
                    adapter=ROOT / "rust/hia-ndu-raw-model", release=not args.debug)
    print(json.dumps({key: receipt[key] for key in
                     ("binary", "binary_sha256", "original_rust_sources_unchanged")}, indent=2))


if __name__ == "__main__":
    main()
