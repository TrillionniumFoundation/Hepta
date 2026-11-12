#!/usr/bin/env python3
"""Build original scalar NDU with the bounded live search-backup adapter."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.build_hia_ndu_bridge import build

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", required=True)
    args = parser.parse_args()
    result = build(args.upstream, args.output, cargo=args.cargo,
                   adapter=ROOT / "rust/hia-ndu-value", release=True)
    print(json.dumps({k: result[k] for k in ("binary", "binary_sha256", "original_rust_sources_unchanged")}, sort_keys=True))
if __name__ == "__main__":
    main()
