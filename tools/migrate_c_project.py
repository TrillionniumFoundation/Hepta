"""Capture and migrate a bounded C project without executing database commands."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hepta.c_migrate import migrate_c_project


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--contracts", type=Path)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc")
    parser.add_argument("--verify-native", action="store_true")
    args = parser.parse_args()
    contracts = json.loads(args.contracts.read_text()) if args.contracts else None
    result = migrate_c_project(args.database, args.output, contracts=contracts, clang=args.clang,
                               rustc=args.rustc, verify_native=args.verify_native)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
