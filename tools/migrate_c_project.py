"""Capture and migrate a bounded C project without executing database commands."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hepta.c_migrate import MigrationRejected, migrate_c_project
from hepta.c_contracts import load_contracts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--contracts", type=Path)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc")
    parser.add_argument("--verify-native", action="store_true")
    args = parser.parse_args()
    try:
        contracts = load_contracts(args.contracts) if args.contracts else None
    except MigrationRejected as exc:
        print(json.dumps({"ok": False, "status": "rejected",
                          "diagnostics": [{"code": exc.code, "message": str(exc)}]},
                         indent=2, sort_keys=True))
        return 1
    result = migrate_c_project(args.database, args.output, contracts=contracts, clang=args.clang,
                               rustc=args.rustc, verify_native=args.verify_native)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
