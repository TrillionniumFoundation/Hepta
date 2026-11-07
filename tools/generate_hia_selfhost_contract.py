"""Write or verify the checked-in Selfhost-Core support and identity contract."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import CONTRACT_PATH, support_contract, validate_contract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        contract = validate_contract()
    else:
        contract = support_contract()
        (ROOT / CONTRACT_PATH).write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"profile": contract["profile"], "path": CONTRACT_PATH,
                      "source_files": len(contract["source_identity"]["files"]),
                      "mode": "checked" if args.check else "written"}, sort_keys=True))


if __name__ == "__main__":
    main()
