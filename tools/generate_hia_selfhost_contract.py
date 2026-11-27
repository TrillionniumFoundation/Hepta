"""Write or verify the checked-in Selfhost-Core support and identity contract."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import CONTRACT_PATH, support_contract
from tools.hia_release_contract import read_contract, source_domain, validate_release_contract


def write_hosted_contract(root=ROOT):
    root = Path(root)
    path = root / CONTRACT_PATH
    if path.exists() and source_domain(read_contract(root)) == 'native':
        raise ValueError('native source contract requires the native inventory/contract producer; '
                         'the hosted generator must not overwrite it')
    contract = support_contract(root)
    path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")
    return contract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        contract = validate_release_contract()
    else:
        contract = write_hosted_contract()
    print(json.dumps({"profile": contract["profile"], "path": CONTRACT_PATH,
                      "source_files": len(contract["source_identity"]["files"]),
                      "source_domain": source_domain(contract),
                      "mode": "checked" if args.check else "written"}, sort_keys=True))


if __name__ == "__main__":
    main()
