#!/usr/bin/env python3
"""Deterministically generate/check the public catalog from the checker table."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_opcodes import opcode_catalog, render_opcode_reference


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = {ROOT / "docs/HIA_OPCODE_REFERENCE.md": render_opcode_reference(),
               ROOT / "docs/hia-opcode-catalog.v8.json": json.dumps(opcode_catalog(), indent=2, sort_keys=True) + "\n"}
    stale = []
    for path, text in outputs.items():
        if args.check:
            if not path.is_file() or path.read_text() != text:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(text)
    if stale:
        print("Generated catalog drift: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("Catalog/docs checked" if args.check else "Catalog/docs generated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
