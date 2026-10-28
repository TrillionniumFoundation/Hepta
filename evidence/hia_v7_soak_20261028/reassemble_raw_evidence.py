#!/usr/bin/env python3
"""Reassemble the unchanged raw evidence archive, checking every transport part."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "raw-evidence-parts.json").read_text())
    if manifest["schema"] != "hepta.hia.evidence-transport-parts.v1":
        raise ValueError("unsupported transport schema")
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    descriptor, temporary = tempfile.mkstemp(prefix="hia-evidence-", suffix=".tmp", dir=output.parent)
    total = 0
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "wb") as stream:
            for index, row in enumerate(manifest["parts"]):
                expected = f"raw-evidence.parts/part-{index:04d}.bin"
                if row["path"] != expected:
                    raise ValueError("noncanonical transport part path/order")
                path = root / expected
                if path.is_symlink() or not path.is_file():
                    raise ValueError("ordinary transport part required")
                raw = path.read_bytes()
                if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                    raise ValueError("transport part content mismatch: " + expected)
                stream.write(raw)
                digest.update(raw)
                total += len(raw)
            if total != manifest["archive"]["bytes"] or digest.hexdigest() != manifest["archive"]["sha256"]:
                raise ValueError("reassembled archive identity mismatch")
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link within the output directory: publication is atomic and never
        # overwrites an existing destination, including a concurrently created one.
        os.link(temporary, output)
    finally:
        os.unlink(temporary)
    print(json.dumps({"output": str(output), "bytes": total, "sha256": digest.hexdigest(),
                      "verified_parts": len(manifest["parts"])}))


if __name__ == "__main__":
    main()
