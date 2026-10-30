#!/usr/bin/env python3
"""Reconstruct the unchanged original raw archive from verified Git-sized parts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "ARCHIVE_PARTS.json").read_text())
    output = Path(args.output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("refusing to replace an existing output")
    whole = hashlib.sha256()
    total = 0
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as writer:
            temporary = Path(writer.name)
            for row in manifest["parts"]:
                if Path(row["name"]).name != row["name"]:
                    raise ValueError("part name must be a simple filename")
                source = root / row["name"]
                if source.is_symlink() or not source.is_file():
                    raise ValueError("archive part must be a regular file")
                digest, count = hashlib.sha256(), 0
                with source.open("rb") as reader:
                    while block := reader.read(1024 * 1024):
                        count += len(block)
                        if count > row["bytes"]:
                            raise ValueError("archive part exceeds its registered length")
                        digest.update(block)
                        whole.update(block)
                        writer.write(block)
                if count != row["bytes"] or digest.hexdigest() != row["sha256"]:
                    raise ValueError("archive part identity differs")
                total += count
        if total != manifest["archive"]["bytes"] or whole.hexdigest() != manifest["archive"]["sha256"]:
            raise ValueError("reconstructed original archive identity differs")
        os.link(temporary, output)
        print(json.dumps({"output": str(output), "bytes": total, "sha256": whole.hexdigest(),
                          "original_archive_bytes_preserved": True}))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
