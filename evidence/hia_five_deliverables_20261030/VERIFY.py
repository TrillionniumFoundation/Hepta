#!/usr/bin/env python3
"""Check the retained evidence bytes; never execute archived artifacts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    index = json.loads(Path(__file__).with_name("EVIDENCE_FILES.json").read_text())
    failures = []
    seen = set()
    checked_bytes = 0
    for row in index["files"]:
        name = row["path"]
        path = root / name
        if name in seen or path.is_symlink() or not path.resolve().is_relative_to(root):
            failures.append({"path": name, "reason": "duplicate or nonregular path"})
            continue
        seen.add(name)
        if not path.is_file():
            failures.append({"path": name, "reason": "missing file"})
            continue
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(block)
                digest.update(block)
        checked_bytes += size
        if size != row["bytes"] or digest.hexdigest() != row["sha256"]:
            failures.append({"path": name, "reason": "size or hash mismatch"})
    result = {"schema": "hepta.five-deliverables.evidence-integrity.v1",
              "files_checked": len(seen), "bytes_checked": checked_bytes,
              "failures": failures, "passed": not failures,
              "scope": "retained bytes only; not a new experiment or safety proof"}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
