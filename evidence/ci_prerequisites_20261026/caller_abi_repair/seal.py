#!/usr/bin/env python3
"""Hash the exact evidence appendix; no retained source is executed."""
import hashlib
import json
from pathlib import Path

directory = Path(__file__).resolve().parent
files = {}
for path in sorted(directory.rglob("*")):
    if path.is_dir():
        continue
    assert path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts
    name = path.relative_to(directory).as_posix()
    if name == "MANIFEST.json":
        continue
    raw = path.read_bytes()
    files[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
(directory / "MANIFEST.json").write_text(json.dumps({"schema": "hepta.caller-abi.bundle.v1",
    "files": files, "scope": "exact archive and sidecar inventory; no whole-candidate qualification"}, indent=2, sort_keys=True) + "\n")
print(json.dumps({"files": len(files), "bytes": sum(row["bytes"] for row in files.values())}))
