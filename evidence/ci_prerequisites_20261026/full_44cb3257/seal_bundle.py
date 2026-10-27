"""Seal the new evidence directory without altering any retained original bytes."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
args = parser.parse_args()
directory = args.directory.resolve()
archive = json.loads((directory / "run-artifacts.manifest.json").read_bytes())
parts = [row["path"] for row in archive["parts"]]
files = {}
for path in sorted(directory.rglob("*")):
    if path.is_dir():
        continue
    assert path.is_file() and not path.is_symlink()
    name = path.relative_to(directory).as_posix()
    if name == "MANIFEST.json" or name in parts:
        continue
    raw = path.read_bytes()
    files[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
manifest = {"schema": "hepta.ci-candidate.bundle.v1", "source_commit": archive["source_commit"],
    "original_zip": json.loads((directory / "zip-identity.json").read_bytes()),
    "archive_parts": parts, "files": files,
    "scope": "exact provider originals and independently derived data reviews; verification does not upgrade the original CI conclusion or known qualification limitations"}
(directory / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(json.dumps({"sidecars": len(files), "archive_parts": len(parts), "source_commit": manifest["source_commit"]}))
