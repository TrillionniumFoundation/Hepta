"""Restore the retained archive from a checkout of this evidence directory."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
manifest = json.loads((args.directory / "raw-parts.json").read_text())
assert not args.output.exists(), "Refuse to overwrite an existing output"
whole = hashlib.sha256()
whole_git = hashlib.sha1(b"blob " + str(manifest["archive_identity"]["bytes"]).encode() + b"\0")
offset = 0
with args.output.open("xb") as output:
    for index, row in enumerate(manifest["parts"], start=1):
        assert row["part"] == index and row["offset"] == offset
        data = (args.directory / "raw-artifacts" / Path(row["repository_path"]).name).read_bytes()
        assert len(data) == row["bytes"]
        assert hashlib.sha256(data).hexdigest() == row["sha256"]
        assert hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["git_blob_sha1"]
        output.write(data)
        whole.update(data)
        whole_git.update(data)
        offset += len(data)
assert offset == manifest["archive_identity"]["bytes"]
assert whole.hexdigest() == manifest["archive_identity"]["sha256"]
assert whole_git.hexdigest() == manifest["archive_identity"]["git_blob_sha1"]
print(json.dumps({"output": str(args.output), "bytes": offset, "sha256": whole.hexdigest(),
                  "git_blob_sha1": whole_git.hexdigest(), "ordered_parts_verified": len(manifest["parts"])}))
