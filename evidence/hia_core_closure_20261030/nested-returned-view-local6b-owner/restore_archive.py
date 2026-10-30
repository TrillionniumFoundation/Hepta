"""Reassemble the original archive and verify every retained member; never execute it."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tarfile

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
parts = json.loads((root / "raw-parts.json").read_bytes())
members = json.loads((root / "archive-members.json").read_bytes())
expected = members["members"]
target = args.output.resolve()
total, digest = 0, hashlib.sha256()
with target.open("xb") as output:
    for index, row in enumerate(parts["parts"], 1):
        assert row["index"] == index and row["offset"] == total
        name = Path(row["name"])
        assert not name.is_absolute() and len(name.parts) == 1
        data = (root / name).read_bytes()
        assert len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"]
        output.write(data)
        digest.update(data)
        total += len(data)
assert total == parts["archive_bytes"] and digest.hexdigest() == parts["archive_sha256"]
with gzip.open(target, "rb") as stream:
    while stream.read(1024 * 1024):
        pass
with tarfile.open(target, "r:gz") as archive:
    actual = archive.getmembers()
    assert len(actual) == len(expected) and len({row.name for row in actual}) == len(actual)
    for item, row in zip(actual, expected):
        name = Path(item.name)
        assert not name.is_absolute() and ".." not in name.parts
        assert item.isfile() and item.name == row["path"] and item.size == row["bytes"]
        assert item.mode == int(row["mode"][-3:], 8)
        assert hashlib.sha256(archive.extractfile(item).read()).hexdigest() == row["sha256"]
print(json.dumps({"ok": True, "bytes": total, "sha256": digest.hexdigest(),
                  "members": len(expected), "gzip_crc_and_every_member_verified": True,
                  "extracted_or_executed_members": False}))
