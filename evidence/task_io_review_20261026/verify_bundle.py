#!/usr/bin/env python3
"""Verify sealed review bytes without extraction, compilation or execution."""
import base64
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition):
    if not condition:
        raise ValueError("archive identity, bounds or member check failed")


def verify(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "MANIFEST.json").read_text())
    require(manifest["schema"] == "hepta.task-io-review-archive.v1")
    identity = manifest["archive"]
    require(identity["path"] == "native-records.tar.xz.base64")
    encoded = (directory / identity["path"]).read_bytes()
    require(len(encoded) <= 16 * 1024 * 1024)
    require(sha(encoded) == identity["encoded_sha256"])
    packed = base64.b64decode(b"".join(encoded.split()), validate=True)
    require(len(packed) == identity["decoded_bytes"] and sha(packed) == identity["sha256"])
    expected = {row["path"]: row for row in manifest["members"]}
    require(len(expected) == len(manifest["members"]) == manifest["member_count"] <= 512)
    seen = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r|xz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and ".." not in path.parts)
            require(member.name in expected and member.name not in seen)
            row = expected[member.name]
            require(type(row["bytes"]) is int and 0 <= row["bytes"] <= 16 * 1024 * 1024)
            require(member.size == row["bytes"])
            total += member.size
            require(total <= 128 * 1024 * 1024)
            stream = archive.extractfile(member)
            require(stream is not None)
            data = stream.read(member.size + 1)
            require(len(data) == row["bytes"] and sha(data) == row["sha256"])
            seen.add(member.name)
    require(seen == set(expected))
    return {"verified": True, "members": len(seen), "uncompressed_bytes": total,
            "source_commit": manifest["source_commit"], "native_execution_repeated": False}


if __name__ == "__main__":
    print(json.dumps(verify(Path(__file__).resolve().parent), sort_keys=True))
