#!/usr/bin/env python3
"""Verify retained local observations without extracting or executing programs."""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import tarfile


MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_MEMBER_TOTAL = 16 * 1024 * 1024
MAX_TAR_BYTES = 20 * 1024 * 1024
MAX_MEMBERS = 512


def safe_name(value):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise ValueError("invalid relative member name")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or ".." in path.parts or ":" in path.parts[0]:
        raise ValueError("unsafe relative member name")
    return value


def identity(stream, maximum, *, retain=False):
    digest, size = hashlib.sha256(), 0
    chunks = [] if retain else None
    while True:
        block = stream.read(min(65536, maximum - size + 1))
        if not block:
            break
        size += len(block)
        if size > maximum:
            raise ValueError("declared byte limit exceeded")
        digest.update(block)
        if chunks is not None:
            chunks.append(block)
    return size, digest.hexdigest(), b"".join(chunks) if chunks is not None else None


def require_identity(observed, expected, label):
    if observed[0] != expected["bytes"] or observed[1] != expected["sha256"]:
        raise ValueError("byte identity mismatch: " + label)


class LimitedReader:
    def __init__(self, stream, maximum):
        self.stream = stream
        self.maximum = maximum
        self.count = 0

    def read(self, size=-1):
        remaining = self.maximum - self.count
        size = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > self.maximum:
            raise ValueError("decompressed archive limit exceeded")
        return data


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true", required=True,
                        help="Check archive and every original member; no extraction or project execution.")
    parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "MANIFEST.json").read_bytes())
    if manifest.get("schema") != "hepta.round6.local-evidence-manifest.v1":
        raise ValueError("unexpected evidence manifest schema")
    archive = manifest["archive"]
    archive_path = root / safe_name(archive["path"])
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ValueError("archive must be a regular non-symlink file")
    if not 0 < archive["bytes"] <= MAX_ARCHIVE_BYTES:
        raise ValueError("archive byte budget differs")
    with archive_path.open("rb") as stream:
        require_identity(identity(stream, MAX_ARCHIVE_BYTES), archive, archive["path"])
    expected = {}
    for row in manifest["files"]:
        name = safe_name(row["path"])
        if name in expected or row["mode"] != 0o644:
            raise ValueError("duplicate member or unsupported mode")
        if type(row["bytes"]) is not int or not 0 <= row["bytes"] <= MAX_MEMBER_BYTES:
            raise ValueError("invalid member byte budget")
        expected[name] = row
    total = sum(row["bytes"] for row in expected.values())
    if not 0 < len(expected) <= MAX_MEMBERS or total > MAX_MEMBER_TOTAL:
        raise ValueError("member count or total exceeds bounds")
    if len(expected) != manifest["file_count"] or total != manifest["uncompressed_file_bytes"]:
        raise ValueError("manifest totals differ")

    plan_name = "raw/round6-final-focused/PLAN.json"
    result_name = "raw/round6-final-focused/RESULT.json"
    selected, seen = {}, set()
    with lzma.LZMAFile(archive_path, "rb") as decoded:
        limited = LimitedReader(decoded, MAX_TAR_BYTES)
        with tarfile.open(fileobj=limited, mode="r|") as package:
            for member in package:
                name = safe_name(member.name)
                if not member.isfile() or name in seen or name not in expected:
                    raise ValueError("unexpected/nonregular/duplicate member: " + name)
                row = expected[name]
                if member.size != row["bytes"] or member.mode != row["mode"]:
                    raise ValueError("member metadata differs: " + name)
                source = package.extractfile(member)
                if source is None:
                    raise ValueError("member bytes missing: " + name)
                with source:
                    observed = identity(source, row["bytes"], retain=name in {plan_name, result_name})
                require_identity(observed, row, name)
                if observed[2] is not None:
                    selected[name] = json.loads(observed[2])
                seen.add(name)
        # Finish XZ checksum validation after the tar end marker.
        while limited.read(65536):
            pass
    if seen != expected.keys():
        raise ValueError("some indexed original files were not retained")

    plan, result = selected[plan_name], selected[result_name]
    binding = manifest["source_binding"]
    if (plan["source"]["head"] != binding["local_test_commit"]
            or result["source_head"] != binding["local_test_commit"]
            or plan["source"]["tree"] != binding["source_tree"]
            or result["source_tree"] != binding["source_tree"]):
        raise ValueError("original focused source identities differ")
    selectors = plan["unique_selectors"]
    union = set().union(*(set(items) for items in plan["groups"].values()))
    if len(selectors) != len(set(selectors)) or set(selectors) != union:
        raise ValueError("focused selector union differs")
    if (plan["count"] != len(selectors) or result["unique_methods"] != len(selectors)
            or result["tests"] != len(selectors)):
        raise ValueError("focused test denominator differs")

    print(json.dumps({
        "schema": "hepta.round6.local-evidence-verification.v1",
        "archive_verified": True,
        "archive_sha256": archive["sha256"],
        "raw_files": len(seen),
        "raw_file_bytes": total,
        "local_test_commit": binding["local_test_commit"],
        "published_same_tree_source_commit": binding["published_source_commit"],
        "source_tree": binding["source_tree"],
        "retained_focused_unique_methods": len(selectors),
        "project_code_executed": False,
        "new_tests_executed": 0,
        "files_extracted": 0,
        "native_or_ci_qualification_performed": False,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    run()
