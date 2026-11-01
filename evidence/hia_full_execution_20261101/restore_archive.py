#!/usr/bin/env python3
"""Reconstruct one evidence archive; verify every encoded/decoded part and total.

This utility never extracts or executes the archive. The output must not exist.
Use a stable, trusted local checkout; manifest identity is a separate trust input.
Example: python restore_archive.py archives/archive-manifest.json /tmp/native.tar.xz
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tempfile
import os


LIMIT = 128 * 1024 * 1024


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def checked_size(value):
    if type(value) is not int or not 0 <= value <= LIMIT:
        raise ValueError("invalid or excessive byte count")
    return value


def check_bytes(data, expected_bytes, expected_sha):
    if len(data) != checked_size(expected_bytes):
        raise ValueError("byte count mismatch")
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha):
        raise ValueError("invalid SHA-256")
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError("SHA-256 mismatch")


def restore(manifest_path, output_path):
    manifest_path = Path(manifest_path).resolve(strict=True)
    if manifest_path.stat().st_size > 1024 * 1024:
        raise ValueError("manifest exceeds one MiB")
    manifest = json.loads(manifest_path.read_text(), object_pairs_hook=unique_object)
    if manifest.get("schema") != "hepta.evidence.split-base64.v1":
        raise ValueError("unsupported manifest schema")
    checked_size(manifest["archive_bytes"])
    parts = manifest["parts"]
    if not isinstance(parts, list) or not 1 <= len(parts) <= 8192:
        raise ValueError("invalid part list")
    if "parts_count" in manifest and (type(manifest["parts_count"]) is not int or manifest["parts_count"] != len(parts)):
        raise ValueError("part count mismatch")
    archive = bytearray()
    seen = set()
    resolved_seen = set()
    for index, part in enumerate(parts):
        if "index" in part and (type(part["index"]) is not int or part["index"] != index):
            raise ValueError("part index mismatch")
        if "raw_offset" in part and (type(part["raw_offset"]) is not int or part["raw_offset"] != len(archive)):
            raise ValueError("part offset mismatch")
        name = part["path"]
        if not isinstance(name, str) or "\\" in name or "\x00" in name:
            raise ValueError("invalid part path")
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts or name != relative.as_posix() or name in seen:
            raise ValueError("unsafe or duplicate part path")
        seen.add(name)
        unresolved = manifest_path.parent / name
        if unresolved.is_symlink():
            raise ValueError("part cannot be a symlink")
        path = unresolved.resolve(strict=True)
        if not path.is_relative_to(manifest_path.parent) or not path.is_file():
            raise ValueError("part escapes its manifest directory")
        if path in resolved_seen:
            raise ValueError("duplicate resolved part path")
        resolved_seen.add(path)
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("part exceeds one MiB")
        encoded = path.read_bytes()
        check_bytes(encoded, part["encoded_bytes"], part["encoded_sha256"])
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except binascii.Error as exc:
            raise ValueError("part is not strict base64") from exc
        check_bytes(decoded, part["decoded_bytes"], part["decoded_sha256"])
        if len(archive) + len(decoded) > manifest["archive_bytes"]:
            raise ValueError("parts exceed declared archive size")
        archive.extend(decoded)
    check_bytes(archive, manifest["archive_bytes"], manifest["archive_sha256"])
    output_path = Path(output_path).absolute()
    # Verify everything before creating an output; never replace an existing file.
    with tempfile.NamedTemporaryFile(prefix="hia-evidence-", dir=output_path.parent, delete=False) as f:
        temporary = Path(f.name)
        try:
            f.write(archive)
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.link(temporary, output_path)
    finally:
        temporary.unlink(missing_ok=True)
    return {"output": str(output_path), "bytes": len(archive), "sha256": manifest["archive_sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(restore(args.manifest, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
