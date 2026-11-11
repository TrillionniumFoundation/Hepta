"""Reconstruct the exact failed 6e CI artifact into a new private directory."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

import zstandard

EXPECTED_BYTES = 122628168
EXPECTED_SHA256 = "7ff3905907ac8a02e0b5366ce4bbc3c24e5794c9dde94a0f87149c9ed9cc5137"
COMPRESSED_BYTES = 63568818
COMPRESSED_SHA256 = "b7e36d63bbbad93bfadc95c0b429db34bb8b8996d9ce7041c021b6836b057bc6"


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python restore_original_zip.py NEW_OUTPUT_DIRECTORY")
    base = Path(__file__).resolve().parent
    receipt = json.loads((base / "ORIGINAL-ZIP-PRESERVATION.json").read_bytes())
    assert receipt["original"]["bytes"] == EXPECTED_BYTES
    assert receipt["original"]["sha256"] == EXPECTED_SHA256
    assert receipt["compressed"]["bytes"] == COMPRESSED_BYTES
    assert receipt["compressed"]["sha256"] == COMPRESSED_SHA256
    parts = receipt["parts"]
    assert len(parts) == 16
    output = Path(sys.argv[1])
    output.mkdir(mode=0o700)
    packed = output / "original.zip.zst"
    combined = hashlib.sha256()
    total = 0
    with packed.open("xb") as destination:
        for index, part in enumerate(parts):
            expected_path = f"original-zip-parts/original.zip.zst.part{index:03d}"
            assert part["path"] == expected_path
            path = base.joinpath(*PurePosixPath(expected_path).parts)
            before = path.lstat()
            assert stat.S_ISREG(before.st_mode) and not path.is_symlink()
            raw = path.read_bytes()
            after = path.lstat()
            fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
            assert all(getattr(before, key) == getattr(after, key) for key in fields)
            assert len(raw) == part["bytes"] <= 4 * 1024 * 1024
            assert hashlib.sha256(raw).hexdigest() == part["sha256"]
            assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == part["git_blob_sha1"]
            destination.write(raw)
            combined.update(raw)
            total += len(raw)
        destination.flush()
        os.fsync(destination.fileno())
    assert total == COMPRESSED_BYTES and combined.hexdigest() == COMPRESSED_SHA256
    original = output / "hia-6e-ci-artifact-13865519334-original.zip"
    decoded_digest = hashlib.sha256()
    decoded_bytes = 0
    with packed.open("rb") as source, zstandard.ZstdDecompressor().stream_reader(source) as decoded, original.open("xb") as destination:
        while block := decoded.read(1024 * 1024):
            destination.write(block)
            decoded_digest.update(block)
            decoded_bytes += len(block)
            assert decoded_bytes <= EXPECTED_BYTES
        destination.flush()
        os.fsync(destination.fileno())
    assert decoded_bytes == EXPECTED_BYTES and decoded_digest.hexdigest() == EXPECTED_SHA256
    independent = hashlib.sha256()
    with original.open("rb") as source:
        while block := source.read(1024 * 1024):
            independent.update(block)
    assert independent.hexdigest() == EXPECTED_SHA256 and original.stat().st_size == EXPECTED_BYTES
    result = {"schema": "hia.original-ci-zip-restoration.v1", "status": "EXACT_ORIGINAL_BYTES_RESTORED",
              "path": str(original), "bytes": EXPECTED_BYTES, "sha256": EXPECTED_SHA256,
              "compressed_bytes": COMPRESSED_BYTES, "compressed_sha256": COMPRESSED_SHA256,
              "parts": len(parts), "all_parts_git_sha1_sha256_size_verified": True,
              "decoded_file_independently_read_back": True, "original_workflow_status": "FAILURE",
              "product_tests_rerun": False, "whole_native_delivery_qualified": False}
    raw = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
    with (output / "RESTORATION.json").open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(raw.decode(), end="")


if __name__ == "__main__":
    main()
