#!/usr/bin/env python3
"""Lossless member-CAS packaging; never imports or executes product code."""
from __future__ import annotations

import argparse
import base64
from functools import lru_cache
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import tarfile
import time

ROOT = Path(__file__).resolve().parent
COLLECTED = ROOT / "collected"
BLOCKS = ROOT / "block-pool"
CHUNK = 65536


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while data := source.read(1 << 20):
            digest.update(data)
    return digest.hexdigest()


def meta(path):
    size = path.stat().st_size
    digest = hashlib.sha256()
    git = hashlib.sha1(("blob " + str(size) + "\0").encode())
    with path.open("rb") as source:
        while data := source.read(1 << 20):
            digest.update(data)
            git.update(data)
    return dict(bytes=size, sha256=digest.hexdigest(), git_blob=git.hexdigest())


def blocks():
    BLOCKS.mkdir(exist_ok=False)
    manifest = json.loads((COLLECTED / "MANIFEST.json").read_bytes())
    mapping = {}
    block_sizes = {}
    started = time.monotonic()
    for number, (digest, item) in enumerate(sorted(manifest["pool"].items())):
        path = COLLECTED / "pool" / digest
        total = 0
        check = hashlib.sha256()
        chunks = []
        with path.open("rb") as source:
            while data := source.read(CHUNK):
                check.update(data)
                total += len(data)
                chunk_digest = hashlib.sha256(data).hexdigest()
                target = BLOCKS / chunk_digest
                if chunk_digest in block_sizes:
                    if block_sizes[chunk_digest] != len(data) or target.read_bytes() != data:
                        raise ValueError("chunk collision or existing block changed")
                else:
                    target.write_bytes(data)
                    target.chmod(0o400)
                    block_sizes[chunk_digest] = len(data)
                chunks.append(chunk_digest)
        if total != item["bytes"] or check.hexdigest() != digest:
            raise ValueError(("whole original object changed", digest))
        mapping[digest] = dict(bytes=total, sha256=digest, chunks=chunks)
        if (number + 1) % 5000 == 0:
            print(json.dumps(dict(phase="block_dedupe", objects=number + 1,
                unique_blocks=len(block_sizes), block_bytes=sum(block_sizes.values()),
                seconds=time.monotonic() - started)), flush=True)
    result = dict(schema="hepta.lossless.chunk-map.v1", chunk_size=CHUNK,
                  complete_original_manifest_sha256=sha(COLLECTED / "MANIFEST.json"),
                  objects=mapping, blocks=block_sizes)
    dump(ROOT / "OBJECT-MAP.json", result)
    @lru_cache(maxsize=512)
    def read_block(digest):
        data = (BLOCKS / digest).read_bytes()
        if len(data) != block_sizes[digest] or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(("block readback mismatch", digest))
        return data
    for digest, item in mapping.items():
        check = hashlib.sha256()
        total = 0
        for chunk in item["chunks"]:
            data = read_block(chunk)
            check.update(data)
            total += len(data)
        if check.hexdigest() != digest or total != item["bytes"]:
            raise ValueError(("whole original object reconstruction mismatch", digest))
    summary = dict(status="ALL_ORIGINAL_OBJECTS_RECONSTRUCTED_BYTE_FOR_BYTE",
                   objects=len(mapping), original_object_bytes=sum(x["bytes"] for x in mapping.values()),
                   unique_blocks=len(block_sizes), block_bytes=sum(block_sizes.values()),
                   chunk_size=CHUNK, seconds=time.monotonic() - started,
                   object_map=meta(ROOT / "OBJECT-MAP.json"), product_execution=0)
    dump(ROOT / "BLOCK-VERIFICATION.json", summary)
    print(json.dumps(summary, sort_keys=True), flush=True)


def archive():
    target = ROOT / "COMPLETE-ORIGINAL-MEMBERS.tar.xz"
    if target.exists():
        raise FileExistsError(target)
    mapping = json.loads((ROOT / "OBJECT-MAP.json").read_bytes())
    files = [("pool/" + name, BLOCKS / name) for name in sorted(mapping["blocks"])]
    for path, name in [
        (COLLECTED / "MANIFEST.json", "MANIFEST.json"),
        (COLLECTED / "SUMMARY.json", "COLLECTION-SUMMARY.json"),
        (COLLECTED / "EVENTS.jsonl", "COLLECTION-EVENTS.jsonl"),
        (ROOT / "OBJECT-MAP.json", "OBJECT-MAP.json"),
        (ROOT / "BLOCK-VERIFICATION.json", "BLOCK-VERIFICATION.json"),
        (ROOT / "collect_originals.py", "scripts/collect_originals.py"),
        (ROOT / "package_custody.py", "scripts/package_custody.py"),
        (ROOT / "COLLECTION.stdout.log", "COLLECTION.stdout.log"),
        (ROOT / "COLLECTION.stderr.log", "COLLECTION.stderr.log"),
        (ROOT / "BLOCKS.stdout.log", "BLOCKS.stdout.log"),
        (ROOT / "BLOCKS.stderr.log", "BLOCKS.stderr.log"),
        (ROOT / "MACHINE-PLAN-REVIEW.json", "MACHINE-PLAN-REVIEW.json"),
        (ROOT / "ORIGINAL-OUTCOMES.json", "ORIGINAL-OUTCOMES.json"),
    ]:
        files.append((name, path))
    contents = []
    for name, path in files:
        contents.append(dict(path=name, archive_mode=0o444, **meta(path)))
    dump(ROOT / "CAPSULE-CONTENTS.json", dict(schema="hepta.capsule.contents.v1", files=contents,
         notes="The content inventory excludes its own self-referential identity; all original member modes and paths are in MANIFEST.json."))
    files.append(("CAPSULE-CONTENTS.json", ROOT / "CAPSULE-CONTENTS.json"))
    started = time.monotonic()
    with lzma.open(target, "xb", format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64,
                   preset=3) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            for name, path in files:
                info = tarfile.TarInfo(name)
                info.size = path.stat().st_size
                info.mode = 0o444
                info.uid = info.gid = info.mtime = 0
                with path.open("rb") as source:
                    tar.addfile(info, source)
    expected = {row["path"]: row for row in contents}
    expected["CAPSULE-CONTENTS.json"] = dict(archive_mode=0o444, **meta(ROOT / "CAPSULE-CONTENTS.json"))
    seen = []
    with lzma.open(target, "rb") as compressed:
        with tarfile.open(fileobj=compressed, mode="r|") as tar:
            for info in tar:
                row = expected[info.name]
                if not info.isfile() or info.size != row["bytes"] or info.mode != row["archive_mode"]:
                    raise ValueError(("tar metadata mismatch", info.name))
                digest = hashlib.sha256()
                stream = tar.extractfile(info)
                while data := stream.read(1 << 20):
                    digest.update(data)
                if digest.hexdigest() != row["sha256"]:
                    raise ValueError(("tar bytes mismatch", info.name))
                seen.append(info.name)
        while compressed.read(1 << 20):
            pass
    if set(seen) != set(expected) or len(seen) != len(expected):
        raise ValueError("tar inventory mismatch")
    verification = dict(status="FULL_XZ_CRC64_AND_ALL_TAR_BYTES_MODES_VERIFIED",
                        archive=meta(target), tar_members=len(seen),
                        tar_payload_bytes=sum(x["bytes"] for x in expected.values()),
                        seconds=time.monotonic() - started, product_execution=0,
                        original_outer_zip_git_custody=False)
    dump(ROOT / "ARCHIVE-VERIFICATION.json", verification)
    print(json.dumps(verification, sort_keys=True), flush=True)


def parts():
    target = ROOT / "COMPLETE-ORIGINAL-MEMBERS.tar.xz"
    verification = json.loads((ROOT / "ARCHIVE-VERIFICATION.json").read_bytes())
    if meta(target) != verification["archive"]:
        raise ValueError("archive changed before transport split")
    folder = ROOT / "transport"
    folder.mkdir(exist_ok=False)
    rows = []
    with target.open("rb") as source:
        while data := source.read(512 << 10):
            name = "part-%04d.b64" % (len(rows) + 1)
            path = folder / name
            path.write_bytes(base64.b64encode(data))
            rows.append(dict(path=name, decoded_bytes=len(data),
                             decoded_sha256=hashlib.sha256(data).hexdigest(), **meta(path)))
    dump(ROOT / "TRANSPORT-INDEX.json", dict(schema="hepta.exact-base64-archive-transport.v1",
         archive=verification["archive"], encoding="Each part is strict RFC4648 Base64 with no whitespace; decode independently and concatenate in this exact order.",
         parts=rows, original_outer_zip_git_custody=False))
    print(json.dumps(dict(parts=len(rows), archive=verification["archive"], index=meta(ROOT / "TRANSPORT-INDEX.json"))), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("blocks", "archive", "parts"))
    phase = parser.parse_args().phase
    {"blocks": blocks, "archive": archive, "parts": parts}[phase]()
