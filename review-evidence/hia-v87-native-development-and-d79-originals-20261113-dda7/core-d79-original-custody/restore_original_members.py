#!/usr/bin/env python3
"""Restore d79 original ZIP members from the lossless Git custody capsule.

This restores every original member byte and the mode recorded in the ZIP.
It does not recreate the original outer ZIP's compressed byte stream and
never executes any restored product, test, helper, or binary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import stat
import tarfile


def safe_name(name):
    parts = PurePosixPath(name).parts
    if not name or "\0" in name or name.startswith("/") or any(x in (".", "..") for x in parts):
        raise ValueError(("unsafe original path", name))
    return parts


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive-sha256", default="b30e5d7d0547a98cad21308b48a7ffceb70fba82c328d657cab4c9c544e3802c")
    args = parser.parse_args()
    if digest_file(args.archive) != args.archive_sha256:
        raise ValueError("capsule archive identity differs")
    args.output.mkdir(exist_ok=False)
    capsule = args.output / "capsule"
    capsule.mkdir()
    seen = set()
    with lzma.open(args.archive, "rb") as compressed:
        with tarfile.open(fileobj=compressed, mode="r|") as archive:
            for item in archive:
                if not item.isfile() or item.name in seen:
                    raise ValueError("capsule must contain unique regular files")
                seen.add(item.name)
                target = capsule.joinpath(*safe_name(item.name))
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as source, target.open("xb") as destination:
                    while block := source.read(1 << 20):
                        destination.write(block)
                target.chmod(0o400)
        while compressed.read(1 << 20):
            pass
    contents = json.loads((capsule / "CAPSULE-CONTENTS.json").read_bytes())["files"]
    if {x["path"] for x in contents} | {"CAPSULE-CONTENTS.json"} != seen:
        raise ValueError("capsule path inventory differs")
    for record in contents:
        path = capsule / record["path"]
        if path.stat().st_size != record["bytes"] or digest_file(path) != record["sha256"]:
            raise ValueError(("capsule content differs", record["path"]))
    mapping = json.loads((capsule / "OBJECT-MAP.json").read_bytes())
    manifest_path = capsule / "MANIFEST.json"
    if digest_file(manifest_path) != mapping["complete_original_manifest_sha256"]:
        raise ValueError("original member manifest differs")
    manifest = json.loads(manifest_path.read_bytes())
    for digest, size in mapping["blocks"].items():
        path = capsule / "pool" / digest
        if path.stat().st_size != size or digest_file(path) != digest:
            raise ValueError(("chunk differs", digest))

    def restore_object(digest, target, mode):
        record = mapping["objects"][digest]
        target.parent.mkdir(parents=True, exist_ok=True)
        check = hashlib.sha256()
        count = 0
        with target.open("xb") as destination:
            for chunk in record["chunks"]:
                data = (capsule / "pool" / chunk).read_bytes()
                destination.write(data)
                check.update(data)
                count += len(data)
        if count != record["bytes"] or check.hexdigest() != digest:
            raise ValueError(("restored member differs", str(target)))
        target.chmod(mode)

    restored = []
    for archive in manifest["archives"]:
        folder = args.output / (archive["name"] + ".members")
        paths = set()
        for record in archive["members"]:
            name = record["path"]
            if name in paths:
                raise ValueError("cannot materialize duplicate ZIP names to one path")
            paths.add(name)
            target = folder.joinpath(*safe_name(name))
            if record["is_directory"]:
                target.mkdir(parents=True, exist_ok=True)
                continue
            kind = stat.S_IFMT(record["unix_mode"])
            if kind not in (0, stat.S_IFREG):
                raise ValueError(("non-regular original ZIP member", name, kind))
            restore_object(record["sha256"], target, record["permission_mode"])
        restored.append(dict(archive=archive["name"], members=len(paths),
                             original_zip_sha256=archive["sha256"]))
    for record in manifest["originals"]:
        restore_object(record["sha256"], args.output / "original-sidecars" / record["name"],
                       record["original_identity"]["mode"])
    print(json.dumps(dict(status="ALL_ORIGINAL_MEMBERS_RESTORED", restored=restored,
                         product_execution=0, recreated_original_outer_zip=False), indent=2))


if __name__ == "__main__":
    main()
