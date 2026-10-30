#!/usr/bin/env python3
"""Losslessly retain an entire run before reclaiming its compiled ELF files."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import time


def file_sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pack(source, output, prune_elf=False):
    source, output = Path(source).resolve(strict=True), Path(output).absolute()
    if not source.is_dir() or output == source or source in output.parents:
        raise ValueError("archive must be outside its source directory")
    if output.exists() or output.with_suffix(".manifest.json").exists():
        raise ValueError("refuse to overwrite evidence")
    output.parent.mkdir(parents=True, exist_ok=True)
    inventory = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("unexpected symlink in experiment evidence")
        if path.is_file():
            inventory[str(path.relative_to(source))] = {"bytes": path.stat().st_size, "sha256": file_sha(path)}
    started = time.monotonic_ns()
    with tarfile.open(output, "x:xz", preset=3) as archive:
        for name in inventory:
            archive.add(source / name, arcname=name, recursive=False)
    observed = {}
    with tarfile.open(output, "r:xz") as archive:
        for member in archive:
            if not member.isfile() or member.name in observed:
                raise ValueError("invalid or duplicate archive member")
            with archive.extractfile(member) as stream:
                observed[member.name] = {"bytes": member.size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
    if observed != inventory:
        raise ValueError("archive member identity differs from original evidence")
    manifest = {"schema": "hepta.hia.lossless-evidence-archive.v1", "source": str(source),
                "archive": str(output), "archive_sha256": file_sha(output), "archive_bytes": output.stat().st_size,
                "members": inventory, "member_count": len(inventory),
                "all_member_hashes_verified": True, "pack_and_verify_ns": time.monotonic_ns() - started,
                "pruned_elf_files": [], "reclaimed_bytes": 0}
    if prune_elf:
        for name, item in inventory.items():
            path = source / name
            with path.open("rb") as stream:
                is_elf = stream.read(4) == b"\x7fELF"
            if is_elf:
                if file_sha(path) != item["sha256"]:
                    raise ValueError("artifact changed after archive validation")
                path.unlink()
                manifest["pruned_elf_files"].append(name)
                manifest["reclaimed_bytes"] += item["bytes"]
    with output.with_suffix(".manifest.json").open("x") as stream:
        json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--prune-elf", action="store_true")
    result = pack(**vars(parser.parse_args()))
    print(json.dumps({key: result[key] for key in ("archive", "archive_sha256", "archive_bytes",
        "member_count", "all_member_hashes_verified", "reclaimed_bytes")}), flush=True)


if __name__ == "__main__":
    main()
