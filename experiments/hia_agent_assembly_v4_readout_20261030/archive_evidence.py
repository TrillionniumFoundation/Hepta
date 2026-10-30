#!/usr/bin/env python3
"""Retain every regular raw evidence file and verify the archive member bytes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tarfile
import time


def identity(path):
    with path.open("rb") as stream:
        return {"bytes": path.stat().st_size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}


def archive(source, destination):
    started = time.monotonic_ns()
    source, destination = Path(source).resolve(strict=True), Path(destination).absolute()
    if destination.exists() or destination.is_relative_to(source):
        raise ValueError("new archive outside source required")
    destination.parent.mkdir(parents=True, exist_ok=True)
    files = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("unexpected nonregular raw evidence entry: " + str(path))
        if path.is_file():
            files[str(path.relative_to(source))] = identity(path)
    archive_started = time.monotonic_ns()
    with tarfile.open(destination, "x:xz", preset=3) as output:
        for name in files:
            output.add(source / name, arcname=name, recursive=False)
    compression_ns = time.monotonic_ns() - archive_started
    with tarfile.open(destination, "r:xz") as archived:
        members = archived.getmembers()
        if len(members) != len(files) or {m.name for m in members} != set(files):
            raise RuntimeError("archive inventory differs")
        for member in members:
            if not member.isfile():
                raise RuntimeError("archive contains nonregular evidence")
            with archived.extractfile(member) as stream:
                actual = {"bytes": member.size, "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
            if actual != files[member.name] or identity(source / member.name) != actual:
                raise RuntimeError("archive readback/source identity differs: " + member.name)
    result = {"schema": "hepta.agent.lossless-evidence-archive.v1", "source": str(source),
              "archive": destination.name, "archive_identity": identity(destination),
              "member_count": len(files), "raw_bytes": sum(row["bytes"] for row in files.values()),
              "every_member_roundtrip_verified": True, "files": files,
              "compression_ns": compression_ns, "archive_and_roundtrip_wall_ns": time.monotonic_ns() - started}
    with destination.with_suffix(".manifest.json").open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True); stream.write("\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source"); parser.add_argument("destination")
    result = archive(**vars(parser.parse_args()))
    print(json.dumps({k: result[k] for k in ("archive", "member_count", "raw_bytes", "archive_identity", "archive_and_roundtrip_wall_ns")}))
