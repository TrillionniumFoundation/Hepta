#!/usr/bin/env python3
"""Archive retained evidence without rebuilding or rewriting measured files."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path
import stat
import tarfile


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def bundle(root, directories, destination):
    root, destination = Path(root).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError("archive destination must be new")
    files = {}
    for name in directories:
        directory = (root / name).resolve()
        directory.relative_to(root)
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError("evidence directory is unavailable or not ordinary")
        for path in sorted(directory.rglob("*")):
            meta = path.lstat()
            if stat.S_ISDIR(meta.st_mode):
                continue
            if not stat.S_ISREG(meta.st_mode):
                raise ValueError("evidence contains non-ordinary file: " + str(path))
            key = path.relative_to(root).as_posix()
            if key in files:
                raise ValueError("duplicate evidence member")
            payload = path.read_bytes()
            files[key] = {"bytes": len(payload), "sha256": digest(payload),
                          "mode": stat.S_IMODE(meta.st_mode)}
    manifest = {"schema": "hepta.retained-evidence-archive.v1", "files": files,
        "file_count": len(files), "uncompressed_file_bytes": sum(x["bytes"] for x in files.values()),
        "scope": "exact retained files; absolute paths in receipts remain historical; extraction is not new execution"}
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as raw:
        with lzma.LZMAFile(raw, "w", format=lzma.FORMAT_XZ,
                           filters=[{"id": lzma.FILTER_LZMA2, "preset": 6,
                                     "dict_size": 64 * 1024 * 1024}]) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for name, item in [("MANIFEST.json", {"bytes": len(encoded), "mode": 0o644}), *files.items()]:
                    payload = encoded if name == "MANIFEST.json" else (root / name).read_bytes()
                    if name != "MANIFEST.json" and (len(payload) != item["bytes"] or digest(payload) != item["sha256"]):
                        raise ValueError("evidence changed while packaging: " + name)
                    member = tarfile.TarInfo(name)
                    member.size, member.mode = len(payload), item["mode"]
                    member.mtime, member.uid, member.gid = 0, 0, 0
                    archive.addfile(member, io.BytesIO(payload))
    checked = verify(destination)
    if checked["manifest_sha256"] != digest(encoded):
        raise ValueError("archive readback manifest mismatch")
    sidecar = destination.with_name(destination.name + ".manifest.json")
    with sidecar.open("xb") as stream:
        stream.write(encoded)
    return checked


def verify(path):
    path = Path(path)
    with tarfile.open(path, "r:xz") as archive:
        members = archive.getmembers()
        if len({member.name for member in members}) != len(members):
            raise ValueError("duplicate archive paths")
        for member in members:
            if not member.isfile() or Path(member.name).is_absolute() or ".." in Path(member.name).parts:
                raise ValueError("unsafe or non-file archive member")
        encoded = archive.extractfile("MANIFEST.json").read()
        manifest = json.loads(encoded)
        if set(m.name for m in members) != set(manifest["files"]) | {"MANIFEST.json"}:
            raise ValueError("archive inventory mismatch")
        total = 0
        for member in members:
            if member.name == "MANIFEST.json":
                continue
            data = archive.extractfile(member).read()
            expected = manifest["files"][member.name]
            if len(data) != expected["bytes"] or digest(data) != expected["sha256"] or member.mode != expected["mode"]:
                raise ValueError("archive file mismatch: " + member.name)
            total += len(data)
        if total != manifest["uncompressed_file_bytes"] or len(members) - 1 != manifest["file_count"]:
            raise ValueError("archive totals mismatch")
    payload = path.read_bytes()
    return {"file": path.name, "bytes": len(payload), "sha256": digest(payload),
        "git_blob_sha": hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest(),
        "files": manifest["file_count"], "uncompressed_file_bytes": total,
        "manifest_sha256": digest(encoded), "complete_readback_verified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify")
    parser.add_argument("--root")
    parser.add_argument("--output")
    parser.add_argument("directories", nargs="*")
    args = parser.parse_args()
    if args.verify:
        result = verify(args.verify)
    else:
        if not args.root or not args.output or not args.directories:
            parser.error("provide --root --output and at least one evidence directory")
        result = bundle(args.root, args.directories, args.output)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
