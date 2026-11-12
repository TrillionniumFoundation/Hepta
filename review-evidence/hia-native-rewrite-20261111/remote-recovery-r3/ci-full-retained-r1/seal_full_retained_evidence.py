#!/usr/bin/env python3
"""Stream complete raw evidence into an archive and independently read it back.

Only Git object databases are excluded by name. Source HEAD/tree/blob inventories
remain included. The implementation keeps one catalog row and one tar member at
a time, rather than retaining all TarInfo objects or duplicate full catalogs.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time

def fingerprint(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def file_hash(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("expected regular file: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if fingerprint(opened) != fingerprint(before):
            raise ValueError("evidence changed before read")
        value = hashlib.file_digest(stream, "sha256").hexdigest()
        after_fd = os.fstat(stream.fileno())
    if len({fingerprint(s) for s in (before, opened, after_fd, path.lstat())}) != 1:
        raise ValueError("evidence changed during read")
    return value

def entry(path):
    before = path.lstat()
    row = dict(mode=stat.S_IMODE(before.st_mode))
    if stat.S_ISREG(before.st_mode):
        row.update(kind="file", bytes=before.st_size, sha256=file_hash(path))
    elif stat.S_ISLNK(before.st_mode):
        row.update(kind="symlink", target=os.readlink(path))
    elif stat.S_ISDIR(before.st_mode):
        row.update(kind="directory")
    else:
        raise ValueError("unsupported evidence object: " + str(path))
    if fingerprint(before) != fingerprint(path.lstat()):
        raise ValueError("evidence changed while inventorying")
    return row

def walk(name, root, exclusions):
    if root.name == ".git":
        exclusions.append(name)
        return
    if not name or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
        raise ValueError("unsafe member name")
    row = dict(name=name, **entry(root))
    yield root, row
    if row["kind"] == "directory":
        for child in sorted(root.iterdir(), key=lambda p: p.name):
            yield from walk(name + "/" + child.name, child, exclusions)

def all_members(roots, exclusions):
    for name, path in roots:
        if path.exists() or path.is_symlink():
            yield from walk(name, path, exclusions)

def encoded(row):
    return (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--prerequisites", type=Path, required=True)
    p.add_argument("--qualification", type=Path, required=True)
    p.add_argument("--driver-log", type=Path, action="append", default=[])
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    out = a.output.absolute()
    roots = [("prerequisites", a.prerequisites.absolute()),
             ("qualification", a.qualification.absolute())]
    roots += [("drivers/" + path.name, path.absolute()) for path in a.driver_log]
    if len({name for name, path in roots}) != len(roots):
        raise ValueError("duplicate evidence root")
    if any(out == path or out.is_relative_to(path) for name, path in roots):
        raise ValueError("custody output must be outside observed roots")
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    index, archive = out / "members.jsonl", out / "original-evidence.tar.xz"
    exclusions = []
    count = regular = original_bytes = 0
    with index.open("xb") as catalog:
        with lzma.open(archive, "wb", preset=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                for path, row in all_members(roots, exclusions):
                    catalog.write(encoded(row))
                    info = tar.gettarinfo(str(path), arcname=row["name"])
                    if row["kind"] == "file":
                        info.type, info.linkname, info.size = tarfile.REGTYPE, "", row["bytes"]
                        with path.open("rb") as stream:
                            tar.addfile(info, stream)
                        regular += 1
                        original_bytes += row["bytes"]
                    else:
                        tar.addfile(info)
                    tar.members.clear()
                    tar.inodes.clear()
                    count += 1
    if not count:
        raise ValueError("no original evidence")
    observed = 0
    with index.open("rb") as catalog:
        with tarfile.open(archive, mode="r|xz") as tar:
            for member in tar:
                line = catalog.readline()
                if not line:
                    raise ValueError("archive has additional member")
                expected = json.loads(line)
                row = dict(name=member.name, mode=member.mode)
                if member.isfile():
                    with tar.extractfile(member) as stream:
                        digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    row.update(kind="file", bytes=member.size, sha256=digest)
                elif member.issym():
                    row.update(kind="symlink", target=member.linkname)
                elif member.isdir():
                    row.update(kind="directory")
                else:
                    raise ValueError("unsupported tar member")
                if row != expected:
                    raise ValueError("tar member differs: " + member.name)
                tar.members.clear()
                observed += 1
            if catalog.read(1) or observed != count:
                raise ValueError("incomplete archive")
    after = out / "members-after.jsonl"
    after_exclusions = []
    with after.open("xb") as stream:
        for path, row in all_members(roots, after_exclusions):
            stream.write(encoded(row))
    if (file_hash(index) != file_hash(after) or index.stat().st_size != after.stat().st_size
            or exclusions != after_exclusions):
        raise ValueError("original evidence changed")
    report = dict(
        schema="hia-full-retained-streamed-artifact-custody-v2",
        status="PASS_READBACK_ONLY", archive=archive.name,
        archive_bytes=archive.stat().st_size, archive_sha256=file_hash(archive),
        index=index.name, index_bytes=index.stat().st_size, index_sha256=file_hash(index),
        members=count, regular_files=regular, original_bytes=original_bytes,
        original_roots=[dict(name=name, path=str(path)) for name, path in roots],
        missing_roots=[name for name, path in roots if not path.exists()],
        excluded_git_object_directories=exclusions,
        all_selected_original_bytes_modes_and_links_before_after_equal=True,
        every_tar_member_independently_readback=True,
        qualification_executed=False, whole_stack_closed=False,
        wall_ns=time.monotonic_ns() - started)
    (out / "custody.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)

if __name__ == "__main__":
    main()
