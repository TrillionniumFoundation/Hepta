"""Retain one finished private evidence directory and independently read every member."""
from __future__ import annotations
import argparse
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import tarfile


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError("evidence must be a nonlinked ordinary file: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise RuntimeError("evidence changed before opening")
        raw = stream.read()
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise RuntimeError("evidence changed during reading")
    if identity(path.lstat()) != identity(before):
        raise RuntimeError("evidence path changed during reading")
    return raw, before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.input.resolve(strict=True)
    output = args.output.absolute()
    output.mkdir(mode=0o700)
    files = sorted(path for path in source.rglob("*") if path.is_file() or path.is_symlink())
    records = {}
    archive_path = output / "originals.tar.gz"
    with archive_path.open("xb") as archive_file:
        with tarfile.open(fileobj=archive_file, mode="w:gz", compresslevel=6) as archive:
            import io
            for path in files:
                raw, info = read(path)
                name = path.relative_to(source).as_posix()
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                member.mode = stat.S_IMODE(info.st_mode)
                member.uid, member.gid = info.st_uid, info.st_gid
                member.mtime = info.st_mtime_ns // 1000000000
                archive.addfile(member, io.BytesIO(raw))
                records[name] = {"bytes": len(raw), "sha256": sha256(raw).hexdigest(),
                                 "mode": member.mode, "uid": member.uid, "gid": member.gid,
                                 "mtime_seconds": member.mtime, "original_identity": identity(info)}
        archive_file.flush()
        os.fsync(archive_file.fileno())
    seen, count, read_bytes = set(), 0, 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            if not member.isfile() or member.name in seen or member.name not in records:
                raise RuntimeError("archive membership differs")
            original = records[member.name]
            if (member.size != original["bytes"] or member.mode != original["mode"]
                    or member.uid != original["uid"] or member.gid != original["gid"]
                    or member.mtime != original["mtime_seconds"]):
                raise RuntimeError("archive metadata differs")
            with archive.extractfile(member) as stream:
                digest = sha256()
                length = 0
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
                    length += len(chunk)
            if length != original["bytes"] or digest.hexdigest() != original["sha256"]:
                raise RuntimeError("independent archived member bytes differ")
            raw, info = read(source / member.name)
            if tuple(original["original_identity"]) != identity(info) or sha256(raw).hexdigest() != original["sha256"]:
                raise RuntimeError("source evidence changed before archive readback completed")
            seen.add(member.name)
            count += 1
            read_bytes += length
    after_files = sorted(path.relative_to(source).as_posix()
                         for path in source.rglob("*") if path.is_file() or path.is_symlink())
    if seen != set(records) or after_files != sorted(records):
        raise RuntimeError("source or archive member set changed")
    raw, _ = read(archive_path)
    report = {"schema": "hia.cli.private-evidence-retention.v1", "status": "PASS_BYTE_CUSTODY_ONLY",
              "source_directory": str(source), "archive": str(archive_path),
              "archive_bytes": len(raw), "archive_sha256": sha256(raw).hexdigest(),
              "archive_git_blob_sha1": sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
              "members": records, "members_independently_read": count,
              "uncompressed_bytes_independently_read": read_bytes,
              "every_member_read": True, "source_evidence_preserved": True,
              "source_evidence_deleted": False, "product_gate_rerun": False}
    (output / "retention.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "members"}))


if __name__ == "__main__":
    main()
