"""Retain a finished private observation tree and independently read every member.

Regular bytes, directory metadata and symlink target text are separate node
types. Symlinks are never followed or extracted. This preserves deliberate
symlink refusal fixtures without treating their referents as extra payload.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import gzip
import io
import json
import os
from pathlib import Path
import stat
import tarfile


def key(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_regular(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if key(os.fstat(stream.fileno())) != expected:
            raise RuntimeError("regular member changed before read: " + str(path))
        raw = stream.read()
        if key(os.fstat(stream.fileno())) != expected or len(raw) != expected[6]:
            raise RuntimeError("regular member changed while read: " + str(path))
    if key(path.lstat()) != expected:
        raise RuntimeError("regular member pathname changed: " + str(path))
    return raw


def snapshot(root):
    rows = []
    def visit(folder):
        for item in sorted(os.scandir(folder), key=lambda value: value.name):
            path = Path(item.path)
            status = path.lstat()
            identity = key(status)
            row = {"path": path.relative_to(root).as_posix(), "identity": list(identity),
                   "mode": stat.S_IMODE(status.st_mode), "uid": status.st_uid,
                   "gid": status.st_gid, "mtime_ns": status.st_mtime_ns}
            if stat.S_ISDIR(status.st_mode):
                row["type"] = "directory"
                rows.append(row)
                visit(path)
                if key(path.lstat()) != identity:
                    raise RuntimeError("directory changed during scan")
            elif stat.S_ISREG(status.st_mode):
                if status.st_nlink != 1:
                    raise RuntimeError("regular member is not a private single link")
                raw = read_regular(path, identity)
                row.update(type="file", bytes=len(raw), sha256=sha256(raw).hexdigest())
                rows.append(row)
            elif stat.S_ISLNK(status.st_mode):
                target = os.readlink(path)
                if key(path.lstat()) != identity:
                    raise RuntimeError("symlink changed during observation")
                encoded = os.fsencode(target)
                row.update(type="symlink", target=target, target_bytes=len(encoded),
                           target_sha256=sha256(encoded).hexdigest())
                rows.append(row)
            else:
                raise RuntimeError("unsupported filesystem node: " + str(path))
    initial = key(root.lstat())
    if not stat.S_ISDIR(initial[2]):
        raise RuntimeError("source root is not an ordinary directory")
    visit(root)
    if key(root.lstat()) != initial:
        raise RuntimeError("source root changed during scan")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.absolute()
    if source.is_symlink():
        raise RuntimeError("source root must not be a symlink")
    source = source.resolve(strict=True)
    output = args.output.absolute()
    if source == output or source in output.parents:
        raise RuntimeError("retention output must be outside the source tree")
    output.mkdir(mode=0o700)
    before = snapshot(source)
    names = [row["path"] for row in before]
    if len(names) != len(set(names)) or any(
            Path(name).is_absolute() or ".." in Path(name).parts for name in names):
        raise RuntimeError("invalid archive member names")
    archive = output / "originals.tar.gz"
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as sink:
        with gzip.GzipFile(filename="", fileobj=sink, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as bundle:
                for row in before:
                    info = tarfile.TarInfo(row["path"])
                    info.mode, info.uid, info.gid = row["mode"], row["uid"], row["gid"]
                    info.mtime = row["mtime_ns"] // 1_000_000_000
                    info.pax_headers["HIA.original_mtime_ns"] = str(row["mtime_ns"])
                    path = source / row["path"]
                    if key(path.lstat()) != tuple(row["identity"]):
                        raise RuntimeError("source member changed before archive")
                    if row["type"] == "file":
                        raw = read_regular(path, tuple(row["identity"]))
                        if len(raw) != row["bytes"] or sha256(raw).hexdigest() != row["sha256"]:
                            raise RuntimeError("source member bytes changed")
                        info.type, info.size = tarfile.REGTYPE, len(raw)
                        bundle.addfile(info, io.BytesIO(raw))
                    elif row["type"] == "symlink":
                        if os.readlink(path) != row["target"]:
                            raise RuntimeError("source symlink target changed")
                        info.type, info.linkname = tarfile.SYMTYPE, row["target"]
                        bundle.addfile(info)
                    else:
                        info.type = tarfile.DIRTYPE
                        bundle.addfile(info)
        sink.flush()
        os.fsync(sink.fileno())
    regular_count = regular_bytes = symlink_count = directory_count = 0
    observed = []
    with tarfile.open(archive, "r:gz") as bundle:
        for member, row in zip(bundle, before, strict=True):
            if (member.name, member.mode, member.uid, member.gid) != (
                    row["path"], row["mode"], row["uid"], row["gid"]):
                raise RuntimeError("archive member identity or metadata mismatch")
            if member.pax_headers.get("HIA.original_mtime_ns") != str(row["mtime_ns"]):
                raise RuntimeError("archive member time metadata mismatch")
            if row["type"] == "file":
                if not member.isfile() or member.size != row["bytes"]:
                    raise RuntimeError("archive regular type/size mismatch")
                stream = bundle.extractfile(member)
                if stream is None:
                    raise RuntimeError("archive regular stream missing")
                digest = sha256()
                total = 0
                with stream:
                    while True:
                        part = stream.read(1 << 20)
                        if not part:
                            break
                        digest.update(part)
                        total += len(part)
                if total != row["bytes"] or digest.hexdigest() != row["sha256"]:
                    raise RuntimeError("independent archive regular readback mismatch")
                regular_count += 1
                regular_bytes += total
            elif row["type"] == "symlink":
                if not member.issym() or member.linkname != row["target"] or member.size != 0:
                    raise RuntimeError("archive symlink text mismatch")
                if sha256(os.fsencode(member.linkname)).hexdigest() != row["target_sha256"]:
                    raise RuntimeError("archive symlink byte digest mismatch")
                symlink_count += 1
            else:
                if not member.isdir() or member.size != 0:
                    raise RuntimeError("archive directory mismatch")
                directory_count += 1
            observed.append(member.name)
    if observed != names or snapshot(source) != before:
        raise RuntimeError("archive membership or original source tree changed")
    raw = archive.read_bytes()
    record = {
        "schema": "hia.typed-observation-tree-retention.v1",
        "status": "EXACT_MEMBER_READBACK_PASS",
        "source": str(source), "archive": str(archive), "archive_bytes": len(raw),
        "archive_sha256": sha256(raw).hexdigest(),
        "members": len(before), "regular_members": regular_count,
        "independently_read_regular_bytes": regular_bytes,
        "symlink_members": symlink_count, "directory_members": directory_count,
        "every_regular_member_independently_read": True,
        "symlink_targets_preserved_as_text_not_followed_or_extracted": True,
        "member_mode_uid_gid_and_mtime_preserved": True,
        "original_tree_read_again_after_archive": True,
        "original_tree_preserved": True, "rows": before,
        "product_tests_rerun": False, "source_originals_deleted": False,
    }
    receipt = output / "retention.json"
    with receipt.open("x") as stream:
        stream.write(json.dumps(record, sort_keys=True, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({key: value for key, value in record.items() if key != "rows"}, sort_keys=True))


if __name__ == "__main__":
    main()
